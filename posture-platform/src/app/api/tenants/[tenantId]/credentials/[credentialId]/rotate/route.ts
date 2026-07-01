/**
 * Tenant credential rotation endpoint. Accepts new credential material for a
 * tenant that already has an active credential, encrypts and persists it as a
 * new TenantCredential row, and marks the specified prior credential (and any
 * other currently-active credential for the tenant) as revoked/inactive.
 * Rotation history is preserved — rows are never deleted.
 *
 * Same plaintext-handling rules as the submission endpoint: the secret/key
 * never touches a log line, DB column (outside the encrypted blob), or API
 * response. Gated to ANALYST/SUPER_ADMIN only.
 */

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db/client';
import { encryptCredential, type EncryptedBlob } from '@/lib/crypto/envelope';
import { writeAuditLog } from '@/lib/audit/log';
import { submitCredentialSchema } from '../../../../schemas';
import { requireTenantManagementRoleOrAudit } from '../../../../route-helpers';

interface RouteParams {
  params: { tenantId: string; credentialId: string };
}

export async function POST(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const { tenantId, credentialId } = params;

  const authz = await requireTenantManagementRoleOrAudit({
    action: 'tenant_credential.rotate.denied',
    targetType: 'TenantCredential',
    targetId: credentialId,
  });
  if ('response' in authz) {
    return authz.response;
  }
  const { session } = authz;

  const tenant = await prisma.tenant.findFirst({
    where: { id: tenantId, organizationId: session.organizationId },
  });
  if (!tenant) {
    return NextResponse.json({ error: 'Tenant not found.' }, { status: 404 });
  }

  const priorCredential = await prisma.tenantCredential.findFirst({
    where: { id: credentialId, tenantId },
    select: { id: true },
  });
  if (!priorCredential) {
    return NextResponse.json({ error: 'Credential not found for this tenant.' }, { status: 404 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body.' }, { status: 400 });
  }

  const parsed = submitCredentialSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'Invalid input.', details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const input = parsed.data;
  const plaintext = input.credentialType === 'CERTIFICATE' ? input.privateKeyPem : input.clientSecret;

  let encrypted;
  try {
    encrypted = await encryptCredential(plaintext);
  } catch (err) {
    await writeAuditLog({
      organizationId: session.organizationId,
      actorUserId: session.userId,
      action: 'tenant_credential.rotate.failed',
      targetType: 'TenantCredential',
      targetId: credentialId,
      metadata: { tenantId, credentialType: input.credentialType, reason: 'encryption_failed' },
    }).catch(() => {});
    return NextResponse.json(
      { error: err instanceof Error ? err.message : 'Failed to encrypt credential.' },
      { status: 500 },
    );
  }

  const rotated = await prisma.$transaction(async (tx) => {
    await tx.tenantCredential.updateMany({
      where: { tenantId, isActive: true },
      data: { isActive: false, revokedAt: new Date() },
    });

    return tx.tenantCredential.create({
      data: {
        tenantId,
        credentialType: input.credentialType,
        clientId: input.clientId,
        kmsProvider: encrypted.provider,
        kmsKeyId: encrypted.kmsKeyId,
        kmsKeyVersion: encrypted.kmsKeyVersion,
        wrappedDataKey: Buffer.from(encrypted.wrappedDataKey, 'base64'),
        encryptionAlgorithm: encrypted.algorithm,
        ciphertext: Buffer.from(encrypted.ciphertext, 'base64'),
        iv: Buffer.from(encrypted.iv, 'base64'),
        authTag: Buffer.from(encrypted.authTag, 'base64'),
        certificateThumbprint:
          input.credentialType === 'CERTIFICATE' ? input.certificateThumbprint : null,
        expiresAt: input.expiresAt ? new Date(input.expiresAt) : null,
        isActive: true,
      },
      select: { id: true, credentialType: true, createdAt: true },
    });
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'tenant_credential.rotate',
    targetType: 'TenantCredential',
    targetId: rotated.id,
    metadata: {
      tenantId,
      previousCredentialId: credentialId,
      credentialType: rotated.credentialType,
    },
  });

  return NextResponse.json(
    { id: rotated.id, credentialType: rotated.credentialType, createdAt: rotated.createdAt },
    { status: 201 },
  );
}
