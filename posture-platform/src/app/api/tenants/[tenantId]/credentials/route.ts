/**
 * Tenant credential submission endpoint.
 *
 * Accepts either a certificate (preferred) or client secret (documented
 * fallback) for a customer tenant's Graph app registration, encrypts it via
 * src/lib/crypto/envelope.ts, and persists only the encrypted blob. The
 * plaintext secret/private key is held in memory only for the duration of
 * this request and is never logged, never stored in a database column, and
 * never echoed back in the response — only a success indicator + credential
 * id are returned. See README.md "Security model" item 3.
 *
 * Gated to ANALYST/SUPER_ADMIN only.
 */

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db/client';
import { encryptCredential, type EncryptedBlob } from '@/lib/crypto/envelope';
import { writeAuditLog } from '@/lib/audit/log';
import { submitCredentialSchema } from '../../schemas';
import { requireTenantManagementRoleOrAudit } from '../../route-helpers';

interface RouteParams {
  params: { tenantId: string };
}

export async function POST(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const { tenantId } = params;

  const authz = await requireTenantManagementRoleOrAudit({
    action: 'tenant_credential.submit.denied',
    targetType: 'Tenant',
    targetId: tenantId,
  });
  if ('response' in authz) {
    return authz.response;
  }
  const { session } = authz;

  const tenant = await prisma.tenant.findFirst({
    where: { id: tenantId, organizationId: session.organizationId },
  });
  if (!tenant) {
    // Do not leak existence of tenants outside the caller's organization.
    return NextResponse.json({ error: 'Tenant not found.' }, { status: 404 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body.' }, { status: 400 });
  }

  const parsed = submitCredentialSchema.safeParse(body);
  if (!parsed.success) {
    // Safe: zod's flattened error never includes the field VALUES, only
    // field names + validation messages, so no secret material leaks here.
    return NextResponse.json(
      { error: 'Invalid input.', details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const input = parsed.data;
  const plaintext = input.credentialType === 'CERTIFICATE' ? input.privateKeyPem : input.clientSecret;

  let encrypted: EncryptedBlob;
  try {
    encrypted = await encryptCredential(plaintext);
  } catch (err) {
    // Never include `plaintext` or the underlying error's raw message chain
    // beyond what encryptCredential already sanitized.
    await writeAuditLog({
      organizationId: session.organizationId,
      actorUserId: session.userId,
      action: 'tenant_credential.submit.failed',
      targetType: 'Tenant',
      targetId: tenantId,
      metadata: { credentialType: input.credentialType, reason: 'encryption_failed' },
    }).catch(() => {});
    return NextResponse.json(
      { error: err instanceof Error ? err.message : 'Failed to encrypt credential.' },
      { status: 500 },
    );
  }

  const created = await prisma.$transaction(async (tx) => {
    // Deactivate any currently-active credential of the same tenant so exactly
    // one credential is active at a time (rotation history is preserved via
    // isActive=false rows, never deleted).
    await tx.tenantCredential.updateMany({
      where: { tenantId, isActive: true },
      data: { isActive: false, revokedAt: new Date() },
    });

    return tx.tenantCredential.create({
      data: {
        tenantId,
        credentialType: input.credentialType,
        clientId: input.clientId,
        kmsKeyId: encrypted.kmsKeyId,
        kmsKeyVersion: encrypted.kmsKeyVersion,
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

  // Update tenant status now that credential material has been submitted.
  await prisma.tenant.update({
    where: { id: tenantId },
    data: { status: 'ACTIVE' },
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'tenant_credential.submit',
    targetType: 'TenantCredential',
    targetId: created.id,
    metadata: {
      tenantId,
      credentialType: created.credentialType,
      // Note: wrappedDataKey/kmsKeyId are NOT secrets themselves (they don't
      // decrypt anything without the KMS), but we still avoid logging them
      // here to keep audit metadata minimal and non-sensitive.
    },
  });

  return NextResponse.json(
    { id: created.id, credentialType: created.credentialType, createdAt: created.createdAt },
    { status: 201 },
  );
}

/**
 * Lists credential metadata (never secret material) for a tenant, for the
 * onboarding UI to show current status / expiry / rotation history.
 */
export async function GET(_request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const { tenantId } = params;

  const authz = await requireTenantManagementRoleOrAudit({
    action: 'tenant_credential.list.denied',
    targetType: 'Tenant',
    targetId: tenantId,
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

  const credentials = await prisma.tenantCredential.findMany({
    where: { tenantId },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      credentialType: true,
      clientId: true,
      certificateThumbprint: true,
      expiresAt: true,
      isActive: true,
      createdAt: true,
      revokedAt: true,
      // Deliberately NOT selected: ciphertext, iv, authTag, kmsKeyId,
      // kmsKeyVersion, encryptionAlgorithm — internal to decrypt/rotate paths.
    },
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'tenant_credential.list',
    targetType: 'Tenant',
    targetId: tenantId,
    metadata: { count: credentials.length },
  });

  return NextResponse.json({ credentials });
}
