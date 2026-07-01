/**
 * Step 2 of onboarding: show the analyst the exact admin-consent URL the
 * customer must open (using this platform's multi-tenant app registration),
 * then let the analyst submit the resulting per-tenant credential material
 * (certificate preferred, client secret as a documented fallback).
 *
 * The submitted secret/private key is passed straight to encryptCredential
 * and persisted only as an encrypted blob — see
 * src/app/api/tenants/[tenantId]/credentials/route.ts, which this form posts
 * to via a thin server action wrapper so the page itself needs no client JS
 * for the happy path.
 */

import { notFound, redirect } from 'next/navigation';
import { prisma } from '@/lib/db/client';
import { requireRole } from '@/lib/auth/rbac';
import { encryptCredential, type EncryptedBlob } from '@/lib/crypto/envelope';
import { writeAuditLog } from '@/lib/audit/log';
import { submitCredentialSchema } from '@/app/api/tenants/schemas';

interface PageProps {
  params: { tenantId: string };
  searchParams: { error?: string };
}

function buildAdminConsentUrl(entraTenantId: string, platformClientId: string): string {
  const base = `https://login.microsoftonline.com/${entraTenantId}/adminconsent`;
  const query = new URLSearchParams({ client_id: platformClientId });
  return `${base}?${query.toString()}`;
}

async function submitCredentialAction(tenantId: string, formData: FormData): Promise<void> {
  'use server';

  const session = await requireRole(['ANALYST', 'SUPER_ADMIN']);

  const tenant = await prisma.tenant.findFirst({
    where: { id: tenantId, organizationId: session.organizationId },
  });
  if (!tenant) {
    notFound();
  }

  const credentialType = formData.get('credentialType');
  const clientId = formData.get('clientId');
  const expiresAtRaw = formData.get('expiresAt');
  const expiresAt =
    typeof expiresAtRaw === 'string' && expiresAtRaw.length > 0
      ? new Date(expiresAtRaw).toISOString()
      : undefined;

  const rawInput =
    credentialType === 'CERTIFICATE'
      ? {
          credentialType: 'CERTIFICATE' as const,
          clientId,
          privateKeyPem: formData.get('privateKeyPem'),
          certificateThumbprint: formData.get('certificateThumbprint'),
          expiresAt,
        }
      : {
          credentialType: 'CLIENT_SECRET' as const,
          clientId,
          clientSecret: formData.get('clientSecret'),
          expiresAt,
        };

  const parsed = submitCredentialSchema.safeParse(rawInput);
  if (!parsed.success) {
    redirect(`/onboarding/tenants/${tenantId}/credentials?error=invalid_input`);
  }

  const input = parsed.data;
  const plaintext = input.credentialType === 'CERTIFICATE' ? input.privateKeyPem : input.clientSecret;

  let encrypted: EncryptedBlob;
  try {
    encrypted = await encryptCredential(plaintext);
  } catch {
    await writeAuditLog({
      organizationId: session.organizationId,
      actorUserId: session.userId,
      action: 'tenant_credential.submit.failed',
      targetType: 'Tenant',
      targetId: tenantId,
      metadata: { credentialType: input.credentialType, reason: 'encryption_failed' },
    }).catch(() => {});
    redirect(`/onboarding/tenants/${tenantId}/credentials?error=encryption_failed`);
  }

  const created = await prisma.$transaction(async (tx) => {
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
      select: { id: true },
    });
  });

  await prisma.tenant.update({ where: { id: tenantId }, data: { status: 'ACTIVE' } });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'tenant_credential.submit',
    targetType: 'TenantCredential',
    targetId: created.id,
    metadata: { tenantId, credentialType: input.credentialType },
  });

  redirect(`/onboarding/tenants/${tenantId}/credentials?success=1`);
}

export default async function TenantCredentialsPage({ params, searchParams }: PageProps) {
  const session = await requireRole(['ANALYST', 'SUPER_ADMIN']);

  const tenant = await prisma.tenant.findFirst({
    where: { id: params.tenantId, organizationId: session.organizationId },
  });
  if (!tenant) {
    notFound();
  }

  const platformClientId = process.env['PLATFORM_MULTI_TENANT_APP_CLIENT_ID'];
  const adminConsentUrl = platformClientId
    ? buildAdminConsentUrl(tenant.entraTenantId, platformClientId)
    : null;

  const boundSubmitAction = submitCredentialAction.bind(null, tenant.id);
  const error = searchParams.error;
  const success = searchParams.success === '1' || undefined;

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-lg font-medium mb-4">
          2. Grant admin consent for {tenant.displayName}
        </h2>
        <p className="text-sm text-gray-600 mb-4">
          Send the customer&apos;s Global Administrator the link below. It must be opened by a
          tenant admin of the customer&apos;s own Entra ID directory ({tenant.entraTenantId}) and
          grants this platform the read-only Graph application permissions listed in{' '}
          <code>src/types/domain.ts</code> — no write/remediation scopes are included by default.
        </p>
        {adminConsentUrl ? (
          <div className="rounded border border-gray-300 bg-gray-50 p-3 font-mono text-sm break-all">
            {adminConsentUrl}
          </div>
        ) : (
          <p className="text-sm text-red-600" role="alert">
            PLATFORM_MULTI_TENANT_APP_CLIENT_ID is not configured. Set it in the environment before
            onboarding can generate an admin-consent link.
          </p>
        )}
      </div>

      <div>
        <h2 className="text-lg font-medium mb-4">3. Submit the tenant credential</h2>
        <p className="text-sm text-gray-600 mb-4">
          After the customer completes admin consent, create either a certificate (preferred) or a
          client secret (documented fallback) on the resulting app registration and submit it here.
          The value is encrypted immediately and is never stored, logged, or displayed again after
          this submission.
        </p>

        {error === 'invalid_input' && (
          <p className="text-sm text-red-600 mb-4" role="alert">
            Invalid credential input — check the client ID, thumbprint format, and that the
            required field for the selected credential type is filled in.
          </p>
        )}
        {error === 'encryption_failed' && (
          <p className="text-sm text-red-600 mb-4" role="alert">
            Credential encryption is not available in this environment. Contact an operator to
            configure CREDENTIAL_KMS_KEY_ID before retrying.
          </p>
        )}
        {success && (
          <p className="text-sm text-green-700 mb-4" role="status">
            Credential submitted and encrypted successfully. This tenant is now marked ACTIVE.
          </p>
        )}

        <form action={boundSubmitAction} className="space-y-4">
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">Credential type</legend>
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" name="credentialType" value="CERTIFICATE" defaultChecked required />
              Certificate (preferred)
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" name="credentialType" value="CLIENT_SECRET" required />
              Client secret (fallback — treated as short-lived, rotation tracked)
            </label>
          </fieldset>

          <div>
            <label htmlFor="clientId" className="block text-sm font-medium">
              App registration (application) client ID
            </label>
            <input
              id="clientId"
              name="clientId"
              type="text"
              required
              pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
              className="mt-1 block w-full rounded border border-gray-300 p-2 font-mono"
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </div>

          <div>
            <label htmlFor="privateKeyPem" className="block text-sm font-medium">
              Certificate private key (PEM) — required if credential type is Certificate
            </label>
            <textarea
              id="privateKeyPem"
              name="privateKeyPem"
              rows={6}
              className="mt-1 block w-full rounded border border-gray-300 p-2 font-mono text-xs"
              placeholder="-----BEGIN PRIVATE KEY-----..."
            />
          </div>

          <div>
            <label htmlFor="certificateThumbprint" className="block text-sm font-medium">
              Certificate thumbprint (SHA-1, 40 hex chars) — required if credential type is
              Certificate
            </label>
            <input
              id="certificateThumbprint"
              name="certificateThumbprint"
              type="text"
              className="mt-1 block w-full rounded border border-gray-300 p-2 font-mono"
              placeholder="A1B2C3D4E5F6..."
            />
          </div>

          <div>
            <label htmlFor="clientSecret" className="block text-sm font-medium">
              Client secret value — required if credential type is Client secret
            </label>
            <input
              id="clientSecret"
              name="clientSecret"
              type="password"
              autoComplete="off"
              className="mt-1 block w-full rounded border border-gray-300 p-2 font-mono"
            />
          </div>

          <div>
            <label htmlFor="expiresAt" className="block text-sm font-medium">
              Expiry date (optional, recommended)
            </label>
            <input
              id="expiresAt"
              name="expiresAt"
              type="date"
              className="mt-1 block w-full rounded border border-gray-300 p-2"
            />
          </div>

          <button
            type="submit"
            className="rounded bg-blue-600 px-4 py-2 text-white text-sm font-medium hover:bg-blue-700"
          >
            Encrypt &amp; submit credential
          </button>
        </form>
      </div>
    </div>
  );
}
