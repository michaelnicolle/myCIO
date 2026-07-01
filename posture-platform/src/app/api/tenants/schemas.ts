/**
 * Zod schemas for the tenant onboarding API surface. Kept separate from the
 * route handlers so both the API routes and the onboarding UI/server actions
 * can share the exact same validation.
 */

import { z } from 'zod';

/** Entra ID (Azure AD) tenant GUIDs are standard UUIDs. */
const guidSchema = z
  .string()
  .trim()
  .regex(
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/,
    'Must be a valid GUID, e.g. the customer Entra tenant ID.',
  );

export const createTenantSchema = z.object({
  displayName: z.string().trim().min(2).max(200),
  entraTenantId: guidSchema,
});
export type CreateTenantInput = z.infer<typeof createTenantSchema>;

/** Certificate thumbprints as returned by Entra ID are 40-hex-char SHA-1 hashes. */
const thumbprintSchema = z
  .string()
  .trim()
  .regex(/^[0-9a-fA-F]{40}$/, 'Must be a 40-character hex certificate thumbprint (SHA-1).');

/**
 * Certificate auth is preferred (README "Security model" item 2); client
 * secret is a documented fallback. Exactly one credential shape must be
 * provided per submission.
 */
export const submitCredentialSchema = z.discriminatedUnion('credentialType', [
  z.object({
    credentialType: z.literal('CERTIFICATE'),
    clientId: guidSchema,
    /** PEM-encoded private key (certificate + key pair generated for this tenant's app registration). */
    privateKeyPem: z.string().trim().min(1),
    certificateThumbprint: thumbprintSchema,
    expiresAt: z.string().datetime().optional(),
  }),
  z.object({
    credentialType: z.literal('CLIENT_SECRET'),
    clientId: guidSchema,
    clientSecret: z.string().min(1),
    expiresAt: z.string().datetime().optional(),
  }),
]);
export type SubmitCredentialInput = z.infer<typeof submitCredentialSchema>;
