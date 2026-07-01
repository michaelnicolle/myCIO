/**
 * NextAuth v4 configuration for portal SSO (myCIO staff + customer-viewer login)
 * via Entra ID (Azure AD). See README.md "Security model" item 5 and
 * src/lib/auth/README.md for the operational requirements (Conditional
 * Access / MFA) that this config alone cannot enforce.
 *
 * IMPORTANT: This is the *portal* app registration (staff/customer SSO). It is
 * intentionally separate from each customer tenant's monitoring app
 * registration (see PLATFORM_MULTI_TENANT_APP_CLIENT_ID in src/app/api/tenants,
 * used only for the Graph admin-consent flow, never for portal login).
 */

import type { AuthOptions, Session } from 'next-auth';
import type { JWT } from 'next-auth/jwt';
import AzureADProvider, { AzureADProfile } from 'next-auth/providers/azure-ad';
import type { Role } from './types';
import { isRole } from './types';

const AZURE_AD_CLIENT_ID = requireEnv('AZURE_AD_CLIENT_ID');
const AZURE_AD_CLIENT_SECRET = requireEnv('AZURE_AD_CLIENT_SECRET');
const AZURE_AD_TENANT_ID = requireEnv('AZURE_AD_TENANT_ID');

/** Conservative session lifetime for a product handling sensitive tenant security data. */
const SESSION_MAX_AGE_SECONDS = 8 * 60 * 60; // 8 hours

/**
 * Defense-in-depth check for Conditional Access MFA (see README.md "MFA / step-up
 * authentication"). Parsed once at module load; see `isTruthyEnv` for accepted values.
 *
 * - Falsy/unset (default): warn-only. This is intentional — enabling fail-closed
 *   before the Entra-side `amr` optional claim is actually configured (see README.md)
 *   would lock out every user, since the claim would never be present. Ship with this
 *   unset, confirm the warning path looks correct across real sign-ins, then opt in.
 * - Truthy ("true"/"1"): fail-closed. Sign-in is denied when the `amr` claim is
 *   missing or does not indicate MFA was completed.
 */
const ENFORCE_MFA_CLAIM = isTruthyEnv(process.env.ENFORCE_MFA_CLAIM);

function isTruthyEnv(value: string | undefined): boolean {
  return value === 'true' || value === '1';
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}. See .env.example for the portal ` +
        'Entra ID (Azure AD) app registration values NextAuth needs.',
    );
  }
  return value;
}

/**
 * Augmented JWT/session fields. `role` and `organizationId` are attached during
 * the `jwt` callback below by looking up the User record created/managed by the
 * Prisma-backed user provisioning flow (out of scope for this file — see the
 * `lookupUserByOid`/`lookupUserByEmail` TODO below for the exact extension
 * point another module, or a follow-up here, should fill in).
 */
declare module 'next-auth' {
  interface Session {
    user: {
      id: string;
      email: string;
      name?: string | null;
      role: Role;
      organizationId: string;
    };
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    userId?: string;
    role?: Role;
    organizationId?: string;
  }
}

/**
 * Look up the portal User row for a signed-in Entra ID principal. This is the
 * single extension point that ties an Entra ID identity to this app's
 * Organization/Role model.
 *
 * NOTE: Deliberately implemented here (rather than stubbed as a TODO) using the
 * shared Prisma client per project convention (`@/lib/db/client`), so sign-in
 * actually attaches `role`/`organizationId`. If no matching User row exists
 * (e.g. Entra ID grants access before an admin provisions the portal user),
 * sign-in is denied — there is no default role.
 */
async function lookupPortalUser(
  email: string,
): Promise<{ id: string; organizationId: string; role: Role; isActive: boolean } | null> {
  const { prisma } = await import('@/lib/db/client');
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
    select: { id: true, organizationId: true, role: true, isActive: true },
  });
  if (!user || !isRole(user.role)) {
    return null;
  }
  return user;
}

/**
 * Entra ID's Authentication Methods References (`amr`) claim, present on the ID
 * token only when the "amr" optional claim has been added to this app
 * registration's manifest (Token configuration > Add optional claim > ID token >
 * amr — see README.md for the exact steps). Absence of the claim is
 * indistinguishable, from this code's point of view, between "MFA was not
 * performed" and "the optional claim isn't configured yet" — which is exactly
 * why the default posture below is warn-only rather than fail-closed.
 */
interface AzureADProfileWithAmr extends AzureADProfile {
  amr?: string[];
}

/**
 * True only when Entra's `amr` claim is present and explicitly lists "mfa",
 * Microsoft's documented indicator that multi-factor auth was satisfied for
 * this sign-in. See
 * https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens#payload-claims
 */
function hasMfaAmr(profile: AzureADProfileWithAmr | null | undefined): boolean {
  return Array.isArray(profile?.amr) && profile.amr.includes('mfa');
}

/**
 * Defense-in-depth check backing `ENFORCE_MFA_CLAIM` (see README.md "MFA / step-up
 * authentication"). Returns `true` if sign-in should be allowed to proceed.
 *
 * This is a *secondary* detection/enforcement layer. The primary, authoritative
 * control is still an Entra ID Conditional Access policy requiring MFA for the
 * portal's app registration — this only detects (and, once opted in, enforces)
 * that the amr claim reflects MFA having actually happened, which itself
 * depends on the Entra app registration being configured to emit that claim.
 */
function checkMfaClaim(email: string, profile: AzureADProfileWithAmr | null | undefined): boolean {
  if (hasMfaAmr(profile)) {
    return true;
  }

  if (ENFORCE_MFA_CLAIM) {
    console.warn(
      `Denying sign-in for ${email}: ENFORCE_MFA_CLAIM is enabled and the Entra ID "amr" claim ` +
        'is missing or does not include "mfa". Either Conditional Access MFA was not enforced for ' +
        'this sign-in, or the "amr" optional claim is not configured on the portal app registration ' +
        '— see src/lib/auth/README.md.',
    );
    return false;
  }

  // Warn-only (default) mode: loud, one-time-per-sign-in warning, but still allow.
  // eslint-disable-next-line no-console
  console.warn(
    '\n' +
      '!!! =====================================================================\n' +
      '!!! SECURITY WARNING: sign-in for ' +
      email +
      ' is missing the Entra ID\n' +
      '!!! "amr" claim (or it does not include "mfa"). This usually means either\n' +
      '!!! Conditional Access is not enforcing MFA for this app registration, or\n' +
      '!!! the "amr" optional claim has not been added to the app registration\n' +
      '!!! manifest yet. Allowing sign-in because ENFORCE_MFA_CLAIM is not set.\n' +
      '!!! See src/lib/auth/README.md before setting ENFORCE_MFA_CLAIM=true.\n' +
      '!!! =====================================================================\n',
  );
  return true;
}

export const authOptions: AuthOptions = {
  providers: [
    AzureADProvider({
      clientId: AZURE_AD_CLIENT_ID,
      clientSecret: AZURE_AD_CLIENT_SECRET,
      tenantId: AZURE_AD_TENANT_ID,
      // Override the default `profile()` so the "amr" claim survives onto the
      // user-ish object NextAuth attaches to `account`/`user`. This is belt-and-
      // suspenders: NextAuth v4's OAuth callback handler (core/lib/oauth/callback.js)
      // actually passes the *raw* decoded ID token claims (via `tokens.claims()`,
      // since AzureADProvider's `wellKnown` URL is auto-detected as an OIDC
      // discovery doc) as the separate `profile` argument to the `signIn` callback
      // below — so `amr` is already visible there without this override. We still
      // override `profile()` here so `amr` isn't silently dropped for any other
      // consumer of the provider's mapped profile, and so this doesn't depend on
      // an internal implementation detail of exactly what NextAuth forwards.
      async profile(profile: AzureADProfileWithAmr, tokens) {
        const response = await fetch(
          `https://graph.microsoft.com/v1.0/me/photos/48x48/$value`,
          { headers: { Authorization: `Bearer ${tokens.access_token}` } },
        );
        let image: string | null = null;
        if (response.ok) {
          try {
            const pictureBuffer = await response.arrayBuffer();
            const pictureBase64 = Buffer.from(pictureBuffer).toString('base64');
            image = `data:image/jpeg;base64, ${pictureBase64}`;
          } catch {
            // Same best-effort behavior as the upstream default profile().
          }
        }
        return {
          id: profile.sub,
          name: profile.name,
          email: profile.email,
          image,
          amr: profile.amr,
        };
      },
    }),
  ],

  session: {
    // JWT strategy: no server-side session table dependency for portal auth.
    strategy: 'jwt',
    maxAge: SESSION_MAX_AGE_SECONDS,
  },

  jwt: {
    maxAge: SESSION_MAX_AGE_SECONDS,
  },

  // Explicit cookie configuration. NextAuth v4 already defaults to
  // httpOnly + sameSite=lax, and secure=true whenever NEXTAUTH_URL is https
  // (or `useSecureCookies` is inferred from NODE_ENV), but we set every field
  // explicitly rather than relying on inferred defaults — see
  // src/lib/auth/README.md.
  cookies: {
    sessionToken: {
      name:
        process.env.NODE_ENV === 'production'
          ? '__Secure-next-auth.session-token'
          : 'next-auth.session-token',
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: process.env.NODE_ENV === 'production',
      },
    },
  },

  callbacks: {
    /**
     * Two independent gates must both pass, or sign-in is denied:
     *  1. The Entra ID "amr" claim indicates MFA was completed (see
     *     `checkMfaClaim` and README.md) — checked first since it is a cheap,
     *     in-memory check with no DB round-trip, so a bad/missing claim fails
     *     fast without spending a Prisma query.
     *  2. The principal has a provisioned, active portal User row
     *     (`lookupPortalUser`). This is the primary authorization gate at login
     *     time; RBAC on individual routes is enforced separately via
     *     requireRole. A user with no provisioned User row is denied
     *     regardless of MFA claim status.
     */
    async signIn({ user, profile }) {
      if (!user.email) {
        return false;
      }

      if (!checkMfaClaim(user.email, profile as AzureADProfileWithAmr | undefined)) {
        return false;
      }

      const portalUser = await lookupPortalUser(user.email);
      return Boolean(portalUser?.isActive);
    },

    async jwt({ token, user }): Promise<JWT> {
      // `user` is only present on initial sign-in; on subsequent requests we
      // keep whatever was attached to the token previously. Re-resolving role/
      // organizationId on every request would add a DB round-trip per request;
      // instead the JWT's short maxAge (8h) bounds staleness, and role changes
      // should force re-authentication (e.g. by revoking sessions) when urgent.
      if (user?.email) {
        const portalUser = await lookupPortalUser(user.email);
        if (portalUser) {
          token.userId = portalUser.id;
          token.role = portalUser.role;
          token.organizationId = portalUser.organizationId;
        }
      }
      return token;
    },

    async session({ session, token }): Promise<Session> {
      if (token.userId && token.role && token.organizationId) {
        session.user.id = token.userId;
        session.user.role = token.role;
        session.user.organizationId = token.organizationId;
      }
      return session;
    },
  },

  pages: {
    signIn: '/login',
    error: '/login',
  },

  secret: requireEnv('NEXTAUTH_SECRET'),
};
