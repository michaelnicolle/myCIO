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
import AzureADProvider from 'next-auth/providers/azure-ad';
import type { Role } from './rbac';
import { isRole } from './rbac';

const AZURE_AD_CLIENT_ID = requireEnv('AZURE_AD_CLIENT_ID');
const AZURE_AD_CLIENT_SECRET = requireEnv('AZURE_AD_CLIENT_SECRET');
const AZURE_AD_TENANT_ID = requireEnv('AZURE_AD_TENANT_ID');

/** Conservative session lifetime for a product handling sensitive tenant security data. */
const SESSION_MAX_AGE_SECONDS = 8 * 60 * 60; // 8 hours

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

export const authOptions: AuthOptions = {
  providers: [
    AzureADProvider({
      clientId: AZURE_AD_CLIENT_ID,
      clientSecret: AZURE_AD_CLIENT_SECRET,
      tenantId: AZURE_AD_TENANT_ID,
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
     * Deny sign-in outright for principals with no provisioned portal User row.
     * This is the primary authorization gate at login time; RBAC on individual
     * routes is enforced separately via requireRole.
     */
    async signIn({ user }) {
      if (!user.email) {
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
