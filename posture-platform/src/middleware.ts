/**
 * Portal session enforcement. Deny-by-default: every route requires an
 * authenticated session EXCEPT the explicit allowlist below. See README.md
 * "Security model" item 5.
 *
 * Per-route RBAC (SUPER_ADMIN / ANALYST / CUSTOMER_VIEWER) is enforced inside
 * individual route handlers / server components via `requireRole` (see
 * src/lib/auth/rbac.ts) — this middleware only enforces "is there a session at
 * all", since NextAuth's `withAuth` operates on the JWT and running full
 * Prisma-backed role checks in the Edge middleware runtime is out of scope
 * (and would require a DB round trip per request at the edge).
 *
 * Security headers (CSP/HSTS/etc.) are configured separately in
 * next.config.mjs and are not duplicated here.
 */

import { withAuth } from 'next-auth/middleware';
import { NextResponse } from 'next/server';

/**
 * Explicit allowlist of paths that do NOT require an authenticated session.
 * Everything else is denied by default. Keep this list as small as possible.
 */
const PUBLIC_PATH_PREFIXES = [
  '/login', // sign-in page itself
  '/api/auth', // NextAuth's own endpoints (sign-in, callback, csrf, session, signout)
] as const;

const PUBLIC_EXACT_PATHS = new Set<string>([
  '/', // public marketing/landing page
  '/favicon.ico',
]);

function isPublicPath(pathname: string): boolean {
  if (PUBLIC_EXACT_PATHS.has(pathname)) {
    return true;
  }
  return PUBLIC_PATH_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );
}

export default withAuth(
  function middleware() {
    return NextResponse.next();
  },
  {
    callbacks: {
      /**
       * Returning `true` allows the request to proceed; `false` triggers
       * NextAuth's redirect-to-sign-in behavior. Public paths always pass;
       * everything else requires a non-null token (i.e. a valid session).
       */
      authorized: ({ req, token }) => {
        if (isPublicPath(req.nextUrl.pathname)) {
          return true;
        }
        return Boolean(token);
      },
    },
    pages: {
      signIn: '/login',
    },
  },
);

/**
 * Apply to everything except static assets and Next.js internals — the
 * allowlist above (not this matcher) is the authorization boundary. This
 * matcher only avoids running middleware on files that could never need auth
 * (images, _next static/build output, etc.).
 */
export const config = {
  matcher: ['/((?!_next/static|_next/image|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)'],
};
