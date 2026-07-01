# syntax=docker/dockerfile:1
#
# Multi-stage production image for posture-platform (Next.js web + Prisma).
#
# Used for BOTH Railway services this app needs:
#   - web:    CMD (default below) runs migrations then starts the Next server.
#   - worker: same image, override the Railway service's Start Command to run
#             the background worker instead (see DEPLOYMENT.md) — either the
#             long-lived cron-scheduled process (`npm run worker`) or a single
#             collection cycle for Railway's native Cron Schedule feature
#             (`npm run worker:once`).
#
# Build with Railway's "Root Directory" for both services set to
# `posture-platform` (this Dockerfile lives at the root of that directory) —
# see DEPLOYMENT.md, this is the single most common misconfiguration.
#
# Base image: node:20-bookworm-slim (Debian, glibc) rather than Alpine. Prisma's
# own docs recommend a slim Debian base for production — Alpine (musl libc)
# requires explicit `binaryTargets` overrides in schema.prisma to avoid
# generating the wrong query-engine binary, and this repo's schema
# (prisma/schema.prisma) is intentionally left untouched by this deployment
# change. All stages pin the same base so the Prisma query engine generated in
# the builder stage matches the runtime exactly.

# ---------------------------------------------------------------------------
# Stage 1: install dependencies (including devDependencies, needed to build)
# ---------------------------------------------------------------------------
FROM node:20-bookworm-slim AS deps
WORKDIR /app

# openssl is required by the Prisma engines at both generate-time and (in the
# runner stage) at query-engine-load time.
RUN apt-get update -y && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci

# ---------------------------------------------------------------------------
# Stage 2: generate the Prisma client + build the Next.js app
# ---------------------------------------------------------------------------
FROM node:20-bookworm-slim AS builder
WORKDIR /app

RUN apt-get update -y && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Prisma client codegen needs the schema but does NOT need a live database
# connection, so this is safe to run at build time with no DATABASE_URL set.
RUN npx prisma generate

# Next.js build-time env: values below are placeholders so `next build` can
# statically analyze/collect page data; real secrets are injected at runtime
# by Railway and do not need to match these. NEXT_TELEMETRY_DISABLED avoids
# a network call during the build.
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 3: minimal runtime image
# ---------------------------------------------------------------------------
FROM node:20-bookworm-slim AS runner
WORKDIR /app

RUN apt-get update -y && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Run as an unprivileged user (the official node image ships a `node` user/group).
RUN mkdir -p /app && chown -R node:node /app

# The `prisma` CLI (for `prisma migrate deploy` at startup) and `tsx` (to run
# the worker entrypoint, src/worker/index.ts, directly from TypeScript source
# in this same image — see DEPLOYMENT.md) are needed in addition to whatever
# the Next.js server itself uses. Rather than hand-picking each CLI's
# transitive runtime dependencies one at a time (fragile — e.g. `tsx` needs
# `esbuild`, `prisma` needs `@prisma/engines`, and such a list silently drifts
# as versions change), start from the full pre-build node_modules (the `deps`
# stage, before pruning/tracing), which already has everything both CLIs need.
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/prisma ./prisma
COPY --from=builder --chown=node:node /app/package.json ./package.json
COPY --from=builder --chown=node:node /app/src ./src
COPY --from=builder --chown=node:node /app/tsconfig.json ./tsconfig.json

# Layer the standalone Next.js server output (see next.config.mjs
# `output: "standalone"`) on top, LAST — it must win over the plain `deps`
# copy above because it contains both server.js/the traced server bundle and
# the already-`prisma generate`-d @prisma/client (with the platform-matching
# query engine binary), whereas the `deps` node_modules copied above has only
# the pre-generate @prisma/client stub. Docker's COPY merges directories
# rather than replacing them wholesale, so this only overwrites the specific
# files standalone provides (server bundle + its trimmed node_modules subset)
# and leaves the CLI tooling copied above untouched.
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public

COPY --chown=node:node docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh

USER node

EXPOSE 3000

ENTRYPOINT ["./docker-entrypoint.sh"]

# Default command for the web service. The worker service overrides this via
# Railway's Start Command setting (documented in DEPLOYMENT.md) — it does NOT
# need or want migrate deploy to run a second time, but the entrypoint script
# only runs migrations when CMD is "server" so the worker's override is safe.
CMD ["server"]
