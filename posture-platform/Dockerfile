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
# All stages pin the same node:20-alpine base so the Prisma query engine
# binary generated in the builder stage (musl target) matches the runtime.

# ---------------------------------------------------------------------------
# Stage 1: install dependencies (including devDependencies, needed to build)
# ---------------------------------------------------------------------------
FROM node:20-alpine AS deps
WORKDIR /app

# openssl is required by the Prisma engines on Alpine at both generate-time
# and (in the runner stage) at query-engine-load time.
RUN apk add --no-cache openssl

COPY package.json package-lock.json ./
RUN npm ci

# ---------------------------------------------------------------------------
# Stage 2: generate the Prisma client + build the Next.js app
# ---------------------------------------------------------------------------
FROM node:20-alpine AS builder
WORKDIR /app

RUN apk add --no-cache openssl

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
FROM node:20-alpine AS runner
WORKDIR /app

RUN apk add --no-cache openssl

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Run as an unprivileged user (Alpine's node image ships a `node` user/group).
RUN mkdir -p /app && chown -R node:node /app

# Standalone Next.js output: a self-contained server bundle with only the
# node_modules it actually needs (see next.config.mjs `output: "standalone"`).
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public

# Prisma CLI + generated client + schema + migrations, needed at container
# startup to run `prisma migrate deploy` before the server starts. The
# standalone build's node_modules already contains @prisma/client's generated
# engine, but not the `prisma` CLI package itself, so it's copied explicitly.
COPY --from=builder --chown=node:node /app/node_modules/.bin/prisma ./node_modules/.bin/prisma
COPY --from=builder --chown=node:node /app/node_modules/prisma ./node_modules/prisma
COPY --from=builder --chown=node:node /app/node_modules/@prisma ./node_modules/@prisma
COPY --from=builder --chown=node:node /app/prisma ./prisma
COPY --from=builder --chown=node:node /app/package.json ./package.json

# tsx + its runtime deps are needed to run the worker entrypoint
# (src/worker/index.ts) directly from TypeScript source in this same image —
# see DEPLOYMENT.md for the worker service's Start Command.
COPY --from=builder --chown=node:node /app/node_modules/.bin/tsx ./node_modules/.bin/tsx
COPY --from=builder --chown=node:node /app/node_modules/tsx ./node_modules/tsx
COPY --from=builder --chown=node:node /app/src ./src
COPY --from=builder --chown=node:node /app/tsconfig.json ./tsconfig.json

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
