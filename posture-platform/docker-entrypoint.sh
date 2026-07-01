#!/bin/sh
# Container entrypoint for posture-platform (web + worker share this image).
#
# Usage (set as the Railway service's Start Command, or via Dockerfile CMD):
#   ./docker-entrypoint.sh server        -> run `prisma migrate deploy`, then start Next.js
#   ./docker-entrypoint.sh worker        -> start the long-lived cron worker (no migration step)
#   ./docker-entrypoint.sh worker:once   -> run one collection cycle and exit (no migration step)
#
# Migrations are intentionally run ONLY for the "server" command, and only
# `prisma migrate deploy` (never `migrate dev`, which is interactive and
# dev-only, and never `db seed`, which must stay a manual/CI step so it never
# re-runs on every container restart/redeploy).
#
# Deliberately using `migrate deploy` from the web service's boot sequence
# means only one service applies schema changes; if you run multiple web
# replicas, Prisma's migration locking makes concurrent `migrate deploy`
# invocations safe (one wins, the others no-op), but a single replica during
# migrations is still recommended for anything non-additive.
set -eu

cmd="${1:-server}"

case "$cmd" in
  server)
    echo "[entrypoint] running prisma migrate deploy..."
    node_modules/.bin/prisma migrate deploy
    echo "[entrypoint] starting Next.js standalone server..."
    exec node server.js
    ;;
  worker)
    echo "[entrypoint] starting long-lived worker (node-cron schedule)..."
    exec node_modules/.bin/tsx src/worker/index.ts
    ;;
  worker:once)
    echo "[entrypoint] running a single worker collection cycle..."
    exec node_modules/.bin/tsx src/worker/index.ts --once
    ;;
  *)
    echo "[entrypoint] unknown command '$cmd' (expected: server | worker | worker:once)" >&2
    exit 1
    ;;
esac
