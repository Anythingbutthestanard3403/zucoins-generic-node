# syntax=docker/dockerfile:1
#
# Generic SplitChain Treasury Node v2 (apps/generic-node) — reference deployment image.
# Multi-stage, conventions lifted from the v1 root Dockerfile: the build stage
# compiles apps/generic-node and its workspace dependencies; the runtime stage
# is the slim, non-root image the deployment platform runs.
#
# BUILD CONTEXT IS THE REPO ROOT (this is a pnpm workspace — pnpm needs every
# workspace package.json present to link dependencies):
#   docker build -f apps/generic-node/Dockerfile .
#
# Secrets are NEVER baked into this image. The Stage-2 reference deployment
# injects DATABASE_URL, VAULT_MASTER_KEY, and the separately generated
# BACKUP_MASTER_KEY from the platform secret store (see deploy/deployment.yaml).
# The image carries no private/signing/vault material. Production boots fail
# closed without mandatory identity/gateway/base/vault configuration and the
# backup schedule + durable sink.
# Default CMD is custody main (dist/main.js). Stage-1 zero-custody
# remains a named override: `docker run … node dist/stage1-main.js`.

# Pinned for reproducibility (same digest as root/platform Dockerfiles
# by pinning policy). To bump deliberately: run
# `docker buildx imagetools inspect node:22-alpine`, take the top-level Digest,
# replace the sha256 below in BOTH stages of ALL node:22-alpine Dockerfiles
# (root, apps/platform, apps/generic-node), then verify with a build +
# healthcheck probe before merging.
FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS build
WORKDIR /repo

RUN corepack enable && corepack prepare pnpm@11.13.0 --activate

# Whole-repo copy before install: same pnpm workspace trade-off as the v1
# Dockerfile — correctness over layer-cache granularity.
COPY . .

RUN pnpm install --frozen-lockfile

# Operator SPA then node packages. UI dist is served by runtime-listener from
# apps/generic-node/admin/dist (see src/admin-spa.ts).
RUN pnpm --filter @zucoins/generic-node-ui build \
 && pnpm -r --filter @zucoins/generic-node... build

# Prod-slim the runtime: compiled dist/ output already exists on disk, so
# devDependencies are no longer needed. pnpm cannot prune recursively in a
# workspace in place (v1 Dockerfile documents the empirically verified
# failure), so delete every node_modules dir and reinstall clean, prod-only.
RUN find /repo -name node_modules -type d -prune -exec rm -rf {} +
RUN CI=true pnpm install --prod --frozen-lockfile

# The runtime only ever executes compiled dist/*.js — drop the TypeScript
# source. `! -path '*/node_modules/*'` (not `-prune`) is deliberate: busybox
# find's `-delete` implies `-depth`, which silently disables `-prune`'s
# protection (verified empirically in the v1 Dockerfile before relying on it).
RUN find /repo -type f \( -name '*.ts' -o -name '*.tsx' \) ! -path '*/node_modules/*' -delete

# Pinned for reproducibility, same digest as the build stage above.
FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS runtime
WORKDIR /repo

# tini as PID 1 — correct SIGTERM forwarding into the graceful-stop handler
# (apps/generic-node/src/boot/graceful-stop.ts): stop accepting, bounded
# drain of in-flight persist steps, clean signer-leadership release.
#
# postgresql16-client: src/dr/encrypted-backup.ts spawns pg_dump
# and psql unconditionally once the backup schedule is enabled — without this
# package the first scheduled backup ENOENTs with no client binary, leaving a
# false DR posture. Major version 16
# is pinned to match the deployed Postgres server (postgres:16 in
# the reference deployment); bump this package
# and src/dr/client-probe.ts's EXPECTED_PG_CLIENT_MAJOR_VERSION together, and
# only after verifying the server's own major version has moved too. The
# src/dr/client-probe.ts boot-time probe fails the process closed if this
# package is ever missing or its major version drifts from that constant.
RUN apk add --no-cache tini postgresql16-client

# node:22-alpine ships a non-root `node` user already; reuse it (least
# privilege).
COPY --chown=node:node --from=build /repo /repo

USER node
ENV NODE_ENV=production
WORKDIR /repo/apps/generic-node
EXPOSE 8080

ENTRYPOINT ["/sbin/tini", "--"]
# Default: custody composition root (Stage-2 custody spine).
# Migrations run INSIDE the boot lane (dist/main.js), after the fail-fast
# configuration validation — never as a separate
# pre-step that could run migrations against an invalid configuration.
# Named non-money variant (retain Stage-1): override CMD to
# ["node", "dist/stage1-main.js"] — never silent default after this flip.
CMD ["node", "dist/main.js"]
