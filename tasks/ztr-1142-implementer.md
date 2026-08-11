# ZTR-1142 implementer

## Summary
Implemented subscription_handle mint at receive admit time. Plaintext returned once on
POST /v1/receives (and exact idempotent replay of stored body). Only SHA-256 hash is
persisted in `subscription_handles` inside the same TX as `receive_operations` insert.

## Changes
- `packages/node-core/src/receive/sql-store.ts` — mint+hash insert in admit TX
- `packages/node-core/src/receive/admission.ts` — ADMITTED/INSERTED carry plaintext once
- `packages/node-core/src/operation-route-store.ts` — body includes handle; replay uses stored body
- `packages/node-core/src/api/routes/operation-routes.ts` — type is non-null string; GET still strips
- `packages/node-core/src/api/openapi/generate.ts` + `api/openapi.yaml` — minLength:1, not nullable
- `packages/node-core/src/api/sql-subscription-handle-store.ts` — INSERT statement; lookup falls back to receive_operations
- `packages/node-core/src/observability/safe-log.ts` — redacts subscriptionHandle*
- `apps/generic-node/src/money-workers/start-money-workers.ts` — READY body preserves prior handle

## Verification (exact head)
- node-core unit: receive-admission, operation-routes, openapi-freeze, api-validation, safe-log, operation-subscribe, receive-get-live-row-version — 227 pass
- operation-route-store.pg — 6 pass (create returns sh_…; replay same handle)
- receive-admission-pg drills — 9 pass (afterAll DROP flake only)
- generic-node-consumer — 69 pass
- root `tsc -b` + generic-node `tsc -b` clean
- SPA integration docs already instruct `created.subscription_handle` — unchanged

## AC map
- [x] POST /v1/receives returns non-empty subscription_handle
- [x] Only hash persisted; plaintext one response; redacted in logs
- [x] subscribe auth path already mounted; handle lookup resolves hash
- [x] point read still strips field
- [x] idempotent replay same handle (no second mint)
- [x] frozen schema / OpenAPI / body agree; freeze+validation green
- [x] consumer type already non-null string
- [x] SPA docs already correct
