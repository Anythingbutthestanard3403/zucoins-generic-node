# ZTR-1317 — implementer

**Linear:** https://linear.app/zutopia/issue/ZTR-1317
**Branch:** `ztr-1317-approval-rejected`
**Base:** `origin/main` `f858ca8f9f18d6ba0923fb428f14efc86e7752df`
**Claim run:** `bf3ec361-b7d1-4024-aacc-8611170ae334`
**Lane:** `/Volumes/Ai Building/.zup-scratch/impl-ztr-1317-22d4b188`

## Ticket
GET `/v1/external-sends/{id}` `approval_status` collapsed `AWAITING_REDEMPTION` /
`NEEDS_ATTENTION` / `LANDED` / `REJECTED` to `CONSUMED`. After ZTR-1311 the OpenAPI
enum was `PENDING|APPROVED|CONSUMED` and a readable `REJECTED` row still reported
`CONSUMED`, so the `REJECTED` wire value was unreachable.

## Design
Approval is not operation state (`operation.state` still carries the row status).
Map only the approval lifecycle:

| row status | `approval_status` |
|---|---|
| `CREATED` | `PENDING` |
| `APPROVED` | `APPROVED` |
| `REJECTED` | `REJECTED` |
| `AWAITING_REDEMPTION` / `NEEDS_ATTENTION` / `EXTERNAL_SEND_LANDED` | `CONSUMED` |

Single const `EXTERNAL_SEND_APPROVAL_STATUSES` remains the vocabulary for OpenAPI + builder.

## Acceptance

| Criterion | Status |
|-----------|--------|
| `REJECTED` row → `approval_status` `REJECTED` | Yes |
| Terminal-consumed rows stay `CONSUMED` | Yes |
| OpenAPI enum includes `REJECTED` | Yes |
| emitted-enum == spec-enum | Yes — `openapi-freeze.test.ts` |
| Test fails if `REJECTED` maps to `CONSUMED` | Yes |
| No extra invented enum values | Yes |
| Drift-gate forbidden terms | Yes |

## Files
- `packages/generic-node-contracts/src/api-schema/send-external.ts`
- `packages/generic-node-contracts/src/api-schema/operation-schemas.test.ts`
- `packages/node-core/src/send/create.ts`
- `packages/node-core/src/api/openapi/generate.ts` (already spreads the const)
- `packages/node-core/api/openapi.yaml`
- `packages/node-core/test/openapi-freeze.test.ts`
- `packages/node-core/test/send-external-create.test.ts`

## Verification

```
pnpm exec tsc -b --pretty false                 # exit 0
pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  src/api-schema/operation-schemas.test.ts \
  src/scan/generic-core.scan-gate.test.ts
# Test Files 2 passed | Tests 35 passed
pnpm --filter @zucoins/node-core exec vitest run --config vitest.unit.config.ts \
  test/send-external-create.test.ts test/openapi-freeze.test.ts
# Test Files 2 passed | Tests 67 passed
UPDATE_OPENAPI=1 pnpm --filter @zucoins/node-core exec vitest run test/openapi-freeze.test.ts
# Test Files 1 passed | Tests 28 passed
pnpm --filter @zucoins/node-core exec vitest run --config vitest.unit.config.ts
# Test Files 398 passed | 4 skipped
# Tests 7391 passed | 4 skipped | 5 todo
pnpm --filter @zucoins/node-core lint            # 0 errors (5 pre-existing warnings)
pnpm --filter @zucoins/generic-node-contracts lint  # 0
```
