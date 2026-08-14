# ZTR-1309 — implementer

**Linear:** https://linear.app/zutopia/issue/ZTR-1309
**Branch:** `ztr-1309-send-503-details`
**Claim run:** `0dfda97c-3095-416f-9700-230bc09a2131`

## Ticket
POST `/v1/external-sends` mapped assign rejections (`no_free_send_worker` and siblings) to bare HTTP 503 `service_unavailable` with empty `details`. Integrators (Zukaz) could not distinguish pool-empty from a generic outage.

## Design
Keep HTTP 503 + public code `service_unavailable` (capacity contract unchanged). Put the assign rejection in `error.details.reason` from a closed list. Do **not** add a new public error code — OpenAPI already allowed `details` additionalProperties; Zod was the lock (`z.record(z.never())`).

401/404 auth pins still force empty `details`.

## Acceptance

| Criterion | Status |
|-----------|--------|
| 503 for capacity rejections still, not a silent 200 | Yes |
| Wire carries the specific reason (`details.reason`) | Yes — closed `ASSIGN_CAPACITY_REASONS` |
| Contract tests + consumer SDK tests cover `no_free_send_worker` and siblings | Yes |
| Drift-gate forbidden vocabulary | Yes — scan gate green |

## Governing
- `packages/node-core/src/api/routes/operation-routes.ts`
- `packages/node-core/src/api/error-envelope.ts`
- consumer `packages/generic-node-consumer/src/http/errors.ts` (`assignCapacityReason` → Zukaz `GENERIC_NODE_NO_SEND_WALLET`)

## Verification (at push head)

```
npx tsc -b --pretty false                 # exit 0
pnpm --filter @zucoins/node-core exec vitest run \
  test/error-envelope-schema.test.ts \
  test/operation-routes.test.ts \
  test/api-validation.test.ts \
  test/api-contract-size-limits.test.ts \
  test/operation-router.test.ts
# Test Files 5 passed | Tests 192 passed

pnpm --filter @zucoins/generic-node-consumer exec vitest run \
  src/http/errors.test.ts src/http/sends.test.ts
# Test Files 2 passed | Tests 11 passed

eslint (touched files)                    # max-warnings 0
pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  src/scan/generic-core.scan-gate.test.ts
# Test Files 1 passed | Tests 2 passed
```
