# ZTR-1311 — implementer

**Linear:** https://linear.app/zutopia/issue/ZTR-1311
**Branch:** `ztr-1311-approval-status-enum`
**Claim run:** `22aeee8b-f57c-43a8-895f-f2d80906c909`

## Ticket
`buildExternalSendResponse` emitted `approval_status ∈ {PENDING, APPROVED, CONSUMED}`.
OpenAPI declared `{PENDING, CONSUMED, REJECTED}`. Spec-generated clients rejected `APPROVED`.

## Design
Keep shipped runtime mapping. Contracts do not freeze `REJECTED` as a wire `approval_status` (create Zod is `PENDING`; goldens have no rejected-send wire value). Readable `REJECTED` rows stay `CONSUMED` on the wire; `operation.state` still carries `REJECTED`.

Single const: `EXTERNAL_SEND_APPROVAL_STATUSES` in `packages/generic-node-contracts/src/api-schema/send-external.ts`. OpenAPI generator + response builder share it.

## Acceptance

| Criterion | Status |
|-----------|--------|
| One frozen vocabulary for OpenAPI + `buildExternalSendResponse` | Yes — `PENDING` / `APPROVED` / `CONSUMED` |
| Runtime mapping unchanged | Yes |
| `REJECTED` not advertised on `approval_status` | Yes — dropped from yaml |
| Contract test: parsed OpenAPI enum === builder const | Yes — `test/openapi-freeze.test.ts` |
| Drift-gate forbidden terms | Yes |

## Files
- `packages/generic-node-contracts/src/api-schema/send-external.ts`
- `packages/generic-node-contracts/src/api-schema/index.ts`
- `packages/generic-node-contracts/src/api-schema/operation-schemas.test.ts`
- `packages/node-core/src/send/create.ts`
- `packages/node-core/src/api/openapi/generate.ts`
- `packages/node-core/api/openapi.yaml`
- `packages/node-core/test/openapi-freeze.test.ts`
- `packages/node-core/test/send-external-create.test.ts`

Incidental freeze catch-up: destinations list `state` enum gains `WORKER` already present in `request-bodies.ts`. No destination-store code changed.

## Verification

```
pnpm exec tsc -b --pretty false                 # exit 0
pnpm --filter @zucoins/node-core exec vitest run --config vitest.unit.config.ts
# Test Files 395 passed | 4 skipped
# Tests 7347 passed | 4 skipped | 5 todo
pnpm --filter @zucoins/node-core lint            # 0 errors (5 pre-existing warnings)
pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  src/api-schema/operation-schemas.test.ts \
  src/scan/generic-core.scan-gate.test.ts
# Test Files 2 passed | Tests 35 passed
```

`pnpm --filter @zucoins/node-core test` (unit+pg) fails on origin/main PG/census drift unrelated to this ticket (`destination-state-worker.sql` census, send-create PG `verification_mode` column).
