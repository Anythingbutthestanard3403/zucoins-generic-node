# ZTR-1200 — Strip raw Zod error.message from 400 bodies

## Summary

Six sites embedded Zod's serialized issue array (`expected`/`received`/path dumps)
into 400 response bodies. Replaced with stable non-oracular messages.

## Sites fixed

### `apps/generic-node/src/admin-router.ts`
- `parseApproveBody` / `parseRejectBody` / `parseRecoveryBody`
- `message: r.error.message` → `message: "request body failed validation"`
- code stays `invalid_scalar`

### `packages/node-core/src/api/destination-http.ts`
1. `handleCreateDestination` Zod catch: `apiErrorResponse("invalid_scalar", requestId)` — no message override (canonical DIAGNOSTIC_MESSAGES text)
2. `parseListDestinationsQueryFromTarget`: failure variant is `{ ok: false }` only — dropped `message` from the type so the leak is unreachable by construction
3. reporting list handler: `apiErrorResponse("invalid_scalar", id)` without message override

## Tests
- `packages/node-core/test/destinations-list-reporting.test.ts` — malformed query + create body assert canonical message and no `"expected"`/`"received"` dumps; parse failure has no `message` property
- `apps/generic-node/test/admin-zod-body-messages.test.ts` — approve/reject/recovery-actions bad bodies → 400 `invalid_scalar` + stable message, no Zod dump fingerprints

## Governing pattern
- Pipeline `validateBody`/`validateQuery` already omit message overrides (`pipeline.ts`)
- Canonical `invalid_scalar` message from `error-envelope.ts` DIAGNOSTIC_MESSAGES
- Ticket: Linear ZTR-1200 (audit §7 raw Zod leak)

## Gates (at head SHA)
- `tsc -b` — clean
- `pnpm --filter @zucoins/node-core lint` — 0 errors
- `pnpm --filter @zucoins/generic-node lint` — clean
- destination tests: 38 passed (3 files)
- admin zod + related: 13 passed (3 files)
