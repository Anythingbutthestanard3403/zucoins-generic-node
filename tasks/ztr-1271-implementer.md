# ZTR-1271 implementer — optional source_wallet_id on SEND_EXTERNAL

**Linear:** https://linear.app/zutopia/issue/ZTR-1271  
**Depends on:** ZTR-1270 (`64301e0c8` on main)  
**Branch:** `ztr-1271-optional-source-wallet`  
**Claim run:** `3960b5d0-5225-4f88-8cd8-3a9f36e13ac2`

## Scope

Make `source_wallet_id` optional on the public SEND_EXTERNAL create API. When omitted, run ZTR-1270 `assignAndTopUpExternalSend` **before** expected-artifact bind. Response always echoes the resolved source wallet id.

## Design

1. **Schemas** — `SendExternalRequestSchema` / `CreateExternalSendBody` / OpenAPI: `source_wallet_id` optional; still required on response.
2. **Route store** — With `assignSql` ports (main always injects), every create goes through assign composition (explicit source or pool assign + optional hub top-up). Assign runs before `createExternalSend` artifact bind.
3. **Idempotency** — Client-visible fingerprint via `idempotencySourceWalletId` / `idempotencyReferencesOperationId` so omit-source and top-up MOVE binding stay stable on replay. Early `findByIdempotency` in assign composition avoids re-selection on replay.
4. **Errors** — Assign rejection codes HTTP-mapped in `mapStoreError` (hub_busy→409 wallet_busy; no_free_send_worker / no_hub_liquidity / halted→503; internal-only source→422 protocol_predicate_failed).

## Files

- contracts `send-external.ts`, operation-schemas tests
- node-core route-schemas, openapi request-bodies + regenerated `api/openapi.yaml`
- `send/create.ts` fingerprint overrides
- `assign-and-topup.ts` early idempotency + fingerprint helpers
- `operation-route-store.ts` assign wiring
- `operation-routes.ts` CreateExternalSendInput + error map
- `apps/generic-node/src/main.ts` inject assignSql / halt
- consumer `http/sends.ts` optional field
- tests: assign, create, routes, api-validation, consumer

## AC checklist

| AC | Status |
|----|--------|
| Request without source_wallet_id admits when composition succeeds | Done (route store → assign) |
| Explicit valid send-capable source still works | Done (explicit mode) |
| Explicit internal-only source rejected | Done (allow_external_send=false → 422) |
| OpenAPI / contracts / consumer aligned | Done |
| Idempotent replay stable both body shapes | Done (client fingerprint + early replay) |
| Artifact/source binding invariant | Done (unit: artifact binds resolved wallet) |
| Assign/top-up errors documented + HTTP-mapped | Done (operation-routes tests) |
| Response always includes resolved source_wallet_id | Done (buildExternalSendResponse) |

## Out of scope

- Admin UI cutover
- Fourth money verb
