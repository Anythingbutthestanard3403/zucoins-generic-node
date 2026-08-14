# ZTR-1289 — External-send fund from integration funding wallet (W→sender hop)

## Summary

On omit-source `POST /v1/external-sends`, when the integration has an effective funding wallet **W**, underfunded workers top up via **MOVE_INTERNAL W→sender** only. Dry/ineligible W returns stable wire code `insufficient_funding_wallet` (HTTP 422). Response `source_wallet_id` remains the **sender/worker**. Idempotent replay does not double-hop (early `findByIdempotency` + move key `topup:<sendKey>`).

When W is unset, pre-1289 multi-hub INTERNAL_ONLY top-up is unchanged.

## Governing plan

`docs/proposals/splitchain-verifiable-funding-wallet.md` §1.2.C / payout flow / node ticket split ZTR-1289.

## Acceptance

| Criterion | Status |
|-----------|--------|
| Happy path: omit source; W funded; hop if needed; hunter path; source = sender | Satisfied (S12 matrix) |
| Dry W → clear code; no silent partial form | Satisfied (`insufficient_funding_wallet`; no move/send rows) |
| Idempotent create does not double-hop on replay | Satisfied (S14) |
| PG/unit proofs for hop + insufficient | Satisfied (unit + PG lock SQL) |
| Dual review + merge | Deferred to QA / money-path dual review |

## Files

- `packages/node-core/src/assign-and-topup.ts` — funding lock SQL, evaluateFundingWalletForTopUp, prefer W over hub
- `packages/node-core/src/api/error-envelope.ts` + openapi — `insufficient_funding_wallet` 422
- `packages/node-core/src/api/routes/operation-routes.ts` — map assign rejection
- `packages/node-core/src/operation-route-store.ts` — `resolveFundingWalletId` port
- `apps/generic-node/src/main.ts` — resolve implementer pin else node default
- `packages/node-core/src/implementer/resolve-effective-funding-wallet.ts` — shared pure resolver (also needed by 1288; landed here for hop composition)
- Tests: assign unit/PG, money-capability matrix S12–S14, operation-routes map, error envelope

## Verification (head of this PR)

```
pnpm --filter @zucoins/node-core exec vitest run \
  test/assign-and-topup.test.ts \
  test/money-capability-acceptance.matrix.test.ts \
  test/operation-routes.test.ts \
  test/error-envelope-schema.test.ts \
  src/implementer/resolve-effective-funding-wallet.test.ts \
  src/implementer/funding-wallet.test.ts
# → 6 files, 90 passed

TEST_DATABASE_URL=postgres://… pnpm --filter @zucoins/node-core exec vitest run test/assign-and-topup.pg.test.ts
# → 12 passed

rtk tsc / tsc -b: clean
pnpm --filter @zucoins/node-core lint: 0 errors
boundaries.test.ts: 74 passed
UPDATE_OPENAPI=1 openapi-freeze: 27 passed
```

## Notes / deferred

- Dual money-path review still required before merge (ticket AC).
- ZTR-1288 expose-on-identity may already import the same resolver; this PR exports it from implementer barrel so either order is safe.
- Funding W must have `allow_internal_move` and observed balance ≥ shortfall; unobserved treated as dry.
