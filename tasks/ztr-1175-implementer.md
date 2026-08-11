# ZTR-1175 — Consumer SDK residuals (implementer)

**Claim run:** `6c186f88-fd96-4698-bb51-8e21e337bc2f`
**Branch:** `ztr-1175-consumer-residuals`
**Base:** `origin/main` @ post-#50 merge

## Acceptance

| # | Criterion | Status |
|---|-----------|--------|
| 1 | Append-only changed-response ledger, consecutive-only dedup | Done — `changed-response-ledger.ts` uses contracts `decideAppend` |
| 2 | `A,A` → 1; `A,B,C,A` → 4 with final A regression | Done — tests in `changed-response-ledger.test.ts` |
| 3 | Anomalies always append | Done |
| 4 | Consumer can ack REJECTED / INDETERMINATE | Done — `landing_proof` optional unless verdict VERIFIED (Zod + OpenAPI + builder) |
| 5 | Unknown `node_claim_state` rejected with typed drift error | Done — `NodeStateDriftError` / `parseNodeClaimState` |
| 6 | SDK installable **or** claim removed | Done — removed "installable" claim from package headers (still `private: true` / `0.0.0`; node-core still private) |
| 7 | Arm / move / send helpers | Done — `http/arm.ts`, `http/moves.ts`, `http/sends.ts` |
| 8 | `CreateInternalMoveBody.client_reference` + OpenAPI freeze | Done — schemas, SQL insert, hash, openapi.yaml regenerated |

## Governing surface

- Doc 10 §6.2 changed-response log; §10 fail-closed unknown states
- Doc 11 §8 / §11.6 / §11.7
- Contracts: `dedup-predicate.ts`, `OPERATION_STATES`
- DB already: `verdict <> 'VERIFIED' OR landing_proof_id IS NOT NULL`

## Verification (exact commands)

```
pnpm --filter @zucoins/generic-node-contracts build   # ok
pnpm --filter @zucoins/node-core build                # ok
pnpm --filter @zucoins/generic-node-consumer build    # ok
pnpm --filter @zucoins/generic-node-consumer test      # 16 files / 84 tests pass
pnpm --filter @zucoins/node-core exec vitest run \
  test/api-validation.test.ts test/openapi-freeze.test.ts \
  test/move-internal-create.test.ts test/action-routes.test.ts
  # 4 files / 164 tests pass
pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  src/api-schema/operation-schemas.test.ts src/testkit/fixture-drift-gate.test.ts
  # 2 files / 34 tests pass
pnpm --filter @zucoins/generic-node-consumer lint     # ok
```

Root `node-core` package lint still fails on pre-existing `leadership.ts` `no-useless-catch` (on origin/main). Touched node-core paths eslint clean.

## Files (why)

**Consumer**
- `changed-response-ledger.ts(+test)` — independent append-only ledger
- `node-state.ts(+test)` — closed-set claim vocabulary
- `http/arm.ts|moves.ts|sends.ts(+tests)` — missing helpers
- `pipeline.ts` — non-VERIFIED ack; refuse unknown material kind; parse claim state
- `types.ts`, `index.ts`, headers — optional landing_proof; drop installable claim

**API / contracts / move**
- `route-schemas.ts`, `request-bodies.ts`, `openapi.yaml`, `action-routes.ts` — conditional landing_proof; move client_reference
- `move-internal.ts`, surface, gen golden + drift sha
- `move/create.ts`, `move/sql-store.ts`, route store — persist + hash client_reference
- openapi-freeze `zodObjectKeys` unwraps `ZodEffects`

## Deferred

- Publishing `@zucoins/generic-node-consumer` / bundling out of node-core (distribution decision) — claim removed instead
- Move `client_reference` is advisory and stored; not projected on InternalMoveResponse (matches receive posture; products correlate via create-time side table or future read field)
