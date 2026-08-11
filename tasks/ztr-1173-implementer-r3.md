# ZTR-1173 — implementer r3 (Review B r2 rework)

**Head SHA:** `6dc4fdecd6788a6c2402a27b7c6ccfa0d0eb83f0`
**Code commit:** `6d2d8167bb0189b9bf58eb04b9810319ed374460` (test/gates; docs pins may sit above)
**Branch:** `ztr-1173-test-gate-integrity`
**PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/69
**Prior FAIL:** Review B r2 @ `eaa5a59757a90c63524f84394bb94ffd581d9b04` (`tasks/ztr-1173-review-B-r2.md`)
**Run:** `437ebfe8-a789-431f-9e30-2c03379be96a`

## Blocking items addressed

| Attack | Fix |
|---|---|
| A1 Census still comment-launderable | Census now requires executable `it("DB-TEST-NN…")` / `discharges("DB-TEST-NN…")` (comment-only refused). Token check runs on **title + callback body after comment strip**, majority of distinctive tokens. Synthetic pg+comment pin test. All 36 rows renamed / re-cited to real `it` titles. |
| A3′ / DB-TEST-23 comment-only on enrol | Real PG race in `mandatory-db-discharge-21-36.pg.test.ts`: seed epoch-1 head; competing KEY_ROTATED epoch-2 → first valid commit wins (UNIQUE + advance CAS); stale admission closed; AUTH_HOLD_SET closes admission; single head row. Matrix re-cites discharge suite; enrol laundry header removed. |
| PG guard miswire | `registerPgRequiredGuard({ name, databaseUrl, isReady })` correct API, registered **after** describe (EOF) so beforeAll can set ready. `packages/node-core/vitest.config.ts` wires `vitest.global-setup.ts`. Empty URL + PG_REQUIRED=1 → guard FAIL (no silent green). |

## Acceptance

| Criterion | Status |
|---|---|
| 36 mandatory DB tests cite PG-exercising artifact with executable discharge | satisfied |
| DB-TEST-23 real race assert | satisfied |
| PG_REQUIRED fail-closed for discharge suite | satisfied |
| dependency-boundary unchanged | 37/37 |
| move-execute + live-ops census / passWithNoTests false | holds |

## Governing spec

- `docs/proposals/generic-node-redesign-v2/04-data-model.md` §16 item 23
- `docs/proposals/generic-node-redesign-v2/mandatory-database-tests.md` §3.18

## Verify (this head)

```
pnpm exec vitest run --config packages/node-core/vitest.config.ts \
  test/mandatory-database-tests.census.test.ts \
  test/mandatory-db-discharge-21-36.pg.test.ts \
  test/live-chain/live-ops.census.test.ts \
  test/live-chain/types.test.ts \
  test/live-chain/move-execute.test.ts
# → 5 files, 43 passed

PG_REQUIRED=1 pnpm exec vitest run --config packages/node-core/vitest.config.ts \
  test/mandatory-db-discharge-21-36.pg.test.ts
# → 11 passed (10 body + guard)

TEST_DATABASE_URL= PG_REQUIRED=1 pnpm exec vitest run --config packages/node-core/vitest.config.ts \
  test/mandatory-db-discharge-21-36.pg.test.ts
# → guard FAIL (URL unassigned) — no silent skip green

pnpm exec vitest run --config packages/generic-node-contracts/vitest.config.ts \
  src/scan/dependency-boundary.test.ts
# → 37 passed

pnpm exec vitest run --config packages/node-core/vitest.live-chain.config.ts \
  test/live-chain/this-does-not-exist.live.test.ts
# → exit 1, No test files found
```

## Files

- `packages/node-core/test/mandatory-database-tests.census.test.ts` — executable discharge + synthetic pin
- `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` — DB-TEST-23 race + guard wire
- `packages/node-core/vitest.config.ts` — globalSetup
- `docs/proposals/.../mandatory-database-tests.md` — re-cite 17, 20, 23
- Named `it("DB-TEST-NN…")` on remaining cited suites (01–20, 27–29, 33–35)
- Enrol laundry comment removed

## Not done

- No merge
- Playwright still deferred → ZTR-1137
- Residual depth notes from Review B (22 invalid-sig no-burn breadth; 36 re-parse inner_preimage) non-blocking
