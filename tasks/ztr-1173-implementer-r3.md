# ZTR-1173 — implementer r3 (Review B r2 rework)

**Code commit:** `6d2d8167bb0189b9bf58eb04b9810319ed374460` (test/gates change)
**Branch:** `ztr-1173-test-gate-integrity`
**PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/69
**Prior FAIL:** Review B r2 @ `eaa5a59757a90c63524f84394bb94ffd581d9b04` (`tasks/ztr-1173-review-B-r2.md`)
**Run:** `437ebfe8-a789-431f-9e30-2c03379be96a`

## Blocking items addressed

| Attack | Fix |
|---|---|
| A1 Census still comment-launderable | Census requires executable `it("DB-TEST-NN…")` / `discharges("DB-TEST-NN…")` (comment-only refused). Tokens on title+callback after comment strip (majority). Synthetic pg+comment pin. All 36 rows have named `it` titles. |
| A3′ / DB-TEST-23 comment-only on enrol | Real PG race in discharge suite: seed epoch-1 head; competing KEY_ROTATED epoch-2 first-valid-commit (UNIQUE+advance CAS); stale admission closed; AUTH_HOLD_SET closes admission; single head. Matrix re-cites discharge; enrol laundry removed. |
| PG guard miswire | `registerPgRequiredGuard({ name, databaseUrl, isReady })` at EOF; node-core `globalSetup`. Empty URL + PG_REQUIRED=1 → guard FAIL. |

## Verify @ code commit 6d2d816

```
pnpm exec vitest run --config packages/node-core/vitest.config.ts   test/mandatory-database-tests.census.test.ts   test/mandatory-db-discharge-21-36.pg.test.ts   test/live-chain/live-ops.census.test.ts   test/live-chain/types.test.ts   test/live-chain/move-execute.test.ts
# → 5 files, 43 passed

PG_REQUIRED=1 … mandatory-db-discharge-21-36.pg.test.ts  # → 11 passed
TEST_DATABASE_URL= PG_REQUIRED=1 …                      # → guard FAIL
dependency-boundary                                      # → 37 passed
empty live filter                                        # → exit 1
```

## Not done
No merge. Playwright → ZTR-1137.
