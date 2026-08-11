# ZTR-1173 — implementer r2 (Review B rework)

**Head SHA:** `d2f3d3f72ae7b837d60e170dcf6d23794bb65df8`
**Branch:** `ztr-1173-test-gate-integrity`
**PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/69
**Prior FAIL:** Review B @ `a052b5df49ed20c12566b68706dcf219083a1428`

## Blocking items addressed

| Attack | Fix |
|---|---|
| A1 Census launder (`.pg.test.ts` suffix alone) | `exercisesPostgres()` now requires body opens PG; every row needs per-id marker `// DB-TEST-NN:` or `it("DB-TEST-NN…")`; distinctive requirement-token check |
| A2 DB-TEST-21..26 comment-only on mutation-correlation | Re-cited to new PG suite with real asserts (UNIQUE nonce purpose cross-claim, admission closed / burn retain+immutable, idempotency key CHECK, guarded fingerprint, composite FK) |
| A3 DB-TEST-30..32 comment-only time windows | Real CHECK rejects: unknown enum, illegal FIRST_KEY edge, register shape, 60s/300s windows, KEY_ROTATED overlap ≠ +24h |
| A4 DB-TEST-36 no whole-second assertion | `insertSignIntent` + assert `redemption_expiry_at = date_trunc('second', …)` and equals `redemptionExpiryAtFromSecs` whole-second RFC3339 |

## Acceptance

| Criterion | Status |
|---|---|
| 36 mandatory DB tests cite PG-exercising artifact that asserts the row | satisfied — matrix + census markers + new discharge suite |
| dependency-boundary unchanged | satisfied — 37/37 |
| move-execute.live + live-ops census / passWithNoTests false | holds from r1 |
| D10.4 / admin SPA / Playwright→1137 | holds from r1 |

## Governing spec

- `docs/proposals/generic-node-redesign-v2/04-data-model.md` §16
- `docs/proposals/generic-node-redesign-v2/mandatory-database-tests.md` §3.18

## Verify (this head)

```
tsc -b                                # clean
pnpm exec vitest run --config packages/node-core/vitest.config.ts \
  test/mandatory-database-tests.census.test.ts \
  test/mandatory-db-discharge-21-36.pg.test.ts \
  test/live-chain/live-ops.census.test.ts \
  test/live-chain/types.test.ts \
  test/live-chain/move-execute.test.ts
# → 5 files, 41 passed
pnpm exec vitest run --config packages/generic-node-contracts/vitest.config.ts \
  src/scan/dependency-boundary.test.ts
# → 37 passed
pnpm exec vitest run --config packages/node-core/vitest.live-chain.config.ts \
  test/live-chain/this-does-not-exist.live.test.ts
# → exit 1, No test files found (passWithNoTests: false)
```

## Files

- `packages/node-core/test/mandatory-database-tests.census.test.ts` — tightened census
- `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` — new PG asserts for 21–26, 30–32, 36
- `docs/proposals/generic-node-redesign-v2/mandatory-database-tests.md` — re-cite repaired rows
- Per-id `// DB-TEST-NN:` markers on remaining 27 cited suites
- Laundry headers removed from mutation-correlation / reporting-key-enrol

## Not done

- No merge
- Playwright still deferred → ZTR-1137
