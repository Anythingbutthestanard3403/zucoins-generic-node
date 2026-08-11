# ZTR-1209 implementer rebase (PR #92)

- **lane:** implementer
- **run:** `7be9a03f-0b91-473a-9701-dc8a6d855c38`
- **prior dual VOID head:** `fc05a041af9c62c5f67997553204f2cb470ef9e8`
- **new HEAD:** `593cf578de2d89b25f2ea0ff1274681ce13f6856`
- **product commit:** `01a6990fddbc69dbdeeecb8d9eb2935866ef938c` (serialize PG suites; verify bar)
- **base:** `origin/main` @ `dac8a97ccfbedba730672a3fa2cc2263db46e8fe`
- **PR:** #92 (`ztr-1209-pg-flakiness`)
- **worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1209-rebase`
- **local branch during rebase:** `ztr-1209-pg-flakiness-rebase` → force-with-lease pushed to `origin/ztr-1209-pg-flakiness`

## Why

PR #92 was CONFLICTING after main moved (README PG test section from ZTR-1204 lane
pinning; migrate.ts CLI safe-logger from ZTR-1215). Prior dual PASS at `fc05a041` is void after rebase.

## Commits after rebase

```
593cf578 docs(tasks): ZTR-1209 implementer rebase handoff
69c60a4d docs(tasks): ZTR-1209 final HEAD pin
68f83196 docs(tasks): ZTR-1209 PR #92 + final HEAD
fd92a69a docs(tasks): ZTR-1209 implementer evidence
01a6990f fix(vitest): serialize PG suites to end full-suite deadlock flakes (ZTR-1209)
```

## Conflicts (commit 1/4 only: product admit)

### `README.md` — keep **both**

| Concern | Resolution |
|---------|------------|
| Main | Full `### PostgreSQL for tests (TEST_DATABASE_URL)` section (CI `PG_REQUIRED`, per-lane pin, empty-export semantics, ZTR-1204 backoff) |
| ZTR-1209 | Bullet: full-suite PG serialized via `vitest.pg.config.ts` + `singleFork`; link to `docs/operations/full-suite-test-runs.md` |

### `apps/generic-node/src/db/migrate.ts` — auto-merged clean

| Concern | Resolution |
|---------|------------|
| Main later | CLI uses `createSafeConsoleLogger` / `safeFormatError` (ZTR-1215) |
| ZTR-1209 | Race-safe pgcrypto `DO $$` wrap with `unique_violation` / `duplicate_object` handlers |

Original docs commits 2–4 replayed cleanly; this handoff is the rebase tip.

## Product work preserved

- Root + package vitest split: unit vs pg projects (`poolOptions.forks.singleFork` on pg)
- Census asserts root lists unit+pg configs and `singleFork`
- Unique `degraded_lowpriv_*` role in send-completion-lander
- Race-safe pgcrypto provision in `migrate.ts`
- Ops doc `docs/operations/full-suite-test-runs.md` + ops index link
- Main's README multi-lane `TEST_DATABASE_URL` guidance retained

## Local verify (PASS) @ product `01a6990fddbc69dbdeeecb8d9eb2935866ef938c`

| Command | Result |
|---------|--------|
| `pnpm install` (CI=true --force) | ok |
| `tsc -b` | exit 0 |
| `pnpm --filter @zucoins/node-core lint` | 0 errors (5 pre-existing warnings) |
| `pnpm --filter @zucoins/generic-node lint` | clean |
| node-core `vitest-network-guard.census.test.ts` | **5/5** |
| gn `test/db/migrate-guards.test.ts` | **15/15** |

## Push

`git push --force-with-lease origin HEAD:ztr-1209-pg-flakiness`

Dual must re-run — rebase voids prior dual PASS.
