# ZTR-1209 implementer rebase r2 (PR #92)

- **lane:** implementer
- **run:** `7be9a03f-0b91-473a-9701-dc8a6d855c38`
- **prior dual-void head:** `76ba7637f6f01f5e846763b7cc219a88f7b18190`
- **new HEAD:** `SEE_TIP_AFTER_PUSH`
- **product commit:** `c421cbcfe2b8bde6d5177163f91dfcb981bcb7ac` (serialize PG suites; verify bar)
- **base:** `origin/main` @ `7617099405ea709203e551b2b34942e2136abe88`
- **PR:** #92 (`ztr-1209-pg-flakiness`)
- **worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1209-rebase2`
- **local branch during rebase:** `ztr-1209-pg-flakiness-rebase2` → force-with-lease pushed to `origin/ztr-1209-pg-flakiness`

## Why

PR #92 was CONFLICTING after main advanced past dual head `76ba7637`. Prior dual incomplete
(B PASS posted; A only in tasks) — rebase voids any dual anyway. Fresh dual required.

## Commits after rebase

```
3298225a docs(tasks): ZTR-1209 implementer rebase handoff
6be8cce6 docs(tasks): ZTR-1209 final HEAD pin
b605876d docs(tasks): ZTR-1209 PR #92 + final HEAD
02e7041f docs(tasks): ZTR-1209 implementer evidence
c421cbcf fix(vitest): serialize PG suites to end full-suite deadlock flakes (ZTR-1209)
(plus this handoff commit)
```

## Conflicts (commit 1/5 only: product admit)

### `docs/operations/README.md` — keep **both**

| Concern | Resolution |
|---------|------------|
| Main | Row for `push-action-suffix-rotation.md` (ZTR-1207) |
| ZTR-1209 | Row for `full-suite-test-runs.md` |

### Other files — auto-merged clean

README.md, migrate.ts, vitest splits, census, send-completion-lander — no manual conflict
on this rebase (prior r1 already absorbed ZTR-1204 README + ZTR-1215 migrate logger).

## Product work preserved

- Root + package vitest split: unit vs pg projects (`poolOptions.forks.singleFork` on pg)
- Census asserts root lists unit+pg configs and `singleFork`
- Unique `degraded_lowpriv_*` role in send-completion-lander
- Race-safe pgcrypto provision in `migrate.ts`
- Ops doc `docs/operations/full-suite-test-runs.md` + ops index link (both rows)
- Main's README multi-lane `TEST_DATABASE_URL` guidance retained
- Main's push-action-suffix-rotation ops index row retained

## Local verify (PASS) @ product `c421cbcfe2b8bde6d5177163f91dfcb981bcb7ac`

| Command | Result |
|---------|--------|
| `pnpm install` (CI=true --force) | ok |
| `tsc -b` | exit 0 |
| node-core `vitest-network-guard.census.test.ts` | **5/5** |
| gn `test/db/migrate-guards.test.ts` | **15/15** |

## Push

`git push --force-with-lease origin HEAD:ztr-1209-pg-flakiness`

Dual must re-run — rebase voids prior dual.
