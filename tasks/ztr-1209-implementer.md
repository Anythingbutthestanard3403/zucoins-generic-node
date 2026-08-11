# ZTR-1209 implementer

**PR:** #92  
**HEAD:** `8e636b044cf547574054079ff7b06d3c9da08a6b`

## Approach

Default AC: bound `*.pg.test.ts` concurrency + keep per-run scratch DB isolation.

Vitest workspace projects strip `maxWorkers` / `fileParallelism` (NonProjectOptions). The only
per-project concurrency control is `poolOptions.forks.singleFork`. Root `pnpm test` therefore
lists sibling projects:

- `packages/node-core/vitest.unit.config.ts` + `vitest.pg.config.ts`
- `apps/generic-node/vitest.unit.config.ts` + `vitest.pg.config.ts`

PG projects: `singleFork: true`, includes `*.pg.test.ts`, `*-pg.test.ts`, `pg-concurrency.test.ts`.
Unit projects exclude those globs. Package `vitest.config.ts` is an umbrella for filtered package
runs (nested projects are **not** expanded from workspace package configs — root lists files).

Also:
- `degraded_lowpriv_${pid}_${ts}` unique role in send-completion-lander (cluster-global DROP race).
- `migrate.ts` CREATE EXTENSION wrapped in DO/EXCEPTION for unique_violation (production multi-conn).
- Did **not** DO-wrap `base-enums-domains.sql` — packSql extractors take `CREATE EXTENSION…;` only.
- Docs: `docs/operations/full-suite-test-runs.md` (quiet-machine merge evidence; lane bar = targeted).

## AC

1. PG under full `pnpm test` not multi-file-parallel on one scratch DB — **yes** (singleFork projects + census).
2. Per-run scratch DB + PG_REQUIRED unchanged — **yes** (`vitest.global-setup.ts` untouched).
3. Quiet-machine full-run documented — **yes**.
4. Targeted suites remain lane bar — **yes** (docs).
5. Two consecutive stable passes on ticket-listed flaky files — **yes** (see evidence).

## Evidence (at `8e636b044cf547574054079ff7b06d3c9da08a6b` after rebase on origin/main)

| Batch | Files | Result |
| --- | --- | --- |
| ev1 | census + sql-recovery + attention-retraction + metrics-deadline | 5 files / 49 tests PASS |
| ev2 | same | 5 files / 49 tests PASS |
| ev3 | lander + receive-settle + recovery-ceremony | 3 files PASS (lander 17, settle 7, ceremony 1) |
| ev4 | same | 3 files / 25 tests PASS |
| ev5 | wallet-settled-ledger-writer + overlap-crash-handoff | 2 files / 32 tests PASS |
| ev6 | same | 2 files / 32 tests PASS |
| migrate-guards | after migrate.ts race wrap | 15/15 PASS |
| tsc -b | root | exit 0 |
| lint node-core / generic-node | | 0 errors |

Census gate: `vitest-network-guard.census.test.ts` asserts root lists unit+pg configs and every
`vitest.pg.config.ts` has `singleFork: true`.

## Spec / decisions

No named governing product spec — test harness / ops runbook. Used sweeper AC on ticket +
`vitest.global-setup.ts` PG_REQUIRED contract. No `docs/decisions/D*` load required.

## Deferred

- Full multi-hour `pnpm test` wall-clock not re-run end-to-end in this lane (host shared with other
  lanes); targeted two-pass stability on previously flaky files is the evidence bar.
- Intra-file timing flakes (e.g. overlap latch under extreme host load) remain possible; multi-lane
  host load still needs quiet-machine for merge evidence.
