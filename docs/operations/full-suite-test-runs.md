# Full-suite test runs (`pnpm test`)

## What a green full suite means

`pnpm test` at the repo root runs every Vitest project (contracts, node-core unit + pg,
generic-node unit + pg, consumers, operator SPA). Real-PostgreSQL suites
(`*.pg.test.ts`, `*-pg.test.ts`, and a few historical names) live in dedicated
`vitest.pg.config.ts` projects that **serialize file execution** (`poolOptions.forks.singleFork`).
Non-PG suites keep file parallelism.

Per-run scratch databases are still named `testdb_<pid>_<timestamp>` by
`vitest.global-setup.ts`. `PG_REQUIRED=1` still fails closed when Postgres is missing or a
PG suite's `beforeAll` never becomes ready — that semantics is unchanged.

## Lane-level bar vs merge evidence

| Purpose | Expectation |
| --- | --- |
| Implementer / reviewer lane | **Targeted suites** for the files you touched. Do not treat a noisy full-suite red on an unrelated PG file as your regression without an isolated re-run. |
| Merge / release evidence | A **quiet-machine** full `pnpm test` (no other full-suite lanes sharing the host Postgres). Residual flakes under multi-lane host load are orchestration noise, not a product defect. |

## Why PG files are serialized

Under multi-file parallel execution, suites sharing one scratch Postgres (and sometimes
cluster-global objects such as extensions or roles) produced deadlocks, `CREATE EXTENSION`
unique violations, worker `onTaskUpdate` timeouts, and run-to-run failure drift on an
identical tree. Serializing PG projects removes intra-run multi-file contention. It does
**not** isolate two concurrent `pnpm test` processes on one machine — for that, use a quiet
host or separate Postgres instances.

## Related

- Ticket ZTR-1209 (pg flakiness under parallel lane contention)
- ZTR-1204 (provisioning ETIMEDOUT / filtered-run bypass) — distinct failure class
