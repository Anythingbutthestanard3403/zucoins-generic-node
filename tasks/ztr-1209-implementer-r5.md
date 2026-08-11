# ZTR-1209 implementer r5

**PR:** #92  
**Claim run:** `7be9a03f-0b91-473a-9701-dc8a6d855c38`  
**Code HEAD:** `8c58c835f3629bfe36cadcf0712cf60b32e0a953`  
**Base:** origin/main @ `dc730ef00008bb20178a4f864893664c7b8c4095` (includes #91)

## FAIL binding closed

B r4 FAIL @ `3c19baa34a04a974adf824af7d36e17d1dfb686c` — `tasks/ztr-1209-review-B-r4.md`

| Defect | Fix |
| --- | --- |
| 1 unit-pool real-PG parallelism | Non-suffix live openers listed in `vitest.pg.config.ts` include + unit exclude (node-core 9 files, generic-node 9 files). All ride `poolOptions.forks.singleFork`. |
| 2 census suffix-shaped | `vitest-network-guard.census.test.ts`: unit exclude ↔ pg include lockstep for inventory; tree scan for strong openers (`new Pool` / `from 'pg'` / `runMigrationsOnPool` / `CREATE DATABASE` / `execFileSync/spawn('psql')`) outside singleFork → red. |
| 3 sql-recovery red / dishonest AC5 | PACK_SLICES gains `expected-artifacts` (ZTR-1208 sole owner); `node_signing_keys` id-only stub in FK_TARGET_STUBS; fixture seeds signing key before artifact insert. AC5 batches re-proven ×2 green. |

## Also (rebase hygiene)

- Rebased onto origin/main (post-#91).
- Vitest aliases: `@zucoins/generic-node-contracts/operations/events` before `…/operations` in both unit configs (prefix-match swallow after main landed `durable-events-nine-types.pg.test.ts`).

## Evidence @ `8c58c835f3629bfe36cadcf0712cf60b32e0a953`

| Batch | Result |
| --- | --- |
| census (unit config) ×2 | **7/7** PASS both |
| sql-recovery + attention + metrics ×2 | **37/37** PASS both (`PG_REQUIRED=1`, gn pg config) |
| lander + receive-settle + recovery-ceremony ×2 | **25/25** PASS both |
| wallet-settled-ledger-writer + chaos/overlap-crash-handoff ×2 | **32/32** PASS both (nc pg config) |
| migrate-guards (now pg project) | **15/15** PASS |
| `tsc -b` | exit 0 |
| unit list: zero live non-suffix / `.pg` names | confirmed |
| pg list: all inventory files present | confirmed |

## AC scorecard

| # | Result |
| --- | --- |
| 1 PG not multi-file-parallel on shared scratch | **PASS** — class coverage under singleFork |
| 2 scratch DB + PG_REQUIRED | **PASS** (untouched) |
| 3 quiet-machine docs | **PASS** (prior) |
| 4 targeted = lane bar | **PASS** (prior) |
| 5 two consecutive green on cited flaky set | **PASS** — 37+25+32 all ×2; census 7/7 ×2 |

## Inventory (non-suffix → pg singleFork)

**node-core:** capture.concurrency, quarantine.integration, custody-eligibility-lease-pk, degraded-mode.fault, disk-db-exhaustion.fault, migration-integrity, observation-migration-integrity, operation-lifecycle-concurrency, registry-isolation-rotation

**generic-node:** migrate-guards, migration-lock, overlap-guard, genesis-t0-observer, arm-live-composition, durable-store, production-destinations-list, production-durable-mount, production-reporting-stream

## Deferred

- Full multi-hour `pnpm test` wall-clock not re-run on shared host.
- Mock-only `postgres-deadline.test.ts` stays unit (allowlisted in census).
