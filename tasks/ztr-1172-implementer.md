# ZTR-1172 implementer

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/68
- **Product fix SHA:** `e81ddf9283221771bfbe7f4578fec52ddcdbb501`
- **Head SHA:** `5e78054b5337af26c20e03d1de84bd432d943e27`
- **Worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1172-impl/`
- **Claim:** implementer run=`ba405bf6-dd43-4f33-bab0-12e6f996acd7`
- **Governing:** doc 09 §7.1 / §7.7; `docs/operations/restore.md`; readiness `RESTORE_HOLD_READINESS`

## Acceptance

| AC | Status |
|---|---|
| `dr drill` restores real node backup into throwaway DB and boots against it | Yes — dual-gate schema seed, dual force, readiness probe |
| Drill fails (not no-op) when reporting schema absent | Yes — `ReportingSchemaAbsentError` |
| Drill records RPO and RTO evidence | Yes — `rpoMs`/`rpoStatement`/`durationMs` |
| Fault-injection cases 2–6 exist and assert refusal | Yes — `restore-fault-injection.pg.test.ts` |
| `restore_hold` readiness decision implemented + machine-readable | Yes — gating `restore_hold_clear` + `RESTORE_HOLD_READINESS` |
| Boot queue rebuild implemented or restart proof | Yes — process-local seeds + unit proof |
| Drill runnable in CI (ZTR-1137) | Yes — PG-gated like other DR tests |

## Files

- `apps/generic-node/src/dr/drill.ts` + `drill-node-schema.ts` — real dual-gate drill
- `hold-db-orchestration.ts` / `restore-hold.ts` / `auth-hold.ts` — absent schema fails; orphan head refuse
- readiness contracts + `NodeCoreReadinessState` + health evaluator + shell stamp
- `sql-boot-recovery.ts` — seedReconcileCursor / rebuildReceiveAdmissionQueue materialise seeds
- `main.ts` — `stampRestoreHoldFromDb` post-migration
- tests: fault injection, boot seeds, hold orchestration, health probes, census/gen
- docs: `docs/operations/restore.md`, `README.md`

## Verification (exact head)

```
pnpm exec tsc -b                                 # exit 0
pnpm --filter @zucoins/generic-node-contracts exec vitest run src/readiness
# 9 files / 68 passed
pnpm --filter @zucoins/node-core exec vitest run test/health-probes.test.ts
# 1 file / 35 passed
pnpm --filter @zucoins/generic-node exec vitest run test/dr test/boot-queue-rebuild.test.ts test/metrics-snapshot-source.test.ts test/metrics-postgres-deadline.pg.test.ts
# 17 files / 115 passed
eslint on touched paths                          # 0 errors
```

## Residuals

- Case 5 full parent/child correlation still sequenced with ZTR-1133 (constraint-class proven; full reporting dump case partial).
- Boot seed is process-local handoff; stream writer still loads durable priors on first tick (now proven equal when hydrate runs).
