# ZTR-1183 implementer report

**Head SHA:** `57653fb0333a18c3caa5c8f96fcb0d0f774784d0`
**Branch:** `ztr-1183-backup-leadership`
**PR:** (filled after create)

## Governing

- Boot-lane dispositions (`apps/generic-node/src/boot/boot-lane.ts` — `dispositionForIncompleteBoot`)
- Custody composition root (`apps/generic-node/src/main.ts`)
- Backup scheduler (`apps/generic-node/src/dr/schedule.ts`)
- Ticket: audit 2026-08-06 §7 concurrent `pg_dump` / incomplete-boot start

## Acceptance

| # | Criterion | Status |
|---|-----------|--------|
| 1 | Scheduler starts only when this node holds leadership | **satisfied** — `main.ts` starts only on `result.ready` (leadership held + money workers started); `isLeader: () => shutdownRegistry.authority.held` re-checked each loop |
| 2 | Incomplete boot does not start scheduler | **satisfied** — quarantine / exit-for-reacquire / liveness-only all `return` before create/start |
| 3 | Multi-replica safe: followers do not beginTrackedRun | **satisfied** — follower boot fails leadership acquire → liveness-only return; if leadership lost mid-run, next iteration skips |
| 4 | Tests prove gates | **satisfied** — schedule unit (standby start no-op, mid-loop loss, ownership/RPO), graceful-stop structural composition, admin standby optional, CLI restore/drill/status fail-closed + status posture |
| 5 | Gates green at exact SHA | **satisfied for changed surface** — see evidence |

Secondary CLI coverage expanded without ballooning (fail-closed restore/drill/status + empty-dir / envelope discovery). No `*.pg.test.ts` DR CLI added (would balloon).

## Files

| File | Why |
|------|-----|
| `apps/generic-node/src/dr/schedule.ts` | `isLeader` gate; `ownership` on status; RPO owner-only |
| `apps/generic-node/src/main.ts` | Ready-only start; liveness-only explicit return; wire `isLeader`; status ownership |
| `apps/generic-node/src/dr/index.ts` | Export `BackupScheduleOwnership` |
| `apps/generic-node/src/admin-readiness.ts` | Standby distinct from RPO failure |
| `apps/generic-node/src/admin-router.ts` | Probe type includes ownership |
| `apps/generic-node/src/metrics/snapshot-source.ts` | Optional ownership on backupStatus |
| `apps/generic-node/test/dr/schedule.test.ts` | Leadership unit gates |
| `apps/generic-node/test/dr/cli.test.ts` | restore/drill/status CLI coverage |
| `apps/generic-node/test/graceful-stop.test.ts` | Composition structural ratchet |
| `apps/generic-node/test/admin-readiness.test.ts` | Standby → optional |

## Evidence at `57653fb0333a18c3caa5c8f96fcb0d0f774784d0`

```
pnpm install          # CI=true --force; lockfile up to date; 399 packages
tsc -b                # TypeScript: No errors found
pnpm --filter @zucoins/generic-node lint   # eslint src test — exit 0
pnpm test:boundaries  # 5 files, 162 tests passed
```

Targeted / related:

```
test/dr/schedule.test.ts          9 passed (incl. 5 leadership)
test/dr/cli.test.ts               8 passed
test/graceful-stop.test.ts       39 passed (incl. ZTR-1183 structural)
test/admin-readiness.test.ts     14 passed (standby optional)
test/dr/* + boot-lane + graceful  16 files / 150 passed
```

Full `pnpm --filter @zucoins/generic-node test`:
- Run 1: 1292 passed, 1 failed (`metrics-postgres-deadline.pg` flake) + suite fail `receive-settle-step.pg` (`digest(bytea, unknown)` env)
- Run 2: 1273 passed, suite fail `sql-recovery-store.pg` (same `digest` / pgcrypto env race)
- Isolated re-runs of both flake suites: **pass** (7/7 settle, 1/1 metrics)
- Untouched by this diff; pre-existing PG schema-setup race under parallel load

## Deferred

- Stage 1 (`stage1-main.ts`) has no signer leadership by design — single-writer backup remains; not multi-replica custody.
- No second advisory lock; reuses signer leadership latch (ticket recommended option).
- Full PG-backed CLI restore/drill integration not added (ticket: expand only if in scope without ballooning).
