# ZTR-1165 implementation

**Head SHA:** `938bba18eabf4419dcd816f66f3d50d30b93d595`
**Branch:** `ztr-1165-approve-recovery-catalog`
**Base:** `origin/main` @ `a4bb21e3fc3144cf2d8de0d42a1ffeb873d7fabe`

## Governing surface

- Frozen catalog: `packages/generic-node-contracts/src/operator-halt/halt.contract.ts` — `OPERATOR_RECOVERY_ACTIONS` (9) + `RESERVED_RECOVERY_ACTIONS` (2)
- Audit source: `tasks/audit-2026-08-06.md` §6 first bullet

## Acceptance

| Criterion | Status |
| --- | --- |
| `IMPLEMENTED_RECOVERY_ACTIONS` deleted from ApproveInboxPage; render + mutation use `partitionRecoveryActions` / `isLiveRecoveryAction` | yes |
| `REDELIVER_EXACT_PARTIAL`, `CONTINUE_EXTERNAL_WAIT`, `CLOSE_NEVER_STARTED_EXTERNAL_SEND` clickable when permitted | yes |
| Reserved kinds disabled with reserved-specific reason; never POSTed | yes |
| Unknown action unavailable with "not implemented on this node" reason; never POSTed | yes |
| SPA live ∪ reserved equals contract `OPERATOR_RECOVERY_ACTIONS` (test) | yes |
| contracts runtime dep + operator-halt subpath; vitest aliases in node-core + generic-node above package-root | yes (`@zucoins/generic-node-contracts` was already a runtime dep of the SPA) |
| `pnpm --filter @zucoins/generic-node-ui test` green | 40 files / 318 tests |
| `pnpm test` / `pnpm test:boundaries` | shell-import allowlist test green (71); full `pnpm test:boundaries` still red on pre-existing forbidden-terms hits outside this diff (leadership.test drain, operations-indexes sweep, implementer-events order, markers ORDER BY); transaction-isolation.census also red on main baseline (sql-observation-persistence undeclared BEGIN) |

## Verification (at head)

```
pnpm install
pnpm --filter @zucoins/generic-node-contracts build
pnpm exec tsc -b                          # clean
pnpm --filter @zucoins/generic-node-ui test
# Test Files 40 passed (40) / Tests 318 passed (318)
pnpm --filter @zucoins/generic-node-ui build   # ok; index chunk ~308 kB under 320 limit
pnpm --filter @zucoins/generic-node-ui lint    # clean
pnpm --filter @zucoins/generic-node lint       # clean
pnpm --filter @zucoins/node-core exec vitest run test/boundaries.test.ts
# 71 passed
pnpm --filter @zucoins/generic-node-contracts exec vitest run src/operator-halt
# 39 passed
```

## Files

- `packages/generic-node-contracts/src/operator-halt/index.ts` — new leaf subpath barrel
- `packages/generic-node-contracts/package.json` — `./operator-halt` export
- `packages/node-core/vitest.config.ts` + `apps/generic-node/vitest.config.ts` — source aliases above package-root
- `packages/node-core/test/boundaries.test.ts` — allow `operator-halt` (+ pre-existing `observation` import already in app shell)
- `apps/generic-node/admin/src/lib/money.ts` — LIVE = catalog − RESERVED; re-export OPERATOR
- `apps/generic-node/admin/src/lib/money.test.ts` — equality gate
- `apps/generic-node/admin/src/pages/approve/ApproveInboxPage.tsx` — delete stale set; partition helpers
- `apps/generic-node/admin/src/pages/approve/ApproveInboxPage.test.tsx` — live/reserved/unknown UI assertions
- `apps/generic-node/src/operations/sql-recovery-store.ts` — IMPLEMENTED_EFFECT_KINDS / LAUNCH_RESERVED from contract

## Deferred

None for ticket scope. Pre-existing main reds (forbidden-terms scan-gate, transaction-isolation census drift) not introduced here.
