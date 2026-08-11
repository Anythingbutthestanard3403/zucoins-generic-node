# ZTR-1214 r2 — Review B FAIL clear (implementer)

**PR:** #77  
**HEAD:** `703fa74d2b79b465638ca929d4657a5dc179de24`  
**Base:** rebased onto `origin/main` (`ff22f0a`) before fix commit  
**Prior FAIL head:** `bcfb3a9cfc660a3277a9a997d93e1af7e9a7e4f3`  
**Governing:** doc 01 §4.2 dual-control; peer ZTR-1143 device-signature fail-closed; Review B `tasks/ztr-1214-review-B.md` D1–D4

## Blocking defects cleared

| # | Defect | Fix |
|---|---|---|
| D1 | Unreadable `node_settings` weakened to `defaultMode` (often `single_operator`) | `createSqlDualControlPolicy.getMode`: `!raw.ok` → **`two_human`**; setMode previous on fault also `two_human` |
| D2 | Missing `dualControlPolicy` on approve/challenge/GET → `"single_operator"` | All three sites fail closed to **`two_human`** (+ try/catch like device-sig) |
| D3 | Boot log env-only while claiming effective | `main.ts` awaits `adminRouteDeps.dualControlPolicy.getMode()`; logs `env=` + `effective=` |
| D4 | InMemory `setMode` meta optional / audit mute | `meta` required; always pushes audit; default ctor mode `two_human` (fail-closed lab) |

## Acceptance (ticket)

| # | Criterion | r2 |
|---|---|---|
| 1 | Schema slice + contract; pack ≥ v100 | still MET (unchanged pack 157) |
| 2 | Guarded POST + audit; GET remains | still MET |
| 3 | DB-backed SERIALIZABLE TX | still MET |
| 4 | Device-sig durable home | N/A (peer already on main) |
| 5 | Wiring dualControlMode | still MET |
| 6 | Boot log **effective** mode + tests | **MET** (D3) |

## Tests added/updated

- `dual-control-policy.test.ts`: unreadable + `defaultMode: single_operator` → `two_human`; InMemory default + required meta
- `admin-g4-device-dual-push.test.ts`: omit port → GET `two_human`; approve same-operator → `same_operator_both_sides`; challenge dual_control mode `two_human`
- `dual-control-mode-wiring.test.ts`: census that boot log calls `getMode` and prints env+effective

## Verify at `703fa74d2b79b465638ca929d4657a5dc179de24`

| Command | Result |
|---|---|
| `CI=true pnpm install --frozen-lockfile` | ok |
| `pnpm exec tsc -b` | exit 0 |
| `vitest` dual-control-policy.test.ts | **27/27** |
| `vitest` money-schema-pack.test.ts | **18/18** |
| `vitest` dual-control-mode-wiring + admin-g4 + config-mutable + never-403 | **48/48** |
| eslint touched sources | 0 errors |

Note: vitest process may exit non-zero on globalSetup teardown `psql ETIMEDOUT` DROP DATABASE; test body counts above are green before teardown.

## Files touched (r2)

- `packages/node-core/src/send/dual-control-policy.ts`
- `packages/node-core/src/send/dual-control-policy.test.ts`
- `apps/generic-node/src/admin-router.ts`
- `apps/generic-node/src/main.ts`
- `apps/generic-node/test/admin-g4-device-dual-push.test.ts`
- `apps/generic-node/test/dual-control-mode-wiring.test.ts`

## Deferred

- None for D1–D4. SPA still GET-only for dual-control (out of ticket).
