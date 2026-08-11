# ZTR-1214 — Dual-control policy guarded DB mutation (implementer)

**PR:** (filled after open)  
**HEAD:** (filled after push)  
**Governing:** doc 01 §4.2 dual-control; deferred criterion from ZTR-1148; CONVENTIONS §1 SERIALIZABLE admin mutation TX; pattern peer ZTR-1143 device-signature policy.

## Acceptance

| # | Criterion | Status |
|---|---|---|
| 1 | Schema slice + `.contract.ts` for durable dual-control home; money-pack migration ≥ v100 | **met** — `dual-control-policy.sql` + contract; pack slice index 57 → version **157** |
| 2 | Guarded admin mutation: fresh TOTP + `audit_log` on change; GET remains | **met** — `POST /admin/v1/dual-control-policy` via `runGuardedAdminMutation` + TX `setMode`; GET unchanged |
| 3 | Mode survives restart (DB-backed); SERIALIZABLE mutation TX | **met** — `node_settings` key `ops.dual_control_mode`; writes on TX PoolClient; PG rollback proof |
| 4 | Companion `requireDeviceSignature` durable home | **already met** on main (ZTR-1143) — no second surface built |
| 5 | Wiring assertion `main.ts` → `dualControlMode: config.DUAL_CONTROL_MODE` | **met** — existing `dual-control-mode-wiring.test.ts` kept; SQL defaultMode uses that value when row absent |
| 6 | Boot log effective mode; tests mutation + audit + durability | **met** — `node: dual-control mode=…`; unit + G4 POST + atomic rollback |

## Design

- **Pre-mutation:** boot-validated `DUAL_CONTROL_MODE` is `createSqlDualControlPolicy` `defaultMode` when `node_settings` row is absent (cold apply does **not** seed a default — avoids silently rewriting `two_human` deployments).
- **Post-mutation:** durable row is source of truth; corrupt stored values resolve to `two_human` (never weaken).
- **Audit:** single CTE statement upserts settings + inserts `audit_log` action `ops.dual_control_mode_changed` (same shape as device-signature).
- **TX:** `portsFor` binds TX-scoped SQL dual-control policy so ROLLBACK undoes settings+audit with idempotency row.

## Files

- `packages/node-core/src/send/dual-control-policy.ts` (+ test) — SQL port, setMode meta, effective mode
- `packages/node-core/src/schema/dual-control-policy.{sql,contract.ts}` + money-pack order
- `apps/generic-node/src/{full-http-mount,admin-router,main,config/mutable}.ts`
- Tests: G4 POST, wiring async getMode, atomic PG rollback, migration GREENFIELD

## Verify (at push SHA)

- `pnpm install` — ok
- `tsc -b` — clean
- node-core: dual-control 25/25; money-schema-pack + migration-integrity 28/28
- generic-node: dual-control wiring + G4 + never-403 + config-mutable 45/45; atomic + route-policies + config-schema 99/99
- lint node-core / generic-node — 0 errors
- `pnpm --filter @zucoins/node-core build` — copy-schema-sql 61 slices

## Deferred / notes

- Non-blocking ZTR-1148 note on `config-schema.test.ts` “never echo input” not folded (orthogonal).
- Env `DUAL_CONTROL_MODE` remains immutable via settings write path; runtime change is POST only.
