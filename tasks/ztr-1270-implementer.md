# ZTR-1270 implementer — external send assign + multi-hub top-up

**Linear:** https://linear.app/zutopia/issue/ZTR-1270  
**Epic:** ZTR-1266  
**Depends on:** ZTR-1268 (money-capability gates) — PR #127 / `a878ab6c2`  
**Branch:** `ztr-1270-send-assign-topup`  
**Claim run:** `8750c419-37a5-4f5e-b0a3-70ba7afcadcc`

## Scope

Runtime composition (three verbs only):

1. Select free send-capable worker (`allow_external_send`, SKIP LOCKED)
2. If underfunded → `MOVE_INTERNAL` from INTERNAL_ONLY hub (exact shortfall)
3. Create `SEND_EXTERNAL` with `references_operation_id` → move id
4. Park auto-approve / formation until top-up MOVE is `INTERNAL_MOVE_LANDED`

## Freeze decisions

| Decision | Choice |
|----------|--------|
| Balance observation | Latest `gateway_observations.b_amount` for wallet (admin inventory lateral). Null worker balance ⇒ `"0"`. Null hub balance ⇒ hub skipped (fail closed). |
| Top-up amount | **Exact shortfall** (`N − worker_balance`), never full N when partial funds present. |
| Hub pick sequence | `INTERNAL_ONLY` only; observed balance ≥ shortfall; **wallet id ASC**; `FOR UPDATE SKIP LOCKED LIMIT 1`. |
| Lease groups | **Sequential separate groups** — MOVE admits first (own group); SEND binds via `references_operation_id` but acquires `SEND_SOURCE` only after move lands (workers gate). Same-group continuous transfer rejected (one-in-flight). |

## Files

- `packages/node-core/src/assign-and-topup.ts` — composition + frozen SQL (package root: send↛move boundary)
- `packages/node-core/src/index.ts` — export
- `apps/generic-node/src/money-workers/send-sql-ports.ts` — top-up readiness on auto-approve + formation candidate loads
- `packages/node-core/test/assign-and-topup.test.ts` — unit
- `packages/node-core/test/assign-and-topup.pg.test.ts` — PG
- `packages/generic-node-contracts/src/scan/forbidden-terms.ts` — exemption freeze (+6 / +6)

## AC checklist

| AC | Status | Evidence |
|----|--------|----------|
| Unfunded path MOVE then SEND; linkage durable + queryable | Done | composition + `SELECT_SEND_BY_TOPUP_MOVE` PG |
| Funded path skips MOVE | Done | `decideWorkerFunding` + funded PG readiness |
| Internal-only never send source (PG negative) | Done | hub never in worker select PG |
| Multi-hub second hub when first cannot cover | Done | isolated node PG multi-hub |
| Busy workers / hub / no funds → deterministic errors | Done | rejection codes + hub_busy / no_hub_liquidity |
| Halt blocks first formation | Done | `assertHaltAdmitsKind` before durable rows |
| Auto-approve after source known + top-up ready | Done | candidate SQL gate |
| Node never chain-submits SEND_EXTERNAL | Unchanged | no submit path |
| Load-bearing PG tests in CI | Done | `*.pg.test.ts` under vitest.pg.config |

## Out of scope

- ZTR-1271 optional `source_wallet_id` public API (composition accepts null source; route still requires id until 1271)
- Admin UI / Zukaz cutover
