# Wallet money capabilities (hubs and workers)

How to designate **internal-only hubs** and **send / receive workers** on a live
custody node, fund hubs, verify modes, and rebalance when automation is paused.

This is the operator companion to the money-capability epic (ZTR-1266) and the
acceptance suite (ZTR-1273). Product constraint: exactly three money verbs —
`RECEIVE_EXTERNAL`, `MOVE_INTERNAL`, `SEND_EXTERNAL`. There is no fourth verb and
no separate “float node” type.

Related:

| Surface | Where |
| --- | --- |
| Admin SPA | Wallets → money mode control |
| Mutation API | `PATCH /admin/v1/wallets/:id/money-capability` (session + CSRF + fresh TOTP + CAS `expected_row_version`) |
| Auto-funded external send | [`auto-approve-external-sends.md`](auto-approve-external-sends.md) (omit `source_wallet_id`) |
| Attention triage | [`attention-triage.md`](attention-triage.md) — composition failure modes |
| Implementer cutover | [`zukaz-source-omit-cutover.md`](zukaz-source-omit-cutover.md) |
| Acceptance matrix | `packages/node-core/test/money-capability-acceptance.matrix.test.ts` |

## Modes (presets)

| Mode | External receive | External send | Internal move | Typical role |
| --- | --- | --- | --- | --- |
| **Receive-only** | yes | no | yes | Inbound pool worker |
| **Send-only** | no | yes | yes | Send worker (may receive hub top-ups) |
| **Internal-only** | no | no | yes | Hub / float — **never** an external send source |
| **Full** | yes | yes | yes | Small fleets / break-glass |

Multiple internal-only hubs are allowed and expected. The node picks hubs by
observed balance ≥ shortfall, wallet id ascending, `FOR UPDATE SKIP LOCKED`.

## Designate hubs and workers

1. Open **Wallets** on the admin SPA (or call the inventory API).
2. Confirm each wallet is recovery-verified and in a healthy standing state
   before funding it for live work.
3. Set mode via the money-mode control:
   - Hubs → **Internal-only**
   - Send workers → **Send-only** (or Full only if you intentionally want
     the same wallet in both pools)
   - Inbound workers → **Receive-only**
4. Save with a fresh TOTP. The response echoes flags + bumped `row_version`.
5. Re-read the wallet row and confirm `money_mode` and the three allow flags
   match the table above.

## Bless an existing wallet (do not mint another sink)

Every node-generated mint (destination register, pool scale-up, funding CREATE)
now inserts a `destinations` row in `PENDING`. Blessing stays dual-control
(device + TOTP). You do **not** create a new destination to get a sink for an
already-minted worker.

1. Open **Destinations** on the admin SPA (`GET /v1/destinations`).
2. Find the row whose `wallet_id` is the existing worker (or the dest id from
   the fleet query below). State will be `PENDING` until blessed.
3. Bless that `destination_id` with the enrolled device key + fresh TOTP
   (`POST /admin/v1/destinations/:id/bless`). Do not POST a new destination.
4. Confirm the row is `BLESSED` before expecting omit-source assign to pick it
   as a top-up sink.

Fleet check after deploy (staging / ops — not required to land this change):

```sql
SELECT w.id AS wallet_id,
       w.money_mode,
       d.id AS dest_id,
       d.state AS dest_state
  FROM wallets w
  LEFT JOIN destinations d ON d.wallet_id = w.id
 WHERE w.key_origin = 'node_generated';
```

Every node_generated row should have `dest_id IS NOT NULL`. The only
intentional exclusion is `key_origin = 'imported'` (never a destination).
A missing dest on an already-applied fleet is healed by the
`destinations-pending-backfill` money-pack slice on next migrate / boot.

CAS conflicts (`expected_row_version` stale) mean another operator changed the
row — re-read and retry; do not force.

## Fund hubs and verify

1. Fund **hubs** on-chain the same way you fund any custody wallet (external
   transfer in). Prefer concentrating float on hubs, not on every worker.
2. Wait for a verified gateway observation so `b_amount` is known. Hubs with
   **null** observed balance are skipped for top-up (fail closed).
3. Spot-check inventory: hub balance ≥ peak concurrent shortfall you expect
   under auto-funded sends.
4. Optional smoke: create one small external send **without**
   `source_wallet_id` while a send-only worker is empty and a hub is funded —
   expect a top-up `MOVE_INTERNAL` then `SEND_EXTERNAL` sourced at the worker.
   The node never chain-submits the external send.

## Manual rebalance when automation is paused

When auto-approve is off, halt is engaged, or you have paused money workers:

1. Prefer **internal moves** hub → worker (or hub → hub) from the admin / API
   `MOVE_INTERNAL` path. Both parties need `allow_internal_move` (internal-only
   hubs qualify).
2. Do **not** “fix” float by external-sending from an internal-only hub. That
   path is refused (`allow_external_send=false`). If you need value off-node,
   move to a **send-capable** worker first, then create the external send from
   that worker (or omit source and let the node assign).
3. After rebalance, confirm observations and unsettled operation counts before
   re-enabling automation.

## Failure modes (quick map)

| Symptom | Likely cause | First check |
| --- | --- | --- |
| External send 503 / `no_free_send_worker` | No free send-capable wallet | Mode mix; leases; unsettled sends |
| External send 503 / `no_hub_liquidity` | Worker underfunded and no hub covers shortfall | Hub balances + observations |
| External send 503 / `hub_busy` | Eligible hub(s) locked | Active leases / in-flight moves |
| External send 503 / `worker_destination_missing` | Assign picked a send-capable wallet with no `destinations` row | Bless that wallet's existing dest (below) — do not mint another wallet |
| External send 422 with internal-only source | Explicit `source_wallet_id` pinned to hub | Omit source or pick send-capable wallet |
| Receive assign never picks a wallet | Only send-only / internal-only in pool, or dest is already `BLESSED` | Need receive-capable modes. A `PENDING` dest is blessable, not a receive-pool exclusion |
| Top-up MOVE stuck; SEND parked | Move not `INTERNAL_MOVE_LANDED` | [`attention-triage.md`](attention-triage.md) composition section |
| Halt engaged | Operator halt | Halt contract — new MOVE/SEND formation blocked |

## Alert notes (follow-up OK)

These conditions deserve on-call attention even if Prometheus rules land later:

1. **Zero free send-capable wallets** for a sustained window while external send
   traffic exists → capacity / mode misconfiguration.
2. **Hub aggregate observed balance below watermark** (operator-chosen) while
   workers are underfunded → top-ups will fail closed with `no_hub_liquidity`.

Wire rules under [`alerts/generic-node.rules.yml`](alerts/generic-node.rules.yml)
when metrics exist; until then treat inventory + needs-attention as the signal.

## What never changes

- Exactly three money verbs.
- One-in-flight-per-wallet and dual-control / auto-approve rules (except the
  capability checks and top-up readiness gate).
- **The node never chain-submits `SEND_EXTERNAL`.**
- Drift-gate forbidden vocabulary stays forbidden in code and operator copy
  (use hub / internal-only / float — not product-projection terms).

## Related tests

| Suite | Path |
| --- | --- |
| Scenario matrix (unit + composition) | `packages/node-core/test/money-capability-acceptance.matrix.test.ts` |
| Scenario matrix (PG selection) | `packages/node-core/test/money-capability-acceptance.pg.test.ts` |
| Assign + multi-hub top-up PG | `packages/node-core/test/assign-and-topup.pg.test.ts` |
| Lease capability matrix PG | `packages/node-core/test/wallet-money-capability-gates.pg.test.ts` |
