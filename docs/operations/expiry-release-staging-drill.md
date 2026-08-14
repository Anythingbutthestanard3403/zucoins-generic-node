# Staging drill — receive expiry auto-release (ZTR-1276)

Post-deploy lab checklist proving the money worker releases an unpaid assigned
receive end-to-end via `runReceiveExpiryReleaseStep` → `SqlReceiveExpiryReleaseService`
with a real gateway fresh-head read. **No hand SQL on money-path tables.**

Companion automated proof: `apps/generic-node/test/receive-expiry-release-proof.pg.test.ts`.

## Preconditions

- [ ] Build containing ZTR-1251 (fresh-head wiring) + ZTR-1275 (exact-repeat → `DUPLICATE`) + ZTR-1277 (attention-parked excluded from expiry candidate scan) is deployed to staging
- [ ] Money workers running (`startMoneyWorkers`); leadership held; vault unlocked
- [ ] `SPLITCHAIN_GATEWAY_URLS` points at the staging gateway (live OBSERVE)
- [ ] Operator admin session available (UI + optional read-only SQL for evidence capture)
- [ ] Lab implementer / API credentials that can `POST /v1/receives`
- [ ] At least one recovery-verified, push-subscribed pool wallet eligible for `RECEIVE_WINDOW`

## Drill — happy path (T0 unchanged → auto-release)

### 1. Create a short-TTL lab receive

Create a `RECEIVE_EXTERNAL` with the **shortest allowed TTL** for the environment
(respect `RECEIVE_TTL_MIN_SECS`). Prefer the implementer API or operator tooling —
do not insert into `operations` / `receive_operations` by hand.

Record:

| Field | Value |
| --- | --- |
| `operation_id` | |
| `receiver_wallet_id` | |
| `t0_observation_id` (after READY) | |
| `expiry_unix_time_secs` | |
| create timestamp (UTC) | |

Wait until status is **READY**, code armed if your lab path arms, and the UI
countdown is visible on the wallet / operation.

### 2. Do not pay

Leave the receive unpaid. Do not submit a candidate. Do not run recovery actions.

### 3. Wait past expiry + safety margin

Protocol expiry alone is not enough. The worker requires
`now >= expiry + RECEIVE_EXPIRY_SAFETY_MARGIN_SECS` (30s) before
`loadExpiredReceiveCandidates` selects the row. Wall-clock: **TTL + ≥35s**.

Do not advance clocks in the database. Do not `UPDATE operations SET expiry…`.

### 4. Observe the worker (unaided)

On the next money tick the worker should:

1. Select the op via `loadExpiredReceiveCandidates`
2. `get_transaction__v1` the **receiver** wallet (fresh head outside SERIALIZABLE)
3. Persist a fresh `gateway_observations` row (expect `DUPLICATE` / equivalent when unpaid)
4. Commit `EXPIRED` + `RELEASED_T0_UNCHANGED` + dual proofs + membership close

**Pass signals (all required):**

| Check | Expected |
| --- | --- |
| Operation status | `EXPIRED` |
| `receive_release_status` | `RELEASED_T0_UNCHANGED` |
| `receive_release_proofs.release_kind` | `EXPIRED_T0_UNCHANGED` |
| `receive_release_proofs.t0_observation_id` | equals create-time T0 |
| `receive_release_proofs.fresh_observation_id` | non-null, ≠ T0 |
| `lease_release_proofs.proof_kind` | `RECEIVE_EXPIRED_T0` (consumed) |
| `wallet_lease_memberships.release_reason` | `EXPIRED_T0_UNCHANGED` |
| `wallet_active_leases` for wallet | **absent** |
| Wallet state | `AVAILABLE` |
| `attention_required` | `false` |
| Operator UI | countdown at zero; wallet available; op not needs-attention |
| Hand SQL | **none** used to force release |

### 5. Capture evidence on ZTR-1276

Paste into the Linear ticket (or PR comment) before moving the ticket:

```text
ZTR-1276 staging drill — expiry auto-release
deploy_sha / image: 
environment: staging
operation_id: 
receiver_wallet_id: 
t0_observation_id: 
fresh_observation_id: 
receive_release_proof_id: 
lease_release_proof_id: 
membership release_reason: EXPIRED_T0_UNCHANGED
wallet_state_after: AVAILABLE
ui_confirmed: yes/no
operator: 
timestamp_utc: 
notes: 
```

Optional read-only verification (select-only; never UPDATE/DELETE):

```sql
SELECT o.id, o.status, o.receive_release_status, o.attention_required,
       w.id AS wallet_id, w.state AS wallet_state
  FROM operations o
  JOIN operation_wallets ow ON ow.operation_id = o.id AND ow.operation_role = 'RECEIVER'
  JOIN wallets w ON w.id = ow.wallet_id
 WHERE o.id = $operation_id;

SELECT id, release_kind, t0_observation_id, fresh_observation_id
  FROM receive_release_proofs WHERE operation_id = $operation_id;

SELECT proof_id, proof_kind, consumed_at
  FROM lease_release_proofs WHERE operation_id = $operation_id;

SELECT id, release_reason, released_at, release_proof_id
  FROM wallet_lease_memberships
 WHERE release_proof_id IN (
   SELECT proof_id FROM lease_release_proofs WHERE operation_id = $operation_id
 );
```

## Negative lab (optional, same deploy)

If staging time allows, force a **changed head** during the lease (small lab
inbound to the receiver before expiry completes) and confirm:

- status is `EXPIRED` (CAS-to-expired runs before freshExact) **with** attention parked
- `attention_reason = T0_RELEASE_MISMATCH`
- `receive_release_status` is null (no safe terminal release)
- wallet remains `PINNED`; `wallet_active_leases` still holds `RECEIVE_WINDOW`
- **no** `receive_release_proofs` row
- operator follows [`attention-triage.md`](attention-triage.md) § T0_RELEASE_MISMATCH
  (quarantine / escalate — never `RELEASE_EXPIRED_RECEIVE` while mismatch holds;
  `RETRY_OBSERVATION` is not offered for attention-parked `EXPIRED` receives — ZTR-1283)

## Fail criteria (stop and escalate)

- Worker never selects the op after expiry+margin → check workers/leadership/logs for
  `receive expiry-release`; confirm op is not already `attention_required` (ZTR-1277)
- Fresh-head errors loop with null fresh id → gateway URLs / OBSERVE path; see money-worker logs
  `receive expiry fresh-head read failed`
- Op parks `T0_RELEASE_MISMATCH` while unpaid and head should be unchanged → treat as
  regression of ZTR-1251/1275; capture observation ids and gateway raw bytes
- Wallet AVAILABLE without `receive_release_proofs` / lease proof → **custody incident**;
  see [`incidents.md`](incidents.md) forged `EXPIRED_T0_UNCHANGED` section (ZTR-1281)
- Any hand SQL used to DELETE leases or stamp release status → drill invalid; restore from
  evidence and re-run clean

## Out of scope

- Production traffic receives
- Break-glass `RELEASE_EXPIRED_RECEIVE` (recovery store) — different surface; covered by
  recovery PG tests
- Formed READY with code/artifact material when fresh head cannot be obtained — expected
  attention path, not this drill's happy path
