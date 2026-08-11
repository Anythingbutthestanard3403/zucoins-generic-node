# Incident runbook

One section per signal in `SAFETY_ALERT_SIGNALS`. Severity, threshold and the verbatim
posture text are in [`alert-reference.md`](alert-reference.md), which is generated from
source; this document is the part that needs judgement — what to check, what is safe, and
what will make it worse.

All catalogue signals are bound to live readings as of ZTR-1144. P0/P1 also reach the operator webhook when `OPERATOR_ALERT_WEBHOOK_URL` is configured.
Their sections are still here, because the underlying condition is real even when the alert
is not, and because [`alerts/generic-node.rules.yml`](alerts/generic-node.rules.yml) watches
proxy metrics for several of them. Silence from an unbound signal is not an all-clear.

## The rules that override every section below

1. **Never blind-retry a submit.** An ambiguous submit outcome is `INDETERMINATE`. It
   authorizes no landing, no non-landing, no retry, no rebuild, and no lease release.
2. **A lease heartbeat expiring is not a lease release.** Nothing — no alert, no timeout, no
   restart — releases a lease on time alone.
3. **A gateway `status:true` is a receipt, not a settlement.** Landing is asserted only from
   a fresh verified chain read.
4. **Unchanged head alone is not "safe to rebuild".** The only buried-landing oracle is an
   any-depth complete-path proof anchored at a fresh head.
5. **Never delete evidence.** Observation and anomaly ledgers are permanent, including exact
   repeats. Storage pressure is remedied with capacity, never with pruning.

## The nine actions you actually have

Everything an operator may do to a flagged operation goes through
`POST /admin/v1/operations/:operation_id/recovery-actions`, which re-evaluates every
predicate under locks with an expected row version, a single-use recovery nonce, fresh TOTP,
CSRF and an idempotency key. The catalogue is closed:

`RETRY_OBSERVATION` · `REDELIVER_EXACT_PARTIAL` · `CONTINUE_EXTERNAL_WAIT` ·
`CLOSE_NEVER_STARTED_EXTERNAL_SEND` · `CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` ·
`REBUILD_INTERNAL_MOVE` · `RELEASE_EXPIRED_RECEIVE` · `QUARANTINE_WALLETS` ·
`ACKNOWLEDGE_KEEP_PINNED`

These do not exist, in the API or in SQL, and asking for one is a rejected request rather
than a dangerous one:

`RETRY_SUBMIT` · `FORCE_LANDED` · `FORCE_RELEASE` · `EDIT_TRANSACTION` ·
`CHANGE_DESTINATION` · `CHANGE_AMOUNT` · `REFORM_EXTERNAL_SEND` ·
`NODE_SUBMIT_EXTERNAL_SEND` · `DELETE_EVIDENCE` · `SKIP_VERIFICATION`

`REBUILD_INTERNAL_MOVE` is the only action that authorizes a new attempt number, and it is
halt-gated. It archives the old attempt unchanged and never resubmits it. It remains
RESERVED at launch.

`CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` is live under ZTR-1226 (option b): protocol expired
plus the aging margin **and** either `freshHeadEqualsSourceT0` or
`completePathExclusionProved`. Timer-only expiry does not license the close. There is still
no generic PROVEN_NOT_LANDED oracle (D9.6).

## halt

`POST /admin/v1/halt` engages the operator halt. `gn_halt_engaged` is 1 while it is on.

Engaging halt refuses `REBUILD_INTERNAL_MOVE` — the one recovery action that re-authorizes a
fund-moving first formation. Every other recovery action stays available, so a halted node is
still a node you can work an incident on.

**Unexpected halt** means someone else engaged it. Find out who and why before you clear it.
Clearing a halt that another operator engaged mid-investigation is how two people
simultaneously believe they own the incident.

---

## invariant_breach

**P0.** Watch
`gn_wallets_quarantined_unexpected_head > 0` as the closest live proxy; a clean reading there
does not mean no breach.

**Means.** The durable record contains something that cannot arise under the contract: two
active leases on one wallet, an unattributed deep successor while the wallet is actively
leased, expected exact bytes missing while the signer audit says the signer was used, a
signer audit contradicting the durable record, or reconcile evidence observed against an
already-released lease.

**Check.** Which wallets and operations are named. The evidence manifest on the operation.
Whether money workers are still running. Whether more than one instance holds signer
leadership — that alone is an automatic hard stop.

**Safe.** Stop money engines. `QUARANTINE_WALLETS` on the affected wallets.
`ACKNOWLEDGE_KEEP_PINNED` to record that you have seen it without changing protocol state.
Preserve everything and escalate to custody escalation.

**Forbidden.** Un-quarantining to "test whether it is still broken". Rebuilding. Retrying
any submit. Restarting the node to clear the state — the breach is durable, and a restart
just makes boot recovery refuse readiness, correctly.

## duplicate_submit_attempt

**P0.** Fired from `gn_duplicate_submit_rejection_total` (submit_decisions mint loser).

**Means.** A `submit_decision_id` uniqueness constraint rejected a write: the same submit
decision was attempted twice. The database prevented the second one. What you do not yet
know is whether the *first* one reached the chain, and whether the bytes changed between the
two attempts.

**Check.** The submit ledger rows for that decision id. The exact byte record for each
attempt — are they the same bytes? A fresh verified chain read for the wallet.

**Safe.** Stop money engines. Quarantine the affected wallets. Preserve the exact bytes of
both attempts. Escalate.

**Forbidden.** Retrying. Deciding the operation "did not land" because the second attempt was
rejected — the rejection is about the database, not the chain. Alerting on raw submit retry
count instead of the uniqueness rejection, which produces noise that trains you to ignore
this signal.

## lease_age

**P1, diagnostic only.** Live: `gn_oldest_lease_age_seconds`, suppressed while
`gn_database_truth_available` is 0.

**Means.** The oldest active lease has not heartbeated for longer than the threshold
(default 300 s / 5 min). It means a worker stopped heartbeating. **It does not mean the lease
is free.**

**Check.** `gn_active_leases{lease_role}` and `gn_worker_healthy{worker}`. Whether the
process holding the lease is alive. Whether the operation under the lease is mid-submit — if
it is, its outcome is ambiguous and the lease is doing exactly its job.

**Safe.** Investigate the worker. Restart the *worker process* if it is wedged; the lease
survives and is re-acquired by its owner. `ACKNOWLEDGE_KEEP_PINNED` on the operation.

**Forbidden.** Releasing the lease. `FORCE_RELEASE` does not exist for this reason. Deleting
the lease row. Restarting the node "to clear stale leases" — boot deliberately does not
delete a lease based on time, so this achieves nothing except an outage. A released lease
over an operation with an ambiguous submit is a second signer over the same wallet.

## path_gap

**P1.** Watch
`increase(gn_proof_budget_exhaustion_total[15m]) > 0` as a partial proxy.

**Means.** Lineage verification found a persistent gap: a missing body between the anchor and
the target. The result is `INDETERMINATE`.

**Check.** Which operation and which wallet. Whether the gateway is returning bodies at all
(`gn_t0_read_failures_total`, `gn_observation_degraded`). Whether the gap is one endpoint's
view or every endpoint's.

**Safe.** `RETRY_OBSERVATION` — re-read, do not re-submit. Stop the affected wallet or
operation while other isolated lanes keep running if their invariants hold. Escalate.

**Forbidden.** Treating `INDETERMINATE` as "not landed". Rebuilding on an unchanged head —
unchanged head alone is insufficient. Widening the proof budget until the gap "resolves".

## regression

**P1.** Watch
`increase(gn_observation_anomalies_total[15m]) > 0` — that counter is emitted and consumed by
no in-process signal.

**Means.** The chain view moved backwards: a `REGRESSION` relationship, or
`GENESIS_AFTER_HISTORY` on a wallet that already had history. Both quarantine the wallet and
map to `LEASE_INVARIANT_VIOLATION`.

**Check.** `gn_wallets_quarantined_unexpected_head`. Which endpoint produced the observation.
Whether other endpoints agree — an endpoint that rewound is a different problem from a chain
that rewound.

**Safe.** Park the affected operations. Keep reading. Page the operator.

**Forbidden.** Releasing anything. Rebuilding. "Resyncing" by pointing at a different
gateway and treating the new stream as authoritative — switching gateways starts a new
observation stream and does not erase what was recorded.

## endpoint_disagreement

**P1.** Watch `gn_observation_degraded == 1`.

**Means.** Two independent gateway endpoints disagree about authoritative state. The node
fails closed for money decisions until the configured authority policy resolves it.

**Check.** Which endpoints, and what each returned. `SPLITCHAIN_GATEWAY_URLS` ordering — the
first entry is primary. Whether one endpoint is simply behind, or actually contradicts.

**Safe.** Let it fail closed. Record both responses — they are permanent evidence, including
when they repeat. Escalate.

**Forbidden.** Removing the disagreeing endpoint from the configuration to make the alert
stop. A disagreement already recorded is not erased by reconfiguration, and you have just
deleted your second opinion.

## storage_pressure

**P1 escalating to P0.** Live: `gn_storage_pressure`. Note this is a **0/1 band flag**, not a
utilization fraction, so engaging the band crosses both the 0.9 and 0.95 default bands at
once and reports P0.

**Means.** Evidence storage is at or past its configured bound. The node refuses new evidence
at pressure and halts operations at critical, because losing evidence is worse than stopping.

**Check.** Actual disk headroom on the evidence volume. Growth rate. Whether retention of
*backups* (a bounded, prunable set) is what filled the volume, versus the observation ledger
(which is not prunable).

**Safe.** Add capacity. Move backups to a different volume. Reduce `BACKUP_RETENTION_DAYS`
within its 1–90 bounds — backups are the one thing here with a retention policy.

**Forbidden.** Deleting observation, anomaly or exact-byte rows. Any of them. A recurrence of
older bytes is retained deliberately and is not a duplicate. `DELETE_EVIDENCE` does not exist
as an action, and the runtime role has no `DELETE` or `TRUNCATE` grant on public tables — if
you find yourself needing a superuser connection to relieve storage pressure, stop.

## queue_caps

**P1.** Live: receive-queue depth, pool-cap utilization and pinned ratio, suppressed while
`gn_database_truth_available` is 0. The 503 rate is bound to `gn_receive_queue_full_503_total`
(process counter — **not** DB-gated in-process or in Prom `GenericNodeReceiveQueueFull503`).

**Means.** One of three things is at 90%: the receive-admission queue against
`RECEIVE_QUEUE_CAP` (which is derived from `POOL_CAP_TOTAL`, not separately configurable),
the wallet pool against `POOL_CAP_TOTAL`, or the **pinned ratio** — pinned wallets over live
pool size.

The pinned ratio is the one that catches people. A node whose consumer never posts
verification-complete never releases wallets from `PINNED`, so the pinned share climbs toward
1.0 while cap utilization still looks healthy. That is a stalled consumer, not a busy node.

**Check.** `gn_wallets{state}` — how many are `PINNED` versus `AVAILABLE`.
`gn_receive_queue_oldest_age_seconds`. Whether the implementer above this node is posting
verification-complete at all. `gn_available_wallets` — if it is 0 while `gn_total_wallets` is
at cap, minting cannot help you.

**Safe.** Stop the affected admission path. Fix the consumer. Raise `POOL_CAP_TOTAL` (mutable,
bounds 5–500) if the pool is genuinely undersized. Let queued receives expire — that is what
`RECEIVE_QUEUE_MAX_WAIT` is for.

**Forbidden.** Un-pinning wallets by hand to free capacity. A `PINNED` wallet is holding
evidence for an operation that has not been verified; releasing it discards the only thing
tying the wallet to that operation.

## signer_loss

**P1; P0 when an in-flight signing outcome is ambiguous.** Live:
`gn_signer_leadership_held`. The input that raises it to P0 is `gn_signer_in_flight_ambiguous` — **you
must make that call by hand.**

**Means.** This process does not hold the signer leadership lock. Readiness reports
degraded. Unsigned operations stay in whatever public state they are already in.

**Check.** Whether another instance holds it — exactly one leader is the invariant, and
**more than one observed leader is an automatic hard stop**, not a degraded mode. Whether a
signing attempt was in flight when leadership was lost: if so, treat this as **P0**, because
that outcome is ambiguous.

**Safe.** Let the node stay not-ready. Investigate why leadership was lost or cannot be
re-acquired. If shutdown exited while still holding the lock after a failed flush, that is
deliberate — the lock is protecting an unflushed state.

**Forbidden.** Starting a second instance to "take over" signing. Force-releasing the
leadership lock. Retrying the in-flight signing attempt.

## backup_age

**P1.** Live: `gn_backup_last_success_age_seconds`, suppressed while
`gn_backup_last_success_available` is 0. The threshold comes from the configured cadence —
`resolveBackupAgeThreshold` refuses a zero or negative value rather than inventing one.

**Means.** The newest successful backup is older than the configured maximum age. Default
RPO target is 24h.

**Check.** `pnpm --filter @zucoins/generic-node dr status`. Whether `BACKUP_OUTPUT_DIR` is a
durable volume rather than `/tmp`. Whether the pg client binaries (`pg_dump`, `psql`) are on
`PATH` or at `PG_BIN` — a missing binary is a fail-closed refusal, not a silent skip.

**Safe.** Take a backup now. Fix the sink. Verify the newest artifact with
`dr verify --path`.

**Forbidden.** Assuming the scheduler is fine because no alert fired — the alert is
suppressed entirely when there has never been a successful backup, which is exactly the worst
case. `GenericNodeBackupNeverSucceeded` covers that gap; make sure it is loaded.

---


## push_no_transfer_code_streak

**P1. Live:** `gn_push_no_transfer_code_streak` (process-local gauge) and in-process
`SAFETY_ALERT_SIGNALS` evaluation from `composePush` when the consecutive count first
reaches the threshold (default 20). Prometheus rule `GenericNodePushNoTransferCodeStreak`
watches the same gauge.

**Means.** The inbound Web Push channel returned `no_transfer_code` this many times in a
row with no intervening `enqueued`. A single miss is normal (non-transfer notification).
A sustained run is the silent-money-stop failure mode: the wallet reshaped the delivered
envelope, `resolveTransferCodeFromEnvelope` returns null, the route still answers **204**
by design, and nothing else goes red unless this signal fires.

**Check.** Recent `push.receive_no_code` audit rows. A freshly decrypted live cleartext
against `packages/generic-node-contracts/goldens/push/delivered-envelope.data.v1.json.txt`.
`gn_push_receive_total{outcome,shape}` — whether any `enqueued` still occurs and whether
shape labels migrated. Whether the subscription is still ACTIVE.

**Safe.** Preserve evidence (audit rows, a redacted cleartext sample). Update
`payload.ts` precedence and refresh the golden in the same reviewed commit if the nest
moved. Page on-call; treat as a primary external-receive detection outage for the push
channel.

**Forbidden.** Changing the 204 discard response to "fix" the miss. Blind-retrying
submits. Treating readiness green or other unbound signal silence as an all-clear on
push. Deleting audit rows to "clear" the streak (the gauge is process-local; restart
zeros it without fixing the shape).

## When you are not sure which section applies

Start from the operation, not the alert. `GET /admin/v1/operations/needs-attention` lists
flagged operations with their `attention_reason`; each reason has an entry in
[`attention-triage.md`](attention-triage.md) naming its cause and what resolves it.

When in doubt, the safe default is the recovery axiom this system is built on: **retain
leases, preserve exact bytes, keep reading, and require attention. Availability never
outranks the possibility of a second transaction.**

## attention_backlog

**P1.** `gn_operations_attention_required` (DB-truth). Suppressed while `gn_database_truth_available` is 0.

Page operator. Drain via admin recovery; do not release leases or rebuild.

## gateway_read_failure

**P1.** `gn_t0_read_failures_total` and/or `gn_observation_degraded`.

Fail closed for money decisions until gateway reads recover. Do not switch endpoints to erase disagreement.

## queue_oldest_age

**P1.** `gn_receive_queue_oldest_age_seconds` vs `RECEIVE_QUEUE_MAX_WAIT`. Suppressed while DB-truth unavailable.

Stop affected admission path; keep other isolated lanes operating if invariants hold.
