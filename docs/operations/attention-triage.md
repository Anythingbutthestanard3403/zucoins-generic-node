# Attention triage guide

One entry per value in `ATTENTION_REASONS`
(`packages/generic-node-contracts/src/operations/events.contract.ts`) — the closed vocabulary
carried on `operation.needs_attention`. The list is frozen at fifteen values;
`apps/generic-node/test/operator-docs.census.test.ts` fails if one loses its entry here.

Find flagged operations with `GET /admin/v1/operations/needs-attention`. Act on them with
`POST /admin/v1/operations/:operation_id/recovery-actions` — the nine permitted actions and
the ten that do not exist are listed in [`incidents.md`](incidents.md).

**Almost nothing auto-clears.** Boot does not clear attention, and time does not clear
attention. Most reasons stay until an operator acts — deliberate, because the flag exists
when a machine could not safely decide. **Exception (ZTR-1245):** provisional `LINEAGE_GAP`
(and any other attention still on the row) is cleared when the same operation reaches a
positive land (`RECEIVE_LANDED` / `INTERNAL_MOVE_LANDED`) or verification-complete
`VERIFIED`, because positive custody evidence supersedes the provisional park.

## Reasons with deferred writers

Two values are in the frozen vocabulary and the `attention_reason` Postgres ENUM, but have
**no production setter yet** (recorded disposition in
`packages/generic-node-contracts/src/operations/attention-reason-setters.ts`):
`GATEWAY_RESPONSE_INVALID`, `GATEWAY_UNAVAILABLE_BEYOND_BUDGET`.

They become reachable once non-verified gateway reads and anomalies are bound to operations
(ZTR-1127 / ZTR-1128). The mapper already accepts them; the observation→operation binder does
not. If you see one on a node running this code before those tickets land, escalate rather
than triage.

`DESTINATION_NO_LONGER_BLESSED` is set when move baseline recheck finds the destination no
longer blessed. `OPERATOR_PARKED` is set by
`POST /admin/v1/operations/:operation_id/operator-park`.

---

## GATEWAY_RESPONSE_INVALID

**Deferred writer** (disposition ZTR-1147). See above.

**Would mean.** A gateway response failed structural validation — it was not a response this
node can interpret as evidence at all.

**Resolved by.** `RETRY_OBSERVATION` once the gateway returns well-formed responses. The
invalid response itself is retained permanently as anomaly evidence.

**Never.** Parse around it. A response the node cannot validate is not evidence of anything,
including of non-landing.

## GATEWAY_UNAVAILABLE_BEYOND_BUDGET

**Deferred writer** (disposition ZTR-1147). See above. The live symptom of the same condition is
`gn_observation_degraded == 1` plus a rising `gn_t0_read_failures_total`.

**Would mean.** Gateway reads exhausted `GATEWAY_READ_FAILURE_BUDGET` consecutive failures.
Readiness reports degraded.

**Resolved by.** Gateway reachability returning, then `RETRY_OBSERVATION`.

**Never.** Raise the budget to make the flag go away. The budget is what turns "we cannot
see the chain" into a refusal instead of a guess.

## UNEXPECTED_HEAD_CHANGE

**Caused by.** An observation anomaly that is not one of the three custody-grade ones, or a
reconcile that observed **no successor at all** where one was expected
(`packages/node-core/src/protocol/reconcile/types.ts`).

**Resolved by.** `RETRY_OBSERVATION` against a fresh head. If the head keeps moving
unexpectedly for one wallet, `QUARANTINE_WALLETS` and escalate — an unexpected head on a
wallet this node believes it exclusively controls is a custody question, not a sync question.

**Never.** Rebuild on the strength of an unchanged head afterwards. Unchanged head alone is
not proof of non-landing.

## LINEAGE_GAP

**Caused by.** Landing-proof verification hit a `MISSING_BODY` or `GAP` fault: the path from
the anchor to the target is incomplete. The verdict is `INDETERMINATE`.

**Resolved by.** `RETRY_OBSERVATION` — the bodies may arrive. A gap that persists is
escalated as `path_gap`, and the operation stays parked with its lease held.

**Auto-clears (ZTR-1245).** When the same operation later reaches a positive land
(`RECEIVE_LANDED` / `INTERNAL_MOVE_LANDED`) or verification-complete with verdict
`VERIFIED`, provisional `LINEAGE_GAP` attention is cleared with the land/ack write. That
is not a general auto-clear of every attention reason — only the superseding positive
path. Permanent lineage failures that never land stay parked.

**Never.** Treat the gap as non-landing. `INDETERMINATE` authorizes no landing, no
non-landing, no retry, no rebuild and no lease release.

## SUBMIT_OUTCOME_AMBIGUOUS

**Caused by.** The submit call boundary was crossed with an unknown outcome — a timeout, a
dropped connection, a response the node could not attribute, or a **2xx with an empty /
malformed body** (no boolean `status` field). Those empty/malformed 2xx replies are
classified **INDETERMINATE** at the transport layer, never as a receipt ACK. The transaction
may still be on the chain.

**Resolved by.** `RETRY_OBSERVATION` until a fresh verified chain read settles it, then the
normal landing path. For a receive parked at `STEP2_SIGNATURE_PERSISTED` whose durable claim
already exists and whose confirm-read still shows an **unmoved** head, the settle step may
**POST the exact same signed request bytes again** (identical-byte redelivery). That is not a
second authorization: no second `submit_decisions` row, no second `gateway_submit_attempts`
row, no rebuilt body. For a `MOVE_INTERNAL` whose claim is burned, last transport outcome is
AMBIGUOUS/INDETERMINATE, and **both** source and destination heads are still unmoved, the
LAND step may likewise redeliver the durable `gateway_submit_attempts.request_body` bytes
(ZTR-1244) before reconcile — again no second claim or attempt row. For a `MOVE_INTERNAL`
where positive non-landing has been *proved*, `REBUILD_INTERNAL_MOVE` with the proof id —
which archives the old attempt unchanged and creates a new attempt number. It never
resubmits a *different* attempt.

**Never.** Blind-retry a *new* submit body or invent a second attempt number. That is golden
rule 4 and the single most dangerous instinct in this runbook: a second authorization is how
the same value moves twice.

## SIGNING_OUTCOME_AMBIGUOUS

**Caused by.** The signer audit trail contradicts the durable record — the database says sign
intent is absent while the audit indicates a call was made, or an expected exact preimage is
unavailable.

**Resolved by.** Operator investigation with custody escalation. Preserve the signer audit and
every exact byte record first.

**Never.** Sign again. Assume the signature does not exist because the record does not show
it — the contradiction is the point.

## DESTINATION_NO_LONGER_BLESSED

**Caused by.** Move baseline recheck (`captureAndBindMoveBaselines`) finds the destination is
no longer `BLESSED` (retired or pending) while the move is in flight.

**Would mean.** The destination an operation was formed against is no longer in the blessed
set.

**Resolved by.** `CLOSE_NEVER_STARTED_EXTERNAL_SEND` when the send provably never started, or
`CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` when complete-path exclusion proved non-landing
(ZTR-1226: authorized under the bounded oracle — protocol expired + aging margin AND
(freshHeadEqualsSourceT0 OR completePathExclusionProved); not timer-only; no generic
PROVEN_NOT_LANDED oracle).

**Never.** `CHANGE_DESTINATION`. It does not exist. A send is formed against one destination
and that is the only destination it can ever have. Boot does not auto-accept a new
destination either.

## T0_RELEASE_MISMATCH

**Caused by.** The lease-release predicate was not satisfied: the fresh observation does not
equal the recorded T0 for the wallet, so the "nothing happened while we held this" claim
cannot be made (`packages/node-core/src/receive/expiry-release.ts`).

**Resolved by.** Treat as a custody question once the row is attention-parked on `EXPIRED`
(post ZTR-1277 the automatic expiry sweep will not re-pick it). Prefer
`QUARANTINE_WALLETS` and escalate when the head truly moved during the lease. If a later
fresh read (outside recovery) shows the head is back to T0 and all five release predicates
hold, break-glass `RELEASE_EXPIRED_RECEIVE` is the state-changing path — not
`RETRY_OBSERVATION` (ZTR-1283: that action is a row_version-only CAS bump and is not offered
for attention-parked `EXPIRED` receives).

**Never.** `RELEASE_EXPIRED_RECEIVE` while the mismatch still holds. That action requires
all five release predicates, and this reason exists precisely because one failed. The safe
terminal release status is `RELEASED_T0_UNCHANGED` — releasing on a *changed* T0 discards
the evidence that something happened. Do not offer or press `RETRY_OBSERVATION` on these
rows; it burns TOTP/nonce with no re-evaluate.

### Legacy / held-episode `attention_detail` (ZTR-1279 / ZTR-1285)

**What operators see.** The SPA Evidence-gap card reads durable
`operations.attention_detail` from recovery inspection. New parks write the ZTR-1279 JSON
shape (`failed_predicates`, `predicate_causes`, `fresh_read`) via
`buildReceiveExpiryAttentionDetail`. Free-form older notes still render as raw text.

**Held episode does not rewrite the column.** When a receive is already
`attention_required=true`, later expiry ticks re-evaluate predicates in-process and return
fresh detail on the service result, but they do **not** `UPDATE operations.attention_detail`
unless severity escalates to `POST_EXPIRY_RECONCILING` (the only held-path writer).
`LOAD_ATTENTION` still selects the column for the CAS/hold branch; the durable value is
whatever was stamped when the episode opened (or last escalated).

**Why no automatic backfill.** Post ZTR-1277 the automatic expiry sweep excludes
attention-parked receives, so those rows are not re-parked with enriched JSON. Rewriting
detail on every held tick would churn `row_version` without changing custody state. Rows
parked before ZTR-1279 may therefore keep bare / free-form detail until an operator
recovery action or escalation path writes a new value.

**Operator expectation.** Treat missing Evidence-gap structure on a long-held
`T0_RELEASE_MISMATCH` / `EXPIRED` row as “parked before structured detail,” not as proof
the confirm-read was never attempted. Use recovery classification, permitted actions, and
fresh break-glass confirm-read under `RELEASE_EXPIRED_RECEIVE` when re-evaluating release
eligibility — do not wait for a background rewrite of `attention_detail`.

## VERIFICATION_REJECTED

**Caused by.** Proof intake rejected the supplied material — it did not verify.

**Resolved by.** Supplying material that verifies, then `RETRY_OBSERVATION`. The rejected
submission is retained as evidence.

**Never.** `SKIP_VERIFICATION`. It does not exist.

## VERIFICATION_INDETERMINATE

**Caused by.** Path verification found a `CONFLICT`, `DUPLICATE`, `CYCLE`, or an
anomalous/contradictory body; or two paths disagreed. Not a gap — a contradiction.

**Resolved by.** `RETRY_OBSERVATION` against a fresh head. A durable contradiction is parked
and escalated; it is not something an operator resolves by choosing a branch.

**Never.** Pick the path that agrees with what you expect. Delete the contradicting
observation.

## VERIFICATION_RESOURCE_EXHAUSTED

**Caused by.** Any-depth verification hit its path-depth or proof budget before reaching a
complete path (`gn_proof_budget_exhaustion_total` increments here).

**Resolved by.** `RETRY_OBSERVATION`, possibly after the chain has advanced enough for a
shorter complete path to exist. Escalate if it recurs — a budget that is structurally too
small for this node's depth is a configuration question for custody escalation, not a knob to
turn during an incident.

**Never.** Treat exhaustion as non-landing. It is `INDETERMINATE`, with all the same
prohibitions.

## LEASE_INVARIANT_VIOLATION

**Caused by.** One of three custody-grade conditions:
a `REGRESSION`, `GENESIS_AFTER_HISTORY` or `SIGNATURE_COLLISION` observation anomaly; an
unattributed deep successor while the wallet is still actively leased; or reconcile evidence
observed while the lease had already been released — which cannot arise under the guarded
release sequence.

**This is the P0 shape.** It is the same class the `invariant_breach` signal exists to catch.

**Resolved by.** Stop money engines. `QUARANTINE_WALLETS`. Preserve evidence. Custody
escalation. `ACKNOWLEDGE_KEEP_PINNED` records that you have seen it without touching protocol
state or leases.

**Never.** Release the lease. Un-quarantine. Rebuild. Restart to clear it.

### MOVE parked severity upgrade (ZTR-1222)

While a `MOVE_INTERNAL` is already parked with `attention_required=true` and
`status=NEEDS_ATTENTION`, later reconcile ticks do **not** re-append equal-severity
parks (no spam, no status edge). A **higher** parking severity does upgrade in place:

- `INDETERMINATE` (e.g. `VERIFICATION_INDETERMINATE`) → `INVARIANT_BREACH`
  (e.g. `LEASE_INVARIANT_VIOLATION`) updates `attention_reason` / `attention_detail`,
  increments `attention_episode`, appends one dual-chain `operation.needs_attention`
  event, and fires the P0 `invariant_breach` metric.
- Equal or lower severity is a no-op hold. Severity never downgrades.
- `LANDED_VERIFIED` still proceeds through the normal landing path.
- Operator retraction (`attention_required=false`, status still `NEEDS_ATTENTION`)
  still re-raises on the next park (ZTR-1223); that path is unchanged.

## EXACT_BYTES_UNAVAILABLE

**Caused by.** A `MALFORMED_BODY` during path verification, or — far more seriously — expected
exact byte records missing while the signer audit indicates the signer was used.

**Resolved by.** The malformed-body case: `RETRY_OBSERVATION`. The missing-bytes-after-signing
case: nothing an operator can do at the node. Preserve everything and escalate as P0.

**Never.** Synthesize the missing bytes from parsed JSON. Boot explicitly does not do this,
and neither may you — reconstructed bytes are not the signed bytes, and the whole verification
chain is byte-exact.

## OPERATOR_PARKED

**Caused by.** An operator deliberately parked the operation via
`POST /admin/v1/operations/:operation_id/operator-park` (session + CSRF + fresh TOTP).

**Would mean.** An operator deliberately parked the operation pending investigation.

**Resolved by.** The operator who parked it, once the investigation concludes. Use
`ACKNOWLEDGE_KEEP_PINNED` to record acknowledgement — it bumps the row version for
single-winner semantics and changes neither public status nor leases. Clear a false-positive
flag with attention-retraction, not park.

## POST_EXPIRY_RECONCILING

**Caused by.** A receive passed its expiry boundary and reconcile has not completed. The node
holds the lease, retains all evidence, and reconciles **first** — the order is
`hold_lease → retain_evidence → reconcile_first → resolve_or_release`, and it is never
reordered.

**Resolved by.** Waiting for reconcile to complete. A landing wins and the operation resolves
`RECEIVE_LANDED`. A durably inconclusive reconcile resolves `INDETERMINATE` and is **held
indefinitely** — there is no post-boundary release branch at any proof level.

**Never.** Read "head unchanged, all acknowledgements in" as proof it will never land. A
head-unchanged read is a snapshot, not proof that a signed, durable transaction will never
land. That belief is the exact defect this contract forbids. `RELEASE_EXPIRED_RECEIVE`
applies to the pre-boundary safe-terminal case, not to this one.

---

## Composition failure modes (wallet money capabilities / auto-funded send)

These are **operator diagnosis paths**, not new `ATTENTION_REASONS` enum values.
They surface as rejected creates (HTTP), parked formation (send waiting on top-up
MOVE), or ordinary attention reasons on the MOVE/SEND rows. Use
`GET /admin/v1/operations/needs-attention` plus inventory.

Cross-links: [`wallet-money-capabilities.md`](wallet-money-capabilities.md) ·
[`auto-approve-external-sends.md`](auto-approve-external-sends.md).

### Top-up MOVE stuck (SEND references MOVE, move not landed)

**Looks like.** `SEND_EXTERNAL` stays approval-pending / formation-parked;
`references_operation_id` points at a `MOVE_INTERNAL` that is not
`INTERNAL_MOVE_LANDED`. Auto-approve and formation deliberately wait (top-up
readiness probe).

**Check.**

1. Open the referenced MOVE. Is it `NEEDS_ATTENTION`, in-flight, or halted?
2. Triage the MOVE with the reason section above (gateway, lease, proof, …).
3. Confirm hub and worker still hold expected leases / standing.

**Resolved by.** Landing or terminal resolution of the MOVE first. Only then
does the SEND become formation-eligible. Do not create a second SEND from the
hub.

**Never.** External-send from the internal-only hub to “unstick” float. Never
clear SEND attention while the referenced MOVE is still open without
understanding dual-path proof on the MOVE.

### SEND waiting on MOVE (healthy park)

**Looks like.** No attention flag yet; SEND simply does not auto-approve or form.
This is the **funded-after-top-up** design: readiness requires
`INTERNAL_MOVE_LANDED` (or no reference on the funded path).

**Resolved by.** Waiting for the MOVE money worker to land, or fixing the MOVE
if it parked. Not an incident by itself.

### Capability misconfiguration

**Looks like.**

| API / symptom | Misconfiguration |
| --- | --- |
| `no_free_send_worker` | No wallet with `allow_external_send` free (all receive-only / internal-only / busy) |
| `no_hub_liquidity` | Workers underfunded; hubs empty, unobserved, or non-internal-only |
| `allow_external_send=false` on explicit source | Client pinned an internal-only or receive-only wallet |
| Receive pool dry while wallets exist | Only send-only / internal-only in the fleet |
| Fleet warnings on mode PATCH | Last send-capable or receive-capable wallet re-moded away |

**Resolved by.** Correct modes on the admin money-capability control; fund hubs;
omit `source_wallet_id` so assign can pick a worker. See
[`wallet-money-capabilities.md`](wallet-money-capabilities.md).

**Never.** “Fix” by forcing an internal-only wallet through external send.
