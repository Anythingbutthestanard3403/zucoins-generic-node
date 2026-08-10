# Attention triage guide

One entry per value in `ATTENTION_REASONS`
(`packages/generic-node-contracts/src/operations/events.contract.ts`) — the closed vocabulary
carried on `operation.needs_attention`. The list is frozen at fifteen values;
`apps/generic-node/test/operator-docs.census.test.ts` fails if one loses its entry here.

Find flagged operations with `GET /admin/v1/operations/needs-attention`. Act on them with
`POST /admin/v1/operations/:operation_id/recovery-actions` — the nine permitted actions and
the ten that do not exist are listed in [`incidents.md`](incidents.md).

**Nothing here auto-clears.** Boot does not clear attention, workers do not clear attention,
and time does not clear attention. Every one of these is resolved by an operator or not at
all. That is deliberate: the flag exists because a machine could not safely decide.

## Reasons with no shipped writer

Four values are in the frozen vocabulary and in the database CHECK constraint, but **no code
path in this repository ever writes them**: `GATEWAY_RESPONSE_INVALID`,
`GATEWAY_UNAVAILABLE_BEYOND_BUDGET`, `DESTINATION_NO_LONGER_BLESSED`, `OPERATOR_PARKED`.

They cannot appear on a live node today. Their entries below describe what the value means so
that an operation carrying one — from an older release, or after the writer lands — is
readable. If you see one on a node running this code, that is itself the incident: escalate
rather than triage.

---

## GATEWAY_RESPONSE_INVALID

**No shipped writer.** See above.

**Would mean.** A gateway response failed structural validation — it was not a response this
node can interpret as evidence at all.

**Resolved by.** `RETRY_OBSERVATION` once the gateway returns well-formed responses. The
invalid response itself is retained permanently as anomaly evidence.

**Never.** Parse around it. A response the node cannot validate is not evidence of anything,
including of non-landing.

## GATEWAY_UNAVAILABLE_BEYOND_BUDGET

**No shipped writer.** See above. The live symptom of the same condition is
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

**Never.** Treat the gap as non-landing. `INDETERMINATE` authorizes no landing, no
non-landing, no retry, no rebuild and no lease release.

## SUBMIT_OUTCOME_AMBIGUOUS

**Caused by.** The submit call boundary was crossed with an unknown outcome — a timeout, a
dropped connection, a response the node could not attribute. The transaction may be on the
chain.

**Resolved by.** `RETRY_OBSERVATION` until a fresh verified chain read settles it, then the
normal landing path. For a `MOVE_INTERNAL` where positive non-landing has been *proved*,
`REBUILD_INTERNAL_MOVE` with the proof id — which archives the old attempt unchanged and
creates a new attempt number. It never resubmits the old attempt.

**Never.** Retry the submit. This is golden rule 4 and the single most dangerous instinct in
this runbook: retrying an ambiguous submit is how the same value moves twice.

## SIGNING_OUTCOME_AMBIGUOUS

**Caused by.** The signer audit trail contradicts the durable record — the database says sign
intent is absent while the audit indicates a call was made, or an expected exact preimage is
unavailable.

**Resolved by.** Operator investigation with custody escalation. Preserve the signer audit and
every exact byte record first.

**Never.** Sign again. Assume the signature does not exist because the record does not show
it — the contradiction is the point.

## DESTINATION_NO_LONGER_BLESSED

**No shipped writer.** See above.

**Would mean.** The destination an operation was formed against is no longer in the blessed
set.

**Resolved by.** `CLOSE_NEVER_STARTED_EXTERNAL_SEND` when the send provably never started, or
`CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` when complete-path exclusion proved non-landing.

**Never.** `CHANGE_DESTINATION`. It does not exist. A send is formed against one destination
and that is the only destination it can ever have. Boot does not auto-accept a new
destination either.

## T0_RELEASE_MISMATCH

**Caused by.** The lease-release predicate was not satisfied: the fresh observation does not
equal the recorded T0 for the wallet, so the "nothing happened while we held this" claim
cannot be made (`packages/node-core/src/receive/expiry-release.ts`).

**Resolved by.** `RETRY_OBSERVATION` — the read may be stale. If the mismatch is real, the
wallet's head moved during the lease and this becomes a custody question: quarantine and
escalate.

**Never.** `RELEASE_EXPIRED_RECEIVE` anyway. That action requires all five release
predicates, and this reason exists precisely because one failed. The safe terminal release
status is `RELEASED_T0_UNCHANGED` — releasing on a *changed* T0 discards the evidence that
something happened.

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

## EXACT_BYTES_UNAVAILABLE

**Caused by.** A `MALFORMED_BODY` during path verification, or — far more seriously — expected
exact byte records missing while the signer audit indicates the signer was used.

**Resolved by.** The malformed-body case: `RETRY_OBSERVATION`. The missing-bytes-after-signing
case: nothing an operator can do at the node. Preserve everything and escalate as P0.

**Never.** Synthesize the missing bytes from parsed JSON. Boot explicitly does not do this,
and neither may you — reconstructed bytes are not the signed bytes, and the whole verification
chain is byte-exact.

## OPERATOR_PARKED

**No shipped writer.** See above.

**Would mean.** An operator deliberately parked the operation pending investigation.

**Resolved by.** The operator who parked it, once the investigation concludes. Today, use
`ACKNOWLEDGE_KEEP_PINNED` to record acknowledgement — it bumps the row version for
single-winner semantics and changes neither public status nor leases.

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
