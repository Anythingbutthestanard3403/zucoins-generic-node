# Approval concern — CONTRACT_FREEZE

Freezes the frozen **one approval → one exact persisted external partial** rule. Governing
decisions: `approval-tuple-freeze`, amended by `two-timer-separation`. Governing spec: freeze-gate
requirements R-08 and C-08; signing custody and security invariants; operation flows; build/test
gates; canonical serialization A.1.1, approval tuple A.4.1, byte goldens A.8, negative vectors A.9.
Gate: contract + pure verifiers + tests only — **no runtime/production formation implementation.**

The concern names only the external-send operation kind; the two other operation kinds are described
behaviorally, never co-cited, per the anti-self-reference census.

## What the approval tuple freezes

`approval-tuple.contract.ts` freezes `zp-send-external-approval-v1` (A.4.1): the exact 12-field
sequence binding the immutable economic intent — source (selector + pubkey), destination address,
amount, operation/reference ids, nonce, issue time, and expiry — each modelled as its own frozen
economic-intent role. Also frozen: the suite serializer (`purpose + LF + JSON.stringify(payload)`,
distinct from prefix-less SplitChain native bytes); the authentication semantics (a mandatory fresh
single-use TOTP authenticates the guarded mutation and is **not** a signature — C-08; an optional
additive device key **may** sign the exact approval bytes but never replaces the TOTP); and the
sequencing fact that approval precedes source-lease acquisition and fresh chain formation, so the
tuple deliberately carries no `split_inner_sha256` and binds no later-formed inner.

## WALLET_ID closure

A resolved `source_selector` inside SIGNED approval bytes is ALWAYS the exact two-key object
`{kind:"WALLET_ID", wallet_id}`, in that key sequence (`SOURCE_SELECTOR_SIGNED_CLOSURE`). Every other
selector kind is a pre-resolution concept the node resolves to a concrete `wallet_id` before
signing; it never itself reaches signed bytes. The verifier rejects any other `kind` or a selector
carrying a third key with `field_value_invalid`.

## What the one-partial state machine freezes

`sign-intent.contract.ts` freezes the linear formation-state sequence (`APPROVED_UNSIGNED →
SIGNING_CLAIMED → PARTIAL_PERSISTED → PARTIAL_DELIVERED → AWAITING_REDEMPTION`) and its guarded
transitions, with the two crash-safety fences (persist the sign intent before the signer; persist
the partial before delivery). It freezes: the one-approval cardinality (at most one sign intent,
one step-1 signature, one persisted partial, one externally observable code); the inputs a sign
intent binds before the signer runs; the bytes made immutable once the intent exists (no re-form of
chain link, time, expiry, destination, amount); approval consumption with burn-on-failure and no
restoration after a downstream failure; redelivery restricted to the byte-identical persisted
partial; the replacement rule (expiry or any changed signed byte ⇒ safe resolution + a **new**
operation under a **fresh** approval, never a second partial under the old one); and
`two-timer-separation`: T1 approval-challenge freshness (`approval.expires_at`, a pre-formation gate)
is never the redemption deadline; T2 redemption expiry is the signed inner's expiry, materialized
once at formation and byte-frozen.

## What crash/replay exactness proves

`crash-recovery.contract.ts` freezes the crash-recovery decision table: for each durable state a crash can
leave behind, the single allowed recovery action and the single forbidden action, plus the mapping
from the four crash points (before intent persist / after intent before sign / after sign before
delivery / after delivery) onto those states. `crash-recovery.census.test.ts` drives the whole table
and carries the five mandatory negatives: a re-formed preimage, a refreshed-expiry partial, a second
partial after delivery, a replayed TOTP re-authorizing, and approval/SplitChain preimage
cross-contamination are each rejected. The deterministic-re-sign fact (Ed25519 is deterministic, so
recovery completes the same preimage rather than authorizing a new partial) is frozen.

## Goldens

`goldens/approval/zp-send-external-approval-v1.{preimage.txt,digest.hex,sig.b64,meta.json}` are the
raw byte artifacts (byte goldens A.8.2/A.8): the exact preimage bytes (its own SHA-256 equals the
pinned artifact digest), the pinned digest, and the optional additive **device** signature (seed
byte 0x01). `reproduction.test.ts` re-derives the device key, digest, and signature independently
via the pinned wallet libsodium family and asserts each equals the on-disk golden — the golden is
read and checked, never written by a test (A8). No approval-preimage vectors were fabricated: every
pinned value reproduces from the canonical-fields byte goldens.

## Encoding tiers

1. `.contract.ts` `as const` sources — the byte authority.
2. `gen/approval.json` — review-diff snapshot of `buildApprovalManifest()`, never byte authority;
   `manifest.freeze.test.ts` diffs it. Regenerate with `JSON.stringify(buildApprovalManifest(), null, 2) + "\n"`.
3. Raw digest-pinned byte goldens under `goldens/approval/` (prettier/eslint-ignored, digest-pinned
   in `APPROVAL_CONCERN_MANIFEST.goldenRefs` and cross-checked by `manifest.freeze.test.ts`).

## Boundary

Depends on the artifacts concern (the expected-artifact/testkit surfaces). The approval tuple's
economic intent is the same intent the `zp-send-external-expected-v1` artifact binds; this concern
adds the tuple's time bound, authentication semantics, and the post-approval state machine that
`artifacts-freeze` explicitly carves out of the frozen-artifact scope. No DB, network, worker, or
private-key seam — the dependency-boundary gate forbids them; the real-PostgreSQL
crash/concurrency and live-chain proofs belong to the runtime layer.

## Scope boundary

This concern freezes the send-inner immutability RULE only (no re-form of chain link, time,
expiry, destination, or amount once a sign intent exists — see the one-partial state machine
above). It deliberately does NOT mint the `SEND_EXTERNAL` redemption-inner byte template or its
golden: the canonical-fields appendix provides no A.8 spec vector for it, the A.8.1 SplitChain
golden is a RECEIVE inbound inner (payer-chosen 3600s expiry), and the SEND_EXTERNAL redemption
window (`two-timer-separation`, `SEND_REDEMPTION_WINDOW_SECS`, 300s) governs a materially
different, still-unminted object. `appendix-a8.docs-artifact.test.ts` asserts no
`goldens/approval/` file claims to be a redemption inner, so a future mis-scoped mint fails loudly
here.
