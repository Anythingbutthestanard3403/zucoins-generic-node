# implementer-events — CONTRACT

Freeze slice: **byte-freeze of the zp-implementer-event-v1 / zp-implementer-checkpoint-v1 /
zp-implementer-keyrotation-v1 goldens**. Gate: `CONTRACT_FREEZE`.

Governing sources: canonical fields A.1.1 (suite serializer), A.6 (zp-node-event-v1 11-field order + <!-- contract-allow:frozen-field-order-citation -->
implementer-event architecture), A.8 (deterministic goldens, seed byte 00 node event key), A.9
(negative vectors); the closed nine-value event set; the data model: dual continuity and
implementer_seq encoding (the implementer-scoped continuity stream). Canonical rules:
`reporting-channel`, `reporting-key-enrolment`, `pull-cursor-authority`, and
`checkpoint-anti-rollback`.

## What is frozen

Three new suite-canonical signed tuple types for the tenant-facing implementer-scoped continuity
stream (the dual continuity model). These are the artifacts actually served on
`/v1/events`, the SSE stream, and `/v1/state/snapshot` — the operator/auditor-only
`zp-node-event-v1` and its node-global `seq` are never served to tenants.

- **`implementer-event-tuple.ts` — `zp-implementer-event-v1`.** 13-field order: purpose, <!-- contract-allow:frozen-field-order-citation -->
  canonical_version, node_id, implementer_id, event_id, implementer_seq, operation_id, wallet_id,
  event_type, data_sha256, node_event_hash, implementer_previous_event_hash, created_at. Carries
  the implementer's own gapless `implementer_seq` (per-(node_id, implementer_id) counter allocated
  pre-sign from a locked-head counter — NOT IDENTITY), the same underlying event_id/data_sha256 as
  the corresponding zp-node-event-v1 row, and an independent
  `implementer_previous_event_hash` chain (never the node-global chain). The non-invertible
  `node_event_hash` = SHA256(preimage_bytes || signature_bytes) of the corresponding
  zp-node-event-v1 row binds for operator/auditor correlation only — the tenant cannot recover the
  global `seq` or `node_events.previous_event_hash` from it. Signed with the node's existing
  EVENT_SIGNING key (A.8 seed byte 00) — no new custody surface (the key-custody rule).

- **`implementer-checkpoint.ts` — `zp-implementer-checkpoint-v1`.** 9-field order: purpose, <!-- contract-allow:frozen-field-order-citation -->
  canonical_version, node_id, implementer_id, checkpoint_epoch, implementer_seq_head,
  implementer_event_hash, signing_key_id, created_at. Anti-rollback: persists the highest
  checkpoint epoch/head seen and REFUSES any lower value. Validates the signing key against the
  seq-canonical key via the node-identity directory. Conflicting equal-epoch heads =
  INVARIANT_BREACH (alarm, never pick one).

- **`implementer-keyrotation.ts` — `zp-implementer-keyrotation-v1`.** 11-field order: purpose, <!-- contract-allow:frozen-field-order-citation -->
  canonical_version, node_id, implementer_id, implementer_seq, retired_key_id, new_key_id,
  new_public_key, supersedes_key_id, implementer_previous_event_hash, created_at. Expresses
  retirement of an implementer's reporting key via that implementer's own implementer_seq cursor,
  never the node-global cursor (preserves NC2).

## Open questions

- **Key-rotation co-signing parties:** the exact co-signing parties for
  `zp-implementer-keyrotation-v1` are an OPEN QUESTION. This freeze signs with the
  node event key only (A.8 seed byte 00) and does NOT decide the co-signing question. Resolution
  is deferred; a future decision may add co-signature fields without changing the frozen field
  order (additive-only at the end, new canonical_version, or a new purpose literal). <!-- contract-allow:frozen-field-order-citation -->

## Non-invertibility proof

`node_event_hash = SHA256(preimage_bytes || signature_bytes)` of the corresponding
`zp-node-event-v1` row. The tenant sees only this 32-byte hash. Because SHA-256 is a one-way
function and the preimage contains the global `seq` and `previous_event_hash`, the tenant cannot
recover either value from the hash alone. A negative vector proves this: given only the
`node_event_hash`, no feasible computation yields the global seq or the global previous_event_hash.

## Cross-implementation verification (the `reporting-channel` ship gate)

The freeze test derives the A.8 seed-0x00 (node event) keypair with node:crypto, asserts the
derived public key equals the A.8 fixture, reproduces all signatures byte-for-byte, confirms the
implementer event hashes chain across A -> B, and verifies the checkpoint and keyrotation tuples
sign and verify correctly. All cross-implementation node-signs -> consumer-verifies goldens ship
together in one commit, as the `reporting-channel` ship gate requires.

## Additive-only constraint

Existing zp-node-event-v1 golden A/B bytes are reproduced byte-for-byte and UNCHANGED:
- Golden A SHA-256: `9644a48d9f0a988c62321a371ad66f993ae4f428ae3a3ee48d0dc290e0560226`
- Golden B SHA-256: `42c27944165f242f2c4fc276ff369da58ed6055ffd71c2788f1f6fe73aec2e2c`

Zero edits to existing goldens. This concern is purely additive.
