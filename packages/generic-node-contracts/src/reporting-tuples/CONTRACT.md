# reporting-tuples — CONTRACT

Freeze slice: **freeze signed request and event bytes** (part of the reporting group, depends on
the reporting-auth register slice). Gate: `CONTRACT_FREEZE`.

Governing sources: canonical fields A.1.1 (suite serializer), A.5 (`zp-report-request-v1`), A.6
(`zp-node-event-v1`), A.8 (deterministic goldens), A.9 (negative vectors); the state-event
reference's closed event set; the API contract's reporting surface. Decisions:
`reporting-ingest-auth` / `signed-event-log` / `sealed-store` + **`reporting-channel`** (two-key
PULL, 60s window vs SIGNED issued_at, per-node gapless pre-signed seq, seq-cursor event-key
retirement).

## What is frozen

Unlike the register slice (which had to define the missing register tuple), both tuples here
already exist in the canonical field appendix. This slice encodes them as as-const contract data
with byte-exact goldens that reproduce the A.8 pinned digests and signatures exactly, plus pure
verifiers and the semantics.

- **`request-tuple.ts` — `zp-report-request-v1`.** A.5 field sequence
  (`node_id, implementer_id, method, path, body_sha256, nonce, issued_at, expires_at`), the five
  mandatory `X-ZP-Reporting-*` headers (Key-Id selects the registration and is NOT signed),
  and the strictly-positive, at-most-60-second window enforced against the SIGNED `issued_at`.
  The original A.8 queryless golden remains byte-for-byte unchanged (488 bytes, sha256
  `31a0edb5…`, reporting-key signature `Drt5bF…`). A separate 477-byte query-bearing golden covers
  `GET /v1/events?after_implementer_seq=1043&limit=100&wait_seconds=30`.
- **`request-target.ts`.** The signed target is the exact visible-ASCII origin-form target captured
  by the outer trusted HTTP adapter before parsing/decoding/routing. It is never reconstructed from
  URL components and never sourced from `X-Original-URL`. The policy rejects percent encoding,
  `+`, fragments, backslashes, parser aliases, unknown routes/keys, duplicate keys, and noncanonical
  query sequence. Query keys are unique and strictly ascending by raw ASCII bytes; values are checked
  against each signed reporting route's frozen schema. Canonical timestamps require exact
  `YYYY-MM-DDTHH:mm:ss.sssZ`, calendar validity, and an exact `toISOString()` round trip. Clock skew
  is frozen at zero; any future nonzero allowance requires a separately frozen decision.
- **`event-tuple.ts` — `zp-node-event-v1`.** A.6 field sequence, the nine closed neutral event types
  (the state-event reference), the per-node gapless pre-signed sequence model (one counter per node;
  a skipped seq is another tenant's event, not a gap; never identity/bigserial), and the hash-chain
  rule `event_hash = SHA256(preimage_bytes || signature_bytes)`. Golden A (A.8, 460 bytes, sha256
  `9644a48d…`, node-event signature `AQPu22…`, event_hash `1f0ec14d…`) and golden B — a null
  `wallet_id` event (the `sealed-store` null case) chained off A,
  `previous_event_hash == A.event_hash`.
- **`verifier.ts`.** Pure structural verifiers `verifyReportRequestPreimage`,
  `verifyNodeEventPreimage`, and `eventChainLinks`. Signature and event-hash crypto is exercised in
the freeze test via node:crypto, keeping the package a zero-runtime-dep leaf. The reporting
behaviour slice consumes these. Runtime adapters must preserve the raw request-target (including
through any trusted proxy) or fail closed; a deployment rewrite is non-conformant.

## Cross-implementation verification (ship-gate coverage)

The freeze test derives the A.8 seed-0x04 (reporting) and seed-0x00 (node event) keypairs with
node:crypto, asserts the derived public keys equal the A.8 fixtures, reproduces both A.8 signatures
byte-for-byte, and confirms the event hashes chain across A → B — including the null-field case, as
the `reporting-channel` ship gate requires (cross-implementation goldens for both tuples including
null-data / null-previous_event_hash).

## Alignment with the register slice (the register slice wins)

The freeze test asserts `zp-report-request-v1` and `zp-node-event-v1` are exactly the purposes the
register slice froze in `REPORTING_KEY_ALLOWED_PURPOSES` / `NODE_EVENT_KEY_ALLOWED_PURPOSES` and
`V2_REPORTING_PURPOSES`. Any drift from the register slice fails here.

## Scope boundary

CONTRACT_FREEZE only — no runtime code. The transport wiring, nonce store, sequence allocator, and
event outbox are later implementation slices. Behavioural replay / rotation / cutover / rollback /
batch-gap / reorder tests belong to the **reporting-behavior** slice (consuming these verifiers and
goldens).

## Judgment call

- **J1 — event golden B fixture.** A.8 has one event golden (previous_event_hash null, operation +
  wallet present). This slice adds golden B (`operation.needs_attention`, `wallet_id: null`,
  event_id `dddd…` extending the A.8 letter series, chained off A) to cover the `reporting-channel`
  null-case + hash-chain ship-gate requirement. Test-only fixture; signature/hash recomputed from
  the A.8 seeds.
