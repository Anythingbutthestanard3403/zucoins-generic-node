# Observation concern — CONTRACT_FREEZE

Frozen artifacts for the frozen permanent exact observation ledger. Canonical rule:
`observation-dedup`. Governing sources: freeze-gate: permanent retention; product-evaluation:
observation feed; the data model: enum vocabulary and observation tables; observation-verification:
capture and classification, retention and goldens; integration: observation feed (boundary evidence
only). Gate: contract + verifiers + tests only — **no runtime/production observation
implementation.**

## What the record layer freezes

The **raw observation record contract**: the field shape of a captured/persisted observation,
the pairwise consecutive-dedup primitive, and the permanent-retention rule.

- **`enums.contract.ts`** — `observer_domain`, `observation_parse_result`,
  `observation_relationship`, `gateway_observations.wallet_role`, and
  `observation_anomalies.kind` vocabularies, transcribed from the data model's enum vocabulary and
  observation tables with member sequence frozen (the SQL declaration sequence).
- **`scalars.contract.ts`** — the `sha256_hex`, `padded_base64url_pubkey`,
  `padded_base64url_signature`, and `zkz_balance_text` domain patterns the record's fields carry.
- **`record-fields.contract.ts`** — sequenced field contracts (name, type, nullability,
  semantics) for four record shapes: the pre-parse **capture**, the persisted append-only
  **`gateway_observations`** row, the mutable **`wallet_observation_cursors`** index, and the
  permanent **`observation_anomalies`** row. Covers the checklist exactly: byte column,
  digest, length, endpoint fingerprint, request metadata, observer-wallet sequence,
  verification result, relationship, dedup linkage, timestamps.
- **`invariants.contract.ts` + `record-verifier.ts`** — the six `gateway_observations` CHECK
  constraints (field presence keyed on `parse_result`) plus enum/scalar format, as a pure
  total verifier returning the frozen invariant ids a record violates.
- **`dedup.contract.ts` + `dedup-predicate.ts`** — the consecutive-dedup key
  (`EXACT_RAW_BYTE_EQUALITY`), the digest's role (candidate index, never equality authority),
  the pairwise `decideAppend` primitive (both sides verified AND digest → length → exact-byte
  equal ⇒ suppress; else append), and the permanent-retention facts (append-only,
  anomalies-always-append, no global dedup, recurrence retained, bytea-never-JSONB).

Byte behaviour this pins: byte-identical `A,A` ⇒ one row + a cursor sighting; `A,B,C,A` ⇒ four
rows; identical malformed `X,X` ⇒ two rows + two anomalies; a digest collision with differing
bytes still appends.

## What the classification layer freezes

The **semantic relationship classification** that runs on an appended verified row, ON TOP of
the record layer's byte primitive (observation-verification: capture and classification;
`observation-dedup`).

- **`relationship.contract.ts`** — the frozen classification table (condition sequence =
  evaluation precedence), the three-tier `COMPARISON_LADDER` (record-layer bytes → equal
  fingerprint = `EQUIVALENT_STATE_DIFFERENT_ENVELOPE` → differing fingerprint = state
  transition), the seven classifier-output relationships, the three non-classifier members
  (`DUPLICATE` diagnostic, `COMPLETE_PATH_SUCCESSOR` used only by `complete-path-adjudication`,
  `NOT_APPLICABLE` non-verified), and the single state-unchanged output. A census test proves the
  outputs plus non-outputs exactly cover the record layer's relationship enum.
- **`relationship-classifier.ts`** — the pure `classifyRelationship` decision procedure that
  separates an equivalent-envelope change (`state_changed=false`) from a real state transition
  (`state_changed=true`), and classifies `SUCCESSOR` / `SIGNATURE_COLLISION` /
  `GENESIS_AFTER_HISTORY` / `REGRESSION` / `UNEXPLAINED_JUMP`. It consumes the record layer's
  semantic fingerprint and never sees raw bytes; the byte comparison stays in the record layer.

Boundary held: the record layer's frozen shapes win on any conflict — this slice imports and
consumes the relationship enum and the record shape, and re-freezes neither.

## What the sequence proofs establish

The permanent observation **sequences**, composing the byte primitive and the classifier
end-to-end (observation-verification: retention and goldens; `observation-dedup`).

- **`sequence-driver.ts`** — a pure, in-memory reducer `runObservationSequence(captures,
  cursor)` that folds a read stream through `decideAppend` then `classifyRelationship`,
  allocating `wallet_seq`, counting suppressed sightings and anomaly rows, and threading the
  cursor as plain data. No DB, no persistence, no worker.
- **`sequences.contract.ts`** — the frozen golden outcomes: `AA_BYTE_IDENTICAL` (1 row + 1
  sighting), `AA_PRIME_WRAPPER` (2 rows, second `EQUIVALENT_STATE_DIFFERENT_ENVELOPE`),
  `ABCA_REGRESSION` (4 rows, final `REGRESSION` + 1 anomaly), `MALFORMED_XX` (2 rows + 2
  anomalies), `DIGEST_COLLISION` (forced-equal digest, differing bytes → 2 rows), plus the
  restart / concurrent / append-only sequence properties.
- **`sequence-proof.test.ts`** drives every golden and reproduces its frozen outcome, proves
  restart restoration (resume from a returned cursor equals the whole run) and per-stream
  independence (each stream's own contiguous `wallet_seq`), and carries a negative per class
  (byte-different/non-verified never suppresses; a different head is never `EQUIVALENT`; a
  non-recurring 4th state is `UNEXPLAINED_JUMP` not `REGRESSION`; a lost cursor diverges; a
  shared cursor leaks sequence).

Out of CONTRACT_FREEZE scope: real-PostgreSQL serialized-write evidence — no DB seam is permitted
in this package (the dependency-boundary gate forbids `pg`/`postgres`). The logical serialization
and per-stream sequencing invariants are proven here in-memory; the runtime build owns the
real-PostgreSQL serialization test.

## Canonical reconciliations (flagged)

- **`b_amount` domain.** `gateway_observations.b_amount` is a role-relative absolute
  **balance**, so it uses the canonical `zkz_balance_text` domain
  `^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$` (`0 ≤ amount < 1e8`, "0" legal). This **overrides**
  the draft's `zkz_amount_text` column type with its unbounded regex
  `^(0|[1-9][0-9]*)(\.[0-9]{1,32})?$` in the data model. Never the strictly-positive
  `zkz_amount_positive_text` domain — a genesis/swept balance of "0" is legal. `zkz_balance_text`
  is owned by the `amounts` concern (`zkz-amount-grammar`) and only referenced here.
- **`COMPLETE_PATH_SUCCESSOR` / `UNEXPLAINED_JUMP`** appear in the `relationship` vocabulary but
  their semantics are the `complete-path-adjudication` landing oracle's; here they are frozen only
  as members of the field domain.

## Encoding tiers

1. `.contract.ts` `as const` sources — the byte authority.
2. `gen/observation.json` (package `gen/`) — review-diff snapshot of `OBSERVATION_CONTRACT`,
   never byte authority; `gen-sync.test.ts` asserts it equals a fresh emit. Its sha256 is pinned
   in `OBSERVATION_CONCERN_MANIFEST.goldenRefs` and cross-checked by `manifest.census.test.ts`.
   Regenerate with the exact serializer `gen-sync.test.ts` uses:
   `JSON.stringify(toSortedPlainObject(OBSERVATION_CONTRACT), null, 2) + "\n"`.
3. No tier-3 raw digest-pinned byte artifact: this slice governs field shape/types/invariants,
   not a fixed signed preimage (the `zp-wallet-head-fingerprint-v1` preimage is Appendix A's,
   owned by the fingerprint/verification contracts).
