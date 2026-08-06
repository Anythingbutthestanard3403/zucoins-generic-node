# reporting-auth — CONTRACT

Freeze slice: **reporting.1 — freeze reporting identity and handshake** (first slice of the
reporting group; closes the `reporting-channel` build-blocker). Gate: `CONTRACT_FREEZE`.

Governing spec: canonical-fields A.1.1 (suite serializer), A.5.1 (register tuple fields), A.8
(deterministic fixture), A.9 (required negative vectors); signing-custody: key inventory, purpose
separation, signing matrix; the API contract: signed reporting. Governing rules:
`reporting-ingest-auth`, `signed-event-log`, `sealed-store` (inherited principles),
`reporting-channel` (the two-key PULL contract) and `reporting-key-enrolment` (the frozen
`zp-reporting-register-v1` freeze that amends `reporting-channel` and discharges its
build-blocker).

## What is frozen (the `reporting-channel` build-blocker, closed by `reporting-key-enrolment`)

`reporting-channel` named one materially-incomplete piece before the group can go green: a
`zp-reporting-register-v1` enrolment / proof-of-possession tuple. The canonical field set had none
(A.4.3 is device-enrol; A.5 is the request tuple). `reporting-key-enrolment` froze it into A.5.1 /
A.8 with an exact field sequence and golden. This concern defines and freezes it, plus the
surrounding identity model.

- **`register-tuple.ts` — `zp-reporting-register-v1`.** The A.1.1 suite preimage
  `purpose + "\n" + JSON.stringify(payload)`, purpose as prefix and payload field 1,
  `canonical_version` the number 1, field sequence (A.5.1)
  `node_id, implementer_id, new_reporting_key_id, new_reporting_public_key, supersedes_key_id,
  nonce, issued_at, expires_at`. `supersedes_key_id` is `null` at bootstrap and the current active
  key id on rotation (present as JSON `null`, never omitted). The implementer self-signs it with the
  reporting private key → proof of possession of `new_reporting_public_key`, binding it to
  `(node_id, implementer_id, new_reporting_key_id)`. Enrolment ceremony window
  `REPORTING_KEY_ENROL_WINDOW = 300 s`. Byte-frozen golden preimage (477 bytes, the frozen A.8
  vector: SHA-256 `98fba788…9e7e`) with digest and proof-of-possession signature pinned in
  `digests.ts` and the raw bytes in `gen/zp-reporting-register-v1.preimage.txt`.
- **`keys.ts` — key ownership, custody, separation, Ed25519-only, legacy separation.** Two keys:
  the implementer-owned `reporting` key (node stores public only) and the node-owned `node_event`
  key. Each purpose-separated from the wallet and node-identity keys (signing-custody: purpose
  separation). No HMAC, no bearer. The v2 pull purposes are disjoint from the frozen legacy push
  purposes (`zupay-reporting-v1`, `-transport-v1`, `-handshake-v1`), which stay owned by the legacy
  channel.
- **`lifecycle.ts` — binding, revocation/rotation, restore guard.** Registration binds
  `reporting_key_id → (node_id, implementer_id)`; the request verifier requires a tuple's node_id
  AND implementer_id to EQUAL the binding, checked BEFORE object lookup (confused-deputy close).
  Per-key state machine `PENDING → ACTIVE → (RETIRED | REVOKED)`, terminal ends, no reactivation;
  verifier sequence `key_status → tenant_equality → signature`; rotation overlap (current+prior; event
  key retired by seq-cursor); revoke-to-zero is an explicit ALARMED fail-closed state; restore guard
  is a monotonic epoch + hard-stop on hash-chain break.
- **`verifier.ts`.** Pure structural verifiers and an injected-crypto PoP orchestration API (no
  bundled signature or curve implementation, so the package stays a zero-runtime-dep leaf).
  `verifyRegisterPreimage` enforces the A.9 layout/format classes;
  `reportingKeyMaySign`, `isLegalReportingKeyTransition`, `requestTupleMatchesBinding`,
  `credentialMechanismAllowed`. `verifyRegisterProofOfPossession` strictly decodes and exactly
  re-encodes the padded-base64url 32-byte embedded key and 64-byte signature, rejects noncanonical
  compressed encodings and the frozen complete eight-encoding `nonsmall_order`/torsion list, then calls
  the injected `validatePublicKeyPoint` callback before—and only on success—the injected
  `verifyDetached` callback with one named `{ publicKey, preimage, signature }` object. Each
  callback succeeds only on literal `true`; false, throw, truthy non-booleans, boxed booleans, and
  Promise values fail closed, and point failure never calls proof-of-possession verification.
  Callbacks receive fresh byte copies, verification receives the original exact preimage UTF-8
  bytes, and each successful verifier call returns a fresh result. The exported, runtime-frozen
  `REGISTER_PROOF_VERIFICATION_STAGES` tuple pins the seven exact sequenced stages and the manifest
  snapshots it.

  The byte-only checks establish only **canonical/prevalidated bytes**. Full canonical-encoding,
  on-curve, `main_prime_order_subgroup`, `nonidentity`, and `nonsmall_order` validity belongs to the
  injected point validator, which must itself return literal `true`. This
  zero-curve-math contract makes no runtime-complete validation claim. reporting.2 / reporting.3
  consume these.

## Proof of possession (handshake, end to end)

The freeze test derives the A.8 seed-0x04 reporting keypair with `node:crypto`, asserts the derived
public key equals the frozen A.8 reporting key (cross-validating our crypto against the suite),
signs the golden preimage, and asserts the signature equals the pinned golden and verifies. Signing
crypto lives only in the test; the package itself ships no crypto dependency.

## Scope boundary

CONTRACT_FREEZE only — no runtime reporting code, no HTTP, no key storage. reporting.1 owns the
**register** tuple and the identity/lifecycle model. The **request** tuple (`zp-report-request-v1`)
and **event** tuple (`zp-node-event-v1`) byte layouts, headers, nonce/time window, and seq/hash
fields are **reporting.2**; replay and key-rotation behavioural tests are **reporting.3**; the
package index/registry is assembled by the concern-manifest registry.

## Judgment calls

- **J0 — the frozen shape is authoritative.** An earlier 9-field draft (`reporting_key_id,
  reporting_pubkey, challenge`, golden `501d1f0d…`) is NOT adopted, and neither is the competing
  11-field freeze branch: the frozen 10-field `reporting-key-enrolment` / A.5.1 contract governs,
  and the minted golden hashes to its frozen `98fba788…9e7e`.
- **J1 — `new_reporting_key_id` fixture id.** A.8 has no reporting key id; `cccccccc-…` extends the
  A.8 letter series (aaaa=device_key_id, bbbb=event_id). Test-only, never a live key.
- **J2 — `nonce` and `supersedes_key_id`.** The node-issued single-use durable value per
  `(implementer_id, node_id)` is `nonce` (the enrolment freeze folded the earlier draft's separate
  `challenge` into it — the PoP signature itself proves possession, so no distinct challenge field
  is needed). Rotation uses `supersedes_key_id` (the current active key id, `null` at bootstrap)
  with a time-bounded 24 h overlap — a recorded departure from the event key's seq-cursor
  retirement.
- **J3 — strict state machine.** Only `PENDING → ACTIVE → (RETIRED | REVOKED)` is frozen, exactly
  as the `reporting-channel` rule states; `PENDING → REVOKED` and `RETIRED → REVOKED` are NOT added
  (an abandoned pending enrolment expires; hardening either would be an additive change).
- **J4 — bootstrap trust-root PERMANENT.** The `bootstrap-enrolment-trust-root` rule resolved the
  bootstrap "who may bind a first reporting key to an `implementer_id`" authority as Option A,
  PERMANENT. `BOOTSTRAP_TRUST_ROOT` (lifecycle.ts) and `evaluateBootstrapEnrolment`
  (reporting-behavior) enforce the frozen fail-closed permanent root — all three of an
  authenticated onboarding credential (implementer_id from the caller, never the body), a
  node-origin operator approval, and a valid PoP signature — granting live-ZKZ reporting authority.

## Evolving a frozen fact

Edit the fact, then regenerate `gen/reporting-auth.json` and, if the preimage changed, its raw
`gen/*.preimage.txt` artifact and the `digests.ts` pins (recomputing the signature from the fixture
seed) in the SAME commit.
