# reporting-persistence — CONTRACT

Governing decisions: `reporting-channel` and `reporting-key-enrolment`. Governing sources: the
data model's reporting, nonce, and idempotency sections; the API contract's wire conventions,
reporting surface, and event serving; signing custody; operations recovery. The frozen
`bootstrap-enrolment-trust-root` remains unchanged. The reporting-tuples raw target is consumed as
opaque exact signed bytes and is never normalized or reconstructed here.

## Shared durable nonce ledger

Nonce uniqueness is exactly `(node_id, implementer_id, nonce)`. Route and reporting key are
evidence projections, never replay scope. The same ledger covers both
`zp-reporting-register-v1` bootstrap/rotation nonces and every `zp-report-request-v1` nonce.
`reporting_key_id` is nullable only for a first-key bootstrap; it is required for an
existing-key-anchored rotation and every signed request. Registration burns also retain the new
reporting-key identity. Request signatures have a maximum 60-second issued-to-expiry window;
registration signatures have a maximum 300-second window. Every accepted burn immutably retains
purpose, route, key identity, lifecycle epoch, exact request preimage and SHA-256, signature,
method, raw target, body digest, signed issue/expiry times, receipt/consumption times, and
retention class.

Bounded shape, time, size, and rate checks plus binding, lifecycle, and signature validation all
finish before a short transaction locks and rechecks the shared lifecycle head, inserts the nonce
evidence, and commits. Only then may post-burn work begin. A completed idempotency record is looked
up and its logical fingerprint is checked before protected object lookup: an exact match replays
even if the object was later removed, while a changed fingerprint conflicts without revealing
object existence. Protected lookup runs only when no completed result exists. Invalid, expired,
revoked, or badly signed requests insert nothing. Authenticated 404, 409,
500, handler failure, and crash paths retain the committed burn.

## Reporting-key lifecycle

Reporting key identities are immutable and contain public material only. Exactly one lifecycle
head exists per node and implementer. Its canonical pre-bootstrap state is epoch zero, null current,
prior and event IDs, null overlap expiry, and an active authorization hold. `FIRST_KEY_ACTIVATED`
advances that head to epoch one, activates the pending key as current, and clears the hold. The only
other event names are `KEY_ROTATED`, `PRIOR_KEY_RETIRED`, `KEY_REVOKED`, `AUTH_HOLD_SET`, and
`AUTH_HOLD_RELEASED`. These events lock that same head; the first valid commit wins and
appends one event unique by `(node_id, implementer_id, epoch)`. A lifecycle commit derives the
legal transition from authoritative key identities and states. It never accepts a caller's claim
that the transition is valid, and the complete new head must byte-for-byte project the cited event.
Lifecycle event bytes are permanent, immutable, append-only, and chained by an exact predecessor
event hash after the first event. Revoked and retired identities never reactivate, and once the sole
active key is revoked that `(node_id, implementer_id)` lifecycle head is permanently dead at the
contract layer: recovery is bootstrap of a new `implementer_id`, never a fresh enrolment of the same
one. A rotation never silently replaces an occupied prior slot; that prior must first receive an
explicit retirement or revocation event.
The `reporting-key-enrolment` prior-key overlap is strict and half-open for exactly 24 hours: the key must occupy the
eligible prior slot, remain ACTIVE and non-revoked, and the receipt must be at or after successor
commit and strictly before overlap expiry. Both commit and admission derive expiry internally as
successor commit plus exactly 24 hours; a stored shorter or longer value is invalid. First-key
bootstrap evidence is the `bootstrap-enrolment-trust-root` three-gate set (authenticated caller
identity, node-origin approval, and proof of possession). Rotation is
separate evidence: an existing-key anchor plus proof of possession. For every registration, durable
nonce and enrolment rows must exactly agree on the nonce evidence ID, purpose, new key, preimage text,
preimage digest, signature, and signed issue/expiry times. Bootstrap evidence must cite the same
bootstrap evidence ID and new key. Rotation must cite the same existing authorizing/superseded key,
and its retained authorizing preimage, digest, and signature must exactly match independently verified
authorizer evidence.

## Mutation idempotency

Mutation idempotency uniqueness is exactly
`(node_id, implementer_id, route_id, idempotency_key)`. Its logical signed fingerprint contains
method, the opaque exact raw target, and body digest only. Nonce, key identity, lifecycle epoch,
signed/receipt times, and the unsigned idempotency header are excluded. A changed method, target,
or body conflicts; a fresh nonce using the same idempotency record replays the exact committed HTTP
status and response bytes across key rotation. Arm and verification-complete additionally enforce
guarded request-tuple uniqueness so changing only the unsigned header cannot execute either mutation
twice. The duplicate decision compares the actual method, raw target, and body digest; the stored
logical fingerprint is derived audit evidence and cannot be supplied as a bypass.
`Idempotency-Key` is 16–255 visible ASCII characters (`0x21`–`0x7e`). The mutation, HTTP status,
an immutable copy of the exact response bytes, and completion timestamp commit atomically; a crash
cannot leave a partial result or a durable pending idempotency row. Status, bytes, and completion
time are mandatory for every persisted row, and a completed parent without its matching child is
invalid. The nonce burn, completed idempotency row, and child
mutation record cross-bind the same nonce, idempotency and child identities plus method, exact raw
target, body digest, and logical fingerprint. Every mutation route retains its burn and idempotency
evidence permanently. Nonce, idempotency, child, and exact response evidence is append-only and
immutable. Each replay returns a fresh byte copy with the exact committed content.

## Restore, retention, and custody

Backups include all reporting key, lifecycle, nonce, idempotency, preimage, signature, digest, and
exact response evidence. Reporting authorization always starts hard-held after restore. Release
requires independently verified external lifecycle-epoch and nonce-burn-high-water markers, with
the restored epoch and high-water exactly equal to external authority; local regression or local
advancement remains held. Equality alone never opens the channel. Release also requires the restored
event hash to equal the independently trusted event
hash and the next event's previous-hash link to continue from it. Reporting admission requires
both the node restore hold and lifecycle-head authorization hold to be clear; automatic release is
forbidden. Read-burn pruning is forbidden until a safety source
and margin are separately frozen. Mutation burns, mutation idempotency, and lifecycle evidence are
permanent.

This concern stores exactly `id`, `node_id`, `implementer_id`, `public_key`, and `registered_at` for
an implementer reporting key identity. Every additional or substituted field is rejected, including
unknown secret-like fields. It defines no private, seed, secret, or sealed-store-reference field.
It creates no application migration, legacy push-reporting table,
frozen v1 path change, or live action, and it changes no signed tuple or existing golden.
