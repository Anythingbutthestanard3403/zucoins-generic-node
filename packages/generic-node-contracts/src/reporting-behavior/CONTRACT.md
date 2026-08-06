# reporting-behavior — CONTRACT

Freeze slice: **prove replay and key-rotation behavior** (the final slice of the reporting group;
depends on the register slice + reporting-tuples). Gate: `CONTRACT_FREEZE`.

Governing sources: canonical fields A.5/A.6; the API contract's reporting surface. Decisions:
`reporting-ingest-auth` / `signed-event-log` / `sealed-store` + **`reporting-channel`** (60s window
vs SIGNED issued_at; durable single-use nonce; per-node gapless pre-signed seq; seq-cursor
retirement; revoke-to-zero fail-closed; restore monotonic epoch + hash-chain hard-stop).

## Scope boundary

There is no runtime server in this CONTRACT_FREEZE group, so each behaviour is modelled as a **pure
decision function** over frozen inputs, and the freeze test drives the full scenario matrix. A
live-server acceptance run of the same matrix is a later implementation slice. The decisions
consume the register slice's lifecycle rules and reporting-tuples' tuple goldens — both win on any
conflict.

## What is frozen (`decisions.ts` + `matrix.ts`)

Five behavioural dimensions, with frozen outcome cells snapshotted in `gen/reporting-behavior.json`:

- **request** — `evaluateReportRequest`: tenant equality first; then a strictly positive signed
  lifetime no greater than 60,000 ms; then the one ingress receipt instant with zero skew and
  inclusive `issued_at <= receipt <= expires_at` boundaries; then byte-exact signed-versus-actual
  method, raw target, and body-digest binding; then the durable single-use nonce. Fresh and both
  exact time boundaries accept. One millisecond outside rejects; zero/negative/>60s windows reject;
  method, target, and body mutation each have distinct rejects. The future HTTP adapter captures the
  target before URL parsing and must perform all binding checks before atomically consuming a nonce.
- **rotation** — `evaluateKeyUse`: key status first (the register slice's verifier sequence). Current
  ACTIVE → ACCEPT_CURRENT; prior ACTIVE during overlap → ACCEPT_PRIOR_OVERLAP; retired →
  REJECT_RETIRED; revoked → REJECT_REVOKED (terminal, even in the current slot); unknown →
  REJECT_UNKNOWN; no active key → ALARM_NO_ACTIVE_KEY (revoke-to-zero, loud fail-closed).
- **cutover** — `cutoverNeverGoesDark`: the new current is activated BEFORE the prior is retired, so
  no intermediate registry has zero active keys. Retire-before-activate is INVALID.
- **event_stream** — `evaluateTenantSeq` + `evaluateChainAppend`: a tenant-filtered consumer treats
  any strictly greater seq as an advance (a skipped seq is another tenant's event, NOT a gap); a seq
  at or below the cursor is a reorder/replay. The node-global hash chain is the true gap detector —
  an intact `previous_event_hash` link accepts, a mismatch is a HARD_STOP_CHAIN_BREAK. The intact
  case is exactly reporting-tuples' golden B linking to golden A.
- **restore** — `evaluateRestoreIngest`: a post-restore stream must carry a strictly greater
  monotonic epoch (so a replayed seq cannot silently collide); within an epoch a hash-chain break is
  a hard stop; an epoch regression is rejected.

## Consuming the register and tuple slices

The freeze test asserts the rotation transitions the matrix exercises are legal per the register
slice's `isLegalReportingKeyTransition`, that
`ROTATION_MODEL.revokeCurrentReactivatesPrior === false` and `revokeToZero` is the ALARMED state,
and that the chain-intact scenario is exactly reporting-tuples'
`eventChainLinks(NODE_EVENT_A_EVENT_HASH, NODE_EVENT_GOLDEN_B)`. Drift in either prior slice fails
here.

## Mandatory negatives

Every dimension carries at least one reject / hard-stop / alarm / invalid outcome, asserted both
individually and by a per-dimension scan. Demonstrated to fire: breaking a decision function flips
its dimension's reject cells and reddens the sync golden, the dimension assertions, and the
per-dimension-negative check.

## Scope handoff

CONTRACT_FREEZE only. A live-server behavioural acceptance run is a later slice. This completes the
reporting group: identity/handshake, signed bytes, and replay/rotation behaviour.
