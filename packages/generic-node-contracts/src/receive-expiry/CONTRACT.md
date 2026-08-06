# Receive-expiry concern — frozen contract

Repairs the receive late-landing state hole: a receive may expire after a durable possible landing
but land later. Binding source: the **receive-expiry prevention rule**, which takes the STRICTER
branch — PREVENT terminal expiry after the durable-candidate boundary rather than define
`EXPIRED -> RECEIVE_LANDED`. Tier-1 grounds: the 30-minute fold-out rule, the landing-proof
complete-path rule, C-04 / C-09, invariant #6, the one-in-flight-per-wallet rule. LIVE-CHAIN premise
(see below). Consumes the wallet-state concern's lease-hold predicate (consistency asserted).
CONTRACT_FREEZE: data + pure verifiers + tests only, no DB code.

## Frozen facts

- **Durable-candidate boundary** (`boundary.ts`): the boundary is `EXISTS(operation_transactions)`
  at min phase `STEP1_SIGNATURE_PERSISTED`, under the op-row lock. `isPastDurableCandidateBoundary`
  keys off the persisted operation-transaction phase, NEVER the public `execution_phase` (which
  still reads `NOT_STARTED` at the boundary — keying off it reopens the hole;
  `boundaryFromExecutionPhaseIsUnsafe` proves the divergence). `OPERATION_TRANSACTION_PHASES` is
  the `operation_transactions.attempt_phase` CHECK domain of the data model, in that domain's
  frozen sequence, and never borrows a public `execution_phase` name
  (`attempt-phase-domain.test.ts` pins it against inlined frozen fixtures).
- **Expiry legality** (`lifecycle.ts`): terminal `-> EXPIRED` is legal ONLY pre-boundary. Post-
  boundary, `READY -> EXPIRED` is forbidden; the receive stays `READY`, holds the lease (the one-in-flight-per-wallet rule), and appends `operation.needs_attention` with the ONE new attention reason
  `POST_EXPIRY_RECONCILING` — NEVER `operation.expired`. No new state / event / TTL. Terminal states
  (`EXPIRED`, `RECEIVE_LANDED`) carry a terminal timestamp; `READY` / `INDETERMINATE` stay open.
- **Resolution** (`resolution.ts`): post-boundary a receive reconciles ONLY to `RECEIVE_LANDED`
  (the landing-proof complete-path rule) or `INDETERMINATE` (indefinitely). No
  `EXPIRED -> RECEIVE_LANDED`, and NO 30-minute fold-out (`FOLD_OUT_ALLOWED = false`; the
  landing-proof complete-path rule has no `PROVEN_NOT_LANDED` — folding + freeing reopens
  the landed-into-released-wallet loss). An unattributed deep successor -> `INVARIANT_BREACH_QUARANTINE`.
- **Consumer terminality** (`consumer.ts`): a platform consumer MUST NOT treat receive `EXPIRED` as
  a terminal landing failure unless it positively proves `release_status == RELEASED_T0_UNCHANGED`.
- **Released-wallet safety** (`consumer.ts`): a wallet released to AVAILABLE is observed; any head
  movement quarantines it; it is never a new op's T0 baseline (release-then-retire, not reassign).
- **Live-chain premise** (`assumptions.ts`): the whole non-terminal-expiry design is valid ONLY
  while no ZKZ can land on a node receiver without that wallet's step-2 signature (v2 = 2-signer
  `unique_combinable`). Frozen as a load-bearing ASSUMPTION whose confirmation is a
  **live-gateway acceptance** item — not provable in this contract.

## Cross-concern consistency

`manifest.test.ts` asserts this concern agrees with the wallet-state concern's
`canExpiryReleaseReceiveLease`: post-boundary, neither the lease releases nor the receive terminally
expires; pre-boundary, both may.

## Expiry -> reconcile -> release sequencing (frozen)

The sequencing contract for a post-boundary expiry, as data + pure verifiers (wired to .1's
resolution; .1 wins). **MONEY-LOSS guard:** there is NO release disposition post-boundary at any
proof level. A reconcile-first, T0-unchanged, fully-acked read must NOT resolve to a
`released`/`RELEASED_T0_UNCHANGED` disposition — that would let the lease drop while a signed,
durably-persisted tx could still land (double-spend). The prevention rule's stricter branch offers
no such exit. The .1 consumer's `RELEASED_T0_UNCHANGED` safe-terminal branch (`consumer.ts`) is
valid ONLY for the **pre-boundary** `EXPIRED` + T0-proof release path — it is unreachable from a
post-boundary reconcile.

- **Order** <!-- contract-allow:frozen-module-path-and-const-citation --> (`ordering.ts` `EXPIRY_RECONCILE_RELEASE_ORDER`): `hold_lease -> retain_evidence ->
  reconcile_first -> resolve_or_release`. Resolution never precedes reconcile.
- **Disposition** (`postBoundaryExpiryDisposition`): held until reconcile completes; a landing ->
  `RECEIVE_LANDED`; durably inconclusive -> `INDETERMINATE` (held indefinitely, even with a
  head-unchanged, fully-acked read — that combination is NOT no-landing proof); otherwise held and
  reconciling. Output domain is exactly `{RECEIVE_LANDED, INDETERMINATE}` (`resolution.ts`).
  `leaseDropAllowed` permits a lease drop only on a landing — never while held or INDETERMINATE.
- **Forbidden shortcuts** (`shortcuts.ts` `FORBIDDEN_SHORTCUTS`) with detection verifiers:
  `post_boundary_release_on_reconcile` (the exact "fully proven" combination above — flagged, not
  treated as safe), `evidence_disposal_on_expiry`, `lease_drop_before_disposition`. Each reopens the
  late-landing loss the prevention rule closes.

## Fault injection over every receive expiry phase (frozen)

The full phase matrix as freeze tests over the .1/.2 contracts (`phases.ts` catalog + snapshot
`gen/receive-expiry-phases.json`; `fault-injection.test.ts` drives it). Eight phases, each with its
durable `operation_transactions` phase and frozen expiry outcome:

- pre-boundary (terminal expiry legal): `unassigned`, `pre_arm`, `post_arm` (no operation_transactions
  row yet).
- post-boundary (held, non-terminal): `candidate_persisted` (the boundary, STEP1 persisted),
  `pre_sign`, `post_sign`, `ambiguous_submit`, `landed_before_read`.

Proven per phase: the boundary classification derives from `EXISTS(operation_transactions)` (matches
`isPastDurableCandidateBoundary`); the expiry outcome (terminal vs held POST_EXPIRY_RECONCILING) per
.1; the .2 disposition at the landing races (landed -> RECEIVE_LANDED, ambiguous -> held). Restart
races re-read the durable operation_transactions phase and preserve the boundary. Negatives per phase
class: no post-boundary phase permits terminal expiry; a restart at a post-boundary phase never
produces terminal expiry (and an execution_phase-keyed restart is shown unsafe).

## Scope boundary

.1 (boundary + state graph), .2 (sequencing), and .3 (phase fault-injection) freeze
the contract + verifiers + tests only (CONTRACT_FREEZE): no DB code, no reconcile/release runtime.
Binding the reconcile oracle and the release path to real queries is a later implementation slice.
