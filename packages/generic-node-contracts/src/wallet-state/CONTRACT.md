# Wallet-state concern — frozen contract

Aligns public wallet state with active-lease reality. Binding sources: the universal wallet lease
(`wallet_active_leases` is the SOLE wallet-sequencing authority), **`receive-expiry-prevention-rule`**
(a post-candidate receive holds its lease past expiry — the one-in-flight-per-wallet rule),
**`recovery-gate-rule`** (per-lease-role recovery gate), and the data model, operation flows, and
operations-recovery specs. Depends on pool-policy (state set + recovery eligibility);
**pool-policy wins on conflict**. CONTRACT_FREEZE: data + pure verifiers + tests only, no DB code.

## The problem this resolves

Boot inventory expects every leased wallet to be PINNED, but move/send flows could leave a leased
wallet looking AVAILABLE. The resolution: **public wallet state is a PROJECTION of lease reality,
not an independently mutable column** — lease truth takes precedence.

## Frozen facts

- **Projection** (`projection.ts` `projectWalletState`): from `{ leases, quarantined, retired }`
  derive `{ state, activeRole, reconciliationActive, breach }`. Precedence: more than one active
  operation lease -> PINNED + breach; one active operation lease + quarantined -> QUARANTINED
  (activeRole set — quarantine is operator state and strictly more restricted than PINNED);
  one active operation lease otherwise -> PINNED (never AVAILABLE); else quarantined ->
  QUARANTINED; else retired -> RETIRED; else AVAILABLE. A RELEASED lease does not pin; a
  RECONCILIATION lease never pins (observation must not exclude a wallet from selection).
- **One in-flight per wallet** (the one-in-flight-per-wallet rule): at most one active operation lease; more than one
  projects PINNED with `breach = "multiple_active_operation_leases"`.
- **Lease vocabulary** (`leases.ts`): five roles (RECEIVE_WINDOW, MOVE_DESTINATION, SEND_SOURCE,
  MOVE_SOURCE, RECONCILIATION); the four operation roles pin, RECONCILIATION is observation-only.
  Lifecycle ACTIVE/RELEASED; per **`receive-expiry-prevention-rule`** a post-candidate
  RECEIVE_WINDOW lease is modeled ACTIVE (held), not released by expiry.
- **Transition legality** (`legality.ts`): a wallet-state change is legal iff it is in the
  pool-policy pool-transition set AND driven by its required lease event (`LEASE_ACQUIRED` /
  `LEASE_RELEASED` / `QUARANTINE_FLAGGED` / `QUARANTINE_CLEARED` / `RETIRED_FLAGGED`). This enforces
  **no state change without a lease event**; a transition with the wrong event, absent from the set
  (e.g. `PINNED -> RETIRED`, cannot retire a leased wallet), or a spontaneous self-transition is
  illegal.
- **Lease-hold precedence over expiry** (`canExpiryReleaseReceiveLease`): pre-candidate expiry may
  release; post-candidate expiry must NOT (the wallet stays PINNED, held).
- **Selectability = projection AND recovery** (`isSelectableForReceive`): receive-selectable iff
  the wallet projects AVAILABLE AND passes the recovery gate (pool-policy's
  `isAvailableForReceive`). This is the single place projection, receive-pool exclusion, and
  recovery meet — the concern's exit criterion.

## Selector consistency + boot-audit alignment (frozen)

Aligns every selector and boot audit to the ONE projection, as frozen data + pure verifiers.

- **Selector-consistency** (`selectors.ts`): `WALLET_SELECTORS` names each selector and the
  projection predicate it must consume — `pool_receive_selection` / `move_destination_selection`
  (adds BLESSED) via `isSelectableForReceive`, `send_source_selection` / `signer_eligibility` /
  `release_path` via `projectWalletState`; `recovery_flow` (the recovery ceremony + exempt
  RECONCILIATION reads) is the one selector that is NOT projection-bound.
  `isSelectorConsistent(selector, usesProjection)` rejects a projection-bound selector that reads a
  stored state column directly — a selector bypassing the projection is a defect.
- **Boot audit** (`boot-audit.ts`): `auditPersistedWallet(stored, projection)` re-projects every
  persisted wallet and reconciles. Frozen contradiction classes + dispositions: consistent ->
  `CONSISTENT`; a leased wallet stored AVAILABLE -> `REPAIR_TO_PROJECTION` (to PINNED) + audit; a
  stored non-AVAILABLE wallet projecting AVAILABLE (phantom PIN / lost lease / would-be un-retire)
  -> `QUARANTINE_FOR_RECONCILIATION` + audit (fail-closed, never silently made selectable); a
  persisted one-in-flight-per-wallet breach -> `INVARIANT_BREACH_QUARANTINE`. A stored `QUARANTINED`
  wallet is never classified `understated_restriction` and never repaired toward PINNED — operator
  quarantine is retained. Safety principle: safe to repair toward a MORE-restricted projection;
  never silently repair a persisted non-AVAILABLE wallet into AVAILABLE; never clear quarantine.
  A contradiction is never silently accepted (every non-`none` class requires an audit event).

## Exhaustive wallet-state matrix (frozen)

The full combinatorial matrix as freeze tests over the REAL projection and the real
selectors/boot-audit (`matrix.ts` dimensions + snapshot `gen/wallet-state-matrix.json`;
`matrix.test.ts` drives it). Two invariants proven across every cell, plus a negative per dimension:

- **No leased wallet is ever selected** — operation-role x quarantine x retirement x recovery (all
  32 cells with an active operation lease): the wallet projects PINNED (or QUARANTINED when the
  quarantine flag is set) and is never receive-selectable, regardless of flags or recovery status.
- **No leased wallet is ever silently released** — operation-role x stored-state x restart (all 16
  cells): a leased wallet is never AVAILABLE and the boot audit either confirms it (stored PINNED ->
  CONSISTENT) or repairs AVAILABLE to PINNED (REPAIR_TO_PROJECTION), never QUARANTINE_FOR_RECONCILIATION
  and never AVAILABLE. Stored QUARANTINED is retained, never repaired to PINNED.
- Per-dimension negatives: a RECONCILIATION lease never pins; a RELEASED operation lease never pins;
  a leased wallet is never AVAILABLE; a quarantined / retired unleased wallet is not selectable; a
  phantom-pin fails closed to quarantine.

## Scope boundary

The projection, the selector + boot-audit alignment, and the exhaustive matrix freeze contracts /
verifiers / tests only (CONTRACT_FREEZE): no DB code, no query, no runtime. The schema and runtime
slices bind the selectors and the boot-audit disposition to real queries.
