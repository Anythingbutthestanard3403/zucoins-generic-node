// the named concern — selector-consistency contract. Every wallet selector and boot audit consumes the
// ONE projection (the named concern projectWalletState / isSelectableForReceive); none may read a stored
// state column directly. Frozen data naming each selector, the .1 predicate it must consume, and
// whether it is projection-bound. CONTRACT_FREEZE — no query/runtime here.

export const WALLET_SELECTORS = {
  // Receive-pool assignment: projected AVAILABLE + the recovery-gate rule receive-eligibility.
  pool_receive_selection: { predicate: "isSelectableForReceive", requiresProjection: true },
  // Automatic-sink / MOVE_INTERNAL destination: receive-eligibility PLUS destinations.BLESSED
  // (the custody selection rule/the recovery-gate rule automatic-sink eligibility).
  move_destination_selection: { predicate: "isSelectableForReceive", requiresProjection: true },
  // Send source: projected AVAILABLE (not leased — one in-flight) + defensive recovery gate.
  send_source_selection: { predicate: "projectWalletState", requiresProjection: true },
  // Signer eligibility: the wallet must project PINNED under the operation's own lease.
  signer_eligibility: { predicate: "projectWalletState", requiresProjection: true },
  // Release path: PINNED -> AVAILABLE via lease release, subject to the receive-expiry rule lease-hold legality.
  release_path: { predicate: "projectWalletState", requiresProjection: true },
  // Recovery ceremony (the recovery-drill concern) stamps recovery_verified_at; RECONCILIATION reads are exempt and
  // observe any wallet in any state — the one selector that is not projection-bound.
  recovery_flow: { predicate: "none", requiresProjection: false },
} as const;

export type WalletSelectorName = keyof typeof WALLET_SELECTORS;

// A selector is consistent iff, when it is projection-bound, it actually consumes the projection.
// A projection-bound selector that reads a stored state column directly (usesProjection=false) is
// rejected — this is how "reject a selector that bypasses the projection" is enforced.
export function isSelectorConsistent(selector: WalletSelectorName, usesProjection: boolean): boolean {
  return !WALLET_SELECTORS[selector].requiresProjection || usesProjection;
}

export const PROJECTION_BOUND_SELECTORS = (
  Object.keys(WALLET_SELECTORS) as WalletSelectorName[]
).filter((name) => WALLET_SELECTORS[name].requiresProjection);
