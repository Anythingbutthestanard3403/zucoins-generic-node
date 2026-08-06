/**
 * SOURCE: the vault-storage decision guards 3 (crash-safe rotation) and 4 (signing concurrency)
 * plus the signing-custody recovery contract.
 *
 * Architecture-level state machine and invariants only. The exact rotation journal / cutover
 * format and the crash matrices are the vault threat-model freeze's runtime subcontract.
 */

export const ROTATION_STATES = ["STABLE", "ROTATING", "ROTATION_COMPLETE"] as const;
export type RotationState = (typeof ROTATION_STATES)[number];

export interface RotationTransition {
  readonly from: RotationState;
  readonly to: RotationState;
  readonly guard: string;
}

/** Transition sequence is the frozen fact; guard text is the architecture requirement. */
export const ROTATION_TRANSITIONS = [
  {
    from: "STABLE",
    to: "ROTATING",
    guard: "operator initiates master-key rotation; old KEK and root are retained",
  },
  {
    from: "ROTATING",
    to: "ROTATING",
    guard: "resume after a crash; boot key-ring reads the mixed key_version population and re-rewraps unresolved rows",
  },
  {
    from: "ROTATING",
    to: "ROTATION_COMPLETE",
    guard: "every row rewrapped and pubkey-derivation-verified; a committed rotation-complete marker is written",
  },
  {
    from: "ROTATION_COMPLETE",
    to: "STABLE",
    guard: "old ciphertext garbage-collected only post-complete; old KEK and root decommissioned",
  },
] as const satisfies readonly RotationTransition[];

export const ROTATION_INVARIANTS = {
  crash_safe_resumable: true,
  old_key_retained_until_committed_marker: true,
  boot_reads_mixed_version_via_key_ring: true,
  unreadable_or_failed_pubkey_row_aborts_without_advancing_writer_version: true,
  old_ciphertext_gc_only_post_complete: true,
} as const;

/**
 * Signing takes no row lock on the vault; the C-02 universal per-wallet lease is the sole
 * wallet-sequencing authority. Rotation is the only all-envelope writer and quiesces signing,
 * locking wallets in a canonical wallet-id sequence (matching MOVE_INTERNAL's two-lease
 * sequence).
 */
export const SIGNING_CONCURRENCY = {
  vault_read_access: "READ_ONLY_BY_PRIMARY_KEY",
  vault_row_lock_held_across_signing: false,
  wallet_ordering_authority: "C-02_UNIVERSAL_LEASE",
  rotation_writer: "QUIESCES_SIGNING_LOCKS_CANONICAL_WALLET_ID_SEQUENCE",
} as const;

/**
 * B1 export-eligibility is a per-wallet recoverability proof; it is monotonic and never cleared
 * by master-key rotation (rotation preserves the underlying key). Per-wallet key replacement is
 * never in-place: mint a new wallet, move funds via the blessed-sink path, and logically retire
 * the old one (the frozen rule).
 */
export const RECOVERY = {
  recovery_verified_at_scope: "PER_WALLET",
  monotonic: true,
  cleared_by_rotation: false,
  key_replacement_in_place: false,
  key_replacement_path: "MINT_NEW_WALLET_MOVE_VIA_BLESSED_SINK_RETIRE_OLD",
} as const;
