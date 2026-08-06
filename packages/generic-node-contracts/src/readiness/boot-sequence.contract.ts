/**
 * SOURCE: the operations-recovery boot-recovery section (boot recovery: schema validation and vault unlock
 * precede leadership and money workers) + the readiness-leadership decoupling rule (signer authority flips on
 * LAST, after key validation and recovery) and the wallet-vault envelope freeze guard 3 (boot reads the mixed key_version
 * population via the key-ring). Consumes the vault boot key-ring fact from the vault concern lifecycle
 * contract.
 *
 * the named concern freezes the boot stage sequence and its invariants as data. The precise prerequisite
 * chain the ticket names is key-ring load -> vault census verify -> leadership acquisition.
 */

/** The frozen boot stage sequence. The array position is the contract; each label is a stage. */
export const BOOT_SEQUENCE = [
  "SCHEMA_VALIDATE",
  "VAULT_KEY_RING_LOAD",
  "VAULT_CENSUS_VERIFY",
  "LEADERSHIP_ACQUIRE",
  "BOOT_RECOVERY_CLASSIFY",
  "ENGINE_ACTIVATION",
] as const;

export type BootStage = (typeof BOOT_SEQUENCE)[number];

/**
 * The leadership prerequisite chain: the three stages that MUST precede a leadership claim, in
 * this sequence. Fail-closed rule NO_LEADERSHIP_WITHOUT_VAULT_CENSUS depends on
 * VAULT_CENSUS_VERIFY sitting immediately before LEADERSHIP_ACQUIRE.
 */
export const LEADERSHIP_PREREQUISITE_SEQUENCE = [
  "VAULT_KEY_RING_LOAD",
  "VAULT_CENSUS_VERIFY",
  "LEADERSHIP_ACQUIRE",
] as const satisfies readonly BootStage[];

/**
 * Boot invariants as booleans. `readiness_reachable_before_leadership` is the readiness-leadership decoupling rule core: the
 * gating readiness checks can all pass before (or entirely without) a leadership claim, so a
 * web-active-but-not-leader instance answers ready and an overlap deploy never deadlocks.
 */
export const BOOT_SEQUENCE_INVARIANTS = {
  vault_census_after_key_ring_load: true,
  leadership_acquire_after_vault_census: true,
  engine_activation_after_leadership: true,
  readiness_reachable_before_leadership: true,
  signer_authority_active_last: true,
} as const;

/**
 * The graceful-shutdown stage sequence — the exit mirror of BOOT_SEQUENCE (this concern's frozen
 * lifecycle-sequence data lives here). On SIGTERM the signer authority is withdrawn FIRST so the
 * request-driven signers refuse, money engines quiesce, in-flight signing completes, and the
 * leadership lock is released LAST — so a READY standby successor never acquires the lock and signs
 * while this instance still accepts signing. SOURCE: the readiness-leadership decoupling rule (the v2 anchor for
 * this frozen sequence) + the readiness-leadership decoupling rule (the v1 boot-side precedent this sequence mirrors, not itself the
 * anchor — see the readiness-leadership decoupling rule) + the node-core leadership section (money engines run under the process-wide leadership
 * lock) + the operations-recovery spec (signer unavailable).
 */
export const SHUTDOWN_SEQUENCE = [
  "SIGNER_AUTHORITY_WITHDRAW",
  "ENGINE_QUIESCE",
  "INFLIGHT_SIGNING_COMPLETE",
  "LEADERSHIP_RELEASE",
] as const;

export type ShutdownStage = (typeof SHUTDOWN_SEQUENCE)[number];

/**
 * Shutdown invariants as booleans. `signer_authority_withdrawn_first` and
 * `leadership_release_is_last` are the load-bearing pair that keeps a handover single-signer: the
 * successor only ever acquires a lock this instance has already stopped signing under.
 */
export const SHUTDOWN_SEQUENCE_INVARIANTS = {
  signer_authority_withdrawn_first: true,
  engines_quiesce_before_inflight_signing_completes: true,
  inflight_signing_completes_before_leadership_release: true,
  leadership_release_is_last: true,
} as const;
