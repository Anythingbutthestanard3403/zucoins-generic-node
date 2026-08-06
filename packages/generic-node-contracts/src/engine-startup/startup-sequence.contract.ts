/**
 * SOURCE: the startup-sequence decision (crash-recovery then engines then signer authority flips on
 * LAST; on lock loss markLost + gate closed then graceful shutdown) + the operations-recovery
 * boot-recovery rule (rebuild bounded queues before normal money workers) and the
 * leadership rule. Consumes the engine-startup concern
 * ENGINE_ACTIVATION boot stage — this concern expands that single stage into the sub-sequence
 * below; it does not re-freeze the named concern boot sequence.
 */

import { BOOT_SEQUENCE } from "../readiness/index.ts";

/** The named concern boot stage this concern expands. Bound so the dependency is explicit and checked.*/
export const EXPANDED_BOOT_STAGE = "ENGINE_ACTIVATION" as const satisfies (typeof BOOT_SEQUENCE)[number];

/**
 * The leader-only engine startup sub-sequence, run after LEADERSHIP_ACQUIRE and
 * BOOT_RECOVERY_CLASSIFY. ARM_SIGNER_AUTHORITY is last: request-driven signing is admitted only
 * after queues are rebuilt and the background engines are running (the frozen rule flips authority last).
 */
export const ENGINE_STARTUP_SEQUENCE = [
  "REBUILD_QUEUES",
  "START_RECONCILER",
  "START_MUTATION_WORKERS",
  "ARM_SIGNER_AUTHORITY",
] as const;

export type EngineStartupStage = (typeof ENGINE_STARTUP_SEQUENCE)[number];

export const STARTUP_INVARIANTS = {
  runs_only_on_leader: true,
  starts_after_boot_recovery_classify: true,
  queues_rebuilt_before_mutation_workers: true,
  signer_authority_armed_last: true,
} as const;

/**
 * The leadership-loss shutdown sub-sequence. Losing leadership stops NEW work immediately; any
 * in-flight operation stays bound to its C-02 lease (never force-released, never re-sequenced)
 * and completes there or is recovered by the next leader's boot recovery. The process then exits
 * gracefully so the platform restarts a clean instance that re-acquires (the frozen rule).
 */
export const LEADERSHIP_LOSS_SHUTDOWN_SEQUENCE = [
  "MARK_LEADERSHIP_LOST",
  "STOP_ADMITTING_NEW_WORK",
  "QUIESCE_IN_FLIGHT_UNDER_C02_LEASE",
  "GRACEFUL_EXIT_FOR_RESTART",
] as const;

export type ShutdownStage = (typeof LEADERSHIP_LOSS_SHUTDOWN_SEQUENCE)[number];

export const SHUTDOWN_INVARIANTS = {
  marks_leadership_lost_first: true,
  stops_new_work_immediately: true,
  in_flight_completes_under_c02_lease: true,
  never_force_releases_lease: true,
  never_re_sequences_lease: true,
  never_second_authority: true,
} as const;
