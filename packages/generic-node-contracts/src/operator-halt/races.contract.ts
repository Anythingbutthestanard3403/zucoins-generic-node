import { OPERATION_KINDS, type OperationKind } from "../operations/operations.contract.ts";
import { isHaltGatedOperationKind } from "./halt.contract.ts";

/**
 * The kill-switch rule ("an already-claimed tick completes — fail-safe, no abort");
 * the state-event reference applies-to table
 * (execution-phase names and per-kind applicability, quoted here for halt-race purposes only —
 * this file does not freeze the applies-to table as a general-purpose manifest, which remains a
 * separate concern's responsibility if one claims it); guarded CAS
 * mutation); the never-blind-retry rule (never blind-retry submit).
 */
export const HALT_RACE_PHASES = [
  "NOT_STARTED",
  "PREIMAGE_PERSISTED",
  "SIGNED_PERSISTED",
  "DELIVERED",
  "SUBMIT_STARTED",
  "SUBMIT_RETURNED",
  "LANDED_VERIFIED",
] as const;

export type HaltRacePhase = (typeof HALT_RACE_PHASES)[number];

/**
 * The "Applies to" column, transcribed per frozen operation kind. The key
 * sequence below is this file's own choice (a lookup record, not a frozen sequence artifact)
 * and deliberately places the halt-exempt kind last.
 */
export const PHASE_APPLICABILITY: Readonly<Record<OperationKind, readonly HaltRacePhase[]>> = {
  MOVE_INTERNAL: [
    "NOT_STARTED",
    "PREIMAGE_PERSISTED",
    "SIGNED_PERSISTED",
    "SUBMIT_STARTED",
    "SUBMIT_RETURNED",
    "LANDED_VERIFIED",
  ],
  SEND_EXTERNAL: ["NOT_STARTED", "PREIMAGE_PERSISTED", "SIGNED_PERSISTED", "DELIVERED", "LANDED_VERIFIED"],
  RECEIVE_EXTERNAL: [
    "NOT_STARTED",
    "PREIMAGE_PERSISTED",
    "SIGNED_PERSISTED",
    "SUBMIT_STARTED",
    "SUBMIT_RETURNED",
    "LANDED_VERIFIED",
  ],
};

export const HALT_RACE_ACTIONS = ["BLOCKED_FROM_STARTING", "COMPLETES_NO_ABORT", "NEVER_GATED"] as const;

export type HaltRaceAction = (typeof HALT_RACE_ACTIONS)[number];

export interface HaltRaceEntry {
  readonly operationKind: OperationKind;
  readonly phaseAtEngage: HaltRacePhase;
  readonly action: HaltRaceAction;
}

/**
 * Halt-flag precedence over in-flight intents, as frozen decision-table data. Derived, not
 * hand-typed: an exempt kind is `NEVER_GATED` at every phase; a gated kind is blocked only at
 * `NOT_STARTED` (the one phase before any signing decision has been made) and otherwise
 * completes to its existing terminal path without abort, matching the kill-switch rule's "already-claimed
 * tick completes" and the never-blind-retry rule's never-blind-retry/never-abort discipline.
 */
export const HALT_RACE_TABLE: readonly HaltRaceEntry[] = OPERATION_KINDS.flatMap((operationKind) =>
  PHASE_APPLICABILITY[operationKind].map((phaseAtEngage) => {
    const action: HaltRaceAction = !isHaltGatedOperationKind(operationKind)
      ? "NEVER_GATED"
      : phaseAtEngage === "NOT_STARTED"
        ? "BLOCKED_FROM_STARTING"
        : "COMPLETES_NO_ABORT";
    return { operationKind, phaseAtEngage, action };
  }),
);

/**
 * the kill-switch rule is silent on concurrent admin engage/disengage races. This generalizes the existing
 * generic-core CAS-guarded-mutation invariant (state changes use a
 * compare-and-swap predicate on expected state/row_version inside one transaction) onto the
 * halt record as an ATOMIC MONOTONIC compare-and-swap. The halt toggle rides the generic
 * settings row's existing monotonic `row_version` (NOT a new halt-specific
 * field, so still one row and no schema migration, consistent with the kill-switch rule's "no migration"). A
 * toggle reads a version, and its write is admitted iff (1) the CAS still matches — its expected
 * prior version is the current persisted version — AND (2) it strictly increments —
 * `nextVersion === expectedPriorVersion + 1`. Together these give a TOTAL monotonic sequence
 * over halt toggles: a stale writer's expected version is no longer current, so it can neither
 * re-apply an old version nor clobber a newer toggle — a delayed disengage physically cannot
 * overwrite a newer engage. Exactly one of two racers succeeds; the loser is rejected and must
 * re-read and retry. There is no engage- or disengage-always-wins bias — a bias would contradict
 * the kill-switch rule's "disengage gated exactly as strongly as engage" symmetry. This is an EXTRAPOLATION
 * not a restatement of an explicit kill-switch clause; flagged for confirmation at the concern-manifest registry assembly
 * operator.
 */
export const CONCURRENT_TOGGLE_RESOLUTION = {
  mechanism: "compare-and-swap-on-expected-prior-version",
  sequenceDiscipline: "strict-monotonic-increment",
  biasedTowardEngage: false,
  biasedTowardDisengage: false,
  loserAction: "REJECT_AND_REQUIRE_REREAD",
} as const;

export interface HaltToggleAttempt {
  readonly expectedPriorVersion: number;
  readonly currentPersistedVersion: number;
  readonly nextVersion: number;
}

/**
 * Pure atomic monotonic-CAS verifier: admits a toggle write iff its expected prior version is
 * still current (the atomic compare-and-swap) AND the write strictly increments the version by
 * one (the monotonic sequence). A stale-version racer and a non-monotonic write are both
 * rejected.
 */
export const resolveConcurrentToggle = (attempt: HaltToggleAttempt): boolean =>
  attempt.expectedPriorVersion === attempt.currentPersistedVersion &&
  attempt.nextVersion === attempt.expectedPriorVersion + 1;

export const SOURCE = "operator-kill-switch; applies-to table; guarded CAS mutation; the never-blind-retry rule" as const;
