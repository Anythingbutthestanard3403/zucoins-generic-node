import type { AuthMode, RouteEntry } from "../operations/routes.contract.ts";
import { OPERATION_KINDS, type OperationKind } from "../operations/operations.contract.ts";

/**
 * The kill-switch rule (emergency operator kill-switch); the scale-to-zero rule (total-halt
 * recourse, cited only to exclude it); operations recovery; guarded CAS mutation.
 *
 * the kill-switch rule maps into exactly one generic halt kind at launch: a durable, operator-controlled
 * in-process switch that stops the node from STARTING new fund-moving signing while
 * deliberately leaving inbound co-sign and all read/reconcile work running. It is explicitly
 * NOT a security boundary for suspected key compromise — the scale-to-zero rule is that
 * recourse, is out-of-process, and is not modeled by this contract.
 */
export const HALT_KINDS = ["OPERATOR_PAUSE"] as const;

export type HaltKind = (typeof HALT_KINDS)[number];

export const OUT_OF_SCOPE_HALT_MECHANISMS = ["TOTAL_HALT_SCALE_TO_ZERO"] as const;

/**
 * the kill-switch rule "Surfaces halted" / "Surfaces DELIBERATELY NOT halted", generalized onto the three
 * frozen operation kinds (imported from the generic-core scan concern, never redeclared here). `MOVE_INTERNAL` and
 * `SEND_EXTERNAL` together cover every product-specific trigger the kill-switch rule named — two distinct
 * background/request-driven triggers both forming a new internal-move attempt collapse into
 * one `MOVE_INTERNAL`, and forming the sender partial the node hands to an external recipient
 * is `SEND_EXTERNAL` — because those triggers are implementer projections, not generic
 * distinctions. The remaining frozen kind's inbound co-sign is revenue and stays exempt
 * below: bundling it in would turn an outflow pause into a revenue outage.
 */
export const HALT_GATED_OPERATION_KINDS = ["MOVE_INTERNAL", "SEND_EXTERNAL"] as const;

/** The one frozen kind the kill-switch rule deliberately never gates — see the rationale above.*/
export const HALT_EXEMPT_OPERATION_KINDS = ["RECEIVE_EXTERNAL"] as const;

export type HaltGatedOperationKind = (typeof HALT_GATED_OPERATION_KINDS)[number];
export type HaltExemptOperationKind = (typeof HALT_EXEMPT_OPERATION_KINDS)[number];

/** Coverage check helper: every frozen operation kind is scoped exactly once, never both. */
export const isHaltGatedOperationKind = (kind: OperationKind): kind is HaltGatedOperationKind =>
  (HALT_GATED_OPERATION_KINDS as readonly OperationKind[]).includes(kind);

export const isHaltExemptOperationKind = (kind: OperationKind): kind is HaltExemptOperationKind =>
  (HALT_EXEMPT_OPERATION_KINDS as readonly OperationKind[]).includes(kind);

/**
 * Internal read/reconcile/evidence work — NOT the operator-action catalog operator actions — that the kill-switch rule and
 * 09-operations-recovery.md leave running regardless of halt state: settlement/observation
 * reads, reconciliation classification, and boot recovery classifying every
 * nonterminal/attention operation "without submitting or signing" before readiness is reported.
 * These sign and submit nothing, so halt never gates them. The operator-action catalog OPERATOR recovery-action
 * surface is a DISTINCT surface, classified exhaustively below — it is NOT uniformly non-signing
 * (`REBUILD_INTERNAL_MOVE` re-authorizes a fund-moving first formation and IS gated), so the two
 * surfaces must never be conflated into one "never gated" list.
 */
export const HALT_NEVER_GATED_INTERNAL_PATHS = [
  "OBSERVATION_SERVICE_READS",
  "RECOVERY_CLASSIFICATION",
  "BOOT_RECOVERY_CLASSIFICATION",
] as const;

export type HaltNeverGatedInternalPath = (typeof HALT_NEVER_GATED_INTERNAL_PATHS)[number];

/**
 * The nine operator recovery actions of the operator-action catalog ("Allowed action
 * values"), transcribed in the doc's table sequence as a CLOSED set. This is the byte-exact
 * quotation of the spec's action column and the diff anchor for spec↔freeze drift: the census
 * (halt.census.test.ts) pins this sequence against an inline literal and asserts every member is
 * classified exactly once, so adding, removing, or reordering a the operator-action catalog action without updating
 * this contract fails the build. "Actions that do not exist" is deliberately NOT modeled
 * — those tokens are non-actions.
 */
export const OPERATOR_RECOVERY_ACTIONS = [
  "RETRY_OBSERVATION",
  "REDELIVER_EXACT_PARTIAL",
  "CONTINUE_EXTERNAL_WAIT",
  "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
  "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
  "REBUILD_INTERNAL_MOVE",
  "RELEASE_EXPIRED_RECEIVE",
  "QUARANTINE_WALLETS",
  "ACKNOWLEDGE_KEEP_PINNED",
] as const;

export type OperatorRecoveryAction = (typeof OPERATOR_RECOVERY_ACTIONS)[number];

/**
 * RESERVED (note under "Allowed action values"): both
 * actions are RESERVED pending a future reviewed freeze; the landing-proof complete-path rule governs at launch (no generic
 * PROVEN_NOT_LANDED oracle), and INDETERMINATE authorizes no non-landing, retry/rebuild, or
 * lease/reuse release. They remain members of the operator-action catalog census above — being RESERVED is a
 * launch-grantability status, not a removal from the catalog — but they cannot be granted at
 * runtime. Same reserved-capacity semantics as the non-landing precondition in
 * states.contract.ts. Modeled as its own named const (cf. OUT_OF_SCOPE_HALT_MECHANISMS) so the
 * doc's RESERVED note is machine-readable, not only a prose aside.
 */
export const RESERVED_RECOVERY_ACTIONS = [
  "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
  "REBUILD_INTERNAL_MOVE",
] as const;

export type RecoveryActionHaltDisposition = "HALT_GATED" | "HALT_NEVER_GATED";

/**
 * Per-action justification for the operator-action catalog halt classification. the kill-switch rule's principle: halt gates a
 * node-initiated NEW fund-moving first formation; every read/reconcile/close/release/record
 * continues.
 *   RETRY_OBSERVATION                     never — bounded read reconciliation only, no signing.
 *   REDELIVER_EXACT_PARTIAL               never — re-serves IDENTICAL stored bytes; forms no new
 *                                         signature or submit (cf. the kill-switch rule degraded-mode "existing
 *                                         exact external partials may be served").
 *   CONTINUE_EXTERNAL_WAIT                never — clears an attention episode, keeps the existing
 *                                         lease; no new signing or submit.
 *   CLOSE_NEVER_STARTED_EXTERNAL_SEND     never — non-signing close + lease release.
 *   CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED never — re-evaluates a stored proof, closes to REJECTED,
 *                                         releases the source lease; signs and submits nothing.
 *   REBUILD_INTERNAL_MOVE                 GATED — "archives attempt and authorizes one new
 *                                         attempt": a new MOVE_INTERNAL first formation, the exact
 *                                         signer surface the kill-switch rule's kill-switch stops.
 *   RELEASE_EXPIRED_RECEIVE               never — releases an inbound receive pin/group; no
 *                                         send-side signing (inbound is the kill-switch rule-exempt regardless).
 *   QUARANTINE_WALLETS                    never — a safety escalation that DISABLES money paths;
 *                                         strictly de-risking, must stay available while halted.
 *   ACKNOWLEDGE_KEEP_PINNED               never — records operator awareness only; no state change.
 *
 * The classification is DERIVED, not hand-asserted per action: an action is gated iff it
 * re-authorizes a new first formation of a halt-gated operation kind, so it cannot drift from
 * the named concern's operation-kind scope (`isHaltGatedOperationKind`) or the named concern's signing-trigger
 * gate (which freezes `MOVE_INTERNAL / RECOVERY_RESUMED_FIRST_FORMATION` as halt-gated).
 */
export const RECOVERY_ACTION_REAUTHORIZED_FORMATION: Readonly<
  Partial<Record<OperatorRecoveryAction, OperationKind>>
> = {
  REBUILD_INTERNAL_MOVE: "MOVE_INTERNAL",
};

export const classifyRecoveryActionHalt = (
  action: OperatorRecoveryAction,
): RecoveryActionHaltDisposition => {
  const reauthorizedKind = RECOVERY_ACTION_REAUTHORIZED_FORMATION[action];
  return reauthorizedKind !== undefined && isHaltGatedOperationKind(reauthorizedKind)
    ? "HALT_GATED"
    : "HALT_NEVER_GATED";
};

/** The operator-action catalog actions halt gates: exactly the fund-moving re-authorizations. Derived, drift-proof. */
export const HALT_GATED_RECOVERY_ACTIONS: readonly OperatorRecoveryAction[] =
  OPERATOR_RECOVERY_ACTIONS.filter((action) => classifyRecoveryActionHalt(action) === "HALT_GATED");

/** The operator-action catalog actions halt never gates: every non-signing read/reconcile/close/release/record. */
export const HALT_NEVER_GATED_RECOVERY_ACTIONS: readonly OperatorRecoveryAction[] =
  OPERATOR_RECOVERY_ACTIONS.filter(
    (action) => classifyRecoveryActionHalt(action) === "HALT_NEVER_GATED",
  );

/**
 * Pure money-path predicate — the operator-action catalog projection of the kill-switch rule's pre-sign gate onto the operator
 * recovery surface. A halted node ADMITS every non-signing recovery action and REFUSES every
 * fund-moving re-authorization (only `REBUILD_INTERNAL_MOVE` today); a running node admits all.
 * The named breaking input `(REBUILD_INTERNAL_MOVE, haltEngaged=true)` returns false.
 */
export const isRecoveryActionAdmitted = (
  action: OperatorRecoveryAction,
  haltEngaged: boolean,
): boolean => !haltEngaged || classifyRecoveryActionHalt(action) === "HALT_NEVER_GATED";

/**
 * the kill-switch rule: "DISENGAGE gated exactly as strongly as engage (re-enabling money movement is never
 * the cheaper action)". Both actions require the full money-mutation admin auth chain; the
 * generic `operator_session_totp` auth mode (frozen by the generic-core scan concern's `routes.contract.ts`) is the
 * generic label for that chain (session + CSRF + password-changed + fresh single-use TOTP).
 */
export const HALT_TOGGLE_AUTH: Readonly<Record<"engage" | "disengage", AuthMode>> = {
  engage: "operator_session_totp",
  disengage: "operator_session_totp",
};

/**
 * the kill-switch rule admin surface, generalized: `GET` is read-only (session only); `POST` performs the
 * guarded engage/disengage mutation and requires the full auth chain above. Reuses the generic-core scan concern's
 * `RouteEntry`/`AuthMode` types (never redeclares `ADMIN_ROUTES` itself, which the generic-core scan concern owns).
 */
export const HALT_ADMIN_ROUTES: readonly RouteEntry[] = [
  { method: "GET", path: "/admin/v1/halt", authMode: "operator_session" },
  { method: "POST", path: "/admin/v1/halt", authMode: "operator_session_totp" },
];

/** Durable halt record shape. the kill-switch rule: one row, JSON `{engaged,reason}`, no schema migration.*/
export interface HaltState {
  readonly engaged: boolean;
  readonly reason: string | null;
}

/**
 * the kill-switch rule persistence contract: a single durable record, restored into the live gate BEFORE any
 * money engine starts. No schema migration is required — it reuses the generic node's existing
 * durable single-record settings primitive. A fresh node that was never halted defaults to
 * not-engaged; every other outcome is decided by `resolveHaltStateOnRestore` below.
 */
export const HALT_PERSISTENCE = {
  storage: "single-durable-record",
  schemaMigrationRequired: false,
  restoredBeforeMoneyEnginesStart: true,
  freshNodeDefault: false,
} as const;

/**
 * the kill-switch rule "Fail-CLOSED restore": `operatorPaused` defaults TRUE going into restore and is
 * un-paused ONLY on an affirmative determined-disengaged outcome — a clean parseable row with
 * `engaged:false`, or no row at all (a fresh node never halted). A read that still fails after
 * bounded retry, or a present-but-corrupt/unparseable row, keeps the gate halted: an unreadable
 * state is the safe failure, and the operator can always explicitly disengage. Pure function —
 * no I/O; the caller performs the bounded-retry read and passes its outcome in.
 */
export type HaltRestoreReadOutcome =
  | { readonly kind: "NO_ROW" }
  | { readonly kind: "CLEAN_PARSEABLE"; readonly state: HaltState }
  | { readonly kind: "CORRUPT_UNPARSEABLE" }
  | { readonly kind: "READ_FAILED_AFTER_RETRY" };

const assertNeverRestoreOutcome = (outcome: never): never => {
  throw new Error(`unhandled halt restore outcome: ${JSON.stringify(outcome)}`);
};

export const resolveHaltStateOnRestore = (outcome: HaltRestoreReadOutcome): boolean => {
  switch (outcome.kind) {
    case "NO_ROW":
      return HALT_PERSISTENCE.freshNodeDefault;
    case "CLEAN_PARSEABLE":
      return outcome.state.engaged;
    case "CORRUPT_UNPARSEABLE":
    case "READ_FAILED_AFTER_RETRY":
      return true;
    default:
      return assertNeverRestoreOutcome(outcome);
  }
};

/** Compile-time canary: every frozen operation kind is scoped by this contract exactly once. */
export const ALL_OPERATION_KINDS_SCOPED: readonly OperationKind[] = OPERATION_KINDS;

export const SOURCE = "operator-kill-switch; scale-to-zero (exclusion only); operations recovery; guarded CAS mutation" as const;
