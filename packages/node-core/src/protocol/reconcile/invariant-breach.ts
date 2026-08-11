// MOVE_INTERNAL INVARIANT_BREACH quarantine at the
// operation-store / reconciler boundary.
//
// Rules this module enforces:
// 1. An unattributed deep successor under an active lease is an invariant/custody breach;
//    there is no PROVEN_NOT_LANDED verdict, and a lease is never history.
// 2. On INVARIANT_BREACH: stop money engines, quarantine affected wallets, page the
//    operator. QUARANTINE_WALLETS and ACKNOWLEDGE_KEEP_PINNED are the permitted actions;
//    FORCE_LANDED, FORCE_RELEASE, EDIT_TRANSACTION and DELETE_EVIDENCE are non-actions.
// 3. Fail closed: operator resolution never deletes evidence, rewrites a verdict, frees a
//    possible in-flight wallet without a fresh read, or creates implicit submit authority.
// 4. wallets.state / quarantine_reason carry a CHECK; a breach writes observation_anomalies
//    with lineage_proof_verdict='INVARIANT_BREACH' and an audit_log row.
// 5. Park on breach; never rebuild around it.
// Sibling (move-ambiguity.ts) classifies and surfaces
// SURFACE_INVARIANT_BREACH_QUARANTINE. This module owns the durable side-effects:
// both wallets → QUARANTINED with quarantine_reason, typed evidence rows, audit
// trail, acknowledgement-only operator control. Keys, identity columns, signed
// attempt bytes, and wallet_active_leases rows are never mutated.
//
// Known conflict (inherited, not re-opened): REBUILD_INTERNAL_MOVE
// is RESERVED and is deliberately absent from the permitted operator
// surface here. Do not add a release or rebuild path without a new decision.

import { randomUUID } from "node:crypto";

import {
  type MoveAmbiguityOutcome,
} from "./move-ambiguity.js";
import {
  type InvariantBreachObservationAnomaly,
  type ReconcileInvariantBreachReason,
  assertUnreachable,
  toAttentionReason,
} from "./types.js";

/**
 * Closed action catalog (byte-exact names). Duplicated here rather than
 * imported from generic-node-contracts/operator-halt because that subpath is not
 * a package export; the census test pins this list against the contracts source.
 */
export const OPERATOR_RECOVERY_ACTION_CATALOG = [
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

export type OperatorRecoveryActionCatalog =
  (typeof OPERATOR_RECOVERY_ACTION_CATALOG)[number];

// ─────────────────────────────────────────────────────────────────────────────
// Closed vocabularies
// ─────────────────────────────────────────────────────────────────────────────

/** lineage_proof_verdict — breach writes only this member. */
export const MOVE_BREACH_LINEAGE_VERDICT = "INVARIANT_BREACH" as const;
export type MoveBreachLineageVerdict = typeof MOVE_BREACH_LINEAGE_VERDICT;

/**
 * observation_anomalies.kind values usable as typed breach evidence
 * Closed subset of the DDL CHECK.
 */
export const MOVE_BREACH_ANOMALY_KINDS = [
  "REGRESSION",
  "GENESIS_AFTER_HISTORY",
  "SIGNATURE_COLLISION",
  "UNEXPLAINED_JUMP",
] as const;

export type MoveBreachAnomalyKind = (typeof MOVE_BREACH_ANOMALY_KINDS)[number];

export type WalletLifecycleState = "AVAILABLE" | "PINNED" | "QUARANTINED" | "RETIRED";

/** Operator actions this module admits. closed set filtered to MOVE breach. */
export const MOVE_BREACH_PERMITTED_OPERATOR_ACTIONS = [
  "QUARANTINE_WALLETS",
  "ACKNOWLEDGE_KEEP_PINNED",
] as const satisfies readonly OperatorRecoveryActionCatalog[];

export type MoveBreachPermittedOperatorAction =
  (typeof MOVE_BREACH_PERMITTED_OPERATOR_ACTIONS)[number];

/**
 * Non-actions plus every release/rebuild token that must stay rejected on a
 * quarantined MOVE. Compile-time + runtime pin (same pattern as
 * MOVE_AMBIGUITY_FORBIDDEN_ACTIONS).
 */
export const MOVE_BREACH_FORBIDDEN_OPERATOR_ACTIONS = [
  "FORCE_LANDED",
  "FORCE_RELEASE",
  "FORCE_RELEASE_SOURCE_LEASE",
  "FORCE_RELEASE_DESTINATION_LEASE",
  "FORCE_RELEASE_EITHER_LEASE",
  "EDIT_TRANSACTION",
  "DELETE_EVIDENCE",
  "CHANGE_DESTINATION",
  "CHANGE_AMOUNT",
  "RETRY_SUBMIT",
  "RESUBMIT",
  "REBUILD_INTERNAL_MOVE",
  "SKIP_VERIFICATION",
  "RESOLVE_QUARANTINE",
  "UNQUARANTINE",
  "RELEASE_WALLET",
] as const;

export type MoveBreachForbiddenOperatorAction =
  (typeof MOVE_BREACH_FORBIDDEN_OPERATOR_ACTIONS)[number];

export function isMoveBreachOperatorActionPermitted(
  action: string,
): action is MoveBreachPermittedOperatorAction {
  return (MOVE_BREACH_PERMITTED_OPERATOR_ACTIONS as readonly string[]).includes(action);
}

export function isMoveBreachOperatorActionForbidden(
  action: string,
): action is MoveBreachForbiddenOperatorAction {
  return (MOVE_BREACH_FORBIDDEN_OPERATOR_ACTIONS as readonly string[]).includes(action);
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshots + evidence shapes (compose existing tables; no new schema object)
// ─────────────────────────────────────────────────────────────────────────────

export interface MoveBreachWalletSnapshot {
  readonly walletId: string;
  readonly state: WalletLifecycleState;
  readonly quarantineReason: string | null;
  /** Active lease id if held. NEVER cleared by this module. */
  readonly activeLeaseId: string | null;
  /** Immutable identity fields — written only at seed; never updated here. */
  readonly publicKey: string;
  readonly keyOrigin: string;
  readonly nodeId: string;
  /** Opaque row_version stand-in so acknowledge can prove byte-identity. */
  readonly rowVersion: number;
}

export interface MoveBreachOperationSnapshot {
  readonly operationId: string;
  readonly moveAttemptId: string;
  readonly status: string;
  readonly rowVersion: number;
  readonly attentionRequired: boolean;
  readonly attentionReason: string | null;
  readonly sourceWalletId: string;
  readonly destinationWalletId: string;
  /** Operator-awareness flag only — never protocol state (ACKNOWLEDGE_KEEP_PINNED). */
  readonly operatorAcknowledged: boolean;
  readonly acknowledgedAt: string | null;
  readonly acknowledgedBy: string | null;
  readonly acknowledgeNote: string | null;
}

export interface MoveBreachObservationAnomalyRow {
  readonly id: string;
  readonly operationId: string;
  readonly walletId: string;
  readonly kind: MoveBreachAnomalyKind;
  readonly details: string;
  readonly detectedAt: string;
}

/**
 * Stand-in for operation_landing_proofs / lineage_path_proofs verdict column
 * (lineage_proof_verdict includes INVARIANT_BREACH).
 */
export interface MoveBreachLineageProofRow {
  readonly id: string;
  readonly operationId: string;
  readonly walletId: string;
  readonly verdict: MoveBreachLineageVerdict;
  readonly reasonSource: ReconcileInvariantBreachReason["source"];
  readonly recordedAt: string;
}

export interface MoveBreachAuditEntry {
  readonly id: string;
  readonly action:
    | "move.invariant_breach.quarantine_wallets"
    | "move.invariant_breach.acknowledge_keep_pinned"
    | "move.invariant_breach.operator_action_rejected";
  readonly actorKind: "SYSTEM" | "OPERATOR_SESSION";
  readonly actorId: string | null;
  readonly operationId: string;
  readonly walletId: string | null;
  readonly details: Readonly<Record<string, unknown>>;
  readonly createdAt: string;
}

export interface MoveBreachLeaseSnapshot {
  readonly walletId: string;
  readonly leaseId: string;
  readonly lifecycle: "ACTIVE" | "RELEASED";
  /** Opaque blob representing the durable lease row bytes for identity asserts. */
  readonly rowFingerprint: string;
}

/**
 * Immutable attempt material. This module exposes read access so tests can prove
 * signed-byte columns are never rewritten; the store has no mutator for them.
 */
export interface MoveBreachAttemptBytes {
  readonly operationId: string;
  readonly moveAttemptId: string;
  readonly step1PreimageText: string;
  readonly step1Signature: string;
  readonly completedBodyText: string | null;
  readonly completedBodySha256: string | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence port
// ─────────────────────────────────────────────────────────────────────────────

export interface MoveInvariantBreachStore {
  getWallet(walletId: string): Promise<MoveBreachWalletSnapshot | null>;
  getOperation(operationId: string): Promise<MoveBreachOperationSnapshot | null>;
  getLease(walletId: string): Promise<MoveBreachLeaseSnapshot | null>;
  getAttemptBytes(operationId: string): Promise<MoveBreachAttemptBytes | null>;

  /**
   * Set state='QUARANTINED' and quarantine_reason together (CHECK).
   * MUST preserve activeLeaseId, publicKey, keyOrigin, nodeId.
   * RETIRED stays RETIRED (selection already blocked).
   */
  quarantineWallet(
    walletId: string,
    quarantineReason: string,
  ): Promise<MoveBreachWalletSnapshot>;

  /**
   * Park the MOVE operation for attention. Does NOT change attempt bytes,
   * does NOT release leases, does NOT invent a second attempt.
   */
  markOperationBreach(
    operationId: string,
    attentionReason: string,
    detail: string,
  ): Promise<MoveBreachOperationSnapshot>;

  /**
   * ACKNOWLEDGE_KEEP_PINNED — records operator awareness only.
   * MUST leave status, row_version, leases, wallet state, attempt bytes unchanged.
   */
  acknowledgeOperation(
    operationId: string,
    operatorId: string,
    note: string,
    at: string,
  ): Promise<MoveBreachOperationSnapshot>;

  appendObservationAnomaly(row: MoveBreachObservationAnomalyRow): Promise<void>;
  appendLineageProofVerdict(row: MoveBreachLineageProofRow): Promise<void>;
  appendAudit(entry: MoveBreachAuditEntry): Promise<void>;

  /**
   * Atomic unit. On throw every write inside is rolled back (in-memory: snapshot
   * restore; SQL: real transaction). Both wallets + evidence + audit commit together.
   */
  runAtomic<T>(fn: () => Promise<T>): Promise<T>;

  listObservationAnomalies(operationId: string): Promise<readonly MoveBreachObservationAnomalyRow[]>;
  listLineageProofVerdicts(operationId: string): Promise<readonly MoveBreachLineageProofRow[]>;
  listAudit(operationId: string): Promise<readonly MoveBreachAuditEntry[]>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Inputs / results
// ─────────────────────────────────────────────────────────────────────────────

export interface MoveInvariantBreachQuarantineInput {
  readonly outcome: Extract<MoveAmbiguityOutcome, { kind: "INVARIANT_BREACH" }>;
  readonly operationId: string;
  readonly sourceWalletId: string;
  readonly destinationWalletId: string;
  /** Optional wall clock; defaults to Date.now ISO. */
  readonly nowIso?: string;
  /** Optional id factory (tests). */
  readonly newId?: () => string;
  /** Optional metric/page hook after durable quarantine commits (ZTR-1144). */
  readonly onQuarantineApplied?: () => void;
}

export interface MoveInvariantBreachQuarantineResult {
  readonly operationId: string;
  readonly moveAttemptId: string;
  readonly sourceWallet: MoveBreachWalletSnapshot;
  readonly destinationWallet: MoveBreachWalletSnapshot;
  readonly anomalyKind: MoveBreachAnomalyKind;
  readonly quarantineReason: string;
  readonly lineageVerdict: MoveBreachLineageVerdict;
  readonly attentionReason: string;
  readonly sourceLeasePreserved: true;
  readonly destinationLeasePreserved: true;
  readonly attemptBytesUntouched: true;
  readonly secondAttemptCreated: false;
  readonly auditAction: "move.invariant_breach.quarantine_wallets";
}

export interface MoveBreachAcknowledgeInput {
  readonly operationId: string;
  readonly operatorId: string;
  readonly note: string;
  readonly nowIso?: string;
  readonly newId?: () => string;
}

export interface MoveBreachAcknowledgeResult {
  readonly operationId: string;
  /** Protocol snapshot after acknowledge — status/rowVersion must match prior. */
  readonly operation: MoveBreachOperationSnapshot;
  readonly priorRowVersion: number;
  readonly priorStatus: string;
  readonly sourceLease: MoveBreachLeaseSnapshot | null;
  readonly destinationLease: MoveBreachLeaseSnapshot | null;
  readonly priorSourceLeaseFingerprint: string | null;
  readonly priorDestinationLeaseFingerprint: string | null;
  readonly protocolStateUnchanged: true;
  readonly leasesUnchanged: true;
}

export interface MoveBreachDiagnostics {
  readonly operationId: string;
  readonly moveAttemptId: string;
  readonly status: string;
  readonly quarantineReason: string | null;
  readonly anomalyKind: MoveBreachAnomalyKind | null;
  readonly lineageVerdict: MoveBreachLineageVerdict | null;
  readonly breachReasonSource: ReconcileInvariantBreachReason["source"] | null;
  readonly sourceWalletId: string;
  readonly destinationWalletId: string;
  readonly sourceWalletState: WalletLifecycleState | null;
  readonly destinationWalletState: WalletLifecycleState | null;
  readonly sourceLeaseId: string | null;
  readonly destinationLeaseId: string | null;
  readonly operatorAcknowledged: boolean;
  readonly permittedOperatorActions: readonly MoveBreachPermittedOperatorAction[];
  readonly forbiddenOperatorActions: readonly MoveBreachForbiddenOperatorAction[];
}

export class MoveInvariantBreachError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MoveInvariantBreachError";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Map a reconcile breach reason onto an observation_anomalies.kind value from the
 * closed set of anomaly kinds. Observation-anomaly breaches keep their kind;
 * every other custody breach is recorded as UNEXPLAINED_JUMP (unattributed /
 * contradictory evidence under lease).
 */
export function anomalyKindForBreachReason(
  reason: ReconcileInvariantBreachReason,
): MoveBreachAnomalyKind {
  switch (reason.source) {
    case "OBSERVATION_ANOMALY":
      return mapObservationAnomaly(reason.anomaly);
    case "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE":
    case "EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT":
    case "SIGNER_AUDIT_CONTRADICTS_DURABLE_RECORD":
    case "LEASE_NOT_ACTIVE_DURING_RECONCILE":
    case "DESTINATION_NO_LONGER_BLESSED":
      return "UNEXPLAINED_JUMP";
    default:
      return assertUnreachable(reason);
  }
}

function mapObservationAnomaly(
  anomaly: InvariantBreachObservationAnomaly,
): MoveBreachAnomalyKind {
  switch (anomaly) {
    case "REGRESSION":
    case "GENESIS_AFTER_HISTORY":
    case "SIGNATURE_COLLISION":
      return anomaly;
    default:
      return assertUnreachable(anomaly);
  }
}

/** Stable quarantine_reason string (wallets.quarantine_reason NOT NULL under QUARANTINED). */
export function quarantineReasonForBreach(
  reason: ReconcileInvariantBreachReason,
  moveAttemptId: string,
): string {
  const kind = anomalyKindForBreachReason(reason);
  return `MOVE_INVARIANT_BREACH:${reason.source}:${kind}:attempt=${moveAttemptId}`;
}

export function assertOutcomeIsInvariantBreach(
  outcome: MoveAmbiguityOutcome,
): asserts outcome is Extract<MoveAmbiguityOutcome, { kind: "INVARIANT_BREACH" }> {
  if (outcome.kind !== "INVARIANT_BREACH") {
    throw new MoveInvariantBreachError(
      `expected INVARIANT_BREACH outcome, got ${outcome.kind}`,
    );
  }
  if (outcome.automaticEffect !== "SURFACE_INVARIANT_BREACH_QUARANTINE") {
    throw new MoveInvariantBreachError(
      `INVARIANT_BREACH outcome must carry SURFACE_INVARIANT_BREACH_QUARANTINE, got ${
        (outcome as { automaticEffect?: string }).automaticEffect ?? "(absent)"
      }`,
    );
  }
  if (outcome.permitsSubmitCall !== false || outcome.permitsSecondAttempt !== false) {
    throw new MoveInvariantBreachError(
      "INVARIANT_BREACH outcome must forbid submit and second attempt",
    );
  }
  if (outcome.retainSourceLease !== true || outcome.retainDestinationLease !== true) {
    throw new MoveInvariantBreachError(
      "INVARIANT_BREACH outcome must retain both leases (quarantine holds custody)",
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply quarantine (QUARANTINE_WALLETS automatic effect of INVARIANT_BREACH)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Persist the INVARIANT_BREACH side-effects surfaces:
 * - both wallets → QUARANTINED + quarantine_reason (same atomic unit)
 * - observation_anomalies row per wallet (typed kind)
 * - lineage_proof_verdict='INVARIANT_BREACH' per wallet
 * - audit_log entry
 * - operation parked NEEDS_ATTENTION
 *
 * Never releases a lease, never creates a second attempt, never edits signed
 * attempt bytes, never touches key/identity columns.
 */
export async function applyMoveInvariantBreachQuarantine(
  store: MoveInvariantBreachStore,
  input: MoveInvariantBreachQuarantineInput,
): Promise<MoveInvariantBreachQuarantineResult> {
  assertOutcomeIsInvariantBreach(input.outcome);

  const { outcome, operationId, sourceWalletId, destinationWalletId } = input;
  if (sourceWalletId === destinationWalletId) {
    throw new MoveInvariantBreachError(
      "source and destination wallets must be distinct for MOVE_INTERNAL quarantine",
    );
  }

  const nowIso = input.nowIso ?? new Date().toISOString();
  const newId = input.newId ?? (() => randomUUID());
  const anomalyKind = anomalyKindForBreachReason(outcome.reason);
  const quarantineReason = quarantineReasonForBreach(outcome.reason, outcome.moveAttemptId);
  const attentionReason = toAttentionReason(outcome.reason);

  // Capture prior lease + attempt fingerprints so the post-condition can prove
  // they were not rewritten (the one-in-flight-per-wallet and byte-exact signing rules).
  const priorSourceLease = await store.getLease(sourceWalletId);
  const priorDestLease = await store.getLease(destinationWalletId);
  const priorAttempt = await store.getAttemptBytes(operationId);
  const priorSourceWallet = await requireWallet(store, sourceWalletId);
  const priorDestWallet = await requireWallet(store, destinationWalletId);
  const priorSourceIdentity = identityOf(priorSourceWallet);
  const priorDestIdentity = identityOf(priorDestWallet);

  const result = await store.runAtomic(async () => {
    const sourceWallet = await store.quarantineWallet(sourceWalletId, quarantineReason);
    const destinationWallet = await store.quarantineWallet(
      destinationWalletId,
      quarantineReason,
    );

    assertWalletQuarantined(sourceWallet, quarantineReason, priorSourceLease);
    assertWalletQuarantined(destinationWallet, quarantineReason, priorDestLease);
    assertIdentityUntouched(priorSourceIdentity, sourceWallet);
    assertIdentityUntouched(priorDestIdentity, destinationWallet);

    await store.markOperationBreach(
      operationId,
      attentionReason,
      quarantineReason,
    );

    // One anomaly + one lineage verdict per wallet (both sides of the MOVE).
    for (const walletId of [sourceWalletId, destinationWalletId] as const) {
      await store.appendObservationAnomaly({
        id: newId(),
        operationId,
        walletId,
        kind: anomalyKind,
        details: JSON.stringify({
          move_attempt_id: outcome.moveAttemptId,
          evidence_kind: outcome.evidenceKind,
          reason: outcome.reason,
          quarantine_reason: quarantineReason,
          automatic_effect: outcome.automaticEffect,
        }),
        detectedAt: nowIso,
      });
      await store.appendLineageProofVerdict({
        id: newId(),
        operationId,
        walletId,
        verdict: MOVE_BREACH_LINEAGE_VERDICT,
        reasonSource: outcome.reason.source,
        recordedAt: nowIso,
      });
    }

    await store.appendAudit({
      id: newId(),
      action: "move.invariant_breach.quarantine_wallets",
      actorKind: "SYSTEM",
      actorId: null,
      operationId,
      walletId: null,
      details: {
        move_attempt_id: outcome.moveAttemptId,
        source_wallet_id: sourceWalletId,
        destination_wallet_id: destinationWalletId,
        anomaly_kind: anomalyKind,
        quarantine_reason: quarantineReason,
        reason: outcome.reason,
        evidence_kind: outcome.evidenceKind,
        lineage_verdict: MOVE_BREACH_LINEAGE_VERDICT,
        retain_source_lease: true,
        retain_destination_lease: true,
        permits_submit_call: false,
        permits_second_attempt: false,
      },
      createdAt: nowIso,
    });

    // Post-condition: leases + attempt bytes still byte-identical.
    await assertLeaseUntouched(store, sourceWalletId, priorSourceLease);
    await assertLeaseUntouched(store, destinationWalletId, priorDestLease);
    await assertAttemptBytesUntouched(store, operationId, priorAttempt);

    return {
      operationId,
      moveAttemptId: outcome.moveAttemptId,
      sourceWallet,
      destinationWallet,
      anomalyKind,
      quarantineReason,
      lineageVerdict: MOVE_BREACH_LINEAGE_VERDICT,
      attentionReason,
      sourceLeasePreserved: true as const,
      destinationLeasePreserved: true as const,
      attemptBytesUntouched: true as const,
      secondAttemptCreated: false as const,
      auditAction: "move.invariant_breach.quarantine_wallets" as const,
    };
  });
  input.onQuarantineApplied?.();
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator controls
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ACKNOWLEDGE_KEEP_PINNED: records operator awareness without changing
 * protocol state or leases. row_version, wallet_active_leases, operations.status,
 * wallet quarantine state, and attempt bytes are byte-identical before and after.
 */
export async function acknowledgeMoveInvariantBreach(
  store: MoveInvariantBreachStore,
  input: MoveBreachAcknowledgeInput,
): Promise<MoveBreachAcknowledgeResult> {
  const prior = await store.getOperation(input.operationId);
  if (prior === null) {
    throw new MoveInvariantBreachError(
      `operation ${input.operationId} not found`,
    );
  }

  const priorSourceLease = await store.getLease(prior.sourceWalletId);
  const priorDestLease = await store.getLease(prior.destinationWalletId);
  const priorAttempt = await store.getAttemptBytes(input.operationId);
  const priorSourceWallet = await store.getWallet(prior.sourceWalletId);
  const priorDestWallet = await store.getWallet(prior.destinationWalletId);
  const nowIso = input.nowIso ?? new Date().toISOString();
  const newId = input.newId ?? (() => randomUUID());

  return store.runAtomic(async () => {
    const operation = await store.acknowledgeOperation(
      input.operationId,
      input.operatorId,
      input.note,
      nowIso,
    );

    // Protocol state / row_version / status must be unchanged.
    if (operation.status !== prior.status) {
      throw new MoveInvariantBreachError(
        "ACKNOWLEDGE_KEEP_PINNED must not change operations.status",
      );
    }
    if (operation.rowVersion !== prior.rowVersion) {
      throw new MoveInvariantBreachError(
        "ACKNOWLEDGE_KEEP_PINNED must not change operations.row_version",
      );
    }
    if (operation.moveAttemptId !== prior.moveAttemptId) {
      throw new MoveInvariantBreachError(
        "ACKNOWLEDGE_KEEP_PINNED must not change move attempt identity",
      );
    }

    // Wallet quarantine state must remain (no FORCE_RELEASE via acknowledge).
    await assertWalletStateUnchanged(store, prior.sourceWalletId, priorSourceWallet);
    await assertWalletStateUnchanged(store, prior.destinationWalletId, priorDestWallet);
    await assertLeaseUntouched(store, prior.sourceWalletId, priorSourceLease);
    await assertLeaseUntouched(store, prior.destinationWalletId, priorDestLease);
    await assertAttemptBytesUntouched(store, input.operationId, priorAttempt);

    await store.appendAudit({
      id: newId(),
      action: "move.invariant_breach.acknowledge_keep_pinned",
      actorKind: "OPERATOR_SESSION",
      actorId: input.operatorId,
      operationId: input.operationId,
      walletId: null,
      details: {
        note: input.note,
        prior_status: prior.status,
        prior_row_version: prior.rowVersion,
        protocol_state_unchanged: true,
        leases_unchanged: true,
      },
      createdAt: nowIso,
    });

    const sourceLease = await store.getLease(prior.sourceWalletId);
    const destinationLease = await store.getLease(prior.destinationWalletId);

    return {
      operationId: input.operationId,
      operation,
      priorRowVersion: prior.rowVersion,
      priorStatus: prior.status,
      sourceLease,
      destinationLease,
      priorSourceLeaseFingerprint: priorSourceLease?.rowFingerprint ?? null,
      priorDestinationLeaseFingerprint: priorDestLease?.rowFingerprint ?? null,
      protocolStateUnchanged: true as const,
      leasesUnchanged: true as const,
    };
  });
}

/**
 * Reject every non-permitted operator action against a quarantined MOVE.
 * Returns a structured rejection; never mutates protocol state.
 */
export async function rejectMoveBreachOperatorAction(
  store: MoveInvariantBreachStore,
  input: {
    readonly operationId: string;
    readonly action: string;
    readonly operatorId: string;
    readonly nowIso?: string;
    readonly newId?: () => string;
  },
): Promise<{ readonly rejected: true; readonly action: string; readonly reason: string }> {
  if (isMoveBreachOperatorActionPermitted(input.action)) {
    throw new MoveInvariantBreachError(
      `${input.action} is permitted — call the dedicated handler, not reject`,
    );
  }

  const reason = isMoveBreachOperatorActionForbidden(input.action)
    ? `action ${input.action} is forbidden on MOVE invariant-breach quarantine (forbidden non-action)`
    : `action ${input.action} is not in the MOVE breach permitted set (${MOVE_BREACH_PERMITTED_OPERATOR_ACTIONS.join(", ")})`;

  const nowIso = input.nowIso ?? new Date().toISOString();
  const newId = input.newId ?? (() => randomUUID());

  await store.appendAudit({
    id: newId(),
    action: "move.invariant_breach.operator_action_rejected",
    actorKind: "OPERATOR_SESSION",
    actorId: input.operatorId,
    operationId: input.operationId,
    walletId: null,
    details: {
      action: input.action,
      reason,
      permitted: [...MOVE_BREACH_PERMITTED_OPERATOR_ACTIONS],
    },
    createdAt: nowIso,
  });

  return { rejected: true as const, action: input.action, reason };
}

/**
 * Dispatch a recovery action against a MOVE breach. Only QUARANTINE_WALLETS
 * (idempotent re-apply when already quarantined) and ACKNOWLEDGE_KEEP_PINNED are
 * admitted. Everything else is rejected without mutation.
 */
export async function applyMoveBreachOperatorAction(
  store: MoveInvariantBreachStore,
  input: {
    readonly operationId: string;
    readonly action: string;
    readonly operatorId: string;
    readonly note?: string;
    readonly nowIso?: string;
    readonly newId?: () => string;
    /**
     * Required when action is QUARANTINE_WALLETS and the operation is not yet
     * under breach quarantine — the classifier outcome that authorizes it.
     */
    readonly breachOutcome?: Extract<MoveAmbiguityOutcome, { kind: "INVARIANT_BREACH" }>;
    readonly sourceWalletId?: string;
    readonly destinationWalletId?: string;
    /** Forwarded to applyMoveInvariantBreachQuarantine (ZTR-1144). */
    readonly onQuarantineApplied?: () => void;
  },
): Promise<
  | { readonly kind: "ACKNOWLEDGED"; readonly result: MoveBreachAcknowledgeResult }
  | { readonly kind: "QUARANTINED"; readonly result: MoveInvariantBreachQuarantineResult }
  | { readonly kind: "ALREADY_QUARANTINED"; readonly operationId: string }
  | { readonly kind: "REJECTED"; readonly action: string; readonly reason: string }
> {
  if (!isMoveBreachOperatorActionPermitted(input.action)) {
    const rejected = await rejectMoveBreachOperatorAction(store, {
      operationId: input.operationId,
      action: input.action,
      operatorId: input.operatorId,
      nowIso: input.nowIso,
      newId: input.newId,
    });
    return { kind: "REJECTED", action: rejected.action, reason: rejected.reason };
  }

  if (input.action === "ACKNOWLEDGE_KEEP_PINNED") {
    const result = await acknowledgeMoveInvariantBreach(store, {
      operationId: input.operationId,
      operatorId: input.operatorId,
      note: input.note ?? "",
      nowIso: input.nowIso,
      newId: input.newId,
    });
    return { kind: "ACKNOWLEDGED", result };
  }

  // QUARANTINE_WALLETS
  const op = await store.getOperation(input.operationId);
  if (op === null) {
    throw new MoveInvariantBreachError(`operation ${input.operationId} not found`);
  }
  const source = await store.getWallet(op.sourceWalletId);
  const dest = await store.getWallet(op.destinationWalletId);
  if (
    source?.state === "QUARANTINED" &&
    dest?.state === "QUARANTINED" &&
    source.quarantineReason !== null &&
    dest.quarantineReason !== null
  ) {
    // Idempotent: already quarantined. Do not re-write evidence or invent attempts.
    return { kind: "ALREADY_QUARANTINED", operationId: input.operationId };
  }

  if (input.breachOutcome === undefined) {
    throw new MoveInvariantBreachError(
      "QUARANTINE_WALLETS requires the INVARIANT_BREACH classifier outcome",
    );
  }

  const result = await applyMoveInvariantBreachQuarantine(store, {
    outcome: input.breachOutcome,
    operationId: input.operationId,
    sourceWalletId: input.sourceWalletId ?? op.sourceWalletId,
    destinationWalletId: input.destinationWalletId ?? op.destinationWalletId,
    nowIso: input.nowIso,
    newId: input.newId,
    onQuarantineApplied: input.onQuarantineApplied,
  });
  return { kind: "QUARANTINED", result };
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostics (GET /admin/v1/operations/:operation_id/recovery surface)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compose the recovery diagnostics payload from existing store rows. No bespoke
 * endpoint — callers fold this into the existing recovery GET.
 */
export async function getMoveBreachDiagnostics(
  store: MoveInvariantBreachStore,
  operationId: string,
): Promise<MoveBreachDiagnostics | null> {
  const op = await store.getOperation(operationId);
  if (op === null) return null;

  const source = await store.getWallet(op.sourceWalletId);
  const dest = await store.getWallet(op.destinationWalletId);
  const sourceLease = await store.getLease(op.sourceWalletId);
  const destLease = await store.getLease(op.destinationWalletId);
  const anomalies = await store.listObservationAnomalies(operationId);
  const proofs = await store.listLineageProofVerdicts(operationId);

  const anomalyKind = anomalies[0]?.kind ?? null;
  const lineageVerdict = proofs[0]?.verdict ?? null;
  const breachReasonSource = proofs[0]?.reasonSource ?? null;

  const quarantineReason =
    source?.state === "QUARANTINED"
      ? source.quarantineReason
      : dest?.state === "QUARANTINED"
        ? dest.quarantineReason
        : null;

  return {
    operationId,
    moveAttemptId: op.moveAttemptId,
    status: op.status,
    quarantineReason,
    anomalyKind,
    lineageVerdict,
    breachReasonSource,
    sourceWalletId: op.sourceWalletId,
    destinationWalletId: op.destinationWalletId,
    sourceWalletState: source?.state ?? null,
    destinationWalletState: dest?.state ?? null,
    sourceLeaseId: sourceLease?.leaseId ?? null,
    destinationLeaseId: destLease?.leaseId ?? null,
    operatorAcknowledged: op.operatorAcknowledged,
    permittedOperatorActions: MOVE_BREACH_PERMITTED_OPERATOR_ACTIONS,
    forbiddenOperatorActions: MOVE_BREACH_FORBIDDEN_OPERATOR_ACTIONS,
  };
}

/** True when a wallet is frozen for money paths by this quarantine. */
export function isMoveBreachWalletFrozen(
  wallet: MoveBreachWalletSnapshot | null,
): boolean {
  if (wallet === null) return false;
  return wallet.state === "QUARANTINED" && wallet.quarantineReason !== null;
}

/**
 * Structural census: every catalog action is either permitted here, reserved
 * elsewhere, or out of MOVE-breach scope — and every non-action is forbidden.
 * Used by tests so the pin cannot silently drift from the contracts package.
 */
export function assertMoveBreachActionCatalogCoherent(): void {
  for (const action of MOVE_BREACH_PERMITTED_OPERATOR_ACTIONS) {
    if (!(OPERATOR_RECOVERY_ACTION_CATALOG as readonly string[]).includes(action)) {
      throw new Error(`${action} is not in OPERATOR_RECOVERY_ACTION_CATALOG`);
    }
    if (isMoveBreachOperatorActionForbidden(action)) {
      throw new Error(`${action} cannot be both permitted and forbidden`);
    }
  }
  for (const forbidden of [
    "FORCE_LANDED",
    "FORCE_RELEASE",
    "EDIT_TRANSACTION",
    "DELETE_EVIDENCE",
  ] as const) {
    if (!isMoveBreachOperatorActionForbidden(forbidden)) {
      throw new Error(`${forbidden} must be forbidden`);
    }
    if ((OPERATOR_RECOVERY_ACTION_CATALOG as readonly string[]).includes(forbidden)) {
      throw new Error(`${forbidden} must not appear in OPERATOR_RECOVERY_ACTION_CATALOG`);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal asserts
// ─────────────────────────────────────────────────────────────────────────────

async function requireWallet(
  store: MoveInvariantBreachStore,
  walletId: string,
): Promise<MoveBreachWalletSnapshot> {
  const wallet = await store.getWallet(walletId);
  if (wallet === null) {
    throw new MoveInvariantBreachError(`wallet ${walletId} not found`);
  }
  return wallet;
}

function identityOf(wallet: MoveBreachWalletSnapshot): {
  readonly publicKey: string;
  readonly keyOrigin: string;
  readonly nodeId: string;
} {
  return {
    publicKey: wallet.publicKey,
    keyOrigin: wallet.keyOrigin,
    nodeId: wallet.nodeId,
  };
}

function assertIdentityUntouched(
  prior: { readonly publicKey: string; readonly keyOrigin: string; readonly nodeId: string },
  next: MoveBreachWalletSnapshot,
): void {
  if (
    next.publicKey !== prior.publicKey ||
    next.keyOrigin !== prior.keyOrigin ||
    next.nodeId !== prior.nodeId
  ) {
    throw new MoveInvariantBreachError(
      `wallet ${next.walletId} identity/key columns must not change under quarantine`,
    );
  }
}

function assertWalletQuarantined(
  wallet: MoveBreachWalletSnapshot,
  expectedReason: string,
  priorLease: MoveBreachLeaseSnapshot | null,
): void {
  // RETIRED outranks quarantine for selection; still must not release lease.
  if (wallet.state === "RETIRED") {
    if (priorLease !== null && wallet.activeLeaseId !== priorLease.leaseId) {
      throw new MoveInvariantBreachError(
        `retired wallet ${wallet.walletId} lease must be preserved`,
      );
    }
    return;
  }
  if (wallet.state !== "QUARANTINED") {
    throw new MoveInvariantBreachError(
      `wallet ${wallet.walletId} must be QUARANTINED after breach apply, got ${wallet.state}`,
    );
  }
  if (wallet.quarantineReason === null || wallet.quarantineReason.length === 0) {
    throw new MoveInvariantBreachError(
      `wallet ${wallet.walletId} quarantine_reason must be non-null with QUARANTINED (CHECK constraint)`,
    );
  }
  if (wallet.quarantineReason !== expectedReason) {
    throw new MoveInvariantBreachError(
      `wallet ${wallet.walletId} quarantine_reason mismatch`,
    );
  }
  if (priorLease !== null && wallet.activeLeaseId !== priorLease.leaseId) {
    throw new MoveInvariantBreachError(
      `wallet ${wallet.walletId} active lease must be preserved under quarantine`,
    );
  }
}

async function assertLeaseUntouched(
  store: MoveInvariantBreachStore,
  walletId: string,
  prior: MoveBreachLeaseSnapshot | null,
): Promise<void> {
  const next = await store.getLease(walletId);
  if (prior === null && next === null) return;
  if (prior === null || next === null) {
    throw new MoveInvariantBreachError(
      `wallet ${walletId} lease presence changed under breach handling`,
    );
  }
  if (
    next.leaseId !== prior.leaseId ||
    next.lifecycle !== prior.lifecycle ||
    next.rowFingerprint !== prior.rowFingerprint
  ) {
    throw new MoveInvariantBreachError(
      `wallet ${walletId} lease row was mutated under breach handling (forbidden)`,
    );
  }
}

async function assertAttemptBytesUntouched(
  store: MoveInvariantBreachStore,
  operationId: string,
  prior: MoveBreachAttemptBytes | null,
): Promise<void> {
  const next = await store.getAttemptBytes(operationId);
  if (prior === null && next === null) return;
  if (prior === null || next === null) {
    throw new MoveInvariantBreachError(
      `operation ${operationId} attempt bytes presence changed under breach handling`,
    );
  }
  if (
    next.step1PreimageText !== prior.step1PreimageText ||
    next.step1Signature !== prior.step1Signature ||
    next.completedBodyText !== prior.completedBodyText ||
    next.completedBodySha256 !== prior.completedBodySha256 ||
    next.moveAttemptId !== prior.moveAttemptId
  ) {
    throw new MoveInvariantBreachError(
      `operation ${operationId} signed attempt bytes were mutated (forbidden)`,
    );
  }
}

async function assertWalletStateUnchanged(
  store: MoveInvariantBreachStore,
  walletId: string,
  prior: MoveBreachWalletSnapshot | null,
): Promise<void> {
  const next = await store.getWallet(walletId);
  if (prior === null && next === null) return;
  if (prior === null || next === null) {
    throw new MoveInvariantBreachError(`wallet ${walletId} presence changed`);
  }
  if (
    next.state !== prior.state ||
    next.quarantineReason !== prior.quarantineReason ||
    next.activeLeaseId !== prior.activeLeaseId ||
    next.rowVersion !== prior.rowVersion
  ) {
    throw new MoveInvariantBreachError(
      `wallet ${walletId} state changed under ACKNOWLEDGE_KEEP_PINNED (forbidden)`,
    );
  }
}

