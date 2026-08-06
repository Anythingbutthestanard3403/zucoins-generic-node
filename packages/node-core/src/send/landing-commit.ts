// DB-TX landing commit for SEND_EXTERNAL.
//
// (verification_material_available_until);.
//
// On a VERIFIED nine-predicate verdict this module, in ONE database transaction:
// 1. persists the exact completed settled body + terminal observation at
// attempt_phase = SETTLED_BODY_PERSISTED;
// 2. derives public execution phase LANDED_VERIFIED (carried on the landing record);
// 3. transitions AWAITING_REDEMPTION|NEEDS_ATTENTION → EXTERNAL_SEND_LANDED;
// 4. appends external_send.landed with {terminal_observation_id, landed_at};
// 5. sets proof-access expiry (terminal_at + window);
// 6. commits.
//
// The source lease is deliberately NOT released here (step 6). Release is a
// later verification-complete step. Callers must never invoke a lease-release path
// as part of this commit.
//
// The arbiter is the database: the status guard is in the UPDATE WHERE clause. A race
// that already landed (or left the entry set) matches zero rows → CONFLICT, no partial write.

import {
  DEFAULT_PROOF_ACCESS_WINDOW_MS,
  verificationMaterialAvailableUntilMs,
} from "../data/retention.js";
import type { LandingPathProof } from "../protocol/reconcile/landing-proof.js";
import {
  sha256HexUtf8,
  type CandidateCompletedEvidence,
  type SendLandingEntryStatus,
  type SendLandingVerdict,
} from "./landing-verify.js";

export const EXTERNAL_SEND_LANDED_STATUS = "EXTERNAL_SEND_LANDED" as const;
export const SETTLED_BODY_PERSISTED_PHASE = "SETTLED_BODY_PERSISTED" as const;
export const LANDED_VERIFIED_PHASE = "LANDED_VERIFIED" as const;
export const EXTERNAL_SEND_LANDED_EVENT = "external_send.landed" as const;

export const SEND_LANDING_ENTRY_STATUSES = ["AWAITING_REDEMPTION", "NEEDS_ATTENTION"] as const;

export interface ExternalSendLandingRecord {
  readonly operationId: string;
  readonly attemptPhase: typeof SETTLED_BODY_PERSISTED_PHASE;
  readonly publicExecutionPhase: typeof LANDED_VERIFIED_PHASE;
  readonly completedTransactionText: string;
  readonly completedTransactionSha256: string;
  readonly terminalObservationId: string;
  readonly sourcePathKind: LandingPathProof["kind"];
  readonly sourcePathDepth: number;
  readonly landedAtMs: number;
  readonly verificationMaterialAvailableUntilMs: number;
  readonly entryStatus: SendLandingEntryStatus;
}

export interface ExternalSendLandedEvent {
  readonly operationId: string;
  readonly eventType: typeof EXTERNAL_SEND_LANDED_EVENT;
  readonly terminalObservationId: string;
  readonly landedAtMs: number;
  readonly dataText: string;
}

export interface CommitExternalSendLandingCommand {
  readonly operationId: string;
  readonly expectedEntryStatus: SendLandingEntryStatus;
  readonly candidate: CandidateCompletedEvidence;
  readonly terminalObservationId: string;
  readonly sourcePath: LandingPathProof;
  readonly landedAtMs: number;
  readonly proofAccessWindowMs?: number;
}

export type CommitExternalSendLandingOutcome =
  | {
      readonly outcome: "APPLIED";
      readonly status: typeof EXTERNAL_SEND_LANDED_STATUS;
      readonly record: ExternalSendLandingRecord;
      readonly event: ExternalSendLandedEvent;
      /** Always true after a successful land — lease release is out of scope. */
      readonly sourceLeaseStillHeld: true;
    }
  | {
      readonly outcome: "CONFLICT";
      readonly reason: "STATUS_GUARD_MISMATCH" | "ALREADY_LANDED" | "LEASE_MISSING";
      readonly detail: string;
    }
  | {
      readonly outcome: "REJECTED";
      readonly reason:
        | "VERDICT_NOT_VERIFIED"
        | "COMPLETED_BODY_TEXT_REQUIRED"
        | "SETTLED_BODY_INTEGRITY";
      readonly detail: string;
    };

/**
 * Persistence port for the landing DB-TX. Implementations MUST run the status transition,
 * settled-body insert, event append, and proof-access write in a single transaction.
 * Implementations MUST NOT delete or update wallet_active_leases rows.
 */
export interface ExternalSendLandingStore {
  /**
   * Atomically land the operation. Returns null when the status guard matched no row
   * (already landed, wrong state, or missing). MUST leave the source lease intact.
   */
  commitLanding(command: CommitExternalSendLandingCommand): Promise<{
    readonly applied: boolean;
    readonly reason?: "STATUS_GUARD_MISMATCH" | "ALREADY_LANDED" | "LEASE_MISSING";
    readonly record?: ExternalSendLandingRecord;
    readonly event?: ExternalSendLandedEvent;
    readonly sourceLeaseStillHeld: boolean;
  }>;
}

function buildEventData(terminalObservationId: string, landedAtMs: number): string {
  // external_send.landed data: terminal_observation_id, landed_at.
  // Byte-stable field ordering for audit reproducibility.
  return JSON.stringify({
    terminal_observation_id: terminalObservationId,
    landed_at: new Date(landedAtMs).toISOString(),
  });
}

/**
 * Fail-closed settled-body triple: text === JSON.stringify(E) and sha256(text) === sha.
 * Returns null when identity holds; otherwise a reject reason detail.
 */
export function settledBodyIntegrityFailure(
  candidate: CandidateCompletedEvidence,
): string | null {
  const completedText = candidate.completedTransactionText;
  if (completedText === null || completedText.length === 0) {
    return "completedTransactionText is required to persist SETTLED_BODY_PERSISTED";
  }
  if (JSON.stringify(candidate.completedTransaction) !== completedText) {
    return "completedTransactionText is not JSON.stringify(E)";
  }
  if (sha256HexUtf8(completedText) !== candidate.completedTransactionSha256) {
    return "sha256(completedTransactionText) does not equal completedTransactionSha256";
  }
  return null;
}

export function buildLandingRecord(
  command: CommitExternalSendLandingCommand,
): ExternalSendLandingRecord {
  const integrity = settledBodyIntegrityFailure(command.candidate);
  if (integrity !== null) {
    throw new Error(integrity);
  }
  const completedText = command.candidate.completedTransactionText!;
  const windowMs = command.proofAccessWindowMs ?? DEFAULT_PROOF_ACCESS_WINDOW_MS;
  return {
    operationId: command.operationId,
    attemptPhase: SETTLED_BODY_PERSISTED_PHASE,
    publicExecutionPhase: LANDED_VERIFIED_PHASE,
    completedTransactionText: completedText,
    completedTransactionSha256: command.candidate.completedTransactionSha256,
    terminalObservationId: command.terminalObservationId,
    sourcePathKind: command.sourcePath.kind,
    sourcePathDepth: command.sourcePath.depth,
    landedAtMs: command.landedAtMs,
    verificationMaterialAvailableUntilMs: verificationMaterialAvailableUntilMs(
      command.landedAtMs,
      windowMs,
    ),
    entryStatus: command.expectedEntryStatus,
  };
}

export function buildLandedEvent(
  command: CommitExternalSendLandingCommand,
): ExternalSendLandedEvent {
  return {
    operationId: command.operationId,
    eventType: EXTERNAL_SEND_LANDED_EVENT,
    terminalObservationId: command.terminalObservationId,
    landedAtMs: command.landedAtMs,
    dataText: buildEventData(command.terminalObservationId, command.landedAtMs),
  };
}

/**
 * Commit a landing only when the nine-predicate pipeline returned VERIFIED.
 * Never lands on FAILED or INDETERMINATE. Never releases the source lease.
 */
export async function commitExternalSendLanding(
  verdict: SendLandingVerdict,
  store: ExternalSendLandingStore,
  options?: { readonly landedAtMs?: number; readonly proofAccessWindowMs?: number },
): Promise<CommitExternalSendLandingOutcome> {
  if (verdict.kind !== "VERIFIED") {
    return {
      outcome: "REJECTED",
      reason: "VERDICT_NOT_VERIFIED",
      detail: `landing commit requires VERIFIED, got ${verdict.kind}`,
    };
  }
  if (
    verdict.candidate.completedTransactionText === null ||
    verdict.candidate.completedTransactionText.length === 0
  ) {
    return {
      outcome: "REJECTED",
      reason: "COMPLETED_BODY_TEXT_REQUIRED",
      detail: "exact completed settled body text is required for SETTLED_BODY_PERSISTED",
    };
  }
  const integrity = settledBodyIntegrityFailure(verdict.candidate);
  if (integrity !== null) {
    return {
      outcome: "REJECTED",
      reason: "SETTLED_BODY_INTEGRITY",
      detail: integrity,
    };
  }

  const landedAtMs = options?.landedAtMs ?? Date.now();
  const command: CommitExternalSendLandingCommand = {
    operationId: verdict.operationId,
    expectedEntryStatus: verdict.entryStatus,
    candidate: verdict.candidate,
    terminalObservationId: verdict.terminalObservationId,
    sourcePath: verdict.proof,
    landedAtMs,
    proofAccessWindowMs: options?.proofAccessWindowMs,
  };

  const result = await store.commitLanding(command);
  if (!result.applied || result.record === undefined || result.event === undefined) {
    return {
      outcome: "CONFLICT",
      reason: result.reason ?? "STATUS_GUARD_MISMATCH",
      detail: "status guard matched no row or lease missing; no partial landing write",
    };
  }
  if (!result.sourceLeaseStillHeld) {
    // A store that releases the lease has violated step 6. Surface as conflict so
    // callers never treat a lease-releasing implementation as a successful land.
    return {
      outcome: "CONFLICT",
      reason: "LEASE_MISSING",
      detail: "landing store reported source lease not held after commit — step 6 breach",
    };
  }
  return {
    outcome: "APPLIED",
    status: EXTERNAL_SEND_LANDED_STATUS,
    record: result.record,
    event: result.event,
    sourceLeaseStillHeld: true,
  };
}
