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
// Step 6 (ZTR-1304): for NODE_VERIFIED only, the landing store mints a terminal-positive
// release proof and releases SEND_SOURCE in the same TX (EXTERNAL_SEND_LANDED proof kind).
// INDEPENDENT keeps the lease held until verification-complete. Attention/park paths never
// reach this commit, so they release nothing.
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
      /**
       * True when SEND_SOURCE remains held after commit (INDEPENDENT). False only when
       * NODE_VERIFIED released custody in the same landing TX (ZTR-1304).
       */
      readonly sourceLeaseStillHeld: boolean;
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
 * Lease mutation is allowed only for the NODE_VERIFIED release branch (mintReleaseProof +
 * releaseLease on the same pinned executor); INDEPENDENT MUST leave wallet_active_leases
 * byte-identical.
 */
export interface ExternalSendLandingStore {
  /**
   * Atomically land the operation. Returns applied:false when the status guard matched no row
   * (already landed, wrong state, or missing). `sourceLeaseStillHeld` reports post-commit
   * custody: false only after an intentional NODE_VERIFIED same-TX release.
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
  // Byte-stable field sequence for audit reproducibility.
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
 * Never lands on FAILED or INDETERMINATE. Lease release is store-owned: NODE_VERIFIED
 * may clear SEND_SOURCE inside the landing TX (ZTR-1304); INDEPENDENT keeps it held.
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
  // NODE_VERIFIED may clear the lease inside the landing TX (ZTR-1304). The store is the
  // authority: applied:true with sourceLeaseStillHeld:false is intentional release, not a
  // custody breach. applied:false + LEASE_MISSING still surfaces missing-lease races.
  return {
    outcome: "APPLIED",
    status: EXTERNAL_SEND_LANDED_STATUS,
    record: result.record,
    event: result.event,
    sourceLeaseStillHeld: result.sourceLeaseStillHeld,
  };
}
