// SEND_EXTERNAL late-landing reconciliation after post-delivery expiry.
//
// (NEEDS_ATTENTION → EXTERNAL_SEND_LANDED)
// landing-path oracle (any-depth complete-path oracle; no generic PROVEN_NOT_LANDED)
// SEND_EXTERNAL expiry single-source (expiry never terminally rejects / never releases the source lease)
//
// parks past-T2 AWAITING_REDEMPTION → NEEDS_ATTENTION. This module is the
// independently deliverable *positive* half of the subsequent loop: keep reading the
// source head, assemble a landing-path oracle complete-path proof at any depth, and on a verified
// landing drive NEEDS_ATTENTION → EXTERNAL_SEND_LANDED via the existing landing commit
// (steps 5–6). The *negative* half (CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED) is
// out of scope — this loop never itself triggers a terminal close or any release.
//
// Hard guarantees:
// - Unchanged head, silence, timeout, malformed response, missing body, gap, anomaly,
// endpoint disagreement, or verifier-budget exhaustion → INDETERMINATE / WAITING;
// remain NEEDS_ATTENTION; lease held.
// - No grace window that refuses a late landing (prior scaffold's LATE_LANDING_OUTSIDE_WINDOW
// is rejected — landing-path oracle has no time-box on the positive oracle after expiry).
// - No lease DELETE/UPDATE. No second partial. No one-hop LANDED_DIRECT_SUCCESSOR.
// - Landing-proof rows are insert-once per attempt: a second land attempt after
// EXTERNAL_SEND_LANDED is ALREADY_LANDED / CONFLICT, never a duplicate proof row.
// Proof-then-commit dual-write is recoverable: a durable positive row with
// send_operations still in the landing entry set always retries commitExternalSendLanding;
// ALREADY_LANDED is returned only when the land CAS reports already landed.

import { createHash, randomUUID } from "node:crypto";

import { mintLandingPathProofFromOracle } from "../protocol/reconcile/landing-oracle-mint.js";
import type { LandingPathProof } from "../protocol/reconcile/landing-proof.js";
import type { PathObservation } from "../protocol/reconcile/observation-input.js";
import { classifySendReconcile } from "../protocol/reconcile/send.js";
import {
  type ReconcileIndeterminateReason,
  type ReconcileInvariantBreachReason,
  assertUnreachable,
  toAttentionReason,
} from "../protocol/reconcile/types.js";
import type {
  LineagePathBodyRow,
  LineagePathProofRow,
  LineagePathProofStore,
  PathBaseline,
  RetainedPathBody,
  RetainedPathBodySource,
  WalkOperation,
} from "../verifier/ancestry-walker.js";
import { walkAncestryPath } from "../verifier/ancestry-walker.js";
import type { ParsedSettledTransaction } from "../verifier/gateway-envelope.js";
import type { FreshHeadRead, ReadFreshHead } from "../verifier/landing-path-oracle.js";
import {
  pathContinuityFault,
  proveSendLanding,
  landingProofToPathObservation,
} from "../verifier/landing-path-oracle.js";
import { verifySettledTransaction } from "../verifier/transaction-verify.js";

import {
  commitExternalSendLanding,
  type CommitExternalSendLandingOutcome,
  type ExternalSendLandingStore,
} from "./landing-commit.js";
import {
  verifyExternalSendLanding,
  type CandidateCompletedEvidence,
  type SendLandingEvidence,
  type SendLandingEntryStatus,
  type SendLandingVerdict,
} from "./landing-verify.js";

const sha256HexUtf8 = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

/**
 * Build one lineage_path_bodies row from a verified settled body.
 * path_index 0 is always EXPECTED_OPERATION; later hops are PROOF_CHANNEL
 * (caller-supplied evidence that already passed the oracle).
 */
function lineageBodyRowFromVerified(
  pathProofId: string,
  pathIndex: number,
  sourceKind: "EXPECTED_OPERATION" | "PROOF_CHANNEL" | "FRESH_GATEWAY_HEAD",
  verified: {
    readonly completedTransactionText: string;
    readonly completedTransactionSha256: string;
    readonly innerPreimageText: string;
    readonly transaction: {
      readonly step_1_signature: string;
      readonly step_2_signature: string;
      readonly inner: {
        readonly previous_step_1_state_signature: string;
        readonly step_1_state: { readonly amount: string };
      };
    };
    readonly projection: { readonly S: string; readonly P: string; readonly B: string };
  },
): LineagePathBodyRow {
  const octets = Buffer.byteLength(verified.completedTransactionText, "utf8");
  const innerSha256 = sha256HexUtf8(verified.innerPreimageText);
  const manifestText = JSON.stringify({
    path_index: pathIndex,
    completed_transaction_sha256: verified.completedTransactionSha256,
    completed_transaction_octets: octets,
    s_signature: verified.projection.S,
    p_signature: verified.projection.P,
    b_amount: verified.projection.B,
    wallet_role: "sender",
    inner_sha256: innerSha256,
  });
  return {
    path_proof_id: pathProofId,
    path_index: pathIndex,
    source_kind: sourceKind,
    completed_transaction_text: verified.completedTransactionText,
    completed_transaction_sha256: verified.completedTransactionSha256,
    completed_transaction_octets: octets,
    wallet_role: "sender",
    s_signature: verified.projection.S,
    p_signature: verified.projection.P,
    b_amount: verified.projection.B,
    inner_preimage_text: verified.innerPreimageText,
    inner_sha256: innerSha256,
    step_1_signature: verified.transaction.step_1_signature,
    step_2_signature: verified.transaction.step_2_signature,
    verification_manifest_text: manifestText,
    verification_manifest_sha256: sha256HexUtf8(manifestText),
  };
}

/**
 * Assemble ordered path bodies 0..n for a positive land.
 * Prefer walk staging (full rows already verified). Otherwise rebuild from
 * expected body + successorBodies via verifySettledTransaction (same path the
 * oracle just accepted). Returns null when assembly cannot match path.depth.
 */
function assembleCompletePathBodies(input: {
  readonly pathProofId: string;
  readonly pathDepth: number;
  readonly sourcePubkey: string;
  readonly expectedBody: ParsedSettledTransaction;
  readonly expectedBodyText: string;
  readonly successorBodies: readonly ParsedSettledTransaction[];
  readonly staged: { proof: LineagePathProofRow; bodies: readonly LineagePathBodyRow[] } | null;
}): {
  readonly bodies: readonly LineagePathBodyRow[];
  readonly freshHeadSha256: string;
  readonly totalBytes: number;
} | null {
  const { pathProofId, pathDepth, sourcePubkey, staged } = input;
  const expectedCount = pathDepth + 1;

  if (staged !== null && staged.bodies.length === expectedCount) {
    // Re-key staged rows onto this path_proof_id (walk used a provisional id).
    const bodies = staged.bodies.map((b, i) => ({
      ...b,
      path_proof_id: pathProofId,
      path_index: i,
    }));
    const last = bodies[bodies.length - 1]!;
    const totalBytes = bodies.reduce((n, b) => n + b.completed_transaction_octets, 0);
    return {
      bodies,
      freshHeadSha256: last.completed_transaction_sha256,
      totalBytes,
    };
  }

  // Oracle / supplied-body path: expected + successors in sequence.
  const parsedPath: ParsedSettledTransaction[] = [
    input.expectedBody,
    ...input.successorBodies.slice(0, pathDepth),
  ];
  if (parsedPath.length !== expectedCount) {
    return null;
  }

  const bodies: LineagePathBodyRow[] = [];
  for (let i = 0; i < parsedPath.length; i += 1) {
    const parsed = parsedPath[i]!;
    const verified = verifySettledTransaction(parsed, sourcePubkey);
    if (verified.verdict !== "VERIFIED") {
      return null;
    }
    // path_index 0 must byte-match the operation's expected body text.
    if (i === 0 && verified.completedTransactionText !== input.expectedBodyText) {
      // Prefer the durable expected-body bytes when reconstruction differs only
      // by parse round-trip; digest must still match oracle expectedSha.
      if (sha256HexUtf8(input.expectedBodyText) !== verified.completedTransactionSha256) {
        return null;
      }
    }
    const sourceKind =
      i === 0
        ? "EXPECTED_OPERATION"
        : i === parsedPath.length - 1 && pathDepth > 0
          ? "FRESH_GATEWAY_HEAD"
          : "PROOF_CHANNEL";
    const rowBase =
      i === 0
        ? {
            ...verified,
            // Persist the operation artifact's exact bytes at index 0.
            completedTransactionText: input.expectedBodyText,
            completedTransactionSha256: sha256HexUtf8(input.expectedBodyText),
          }
        : verified;
    bodies.push(
      lineageBodyRowFromVerified(pathProofId, i, sourceKind, rowBase),
    );
  }

  const last = bodies[bodies.length - 1]!;
  const totalBytes = bodies.reduce((n, b) => n + b.completed_transaction_octets, 0);
  return {
    bodies,
    freshHeadSha256: last.completed_transaction_sha256,
    totalBytes,
  };
}

/** Closed set of SQL surfaces this module may emit (negative catalogue). */
export const LATE_LANDING_RECONCILE_ALLOWED_SQL: ReadonlySet<string> = new Set([
  // Landing commit — status CAS + settled body + event; lease SELECT only.
  "UPDATE send_operations SET status",
  "INSERT INTO external_send_landing_records",
  "INSERT INTO external_send_landing_events",
  "SELECT wallet_id FROM wallet_active_leases",
  "SELECT status FROM send_operations",
  // Proof persistence (construction half).
  "INSERT INTO operation_landing_proofs",
  "INSERT INTO lineage_path_proofs",
  "INSERT INTO lineage_path_bodies",
  "SELECT id FROM operation_landing_proofs",
  "SELECT id FROM lineage_path_proofs",
  "SELECT path_index FROM lineage_path_bodies",
]);

const FORBIDDEN_SQL_FRAGMENTS = [
  "DELETE FROM wallet_active_leases",
  "UPDATE wallet_active_leases",
  "INSERT INTO external_send_partials",
  "INSERT INTO external_send_sign_intents",
  "status = 'EXPIRED'",
  "status = 'REJECTED'",
  "AWAITING_REDEMPTION' → 'REJECTED",
] as const;

/**
 * Structural guard: the allowed-SQL catalogue must never admit lease release, a second
 * partial, or a terminal EXPIRED/REJECTED write. Called from tests.
 */
export function assertLateLandingSqlCatalogueSafe(): void {
  for (const allowed of LATE_LANDING_RECONCILE_ALLOWED_SQL) {
    const upper = allowed.toUpperCase();
    for (const frag of FORBIDDEN_SQL_FRAGMENTS) {
      if (upper.includes(frag.toUpperCase())) {
        throw new Error(`late-landing SQL catalogue admits forbidden fragment: ${frag}`);
      }
    }
  }
}

// ─── Durable landing-proof progress ──────────────────────────────────────

export type LineageProofVerdict =
  | "LANDED_EXACT"
  | "LANDED_COMPLETE_PATH"
  | "INDETERMINATE"
  | "INVARIANT_BREACH";

export interface OperationLandingProofRow {
  readonly id: string;
  readonly operationId: string;
  readonly verifierObserverId: string;
  readonly expectedTransactionAttemptNo: 1;
  readonly verdict: LineageProofVerdict;
  readonly requiredPathCount: 1;
  readonly declaredBodyCount: number;
  readonly declaredTotalBodyBytes: number;
  readonly proofManifestText: string;
  readonly proofManifestSha256: string;
  readonly verifiedAtMs: number | null;
  readonly createdAtMs: number;
}

export interface LateLandingProofProgress {
  readonly landingProof: OperationLandingProofRow;
  readonly pathProof: LineagePathProofRow | null;
  readonly bodies: readonly LineagePathBodyRow[];
}

/**
 * Persistence port for operation_landing_proofs / lineage_path_proofs /
 * lineage_path_bodies. Implementations MUST be insert-once for a given
 * (operation_id, attempt_no=1) positive landing — a second positive write is refused.
 * Incomplete (INDETERMINATE) progress may be upserted so a restart resumes.
 */
export interface SendLateLandingProofStore {
  /**
   * Load the single attempt-1 proof row for this operation, if any.
   * MUST read durable storage (not process-local memory alone) so a restart after
   * positive proof INSERT can recover the land CAS.
   */
  loadAttempt1(operationId: string): Promise<LateLandingProofProgress | null>;

  /**
   * Persist an INDETERMINATE progress snapshot. Must not overwrite a row whose verdict
   * is already LANDED_EXACT / LANDED_COMPLETE_PATH.
   */
  saveIndeterminateProgress(progress: LateLandingProofProgress): Promise<void>;

  /**
   * Persist a positive landing proof + SOURCE path + ordered bodies. Must refuse if a
   * positive proof already exists for this operation/attempt (no duplicate landing-proof row).
   */
  savePositiveProof(progress: LateLandingProofProgress): Promise<
    | { readonly kind: "INSERTED" }
    | { readonly kind: "ALREADY_POSITIVE"; readonly existingId: string }
  >;
}

/** In-memory store for unit tests — mirrors insert-once positive semantics. */
export class InMemorySendLateLandingProofStore implements SendLateLandingProofStore {
  readonly byOperation = new Map<string, LateLandingProofProgress>();

  async loadAttempt1(operationId: string): Promise<LateLandingProofProgress | null> {
    return this.byOperation.get(operationId) ?? null;
  }

  async saveIndeterminateProgress(progress: LateLandingProofProgress): Promise<void> {
    const existing = this.byOperation.get(progress.landingProof.operationId);
    if (
      existing !== undefined &&
      (existing.landingProof.verdict === "LANDED_EXACT" ||
        existing.landingProof.verdict === "LANDED_COMPLETE_PATH")
    ) {
      // Positive proof is immutable; never regress.
      return;
    }
    this.byOperation.set(progress.landingProof.operationId, progress);
  }

  async savePositiveProof(
    progress: LateLandingProofProgress,
  ): Promise<{ readonly kind: "INSERTED" } | { readonly kind: "ALREADY_POSITIVE"; readonly existingId: string }> {
    const existing = this.byOperation.get(progress.landingProof.operationId);
    if (
      existing !== undefined &&
      (existing.landingProof.verdict === "LANDED_EXACT" ||
        existing.landingProof.verdict === "LANDED_COMPLETE_PATH")
    ) {
      return { kind: "ALREADY_POSITIVE", existingId: existing.landingProof.id };
    }
    this.byOperation.set(progress.landingProof.operationId, progress);
    return { kind: "INSERTED" };
  }
}

/** LineagePathProofStore adapter that stages rows until the parent landing proof commits. */
export class StagingLineagePathProofStore implements LineagePathProofStore {
  last: { proof: LineagePathProofRow; bodies: readonly LineagePathBodyRow[] } | null = null;

  async writePathProof(
    proof: LineagePathProofRow,
    bodies: readonly LineagePathBodyRow[],
  ): Promise<void> {
    this.last = { proof, bodies };
  }
}

// ─── Reconcile inputs / outcomes ─────────────────────────────────────────────

export type LateLandingClassification =
  | {
      readonly kind: "LANDED_VERIFIED";
      readonly sendAttemptId: string;
      readonly sourcePath: LandingPathProof;
      readonly landingVerdict: Extract<SendLandingVerdict, { kind: "VERIFIED" }>;
    }
  | {
      readonly kind: "INDETERMINATE";
      readonly sendAttemptId: string;
      readonly reason: ReconcileIndeterminateReason;
    }
  | {
      readonly kind: "WAITING";
      readonly sendAttemptId: string;
      readonly redeliverableTransferCodeSha256: string;
    }
  | {
      readonly kind: "INVARIANT_BREACH";
      readonly sourceWalletId: string;
      readonly reason: ReconcileInvariantBreachReason;
    };

export type LateLandingApplyOutcome =
  | {
      readonly kind: "LANDED";
      readonly classification: Extract<LateLandingClassification, { kind: "LANDED_VERIFIED" }>;
      readonly commit: Extract<CommitExternalSendLandingOutcome, { outcome: "APPLIED" }>;
      readonly proofProgress: LateLandingProofProgress;
      readonly sourceLeaseStillHeld: true;
    }
  | {
      readonly kind: "REMAIN_ATTENTION";
      readonly classification: Exclude<LateLandingClassification, { kind: "LANDED_VERIFIED" }>;
      readonly sourceLeaseStillHeld: true;
      /** Present when partial path bodies were staged for restart. */
      readonly proofProgress: LateLandingProofProgress | null;
    }
  | {
      readonly kind: "ALREADY_LANDED";
      readonly sourceLeaseStillHeld: true;
      readonly existingLandingProofId: string | null;
    }
  | {
      readonly kind: "REFUSED_CLOSE";
      readonly detail: string;
      readonly classification: LateLandingClassification;
      readonly sourceLeaseStillHeld: true;
    };

export interface LateLandingOperationFacts {
  readonly operationId: string;
  readonly sendAttemptId: string;
  readonly sourceWalletId: string;
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  readonly amountZkz: string;
  readonly transferCodeSha256: string;
  /** Must be NEEDS_ATTENTION for this loop (park). */
  readonly status: SendLandingEntryStatus;
  readonly sourceLeaseActive: boolean;
  /** Attempt-1 expected completed body (recipient-completed SEND). */
  readonly expectedBody: ParsedSettledTransaction;
  readonly expectedBodyText: string;
  readonly t0Body: ParsedSettledTransaction | null;
  /** Evidence for the nine-predicate verifier (candidate filled by this loop when proven). */
  readonly landingEvidenceBase: Omit<
    SendLandingEvidence,
    "candidate" | "sourcePathProof" | "sourcePathProofIncomplete" | "entryStatus"
  >;
  readonly candidateFromExpected: CandidateCompletedEvidence;
  readonly verifierObserverId: string;
}

export interface LateLandingCycleInput {
  readonly facts: LateLandingOperationFacts;
  /**
   * Fresh observation of the source path. Callers obtain this via the observation
   * service — this module never calls a gateway submit surface.
   */
  readonly sourceObservation: PathObservation;
  /**
   * When the observation is not yet a full landing-path oracle proof, the cycle may run the oracle /
   * ancestry walk against retained bodies. Empty successors = depth-0 exact-head claim.
   */
  readonly successorBodies?: readonly ParsedSettledTransaction[];
  readonly retainedSource?: RetainedPathBodySource;
  readonly expectedRetainedBody?: RetainedPathBody;
  readonly baseline?: PathBaseline;
  readonly readFreshHead?: ReadFreshHead;
  readonly maxDepth?: number;
  readonly nowMs?: number;
}

function buildLandingProofManifest(input: {
  readonly operationId: string;
  readonly expectedBodySha256: string;
  readonly verdict: LineageProofVerdict;
  readonly bodyCount: number;
  readonly totalBytes: number;
  readonly pathProofId: string | null;
}): { text: string; sha256: string } {
  const text = JSON.stringify({
    purpose: "zp-operation-landing-proof-v1",
    operation_id: input.operationId,
    attempt_no: 1,
    expected_completed_transaction_sha256: input.expectedBodySha256,
    required_path_count: 1,
    path_role: "SOURCE",
    path_proof_id: input.pathProofId,
    declared_body_count: input.bodyCount,
    declared_total_body_bytes: input.totalBytes,
    verdict: input.verdict,
  });
  return { text, sha256: sha256HexUtf8(text) };
}

function emptyIndeterminateProgress(
  facts: LateLandingOperationFacts,
  faultSource: ReconcileIndeterminateReason,
  nowMs: number,
): LateLandingProofProgress {
  const id = randomUUID();
  const expectedSha = sha256HexUtf8(facts.expectedBodyText);
  const manifest = buildLandingProofManifest({
    operationId: facts.operationId,
    expectedBodySha256: expectedSha,
    verdict: "INDETERMINATE",
    bodyCount: 1,
    totalBytes: Buffer.byteLength(facts.expectedBodyText, "utf8"),
    pathProofId: null,
  });
  return {
    landingProof: {
      id,
      operationId: facts.operationId,
      verifierObserverId: facts.verifierObserverId,
      expectedTransactionAttemptNo: 1,
      verdict: "INDETERMINATE",
      requiredPathCount: 1,
      declaredBodyCount: 1,
      declaredTotalBodyBytes: Buffer.byteLength(facts.expectedBodyText, "utf8"),
      proofManifestText: manifest.text,
      proofManifestSha256: manifest.sha256,
      verifiedAtMs: null,
      createdAtMs: nowMs,
    },
    pathProof: null,
    bodies: [],
  };
}

/**
 * Classify one late-landing cycle for a NEEDS_ATTENTION SEND_EXTERNAL.
 *
 * Prefers a caller-supplied PathObservation (already proven by the observation pipeline).
 * When the observation is incomplete and retained bodies + a fresh-head reader are
 * provided, runs `proveSendLanding` / `walkAncestryPath` to assemble the landing-path oracle path.
 */
export async function classifyLateLandingCycle(
  input: LateLandingCycleInput,
): Promise<LateLandingClassification> {
  const { facts } = input;
  if (facts.status !== "NEEDS_ATTENTION" && facts.status !== "AWAITING_REDEMPTION") {
    return {
      kind: "INDETERMINATE",
      sendAttemptId: facts.sendAttemptId,
      reason: { source: "RELEASE_PREDICATE_UNSATISFIED", predicate: "entry_status" },
    };
  }
  if (!facts.sourceLeaseActive) {
    return {
      kind: "INVARIANT_BREACH",
      sourceWalletId: facts.sourceWalletId,
      reason: { source: "LEASE_NOT_ACTIVE_DURING_RECONCILE" },
    };
  }

  let observation = input.sourceObservation;

  // If the observation is not yet a positive proof, try the landing-path oracle with supplied bodies.
  if (observation.result !== "PROOF" && input.readFreshHead !== undefined) {
    const oracleOutcome = await proveSendLanding(
      {
        walletPubkeyBase64Urlsafe: facts.sourcePubkey,
        t0Body: facts.t0Body,
        expectedBody: facts.expectedBody,
        successorBodies: input.successorBodies ?? [],
        operation: {
          amountZkz: facts.amountZkz,
          sourcePubkey: facts.sourcePubkey,
          destinationAddress: facts.destinationAddress,
        },
        maxDepth: input.maxDepth,
      },
      input.readFreshHead,
    );
    observation = landingProofToPathObservation(oracleOutcome);
  }

  // Retained-storage walk (optional): when a body source is wired, assemble path rows.
  if (
    observation.result !== "PROOF" &&
    input.retainedSource !== undefined &&
    input.expectedRetainedBody !== undefined &&
    input.baseline !== undefined &&
    input.readFreshHead !== undefined
  ) {
    const staging = new StagingLineagePathProofStore();
    const walk = await walkAncestryPath(
      {
        pathProofId: randomUUID(),
        landingProofId: randomUUID(),
        walletId: facts.sourceWalletId,
        walletPublicKey: facts.sourcePubkey,
        operation: {
          kind: "SEND_EXTERNAL",
          amountZkz: facts.amountZkz,
          sourcePubkey: facts.sourcePubkey,
          destinationAddress: facts.destinationAddress,
        } satisfies WalkOperation,
        expectedBody: input.expectedRetainedBody,
        baseline: input.baseline,
        maxPathDepth: input.maxDepth,
      },
      input.retainedSource,
      input.readFreshHead,
      staging,
    );
    if (walk.kind === "PATH_PROVEN") {
      observation = { result: "PROOF", proof: walk.proof };
    } else {
      observation = { result: "PROOF_INCOMPLETE", fault: walk.fault };
    }
  }

  // Delivered-boundary classify: WAITING only for clean NO_SUCCESSOR; genuine faults stay
  // INDETERMINATE. Expiry does not add a grace-window gate (positive oracle is unbounded).
  const reconcile = classifySendReconcile({
    boundary: "DELIVERED",
    sendAttemptId: facts.sendAttemptId,
    sourceWalletId: facts.sourceWalletId,
    sourceLeaseState: facts.sourceLeaseActive ? "ACTIVE" : "RELEASED",
    transferCodeSha256: facts.transferCodeSha256,
    sourceObservation: observation,
  });

  switch (reconcile.kind) {
    case "LANDED_VERIFIED": {
      const landingVerdict = verifyExternalSendLanding({
        ...facts.landingEvidenceBase,
        entryStatus: facts.status === "NEEDS_ATTENTION" ? "NEEDS_ATTENTION" : "AWAITING_REDEMPTION",
        candidate: facts.candidateFromExpected,
        sourcePathProof: reconcile.sourcePath,
        sourcePathProofIncomplete: false,
      });
      if (landingVerdict.kind !== "VERIFIED") {
        if (landingVerdict.kind === "INDETERMINATE") {
          return {
            kind: "INDETERMINATE",
            sendAttemptId: facts.sendAttemptId,
            reason: {
              source: "LANDING_PROOF_INCOMPLETE",
              fault:
                landingVerdict.reason === "SOURCE_PATH_PROOF_INCOMPLETE" ||
                landingVerdict.reason === "SOURCE_PATH_PROOF_ABSENT"
                  ? "MISSING_BODY"
                  : "ANOMALOUS_OR_CONTRADICTORY",
            },
          };
        }
        return {
          kind: "INDETERMINATE",
          sendAttemptId: facts.sendAttemptId,
          reason: {
            source: "RELEASE_PREDICATE_UNSATISFIED",
            predicate: landingVerdict.failedPredicate,
          },
        };
      }
      return {
        kind: "LANDED_VERIFIED",
        sendAttemptId: facts.sendAttemptId,
        sourcePath: reconcile.sourcePath,
        landingVerdict,
      };
    }
    case "WAITING":
      return {
        kind: "WAITING",
        sendAttemptId: reconcile.sendAttemptId,
        redeliverableTransferCodeSha256: reconcile.redeliverableTransferCodeSha256,
      };
    case "INDETERMINATE":
      return {
        kind: "INDETERMINATE",
        sendAttemptId: reconcile.sendAttemptId,
        reason: reconcile.reason,
      };
    case "INVARIANT_BREACH":
      return {
        kind: "INVARIANT_BREACH",
        sourceWalletId: reconcile.sourceWalletId,
        reason: reconcile.reason,
      };
    case "PROVEN_NOT_STARTED":
      // A delivered/expired partial cannot re-enter formation.
      return {
        kind: "INDETERMINATE",
        sendAttemptId: facts.sendAttemptId,
        reason: { source: "RELEASE_PREDICATE_UNSATISFIED", predicate: "post_delivery_only" },
      };
    default:
      return assertUnreachable(reconcile);
  }
}

/**
 * Rebuild a VERIFIED nine-predicate verdict from a durable positive proof plus
 * the operation facts the worker still holds. Used when proof was persisted but
 * commitExternalSendLanding did not complete (crash / dual-write window).
 *
 * never mint from the path-row header alone. Transactionally revalidate every
 * persisted body (signature + preimage reconstruction), path continuity, and the bound
 * observation id / expected / fresh-head digests, then issue an oracle seal.
 */
function rebuildVerifiedVerdictFromPositiveProof(
  facts: LateLandingOperationFacts,
  progress: LateLandingProofProgress,
): Extract<SendLandingVerdict, { kind: "VERIFIED" }> | null {
  const pathRow = progress.pathProof;
  const verdictKind = progress.landingProof.verdict;
  if (pathRow === null) return null;
  if (verdictKind !== "LANDED_EXACT" && verdictKind !== "LANDED_COMPLETE_PATH") return null;
  if (progress.bodies.length !== pathRow.path_depth + 1) return null;

  const wallet = pathRow.wallet_public_key;
  const ordered = [...progress.bodies].sort((a, b) => a.path_index - b.path_index);
  const seenBodyDigests = new Set<string>();
  const seenStateSignatures = new Set<string>();
  let previousS: string | undefined;
  let expectedSha: string | undefined;
  let headSha: string | undefined;

  for (let i = 0; i < ordered.length; i += 1) {
    const row = ordered[i]!;
    if (row.path_index !== i) return null;
    const textSha = sha256HexUtf8(row.completed_transaction_text);
    if (textSha !== row.completed_transaction_sha256) return null;

    // Parse retained bytes via the gateway envelope shape scanner used elsewhere for
    // body-as-JSON settled txs: JSON.parse + closed field check is enough for verifySettledTransaction.
    let parsed: ParsedSettledTransaction;
    try {
      parsed = JSON.parse(row.completed_transaction_text) as ParsedSettledTransaction;
    } catch {
      return null;
    }
    const verified = verifySettledTransaction(parsed, wallet);
    if (verified.verdict !== "VERIFIED") return null;
    if (verified.completedTransactionSha256 !== row.completed_transaction_sha256) return null;
    if (verified.completedTransactionText !== row.completed_transaction_text) {
      // Durable expected-body bytes at index 0 may prefer the operation artifact text.
      if (i !== 0 || verified.completedTransactionSha256 !== textSha) return null;
    }

    const continuity = pathContinuityFault({
      bodySha256: verified.completedTransactionSha256,
      S: verified.projection.S,
      P: verified.projection.P,
      previousS,
      seenBodyDigests,
      seenStateSignatures,
    });
    if (continuity !== null) return null;
    seenBodyDigests.add(verified.completedTransactionSha256);
    seenStateSignatures.add(verified.projection.S);
    previousS = verified.projection.S;
    expectedSha ??= verified.completedTransactionSha256;
    headSha = verified.completedTransactionSha256;
  }

  if (expectedSha === undefined || headSha === undefined) return null;
  if (expectedSha !== pathRow.expected_completed_transaction_sha256) return null;
  if (headSha !== pathRow.fresh_head_completed_transaction_sha256) return null;

  try {
    const path = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: wallet,
      expectedBodySha256: pathRow.expected_completed_transaction_sha256,
      freshHeadBodySha256: pathRow.fresh_head_completed_transaction_sha256,
      freshHeadObservationId: pathRow.fresh_head_observation_id,
      depth: pathRow.path_depth,
    });
    const landingVerdict = verifyExternalSendLanding({
      ...facts.landingEvidenceBase,
      entryStatus:
        facts.status === "NEEDS_ATTENTION" ? "NEEDS_ATTENTION" : "AWAITING_REDEMPTION",
      candidate: facts.candidateFromExpected,
      sourcePathProof: path,
      sourcePathProofIncomplete: false,
    });
    return landingVerdict.kind === "VERIFIED" ? landingVerdict : null;
  } catch {
    return null;
  }
}

/**
 * Complete EXTERNAL_SEND_LANDED from an already-durable positive proof.
 * Returns ALREADY_LANDED only when the landing store reports the status CAS as
 * already landed — never when the op is still in the entry set.
 */
async function completeLandFromPositiveProof(
  input: LateLandingCycleInput,
  progress: LateLandingProofProgress,
  landingStore: ExternalSendLandingStore,
  nowMs: number,
): Promise<LateLandingApplyOutcome> {
  const landingVerdict = rebuildVerifiedVerdictFromPositiveProof(input.facts, progress);
  if (landingVerdict === null) {
    return {
      kind: "REMAIN_ATTENTION",
      classification: {
        kind: "INDETERMINATE",
        sendAttemptId: input.facts.sendAttemptId,
        reason: {
          source: "RELEASE_PREDICATE_UNSATISFIED",
          predicate: "positive_proof_land_recovery_rebuild_failed",
        },
      },
      sourceLeaseStillHeld: true,
      proofProgress: progress,
    };
  }

  const commit = await commitExternalSendLanding(landingVerdict, landingStore, {
    landedAtMs: nowMs,
  });

  if (commit.outcome === "APPLIED") {
    return {
      kind: "LANDED",
      classification: {
        kind: "LANDED_VERIFIED",
        sendAttemptId: input.facts.sendAttemptId,
        sourcePath: landingVerdict.proof,
        landingVerdict,
      },
      commit,
      proofProgress: progress,
      sourceLeaseStillHeld: true,
    };
  }

  if (commit.outcome === "CONFLICT" && commit.reason === "ALREADY_LANDED") {
    return {
      kind: "ALREADY_LANDED",
      sourceLeaseStillHeld: true,
      existingLandingProofId: progress.landingProof.id,
    };
  }

  // Status still entry-set but CAS missed, or lease missing — keep attention; lease held.
  return {
    kind: "REMAIN_ATTENTION",
    classification: {
      kind: "INDETERMINATE",
      sendAttemptId: input.facts.sendAttemptId,
      reason: {
        source: "RELEASE_PREDICATE_UNSATISFIED",
        predicate: `landing_commit_recovery_${commit.outcome}`,
      },
    },
    sourceLeaseStillHeld: true,
    proofProgress: progress,
  };
}

export interface ApplyLateLandingDeps {
  readonly landingStore: ExternalSendLandingStore;
  readonly proofStore: SendLateLandingProofStore;
  readonly pathProofStore?: LineagePathProofStore;
  readonly clock?: () => number;
}

/**
 * Run one late-landing cycle and apply the durable effect:
 * LANDED_VERIFIED → persist positive proof + commitExternalSendLanding
 * - durable positive proof already present → complete land CAS (dual-write recovery)
 * - anything else → remain NEEDS_ATTENTION (optionally stage INDETERMINATE proof progress)
 *
 * Never releases the source lease. Never transitions to REJECTED/EXPIRED.
 * An attempted terminal-close while classification is not a positive land is REFUSED_CLOSE.
 * Never treats UNIQUE/positive proof alone as EXTERNAL_SEND_LANDED.
 */
export async function applyLateLandingCycle(
  input: LateLandingCycleInput,
  deps: ApplyLateLandingDeps,
  options?: { readonly attemptTerminalClose?: boolean },
): Promise<LateLandingApplyOutcome> {
  const nowMs = input.nowMs ?? deps.clock?.() ?? Date.now();
  const existing = await deps.proofStore.loadAttempt1(input.facts.operationId);
  // Positive proof without EXTERNAL_SEND_LANDED is a dual-write recovery window:
  // complete the land CAS. ALREADY_LANDED only when commit reports already landed.
  if (
    existing !== null &&
    (existing.landingProof.verdict === "LANDED_EXACT" ||
      existing.landingProof.verdict === "LANDED_COMPLETE_PATH")
  ) {
    return completeLandFromPositiveProof(input, existing, deps.landingStore, nowMs);
  }

  const classification = await classifyLateLandingCycle(input);

  if (options?.attemptTerminalClose === true) {
    // Closure gate: only a positive land may proceed past attention; incomplete stays open.
    if (classification.kind !== "LANDED_VERIFIED") {
      return {
        kind: "REFUSED_CLOSE",
        detail:
          "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED refused: classification is not a complete verified path (INDETERMINATE/WAITING/breach)",
        classification,
        sourceLeaseStillHeld: true,
      };
    }
  }

  if (classification.kind !== "LANDED_VERIFIED") {
    const progress =
      classification.kind === "INDETERMINATE"
        ? emptyIndeterminateProgress(input.facts, classification.reason, nowMs)
        : null;
    if (progress !== null) {
      // Resume-friendly: keep prior positive-safe progress id if one was already staged.
      const prior = existing;
      const toSave =
        prior !== null && prior.landingProof.verdict === "INDETERMINATE"
          ? {
              ...progress,
              landingProof: {
                ...progress.landingProof,
                id: prior.landingProof.id,
                createdAtMs: prior.landingProof.createdAtMs,
              },
            }
          : progress;
      await deps.proofStore.saveIndeterminateProgress(toSave);
      return {
        kind: "REMAIN_ATTENTION",
        classification,
        sourceLeaseStillHeld: true,
        proofProgress: toSave,
      };
    }
    return {
      kind: "REMAIN_ATTENTION",
      classification,
      sourceLeaseStillHeld: true,
      proofProgress: existing,
    };
  }

  // Positive land: build complete path (bodies 0..n) then commit landing.
  // permanent accepted proof requires every body present (path assembly).
  const path = classification.sourcePath;
  const landingProofId = existing?.landingProof.id ?? randomUUID();
  const pathProofId = randomUUID();
  const expectedSha = path.expectedBodySha256;
  const bodyCount = path.depth + 1;
  const verdict: LineageProofVerdict = path.kind;

  // Prefer walk staging produced during classify; else rebuild from successorBodies.
  // classify currently discards StagingLineagePathProofStore after minting the
  // observation — re-run a local stage when retained walk inputs are still present,
  // otherwise assemble from the oracle's successorBodies (same evidence classify used).
  let staged: { proof: LineagePathProofRow; bodies: readonly LineagePathBodyRow[] } | null =
    null;
  if (
    path.depth >= 1 &&
    input.retainedSource !== undefined &&
    input.expectedRetainedBody !== undefined &&
    input.baseline !== undefined &&
    input.readFreshHead !== undefined
  ) {
    const staging = new StagingLineagePathProofStore();
    const walk = await walkAncestryPath(
      {
        pathProofId,
        landingProofId,
        walletId: input.facts.sourceWalletId,
        walletPublicKey: input.facts.sourcePubkey,
        operation: {
          kind: "SEND_EXTERNAL",
          amountZkz: input.facts.amountZkz,
          sourcePubkey: input.facts.sourcePubkey,
          destinationAddress: input.facts.destinationAddress,
        } satisfies WalkOperation,
        expectedBody: input.expectedRetainedBody,
        baseline: input.baseline,
        maxPathDepth: input.maxDepth,
      },
      input.retainedSource,
      input.readFreshHead,
      staging,
    );
    if (walk.kind === "PATH_PROVEN" && staging.last !== null) {
      staged = staging.last;
    }
  }

  const assembled = assembleCompletePathBodies({
    pathProofId,
    pathDepth: path.depth,
    sourcePubkey: input.facts.sourcePubkey,
    expectedBody: input.facts.expectedBody,
    expectedBodyText: input.facts.expectedBodyText,
    successorBodies: input.successorBodies ?? [],
    staged,
  });

  if (assembled === null || assembled.bodies.length !== bodyCount) {
    // Oracle said land but durable complete-path assembly failed — remain attention.
    // Never write a false partial permanent proof.
    const progress = emptyIndeterminateProgress(
      input.facts,
      {
        source: "LANDING_PROOF_INCOMPLETE",
        fault: "MISSING_BODY",
      },
      nowMs,
    );
    const prior = existing;
    const toSave =
      prior !== null && prior.landingProof.verdict === "INDETERMINATE"
        ? {
            ...progress,
            landingProof: {
              ...progress.landingProof,
              id: prior.landingProof.id,
              createdAtMs: prior.landingProof.createdAtMs,
            },
          }
        : progress;
    await deps.proofStore.saveIndeterminateProgress(toSave);
    return {
      kind: "REMAIN_ATTENTION",
      classification: {
        kind: "INDETERMINATE",
        sendAttemptId: input.facts.sendAttemptId,
        reason: {
          source: "LANDING_PROOF_INCOMPLETE",
          fault: "MISSING_BODY",
        },
      },
      sourceLeaseStillHeld: true,
      proofProgress: toSave,
    };
  }

  const { bodies, freshHeadSha256, totalBytes } = assembled;
  // depth≥1: terminal head digest must be the last body, not expectedSha tautology.
  if (path.depth >= 1 && freshHeadSha256 === expectedSha) {
    const progress = emptyIndeterminateProgress(
      input.facts,
      {
        source: "LANDING_PROOF_INCOMPLETE",
        fault: "ANOMALOUS_OR_CONTRADICTORY",
      },
      nowMs,
    );
    await deps.proofStore.saveIndeterminateProgress(progress);
    return {
      kind: "REMAIN_ATTENTION",
      classification: {
        kind: "INDETERMINATE",
        sendAttemptId: input.facts.sendAttemptId,
        reason: {
          source: "LANDING_PROOF_INCOMPLETE",
          fault: "ANOMALOUS_OR_CONTRADICTORY",
        },
      },
      sourceLeaseStillHeld: true,
      proofProgress: progress,
    };
  }

  const manifest = buildLandingProofManifest({
    operationId: input.facts.operationId,
    expectedBodySha256: expectedSha,
    verdict,
    bodyCount,
    totalBytes,
    pathProofId,
  });

  const pathProof: LineagePathProofRow = {
    id: pathProofId,
    landing_proof_id: landingProofId,
    path_role: "SOURCE",
    wallet_id: input.facts.sourceWalletId,
    wallet_public_key: input.facts.sourcePubkey,
    t0_observation_id:
      input.facts.landingEvidenceBase.sourceT0.observationId,
    fresh_head_observation_id: path.freshHeadObservationId,
    expected_completed_transaction_sha256: expectedSha,
    fresh_head_completed_transaction_sha256: freshHeadSha256,
    body_count: bodyCount,
    path_depth: path.depth,
  };

  const progress: LateLandingProofProgress = {
    landingProof: {
      id: landingProofId,
      operationId: input.facts.operationId,
      verifierObserverId: input.facts.verifierObserverId,
      expectedTransactionAttemptNo: 1,
      verdict,
      requiredPathCount: 1,
      declaredBodyCount: bodyCount,
      declaredTotalBodyBytes: totalBytes,
      proofManifestText: manifest.text,
      proofManifestSha256: manifest.sha256,
      verifiedAtMs: nowMs,
      createdAtMs: existing?.landingProof.createdAtMs ?? nowMs,
    },
    pathProof,
    bodies,
  };

  const saved = await deps.proofStore.savePositiveProof(progress);
  if (saved.kind === "ALREADY_POSITIVE") {
    // UNIQUE hit: another cycle (or prior crash) already wrote the positive row.
    // Reload durable progress and finish the land — UNIQUE alone is not "landed".
    const durable =
      (await deps.proofStore.loadAttempt1(input.facts.operationId)) ?? progress;
    return completeLandFromPositiveProof(input, durable, deps.landingStore, nowMs);
  }

  if (deps.pathProofStore !== undefined) {
    await deps.pathProofStore.writePathProof(pathProof, bodies);
  }

  const commit = await commitExternalSendLanding(
    classification.landingVerdict,
    deps.landingStore,
    { landedAtMs: nowMs },
  );

  if (commit.outcome === "APPLIED") {
    return {
      kind: "LANDED",
      classification,
      commit,
      proofProgress: progress,
      sourceLeaseStillHeld: true,
    };
  }

  if (commit.outcome === "CONFLICT" && commit.reason === "ALREADY_LANDED") {
    return {
      kind: "ALREADY_LANDED",
      sourceLeaseStillHeld: true,
      existingLandingProofId: landingProofId,
    };
  }

  // Commit refused after positive proof — keep attention, lease held. Do not release.
  return {
    kind: "REMAIN_ATTENTION",
    classification: {
      kind: "INDETERMINATE",
      sendAttemptId: input.facts.sendAttemptId,
      reason: {
        source: "RELEASE_PREDICATE_UNSATISFIED",
        predicate: `landing_commit_${commit.outcome}`,
      },
    },
    sourceLeaseStillHeld: true,
    proofProgress: progress,
  };
}

/**
 * Map a late-landing classification onto the attention diagnostic vocabulary.
 * Terminal close is never authorized from INDETERMINATE/WAITING.
 */
export function lateLandingAttentionReason(
  classification: Exclude<LateLandingClassification, { kind: "LANDED_VERIFIED" }>,
) {
  switch (classification.kind) {
    case "INDETERMINATE":
      return toAttentionReason(classification.reason);
    case "INVARIANT_BREACH":
      return toAttentionReason(classification.reason);
    case "WAITING":
      return toAttentionReason({ source: "NO_SUCCESSOR_OBSERVED" });
    default:
      return assertUnreachable(classification);
  }
}

/** True when a closure gate elsewhere must refuse (not a positive land). */
export function refusesTerminalClose(classification: LateLandingClassification): boolean {
  return classification.kind !== "LANDED_VERIFIED";
}

// Re-export observation helpers so tests compose without reaching into verifier internals.
export { landingProofToPathObservation, proveSendLanding };
export type { FreshHeadRead, ReadFreshHead };
