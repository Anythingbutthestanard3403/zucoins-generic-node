// Operation action routes: arm, verification-complete, and
// verification-material. No generic mutate-state endpoint lives here.
//
// 9.2, 10.1
// three public money operations (operation neutrality),
// (incomplete path → INDETERMINATE only, never a landing classification).
//
// Vocabulary: consume OPERATION_KINDS / OPERATION_STATUS from
// @zucoins/generic-node-contracts — never redeclare Layer-1 states.
// Approve/reject for SEND_EXTERNAL is the admin surface under;
// this slice owns no approve/reject/sign/cancel implementer routes.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";
import { OPERATION_KINDS } from "@zucoins/generic-node-contracts/operations";

import type { PipelineContext } from "../pipeline.js";
import { apiErrorResponse, type ApiErrorResponse } from "../error-envelope.js";
import type { ExpectedArtifact, RouteHandlerResult } from "./operation-routes.js";
import { IdempotencyConflictError } from "./operation-routes.js";

// a completed-mutation idempotent replay returns the stored status and body bytes
// unchanged with `Idempotency-Replayed: true`. Same contract as create routes.
const IDEMPOTENT_REPLAY_HEADERS: Readonly<Record<string, string>> = {
  "Idempotency-Replayed": "true",
};

function createSuccess(result: {
  readonly status: number;
  readonly body: unknown;
  readonly idempotentReplay?: boolean;
}): RouteHandlerResult {
  const body = JSON.stringify(result.body);
  return result.idempotentReplay
    ? { ok: true, status: result.status, body, headers: IDEMPOTENT_REPLAY_HEADERS }
    : { ok: true, status: result.status, body };
}

// --- Wire shapes --

export interface T0ProjectionWire {
  readonly s: string;
  readonly p: string;
  readonly b_zkz: string;
}

export interface T0EvidenceWire {
  readonly observation_id: string;
  readonly projection: T0ProjectionWire;
}

export interface ArmInput {
  readonly expected_row_version: number;
  readonly t0: T0EvidenceWire;
  readonly opened_cursor: string;
  readonly idempotencyKey: string;
}

export interface ArmSuccessResponse {
  readonly operation_id: string;
  readonly state: "READY";
  readonly row_version: number;
  readonly code_status: "RELEASED";
  readonly transfer_code: string;
  readonly transfer_code_sha256: string;
  readonly expires_at: string;
}

export type VerificationVerdict = "VERIFIED" | "REJECTED" | "INDETERMINATE";

export type LeaseReleaseStatus =
  | "RELEASED"
  | "PINNED_GROUP_PENDING"
  | "PINNED_FOR_ATTENTION";

export interface LandingProofWire {
  readonly classification: "EXPECTED_AT_HEAD" | "EXPECTED_ANCESTOR";
  readonly fresh_head_step_2_signature: string;
  readonly fresh_head_transaction_sha256: string;
  readonly path_manifest_sha256: string;
}

export interface WalletEvidenceWire {
  readonly wallet_id: string;
  readonly role: "RECEIVER" | "SOURCE" | "DESTINATION";
  readonly t0: T0EvidenceWire;
  readonly terminal: T0EvidenceWire;
  readonly landing_proof: LandingProofWire;
}

export interface VerificationCompleteInput {
  readonly expected_row_version: number;
  readonly consumed_cursor: string;
  readonly verdict: VerificationVerdict;
  readonly wallet_evidence: readonly WalletEvidenceWire[];
  readonly idempotencyKey: string;
}

export interface VerificationCompleteSuccessResponse {
  readonly operation_id: string;
  readonly acknowledgement_id: string;
  readonly verdict: VerificationVerdict;
  readonly lease_release_status: LeaseReleaseStatus;
  readonly acknowledged_at: string;
}

export type IndeterminateReason =
  | "MISSING_BODY"
  | "LINK_GAP"
  | "ANOMALY"
  | "FRESH_HEAD_MISMATCH"
  | "BUDGET_EXCEEDED";

export type AncestorProofClassification =
  | "EXPECTED_AT_HEAD"
  | "EXPECTED_ANCESTOR"
  | "INDETERMINATE";

export interface PathManifestEntry {
  readonly position: number;
  readonly step_2_signature: string;
  readonly queried_wallet_previous_signature: string;
  readonly transaction_sha256: string;
  readonly body_index: number;
}

export interface TransactionBodyEntry {
  readonly body_index: number;
  readonly transaction_sha256: string;
  readonly settled_transaction_text: string;
}

// evidence_role closed set — identical tokens to observation/verification
// EVIDENCE_ROLES. material.test.ts locks the two surfaces together.
export const ACTION_EVIDENCE_ROLES = [
  "RECEIVER",
  "SOURCE",
  "DESTINATION",
  "EXTERNAL_SENDER_PREFLIGHT",
  "EXTERNAL_DESTINATION_PARTIAL",
] as const;
export type ActionEvidenceRole = (typeof ACTION_EVIDENCE_ROLES)[number];

export interface AncestorProof {
  readonly evidence_role: ActionEvidenceRole;
  readonly wallet_public_key: string;
  readonly classification: AncestorProofClassification;
  readonly expected_step_2_signature: string;
  readonly fresh_head_step_2_signature: string;
  readonly fresh_head_transaction_sha256: string;
  readonly hop_count: number;
  readonly path_manifest_sha256: string;
  readonly path_manifest: readonly PathManifestEntry[];
  readonly transaction_bodies: readonly TransactionBodyEntry[];
  readonly indeterminate_reason: IndeterminateReason | null;
}

export interface ObservationEvidence {
  readonly evidence_role: ActionEvidenceRole;
  readonly wallet_id: string | null;
  readonly wallet_public_key: string;
  readonly t0: T0EvidenceWire;
  readonly terminal: T0EvidenceWire | null;
  readonly node_observation_raw_body_base64: string;
}

export interface AttemptTransaction {
  readonly inner_preimage_text: string;
  readonly inner_sha256: string;
  readonly step_1_signature: string;
  readonly step_2_preimage_text: string;
  readonly step_2_signature: string;
  readonly settled_transaction_text: string;
}

export interface AttemptEntry {
  readonly attempt_no: number;
  readonly classification: string;
  readonly transaction: AttemptTransaction;
}

// Wire shape for material (documentation / store composition). The live GET
// transport is api/verification-material.ts (gated 409/200/410) — not a twin here.
// landed_attempt_no is null when unavailable ("Unavailable terminal fields are null").
export interface VerificationMaterialResponse {
  readonly operation_id: string;
  readonly operation_type: OperationKind;
  readonly state: string;
  readonly landed_attempt_no: number | null;
  readonly expected_artifact: ExpectedArtifact;
  readonly observation_evidence: readonly ObservationEvidence[];
  readonly attempts: readonly AttemptEntry[];
  readonly ancestor_proofs: readonly AncestorProof[];
  readonly available_until: string;
}

// --- Store port --
// Persistence owns the CAS write, durable T0 compare, code release, ack commit,
// and lease decision. Handlers map typed failures to the frozen error taxonomy.
//
// GET verification-material is NOT on this port. The gated transport
// (api/verification-material.ts handleGetVerificationMaterial + VerificationMaterialSource)
// owns 409/200/410; a store passthrough twin was retired.

export interface ActionRouteStore {
  arm(
    operationId: string,
    input: ArmInput,
  ): Promise<{ status: 200; body: ArmSuccessResponse; idempotentReplay?: boolean }>;
  verificationComplete(
    operationId: string,
    input: VerificationCompleteInput,
  ): Promise<{
    status: 200;
    body: VerificationCompleteSuccessResponse;
    idempotentReplay?: boolean;
  }>;
}

// --- Typed store errors (HTTP mapping is the only layer that knows status codes) --

export class OperationVersionConflictError extends Error {
  constructor() {
    super("operation_version_conflict");
    this.name = "OperationVersionConflictError";
  }
}

export class T0MismatchError extends Error {
  readonly field: string;
  constructor(field: string) {
    super("t0_mismatch");
    this.name = "T0MismatchError";
    this.field = field;
  }
}

export class OperationNotArmableError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super("operation_not_armable");
    this.name = "OperationNotArmableError";
    this.reason = reason;
  }
}

export class VerificationMaterialNotReadyError extends Error {
  constructor() {
    super("verification_material_not_ready");
    this.name = "VerificationMaterialNotReadyError";
  }
}

export class VerificationMaterialExpiredError extends Error {
  constructor() {
    super("verification_material_expired");
    this.name = "VerificationMaterialExpiredError";
  }
}

export class ProtocolPredicateFailedError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super("protocol_predicate_failed");
    this.name = "ProtocolPredicateFailedError";
    this.reason = reason;
  }
}

// --- Pure predicates (stores and tests share these; no side effects) --

/** Field names mirror the wire projection keys that compares against durable T0. */
export type T0MismatchField =
  | "observation_id"
  | "s"
  | "p"
  | "b_zkz";

/**
 * "The node compares all fields with its durable T0."
 * Returns the first mismatched field, or null when all fields agree.
 * A mismatch path must not mutate T0 or release the transfer code.
 */
export function compareT0Evidence(
  durable: T0EvidenceWire,
  supplied: T0EvidenceWire,
): T0MismatchField | null {
  if (supplied.observation_id !== durable.observation_id) return "observation_id";
  if (supplied.projection.s !== durable.projection.s) return "s";
  if (supplied.projection.p !== durable.projection.p) return "p";
  if (supplied.projection.b_zkz !== durable.projection.b_zkz) return "b_zkz";
  return null;
}

/**
 * "Acknowledging REJECTED or INDETERMINATE never silently releases a wallet."
 * VERIFIED may release (or pin when a multi-wallet group is still pending — that
 * distinction is store-owned). Non-VERIFIED verdicts are forced to pin.
 */
export function leaseReleaseStatusForVerdict(
  verdict: VerificationVerdict,
  storePreference: LeaseReleaseStatus = "RELEASED",
): LeaseReleaseStatus {
  if (verdict !== "VERIFIED") {
    return storePreference === "PINNED_GROUP_PENDING"
      ? "PINNED_GROUP_PENDING"
      : "PINNED_FOR_ATTENTION";
  }
  return storePreference;
}

export interface AncestorProofCompletenessFlags {
  readonly missingBody: boolean;
  readonly linkGap: boolean;
  readonly anomaly: boolean;
  readonly freshHeadMismatch: boolean;
  readonly budgetExceeded: boolean;
  /** Positive landing classification the caller would assert if complete. */
  readonly intendedClassification: "EXPECTED_AT_HEAD" | "EXPECTED_ANCESTOR";
}

/**
 * landing-path oracle / an incomplete or anomalous path cannot establish landing. Force
 * `INDETERMINATE` with the first matching reason; never emit a landing classification
 * when any completeness flag is set.
 */
export function classifyAncestorProof(
  flags: AncestorProofCompletenessFlags,
): {
  readonly classification: AncestorProofClassification;
  readonly indeterminate_reason: IndeterminateReason | null;
} {
  if (flags.missingBody) {
    return { classification: "INDETERMINATE", indeterminate_reason: "MISSING_BODY" };
  }
  if (flags.linkGap) {
    return { classification: "INDETERMINATE", indeterminate_reason: "LINK_GAP" };
  }
  if (flags.anomaly) {
    return { classification: "INDETERMINATE", indeterminate_reason: "ANOMALY" };
  }
  if (flags.freshHeadMismatch) {
    return { classification: "INDETERMINATE", indeterminate_reason: "FRESH_HEAD_MISMATCH" };
  }
  if (flags.budgetExceeded) {
    return { classification: "INDETERMINATE", indeterminate_reason: "BUDGET_EXCEEDED" };
  }
  return {
    classification: flags.intendedClassification,
    indeterminate_reason: null,
  };
}

/** Guard: only the three frozen operation kinds may appear on the material surface. */
export function isOperationKind(value: string): value is OperationKind {
  return (OPERATION_KINDS as readonly string[]).includes(value);
}

// --- Handlers --

export async function handleArm(
  ctx: PipelineContext,
  store: ActionRouteStore,
  operationId: string,
): Promise<RouteHandlerResult> {
  const body = ctx.parsedBody as Omit<ArmInput, "idempotencyKey">;
  const idempotencyKey = ctx.request.headers["idempotency-key"]!;
  try {
    return createSuccess(
      await store.arm(operationId, { ...body, idempotencyKey }),
    );
  } catch (err) {
    return mapActionStoreError(err, ctx.requestId);
  }
}

export async function handleVerificationComplete(
  ctx: PipelineContext,
  store: ActionRouteStore,
  operationId: string,
): Promise<RouteHandlerResult> {
  const body = ctx.parsedBody as Omit<VerificationCompleteInput, "idempotencyKey">;
  const idempotencyKey = ctx.request.headers["idempotency-key"]!;
  try {
    const result = await store.verificationComplete(operationId, {
      ...body,
      idempotencyKey,
    });
    // Defence in depth: never surface a silent release on a non-VERIFIED verdict.
    const safeBody: VerificationCompleteSuccessResponse = {
      ...result.body,
      lease_release_status: leaseReleaseStatusForVerdict(
        result.body.verdict,
        result.body.lease_release_status,
      ),
    };
    return createSuccess({
      status: result.status,
      body: safeBody,
      idempotentReplay: result.idempotentReplay,
    });
  } catch (err) {
    return mapActionStoreError(err, ctx.requestId);
  }
}

// handleGetVerificationMaterial intentionally lives ONLY in api/verification-material.ts
// (access gate). Do not reintroduce an ungated action-routes twin.

function mapActionStoreError(err: unknown, requestId: string): RouteHandlerResult {
  if (err instanceof OperationVersionConflictError) {
    return { ok: false, error: apiErrorResponse("operation_version_conflict", requestId) };
  }
  if (err instanceof T0MismatchError) {
    return { ok: false, error: apiErrorResponse("t0_mismatch", requestId) };
  }
  if (err instanceof OperationNotArmableError) {
    return { ok: false, error: apiErrorResponse("operation_not_armable", requestId) };
  }
  if (err instanceof VerificationMaterialNotReadyError) {
    return { ok: false, error: apiErrorResponse("verification_material_not_ready", requestId) };
  }
  if (err instanceof VerificationMaterialExpiredError) {
    return { ok: false, error: apiErrorResponse("verification_material_expired", requestId) };
  }
  if (err instanceof ProtocolPredicateFailedError) {
    return { ok: false, error: apiErrorResponse("protocol_predicate_failed", requestId) };
  }
  if (err instanceof IdempotencyConflictError) {
    return { ok: false, error: apiErrorResponse("idempotency_conflict", requestId) };
  }
  return { ok: false, error: apiErrorResponse("service_unavailable", requestId) };
}

// Re-export for callers that already import ApiErrorResponse through this module surface.
export type { ApiErrorResponse };
