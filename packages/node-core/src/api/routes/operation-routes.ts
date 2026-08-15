// Operation route handlers for the three Layer-1 operation types.
// 5.1–5.2, 6.1–6.2.

import type { OperationKind, VerificationMode } from "@zucoins/generic-node-contracts/operations";
import type { ExecutionPhase } from "../../core/execution-phase.js";
import type { PipelineContext } from "../pipeline.js";
import {
  apiErrorResponse,
  isAssignCapacityReason,
  type ApiErrorResponse,
  type AssignCapacityReason,
} from "../error-envelope.js";
import { MoveAdmissionError } from "../../move/create.js";
import { PushSubscriptionRequiredError } from "../../push/subscription-service.js";

export interface OperationObject {
  readonly operation_id: string;
  readonly operation_type: OperationKind;
  readonly state: string;
  readonly amount_zkz: string;
  readonly row_version: number;
  readonly attention_required: boolean;
  readonly attention_reason: string | null;
  readonly created_at: string;
  readonly updated_at: string;
  readonly terminal_at: string | null;
  readonly verification_material_available_until: string | null;
  /** Immutable after admission (ZTR-1301). */
  readonly verification_mode: VerificationMode;
}

export interface ExpectedArtifact {
  readonly key_id: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly signature: string;
}

export interface ReceiveResponse {
  readonly operation: OperationObject;
  readonly receiver_pubkey: string | null;
  readonly discriminator: string;
  readonly expires_at: string | null;
  readonly after_landing: { readonly kind: "HOLD" | "INTERNAL_MOVE"; readonly destination_id: string | null };
  readonly code_status: string;
  readonly transfer_code: string | null;
  readonly expected_artifact: ExpectedArtifact | null;
  readonly t0: { readonly observation_id: string; readonly projection: { readonly s: string; readonly p: string; readonly b_zkz: string } } | null;
  /**
   * One-time `sh_…` plaintext on create (201/202) and idempotent replay of that
   * create body. Point GET strips this field. Never null on a successful create.
   */
  readonly subscription_handle: string;
}

export interface InternalMoveResponse {
  readonly operation: OperationObject;
  readonly source_wallet_id: string;
  readonly destination_id: string;
  readonly spawned_from_operation_id: string | null;
  readonly lease_status: string;
  readonly execution_phase: ExecutionPhase;
  readonly expected_artifact: ExpectedArtifact | null;
  readonly source_terminal_observation_id: string | null;
  readonly destination_terminal_observation_id: string | null;
}

export interface ExternalSendResponse {
  readonly operation: OperationObject;
  readonly source_wallet_id: string;
  readonly destination_address: string;
  readonly references_operation_id: string | null;
  readonly approval_status: string;
  readonly transfer_code: string | null;
  readonly transfer_code_sha256: string | null;
  readonly available_until: string | null;
  readonly expected_artifact: ExpectedArtifact | null;
}

export type RouteHandlerResult =
  | { readonly ok: true; readonly status: number; readonly body: string; readonly headers?: Readonly<Record<string, string>> }
  | { readonly ok: false; readonly error: ApiErrorResponse };

// a completed-mutation idempotent replay returns the stored status and body bytes
// unchanged with `Idempotency-Replayed: true`. The success RouteHandlerResult variant
// carries that header (the error variant already carries headers via ApiErrorResponse).
// Route-layer detection lives in the store, which owns the idempotency record written in
// the same transaction as the mutation; the pre-handler pipeline short-circuit (stage 4
// enforce_idempotency) is.
const IDEMPOTENT_REPLAY_HEADERS: Readonly<Record<string, string>> = { "Idempotency-Replayed": "true" };

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

export interface CreateReceiveInput {
  readonly amount_zkz: string;
  readonly anchor: string;
  readonly expires_in_seconds?: number;
  readonly after_landing: { readonly kind: "HOLD" | "INTERNAL_MOVE"; readonly destination_id: string | null };
  /** Optional; Zod defaults omitted field to INDEPENDENT before the handler. */
  readonly verification_mode?: VerificationMode;
  readonly idempotencyKey: string;
  /** Credential-bound tenant — never accepted from the request body. */
  readonly implementerId: string;
}

export interface CreateInternalMoveInput {
  readonly source_wallet_id: string;
  readonly destination_id: string;
  readonly amount_zkz: string;
  /** Advisory product correlation only — unsigned, never a settlement match key. */
  readonly client_reference?: string;
  /** Optional; Zod defaults omitted field to INDEPENDENT before the handler. */
  readonly verification_mode?: VerificationMode;
  readonly idempotencyKey: string;
  /** Credential-bound tenant — never accepted from the request body. */
  readonly implementerId: string;
}

export interface CreateExternalSendInput {
  /**
   * Optional send-capable source. When omitted/undefined, the route store runs
   * assign-and-top-up composition (ZTR-1271 / ZTR-1270) before artifact bind.
   */
  readonly source_wallet_id?: string;
  readonly destination_address: string;
  readonly amount_zkz: string;
  readonly references_operation_id?: string;
  readonly client_reference?: string;
  readonly description?: string;
  /** Optional; Zod defaults omitted field to INDEPENDENT before the handler. */
  readonly verification_mode?: VerificationMode;
  readonly idempotencyKey: string;
  /** Credential-bound tenant — never accepted from the request body. */
  readonly implementerId: string;
}

/**
 * Tenant-scoped operation store. Every method takes the credential-bound
 * implementerId so unscoped gets do not typecheck.
 */
export interface OperationRouteStore {
  createReceive(input: CreateReceiveInput): Promise<{ status: 201 | 202; body: ReceiveResponse; idempotentReplay?: boolean }>;
  getReceive(operationId: string, implementerId: string): Promise<ReceiveResponse | null>;
  createInternalMove(input: CreateInternalMoveInput): Promise<{ status: 201; body: InternalMoveResponse; idempotentReplay?: boolean }>;
  getInternalMove(operationId: string, implementerId: string): Promise<InternalMoveResponse | null>;
  createExternalSend(input: CreateExternalSendInput): Promise<{ status: 201; body: ExternalSendResponse; idempotentReplay?: boolean }>;
  getExternalSend(operationId: string, implementerId: string): Promise<ExternalSendResponse | null>;
}

function requireImplementerId(
  ctx: PipelineContext,
): { ok: true; implementerId: string } | { ok: false; error: ApiErrorResponse } {
  const implementerId = ctx.principal?.implementerId ?? ctx.idempotencyTenantId;
  if (typeof implementerId !== "string" || implementerId.length === 0) {
    // Fail closed: tenant-scoped money path without a bound principal is not servable.
    return { ok: false, error: apiErrorResponse("invalid_api_key", ctx.requestId) };
  }
  return { ok: true, implementerId };
}

export async function handleCreateReceive(
  ctx: PipelineContext,
  store: OperationRouteStore,
): Promise<RouteHandlerResult> {
  const tenant = requireImplementerId(ctx);
  if (!tenant.ok) return tenant;
  const body = ctx.parsedBody as Omit<CreateReceiveInput, "idempotencyKey" | "implementerId">;
  const idempotencyKey = ctx.request.headers["idempotency-key"]!;
  try {
    return createSuccess(
      await store.createReceive({
        ...body,
        idempotencyKey,
        implementerId: tenant.implementerId,
      }),
    );
  } catch (err) {
    return mapStoreError(err, ctx.requestId);
  }
}

export async function handleGetReceive(
  ctx: PipelineContext,
  store: OperationRouteStore,
  operationId: string,
): Promise<RouteHandlerResult> {
  const tenant = requireImplementerId(ctx);
  if (!tenant.ok) return tenant;
  try {
    const result = await store.getReceive(operationId, tenant.implementerId);
    if (result === null) {
      return { ok: false, error: apiErrorResponse("not_found", ctx.requestId) };
    }
    // `subscription_handle` plaintext is returned only by the original idempotent
    // create response, never by point read. Strip it before serializing the point read.
    const { subscription_handle, ...pointRead } = result;
    return { ok: true, status: 200, body: JSON.stringify(pointRead) };
  } catch (err) {
    return mapStoreError(err, ctx.requestId);
  }
}

export async function handleCreateInternalMove(
  ctx: PipelineContext,
  store: OperationRouteStore,
): Promise<RouteHandlerResult> {
  const tenant = requireImplementerId(ctx);
  if (!tenant.ok) return tenant;
  const body = ctx.parsedBody as Omit<CreateInternalMoveInput, "idempotencyKey" | "implementerId">;
  const idempotencyKey = ctx.request.headers["idempotency-key"]!;
  try {
    return createSuccess(
      await store.createInternalMove({
        ...body,
        idempotencyKey,
        implementerId: tenant.implementerId,
      }),
    );
  } catch (err) {
    return mapStoreError(err, ctx.requestId);
  }
}

export async function handleGetInternalMove(
  ctx: PipelineContext,
  store: OperationRouteStore,
  operationId: string,
): Promise<RouteHandlerResult> {
  const tenant = requireImplementerId(ctx);
  if (!tenant.ok) return tenant;
  try {
    const result = await store.getInternalMove(operationId, tenant.implementerId);
    if (result === null) {
      return { ok: false, error: apiErrorResponse("not_found", ctx.requestId) };
    }
    return { ok: true, status: 200, body: JSON.stringify(result) };
  } catch (err) {
    return mapStoreError(err, ctx.requestId);
  }
}

export async function handleCreateExternalSend(
  ctx: PipelineContext,
  store: OperationRouteStore,
): Promise<RouteHandlerResult> {
  const tenant = requireImplementerId(ctx);
  if (!tenant.ok) return tenant;
  const body = ctx.parsedBody as Omit<CreateExternalSendInput, "idempotencyKey" | "implementerId">;
  const idempotencyKey = ctx.request.headers["idempotency-key"]!;
  try {
    return createSuccess(
      await store.createExternalSend({
        ...body,
        idempotencyKey,
        implementerId: tenant.implementerId,
      }),
    );
  } catch (err) {
    return mapStoreError(err, ctx.requestId);
  }
}

export async function handleGetExternalSend(
  ctx: PipelineContext,
  store: OperationRouteStore,
  operationId: string,
): Promise<RouteHandlerResult> {
  const tenant = requireImplementerId(ctx);
  if (!tenant.ok) return tenant;
  try {
    const result = await store.getExternalSend(operationId, tenant.implementerId);
    if (result === null) {
      return { ok: false, error: apiErrorResponse("not_found", ctx.requestId) };
    }
    return { ok: true, status: 200, body: JSON.stringify(result) };
  } catch (err) {
    return mapStoreError(err, ctx.requestId);
  }
}

export class WalletBusyError extends Error {
  constructor() { super("wallet_busy"); this.name = "WalletBusyError"; }
}

export class ReceiveQueueFullError extends Error {
  readonly retryAfterSeconds: number;
  constructor(retryAfterSeconds = 30) {
    super("receive_queue_full");
    this.name = "ReceiveQueueFullError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class IdempotencyConflictError extends Error {
  constructor() { super("idempotency_conflict"); this.name = "IdempotencyConflictError"; }
}

// rule 2 — same key, different request hash.
export class IdempotencyKeyReusedError extends Error {
  constructor() {
    super("idempotency_key_reused");
    this.name = "IdempotencyKeyReusedError";
  }
}

// rule 3 — concurrent first use; followers get Retry-After.
export class IdempotencyInProgressError extends Error {
  readonly retryAfterSeconds: number;
  constructor(retryAfterSeconds = 1) {
    super("idempotency_in_progress");
    this.name = "IdempotencyInProgressError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** RECEIVE_EXTERNAL admission rejections (adapter). Codes mirror admission.ts. */
export class ReceiveAdmissionError extends Error {
  readonly code: string;
  readonly detail?: string;
  readonly retryAfterSeconds?: number;
  constructor(code: string, detail?: string, retryAfterSeconds?: number) {
    super(code);
    this.name = "ReceiveAdmissionError";
    this.code = code;
    this.detail = detail;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** SEND_EXTERNAL create rejections (adapter). Codes mirror send/create.ts. */
export class SendAdmissionError extends Error {
  readonly code: string;
  readonly detail?: string;
  readonly retryAfterSeconds?: number;
  constructor(code: string, detail?: string, retryAfterSeconds?: number) {
    super(code);
    this.name = "SendAdmissionError";
    this.code = code;
    this.detail = detail;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

function mapWithRetryAfter(
  code: Parameters<typeof apiErrorResponse>[0],
  requestId: string,
  retryAfterSeconds: number,
): RouteHandlerResult {
  return {
    ok: false,
    error: apiErrorResponse(code, requestId, undefined, retryAfterSeconds),
  };
}

function mapIdempotencyInProgress(
  requestId: string,
  retryAfterSeconds: number | undefined,
): RouteHandlerResult {
  return mapWithRetryAfter("idempotency_in_progress", requestId, retryAfterSeconds ?? 1);
}

function mapAssignCapacityUnavailable(
  requestId: string,
  reason: AssignCapacityReason,
): RouteHandlerResult {
  return {
    ok: false,
    error: apiErrorResponse("service_unavailable", requestId, undefined, undefined, {
      reason,
    }),
  };
}

function mapReceiveQueueFull(
  requestId: string,
  retryAfterSeconds: number | undefined,
): RouteHandlerResult {
  return mapWithRetryAfter("receive_queue_full", requestId, retryAfterSeconds ?? 30);
}

function mapStoreError(err: unknown, requestId: string): RouteHandlerResult {
  if (err instanceof WalletBusyError) {
    return { ok: false, error: apiErrorResponse("wallet_busy", requestId) };
  }
  if (err instanceof ReceiveQueueFullError) {
    return mapReceiveQueueFull(requestId, err.retryAfterSeconds);
  }
  if (err instanceof IdempotencyKeyReusedError) {
    return { ok: false, error: apiErrorResponse("idempotency_key_reused", requestId) };
  }
  if (err instanceof IdempotencyInProgressError) {
    return mapIdempotencyInProgress(requestId, err.retryAfterSeconds);
  }
  if (err instanceof IdempotencyConflictError) {
    return { ok: false, error: apiErrorResponse("idempotency_conflict", requestId) };
  }
  // MOVE_INTERNAL admission rejections. Map onto the frozen API taxonomy:
  // wallet_busy / idempotency codes stay 409; eligibility/validation → 422 protocol
  // predicate or 400 invalid_scalar.
  if (err instanceof MoveAdmissionError) {
    switch (err.code) {
      case "wallet_busy":
        return { ok: false, error: apiErrorResponse("wallet_busy", requestId) };
      case "idempotency_key_reused":
        return { ok: false, error: apiErrorResponse("idempotency_key_reused", requestId) };
      case "idempotency_in_progress":
        return mapIdempotencyInProgress(requestId, err.retryAfterSeconds);
      case "missing_idempotency_key":
      case "invalid_tenant_id":
      case "invalid_source_wallet_id":
      case "invalid_destination_id":
      case "invalid_amount":
      case "invalid_spawned_from_operation_id":
        return { ok: false, error: apiErrorResponse("invalid_scalar", requestId) };
      case "source_wallet_not_found":
      case "destination_not_found":
      case "source_wallet_not_eligible":
      case "destination_not_eligible":
      case "same_wallet":
        return { ok: false, error: apiErrorResponse("protocol_predicate_failed", requestId) };
      case "verification_mode_not_allowed":
        return {
          ok: false,
          error: apiErrorResponse("verification_mode_not_allowed", requestId),
        };
      default:
        return { ok: false, error: apiErrorResponse("service_unavailable", requestId) };
    }
  }
  if (err instanceof ReceiveAdmissionError) {
    switch (err.code) {
      case "wallet_in_flight":
        return { ok: false, error: apiErrorResponse("wallet_busy", requestId) };
      case "idempotency_key_reused":
        return { ok: false, error: apiErrorResponse("idempotency_key_reused", requestId) };
      case "idempotency_in_progress":
        return mapIdempotencyInProgress(requestId, err.retryAfterSeconds);
      case "receive_queue_full":
        return mapReceiveQueueFull(requestId, err.retryAfterSeconds);
      case "destination_not_found":
        return { ok: false, error: apiErrorResponse("not_found", requestId) };
      case "destination_not_eligible":
        return { ok: false, error: apiErrorResponse("protocol_predicate_failed", requestId) };
      case "missing_idempotency_key":
      case "invalid_amount":
      case "invalid_anchor":
      case "invalid_ttl":
      case "invalid_after_landing":
        return { ok: false, error: apiErrorResponse("invalid_scalar", requestId) };
      case "verification_mode_not_allowed":
        return {
          ok: false,
          error: apiErrorResponse("verification_mode_not_allowed", requestId),
        };
      default:
        return { ok: false, error: apiErrorResponse("service_unavailable", requestId) };
    }
  }
  if (err instanceof SendAdmissionError) {
    switch (err.code) {
      case "wallet_in_flight":
        return { ok: false, error: apiErrorResponse("wallet_busy", requestId) };
      case "idempotency_key_reused":
        return { ok: false, error: apiErrorResponse("idempotency_key_reused", requestId) };
      case "idempotency_in_progress":
        return mapIdempotencyInProgress(requestId, err.retryAfterSeconds);
      case "missing_idempotency_key":
      case "invalid_tenant_id":
      case "invalid_source_wallet_id":
      case "invalid_destination_address":
      case "invalid_amount":
      case "invalid_references_operation_id":
        return { ok: false, error: apiErrorResponse("invalid_scalar", requestId) };
      case "source_wallet_not_found":
        return { ok: false, error: apiErrorResponse("not_found", requestId) };
      case "source_wallet_not_eligible":
      case "destination_is_internal":
        return { ok: false, error: apiErrorResponse("protocol_predicate_failed", requestId) };
      case "verification_mode_not_allowed":
        return {
          ok: false,
          error: apiErrorResponse("verification_mode_not_allowed", requestId),
        };
      case "signing_key_unavailable":
        return { ok: false, error: apiErrorResponse("service_unavailable", requestId) };
      // ZTR-1271 assign / top-up composition codes (SendAssignRejectionCode).
      // Documented HTTP map: busy → 409; liquidity/worker absence → 503; predicates → 422;
      // halt / wiring → 503; nested validation → 400 / 422 via cause when present.
      // ZTR-1289: dry / ineligible funding wallet W → insufficient_funding_wallet (422).
      case "hub_busy":
        return { ok: false, error: apiErrorResponse("wallet_busy", requestId) };
      case "insufficient_funding_wallet":
        return {
          ok: false,
          error: apiErrorResponse("insufficient_funding_wallet", requestId),
        };
      case "no_free_send_worker":
      case "no_hub_liquidity":
      case "worker_destination_missing":
      case "halted":
      case "assign_not_wired":
      case "move_rejected":
        // ZTR-1309: keep 503 service_unavailable; put the assign rejection in details.reason
        // so integrators can map no_free_send_worker → GENERIC_NODE_NO_SEND_WALLET.
        if (!isAssignCapacityReason(err.code)) {
          return { ok: false, error: apiErrorResponse("service_unavailable", requestId) };
        }
        return mapAssignCapacityUnavailable(requestId, err.code);
      case "send_rejected": {
        // Nested create codes may appear in detail / as code suffix.
        const nested = err.detail ?? "";
        if (nested === "source_wallet_not_found") {
          return { ok: false, error: apiErrorResponse("not_found", requestId) };
        }
        if (
          nested === "allow_external_send=false" ||
          nested === "source_wallet_not_eligible" ||
          nested.includes("allow_external_send")
        ) {
          return { ok: false, error: apiErrorResponse("protocol_predicate_failed", requestId) };
        }
        if (nested === "invalid_source_wallet_id" || nested === "invalid_amount") {
          return { ok: false, error: apiErrorResponse("invalid_scalar", requestId) };
        }
        if (nested === "idempotency_key_reused") {
          return { ok: false, error: apiErrorResponse("idempotency_key_reused", requestId) };
        }
        if (nested === "idempotency_in_progress") {
          return mapIdempotencyInProgress(requestId, err.retryAfterSeconds);
        }
        if (nested === "wallet_in_flight") {
          return { ok: false, error: apiErrorResponse("wallet_busy", requestId) };
        }
        if (nested === "destination_is_internal") {
          return { ok: false, error: apiErrorResponse("protocol_predicate_failed", requestId) };
        }
        return { ok: false, error: apiErrorResponse("protocol_predicate_failed", requestId) };
      }
      default:
        return { ok: false, error: apiErrorResponse("service_unavailable", requestId) };
    }
  }
  // the always-subscribed invariant. An EXTERNAL operation whose wallet lacks
  // an ACTIVE push subscription is refused as a protocol predicate failure (422).
  if (err instanceof PushSubscriptionRequiredError) {
    return { ok: false, error: apiErrorResponse("protocol_predicate_failed", requestId) };
  }
  return { ok: false, error: apiErrorResponse("service_unavailable", requestId) };
}
