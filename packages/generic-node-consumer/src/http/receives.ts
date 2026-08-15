/**
 * RECEIVE_EXTERNAL initiation. Implementer-bearer authenticated —
 * no signed reporting credential needed for these two routes.
 */

import type { ArtifactEnvelope } from "@zucoins/node-core/verifier/consumer";
import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

import { assertOk } from "./errors.js";
import { resolveFetch, resolveUrl, type NodeClientConfig } from "./client-types.js";
import type { VerificationMode } from "../verification-mode.js";

/** Common operation representation, embedded in every point read. */
export interface CommonOperationView {
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
  /** Immutable after admission; omitted on legacy bodies defaults to INDEPENDENT. */
  readonly verification_mode?: VerificationMode;
}

export type AfterLanding =
  | { readonly kind: "HOLD"; readonly destination_id: null }
  | { readonly kind: "INTERNAL_MOVE"; readonly destination_id: string };

export interface CreateReceiveRequest {
  readonly amount_zkz: string;
  /** Opaque to the node; must match ^[A-Za-z0-9_-]{1,96}$. */
  readonly anchor: string;
  readonly expires_in_seconds?: number;
  readonly after_landing: AfterLanding;
  /** Optional; omitted → INDEPENDENT. NODE_VERIFIED requires operator policy. */
  readonly verification_mode?: VerificationMode;
}

/** Shared by the 201/202 create response and the point read (transfer_code always null there). */
export interface ReceiveOperationView {
  readonly operation: CommonOperationView;
  readonly receiver_pubkey: string | null;
  readonly discriminator: string;
  readonly expires_at: string | null;
  readonly after_landing: AfterLanding;
  readonly code_status: "NOT_CREATED" | "AWAITING_ARM" | "RELEASED" | "EXPIRED";
  readonly transfer_code: string | null;
  readonly expected_artifact: ArtifactEnvelope | null;
  readonly t0: {
    readonly observation_id: string;
    readonly projection: { readonly s: string; readonly p: string; readonly b_zkz: string };
  } | null;
}

/** 201/202 create response — carries the one-time subscription handle. */
export interface CreateReceiveResponse extends ReceiveOperationView {
  readonly subscription_handle: string;
}

export interface CreateReceiveInput {
  readonly config: NodeClientConfig;
  /** `Bearer ik_…` implementer key, scoped `receive:create`. */
  readonly bearerKey: string;
  readonly request: CreateReceiveRequest;
  /**
   * Stable across every retry attempt of this logical mutation — callers must persist and
   * reuse the same value, never mint a fresh one per HTTP attempt.
   */
  readonly idempotencyKey: string;
}

/**
 * `POST /v1/receives`. Returns `201` (wallet assigned synchronously) or `202` (queued)
 * — both share the `ReceiveOperationView` shape; only `202` degrades the wallet-dependent
 * fields to `null`. A `503 receive_queue_full` and any other non-2xx surface as `NodeApiError`.
 */
export async function createReceive(input: CreateReceiveInput): Promise<CreateReceiveResponse> {
  const rawTarget = "/v1/receives";
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, rawTarget), {
    method: "POST",
    headers: {
      "content-type": "application/json; charset=utf-8",
      authorization: `Bearer ${input.bearerKey}`,
      "idempotency-key": input.idempotencyKey,
    },
    body: JSON.stringify(input.request),
  });
  await assertOk(response);
  return (await response.json()) as CreateReceiveResponse;
}

export interface GetReceiveInput {
  readonly config: NodeClientConfig;
  /** `Bearer ik_…` implementer key, scoped `receive:read`. */
  readonly bearerKey: string;
  readonly operationId: string;
}

/** `GET /v1/receives/:operation_id`. `transfer_code` is always `null` on this route. */
export async function getReceive(input: GetReceiveInput): Promise<ReceiveOperationView> {
  const rawTarget = `/v1/receives/${input.operationId}`;
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, rawTarget), {
    method: "GET",
    headers: { authorization: `Bearer ${input.bearerKey}` },
  });
  await assertOk(response);
  return (await response.json()) as ReceiveOperationView;
}

/**
 * Mint a fresh `Idempotency-Key` for one logical mutation. Call this ONCE per mutation and
 * persist the result for every retry attempt of that same mutation — never call it again
 * for a retry.
 */
export function generateIdempotencyKey(): string {
  return crypto.randomUUID();
}
