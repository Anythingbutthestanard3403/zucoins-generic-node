/**
 * MOVE_INTERNAL initiation. Implementer-bearer authenticated —
 * no signed reporting credential needed.
 */

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

import { assertOk } from "./errors.js";
import { resolveFetch, resolveUrl, type NodeClientConfig } from "./client-types.js";
import type { CommonOperationView } from "./receives.js";
import type { VerificationMode } from "../verification-mode.js";

export interface CreateInternalMoveRequest {
  readonly source_wallet_id: string;
  readonly destination_id: string;
  readonly amount_zkz: string;
  /** Advisory product correlation — unsigned, never a settlement match key. */
  readonly client_reference?: string;
  /** Optional; omitted → INDEPENDENT. NODE_VERIFIED requires operator policy. */
  readonly verification_mode?: VerificationMode;
}

export interface InternalMoveOperationView {
  readonly operation: CommonOperationView & { readonly operation_type: OperationKind };
  readonly source_wallet_id: string;
  readonly destination_id: string;
  readonly spawned_from_operation_id: string | null;
  readonly lease_status: string;
  readonly execution_phase: string;
  readonly expected_artifact: unknown | null;
  readonly source_terminal_observation_id: string | null;
  readonly destination_terminal_observation_id: string | null;
}

export interface CreateInternalMoveInput {
  readonly config: NodeClientConfig;
  /** `Bearer ik_…` implementer key, scoped `move:create`. */
  readonly bearerKey: string;
  readonly request: CreateInternalMoveRequest;
  readonly idempotencyKey: string;
}

/** `POST /v1/internal-moves`. */
export async function createInternalMove(
  input: CreateInternalMoveInput,
): Promise<InternalMoveOperationView> {
  const rawTarget = "/v1/internal-moves";
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
  return (await response.json()) as InternalMoveOperationView;
}

export interface GetInternalMoveInput {
  readonly config: NodeClientConfig;
  /** `Bearer ik_…` implementer key, scoped `move:read`. */
  readonly bearerKey: string;
  readonly operationId: string;
}

/** `GET /v1/internal-moves/:operation_id`. */
export async function getInternalMove(
  input: GetInternalMoveInput,
): Promise<InternalMoveOperationView> {
  const rawTarget = `/v1/internal-moves/${input.operationId}`;
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, rawTarget), {
    method: "GET",
    headers: { authorization: `Bearer ${input.bearerKey}` },
  });
  await assertOk(response);
  return (await response.json()) as InternalMoveOperationView;
}
