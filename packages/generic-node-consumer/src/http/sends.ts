/**
 * SEND_EXTERNAL initiation. Implementer-bearer authenticated —
 * no signed reporting credential needed.
 */

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

import { assertOk } from "./errors.js";
import { resolveFetch, resolveUrl, type NodeClientConfig } from "./client-types.js";
import type { CommonOperationView } from "./receives.js";
import type { VerificationMode } from "../verification-mode.js";

export interface CreateExternalSendRequest {
  /**
   * Optional send-capable source wallet. When omitted, the node assigns a free
   * worker (ZTR-1271). Response always includes the resolved `source_wallet_id`.
   */
  readonly source_wallet_id?: string;
  readonly destination_address: string;
  readonly amount_zkz: string;
  readonly references_operation_id?: string;
  readonly client_reference?: string;
  readonly description?: string;
  /** Optional; omitted → INDEPENDENT. NODE_VERIFIED requires operator policy. */
  readonly verification_mode?: VerificationMode;
}

export interface ExternalSendOperationView {
  readonly operation: CommonOperationView & { readonly operation_type: OperationKind };
  readonly source_wallet_id: string;
  readonly destination_address: string;
  readonly references_operation_id?: string | null;
  readonly approval_status: string;
  readonly transfer_code: string | null;
  readonly transfer_code_sha256: string | null;
  readonly available_until: string | null;
  readonly expected_artifact: unknown | null;
}

export interface CreateExternalSendInput {
  readonly config: NodeClientConfig;
  /** `Bearer ik_…` implementer key, scoped `send:create`. */
  readonly bearerKey: string;
  readonly request: CreateExternalSendRequest;
  readonly idempotencyKey: string;
}

/** `POST /v1/external-sends`. */
export async function createExternalSend(
  input: CreateExternalSendInput,
): Promise<ExternalSendOperationView> {
  const rawTarget = "/v1/external-sends";
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
  return (await response.json()) as ExternalSendOperationView;
}

export interface GetExternalSendInput {
  readonly config: NodeClientConfig;
  /** `Bearer ik_…` implementer key, scoped `send:read`. */
  readonly bearerKey: string;
  readonly operationId: string;
}

/** `GET /v1/external-sends/:operation_id`. */
export async function getExternalSend(
  input: GetExternalSendInput,
): Promise<ExternalSendOperationView> {
  const rawTarget = `/v1/external-sends/${input.operationId}`;
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, rawTarget), {
    method: "GET",
    headers: { authorization: `Bearer ${input.bearerKey}` },
  });
  await assertOk(response);
  return (await response.json()) as ExternalSendOperationView;
}
