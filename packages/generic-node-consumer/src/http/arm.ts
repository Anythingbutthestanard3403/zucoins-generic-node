/**
 * POST /v1/operations/:id/armed — signed reporting credential route.
 * Mirrors verification.ts / receives.ts transport shape.
 */

import { assertOk } from "./errors.js";
import { resolveFetch, resolveUrl, type NodeClientConfig } from "./client-types.js";
import {
  buildSignedReportingHeaders,
  type ReportingCredential,
} from "./reporting-signer.js";

export interface ArmRequest {
  readonly expected_row_version: number;
  readonly t0: {
    readonly observation_id: string;
    readonly projection: { readonly s: string; readonly p: string; readonly b_zkz: string };
  };
  readonly opened_cursor: string;
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

export interface ArmOperationInput {
  readonly config: NodeClientConfig;
  readonly credential: ReportingCredential;
  readonly operationId: string;
  readonly request: ArmRequest;
  /** Stable across every retry of this logical mutation. */
  readonly idempotencyKey: string;
}

/** `POST /v1/operations/:operation_id/armed` with signed reporting headers. */
export async function armOperation(input: ArmOperationInput): Promise<ArmSuccessResponse> {
  const rawTarget = `/v1/operations/${input.operationId}/armed`;
  const bodyText = JSON.stringify(input.request);
  const bodyBytes = new TextEncoder().encode(bodyText);
  const headers = await buildSignedReportingHeaders({
    credential: input.credential,
    method: "POST",
    rawTarget,
    bodyBytes,
  });
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("idempotency-key", input.idempotencyKey);

  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, rawTarget), {
    method: "POST",
    headers,
    body: bodyText,
  });
  await assertOk(response);
  return (await response.json()) as ArmSuccessResponse;
}
