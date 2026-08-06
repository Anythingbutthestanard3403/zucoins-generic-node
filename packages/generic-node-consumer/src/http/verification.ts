/**
 * Verification-material read and verification-complete acknowledgement.
 * Both are signed-reporting-credential routes; both wire
 * shapes are exactly the pipeline's existing `VerificationMaterialWire` /
 * `VerificationCompleteRequest` / `VerificationCompleteResponse` types (types.ts) — this
 * module is pure transport around them, so a caller running `verifyOperationIndependently` /
 * `buildVerificationCompleteRequest` (pipeline.ts) never re-shapes data between the wire and
 * the pipeline.
 */

import { assertOk } from "./errors.js";
import { resolveFetch, resolveUrl, type NodeClientConfig } from "./client-types.js";
import {
  buildSignedReportingHeaders,
  type ReportingCredential,
} from "./reporting-signer.js";
import type {
  VerificationCompleteRequest,
  VerificationCompleteResponse,
  VerificationMaterialWire,
} from "../types.js";

export interface GetVerificationMaterialInput {
  readonly config: NodeClientConfig;
  readonly credential: ReportingCredential;
  readonly operationId: string;
}

/**
 * `GET /v1/operations/:id/verification-material`. `409 verification_material_not_ready` and
 * `410 verification_material_expired` surface as `NodeApiError` like any other non-2xx.
 */
export async function getVerificationMaterial(
  input: GetVerificationMaterialInput,
): Promise<VerificationMaterialWire> {
  const rawTarget = `/v1/operations/${input.operationId}/verification-material`;
  const emptyBody = new Uint8Array(0);
  const headers = await buildSignedReportingHeaders({
    credential: input.credential,
    method: "GET",
    rawTarget,
    bodyBytes: emptyBody,
  });
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, rawTarget), {
    method: "GET",
    headers,
  });
  await assertOk(response);
  return (await response.json()) as VerificationMaterialWire;
}

export interface PostVerificationCompleteInput {
  readonly config: NodeClientConfig;
  readonly credential: ReportingCredential;
  readonly operationId: string;
  readonly request: VerificationCompleteRequest;
  /** Stable across every retry attempt of this logical mutation — see receives.ts. */
  readonly idempotencyKey: string;
}

/** `POST /v1/operations/:id/verification-complete`. */
export async function postVerificationComplete(
  input: PostVerificationCompleteInput,
): Promise<VerificationCompleteResponse> {
  const rawTarget = `/v1/operations/${input.operationId}/verification-complete`;
  const bodyText = JSON.stringify(input.request);
  const bodyBytes = new TextEncoder().encode(bodyText);
  const signedHeaders = await buildSignedReportingHeaders({
    credential: input.credential,
    method: "POST",
    rawTarget,
    bodyBytes,
  });
  signedHeaders.set("content-type", "application/json; charset=utf-8");
  signedHeaders.set("idempotency-key", input.idempotencyKey);
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, rawTarget), {
    method: "POST",
    headers: signedHeaders,
    body: bodyText,
  });
  await assertOk(response);
  return (await response.json()) as VerificationCompleteResponse;
}
