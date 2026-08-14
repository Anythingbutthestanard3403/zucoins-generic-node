// Centralized typed error envelopes for the full v2 API surface.
// Reuses the frozen auth-errors emitter (SHA-256 pins 44fa5568…961e7e for 401,
// 949585…64d147 for 404) and extends with the remaining 400/409/410/422/429/503
// codes from.
//
// valid-key-wrong-scope returns the SAME generic 401 invalid_api_key as
// unknown key — NO 403/forbidden code exists anywhere in this surface.
// Byte-exact JSON.stringify with an explicit key insertion sequence.

import { z } from "zod";
import {
  buildAuthErrorBody,
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_AUTH_FAILURE_MESSAGE,
  CANONICAL_NOT_FOUND_CODE,
  CANONICAL_NOT_FOUND_MESSAGE,
  CANONICAL_AUTH_ERROR_HEADERS,
} from "@zucoins/generic-node-contracts/auth-errors";

// The full error code taxonomy for the v2 API surface. The first two are the frozen
// auth-error codes (byte-pinned); the rest are extension per.
export const API_ERROR_CODES = [
  // Frozen auth-errors — byte-pinned, never altered.
  { code: "invalid_api_key", http: 401 },
  { code: "not_found", http: 404 },
  // 400 — malformed input class
  { code: "unknown_field", http: 400 },
  { code: "invalid_scalar", http: 400 },
  { code: "malformed_json", http: 400 },
  { code: "duplicate_json_key", http: 400 },
  { code: "invalid_utf8", http: 400 },
  { code: "request_too_large", http: 400 },
  { code: "nesting_too_deep", http: 400 },
  { code: "invalid_idempotency_key", http: 400 },
  { code: "cursor_mismatch", http: 400 },
  // 415 / 505 — transport-layer rejection, decided by enforceTransportGuards
  // (transport-hardening.ts) BEFORE the eight-stage pipeline runs. Neither code depends on
  // whether the requested route exists, so a transport rejection is not an existence oracle.
  { code: "unsupported_content_type", http: 415 },
  { code: "http_version_too_old", http: 505 },
  // 409 — concurrent-state conflict
  { code: "idempotency_conflict", http: 409 },
  // rules 2–3 — distinct wire codes (UP-04)
  { code: "idempotency_key_reused", http: 409 },
  { code: "idempotency_in_progress", http: 409 },
  { code: "wallet_busy", http: 409 },
  { code: "operation_version_conflict", http: 409 },
  { code: "t0_mismatch", http: 409 },
  { code: "operation_not_armable", http: 409 },
  { code: "verification_material_not_ready", http: 409 },
  // 410 — expired access
  { code: "verification_material_expired", http: 410 },
  // 422 — well-formed but fails custody/protocol predicate
  { code: "protocol_predicate_failed", http: 422 },
  // Funding wallet W cannot cover external-send amount (ZTR-1289). Stable for
  // Zukaz claim failure mapping — not a transient 503.
  { code: "insufficient_funding_wallet", http: 422 },
  // NODE_VERIFIED requested but operator policy refuses the implementer (ZTR-1301).
  { code: "verification_mode_not_allowed", http: 422 },
  // armed / verification-complete against a mode that does not admit that path (ZTR-1302+).
  { code: "verification_mode_mismatch", http: 409 },
  // 429 — rate limit
  { code: "rate_limited", http: 429 },
  // 503 — bounded queue / signer unavailable
  { code: "receive_queue_full", http: 503 },
  { code: "signer_unavailable", http: 503 },
  { code: "service_unavailable", http: 503 },
] as const;

export type ApiErrorCode = (typeof API_ERROR_CODES)[number]["code"];

export const HTTP_STATUS_BY_CODE: Readonly<Record<ApiErrorCode, number>> = Object.freeze(
  Object.fromEntries(API_ERROR_CODES.map((entry) => [entry.code, entry.http])) as Record<
    ApiErrorCode,
    number
  >,
);

const DIAGNOSTIC_MESSAGES: Readonly<Record<ApiErrorCode, string>> = {
  invalid_api_key: CANONICAL_AUTH_FAILURE_MESSAGE,
  not_found: CANONICAL_NOT_FOUND_MESSAGE,
  unknown_field: "The request contains an unrecognized field.",
  invalid_scalar: "A field value does not satisfy its canonical scalar constraint.",
  malformed_json: "The request body is not valid JSON.",
  duplicate_json_key: "The request body contains a duplicate JSON key.",
  invalid_utf8: "The request body is not valid UTF-8.",
  request_too_large: "The request body exceeds the bounded size limit.",
  nesting_too_deep: "The request body exceeds the maximum nesting depth.",
  invalid_idempotency_key: "The Idempotency-Key header is absent, repeated, or malformed.",
  cursor_mismatch: "The Last-Event-ID does not equal the after_implementer_seq cursor.",
  unsupported_content_type: "The request Content-Type is not application/json.",
  http_version_too_old: "The request HTTP version is below the supported minimum.",
  idempotency_conflict: "The idempotency key was completed with a different request fingerprint.",
  idempotency_key_reused: "The idempotency key was already used with a different request fingerprint.",
  idempotency_in_progress: "The idempotency key is currently being processed by a concurrent request.",
  wallet_busy: "The selected wallet already has an active operation.",
  operation_version_conflict: "The expected_row_version does not match the current version.",
  t0_mismatch: "The supplied T0 does not match the node's durable T0.",
  operation_not_armable: "The operation is not in an armable state.",
  verification_material_not_ready: "Verification material is not yet available.",
  verification_material_expired: "The verification-material access window has expired.",
  protocol_predicate_failed: "The request fails a custody or protocol predicate.",
  insufficient_funding_wallet:
    "The integration funding wallet cannot cover the requested amount.",
  verification_mode_not_allowed:
    "NODE_VERIFIED was requested at admission but operator policy does not allow it for the calling implementer.",
  verification_mode_mismatch:
    "armed or verification-complete was called on an operation whose verification_mode does not admit that path.",
  rate_limited: "The principal rate limit is exceeded.",
  receive_queue_full: "The receive bounded queue is at capacity.",
  signer_unavailable: "The signer leadership is currently unavailable.",
  service_unavailable: "The service is temporarily unavailable.",
};

export interface ApiErrorResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export const ApiErrorCodeSchema = z.enum(
  API_ERROR_CODES.map((e) => e.code) as unknown as [string, ...string[]],
) as z.ZodType<ApiErrorCode>;

export const ApiErrorEnvelopeSchema = z.object({
  error: z.object({
    code: ApiErrorCodeSchema,
    message: z.string(),
    request_id: z.string().uuid(),
    details: z.record(z.never()).default({}),
  }).strict(),
}).strict();

export type ApiErrorEnvelope = z.infer<typeof ApiErrorEnvelopeSchema>;

// Build the byte-exact error envelope. For the two frozen auth-error codes, delegates to
// the frozen emitter to preserve the SHA-256 pins. For all others, constructs with the
// same explicit key insertion sequence, so the bytes stay exact.
export function buildApiErrorBody(
  code: ApiErrorCode,
  requestId: string,
  message?: string,
): string {
  if (code === CANONICAL_AUTH_FAILURE_CODE) {
    return buildAuthErrorBody(CANONICAL_AUTH_FAILURE_CODE, CANONICAL_AUTH_FAILURE_MESSAGE, requestId);
  }
  if (code === CANONICAL_NOT_FOUND_CODE) {
    return buildAuthErrorBody(CANONICAL_NOT_FOUND_CODE, CANONICAL_NOT_FOUND_MESSAGE, requestId);
  }
  return JSON.stringify({
    error: {
      code,
      message: message ?? DIAGNOSTIC_MESSAGES[code],
      request_id: requestId,
      details: {},
    },
  });
}

export function apiErrorResponse(
  code: ApiErrorCode,
  requestId: string,
  message?: string,
  retryAfterSeconds?: number,
): ApiErrorResponse {
  const headers: Record<string, string> = { ...CANONICAL_AUTH_ERROR_HEADERS };
  if (retryAfterSeconds !== undefined) {
    headers["Retry-After"] = String(retryAfterSeconds);
  }
  return {
    status: HTTP_STATUS_BY_CODE[code],
    headers,
    body: buildApiErrorBody(code, requestId, message),
  };
}

// enforcement: scope denial collapses to the generic 401. This helper exists so
// callers never accidentally emit a 403 or a distinct scope-denial code.
export function scopeDenialResponse(requestId: string): ApiErrorResponse {
  return apiErrorResponse("invalid_api_key", requestId);
}
