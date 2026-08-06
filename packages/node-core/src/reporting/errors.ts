// reporting rejection taxonomy and the frozen error envelope
// ({error:{code,message,request_id,details}}). Clients branch only on `code`; `message` is
// diagnostic. Code strings + HTTP statuses are frozen in
// `@zucoins/generic-node-contracts/auth-errors` (UP-09) so the platform imports the
// same set without reaching into node-core. Status choices follow.1:
// 401 for every authentication-class failure (never 403 — no cross-tenant existence oracle),
// 400 for bounded-shape failures, 404 for absent routes or tenant-scoped objects, 409 for
// idempotency fingerprint conflict, 429 for bounded rate.

export {
  REPORTING_REJECTION_CODES,
  REJECTION_STATUS,
  type ReportingRejectionCode,
} from "@zucoins/generic-node-contracts/auth-errors";

import {
  REJECTION_STATUS,
  type ReportingRejectionCode,
} from "@zucoins/generic-node-contracts/auth-errors";

const REJECTION_MESSAGES: Readonly<Record<ReportingRejectionCode, string>> = {
  missing_reporting_headers: "The five signed reporting headers are each mandatory exactly once.",
  invalid_reporting_headers: "A signed reporting header value is not in its canonical form.",
  invalid_request_target: "The request target is not an acceptable canonical origin-form target.",
  not_found: "The requested object is absent or outside the authenticated tenant.",
  request_too_large: "The request body exceeds the bounded size limit.",
  invalid_idempotency_key: "The Idempotency-Key header is absent, repeated, or malformed.",
  unsupported_content_encoding: "Signed reporting routes accept only identity content encoding.",
  rate_limited: "The reporting principal rate limit is exceeded.",
  invalid_reporting_window: "The signed issued_at/expires_at window is not within (0, 60s].",
  reporting_request_expired: "The signed expires_at instant has passed.",
  reporting_request_not_yet_valid: "The signed issued_at instant is in the future.",
  unknown_reporting_key: "The reporting key id is not registered on this node.",
  tenant_binding_mismatch: "The signed tenant fields do not equal the key registration binding.",
  reporting_key_not_active: "The reporting key is not admitted at the current lifecycle head.",
  reporting_auth_hold: "Reporting authorization is held on this node or lifecycle head.",
  invalid_signature: "The reporting signature does not verify over the exact request tuple.",
  nonce_replay: "The reporting nonce was already consumed.",
  idempotency_conflict: "The idempotency key was completed with a different request fingerprint.",
  internal_error: "The reporting request failed after authentication; the nonce burn is retained.",
};

const UTF8 = new TextEncoder();

export interface ReportingLiveStream {
  close(): void;
}

export interface ReportingHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyBytes: Uint8Array;
  /**
   * When set, the transport already opened the SSE body via openSink and must NOT end the
   * response. Call close on client disconnect so SSE poll timers cannotint leak.
   */
  readonly liveStream?: ReportingLiveStream;
}

export function reportingErrorResponse(
  code: ReportingRejectionCode,
  requestId: string,
  message?: string,
): ReportingHttpResponse {
  const envelope = {
    error: {
      code,
      message: message ?? REJECTION_MESSAGES[code],
      request_id: requestId,
      details: {},
    },
  };
  return {
    status: REJECTION_STATUS[code],
    headers: { "content-type": "application/json" },
    bodyBytes: UTF8.encode(JSON.stringify(envelope)),
  };
}

export function reportingJsonResponse(status: number, bodyText: string): ReportingHttpResponse {
  return {
    status,
    headers: { "content-type": "application/json" },
    bodyBytes: UTF8.encode(bodyText),
  };
}
