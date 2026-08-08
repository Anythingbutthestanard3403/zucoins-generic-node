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
  buildAuthErrorBody,
  reportingWireCode,
  CANONICAL_AUTH_FAILURE_MESSAGE,
  REJECTION_STATUS,
  type ReportingRejectionCode,
} from "@zucoins/generic-node-contracts/auth-errors";

// The six credential-state codes share the canonical message verbatim: collapsing the code
// while leaving "the reporting key id is not registered on this node" in English restates the
// same distinction and is not a collapse. reportingErrorResponse never reads their entry (it
// builds those bodies through the frozen emitter), but the map stays total so a direct reader
// of the taxonomy sees the same single answer.
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
  unknown_reporting_key: CANONICAL_AUTH_FAILURE_MESSAGE,
  tenant_binding_mismatch: CANONICAL_AUTH_FAILURE_MESSAGE,
  reporting_key_not_active: CANONICAL_AUTH_FAILURE_MESSAGE,
  reporting_auth_hold: CANONICAL_AUTH_FAILURE_MESSAGE,
  invalid_signature: CANONICAL_AUTH_FAILURE_MESSAGE,
  nonce_replay: CANONICAL_AUTH_FAILURE_MESSAGE,
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
  /**
   * Server-side only: the real reason behind a collapsed non-oracular 401, against the
   * `request_id` this response carries. NEVER serialized — the transport writes `status`,
   * `headers` and `bodyBytes` and nothing else — so an operator can resolve the reason from the
   * id the caller quotes while the wire stays a single opaque "no". Set by
   * reportingErrorResponse alone; the HTTP adapter records it as every response is written.
   */
  readonly collapsedRejection?: {
    readonly requestId: string;
    readonly code: ReportingRejectionCode;
  };
}

export function reportingErrorResponse(
  code: ReportingRejectionCode,
  requestId: string,
  message?: string,
): ReportingHttpResponse {
  // The non-oracular collapse, at the single emitter every reporting rejection routes through.
  // `reportingWireCode` is the frozen served mapping (the contracts-side verifier reads the same
  // function), so a credential-state code never reaches the wire: status, code, message and
  // headers are constant across all six and the response answers only "no" — never "that key is
  // unregistered" vs "that key belongs to someone else" vs "only your signature failed". The
  // body comes from the frozen auth-error emitter rather than a hand-built envelope that merely
  // looks the same, so it is byte-identical to the pinned canonical 401 modulo request_id. A
  // caller-supplied `message` is discarded rather than trusted — a future emitter cannot reopen
  // the channel by passing one.
  const wireCode = reportingWireCode(code);
  if (wireCode !== code) {
    return {
      status: REJECTION_STATUS[code],
      headers: { "content-type": "application/json" },
      bodyBytes: UTF8.encode(
        buildAuthErrorBody(wireCode, CANONICAL_AUTH_FAILURE_MESSAGE, requestId),
      ),
      collapsedRejection: { requestId, code },
    };
  }
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
