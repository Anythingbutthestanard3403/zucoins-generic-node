// the reporting node-event purpose — The frozen `zp-report-request-v1` signed read/arm/acknowledge request tuple
// (the canonical-fields report-request table). This is the sole signature for authenticated verification-material reads, arm
// calls, and verification-complete acknowledgements — there is no separate acknowledgement
// signature. Signed by the implementer reporting key registered under the reporting-auth register tuple.
//
// Governing: the canonical serializer, the report-request field/header mapping and golden, the api
// contract, and the pull-cursor authority rule (60s window vs SIGNED issued_at). Byte-exactness is the byte-exact signing rule.

import { parseCanonicalRfc3339Ms } from "./request-target.js";

export const REPORT_REQUEST_PURPOSE = "zp-report-request-v1" as const;
export const REPORT_REQUEST_CANONICAL_VERSION = 1 as const;

export const REPORT_REQUEST_FIELD_ORDER = [
  "purpose",
  "canonical_version",
  "node_id",
  "implementer_id",
  "method",
  "path",
  "body_sha256",
  "nonce",
  "issued_at",
  "expires_at",
] as const;

export interface ReportRequestPayload {
  readonly purpose: typeof REPORT_REQUEST_PURPOSE;
  readonly canonical_version: typeof REPORT_REQUEST_CANONICAL_VERSION;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly method: string;
  readonly path: string;
  readonly body_sha256: string;
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
}

// Nonce/time window (the pull-cursor authority rule): expires_at must be at most this many seconds after the SIGNED
// issued_at (never receipt time); the nonce is durable single-use per implementer/node.
export const REPORT_REQUEST_MAX_WINDOW_SECONDS = 60 as const;

// The single source of byte-layout truth for the A.1.1 preimage (the byte-exact signing rule): serialize once,
// explicit key sequence, no window guard. Kept guard-free and exported so honest minters
// (buildReportRequestPreimage) and adversarial test fixtures (which must construct the very
// out-of-window requests the minter refuses, to exercise the verifier's independent rejection)
// share ONE serializer — the frozen goldens over buildReportRequestPreimage prove the bytes are
// identical. Do NOT reformat/reorder/prettify: any change here is a golden-breaking change.
export function serializeReportRequestPayload(p: ReportRequestPayload): string {
  const payload = {
    purpose: p.purpose,
    canonical_version: p.canonical_version,
    node_id: p.node_id,
    implementer_id: p.implementer_id,
    method: p.method,
    path: p.path,
    body_sha256: p.body_sha256,
    nonce: p.nonce,
    issued_at: p.issued_at,
    expires_at: p.expires_at,
  };
  return `${REPORT_REQUEST_PURPOSE}\n${JSON.stringify(payload)}`;
}

// Build the byte-exact preimage per A.1.1 (the byte-exact signing rule). Enforces the A.5 60s window at mint
// time, matching node-core's enforceSignedWindow: negated-positive comparisons so a NaN
// delta fails closed. On success, serialization is delegated to serializeReportRequestPayload so
// the emitted bytes are identical to the guard-free path.
export function buildReportRequestPreimage(p: ReportRequestPayload): string {
  const issuedMs = parseCanonicalRfc3339Ms(p.issued_at);
  const expiresMs = parseCanonicalRfc3339Ms(p.expires_at);
  if (issuedMs === null || expiresMs === null) {
    throw new Error("buildReportRequestPreimage: issued_at/expires_at must be canonical RFC3339 ms timestamps");
  }
  const deltaMs = expiresMs - issuedMs;
  if (!(deltaMs > 0)) {
    throw new Error("buildReportRequestPreimage: expires_at must be later than issued_at");
  }
  if (!(deltaMs <= REPORT_REQUEST_MAX_WINDOW_SECONDS * 1000)) {
    throw new Error("buildReportRequestPreimage: window exceeds 60 seconds");
  }

  return serializeReportRequestPayload(p);
}

// The five mandatory reporting headers (A.5) and their tuple mapping. X-ZP-Reporting-Key-Id
// selects the registration (the reporting-auth register tuple binding) and is NOT a second signed field; the signature is
// over the exact tuple preimage.
export const REPORTING_REQUEST_HEADERS = [
  { header: "X-ZP-Reporting-Key-Id", mapsTo: "reporting_key_id_selector", signed: false },
  { header: "X-ZP-Reporting-Timestamp", mapsTo: "issued_at", signed: true },
  { header: "X-ZP-Reporting-Expires-At", mapsTo: "expires_at", signed: true },
  { header: "X-ZP-Reporting-Nonce", mapsTo: "nonce", signed: true },
  { header: "X-ZP-Reporting-Signature", mapsTo: "signature", signed: false },
] as const;

// The A.8 deterministic golden (body `{}` → body_sha256 = SHA-256 of "{}"; report window 60s).
export const REPORT_REQUEST_GOLDEN_PAYLOAD: ReportRequestPayload = {
  purpose: REPORT_REQUEST_PURPOSE,
  canonical_version: REPORT_REQUEST_CANONICAL_VERSION,
  node_id: "11111111-1111-4111-8111-111111111111",
  implementer_id: "22222222-2222-4222-8222-222222222222",
  method: "POST",
  path: "/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete",
  body_sha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
  nonce: "99999999-9999-4999-8999-999999999999",
  issued_at: "2026-07-18T00:00:00.000Z",
  expires_at: "2026-07-18T00:01:00.000Z",
};

export const REPORT_REQUEST_GOLDEN_PREIMAGE = buildReportRequestPreimage(REPORT_REQUEST_GOLDEN_PAYLOAD);

// additive query-bearing golden. The Appendix A.8 queryless golden above is immutable.
export const REPORT_REQUEST_QUERY_GOLDEN_PAYLOAD: ReportRequestPayload = {
  ...REPORT_REQUEST_GOLDEN_PAYLOAD,
  method: "GET",
  path: "/v1/events?after_implementer_seq=1043&limit=100&wait_seconds=30",
  body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
};

export const REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE = buildReportRequestPreimage(
  REPORT_REQUEST_QUERY_GOLDEN_PAYLOAD,
);
