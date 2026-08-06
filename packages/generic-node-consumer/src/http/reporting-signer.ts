/**
 * Client-side construction of the five `X-ZP-Reporting-*` headers
 * that authenticate every signed-reporting-credential route this package wraps: GET /v1/events,
 * GET /v1/operations/:id/verification-material, and POST /v1/operations/:id/verification-complete.
 *
 * The signed preimage bytes are the frozen `zp-report-request-v1` tuple
 * (@zucoins/generic-node-contracts reporting-tuples) — this module never re-derives or reorders
 * that serialization. It only supplies the fetch-facing plumbing: nonce
 * allocation, the canonical timestamp pair, body hashing, and header assembly.
 */

import { createHash } from "node:crypto";

import {
  buildReportRequestPreimage,
  parseCanonicalRfc3339Ms,
  validateReportingRequestTarget,
  REPORT_REQUEST_CANONICAL_VERSION,
  REPORT_REQUEST_MAX_WINDOW_SECONDS,
  REPORT_REQUEST_PURPOSE,
  type ReportRequestPayload,
} from "@zucoins/generic-node-contracts";

/**
 * One method only, mirroring the frozen node-side signer surface — no exportPrivateKey /
 * getKeyBytes / raw. Implementations hold the reporting private key; this module never sees it.
 */
export interface ReportingSigner {
  sign(preimage: Uint8Array): Promise<string>;
}

export interface ReportingCredential {
  readonly nodeId: string;
  readonly implementerId: string;
  /** Selector header value (X-ZP-Reporting-Key-Id) — not itself a signed tuple field. */
  readonly keyId: string;
  readonly signer: ReportingSigner;
}

export class ReportingRequestInvalidError extends Error {
  readonly code = "REPORTING_REQUEST_INVALID" as const;
  readonly reason: string;

  constructor(reason: string) {
    super(reason);
    this.name = "ReportingRequestInvalidError";
    this.reason = reason;
  }
}

/** Lowercase hex SHA-256 over the exact body bytes that will be transmitted. */
export function bodySha256Hex(bodyBytes: Uint8Array): string {
  return createHash("sha256").update(bodyBytes).digest("hex");
}

/**
 * Canonical RFC3339 UTC with exactly three fractional digits that survives an exact
 * `Date#toISOString()` round-trip (the frozen timestamp grammar). A `Date` built from `Date.now()` (or
 * any integer millisecond value) always renders this way, but the round-trip is still checked
 * rather than assumed.
 */
function formatCanonicalTimestamp(date: Date): string {
  const rendered = date.toISOString();
  if (parseCanonicalRfc3339Ms(rendered) === null || new Date(rendered).toISOString() !== rendered) {
    throw new ReportingRequestInvalidError(
      "timestamp is not canonical RFC3339 UTC with exactly three fractional digits",
    );
  }
  return rendered;
}

export interface BuildSignedReportingHeadersInput {
  readonly credential: ReportingCredential;
  readonly method: "GET" | "POST";
  /** Exact origin-form target — the same string used verbatim as the fetch request path. */
  readonly rawTarget: string;
  readonly bodyBytes: Uint8Array;
  /** Injected clock; defaults to `new Date()`. */
  readonly issuedAt?: Date;
  /** Signed window in seconds; defaults to and is clamped to the frozen 60s ceiling. */
  readonly windowSeconds?: number;
}

/**
 * Build the five signed reporting headers for one HTTP attempt. A fresh nonce is allocated
 * here on every call — callers must not reuse headers across retries; they must instead call
 * this again with the same stable `Idempotency-Key` body/header the mutation itself carries.
 */
export async function buildSignedReportingHeaders(
  input: BuildSignedReportingHeadersInput,
): Promise<Headers> {
  const targetCheck = validateReportingRequestTarget(input.method, input.rawTarget);
  if (!targetCheck.ok) {
    throw new ReportingRequestInvalidError(`invalid request target: ${targetCheck.reason ?? "rejected"}`);
  }

  const windowSeconds = input.windowSeconds ?? REPORT_REQUEST_MAX_WINDOW_SECONDS;
  if (
    !Number.isInteger(windowSeconds) ||
    windowSeconds <= 0 ||
    windowSeconds > REPORT_REQUEST_MAX_WINDOW_SECONDS
  ) {
    throw new ReportingRequestInvalidError(
      `windowSeconds must be in (0, ${REPORT_REQUEST_MAX_WINDOW_SECONDS}]`,
    );
  }

  const issuedAtDate = input.issuedAt ?? new Date();
  const issued_at = formatCanonicalTimestamp(issuedAtDate);
  const issuedMs = parseCanonicalRfc3339Ms(issued_at)!;
  const expires_at = formatCanonicalTimestamp(new Date(issuedMs + windowSeconds * 1000));

  const payload: ReportRequestPayload = {
    purpose: REPORT_REQUEST_PURPOSE,
    canonical_version: REPORT_REQUEST_CANONICAL_VERSION,
    node_id: input.credential.nodeId,
    implementer_id: input.credential.implementerId,
    method: input.method,
    path: input.rawTarget,
    body_sha256: bodySha256Hex(input.bodyBytes),
    nonce: crypto.randomUUID(),
    issued_at,
    expires_at,
  };

  const preimage = buildReportRequestPreimage(payload);
  const signature = await input.credential.signer.sign(new TextEncoder().encode(preimage));

  const headers = new Headers();
  headers.set("X-ZP-Reporting-Key-Id", input.credential.keyId);
  headers.set("X-ZP-Reporting-Timestamp", payload.issued_at);
  headers.set("X-ZP-Reporting-Expires-At", payload.expires_at);
  headers.set("X-ZP-Reporting-Nonce", payload.nonce);
  headers.set("X-ZP-Reporting-Signature", signature);
  return headers;
}
