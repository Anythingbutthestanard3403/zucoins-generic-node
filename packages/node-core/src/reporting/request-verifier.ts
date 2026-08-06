// the pre-burn verification pipeline for `zp-report-request-v1` signed
// reporting requests. Consumes a raw transport capture (CapturedReportRequest — assembled by
// the outer adapter BEFORE any parse/decode/route) and returns either a fully verified,
// nonce-burned request context or one mapped rejection. Pure response-producing: no sockets,
// no framework, no global state.
//
// The check sequence is the frozen PRE_BURN_CHECKS arrangement
// (reporting-persistence/decisions.ts — bounded_shape → signed_time_window → bounded_size →
// bounded_rate → tenant_and_key_binding → lifecycle_eligibility → signature), never spending
// crypto before key status, never any object-scoped work before tenant binding:
//
// bounded shape (five headers exactly-once via rawHeaders, canonical forms)
// → signed_time_window (0 < window ≤ 60s on the SIGNED fields, then receipt-vs-window at
// skew 0 with inclusive boundaries) — BEFORE bounded rate, the registration lookup,
// holds/key_status, and tenant, so a window-invalid request rejects identically for
// every key state and spends no rate budget
// → bounded size (body cap) → origin-form gate → route-shape match
// → validateReportingRequestTarget → mutation-route Idempotency-Key form → bounded rate
// → tenant_and_key_binding + lifecycle_eligibility (admission.ts) → purpose literal
// → signature → behavior cross-check (+advisory nonce peek) → atomic burn.
//
// The target is matched raw with zero clock skew, and the burn contract applies. Any failure
// inserts NOTHING; the burn is the first and only write.

import {
  buildReportRequestPreimage,
  decodeCanonicalEd25519Signature,
  decodeCanonicalReportingPublicKey,
  evaluateReportRequest,
  idempotencyKeyIsValid,
  parseCanonicalRfc3339Ms,
  reportingKeyMaySign,
  reportingSignedWindowIsValid,
  validateReportingRequestTarget,
  verifyReportRequestPreimage,
  REPORT_REQUEST_PURPOSE,
  REPORT_REQUEST_CANONICAL_VERSION,
  REQUEST_CLOCK_SKEW_MS,
} from "@zucoins/generic-node-contracts";

import { admitReportingKey } from "./admission.js";
import { buildBurnNonceEvidence } from "./burn-evidence.js";
import { sha256Hex, verifyDetachedEd25519 } from "./ed25519.js";
import type { ReportingRejectionCode } from "./errors.js";
import { readExactHeader, readReportingSignedHeaders, REPORTING_HEADER_NAMES } from "./headers.js";
import { classifyReportingRoute, reportingRouteShapeMatches } from "./route-table.js";
import type { ReportingRouteClassification } from "./route-table.js";
import {
  type ReportingNonceEvidence,
  type ReportingRateLimiter,
  type ReportingRegistration,
  type ReportingRequestStore,
} from "./store.js";

const LOWER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export const DEFAULT_MAX_BODY_BYTES = 1_048_576;

// The adapter's raw transport capture: method/target/headers byte-verbatim from the wire
// (never URL-parsed, decoded, or reconstructed), the exact body bytes, and the single ingress
// wall-clock instant threaded to the window check, the overlap check, and received_at.
export interface CapturedReportRequest {
  readonly method: string;
  readonly rawTarget: string;
  readonly rawHeaders: readonly string[];
  readonly bodyBytes: Uint8Array;
  readonly receivedAtMs: number;
}

export interface ReportingRejection {
  readonly ok: false;
  readonly code: ReportingRejectionCode;
  readonly message?: string;
}

export interface VerifiedReportRequest {
  readonly ok: true;
  readonly binding: ReportingRegistration;
  readonly route: ReportingRouteClassification;
  readonly nonceEvidence: ReportingNonceEvidence;
  readonly idempotencyKey: string | null;
  readonly fingerprint: {
    readonly method: string;
    readonly rawTarget: string;
    readonly bodySha256: string;
  };
  readonly bodyBytes: Uint8Array;
  /**
   * Unsigned transport header Last-Event-ID (first occurrence, case-insensitive),
   * extracted at verify time so SSE resume can enforce cursor equality.
   * Null when absent. Not part of the signed preimage.
   */
  readonly lastEventId: string | null;
}

export type ReportingVerifyOutcome = VerifiedReportRequest | ReportingRejection;

export interface ReportingRequestVerifier {
  verify(captured: CapturedReportRequest): Promise<ReportingVerifyOutcome>;
}

export interface ReportingRequestVerifierConfig {
  readonly nodeId: string;
  readonly store: ReportingRequestStore;
  readonly rateLimiter: ReportingRateLimiter;
  readonly nowMs: () => number;
  readonly maxBodyBytes?: number;
}

const reject = (code: ReportingRejectionCode, message?: string): ReportingRejection => ({
  ok: false,
  code,
  ...(message === undefined ? {} : { message }),
});


/** First case-insensitive header value from a rawHeaders name/value pair list; null if absent. */
function readFirstHeaderValue(rawHeaders: readonly string[], name: string): string | null {
  const want = name.toLowerCase();
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    if (rawHeaders[index]!.toLowerCase() === want) {
      return rawHeaders[index + 1]!;
    }
  }
  return null;
}

export function createReportingRequestVerifier(
  config: ReportingRequestVerifierConfig,
): ReportingRequestVerifier {
  const maxBodyBytes = config.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  const verify = async (captured: CapturedReportRequest): Promise<ReportingVerifyOutcome> => {
    // bounded_shape: the five signed headers exactly once each, then canonical value forms.
    const headerRead = readReportingSignedHeaders(captured.rawHeaders);
    if (headerRead.kind !== "OK") return reject("missing_reporting_headers");
    const headers = headerRead.headers;

    const issuedAtMs = parseCanonicalRfc3339Ms(headers.issuedAt);
    const expiresAtMs = parseCanonicalRfc3339Ms(headers.expiresAt);
    const signatureBytes = decodeCanonicalEd25519Signature(headers.signature);
    if (
      !LOWER_UUID.test(headers.keyId) ||
      !LOWER_UUID.test(headers.nonce) ||
      issuedAtMs === null ||
      expiresAtMs === null ||
      signatureBytes === null
    ) {
      return reject("invalid_reporting_headers");
    }

    // signed_time_window (PRE_BURN_CHECKS position 2, immediately after bounded_shape):
    // 0 < (expires - issued) ≤ 60s on the SIGNED fields (signed pull event stream), then receipt vs window at
    // the frozen zero skew with inclusive boundaries — before bounded_rate, registration,
    // holds/key_status, and tenant, so a window-invalid request rejects identically for
    // every key state and consumes no rate-limit budget.
    if (!reportingSignedWindowIsValid(REPORT_REQUEST_PURPOSE, issuedAtMs, expiresAtMs)) {
      return reject("invalid_reporting_window");
    }
    if (captured.receivedAtMs > expiresAtMs + REQUEST_CLOCK_SKEW_MS) {
      return reject("reporting_request_expired");
    }
    if (captured.receivedAtMs < issuedAtMs - REQUEST_CLOCK_SKEW_MS) {
      return reject("reporting_request_not_yet_valid");
    }

    // bounded_size, then the origin-form gate (absolute/asterisk forms fail closed here
    // never reconstructed into a routable path).
    if (captured.bodyBytes.length > maxBodyBytes) return reject("request_too_large");
    if (!captured.rawTarget.startsWith("/") || captured.rawTarget.startsWith("//")) {
      return reject("invalid_request_target");
    }

    // route shape (path-only probe) → 404 for paths this server does not carry, then the
    // frozen canonical target policy → 400 for any byte-level violation on a known route.
    if (!reportingRouteShapeMatches(captured.rawTarget)) return reject("not_found");
    if (!validateReportingRequestTarget(captured.method, captured.rawTarget).ok) {
      return reject("invalid_request_target");
    }
    const route = classifyReportingRoute(captured.method, captured.rawTarget);
    if (route === null) return reject("not_found");

    // Mutation routes carry a mandatory, format-checked Idempotency-Key.
    let idempotencyKey: string | null = null;
    if (route.requestClass === "MUTATION") {
      const keyRead = readExactHeader(captured.rawHeaders, REPORTING_HEADER_NAMES.idempotencyKey);
      if (keyRead.kind !== "ONE" || !idempotencyKeyIsValid(keyRead.value)) {
        return reject("invalid_idempotency_key");
      }
      idempotencyKey = keyRead.value;
    }

    // bounded_rate, keyed on the presented key id (the pre-registration tenant signal).
    if (!(await config.rateLimiter.consume(config.nodeId, headers.keyId, captured.receivedAtMs))) {
      return reject("rate_limited");
    }

    // tenant_and_key_binding → lifecycle_eligibility (admission.ts): the registration
    // lookup, holds + key_status at the ingress instant, then tenant equality.
    const admission = await admitReportingKey(
      config.store,
      config.nodeId,
      headers.keyId,
      captured.receivedAtMs,
    );
    if (!admission.ok) return reject(admission.code);
    const { binding, snapshot } = admission;

    // purpose literal before signature verification (A.9 #10).
    if (!reportingKeyMaySign(REPORT_REQUEST_PURPOSE)) return reject("invalid_signature");

    // Preimage assembly via the frozen builder ONLY — never re-derived, never re-serialized.
    const bodySha256 = sha256Hex(captured.bodyBytes);
    const preimageText = buildReportRequestPreimage({
      purpose: REPORT_REQUEST_PURPOSE,
      canonical_version: REPORT_REQUEST_CANONICAL_VERSION,
      node_id: binding.nodeId,
      implementer_id: binding.implementerId,
      method: captured.method,
      path: captured.rawTarget,
      body_sha256: bodySha256,
      nonce: headers.nonce,
      issued_at: headers.issuedAt,
      expires_at: headers.expiresAt,
    });

    // Structural round-trip through the frozen verifier (defensive: our own assembly is
    // checked before any crypto is spent on it — catches a corrupt binding's field forms).
    if (!verifyReportRequestPreimage(preimageText).ok) {
      return reject("invalid_reporting_headers", "assembled preimage failed structural verify");
    }
    const publicKeyBytes = decodeCanonicalReportingPublicKey(binding.publicKeyEncoded);
    if (publicKeyBytes === null) return reject("reporting_key_not_active");

    const signatureValid = verifyDetachedEd25519({
      publicKeyBytes,
      preimageText,
      signatureBytes,
    });
    if (!signatureValid) return reject("invalid_signature");

    // Behavior cross-check (frozen cell sequence) + advisory pre-burn nonce peek;
    // the burn's atomic unique insert remains the authoritative replay guard.
    const nonceSeen = await config.store.peekNonceBurned(
      config.nodeId,
      binding.implementerId,
      headers.nonce,
    );
    const crossCheck = evaluateReportRequest({
      boundNodeId: binding.nodeId,
      boundImplementerId: binding.implementerId,
      tupleNodeId: binding.nodeId,
      tupleImplementerId: binding.implementerId,
      issuedAtMs,
      expiresAtMs,
      receiptTimeMs: captured.receivedAtMs,
      nonceSeen,
      signedMethod: captured.method,
      actualMethod: captured.method,
      signedTarget: captured.rawTarget,
      actualTarget: captured.rawTarget,
      signedBodySha256: bodySha256,
      actualBodySha256: bodySha256,
    });
    if (crossCheck === "REJECT_REPLAY") return reject("nonce_replay");
    if (crossCheck !== "ACCEPT") {
      return reject("invalid_reporting_headers", `behavior cross-check returned ${crossCheck}`);
    }

    // Atomic burn: epoch/holds/key/overlap rechecked under lock inside the store.
    const evidence = buildBurnNonceEvidence({
      nodeId: config.nodeId,
      binding,
      route,
      lifecycleEpoch: snapshot.epoch,
      keyId: headers.keyId,
      nonce: headers.nonce,
      signature: headers.signature,
      issuedAt: headers.issuedAt,
      expiresAt: headers.expiresAt,
      method: captured.method,
      rawTarget: captured.rawTarget,
      bodySha256,
      preimageText,
      receivedAtMs: captured.receivedAtMs,
      consumedAtMs: config.nowMs(),
    });
    const burn = await config.store.burnNonceAtomically({
      expectedEpoch: snapshot.epoch,
      evidence,
    });
    if (burn.kind === "REPLAY") return reject("nonce_replay");
    if (burn.kind === "HOLD") return reject("reporting_auth_hold");
    if (burn.kind === "LIFECYCLE_RECHECK_FAILED") return reject("reporting_key_not_active");

    // Last-Event-ID is unsigned transport state (SSE resume). Extract once here so route
    // binders never need the discarded rawHeaders array. First occurrence wins.
    const lastEventId = readFirstHeaderValue(captured.rawHeaders, "last-event-id");

    return {
      ok: true,
      binding,
      route,
      nonceEvidence: burn.evidence,
      idempotencyKey,
      fingerprint: { method: captured.method, rawTarget: captured.rawTarget, bodySha256 },
      bodyBytes: captured.bodyBytes,
      lastEventId,
    };
  };

  return { verify };
}
