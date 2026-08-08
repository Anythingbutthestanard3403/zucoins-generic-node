// The non-oracular collapse of the reporting credential class, asserted at the single emitter.
//
// AUTH_CLASS_POLICY.REPORTING_CREDENTIAL freezes the class as `nonOracularFrozen`: a credential
// failure on a signed reporting route answers 401 `invalid_api_key` and nothing else. The
// surface used to serve ten distinguishable 401 codes, six of which described credential state
// — together a key-and-tenant enumeration channel on the tenant-scoped multi-implementer
// surface. This suite is the table over those ten former cases: the six render one
// indistinguishable response, the four that describe only the caller's own request bytes stay
// distinguishable, and the real reason survives server-side against the request_id.
//
// Everything below drives off REPORTING_CREDENTIAL_REJECTION_CODES rather than a copied list,
// so a reject reason added to the credential class inherits the assertions instead of opting in.

import { describe, expect, it } from "vitest";

import {
  CANONICAL_AUTH_FAILURE_BODY,
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_AUTH_FAILURE_MESSAGE,
  isNonOracular,
  normalizeRequestId,
  REJECTION_STATUS,
  REPORTING_CREDENTIAL_REJECTION_CODES,
  REPORTING_REJECTION_CODES,
  REPORTING_REQUEST_SHAPE_401_CODES,
  type ReportingRejectionCode,
  type WireResponse,
} from "@zucoins/generic-node-contracts/auth-errors";

import { reportingErrorResponse } from "./errors.js";

const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

const wire = (produced: ReturnType<typeof reportingErrorResponse>): WireResponse => ({
  status: produced.status,
  body: text(produced.bodyBytes),
  headers: produced.headers,
});

// A distinct request id per case: two responses that only ever matched because they shared one
// id would prove nothing. `indistinguishable` normalizes the id back out before comparing.
const requestIdFor = (index: number): string =>
  `11111111-1111-4111-8111-${String(index).padStart(12, "0")}`;

describe("reportingErrorResponse collapses every credential-state rejection", () => {
  it("renders the six former codes as ONE indistinguishable 401", () => {
    const group = REPORTING_CREDENTIAL_REJECTION_CODES.map((code, index) =>
      wire(reportingErrorResponse(code, requestIdFor(index))),
    );
    expect(group).toHaveLength(6);
    // Status, header set and body bytes all compared, modulo request_id. A code, a message, or
    // a `WWW-Authenticate`-style header that varied by subcase fails here.
    expect(isNonOracular(group)).toBe(true);
  });

  it("puts the canonical code and message on the wire — never the specific reason", () => {
    for (const code of REPORTING_CREDENTIAL_REJECTION_CODES) {
      const produced = reportingErrorResponse(code, requestIdFor(0));
      const body = JSON.parse(text(produced.bodyBytes)) as {
        error: { code: string; message: string; details: Record<string, never> };
      };
      expect(produced.status).toBe(401);
      expect(body.error.code).toBe(CANONICAL_AUTH_FAILURE_CODE);
      expect(body.error.message).toBe(CANONICAL_AUTH_FAILURE_MESSAGE);
      expect(body.error.details).toEqual({});
      // No English restatement of the distinction survives anywhere in the bytes.
      expect(text(produced.bodyBytes)).not.toContain(code);
    }
  });

  it("emits the frozen auth-error body byte-for-byte, not a lookalike envelope", () => {
    for (const code of REPORTING_CREDENTIAL_REJECTION_CODES) {
      const produced = reportingErrorResponse(code, requestIdFor(7));
      expect(normalizeRequestId(text(produced.bodyBytes))).toBe(CANONICAL_AUTH_FAILURE_BODY);
    }
  });

  it("discards a caller-supplied message rather than trusting it", () => {
    // The emitter takes an optional diagnostic message. On a collapsed code it must be ignored
    // — otherwise any future call site reopens the channel by passing one.
    const leaky = reportingErrorResponse("unknown_reporting_key", requestIdFor(1), "no such key");
    const plain = reportingErrorResponse("unknown_reporting_key", requestIdFor(1));
    expect(text(leaky.bodyBytes)).toBe(text(plain.bodyBytes));
    expect(text(leaky.bodyBytes)).not.toContain("no such key");
  });

  it("keeps the real reason server-side against the request_id", () => {
    for (const code of REPORTING_CREDENTIAL_REJECTION_CODES) {
      const requestId = requestIdFor(2);
      const produced = reportingErrorResponse(code, requestId);
      expect(produced.collapsedRejection).toEqual({ requestId, code });
      // The record is a field on the response object, never part of the serialized body.
      expect(text(produced.bodyBytes)).not.toContain(code);
    }
  });
});

describe("the collapse is exactly as wide as the freeze, and no wider", () => {
  it("leaves the four request-shape 401s distinguishable", () => {
    // These are decided from the caller's own submitted bytes before any registration lookup,
    // so they disclose nothing about which keys exist here and stay diagnosable.
    for (const code of REPORTING_REQUEST_SHAPE_401_CODES) {
      const produced = reportingErrorResponse(code, requestIdFor(3));
      expect(produced.status).toBe(401);
      expect((JSON.parse(text(produced.bodyBytes)) as { error: { code: string } }).error.code).toBe(
        code,
      );
      expect(produced.collapsedRejection).toBeUndefined();
    }
  });

  it("leaves every non-credential code rendering its own code and status", () => {
    const collapsed = new Set<string>(REPORTING_CREDENTIAL_REJECTION_CODES);
    for (const code of REPORTING_REJECTION_CODES) {
      if (collapsed.has(code)) continue;
      const produced = reportingErrorResponse(code, requestIdFor(4));
      expect(produced.status).toBe(REJECTION_STATUS[code]);
      expect((JSON.parse(text(produced.bodyBytes)) as { error: { code: string } }).error.code).toBe(
        code,
      );
    }
  });

  it("would catch a credential code that regressed to rendering itself (negative path)", () => {
    // The shape of the defect this suite exists to stop: one code in the class rendering its
    // own name again. Built here rather than reachable in the emitter, so the assertion below
    // is a real detector rather than a restatement of the implementation.
    const regressed: WireResponse = {
      status: 401,
      body: JSON.stringify({
        error: {
          code: "unknown_reporting_key",
          message: "The reporting key id is not registered on this node.",
          request_id: requestIdFor(5),
          details: {},
        },
      }),
      headers: { "content-type": "application/json" },
    };
    const group = [
      wire(reportingErrorResponse("invalid_signature", requestIdFor(6))),
      regressed,
    ];
    expect(isNonOracular(group)).toBe(false);
  });
});

describe("the ten former distinguishable 401 codes", () => {
  it("are ten, are all still 401, and now serve exactly two wire codes", () => {
    const former: readonly ReportingRejectionCode[] = [
      ...REPORTING_REQUEST_SHAPE_401_CODES,
      ...REPORTING_CREDENTIAL_REJECTION_CODES,
    ];
    expect(former).toHaveLength(10);
    const served = new Set(
      former.map((code) => {
        const produced = reportingErrorResponse(code, requestIdFor(8));
        expect(produced.status).toBe(401);
        return (JSON.parse(text(produced.bodyBytes)) as { error: { code: string } }).error.code;
      }),
    );
    // Four request-shape codes verbatim + the one canonical code standing for all six.
    expect(served.size).toBe(5);
    expect(served.has(CANONICAL_AUTH_FAILURE_CODE)).toBe(true);
  });
});
