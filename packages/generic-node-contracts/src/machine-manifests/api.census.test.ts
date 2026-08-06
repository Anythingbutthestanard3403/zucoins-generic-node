import { describe, expect, it } from "vitest";

import { AUTH_ERROR_CODES, REJECTED_AUTH_ERROR_CODES } from "../auth-errors/codes.ts";
import { ERROR_ENVELOPE_FIELD_ORDER } from "../auth-errors/envelope.ts";
import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  API_CONTRACT_VERSION,
  API_ERROR_ENVELOPE_FIELD_SEQUENCE,
  API_ERROR_ENVELOPE_OUTER_KEY,
  API_ERROR_ENVELOPE_RULES,
  API_STATUS_TABLE,
  API_WIRE_CONVENTIONS,
} from "./api.contract.ts";

describe("api census (wire conventions, error envelope; the frozen error vocabulary)", () => {
  it("freezes the nine-row the error-envelope contract status table, in sequence", () => {
    assertFieldOrder(
      API_STATUS_TABLE.map((row) => row.status),
      [400, 401, 403, 404, 409, 410, 422, 429, 503],
    );
  });

  it("resolves the 403 row to the frozen error vocabulary's generic-401 posture (no 403 auth-error code)", () => {
    const row403 = API_STATUS_TABLE.find((row) => row.status === 403);
    expect(row403?.resolution).toContain("scope denial collapses");
    expect(AUTH_ERROR_CODES.map((entry) => entry.http)).not.toContain(403);
    expect(REJECTED_AUTH_ERROR_CODES.map((entry) => entry.http)).toEqual([403, 403, 404]);
  });

  it("restated envelope field sequence agrees with the auth-errors owner (two-source gate)", () => {
    expect(API_ERROR_ENVELOPE_OUTER_KEY).toBe("error");
    assertFieldOrder(API_ERROR_ENVELOPE_FIELD_SEQUENCE, [...ERROR_ENVELOPE_FIELD_ORDER]);
  });

  it("freezes the envelope semantics (the error-envelope contract)", () => {
    expect(API_ERROR_ENVELOPE_RULES.messageIsDiagnosticNotStable).toBe(true);
    expect(API_ERROR_ENVELOPE_RULES.clientsBranchOnCodeOnly).toBe(true);
    assertFieldOrder(API_ERROR_ENVELOPE_RULES.detailsNeverContains, [
      "secrets",
      "raw signed bodies",
      "gateway responses",
      "existence information outside the caller's tenant",
    ]);
  });

  it("freezes the wire conventions", () => {
    expect(API_WIRE_CONVENTIONS.mediaType).toBe("application/json; charset=utf-8");
    expect(API_WIRE_CONVENTIONS.propertyNames).toBe("lower snake_case");
    expect(API_WIRE_CONVENTIONS.amounts).toContain("JSON numbers rejected");
    expect(API_WIRE_CONVENTIONS.unknownRequestProperties).toBe("rejected with 400 unknown_field");
    expect(API_WIRE_CONVENTIONS.operationStateField).toBe("state");
    expect(API_WIRE_CONVENTIONS.eventTypeField).toBe("type");
    expect(API_WIRE_CONVENTIONS.operationTypeField).toBe("operation_type");
    expect(API_WIRE_CONVENTIONS.idempotencyKey.header).toBe("Idempotency-Key");
    expect(API_WIRE_CONVENTIONS.idempotencyKey.acceptedLength).toBe(
      "16-255 visible ASCII characters",
    );
    expect(API_WIRE_CONVENTIONS.idempotencyKey.replayHeader).toBe("Idempotency-Replayed: true");
  });

  it("rejects a reordered status table (negative path)", () => {
    expectRejects(
      () => API_STATUS_TABLE.map((row) => row.status).reverse(),
      (mutated) =>
        assertFieldOrder(
          mutated,
          API_STATUS_TABLE.map((row) => row.status),
        ),
    );
  });

  it("rejects a 403 auth-error code reintroduction (the frozen error vocabulary, negative path)", () => {
    expectRejects(
      () => [...AUTH_ERROR_CODES, { code: "forbidden", http: 403 }],
      (mutated) => assertFieldOrder(mutated, [...AUTH_ERROR_CODES]),
    );
  });

  it("pins the manifest version", () => {
    expect(API_CONTRACT_VERSION).toBe(1);
  });
});
