// Zod schema validation for the centralized error envelope.

import { describe, expect, it } from "vitest";
import {
  ApiErrorEnvelopeSchema,
  ApiErrorCodeSchema,
  API_ERROR_CODES,
  apiErrorResponse,
  buildApiErrorBody,
  HTTP_STATUS_BY_CODE,
} from "../src/api/error-envelope.js";

const TEST_REQUEST_ID = "7b8bb326-0f2b-4dad-a8e7-40115b375ec4";

describe("ApiErrorCodeSchema", () => {
  it("accepts every code in API_ERROR_CODES", () => {
    for (const { code } of API_ERROR_CODES) {
      expect(ApiErrorCodeSchema.safeParse(code).success).toBe(true);
    }
  });

  it("rejects unknown codes", () => {
    expect(ApiErrorCodeSchema.safeParse("not_a_real_code").success).toBe(false);
    expect(ApiErrorCodeSchema.safeParse("").success).toBe(false);
    expect(ApiErrorCodeSchema.safeParse(42).success).toBe(false);
  });
});

describe("ApiErrorEnvelopeSchema", () => {
  it("validates every envelope produced by apiErrorResponse", () => {
    for (const { code } of API_ERROR_CODES) {
      const response = apiErrorResponse(code, TEST_REQUEST_ID);
      const parsed = JSON.parse(response.body);
      const result = ApiErrorEnvelopeSchema.safeParse(parsed);
      expect(result.success, `envelope for ${code} must validate`).toBe(true);
    }
  });

  it("validates a minimal well-formed envelope", () => {
    const envelope = {
      error: {
        code: "wallet_busy",
        message: "The selected wallet already has an active operation.",
        request_id: TEST_REQUEST_ID,
        details: {},
      },
    };
    expect(ApiErrorEnvelopeSchema.safeParse(envelope).success).toBe(true);
  });

  it("rejects envelope with missing error key", () => {
    expect(ApiErrorEnvelopeSchema.safeParse({ code: "not_found" }).success).toBe(false);
  });

  it("rejects envelope with unknown top-level keys", () => {
    const envelope = {
      error: {
        code: "not_found",
        message: "msg",
        request_id: TEST_REQUEST_ID,
        details: {},
      },
      extra: true,
    };
    expect(ApiErrorEnvelopeSchema.safeParse(envelope).success).toBe(false);
  });

  it("rejects envelope with unknown keys inside error", () => {
    const envelope = {
      error: {
        code: "not_found",
        message: "msg",
        request_id: TEST_REQUEST_ID,
        details: {},
        secret: "leaked",
      },
    };
    expect(ApiErrorEnvelopeSchema.safeParse(envelope).success).toBe(false);
  });

  it("rejects envelope with invalid error code", () => {
    const envelope = {
      error: {
        code: "forbidden",
        message: "msg",
        request_id: TEST_REQUEST_ID,
        details: {},
      },
    };
    expect(ApiErrorEnvelopeSchema.safeParse(envelope).success).toBe(false);
  });

  it("rejects envelope with non-uuid request_id", () => {
    const envelope = {
      error: {
        code: "not_found",
        message: "msg",
        request_id: "not-a-uuid",
        details: {},
      },
    };
    expect(ApiErrorEnvelopeSchema.safeParse(envelope).success).toBe(false);
  });

  it("rejects envelope with non-empty details", () => {
    const envelope = {
      error: {
        code: "not_found",
        message: "msg",
        request_id: TEST_REQUEST_ID,
        details: { leaked: "data" },
      },
    };
    expect(ApiErrorEnvelopeSchema.safeParse(envelope).success).toBe(false);
  });

  it("rejects envelope with missing message", () => {
    const envelope = {
      error: {
        code: "not_found",
        request_id: TEST_REQUEST_ID,
        details: {},
      },
    };
    expect(ApiErrorEnvelopeSchema.safeParse(envelope).success).toBe(false);
  });
});

describe("buildApiErrorBody round-trips through schema", () => {
  it("every code produces a schema-valid JSON body", () => {
    for (const { code } of API_ERROR_CODES) {
      const body = buildApiErrorBody(code, TEST_REQUEST_ID);
      const parsed = JSON.parse(body);
      const result = ApiErrorEnvelopeSchema.safeParse(parsed);
      expect(result.success, `buildApiErrorBody(${code}) must be schema-valid`).toBe(true);
      if (result.success) {
        expect(result.data.error.code).toBe(code);
        expect(result.data.error.request_id).toBe(TEST_REQUEST_ID);
      }
    }
  });

  it("custom message override is preserved", () => {
    const body = buildApiErrorBody("rate_limited", TEST_REQUEST_ID, "Custom limit hit.");
    const parsed = JSON.parse(body);
    const result = ApiErrorEnvelopeSchema.safeParse(parsed);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.error.message).toBe("Custom limit hit.");
    }
  });
});

describe("HTTP_STATUS_BY_CODE completeness", () => {
  it("has an entry for every code in API_ERROR_CODES", () => {
    for (const { code, http } of API_ERROR_CODES) {
      expect(HTTP_STATUS_BY_CODE[code]).toBe(http);
    }
  });

  it("no 403 exists", () => {
    const statuses = Object.values(HTTP_STATUS_BY_CODE);
    expect(statuses).not.toContain(403);
  });
});

describe("apiErrorResponse Retry-After (UP-11)", () => {
  it("omits Retry-After when retryAfterSeconds is not supplied", () => {
    const response = apiErrorResponse("rate_limited", TEST_REQUEST_ID);
    expect(response.headers["Retry-After"]).toBeUndefined();
    expect(response.headers["content-type"]).toBe("application/json; charset=utf-8");
  });

  it("emits Retry-After when retryAfterSeconds is supplied", () => {
    const response = apiErrorResponse("receive_queue_full", TEST_REQUEST_ID, undefined, 30);
    expect(response.status).toBe(503);
    expect(response.headers["Retry-After"]).toBe("30");
    expect(response.headers["content-type"]).toBe("application/json; charset=utf-8");
  });

  it("emits Retry-After for idempotency_in_progress", () => {
    const response = apiErrorResponse("idempotency_in_progress", TEST_REQUEST_ID, undefined, 1);
    expect(response.status).toBe(409);
    expect(response.headers["Retry-After"]).toBe("1");
  });
});
