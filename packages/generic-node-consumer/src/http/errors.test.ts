import { describe, expect, it } from "vitest";

import {
  assertOk,
  assignCapacityReason,
  NodeApiError,
  readNodeApiError,
} from "./errors.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("readNodeApiError", () => {
  it("parses the frozen error envelope", async () => {
    const response = jsonResponse(409, {
      error: {
        code: "wallet_busy",
        message: "The selected wallet already has an active operation.",
        request_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
        details: {},
      },
    });
    const err = await readNodeApiError(response);
    expect(err).toBeInstanceOf(NodeApiError);
    expect(err.status).toBe(409);
    expect(err.code).toBe("wallet_busy");
    expect(err.requestId).toBe("7b8bb326-0f2b-4dad-a8e7-40115b375ec4");
    expect(err.message).toMatch(/active operation/);
  });

  it("fails closed on a malformed envelope rather than throwing an unrelated error", async () => {
    const response = new Response("not json", { status: 500 });
    const err = await readNodeApiError(response);
    expect(err.code).toBe("malformed_error_envelope");
    expect(err.status).toBe(500);
  });

  it("fails closed when the body is valid JSON but not the error shape", async () => {
    const response = jsonResponse(400, { oops: true });
    const err = await readNodeApiError(response);
    expect(err.code).toBe("malformed_error_envelope");
  });
});

describe("assertOk", () => {
  it("is a no-op for a 2xx response", async () => {
    await expect(assertOk(new Response("{}", { status: 201 }))).resolves.toBeUndefined();
  });

  it("throws NodeApiError for a non-2xx response", async () => {
    const response = jsonResponse(422, {
      error: { code: "impossible_shape", message: "nope", request_id: "r1", details: {} },
    });
    await expect(assertOk(response)).rejects.toMatchObject({ code: "impossible_shape" });
  });
});

describe("assignCapacityReason (ZTR-1309)", () => {
  it("maps 503 service_unavailable + details.reason=no_free_send_worker", async () => {
    const err = await readNodeApiError(
      jsonResponse(503, {
        error: {
          code: "service_unavailable",
          message: "The service is temporarily unavailable.",
          request_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
          details: { reason: "no_free_send_worker" },
        },
      }),
    );
    expect(err.status).toBe(503);
    expect(err.code).toBe("service_unavailable");
    expect(assignCapacityReason(err)).toBe("no_free_send_worker");
  });

  it("maps sibling assign-capacity reasons", async () => {
    for (const reason of [
      "no_hub_liquidity",
      "halted",
      "assign_not_wired",
      "worker_destination_missing",
      "move_rejected",
    ] as const) {
      const err = await readNodeApiError(
        jsonResponse(503, {
          error: {
            code: "service_unavailable",
            message: "The service is temporarily unavailable.",
            request_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
            details: { reason },
          },
        }),
      );
      expect(assignCapacityReason(err), reason).toBe(reason);
    }
  });

  it("does not treat a bare 503 outage as an assign-capacity reason", async () => {
    const err = await readNodeApiError(
      jsonResponse(503, {
        error: {
          code: "service_unavailable",
          message: "The service is temporarily unavailable.",
          request_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
          details: {},
        },
      }),
    );
    expect(assignCapacityReason(err)).toBeUndefined();
  });
});
