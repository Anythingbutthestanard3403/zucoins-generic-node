import { describe, expect, it } from "vitest";
import { createArmRouteHandler } from "./arm-route.js";
import type { ArmPreopenResult, VerifiedReportRequest } from "@zucoins/node-core";

const OP = "33333333-3333-4333-8333-333333333333";
const BODY = JSON.stringify({
  expected_row_version: 2,
  t0: {
    observation_id: "55555555-5555-4555-8555-555555555555",
    projection: { s: "", p: "", b_zkz: "0" },
  },
  opened_cursor: "1043",
});

function verifiedRequest(): VerifiedReportRequest {
  return {
    ok: true,
    binding: {
      nodeId: "11111111-1111-4111-8111-111111111111",
      implementerId: "22222222-2222-4222-8222-222222222222",
      reportingKeyId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    },
    route: { routeId: "operation_armed", requestClass: "MUTATION" },
    nonceEvidence: {
      id: "nonce-row-1",
      nonce: "99999999-9999-4999-8999-999999999999",
      requestPreimageText: "pre",
      requestSignature: "sig",
    },
    idempotencyKey: "idem-1",
    fingerprint: {
      method: "POST",
      rawTarget: `/v1/operations/${OP}/armed`,
      bodySha256: "b".repeat(64),
    },
    bodyBytes: new TextEncoder().encode(BODY),
  } as unknown as VerifiedReportRequest;
}

describe("createArmRouteHandler + commitArm", () => {
  it("invokes commitArm after successful pre-open with matching T0", async () => {
    let seen: Extract<ArmPreopenResult, { ok: true }> | null = null;
    const handler = createArmRouteHandler({
      durableT0: {
        getNodeDurableT0: async () => ({
          observationId: "55555555-5555-4555-8555-555555555555",
          projection: { s: "", p: "", b_zkz: "0" },
        }),
      },
      newRequestId: () => "req-arm",
      commitArm: async (preopen) => {
        seen = preopen;
        const body = JSON.stringify({
          operation_id: OP,
          state: "READY",
          row_version: 3,
          code_status: "RELEASED",
          transfer_code: "code",
          transfer_code_sha256: "a".repeat(64),
          expires_at: "2033-05-18T03:33:20.000Z",
        });
        return {
          response: {
            status: 200,
            headers: { "content-type": "application/json" },
            bodyBytes: new TextEncoder().encode(body),
          },
          persistChild: async () => "arm-1",
        };
      },
    });
    const result = await handler(verifiedRequest());
    expect(seen).not.toBeNull();
    expect(seen!.mismatchField).toBeNull();
    expect(result.response.status).toBe(200);
    const parsed = JSON.parse(new TextDecoder().decode(result.response.bodyBytes));
    expect(parsed.code_status).toBe("RELEASED");
    expect(parsed.transfer_code).toBe("code");
    expect(result.persistChild).not.toBeNull();
  });

  it("returns 503 when commitArm is not wired (fail-closed)", async () => {
    const handler = createArmRouteHandler({
      durableT0: {
        getNodeDurableT0: async () => ({
          observationId: "55555555-5555-4555-8555-555555555555",
          projection: { s: "", p: "", b_zkz: "0" },
        }),
      },
      newRequestId: () => "req-503",
    });
    const result = await handler(verifiedRequest());
    expect(result.response.status).toBe(503);
    expect(result.persistChild).toBeNull();
  });

  it("returns 409 t0_mismatch without calling commitArm", async () => {
    let called = false;
    const handler = createArmRouteHandler({
      durableT0: {
        getNodeDurableT0: async () => ({
          observationId: "55555555-5555-4555-8555-555555555555",
          projection: { s: "different", p: "", b_zkz: "0" },
        }),
      },
      newRequestId: () => "req-mm",
      commitArm: async () => {
        called = true;
        throw new Error("must not run");
      },
    });
    const result = await handler(verifiedRequest());
    expect(called).toBe(false);
    expect(result.response.status).toBe(409);
    const err = JSON.parse(new TextDecoder().decode(result.response.bodyBytes));
    expect(err.error.code).toBe("t0_mismatch");
    expect(result.persistChild).toBeNull();
  });
});
