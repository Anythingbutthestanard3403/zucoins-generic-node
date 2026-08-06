import { describe, expect, it, vi } from "vitest";

import { getVerificationMaterial, postVerificationComplete } from "./verification.js";
import type { FetchLike } from "./client-types.js";
import type { ReportingCredential, ReportingSigner } from "./reporting-signer.js";
import type { VerificationCompleteRequest } from "../types.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const KEY_ID = "33333333-3333-4333-8333-333333333333";
const OP_ID = "55555555-5555-4555-8555-555555555560";

const CREDENTIAL: ReportingCredential = {
  nodeId: NODE_ID,
  implementerId: IMPLEMENTER_ID,
  keyId: KEY_ID,
  signer: { async sign(): Promise<string> { return "stub-signature"; } } satisfies ReportingSigner,
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("getVerificationMaterial", () => {
  it("GETs the verification-material route with signed reporting headers", async () => {
    const material = {
      operation_id: OP_ID,
      operation_type: "RECEIVE_EXTERNAL",
      state: "RECEIVE_LANDED",
      expected_artifact: { key_id: KEY_ID, preimage_text: "t", preimage_sha256: "a".repeat(64), signature: "s" },
      observation_evidence: [],
    };
    const fetchImpl = vi.fn<FetchLike>(async () => jsonResponse(200, material));

    const result = await getVerificationMaterial({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      credential: CREDENTIAL,
      operationId: OP_ID,
    });

    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(`https://node.example.com/v1/operations/${OP_ID}/verification-material`);
    expect(init?.method).toBe("GET");
    expect((init?.headers as Headers).get("X-ZP-Reporting-Key-Id")).toBe(KEY_ID);
    expect(result).toEqual(material);
  });

  it("surfaces 409 verification_material_not_ready as NodeApiError", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      jsonResponse(409, {
        error: { code: "verification_material_not_ready", message: "not ready", request_id: "r", details: {} },
      }),
    );
    await expect(
      getVerificationMaterial({
        config: { baseUrl: "https://node.example.com", fetchImpl },
        credential: CREDENTIAL,
        operationId: OP_ID,
      }),
    ).rejects.toMatchObject({ code: "verification_material_not_ready" });
  });
});

describe("postVerificationComplete", () => {
  it("POSTs the exact request body with signed headers and the idempotency key", async () => {
    const request: VerificationCompleteRequest = {
      expected_row_version: 7,
      consumed_cursor: "1051",
      verdict: "VERIFIED",
      wallet_evidence: [
        {
          wallet_id: "w1",
          role: "RECEIVER",
          t0: { observation_id: "o1", projection: { s: "", p: "", b_zkz: "0" } },
          terminal: { observation_id: "o2", projection: { s: "sig", p: "", b_zkz: "2.25" } },
          landing_proof: {
            classification: "EXPECTED_AT_HEAD",
            fresh_head_step_2_signature: "sig",
            fresh_head_transaction_sha256: "a".repeat(64),
            path_manifest_sha256: "b".repeat(64),
          },
        },
      ],
    };
    const responseBody = {
      operation_id: OP_ID,
      acknowledgement_id: "ack-1",
      verdict: "VERIFIED",
      lease_release_status: "RELEASED",
      acknowledged_at: "2026-07-15T10:31:00.000Z",
    };
    const fetchImpl = vi.fn<FetchLike>(async () => jsonResponse(200, responseBody));

    const result = await postVerificationComplete({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      credential: CREDENTIAL,
      operationId: OP_ID,
      request,
      idempotencyKey: "idem-vc-1",
    });

    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(`https://node.example.com/v1/operations/${OP_ID}/verification-complete`);
    expect(init?.method).toBe("POST");
    const headers = init?.headers as Headers;
    expect(headers.get("X-ZP-Reporting-Key-Id")).toBe(KEY_ID);
    expect(headers.get("idempotency-key")).toBe("idem-vc-1");
    expect(JSON.parse(init!.body as string)).toEqual(request);
    expect(result.acknowledgement_id).toBe("ack-1");
  });
});
