import { describe, expect, it, vi } from "vitest";

import { armOperation } from "./arm.js";
import type { FetchLike } from "./client-types.js";
import type { ReportingCredential, ReportingSigner } from "./reporting-signer.js";

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

describe("armOperation", () => {
  it("POSTs armed with signed reporting headers and idempotency key", async () => {
    const body = {
      operation_id: OP_ID,
      state: "READY",
      row_version: 2,
      code_status: "RELEASED",
      transfer_code: "code",
      transfer_code_sha256: "a".repeat(64),
      expires_at: "2026-07-15T10:31:00.000Z",
    };
    const fetchImpl = vi.fn<FetchLike>(async () =>
      new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } }),
    );
    const request = {
      expected_row_version: 1,
      t0: {
        observation_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
        projection: { s: "", p: "", b_zkz: "0" },
      },
      opened_cursor: "1043",
    };
    const result = await armOperation({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      credential: CREDENTIAL,
      operationId: OP_ID,
      request,
      idempotencyKey: "idem-arm-1",
    });
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(`https://node.example.com/v1/operations/${OP_ID}/armed`);
    expect(init?.method).toBe("POST");
    const headers = init?.headers as Headers;
    expect(headers.get("X-ZP-Reporting-Key-Id")).toBe(KEY_ID);
    expect(headers.get("idempotency-key")).toBe("idem-arm-1");
    expect(JSON.parse(init!.body as string)).toEqual(request);
    expect(result.state).toBe("READY");
  });
});
