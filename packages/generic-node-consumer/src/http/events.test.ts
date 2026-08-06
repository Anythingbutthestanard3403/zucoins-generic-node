import { describe, expect, it, vi } from "vitest";

import { buildEventsRawTarget, getEvents } from "./events.js";
import type { FetchLike } from "./client-types.js";
import type { ReportingCredential, ReportingSigner } from "./reporting-signer.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const KEY_ID = "33333333-3333-4333-8333-333333333333";

const STUB_SIGNER: ReportingSigner = {
  async sign(): Promise<string> {
    return "stub-signature";
  },
};

const CREDENTIAL: ReportingCredential = {
  nodeId: NODE_ID,
  implementerId: IMPLEMENTER_ID,
  keyId: KEY_ID,
  signer: STUB_SIGNER,
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("buildEventsRawTarget", () => {
  it("emits no query when the query is empty", () => {
    expect(buildEventsRawTarget()).toBe("/v1/events");
  });

  it("emits query keys in the frozen ascending-ASCII order", () => {
    expect(
      buildEventsRawTarget({ afterImplementerSeq: "1043", limit: 100, waitSeconds: 30 }),
    ).toBe("/v1/events?after_implementer_seq=1043&limit=100&wait_seconds=30");
  });

  it("omits absent fields without reordering the rest", () => {
    expect(buildEventsRawTarget({ limit: 50 })).toBe("/v1/events?limit=50");
  });
});

describe("getEvents", () => {
  it("GETs /v1/events with the five signed reporting headers and the exact raw target", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      jsonResponse(200, {
        events: [],
        implementer_watermark_seq: "1043",
        next_after_implementer_seq: "1043",
      }),
    );

    const result = await getEvents({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      credential: CREDENTIAL,
      query: { afterImplementerSeq: "1000", limit: 100, waitSeconds: 0 },
    });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(
      "https://node.example.com/v1/events?after_implementer_seq=1000&limit=100&wait_seconds=0",
    );
    expect(init?.method).toBe("GET");
    const headers = init?.headers as Headers;
    expect(headers.get("X-ZP-Reporting-Key-Id")).toBe(KEY_ID);
    expect(headers.get("X-ZP-Reporting-Signature")).toBe("stub-signature");
    expect(result.next_after_implementer_seq).toBe("1043");
  });

  it("returns each served item as the opaque artifact envelope, unparsed", async () => {
    const envelope = {
      key_id: KEY_ID,
      preimage_text: "zp-implementer-event-v1\n{}",
      preimage_sha256: "a".repeat(64),
      signature: "sig",
    };
    const fetchImpl = vi.fn<FetchLike>(async () =>
      jsonResponse(200, {
        events: [envelope],
        implementer_watermark_seq: "42",
        next_after_implementer_seq: "42",
      }),
    );
    const result = await getEvents({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      credential: CREDENTIAL,
    });
    expect(result.events).toEqual([envelope]);
  });

  it("carries the checkpoints[] durable proof stream through unparsed", async () => {
    const checkpoint = {
      key_id: KEY_ID,
      preimage_text: "zp-implementer-checkpoint-v1\n{}",
      preimage_sha256: "b".repeat(64),
      signature: "checkpoint-sig",
    };
    const fetchImpl = vi.fn<FetchLike>(async () =>
      jsonResponse(200, {
        events: [],
        checkpoints: [checkpoint],
        implementer_watermark_seq: "42",
        next_after_implementer_seq: "42",
      }),
    );
    const result = await getEvents({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      credential: CREDENTIAL,
    });
    expect(result.checkpoints).toEqual([checkpoint]);
  });
});
