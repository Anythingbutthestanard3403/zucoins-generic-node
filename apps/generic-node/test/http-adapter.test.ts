//  — raw-capture fidelity tests for the HTTP adapter. Case 2
// (transport side): capture is byte-verbatim end-to-end (tricky targets reach the pipeline
// untouched), absolute-form is rejected fail-closed at the form gate, and a bogus
// X-Original-URL rewrite header is never consulted (the correctly signed request still
// verifies through the REAL pipeline: live store, live signature crypto, golden bytes).

import { describe, expect, it } from "vitest";

import {
  createNodeEventVerifier,
  createReportingRequestHandler,
  createReportingRequestVerifier,
  InMemoryReportingRateLimiter,
  InMemoryReportingStore,
  reportingJsonResponse,
  type CapturedReportRequest,
  type ReportingHttpResponse,
} from "@zucoins/node-core";
import {
  REPORTING_KEY_PUBKEY,
  REPORT_REQUEST_GOLDEN_SIGNATURE,
} from "@zucoins/generic-node-contracts";

import {
  createReportingHttpListener,
  type RawTransportRequest,
  type RawTransportResponse,
} from "../src/http-adapter.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const KEY_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const GOLDEN_TARGET = "/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete";
const MID_WINDOW_MS = Date.parse("2026-07-18T00:00:30.000Z");

interface FakeRequest extends RawTransportRequest {
  readonly bodyPulled: () => boolean;
}

function fakeRequest(input: {
  method?: string;
  url?: string;
  rawHeaders?: readonly string[];
  chunks?: readonly Uint8Array[];
}): FakeRequest {
  let pulled = false;
  return {
    method: input.method ?? "POST",
    url: input.url ?? GOLDEN_TARGET,
    rawHeaders: input.rawHeaders ?? [],
    bodyPulled: () => pulled,
    bodyChunks: (async function* () {
      pulled = true;
      for (const chunk of input.chunks ?? []) yield chunk;
    })(),
  };
}

interface FakeResponse {
  readonly status: () => number;
  readonly headers: () => Readonly<Record<string, string>>;
  readonly body: () => Uint8Array;
  readonly sink: RawTransportResponse;
}

function fakeResponse(): FakeResponse {
  let status = 0;
  let headers: Readonly<Record<string, string>> = {};
  let body = new Uint8Array(0);
  return {
    status: () => status,
    headers: () => headers,
    body: () => body,
    sink: {
      writeHead: (nextStatus, nextHeaders) => {
        status = nextStatus;
        headers = nextHeaders;
      },
      end: (nextBody) => {
        body = nextBody;
      },
    },
  };
}

const GOLDEN_SIGNED_HEADERS: readonly string[] = [
  "X-ZP-Reporting-Key-Id", KEY_ID,
  "X-ZP-Reporting-Timestamp", "2026-07-18T00:00:00.000Z",
  "X-ZP-Reporting-Expires-At", "2026-07-18T00:01:00.000Z",
  "X-ZP-Reporting-Nonce", "99999999-9999-4999-8999-999999999999",
  "X-ZP-Reporting-Signature", REPORT_REQUEST_GOLDEN_SIGNATURE,
  "Idempotency-Key", "idempotency-key-0001",
];

function realPipeline(handlers: Parameters<typeof createReportingRequestHandler>[0]["handlers"]) {
  const store = new InMemoryReportingStore();
  store.seedRegistration({
    reportingKeyId: KEY_ID,
    nodeId: NODE_ID,
    implementerId: IMPLEMENTER_ID,
    publicKeyEncoded: REPORTING_KEY_PUBKEY,
  });
  store.seedRestoreHold(NODE_ID, false);
  store.seedLifecycleHead(NODE_ID, IMPLEMENTER_ID, {
    epoch: 1n,
    authHold: false,
    currentKeyId: KEY_ID,
    priorKeyId: null,
    overlapExpiresAtMs: null,
    successorCommittedAtMs: null,
  });
  store.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, {
    state: "ACTIVE",
    revokedAtMs: null,
  });
  const nowMs = () => MID_WINDOW_MS;
  const verifier = createReportingRequestVerifier({
    nodeId: NODE_ID,
    store,
    rateLimiter: new InMemoryReportingRateLimiter(60_000, 1_000),
    nowMs,
  });
  const handler = createReportingRequestHandler({
    verifier,
    store,
    handlers,
    newRequestId: () => "request-fixed",
    nowMs,
  });
  void createNodeEventVerifier({ store });
  return {
    store,
    listener: createReportingHttpListener({
      handle: handler.handle,
      nowMs,
      maxBodyBytes: 65_536,
      newRequestId: () => "request-fixed",
    }),
  };
}

describe("raw capture fidelity", () => {
  it("captures method, target, headers, and body byte-verbatim before anything else", async () => {
    const seen: CapturedReportRequest[] = [];
    const listener = createReportingHttpListener({
      handle: (captured) => {
        seen.push(captured);
        return Promise.resolve(reportingJsonResponse(200, "{}"));
      },
      nowMs: () => MID_WINDOW_MS,
      maxBodyBytes: 65_536,
      newRequestId: () => "request-fixed",
    });
    const trickyTargets = [
      "/v1/events?after_implementer_seq=1+2",
      "/v1/ev%2Fents",
      "/v1//events",
      "/v1/events?",
      "/v1/events?after_implementer_seq=1&after_implementer_seq=1",
    ];
    const rawHeaders = ["X-Custom", "VaLue", "x-custom", "second"];
    for (const target of trickyTargets) {
      const body = new TextEncoder().encode("{\"a\":1}");
      await listener(
        fakeRequest({ method: "GET", url: target, rawHeaders, chunks: [body.subarray(0, 3), body.subarray(3)] }),
        fakeResponse().sink,
      );
    }
    expect(seen.map((captured) => captured.rawTarget)).toEqual(trickyTargets);
    expect(seen[0]!.method).toBe("GET");
    expect(seen[0]!.rawHeaders).toEqual(rawHeaders);
    expect(new TextDecoder().decode(seen[0]!.bodyBytes)).toBe("{\"a\":1}");
    expect(seen[0]!.receivedAtMs).toBe(MID_WINDOW_MS);
  });

  it("writes the produced status, headers, content-length, and exact body bytes", async () => {
    const listener = createReportingHttpListener({
      handle: () =>
        Promise.resolve({
          status: 200,
          headers: { "content-type": "application/json", "idempotency-replayed": "true" },
          bodyBytes: new TextEncoder().encode("{\"exact\":true}"),
        }),
      nowMs: () => MID_WINDOW_MS,
      maxBodyBytes: 65_536,
      newRequestId: () => "request-fixed",
    });
    const response = fakeResponse();
    await listener(fakeRequest({ chunks: [] }), response.sink);
    expect(response.status()).toBe(200);
    expect(response.headers()["idempotency-replayed"]).toBe("true");
    expect(response.headers()["content-length"]).toBe("14");
    expect(new TextDecoder().decode(response.body())).toBe("{\"exact\":true}");
  });
});

describe("transport-level rejections", () => {
  const okStub = (): Promise<ReportingHttpResponse> =>
    Promise.resolve(reportingJsonResponse(200, "{}"));

  it("rejects a non-identity content-encoding before any body work", async () => {
    const listener = createReportingHttpListener({
      handle: okStub,
      nowMs: () => MID_WINDOW_MS,
      maxBodyBytes: 65_536,
      newRequestId: () => "request-fixed",
    });
    const request = fakeRequest({
      rawHeaders: ["Content-Encoding", "gzip", "Content-Length", "2"],
      chunks: [new Uint8Array(2)],
    });
    const response = fakeResponse();
    await listener(request, response.sink);
    expect(response.status()).toBe(400);
    expect(JSON.parse(new TextDecoder().decode(response.body())).error.code).toBe(
      "unsupported_content_encoding",
    );
    expect(request.bodyPulled()).toBe(false);
  });

  it("rejects a declared oversized body without pulling the body stream", async () => {
    const listener = createReportingHttpListener({
      handle: okStub,
      nowMs: () => MID_WINDOW_MS,
      maxBodyBytes: 8,
      newRequestId: () => "request-fixed",
    });
    const request = fakeRequest({ rawHeaders: ["Content-Length", "9"], chunks: [new Uint8Array(9)] });
    const response = fakeResponse();
    await listener(request, response.sink);
    expect(response.status()).toBe(400);
    expect(JSON.parse(new TextDecoder().decode(response.body())).error.code).toBe("request_too_large");
    expect(request.bodyPulled()).toBe(false);
  });

  it("rejects a streamed body that grows past the cap mid-read", async () => {
    const listener = createReportingHttpListener({
      handle: okStub,
      nowMs: () => MID_WINDOW_MS,
      maxBodyBytes: 8,
      newRequestId: () => "request-fixed",
    });
    const response = fakeResponse();
    await listener(
      fakeRequest({ chunks: [new Uint8Array(5), new Uint8Array(5)] }),
      response.sink,
    );
    expect(response.status()).toBe(400);
    expect(JSON.parse(new TextDecoder().decode(response.body())).error.code).toBe("request_too_large");
  });
});

describe("through the real verification pipeline", () => {
  const handlers = {
    verification_complete: () =>
      Promise.resolve({ response: reportingJsonResponse(200, "{\"served\":true}"), persistChild: () => Promise.resolve("child-1") }),
  };

  it("accepts a correctly signed request carrying a bogus X-Original-URL rewrite header", async () => {
    const { listener, store } = realPipeline(handlers);
    const response = fakeResponse();
    await listener(
      fakeRequest({
        rawHeaders: [...GOLDEN_SIGNED_HEADERS, "X-Original-URL", "/admin/v1/totally-different"],
        chunks: [new TextEncoder().encode("{}")],
      }),
      response.sink,
    );
    expect(response.status()).toBe(200);
    expect(new TextDecoder().decode(response.body())).toBe("{\"served\":true}");
    expect(store.listNonceEvidence().length).toBe(1);
    expect(store.listNonceEvidence()[0]!.rawTarget).toBe(GOLDEN_TARGET);
  });

  it("rejects a duplicated signed header that node would have comma-joined", async () => {
    const { listener, store } = realPipeline(handlers);
    const response = fakeResponse();
    await listener(
      fakeRequest({
        rawHeaders: [
          ...GOLDEN_SIGNED_HEADERS,
          "x-zp-reporting-nonce", "99999999-9999-4999-8999-999999999999",
        ],
        chunks: [new TextEncoder().encode("{}")],
      }),
      response.sink,
    );
    expect(response.status()).toBe(401);
    expect(JSON.parse(new TextDecoder().decode(response.body())).error.code).toBe(
      "missing_reporting_headers",
    );
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("rejects an absolute-form target at the form gate, never reconstructing it", async () => {
    const { listener, store } = realPipeline(handlers);
    const response = fakeResponse();
    await listener(
      fakeRequest({
        method: "GET",
        url: "http://node.example/v1/events?after_implementer_seq=5",
        rawHeaders: GOLDEN_SIGNED_HEADERS,
        chunks: [],
      }),
      response.sink,
    );
    expect(response.status()).toBe(400);
    expect(JSON.parse(new TextDecoder().decode(response.body())).error.code).toBe(
      "invalid_request_target",
    );
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("r2: liveStream hold-open skips content-length end; close on disconnect", async () => {
    let endCalls = 0;
    let writeHeadStatus = 0;
    let streamClosed = false;
    const closeCbs: Array<() => void> = [];
    const chunks: string[] = [];

    const listener = createReportingHttpListener({
      handle: async (_captured, transport) => {
        const sink = transport!.openSink({
          "content-type": "text/event-stream",
          "cache-control": "no-cache",
          connection: "keep-alive",
        });
        sink.write(": connected\n\n");
        return {
          status: 200,
          headers: { "content-type": "text/event-stream" },
          bodyBytes: new Uint8Array(),
          liveStream: {
            close: () => {
              streamClosed = true;
              sink.close();
            },
          },
        };
      },
      nowMs: () => MID_WINDOW_MS,
      maxBodyBytes: 65_536,
      newRequestId: () => "request-fixed",
    });

    await listener(
      {
        method: "GET",
        url: "/v1/events/stream",
        rawHeaders: [],
        bodyChunks: (async function* () {})(),
        onceClose: (cb) => {
          closeCbs.push(cb);
        },
      },
      {
        writeHead: (status) => {
          writeHeadStatus = status;
        },
        write: (chunk) => {
          chunks.push(typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk));
        },
        end: () => {
          endCalls += 1;
        },
        onceClose: (cb) => {
          closeCbs.push(cb);
        },
      },
    );

    expect(writeHeadStatus).toBe(200);
    expect(endCalls).toBe(0);
    expect(chunks.join("")).toContain("connected");
    expect(streamClosed).toBe(false);

    for (const cb of closeCbs) cb();
    expect(streamClosed).toBe(true);
  });
});
