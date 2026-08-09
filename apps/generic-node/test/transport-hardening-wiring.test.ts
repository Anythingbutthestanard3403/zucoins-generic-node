// Transport hardening is WIRED (ZTR-1186).
//
// packages/node-core/src/api/transport-hardening.ts was fully implemented, fully unit-tested
// and called by nothing: main.ts created its server with no options, so node's own 300 s
// requestTimeout / 60 s headersTimeout held, and no intake guard ran. The module's unit tests
// (packages/node-core/test/transport-hardening.test.ts) still cover the pure functions; this
// file covers the wiring — that the production server carries the limits and that the JSON
// route surface, and only the JSON route surface, runs the intake guards.
//
// Declared ceiling: the network guard (test/setup-network-guard.ts) makes a loopback
// round-trip impossible, so the server here is created but never listened on, and the
// listener is driven through the same in-process request/response seam runtime-listener.test.ts
// uses. Coverage of main.ts's own call is therefore a source-level gate, not a boot.

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { describe, expect, it } from "vitest";

import {
  createFailClosedOperationStore,
  createImplementerBearerAuth,
  DEFAULT_HEADERS_TIMEOUT_MS,
  DEFAULT_MAX_HEADER_BYTES,
  DEFAULT_REQUEST_TIMEOUT_MS,
  PUSH_RECEIVER_PATH_PREFIX,
} from "@zucoins/node-core";

import {
  createNodeRuntimeListener,
  HARDENED_HTTP_SERVER_OPTIONS,
  type NodeRuntimeListenerDeps,
} from "../src/runtime-listener.js";
import { NodeReadiness } from "../src/boot/readiness.js";

const TEST_TOKEN = "ik_test_transport_hardening_token01";
const TEST_AUTH = createImplementerBearerAuth({
  keys: [{ token: TEST_TOKEN, implementerId: "impl-test", scopes: ["receive:create", "receive:read"] }],
});
const AUTH_HEADER = { authorization: `Bearer ${TEST_TOKEN}` };

interface Captured {
  status: number;
  headers: Record<string, string>;
  body: string;
}

function baseDeps(overrides: Partial<NodeRuntimeListenerDeps> = {}): NodeRuntimeListenerDeps {
  return {
    readiness: new NodeReadiness(3),
    pingDb: async () => {
      throw new Error("database adapter is not wired in this test");
    },
    operationStore: createFailClosedOperationStore(),
    operationAuth: TEST_AUTH,
    newRequestId: () => randomUUID(),
    // Pinned so the non-/v1 branch is the health listener deterministically, whether or not
    // the operator SPA happens to be built in this working tree.
    adminSpaDist: null,
    embedDistRoot: null,
    ...overrides,
  };
}

function mockRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body?: Uint8Array,
  httpVersion = "1.1",
): IncomingMessage {
  const chunks = body === undefined ? [] : [body];
  return {
    method,
    url,
    httpVersion,
    headers,
    rawHeaders: Object.entries(headers).flatMap(([name, value]) => [name, value]),
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) yield chunk;
    },
  } as unknown as IncomingMessage;
}

function invoke(
  deps: NodeRuntimeListenerDeps,
  method: string,
  url: string,
  headers: Record<string, string> = {},
  body?: Uint8Array,
  httpVersion = "1.1",
): Promise<Captured> {
  const listener = createNodeRuntimeListener(deps);
  return new Promise<Captured>((resolve) => {
    const captured: Captured = { status: 0, headers: {}, body: "" };
    const response = {
      writeHead(status: number, responseHeaders: Record<string, string> = {}) {
        captured.status = status;
        captured.headers = responseHeaders;
      },
      end(payload?: string | Uint8Array) {
        captured.body =
          typeof payload === "string" ? payload : Buffer.from(payload ?? "").toString("utf8");
        resolve(captured);
      },
      write() {
        return true;
      },
    } as unknown as ServerResponse;
    listener(mockRequest(method, url, headers, body, httpVersion), response);
  });
}

/** Headers a client that actually sends a JSON body would carry. */
function jsonBody(value: unknown): { headers: Record<string, string>; body: Uint8Array } {
  const body = new TextEncoder().encode(JSON.stringify(value));
  return {
    headers: { "content-type": "application/json", "content-length": String(body.length) },
    body,
  };
}

function errorCodeOf(captured: Captured): string {
  return (JSON.parse(captured.body) as { error: { code: string } }).error.code;
}

const RECEIVE_BODY = { amount_zkz: "5.5", anchor: "ord_01J2", after_landing: { kind: "HOLD", destination_id: null } };

describe("hardened node:http server options", () => {
  it("a server built with them carries the module's timeouts, not node's defaults", () => {
    const server = createServer(HARDENED_HTTP_SERVER_OPTIONS, () => {});
    try {
      expect(server.requestTimeout).toBe(30_000);
      expect(server.headersTimeout).toBe(10_000);
      // The values are the module's, not coincidences.
      expect(server.requestTimeout).toBe(DEFAULT_REQUEST_TIMEOUT_MS);
      expect(server.headersTimeout).toBe(DEFAULT_HEADERS_TIMEOUT_MS);
      expect(server.maxHeadersCount).not.toBe(undefined);
    } finally {
      server.close();
    }
  });

  it("options object carries maxHeaderSize from the module", () => {
    expect(HARDENED_HTTP_SERVER_OPTIONS.maxHeaderSize).toBe(DEFAULT_MAX_HEADER_BYTES);
  });

  // The wiring gate. A server built in this file proves the OPTIONS are right; only reading
  // main.ts proves production passes them. Declared ceiling: stage1-main.ts (zero custody)
  // is NOT covered — it creates its own server with no options, deliberately, because
  // importing these would put the whole @zucoins/node-core barrel into a process that today
  // has no value-import path to it at all (see the non-reacher list in
  // submit-write-path-reach.guard.test.ts).
  it("main.ts passes the options to createServer", () => {
    const source = readFileSync(new URL("../src/main.ts", import.meta.url), "utf8");
    expect(source).toContain("HARDENED_HTTP_SERVER_OPTIONS");
    expect(
      /createServer\(\s*HARDENED_HTTP_SERVER_OPTIONS\s*,/.test(source),
      "main.ts must pass HARDENED_HTTP_SERVER_OPTIONS as createServer's first argument",
    ).toBe(true);
  });
});

describe("intake guards on the JSON route surface", () => {
  it("a non-JSON body on a JSON route is rejected 415 unsupported_content_type", async () => {
    const body = new TextEncoder().encode("amount_zkz=5.5");
    const res = await invoke(baseDeps(), "POST", "/v1/receives", {
      ...AUTH_HEADER,
      "content-type": "application/x-www-form-urlencoded",
      "content-length": String(body.length),
      "idempotency-key": "idem-transport-hardening-0000000001",
    }, body);
    expect(res.status).toBe(415);
    expect(errorCodeOf(res)).toBe("unsupported_content_type");
  });

  it("text/plain carrying valid JSON is rejected too — the header is the check", async () => {
    const { body } = jsonBody(RECEIVE_BODY);
    const res = await invoke(baseDeps(), "POST", "/v1/receives", {
      ...AUTH_HEADER,
      "content-type": "text/plain",
      "content-length": String(body.length),
      "idempotency-key": "idem-transport-hardening-0000000002",
    }, body);
    expect(res.status).toBe(415);
  });

  it("application/json with a charset parameter is accepted", async () => {
    const { body } = jsonBody(RECEIVE_BODY);
    const res = await invoke(baseDeps(), "POST", "/v1/receives", {
      ...AUTH_HEADER,
      "content-type": "application/json; charset=utf-8",
      "content-length": String(body.length),
      "idempotency-key": "idem-transport-hardening-0000000003",
    }, body);
    // Fail-closed store — what matters is that the transport layer let it through.
    expect(res.status).not.toBe(415);
  });

  it("HTTP/1.0 is rejected 505 http_version_too_old", async () => {
    const res = await invoke(baseDeps(), "GET", "/v1/receives/" + randomUUID(), AUTH_HEADER, undefined, "1.0");
    expect(res.status).toBe(505);
    expect(errorCodeOf(res)).toBe("http_version_too_old");
  });

  it("a GET carries no Content-Type and is not rejected for the absence of one", async () => {
    const res = await invoke(baseDeps(), "GET", "/v1/receives/" + randomUUID(), AUTH_HEADER);
    expect(res.status).not.toBe(415);
  });

  it("a bodiless POST is not rejected for the absence of a Content-Type", async () => {
    const res = await invoke(baseDeps(), "POST", "/admin/v1/destinations/d1/bless", {
      ...AUTH_HEADER,
      "idempotency-key": "idem-transport-hardening-0000000004",
    });
    expect(res.status).not.toBe(415);
  });

  // Non-oracular: the verdict is computed from the request's own headers, so an absent route
  // and a mounted one answer identically. A caller learns nothing about what exists here.
  it("a transport rejection does not distinguish an existing route from an absent one", async () => {
    const body = new TextEncoder().encode("not json");
    const headers = {
      "content-type": "text/plain",
      "content-length": String(body.length),
    };
    const mounted = await invoke(baseDeps(), "POST", "/v1/receives", headers, body);
    const absent = await invoke(baseDeps(), "POST", "/v1/no-such-route-at-all", headers, body);
    expect(mounted.status).toBe(absent.status);
    expect(errorCodeOf(mounted)).toBe(errorCodeOf(absent));
  });

  // A lying Content-Length must not become a second body-size verdict: readBoundedBody stays
  // the single enforcement point for the cap.
  it("an over-cap declared Content-Length is not rejected at the transport layer", async () => {
    const { body } = jsonBody(RECEIVE_BODY);
    const res = await invoke(baseDeps(), "POST", "/v1/receives", {
      ...AUTH_HEADER,
      "content-type": "application/json",
      "content-length": "999999999",
      "idempotency-key": "idem-transport-hardening-0000000005",
    }, body);
    expect(res.status).not.toBe(415);
    expect(res.status).not.toBe(413);
  });
});

describe("surfaces the intake guards must not touch", () => {
  it("the inbound Web Push delivery route still accepts its binary aes128gcm body", async () => {
    const delivered: Buffer[] = [];
    const binary = new Uint8Array([0x00, 0x01, 0xff, 0xfe, 0x80, 0x7f]);
    const res = await invoke(
      baseDeps({
        onPushDelivery: async (_endpointId, payload) => {
          delivered.push(payload);
        },
      }),
      "POST",
      `${PUSH_RECEIVER_PATH_PREFIX}/endpoint-id-abc`,
      { "content-type": "application/octet-stream", "content-encoding": "aes128gcm", "content-length": String(binary.length) },
      binary,
    );
    expect(res.status).toBe(204);
    expect(delivered).toHaveLength(1);
    expect([...delivered[0]!]).toEqual([...binary]);
  });

  it("the origin-relay deposit still answers 204 whatever its Content-Type", async () => {
    const deposits: unknown[] = [];
    const body = new TextEncoder().encode(JSON.stringify({ action_name: "x" }));
    const res = await invoke(
      baseDeps({ onReceiverChannelDeposit: (raw) => void deposits.push(raw) }),
      "POST",
      "/v1/receivers/origin-relay",
      { "content-type": "text/plain", "content-length": String(body.length) },
      body,
    );
    expect(res.status).toBe(204);
    expect(deposits).toHaveLength(1);
  });

  it("a non-/v1 asset path is unaffected — it never reaches the JSON intake guards", async () => {
    const res = await invoke(baseDeps(), "GET", "/assets/index-abc123.css", {
      "content-type": "text/css",
      "content-length": "42",
    });
    // adminSpaDist is null here, so the health listener answers; the point is that it is the
    // health listener answering and not a 415 from the JSON surface.
    expect(res.status).not.toBe(415);
    expect(res.status).toBe(404);
  });

  it("/health is unaffected", async () => {
    const res = await invoke(baseDeps(), "GET", "/health");
    expect(res.status).toBe(200);
  });
});
