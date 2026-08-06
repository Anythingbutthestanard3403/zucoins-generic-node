import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";

import {
  createPushGatewayActions,
  PushGatewayRejectedError,
  PushGatewayUnavailableError,
} from "./gateway-actions.js";

const PUSH_API_BASE = "https://wallet.zucoins.com/api__v1/";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function decodeBody(init: RequestInit): unknown {
  const raw = Buffer.isBuffer(init.body)
    ? init.body.toString("utf-8")
    : String(init.body);
  return JSON.parse(decodeURIComponent(raw.slice("v=".length)));
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("subscribe", () => {
  test("posts push_notification__subscribe__v1 with the wire shape verbatim", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ status: true, code: "ok", message: "OK", data: {} }));
    const gateway = createPushGatewayActions({ pushApiBase: PUSH_API_BASE });

    await gateway.subscribe({
      idProofQuery: "utm_source=zupayments_node_v1&…",
      endpoint: "https://node.example/v1/receivers/push/wp_abc123",
      keyP256dh: "node-p256dh-pub",
      keyAuth: "node-auth-secret",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, init] = fetchMock.mock.calls[0];
    expect(calledUrl).toBe(PUSH_API_BASE.replace(/\/+$/u, ""));
    const parsed = decodeBody(init) as { action_name: string; action_data: unknown };
    expect(parsed.action_name).toBe("push_notification__subscribe__v1");
    expect(parsed.action_data).toEqual({
      id_proof__url_query: "utm_source=zupayments_node_v1&…",
      subscription: {
        endpoint: "https://node.example/v1/receivers/push/wp_abc123",
        key_p256dh: "node-p256dh-pub",
        key_auth: "node-auth-secret",
      },
    });
  });

  test("throws PushGatewayRejectedError on an application-layer status:false", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ status: false, code: "rate_limited", message: "slow down", data: null }),
    );
    const gateway = createPushGatewayActions({ pushApiBase: PUSH_API_BASE });

    await expect(
      gateway.subscribe({
        idProofQuery: "q",
        endpoint: "e",
        keyP256dh: "p",
        keyAuth: "a",
      }),
    ).rejects.toThrow(PushGatewayRejectedError);
  });
});

describe("hasSubscriptionForPublicKey", () => {
  test("posts the base64urlsafe action and reads the envelope status, not data", async () => {
    // `data` is an empty array both when subscribed and not — reading it would always
    // report false. Only `status` carries the signal.
    fetchMock.mockResolvedValueOnce(jsonResponse({ status: true, code: "ok", message: "OK", data: [] }));
    const gateway = createPushGatewayActions({ pushApiBase: PUSH_API_BASE });

    const result = await gateway.hasSubscriptionForPublicKey("wallet-pub-b64url");

    expect(result).toBe(true);
    const parsed = decodeBody(fetchMock.mock.calls[0][1]) as { action_name: string; action_data: unknown };
    expect(parsed.action_name).toBe(
      "push_notification__has_subscription_for_public_key_base64urlsafe__v1",
    );
    expect(parsed.action_data).toEqual({ wallet_key_public__base64urlsafe: "wallet-pub-b64url" });
  });

  test("returns false when status is false", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ status: false, code: "not_found", message: "", data: [] }));
    const gateway = createPushGatewayActions({ pushApiBase: PUSH_API_BASE });

    expect(await gateway.hasSubscriptionForPublicKey("wallet-pub-b64url")).toBe(false);
  });
});

describe("getAppServerPublicKey — app-server key discovery", () => {
  const rawKeyBytes = Buffer.alloc(65, 0xab);
  rawKeyBytes[0] = 0x04;

  test("reads data.key_public__base64urlsafenopad and accepts a standard-base64 value", async () => {
    const standard = rawKeyBytes.toString("base64"); // contains '+'/'/' or padding in general
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ status: true, code: "ok", message: "OK", data: { key_public__base64urlsafenopad: standard } }),
    );
    const gateway = createPushGatewayActions({ pushApiBase: PUSH_API_BASE });

    const key = await gateway.getAppServerPublicKey();

    expect(key).toBe(standard);
    const parsed = decodeBody(fetchMock.mock.calls[0][1]) as { action_name: string; action_data: unknown };
    expect(parsed.action_name).toBe("push_notification__get_app_server_public_key__v1");
    expect(parsed.action_data).toEqual({});
  });

  test("accepts a base64url-alphabet value of the same bytes (despite the field's name, tolerant decode)", async () => {
    const urlsafe = rawKeyBytes.toString("base64url"); // '-'/'_' , no padding
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ status: true, code: "ok", message: "OK", data: { key_public__base64urlsafenopad: urlsafe } }),
    );
    const gateway = createPushGatewayActions({ pushApiBase: PUSH_API_BASE });

    await expect(gateway.getAppServerPublicKey()).resolves.toBe(urlsafe);
  });

  test("rejects a field value that contains no valid base64 characters at all", async () => {
    // decodeTolerantBase64 mirrors Buffer.from's lenient decode (invalid characters are
    // silently dropped, not rejected) — the only fail-closed signal available at this
    // layer is an entirely-empty decode result, which a string with zero valid base64
    // alphabet characters produces.
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        status: true,
        code: "ok",
        message: "OK",
        data: { key_public__base64urlsafenopad: "!!!!!!!!" },
      }),
    );
    const gateway = createPushGatewayActions({ pushApiBase: PUSH_API_BASE });

    await expect(gateway.getAppServerPublicKey()).rejects.toThrow(PushGatewayRejectedError);
  });

  test("caches the key: a second call makes zero additional gateway exchanges", async () => {
    const standard = rawKeyBytes.toString("base64");
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ status: true, code: "ok", message: "OK", data: { key_public__base64urlsafenopad: standard } }),
    );
    const gateway = createPushGatewayActions({ pushApiBase: PUSH_API_BASE });

    const first = await gateway.getAppServerPublicKey();
    const second = await gateway.getAppServerPublicKey();

    expect(first).toBe(standard);
    expect(second).toBe(standard);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("bounded retry with jitter + backoff", () => {
  test("recovers from a transient network failure on the second attempt", async () => {
    fetchMock
      .mockRejectedValueOnce(new Error("ECONNRESET"))
      .mockResolvedValueOnce(jsonResponse({ status: true, code: "ok", message: "OK", data: {} }));
    const sleep = vi.fn().mockResolvedValue(undefined);
    const gateway = createPushGatewayActions({
      pushApiBase: PUSH_API_BASE,
      sleep,
      jitter: () => 0.5,
    });

    await gateway.hasSubscriptionForPublicKey("k");

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledTimes(1);
  });

  test("retries a non-2xx HTTP status rather than failing immediately", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ status: false }, 503))
      .mockResolvedValueOnce(jsonResponse({ status: true, code: "ok", message: "OK", data: {} }));
    const gateway = createPushGatewayActions({
      pushApiBase: PUSH_API_BASE,
      sleep: vi.fn().mockResolvedValue(undefined),
      jitter: () => 0,
    });

    const result = await gateway.hasSubscriptionForPublicKey("k");

    expect(result).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test("exhausts maxAttempts and throws PushGatewayUnavailableError, sleeping maxAttempts-1 times", async () => {
    fetchMock.mockRejectedValue(new Error("ECONNRESET"));
    const sleep = vi.fn().mockResolvedValue(undefined);
    const gateway = createPushGatewayActions({
      pushApiBase: PUSH_API_BASE,
      maxAttempts: 3,
      baseDelayMs: 1,
      sleep,
      jitter: () => 0,
    });

    await expect(gateway.hasSubscriptionForPublicKey("k")).rejects.toThrow(PushGatewayUnavailableError);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(sleep).toHaveBeenCalledTimes(2);
  });
});

describe("submit exclusion (the never-blind-retry rule)", () => {
  test("the public factory exposes only the three read-safe methods, no generic action passthrough", () => {
    const gateway = createPushGatewayActions({ pushApiBase: PUSH_API_BASE });
    expect(Object.keys(gateway).sort()).toEqual(
      ["getAppServerPublicKey", "hasSubscriptionForPublicKey", "subscribe"].sort(),
    );
  });

  test("the submit action literal never appears in this module's source", () => {
    const here = fileURLToPath(new URL("./gateway-actions.ts", import.meta.url));
    const source = readFileSync(here, "utf-8");
    expect(SUBMIT_ACTION_NAME).toBe("submit_transaction__v1");
    expect(source.includes(SUBMIT_ACTION_NAME)).toBe(false);
  });

  test("assertReadSafeActionName runs before the request is built (call sequencing, defence in depth)", () => {
    const here = fileURLToPath(new URL("./gateway-actions.ts", import.meta.url));
    const source = readFileSync(here, "utf-8");
    const guardIdx = source.indexOf("assertReadSafeActionName(actionName)");
    const buildIdx = source.indexOf("buildGatewayActionRequest(actionName, actionData)");
    expect(guardIdx).toBeGreaterThan(-1);
    expect(buildIdx).toBeGreaterThan(-1);
    expect(guardIdx).toBeLessThan(buildIdx);
  });
});
