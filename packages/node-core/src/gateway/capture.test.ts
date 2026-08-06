// the shared single-exchange transport captures the EXACT request
// and response bytes with their SHA-256 digests, and distinguishes captured exchanges
// (any HTTP status) from ambiguous ones (transport failure, timeout, over-limit body).
import { createHash } from "node:crypto";
import https from "node:https";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { GatewayRequest } from "../protocol/index.js";
import { fingerprintEndpoint } from "./client.js";
import {
  GatewayRequestTooLargeError,
  GatewayTransportAmbiguityError,
  createGatewayExchangeTransport,
  createPinnedGatewayFetch,
  evaluateGatewayCertificatePin,
  sha256Hex,
  type GatewayFetchFn,
  type GatewayFetchInit,
  type GatewayFetchResponse,
} from "./capture.js";
import type { GatewayLimits } from "./types.js";

const ENDPOINT = "https://gateway-a.invalid/";
const PIN_A = "a".repeat(64);
const PIN_B = "b".repeat(64);

const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 1_024,
  maxResponseBytes: 1_024,
};

const REQUEST: GatewayRequest = {
  rpc: "get_transaction__v1",
  bodyBytes: Uint8Array.from([118, 61, 1, 2, 3]),
};

const RESPONSE_BYTES = Uint8Array.from([123, 34, 115, 116, 97, 116, 117, 115, 34, 125]);

function independentSha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function toBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(copy).set(bytes);
  return copy;
}

interface FakeFetch {
  readonly calls: ReadonlyArray<{ readonly url: string; readonly init: GatewayFetchInit }>;
  readonly fetchFn: GatewayFetchFn;
}

function fakeFetchResponding(status: number, body: Uint8Array): FakeFetch {
  const calls: Array<{ url: string; init: GatewayFetchInit }> = [];
  const fetchFn: GatewayFetchFn = async (url, init) => {
    calls.push({ url, init });
    const response: GatewayFetchResponse = {
      status,
      arrayBuffer: async () => toBuffer(body),
    };
    return response;
  };
  return { calls, fetchFn };
}

describe("single exchange — exact byte capture with digests", () => {
  it("sends the exact request bytes as a form-urlencoded POST against the one endpoint", async () => {
    const fake = fakeFetchResponding(200, RESPONSE_BYTES);
    const transport = createGatewayExchangeTransport({ limits: LIMITS, fetchFn: fake.fetchFn });
    await transport.exchange(ENDPOINT, REQUEST);
    expect(fake.calls.length).toBe(1);
    const call = fake.calls[0];
    expect(call?.url).toBe(ENDPOINT);
    expect(call?.init.method).toBe("POST");
    expect(call?.init.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(call?.init.body).toBe(REQUEST.bodyBytes);
  });

  it("captures the exact response bytes and both SHA-256 digests", async () => {
    const fake = fakeFetchResponding(200, RESPONSE_BYTES);
    const transport = createGatewayExchangeTransport({ limits: LIMITS, fetchFn: fake.fetchFn });
    const capture = await transport.exchange(ENDPOINT, REQUEST);
    expect(capture.requestBytes).toBe(REQUEST.bodyBytes);
    expect(capture.requestSha256).toBe(independentSha256(REQUEST.bodyBytes));
    expect(capture.responseBytes).toEqual(RESPONSE_BYTES);
    expect(capture.responseSha256).toBe(independentSha256(RESPONSE_BYTES));
    expect(sha256Hex(RESPONSE_BYTES)).toBe(independentSha256(RESPONSE_BYTES));
  });

  it("fingerprints the endpoint with the canonical sha256_hex preimage", async () => {
    const fake = fakeFetchResponding(200, RESPONSE_BYTES);
    const transport = createGatewayExchangeTransport({ limits: LIMITS, fetchFn: fake.fetchFn });
    const capture = await transport.exchange(ENDPOINT, REQUEST);
    expect(capture.endpoint).toBe(ENDPOINT);
    expect(capture.endpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT));
    expect(capture.endpointFingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it.each([200, 201, 299, 301, 400, 404, 500, 503])(
    "returns a captured exchange verbatim for HTTP %i — status interpretation belongs to the caller",
    async (status) => {
      const fake = fakeFetchResponding(status, RESPONSE_BYTES);
      const transport = createGatewayExchangeTransport({ limits: LIMITS, fetchFn: fake.fetchFn });
      const capture = await transport.exchange(ENDPOINT, REQUEST);
      expect(capture.statusCode).toBe(status);
      expect(capture.responseBytes).toEqual(RESPONSE_BYTES);
    },
  );
});

describe("ambiguity classification — the effect of the exchange is unknown", () => {
  it("a network failure raises GatewayTransportAmbiguityError preserving the cause", async () => {
    const networkFailure = new Error("connection refused");
    const fetchFn: GatewayFetchFn = async () => {
      throw networkFailure;
    };
    const transport = createGatewayExchangeTransport({ limits: LIMITS, fetchFn });
    await expect(transport.exchange(ENDPOINT, REQUEST)).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(GatewayTransportAmbiguityError);
      expect((error as GatewayTransportAmbiguityError).cause).toBe(networkFailure);
      expect((error as Error).message).toContain("ambiguous");
      return true;
    });
  });

  it("a timeout raises GatewayTransportAmbiguityError naming the configured deadline", async () => {
    const fetchFn: GatewayFetchFn = async (_url, init) =>
      await new Promise<GatewayFetchResponse>((_resolve, reject) => {
        init.signal.addEventListener("abort", () => {
          reject(new Error("aborted"));
        });
      });
    const transport = createGatewayExchangeTransport({
      limits: { ...LIMITS, readTimeoutMs: 10 },
      fetchFn,
    });
    await expect(transport.exchange(ENDPOINT, REQUEST)).rejects.toThrow("timed out after 10ms");
  });

  it("a body that cannot be read raises GatewayTransportAmbiguityError", async () => {
    const fetchFn: GatewayFetchFn = async () => ({
      status: 200,
      arrayBuffer: async () => {
        throw new Error("stream reset mid-body");
      },
    });
    const transport = createGatewayExchangeTransport({ limits: LIMITS, fetchFn });
    await expect(transport.exchange(ENDPOINT, REQUEST)).rejects.toBeInstanceOf(
      GatewayTransportAmbiguityError,
    );
  });

  it("an over-limit response body raises GatewayTransportAmbiguityError", async () => {
    const oversized = new Uint8Array(LIMITS.maxResponseBytes + 1);
    const fake = fakeFetchResponding(200, oversized);
    const transport = createGatewayExchangeTransport({ limits: LIMITS, fetchFn: fake.fetchFn });
    await expect(transport.exchange(ENDPOINT, REQUEST)).rejects.toThrow(
      "exceeding the configured maximum",
    );
  });
});

describe("request size bound — a definite local failure, not an ambiguity", () => {
  it("an over-limit request raises GatewayRequestTooLargeError without touching the network", async () => {
    const fake = fakeFetchResponding(200, RESPONSE_BYTES);
    const transport = createGatewayExchangeTransport({ limits: LIMITS, fetchFn: fake.fetchFn });
    const oversized: GatewayRequest = {
      rpc: REQUEST.rpc,
      bodyBytes: new Uint8Array(LIMITS.maxRequestBytes + 1),
    };
    await expect(transport.exchange(ENDPOINT, oversized)).rejects.toBeInstanceOf(
      GatewayRequestTooLargeError,
    );
    expect(fake.calls.length).toBe(0);
  });
});

describe("TLS certificate pinning — pure pin-comparison logic, rotation-safe", () => {
  it("accepts a fingerprint present in the pin set, case/colon-insensitive", () => {
    const pins = new Set([PIN_A]);
    const colonUpper = PIN_A.toUpperCase().replace(/(..)(?!$)/g, "$1:");
    expect(evaluateGatewayCertificatePin(pins, colonUpper, "gateway.invalid")).toBeUndefined();
  });

  it("rejects a fingerprint absent from the pin set, naming the host and fingerprint", () => {
    const pins = new Set([PIN_A]);
    const error = evaluateGatewayCertificatePin(pins, PIN_B, "gateway.invalid");
    expect(error).toBeInstanceOf(Error);
    expect(error?.message).toContain("gateway.invalid");
    expect(error?.message).toContain(PIN_B);
  });

  it("rotation: retiring a pin rejects the old cert; admitting the new pin accepts the new cert", () => {
    const beforeRotation = new Set([PIN_A]);
    expect(evaluateGatewayCertificatePin(beforeRotation, PIN_A, "gateway.invalid")).toBeUndefined();

    const afterRotation = new Set([PIN_B]);
    expect(evaluateGatewayCertificatePin(afterRotation, PIN_A, "gateway.invalid")).toBeInstanceOf(
      Error,
    );
    expect(evaluateGatewayCertificatePin(afterRotation, PIN_B, "gateway.invalid")).toBeUndefined();
  });

  it("an empty pin set rejects every fingerprint fail-closed", () => {
    expect(evaluateGatewayCertificatePin(new Set(), PIN_A, "gateway.invalid")).toBeInstanceOf(
      Error,
    );
  });

  it("dual-pin rotation overlap: a set holding old and new pins accepts either cert", () => {
    const overlap = new Set([PIN_A, PIN_B]);
    expect(evaluateGatewayCertificatePin(overlap, PIN_A, "gateway.invalid")).toBeUndefined();
    expect(evaluateGatewayCertificatePin(overlap, PIN_B, "gateway.invalid")).toBeUndefined();
  });
});

describe("createPinnedGatewayFetch — wired to a real TLS connection, not a no-op", () => {
  it("attempts node:https (denied by this package's network-containment guard in tests)", async () => {
    const fetchFn = createPinnedGatewayFetch([PIN_A]);
    await expect(
      fetchFn(ENDPOINT, {
        method: "POST",
        headers: {},
        body: Uint8Array.from([1]),
        signal: new AbortController().signal,
      }),
    ).rejects.toThrow("network-contained");
  });
});

describe("createGatewayExchangeTransport — pin configuration selects the pinned fetch path", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("routes through node:https, not global fetch, when tlsCertSha256Pins is configured", async () => {
    const httpsSpy = vi.spyOn(https, "request");
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const transport = createGatewayExchangeTransport({ limits: LIMITS, tlsCertSha256Pins: [PIN_A] });
    await expect(transport.exchange(ENDPOINT, REQUEST)).rejects.toBeInstanceOf(
      GatewayTransportAmbiguityError,
    );
    expect(httpsSpy).toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("routes through global fetch unchanged when no pins are configured", async () => {
    const httpsSpy = vi.spyOn(https, "request");
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const transport = createGatewayExchangeTransport({ limits: LIMITS });
    await expect(transport.exchange(ENDPOINT, REQUEST)).rejects.toBeInstanceOf(
      GatewayTransportAmbiguityError,
    );
    expect(fetchSpy).toHaveBeenCalled();
    expect(httpsSpy).not.toHaveBeenCalled();
  });

  it("an explicit fetchFn override wins even when pins are configured", async () => {
    const fake = fakeFetchResponding(200, RESPONSE_BYTES);
    const transport = createGatewayExchangeTransport({
      limits: LIMITS,
      tlsCertSha256Pins: [PIN_A],
      fetchFn: fake.fetchFn,
    });
    await transport.exchange(ENDPOINT, REQUEST);
    expect(fake.calls.length).toBe(1);
  });
});
