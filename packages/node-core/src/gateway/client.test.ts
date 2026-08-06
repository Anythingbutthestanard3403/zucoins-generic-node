import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import type { GatewayRequest, GatewayResponse } from "../protocol/index.js";
import * as gatewayClientModule from "./client.js";
import {
  DEFAULT_GATEWAY_MAX_REQUEST_BYTES,
  DEFAULT_GATEWAY_MAX_RESPONSE_BYTES,
  DEFAULT_GATEWAY_READ_TIMEOUT_MS,
  GatewayConfigurationError,
  GatewaySubmitDisabledError,
  createGatewayClient,
  createGatewayReadCredentials,
  createGatewaySubmitCredentials,
  enableGatewaySubmit,
  fingerprintEndpoint,
} from "./client.js";
import type {
  GatewayConfiguration,
  GatewayReadTransport,
  GatewaySubmitCapability,
  GatewaySubmitTransport,
} from "./types.js";

const ENDPOINT_A = "https://gateway-a.invalid/";
const ENDPOINT_B = "https://gateway-b.invalid/rpc";

const REQUEST: GatewayRequest = {
  rpc: "read_state_v1",
  bodyBytes: Uint8Array.from([1, 2, 3]),
};

const RESPONSE: GatewayResponse = {
  statusCode: 200,
  bodyBytes: Uint8Array.from([4, 5, 6]),
};

interface RecordedCall {
  readonly endpoints: readonly string[];
  readonly request: GatewayRequest;
}

function configuration(overrides: Partial<GatewayConfiguration> = {}): GatewayConfiguration {
  return {
    gatewayUrls: ENDPOINT_A,
    readTransport: { credentials: createGatewayReadCredentials(), read: async () => RESPONSE },
    ...overrides,
  };
}

describe("endpoint list — mandatory, fail-closed, no code default (production gateway transport; SPLITCHAIN_GATEWAY_URLS is REQUIRED with no code default)", () => {
  it.each<[string, string | undefined]>([
    ["absent", undefined],
    ["empty string", ""],
    ["whitespace only", "   "],
    ["separators only", " , ,"],
  ])("rejects an %s endpoint list with GatewayConfigurationError", (_label, gatewayUrls) => {
    expect(() => createGatewayClient(configuration({ gatewayUrls }))).toThrow(
      GatewayConfigurationError,
    );
  });

  it("names the failure explicitly", () => {
    expect(() => createGatewayClient(configuration({ gatewayUrls: "" }))).toThrow(
      "gateway URL list is required",
    );
  });

  it("rejects a non-https endpoint (TLS expectation from platform-trusted config)", () => {
    expect(() =>
      createGatewayClient(configuration({ gatewayUrls: "http://gateway-a.invalid/" })),
    ).toThrow("gateway URL must use https");
  });

  it("exports no string constant that could act as a silent default gateway URL", () => {
    const exportedValues: unknown[] = Object.values(gatewayClientModule);
    const exportedStrings = exportedValues.filter(
      (value): value is string => typeof value === "string",
    );
    expect(exportedStrings).toEqual([]);
  });

  it("carries no hardcoded gateway URL anywhere in the client source", () => {
    const clientSourcePath = fileURLToPath(new URL("./client.ts", import.meta.url));
    const source = readFileSync(clientSourcePath, "utf8");
    expect(source).not.toMatch(/https?:\/\//);
  });
});

describe("submit capability brand — compile-time separation from the read path", () => {
  it("a bare submit transport does not type-check where a read transport is expected", () => {
    const submitTransport: GatewaySubmitTransport = {
      credentials: createGatewaySubmitCredentials(),
      submit: async () => RESPONSE,
    };
    // @ts-expect-error — a submit-only transport has no read; the generic read/retry path must reject it at compile time
    const notAReadTransport: GatewayReadTransport = submitTransport;
    expect(typeof Reflect.get(notAReadTransport, "read")).toBe("undefined");
  });

  it("a plain object literal cannot forge the submit capability brand", () => {
    const submitTransport: GatewaySubmitTransport = {
      credentials: createGatewaySubmitCredentials(),
      submit: async () => RESPONSE,
    };
    // @ts-expect-error — the brand is a unique symbol property no object literal can declare
    const forged: GatewaySubmitCapability = { enabled: true, transport: submitTransport };
    expect(() => createGatewayClient(configuration({ submitCapability: forged }))).toThrow(
      "gateway submit capability is invalid",
    );
  });

  it("enableGatewaySubmit rejects an absent transport", () => {
    const missing = undefined as unknown as GatewaySubmitTransport;
    expect(() => enableGatewaySubmit(missing)).toThrow(GatewayConfigurationError);
  });
});

describe("endpoint fingerprint — sha256_hex of the normalized endpoint", () => {
  it("is a 64-character lowercase hexadecimal string", () => {
    expect(fingerprintEndpoint(ENDPOINT_A)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("equals an independently computed SHA-256 hex digest of the endpoint string", () => {
    const expected = createHash("sha256").update(ENDPOINT_A, "utf8").digest("hex");
    expect(fingerprintEndpoint(ENDPOINT_A)).toBe(expected);
  });

  it("is stable across repeated calls for the same endpoint", () => {
    expect(fingerprintEndpoint(ENDPOINT_A)).toBe(fingerprintEndpoint(ENDPOINT_A));
  });

  it("yields distinct fingerprints for distinct endpoints", () => {
    expect(fingerprintEndpoint(ENDPOINT_A)).not.toBe(fingerprintEndpoint(ENDPOINT_B));
  });

  it("the client exposes one fingerprint per resolved endpoint, index-aligned and frozen", () => {
    const client = createGatewayClient(
      configuration({ gatewayUrls: `${ENDPOINT_A},${ENDPOINT_B}` }),
    );
    expect(client.endpoints).toEqual([ENDPOINT_A, ENDPOINT_B]);
    expect(client.endpointFingerprints).toEqual([
      fingerprintEndpoint(ENDPOINT_A),
      fingerprintEndpoint(ENDPOINT_B),
    ]);
    expect(Object.isFrozen(client.endpointFingerprints)).toBe(true);
  });

  it("fingerprints the normalized URL form the transport dials, not the raw configured text", () => {
    const client = createGatewayClient(configuration({ gatewayUrls: "https://gateway-a.invalid" }));
    const normalized = new URL("https://gateway-a.invalid").toString();
    expect(normalized).toBe("https://gateway-a.invalid/");
    expect(client.endpoints).toEqual([normalized]);
    expect(client.endpointFingerprints).toEqual([fingerprintEndpoint(normalized)]);
  });
});

const LIMIT_FIELDS = ["readTimeoutMs", "maxRequestBytes", "maxResponseBytes"] as const;
type LimitField = (typeof LIMIT_FIELDS)[number];

function configurationWithLimit(field: LimitField, value: number): GatewayConfiguration {
  if (field === "readTimeoutMs") {
    return configuration({ readTimeoutMs: value });
  }
  if (field === "maxRequestBytes") {
    return configuration({ maxRequestBytes: value });
  }
  return configuration({ maxResponseBytes: value });
}

// Absent limits resolve to the named DEFAULT_GATEWAY_* constants — every client always has
// finite bounds (no unbounded behavior), and a present-but-invalid value fails closed.
describe("transport limits — fail-closed bounds with named, overridable defaults", () => {
  it("applies the named defaults when no limits are configured", () => {
    const client = createGatewayClient(configuration());
    expect(client.limits).toEqual({
      readTimeoutMs: DEFAULT_GATEWAY_READ_TIMEOUT_MS,
      maxRequestBytes: DEFAULT_GATEWAY_MAX_REQUEST_BYTES,
      maxResponseBytes: DEFAULT_GATEWAY_MAX_RESPONSE_BYTES,
    });
    expect(Object.isFrozen(client.limits)).toBe(true);
  });

  it("the defaults themselves are positive, finite, and byte bounds are whole numbers", () => {
    for (const value of [
      DEFAULT_GATEWAY_READ_TIMEOUT_MS,
      DEFAULT_GATEWAY_MAX_REQUEST_BYTES,
      DEFAULT_GATEWAY_MAX_RESPONSE_BYTES,
    ]) {
      expect(Number.isFinite(value)).toBe(true);
      expect(value).toBeGreaterThan(0);
    }
    expect(Number.isInteger(DEFAULT_GATEWAY_MAX_REQUEST_BYTES)).toBe(true);
    expect(Number.isInteger(DEFAULT_GATEWAY_MAX_RESPONSE_BYTES)).toBe(true);
  });

  it("accepts explicit valid limits and surfaces them unchanged on the client", () => {
    const client = createGatewayClient(
      configuration({ readTimeoutMs: 2500, maxRequestBytes: 4096, maxResponseBytes: 8192 }),
    );
    expect(client.limits).toEqual({
      readTimeoutMs: 2500,
      maxRequestBytes: 4096,
      maxResponseBytes: 8192,
    });
  });

  it.each([...LIMIT_FIELDS])("rejects a non-positive or non-finite %s", (field) => {
    for (const invalid of [0, -1, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.NaN]) {
      expect(() => createGatewayClient(configurationWithLimit(field, invalid))).toThrow(
        GatewayConfigurationError,
      );
    }
  });

  it("rejects a zero readTimeoutMs with an explicit unit-bearing message", () => {
    expect(() => createGatewayClient(configurationWithLimit("readTimeoutMs", 0))).toThrow(
      "gateway readTimeoutMs must be a positive finite number of milliseconds",
    );
  });

  it.each(["maxRequestBytes", "maxResponseBytes"] as const)(
    "rejects a fractional %s (bytes are whole units)",
    (field) => {
      expect(() => createGatewayClient(configurationWithLimit(field, 1.5))).toThrow(
        "must be a whole number of bytes",
      );
    },
  );
});

describe("client wiring with the resolved configuration", () => {
  it("read delegates to the read transport with the resolved endpoint list", async () => {
    const calls: RecordedCall[] = [];
    const transport: GatewayReadTransport = {
      credentials: createGatewayReadCredentials(),
      read: async (endpoints, request) => {
        calls.push({ endpoints: [...endpoints], request });
        return RESPONSE;
      },
    };
    const client = createGatewayClient(configuration({ readTransport: transport }));
    await expect(client.read(REQUEST)).resolves.toBe(RESPONSE);
    expect(calls).toEqual([{ endpoints: [ENDPOINT_A], request: REQUEST }]);
  });

  it("submit rejects with GatewaySubmitDisabledError when no capability is configured", async () => {
    const client = createGatewayClient(configuration());
    expect(client.canSubmit).toBe(false);
    await expect(client.submit(REQUEST)).rejects.toBeInstanceOf(GatewaySubmitDisabledError);
  });

  it("submit uses the explicitly enabled transport when the branded capability is present", async () => {
    const calls: RecordedCall[] = [];
    const transport: GatewaySubmitTransport = {
      credentials: createGatewaySubmitCredentials(),
      submit: async (endpoints, request) => {
        calls.push({ endpoints: [...endpoints], request });
        return RESPONSE;
      },
    };
    const client = createGatewayClient(
      configuration({
        submitCapability: enableGatewaySubmit(transport),
      }),
    );
    expect(client.canSubmit).toBe(true);
    await expect(client.submit(REQUEST)).resolves.toBe(RESPONSE);
    expect(calls).toEqual([{ endpoints: [ENDPOINT_A], request: REQUEST }]);
  });
});
