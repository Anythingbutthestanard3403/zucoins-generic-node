import { describe, expect, it } from "vitest";

import type { GatewayRequest, GatewayResponse } from "../src/protocol/index.js";
import {
  GatewayConfigurationError,
  createGatewayClient,
  createGatewayReadCredentials,
  createGatewaySubmitCredentials,
  enableGatewaySubmit,
} from "../src/gateway/client.js";
import {
  GatewayEndpointNotAllowedError,
  assertEndpointAllowed,
  createGatewayEndpointAllowlist,
} from "../src/gateway/allowlist.js";
import type {
  GatewayReadCredentials,
  GatewayReadTransport,
  GatewaySubmitCredentials,
  GatewaySubmitTransport,
} from "../src/gateway/types.js";

const ENDPOINT_A = "https://gateway-a.invalid/";
const ENDPOINT_B = "https://gateway-b.invalid/rpc";
const NON_ALLOWLISTED = "https://evil.invalid/steal";

const REQUEST: GatewayRequest = {
  rpc: "get_transaction__v1",
  bodyBytes: Uint8Array.from([1, 2, 3]),
};

const RESPONSE: GatewayResponse = {
  statusCode: 200,
  bodyBytes: Uint8Array.from([4, 5, 6]),
};

function readTransport(): GatewayReadTransport {
  return {
    credentials: createGatewayReadCredentials(),
    read: async () => RESPONSE,
  };
}

describe("endpoint allowlist — construction-time validation", () => {
  it("rejects an empty allowlist", () => {
    expect(() => createGatewayEndpointAllowlist([])).toThrow(GatewayConfigurationError);
    expect(() => createGatewayEndpointAllowlist([])).toThrow(
      "gateway endpoint allowlist must not be empty",
    );
  });

  it("rejects a non-URL entry", () => {
    expect(() => createGatewayEndpointAllowlist(["not-a-url"])).toThrow(
      GatewayConfigurationError,
    );
    expect(() => createGatewayEndpointAllowlist(["not-a-url"])).toThrow(
      "not a valid URL",
    );
  });

  it("rejects a duplicate entry (same origin+pathname after normalization)", () => {
    expect(() =>
      createGatewayEndpointAllowlist(["https://gw.invalid/rpc", "https://gw.invalid/rpc"]),
    ).toThrow("duplicate entry");
  });

  it("rejects a URL containing credentials", () => {
    expect(() =>
      createGatewayEndpointAllowlist(["https://user:pass@gw.invalid/"]),
    ).toThrow("must not contain credentials");
  });

  it("rejects a non-loopback http URL", () => {
    expect(() =>
      createGatewayEndpointAllowlist(["http://gw.invalid/"]),
    ).toThrow("https");
  });

  it("accepts a loopback http URL", () => {
    const allowlist = createGatewayEndpointAllowlist(["http://127.0.0.1:8080/"]);
    expect(allowlist.length).toBe(1);
  });

  it("produces a frozen, non-empty array", () => {
    const allowlist = createGatewayEndpointAllowlist([ENDPOINT_A]);
    expect(Object.isFrozen(allowlist)).toBe(true);
    expect(allowlist.length).toBe(1);
  });
});

describe("assertEndpointAllowed — runtime egress containment", () => {
  it("passes for an endpoint in the allowlist", () => {
    const allowlist = createGatewayEndpointAllowlist([ENDPOINT_A, ENDPOINT_B]);
    expect(() => assertEndpointAllowed(allowlist, ENDPOINT_A)).not.toThrow();
    expect(() => assertEndpointAllowed(allowlist, ENDPOINT_B)).not.toThrow();
  });

  it("rejects an endpoint not in the allowlist with GatewayEndpointNotAllowedError", () => {
    const allowlist = createGatewayEndpointAllowlist([ENDPOINT_A]);
    expect(() => assertEndpointAllowed(allowlist, NON_ALLOWLISTED)).toThrow(
      GatewayEndpointNotAllowedError,
    );
    expect(() => assertEndpointAllowed(allowlist, NON_ALLOWLISTED)).toThrow(
      `gateway endpoint not in allowlist: ${NON_ALLOWLISTED}`,
    );
  });
});

describe("client egress containment — no request reaches a non-allowlisted URL (zero network I/O)", () => {
  it("read path: the client only reaches its configured endpoints", async () => {
    const reached: string[] = [];
    const transport: GatewayReadTransport = {
      credentials: createGatewayReadCredentials(),
      read: async (endpoints) => {
        reached.push(...endpoints);
        return RESPONSE;
      },
    };
    const client = createGatewayClient({
      gatewayUrls: ENDPOINT_A,
      readTransport: transport,
    });
    await client.read(REQUEST);
    expect(reached).toEqual([ENDPOINT_A]);
    expect(reached).not.toContain(NON_ALLOWLISTED);
  });

  it("submit path: the client only reaches its configured endpoints", async () => {
    const reached: string[] = [];
    const transport: GatewaySubmitTransport = {
      credentials: createGatewaySubmitCredentials(),
      submit: async (endpoints) => {
        reached.push(...endpoints);
        return RESPONSE;
      },
    };
    const client = createGatewayClient({
      gatewayUrls: ENDPOINT_A,
      readTransport: readTransport(),
      submitCapability: enableGatewaySubmit(transport),
    });
    await client.submit(REQUEST);
    expect(reached).toEqual([ENDPOINT_A]);
    expect(reached).not.toContain(NON_ALLOWLISTED);
  });

  it("construction rejects a non-allowlisted URL in the gateway URL list", () => {
    expect(() =>
      createGatewayClient({
        gatewayUrls: "not-a-valid-url",
        readTransport: readTransport(),
      }),
    ).toThrow(GatewayConfigurationError);
  });
});

describe("credential separation — type-level enforcement", () => {
  it("read credentials are not assignable to the submit credential type", () => {
    const readCreds = createGatewayReadCredentials();
    // @ts-expect-error — read credentials cannot stand in for submit credentials
    const notSubmitCreds: GatewaySubmitCredentials = readCreds;
    expect(notSubmitCreds).toBe(readCreds);
  });

  it("submit credentials are not assignable to the read credential type", () => {
    const submitCreds = createGatewaySubmitCredentials();
    // @ts-expect-error — submit credentials cannot stand in for read credentials
    const notReadCreds: GatewayReadCredentials = submitCreds;
    expect(notReadCreds).toBe(submitCreds);
  });

  it("a read-credentialed transport cannot be used where a submit transport is expected", () => {
    const readOnly: GatewayReadTransport = {
      credentials: createGatewayReadCredentials(),
      read: async () => RESPONSE,
    };
    // @ts-expect-error — a read transport has no submit method and carries the wrong credential brand
    const notSubmit: GatewaySubmitTransport = readOnly;
    expect(typeof Reflect.get(notSubmit, "submit")).toBe("undefined");
  });

  it("a submit-credentialed transport cannot be used where a read transport is expected", () => {
    const submitOnly: GatewaySubmitTransport = {
      credentials: createGatewaySubmitCredentials(),
      submit: async () => RESPONSE,
    };
    // @ts-expect-error — a submit transport has no read method and carries the wrong credential brand
    const notRead: GatewayReadTransport = submitOnly;
    expect(typeof Reflect.get(notRead, "read")).toBe("undefined");
  });

  it("a plain object cannot forge read credentials", () => {
    // @ts-expect-error — the brand is a unique symbol no object literal can declare
    const forged: GatewayReadCredentials = {};
    expect(forged).toEqual({});
  });

  it("a plain object cannot forge submit credentials", () => {
    // @ts-expect-error — the brand is a unique symbol no object literal can declare
    const forged: GatewaySubmitCredentials = {};
    expect(forged).toEqual({});
  });
});

describe("complementary layers — network guard + allowlist (defense-in-depth)", () => {
  it("the network guard blocks at the socket layer (setup-network-guard is active)", async () => {
    await expect(fetch("https://gateway.invalid/rpc")).rejects.toThrow(
      "generic-node core tests are network-contained",
    );
  });

  it("the allowlist blocks at the config/construction layer (before any socket)", () => {
    const allowlist = createGatewayEndpointAllowlist([ENDPOINT_A]);
    expect(() => assertEndpointAllowed(allowlist, "https://unreachable.invalid/")).toThrow(
      GatewayEndpointNotAllowedError,
    );
  });

  it("the two layers are independent: allowlist rejection is not a network error", () => {
    const allowlist = createGatewayEndpointAllowlist([ENDPOINT_A]);
    try {
      assertEndpointAllowed(allowlist, NON_ALLOWLISTED);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(GatewayEndpointNotAllowedError);
      expect(error).not.toBeInstanceOf(TypeError);
      expect((error as Error).message).not.toContain("network-contained");
    }
  });
});
