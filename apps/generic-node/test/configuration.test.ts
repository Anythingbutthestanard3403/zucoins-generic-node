import http2 from "node:http2";
import { describe, expect, it } from "vitest";

import {
  createGatewayReadCredentials,
  createGatewaySubmitCredentials,
  enableGatewaySubmit,
  GatewayConfigurationError,
  GatewaySubmitDisabledError,
  type GatewayConfiguration,
  type GatewayRequest,
  type GatewayResponse,
  type GatewaySubmitTransport,
  type NodeCoreConfiguration,
} from "@zucoins/node-core";

import { createGenericNodeApplication } from "../src/index.js";

describe("generic-node application configuration", () => {
  it("does not start without explicit core configuration", () => {
    const missing = undefined as unknown as Parameters<typeof createGenericNodeApplication>[0];
    expect(() => createGenericNodeApplication(missing)).toThrow(
      "node core configuration is required",
    );
  });

  it("runs under the package network guard", async () => {
    await expect(fetch("https://gateway.invalid/rpc")).rejects.toThrow(
      "generic-node core tests are network-contained",
    );
  });

  it("blocks static and dynamic HTTP/2 entry points", async () => {
    const denyMessage = "generic-node core tests are network-contained";
    expect(() => http2.connect("https://gateway.invalid")).toThrow(denyMessage);
    const dynamicHttp2 = await import("node:http2");
    expect(() => dynamicHttp2.connect("https://gateway.invalid")).toThrow(denyMessage);
  });
});

// The live-chain gate retirement removed liveChainSubmitAuthorized. Application seam still requires a
// branded enableGatewaySubmit capability; no separate live-chain approval flag.
describe("submit construction through the application seam", () => {
  const RESPONSE: GatewayResponse = {
    statusCode: 200,
    bodyBytes: Uint8Array.from([4, 5, 6]),
  };

  const REQUEST: GatewayRequest = {
    rpc: "read_state_v1",
    bodyBytes: Uint8Array.from([1, 2, 3]),
  };

  function gatewayConfiguration(
    overrides: Partial<GatewayConfiguration> = {},
  ): GatewayConfiguration {
    return {
      gatewayUrls: "https://gateway-a.invalid/rpc, https://gateway-b.invalid/rpc",
      readTransport: { credentials: createGatewayReadCredentials(), read: async () => RESPONSE },
      ...overrides,
    };
  }

  function coreConfiguration(gateway: GatewayConfiguration): NodeCoreConfiguration {
    return {
      database: {
        connectionString: "opaque-test-connection",
        adapter: { checkReady: async () => undefined },
      },
      gateway,
    };
  }

  it("constructs submit-capable apps without a live-chain authorization flag", () => {
    const submitTransport: GatewaySubmitTransport = {
      credentials: createGatewaySubmitCredentials(),
      submit: async () => RESPONSE,
    };
    const application = createGenericNodeApplication(
      coreConfiguration(
        gatewayConfiguration({
          submitCapability: enableGatewaySubmit(submitTransport),
        }),
      ),
    );
    expect(application.core.gateway.canSubmit).toBe(true);
  });

  it("defaults to read-only: submit rejects without a capability", async () => {
    const application = createGenericNodeApplication(
      coreConfiguration(gatewayConfiguration()),
    );
    expect(application.core.gateway.canSubmit).toBe(false);
    await expect(application.core.gateway.submit(REQUEST)).rejects.toBeInstanceOf(
      GatewaySubmitDisabledError,
    );
  });

  it("rejects a forged capability at the application seam", () => {
    const forged = {
      enabled: true,
      transport: {
        credentials: createGatewaySubmitCredentials(),
        submit: async () => RESPONSE,
      },
    } as unknown as ReturnType<typeof enableGatewaySubmit>;
    expect(() =>
      createGenericNodeApplication(
        coreConfiguration(gatewayConfiguration({ submitCapability: forged })),
      ),
    ).toThrow(GatewayConfigurationError);
  });
});
