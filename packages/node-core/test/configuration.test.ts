import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { createNodeCore } from "../src/core/index.js";
import {
  DatabaseConfigurationError,
  requireDatabaseAdapter,
} from "../src/data/index.js";
import {
  createGatewayClient,
  createGatewayReadCredentials,
  createGatewaySubmitCredentials,
  enableGatewaySubmit,
  GatewayConfigurationError,
  GatewaySubmitDisabledError,
  type GatewayConfiguration,
  type GatewaySubmitCapability,
} from "../src/gateway/index.js";
import type { GatewayRequest, GatewayResponse } from "../src/protocol/index.js";
import {
  createOfflineDatabaseAdapter,
  createOfflineReadTransport,
  createOfflineSubmitTransport,
} from "../src/testkit/index.js";

const REQUEST: GatewayRequest = {
  rpc: "read_state_v1",
  bodyBytes: Uint8Array.from([1, 2, 3]),
};

const RESPONSE: GatewayResponse = {
  statusCode: 200,
  bodyBytes: Uint8Array.from([4, 5, 6]),
};

function baseGatewayConfiguration(): GatewayConfiguration {
  return {
    gatewayUrls: "https://gateway-a.invalid/rpc, https://gateway-b.invalid/rpc",
    readTransport: createOfflineReadTransport(createGatewayReadCredentials(), [RESPONSE]),
  };
}

describe("mandatory configuration", () => {
  it("rejects an absent node-core configuration", () => {
    const missing = undefined as unknown as Parameters<typeof createNodeCore>[0];
    expect(() => createNodeCore(missing)).toThrow("node core configuration is required");
  });

  it("rejects an absent database configuration", () => {
    const missing = undefined as unknown as Parameters<typeof requireDatabaseAdapter>[0];
    expect(() => requireDatabaseAdapter(missing)).toThrow(DatabaseConfigurationError);
  });

  it("rejects an absent database adapter", () => {
    const missing = {
      connectionString: "opaque-test-connection",
    } as unknown as Parameters<typeof requireDatabaseAdapter>[0];
    expect(() => requireDatabaseAdapter(missing)).toThrow("database adapter is required");
  });

  it.each([undefined, "", "   "])(
    "rejects the absent or blank database connection string %s",
    (connectionString) => {
      const configuration = {
        connectionString,
        adapter: createOfflineDatabaseAdapter(),
      } as unknown as Parameters<typeof requireDatabaseAdapter>[0];
      expect(() => requireDatabaseAdapter(configuration)).toThrow(
        "database connection string is required",
      );
    },
  );

  it("rejects an absent gateway configuration", () => {
    const missing = undefined as unknown as Parameters<typeof createGatewayClient>[0];
    expect(() => createGatewayClient(missing)).toThrow(GatewayConfigurationError);
  });

  it("rejects an absent read transport", () => {
    const missing = {
      gatewayUrls: "https://gateway.invalid",
    } as unknown as GatewayConfiguration;
    expect(() => createGatewayClient(missing)).toThrow("gateway read transport is required");
  });

  it.each(["", "   , ", "not-a-url", "http://gateway.invalid"])(
    "rejects the unsafe gateway URL list %s",
    (gatewayUrls) => {
      expect(() => createGatewayClient({ ...baseGatewayConfiguration(), gatewayUrls })).toThrow(
        GatewayConfigurationError,
      );
    },
  );

  it("creates a runtime only when both configurations are explicit", () => {
    const database = createOfflineDatabaseAdapter();
    const runtime = createNodeCore({
      database: { connectionString: "opaque-test-connection", adapter: database },
      gateway: baseGatewayConfiguration(),
    });
    expect(runtime.database).toBe(database);
    expect(runtime.gateway.endpoints).toEqual([
      "https://gateway-a.invalid/rpc",
      "https://gateway-b.invalid/rpc",
    ]);
  });
});

describe("submit capability", () => {
  it("is disabled by default and never reaches a transport", async () => {
    const transport = createOfflineSubmitTransport(createGatewaySubmitCredentials(), [RESPONSE]);
    const gateway = createGatewayClient(baseGatewayConfiguration());
    expect(gateway.canSubmit).toBe(false);
    await expect(gateway.submit(REQUEST)).rejects.toBeInstanceOf(GatewaySubmitDisabledError);
    expect(transport.calls).toEqual([]);
  });

  it("rejects a structurally forged capability", () => {
    const transport = createOfflineSubmitTransport(createGatewaySubmitCredentials(), [RESPONSE]);
    const forged = {
      enabled: true,
      transport,
    } as unknown as GatewaySubmitCapability;
    expect(() =>
      createGatewayClient({
        ...baseGatewayConfiguration(),
        submitCapability: forged,
      }),
    ).toThrow("gateway submit capability is invalid");
  });

  it("uses one explicitly enabled transport once without rebuilding the request", async () => {
    const transport = createOfflineSubmitTransport(createGatewaySubmitCredentials(), [RESPONSE]);
    const gateway = createGatewayClient({
      ...baseGatewayConfiguration(),
      submitCapability: enableGatewaySubmit(transport),
    });
    const response = await gateway.submit(REQUEST);
    expect(gateway.canSubmit).toBe(true);
    expect(response).toEqual(RESPONSE);
    expect(transport.calls).toEqual([
      {
        endpoints: [
          "https://gateway-a.invalid/rpc",
          "https://gateway-b.invalid/rpc",
        ],
        request: REQUEST,
      },
    ]);
  });

  it("propagates an asynchronous transport failure without another call", async () => {
    const failure = new Error("ambiguous fixture failure");
    const transport = createOfflineSubmitTransport(createGatewaySubmitCredentials(), [failure, RESPONSE]);
    const gateway = createGatewayClient({
      ...baseGatewayConfiguration(),
      submitCapability: enableGatewaySubmit(transport),
    });
    await expect(gateway.submit(REQUEST)).rejects.toBe(failure);
    expect(transport.calls).toHaveLength(1);
  });
});

// retired liveChainSubmitAuthorized. Submit is gated only by a branded
// enableGatewaySubmit capability — no separate live-chain approval flag at construction.
describe("submit construction without live-chain approval gate", () => {
  function submitConfiguration(
    overrides: Partial<GatewayConfiguration> = {},
  ): GatewayConfiguration {
    return {
      ...baseGatewayConfiguration(),
      submitCapability: enableGatewaySubmit(
        createOfflineSubmitTransport(createGatewaySubmitCredentials(), [RESPONSE]),
      ),
      ...overrides,
    };
  }

  it("constructs submit-capable clients without a live-chain authorization flag", async () => {
    const transport = createOfflineSubmitTransport(createGatewaySubmitCredentials(), [RESPONSE]);
    const gateway = createGatewayClient({
      ...baseGatewayConfiguration(),
      submitCapability: enableGatewaySubmit(transport),
    });
    expect(gateway.canSubmit).toBe(true);
    await expect(gateway.submit(REQUEST)).resolves.toEqual(RESPONSE);
    expect(transport.calls).toHaveLength(1);
  });

  it("still requires a branded capability — flag-less config defaults to read-only", async () => {
    const gateway = createGatewayClient(baseGatewayConfiguration());
    expect(gateway.canSubmit).toBe(false);
    await expect(gateway.submit(REQUEST)).rejects.toBeInstanceOf(GatewaySubmitDisabledError);
  });

  it("rejects a forged capability", () => {
    const forged = {
      enabled: true,
      transport: createOfflineSubmitTransport(createGatewaySubmitCredentials(), [RESPONSE]),
    } as unknown as GatewaySubmitCapability;
    expect(() =>
      createGatewayClient(submitConfiguration({ submitCapability: forged })),
    ).toThrow("gateway submit capability is invalid");
  });

  it("rejects a submit capability when the endpoint list is empty", () => {
    expect(() => createGatewayClient(submitConfiguration({ gatewayUrls: "  ,  " }))).toThrow(
      "gateway URL list is required",
    );
  });

  it("gateway source has no live-chain approval field or env reads", () => {
    for (const moduleName of ["client.ts", "types.ts"]) {
      const sourcePath = fileURLToPath(
        new URL(`../src/gateway/${moduleName}`, import.meta.url),
      );
      const source = readFileSync(sourcePath, "utf8");
      // Field and gate error string must be gone.
      expect(source).not.toMatch(/liveChainSubmitAuthorized\s*[?:]/);
      expect(source).not.toMatch(
        /requires explicit liveChainSubmitAuthorized authorization/,
      );
      expect(source).not.toMatch(/process\.env/);
      expect(source).not.toMatch(/NODE_ENV/);
    }
  });

  it("createNodeCore accepts branded submit without a live-chain flag", () => {
    const database = {
      connectionString: "opaque-test-connection",
      adapter: createOfflineDatabaseAdapter(),
    };
    const runtime = createNodeCore({
      database,
      gateway: submitConfiguration(),
    });
    expect(runtime.gateway.canSubmit).toBe(true);
  });
});

describe("deterministic offline adapters", () => {
  it("replays read responses and errors in script sequence", async () => {
    const failure = new Error("fixture read failure");
    const transport = createOfflineReadTransport(createGatewayReadCredentials(), [RESPONSE, failure]);
    const gateway = createGatewayClient({
      gatewayUrls: "https://gateway.invalid",
      readTransport: transport,
    });
    await expect(gateway.read(REQUEST)).resolves.toEqual(RESPONSE);
    await expect(gateway.read(REQUEST)).rejects.toBe(failure);
    await expect(gateway.read(REQUEST)).rejects.toThrow("offline gateway script is exhausted");
    expect(transport.calls).toHaveLength(3);
  });

  it("reports database readiness asynchronously", async () => {
    const adapter = createOfflineDatabaseAdapter();
    await expect(adapter.checkReady()).resolves.toBeUndefined();
    expect(adapter.readyChecks).toBe(1);
  });

  it("propagates a configured database readiness error", async () => {
    const failure = new Error("fixture database failure");
    const adapter = createOfflineDatabaseAdapter(failure);
    await expect(adapter.checkReady()).rejects.toBe(failure);
    expect(adapter.readyChecks).toBe(1);
  });
});
