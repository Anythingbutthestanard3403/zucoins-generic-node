import { describe, expect, it } from "vitest";

import {
  createGatewayClient,
  createGatewayReadCredentials,
  createGatewaySubmitCredentials,
} from "../../src/gateway/index.js";
import type { GatewayResponse } from "../../src/protocol/index.js";
import type { GatewaySubmitTransport } from "../../src/gateway/types.js";

import {
  amountWithinTolerance,
  compareAmounts,
  enableGatewaySubmit,
  GatewayConfigurationError,
  signedDelta,
  subtractAmounts,
  type GatewaySubmitCapability,
} from "./types.js";

describe("compareAmounts", () => {
  it("orders integer amounts numerically, not lexicographically", () => {
    expect(compareAmounts("2", "10")).toBe(-1);
    expect(compareAmounts("10", "2")).toBe(1);
    expect(compareAmounts("10", "10")).toBe(0);
  });

  it("compares fractional amounts by value", () => {
    expect(compareAmounts("0.000001", "0.01")).toBe(-1);
    expect(compareAmounts("0.01", "0.000001")).toBe(1);
    expect(compareAmounts("0.10", "0.1")).toBe(0);
  });

  it("rejects malformed amounts", () => {
    expect(() => compareAmounts("abc", "1")).toThrow(/malformed amount/);
  });
});

describe("subtractAmounts / signedDelta", () => {
  it("subtracts fractional dust", () => {
    expect(subtractAmounts("1.000001", "0.000001")).toBe("1");
    expect(signedDelta("1", "0.999999")).toBe("-0.000001");
    expect(signedDelta("1", "1.000001")).toBe("0.000001");
  });

  it("amountWithinTolerance respects the bound", () => {
    expect(amountWithinTolerance("0.000001", "0.000001", "0")).toBe(true);
    expect(amountWithinTolerance("0.000001", "0.01", "0")).toBe(false);
  });
});

const RESPONSE: GatewayResponse = {
  statusCode: 200,
  bodyBytes: Uint8Array.from([4, 5, 6]),
};

function submitTransport(): GatewaySubmitTransport {
  return {
    credentials: createGatewaySubmitCredentials(),
    submit: async () => RESPONSE,
  };
}

function readTransport() {
  return {
    credentials: createGatewayReadCredentials(),
    read: async () => RESPONSE,
  };
}

describe("D10.4 branded submit capability (live-chain surface)", () => {
  it("enableGatewaySubmit mints a capability the gateway client accepts", () => {
    const cap = enableGatewaySubmit(submitTransport());
    expect(cap.enabled).toBe(true);
    const client = createGatewayClient({
      gatewayUrls: "https://gateway.example/",
      readTransport: readTransport(),
      submitCapability: cap,
    });
    expect(client.canSubmit).toBe(true);
  });

  it("a plain object cannot forge the submit capability brand", () => {
    const forged = {
      enabled: true,
      transport: submitTransport(),
    } as unknown as GatewaySubmitCapability;
    expect(() =>
      createGatewayClient({
        gatewayUrls: "https://gateway.example/",
        readTransport: readTransport(),
        submitCapability: forged,
      }),
    ).toThrow(GatewayConfigurationError);
  });

  it("enableGatewaySubmit rejects an absent transport", () => {
    expect(() => enableGatewaySubmit(undefined as never)).toThrow(GatewayConfigurationError);
  });
});
