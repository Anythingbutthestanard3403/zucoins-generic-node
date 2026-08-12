import { describe, expect, it, vi } from "vitest";

import {
  gatewayRequestFromPersistedBody,
  redeliverIdenticalSignedRequest,
} from "./identical-byte-redelivery.js";
import type { GatewayLimits } from "./types.js";

const LIMITS: GatewayLimits = {
  maxRequestBytes: 1_000_000,
  maxResponseBytes: 1_000_000,
  readTimeoutMs: 1_000,
};

describe("identical-byte redelivery (ZTR-1243 / ZTR-1244)", () => {
  it("gatewayRequestFromPersistedBody preserves exact body bytes", () => {
    const body = new TextEncoder().encode("v=%7B%22action_name%22%3A%22submit_transaction__v1%22%7D");
    const req = gatewayRequestFromPersistedBody(body);
    expect(req.bodyBytes).toEqual(body);
    expect(req.rpc).toBe("submit_transaction__v1");
  });

  it("redeliverIdenticalSignedRequest POSTs once and swallows transport errors", async () => {
    const seen: Uint8Array[] = [];
    const exchangeFn = async (
      _endpoint: string,
      request: { readonly bodyBytes: Uint8Array },
    ): Promise<never> => {
      seen.push(request.bodyBytes);
      throw new Error("timeout");
    };
    const body = new Uint8Array([1, 2, 3]);
    await expect(
      redeliverIdenticalSignedRequest(
        { rpc: "submit_transaction__v1", bodyBytes: body },
        {
          endpoint: "https://gw.example/rpc",
          limits: LIMITS,
          exchange: { exchange: exchangeFn },
        },
      ),
    ).resolves.toBeUndefined();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual(body);
  });
});

