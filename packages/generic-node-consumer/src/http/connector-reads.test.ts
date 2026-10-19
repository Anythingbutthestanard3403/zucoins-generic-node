import { describe, expect, it } from "vitest";
import { getNodeInfo, listOperations, listWallets } from "./connector-reads.js";
import type { FetchLike } from "./client-types.js";

describe("connector-reads SDK helpers (ZTR-1332 / GN-204)", () => {
  it("getNodeInfo requests GET /v1/node-info with Bearer authorization", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetch: FetchLike = async (url, init) => {
      calls.push({ url, init });
      return new Response(
        JSON.stringify({
          node_id: "11111111-1111-4111-8111-111111111111",
          node_public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n",
          implementer_id: "22222222-2222-4222-8222-222222222222",
          display_name: "Checkout",
          policy_mode: "NODE_VERIFIED",
          scopes: ["receives:write", "sends:write", "wallets:read_linked"],
          default_reserve_wallet_id: "aaaaaaa1-1111-4111-8111-111111111111",
          allow_custom_routing: false,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const info = await getNodeInfo({
      config: { baseUrl: "https://node.example", fetchImpl: fetch },
      bearerKey: "ik_test_123",
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://node.example/v1/node-info");
    expect((calls[0]?.init?.headers as Record<string, string>)?.authorization).toBe(
      "Bearer ik_test_123",
    );
    expect(info.display_name).toBe("Checkout");
    expect(info.scopes).toEqual(["receives:write", "sends:write", "wallets:read_linked"]);
  });

  it("listWallets requests GET /v1/wallets and forwards include_workers when provided", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetch: FetchLike = async (url, init) => {
      calls.push({ url, init });
      return new Response(
        JSON.stringify({
          object: "list",
          data: [
            {
              wallet_id: "aaaaaaa1-1111-4111-8111-111111111111",
              display_name: "Reserve A",
              wallet_address: "pub_a",
              cached_balance_zkz: "100.00000000",
              is_default_for_connector: true,
              blessed: true,
            },
          ],
          wallets: [
            {
              wallet_id: "aaaaaaa1-1111-4111-8111-111111111111",
              display_name: "Reserve A",
              wallet_address: "pub_a",
              cached_balance_zkz: "100.00000000",
              is_default_for_connector: true,
              blessed: true,
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const res = await listWallets({
      config: { baseUrl: "https://node.example", fetchImpl: fetch },
      bearerKey: "ik_test_123",
      includeWorkers: true,
    });

    expect(calls[0]?.url).toBe("https://node.example/v1/wallets?include_workers=true");
    expect(res.data).toHaveLength(1);
    expect(res.data[0]?.wallet_id).toBe("aaaaaaa1-1111-4111-8111-111111111111");
  });

  it("listOperations encodes query filters and returns paginated operations", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetch: FetchLike = async (url, init) => {
      calls.push({ url, init });
      return new Response(
        JSON.stringify({
          object: "list",
          data: [],
          operations: [],
          has_more: false,
          next_cursor: null,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const res = await listOperations({
      config: { baseUrl: "https://node.example", fetchImpl: fetch },
      bearerKey: "ik_test_123",
      kind: "RECEIVE_EXTERNAL",
      state: "LANDED",
      external_ref: "order-101",
      limit: 25,
    });

    expect(calls[0]?.url).toBe(
      "https://node.example/v1/operations?kind=RECEIVE_EXTERNAL&state=LANDED&external_ref=order-101&limit=25",
    );
    expect(res.has_more).toBe(false);
    expect(res.data).toEqual([]);
  });
});
