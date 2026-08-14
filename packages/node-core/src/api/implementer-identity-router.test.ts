// ZTR-1288 · GET /v1/implementer/identity
import { describe, expect, it } from "vitest";

import {
  createFailClosedOperationStore,
  createImplementerBearerAuth,
  createImplementerIdentityRouter,
} from "./index.js";

const IMPL = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const WALLET = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PUB = "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=";
const TOKEN = "ik_test_identity_token_ztr1288_aaaaaaaa";

function auth() {
  return createImplementerBearerAuth({
    keys: [{ token: TOKEN, implementerId: IMPL, scopes: [] }],
  });
}

describe("ZTR-1288 · implementer identity router", () => {
  it("returns effective funding pin for bearer principal", async () => {
    const router = createImplementerIdentityRouter({
      store: createFailClosedOperationStore(),
      auth: auth(),
      newRequestId: () => "rid-1",
      loaders: {
        loadImplementerPin: async (id) => {
          expect(id).toBe(IMPL);
          return { funding_wallet_id: WALLET, funding_wallet_public_key: PUB };
        },
        loadNodeDefaultPin: async () => ({
          funding_wallet_id: null,
          funding_wallet_public_key: null,
        }),
      },
    });
    const res = await router(
      "GET",
      "/v1/implementer/identity",
      new Uint8Array(),
      { authorization: `Bearer ${TOKEN}` },
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as Record<string, unknown>;
    expect(body).toEqual({
      implementer_id: IMPL,
      funding_wallet_id: WALLET,
      funding_wallet_public_key: PUB,
      funding_configured: true,
      funding_source: "implementer",
    });
  });

  it("returns null funding when unset (no silent worker swap)", async () => {
    const router = createImplementerIdentityRouter({
      store: createFailClosedOperationStore(),
      auth: auth(),
      newRequestId: () => "rid-2",
      loaders: {
        loadImplementerPin: async () => ({
          funding_wallet_id: null,
          funding_wallet_public_key: null,
        }),
        loadNodeDefaultPin: async () => ({
          funding_wallet_id: null,
          funding_wallet_public_key: null,
        }),
      },
    });
    const res = await router(
      "GET",
      "/v1/implementer/identity",
      new Uint8Array(),
      { authorization: `Bearer ${TOKEN}` },
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as Record<string, unknown>;
    expect(body.funding_wallet_id).toBeNull();
    expect(body.funding_wallet_public_key).toBeNull();
    expect(body.funding_configured).toBe(false);
    expect(body.funding_source).toBe("unset");
  });

  it("401 without bearer", async () => {
    const router = createImplementerIdentityRouter({
      store: createFailClosedOperationStore(),
      auth: auth(),
      newRequestId: () => "rid-3",
      loaders: {
        loadImplementerPin: async () => {
          throw new Error("should not load");
        },
        loadNodeDefaultPin: async () => {
          throw new Error("should not load");
        },
      },
    });
    const res = await router("GET", "/v1/implementer/identity", new Uint8Array(), {});
    expect(res.status).toBe(401);
  });
});
