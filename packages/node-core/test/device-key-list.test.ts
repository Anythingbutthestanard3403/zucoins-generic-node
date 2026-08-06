import { describe, expect, it } from "vitest";

import {
  createSqlDeviceKeyStore,
  InMemoryDeviceKeyStore,
  type EnrolledDeviceKey,
} from "../src/device/index.js";

const NODE_A = "11111111-1111-4111-8111-111111111111";
const NODE_B = "22222222-2222-4222-8222-222222222222";

function key(
  id: string,
  nodeId: string,
  enrolledAt: string,
  revokedAt: string | null = null,
): EnrolledDeviceKey {
  return {
    id,
    nodeId,
    publicKey: `public-${id}`,
    label: `Device ${id}`,
    enrolledAt,
    revokedAt,
  };
}

describe("active device-key inventory", () => {
  it("lists only active keys for the requested node in stable enrollment order", () => {
    const store = new InMemoryDeviceKeyStore();
    store.insert(key("b", NODE_A, "2026-07-02T00:00:00.000Z"));
    store.insert(key("revoked", NODE_A, "2026-07-01T00:00:00.000Z", "2026-07-03T00:00:00.000Z"));
    store.insert(key("foreign", NODE_B, "2026-06-01T00:00:00.000Z"));
    store.insert(key("a", NODE_A, "2026-07-01T00:00:00.000Z"));

    expect(store.listActiveByNode(NODE_A).map((row) => row.id)).toEqual(["a", "b"]);
  });

  it("lists refreshed durable keys with the same active-only semantics", async () => {
    const sql = {
      async query<R extends Record<string, unknown>>() {
        const rows = [
          {
            id: "active",
            node_id: NODE_A,
            public_key: "public-active",
            label: "Active phone",
            enrolled_at: new Date("2026-07-01T00:00:00.000Z"),
            revoked_at: null,
          },
          {
            id: "revoked",
            node_id: NODE_A,
            public_key: "public-revoked",
            label: "Old phone",
            enrolled_at: new Date("2026-06-01T00:00:00.000Z"),
            revoked_at: new Date("2026-07-02T00:00:00.000Z"),
          },
        ];
        return {
          rows: rows as unknown as R[],
        };
      },
    };
    const store = createSqlDeviceKeyStore(sql);
    await store.refreshNode(NODE_A);

    expect(store.listActiveByNode(NODE_A).map((row) => row.id)).toEqual(["active"]);
  });
});
