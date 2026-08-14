// SqlDestinationStore unit tests (parameterized SQL; mock executor).

import { describe, expect, it, vi } from "vitest";

import { createSqlDestinationStore } from "../src/api/sql-destination-store.js";
import type { Uuid, WalletPublicKey } from "../src/protocol/scalars.js";

const NODE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" as Uuid;
const DEST = "11111111-1111-4111-8111-111111111111" as Uuid;
const WALLET = "22222222-2222-4222-8222-222222222222" as Uuid;
const PUB = `${"A".repeat(43)}=` as WalletPublicKey;

describe("createSqlDestinationStore", () => {
  it("inserts with bound parameters (no string-concat of ids)", async () => {
    const calls: { text: string; params: readonly unknown[] | undefined }[] = [];
    const sql = {
      query: vi.fn(async (text: string, params?: readonly unknown[]) => {
        calls.push({ text, params });
        return {
          rows: [
            {
              id: DEST,
              node_id: NODE,
              wallet_id: WALLET,
              label: "sink",
              state: "PENDING",
              created_at: "2026-07-29T00:00:00.000Z",
              blessed_at: null,
              blessed_by_device_key_id: null,
              blessing_artifact_id: null,
              retired_at: null,
            },
          ],
        };
      }),
    };
    const store = createSqlDestinationStore(sql);
    const created = await store.insert(
      {
        destinationId: DEST,
        nodeId: NODE,
        walletId: WALLET,
        walletPublicKey: PUB,
        label: "sink",
        createdAt: "2026-07-29T00:00:00.000Z",
      },
      "idem-key-should-not-appear-in-sql",
    );
    expect(created.state).toBe("PENDING");
    expect(created.destinationId).toBe(DEST);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.text).toMatch(/\$1/);
    expect(calls[0]!.text).not.toContain(DEST);
    expect(calls[0]!.params).toEqual([
      DEST,
      NODE,
      WALLET,
      "sink",
      "2026-07-29T00:00:00.000Z",
    ]);
    expect(calls[0]!.text).toMatch(/label/);
    expect(calls[0]!.text).toMatch(/ON CONFLICT \(wallet_id\)/);
    expect(calls[0]!.text).toMatch(/RETURNING/);
  });

  it("findById maps a row and returns null when missing", async () => {
    const sql = {
      query: vi.fn(async () => ({
        rows: [
          {
            id: DEST,
            node_id: NODE,
            wallet_id: WALLET,
            wallet_public_key: PUB,
            state: "PENDING",
            label: "Primary sink",
            blessed_at: null,
            blessed_by_device_key_id: null,
            blessing_artifact_id: null,
            retired_at: null,
            created_at: "2026-07-29T00:00:00.000Z",
          },
        ],
      })),
    };
    const store = createSqlDestinationStore(sql);
    const row = await store.findById(DEST);
    expect(row?.destinationId).toBe(DEST);
    expect(row?.label).toBe("Primary sink");
    sql.query.mockResolvedValueOnce({ rows: [] });
    expect(await store.findById(DEST)).toBeNull();
  });

  it("findByIdempotencyKey is a no-op without schema column", async () => {
    const sql = { query: vi.fn(async () => ({ rows: [] })) };
    const store = createSqlDestinationStore(sql);
    expect(await store.findByIdempotencyKey(NODE, "k")).toBeNull();
    expect(sql.query).not.toHaveBeenCalled();
  });
});
