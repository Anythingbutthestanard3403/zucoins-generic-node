// Unit: mint composition writes wallet then PENDING dest; compensate deletes dest first.

import { describe, expect, it, vi } from "vitest";

import {
  DELETE_NODE_GENERATED_WALLET_SQL,
  DELETE_PENDING_DESTINATION_FOR_WALLET_SQL,
  INSERT_NODE_GENERATED_WALLET_SQL,
  INSERT_PENDING_DESTINATION_FOR_WALLET_SQL,
  deleteNodeGeneratedWalletMint,
  insertNodeGeneratedWalletWithPendingDestination,
} from "./insert-node-generated-wallet.js";

const WALLET = "22222222-2222-4222-8222-222222222222";
const NODE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const PUB = `${"A".repeat(43)}=`;

describe("insertNodeGeneratedWalletWithPendingDestination", () => {
  it("inserts wallet then PENDING dest with bound parameters", async () => {
    const calls: { text: string; params: readonly unknown[] | undefined }[] = [];
    const sql = {
      query: vi.fn(async (text: string, params?: readonly unknown[]) => {
        calls.push({ text, params });
        return { rows: [] };
      }),
    };
    await insertNodeGeneratedWalletWithPendingDestination(sql, {
      walletId: WALLET,
      nodeId: NODE,
      publicKey: PUB,
      label: "pool",
    });
    expect(calls).toHaveLength(2);
    expect(calls[0]!.text).toBe(INSERT_NODE_GENERATED_WALLET_SQL);
    expect(calls[0]!.params).toEqual([WALLET, NODE, PUB, true, true, true, "FULL"]);
    expect(calls[1]!.text).toBe(INSERT_PENDING_DESTINATION_FOR_WALLET_SQL);
    expect(calls[1]!.params).toEqual([WALLET, NODE, "pool", "PENDING"]);
    expect(calls[0]!.text).toContain("'node_generated'");
    expect(calls[1]!.text).toContain("$4");
    expect(calls[1]!.text).toMatch(/ON CONFLICT \(wallet_id\) DO NOTHING/);
    expect(calls[0]!.text).not.toContain(WALLET);
    expect(calls[1]!.text).not.toContain(WALLET);
  });

  it("defaults dest label to empty string", async () => {
    const params: (readonly unknown[] | undefined)[] = [];
    const sql = {
      query: vi.fn(async (_text: string, p?: readonly unknown[]) => {
        params.push(p);
        return { rows: [] };
      }),
    };
    await insertNodeGeneratedWalletWithPendingDestination(sql, {
      walletId: WALLET,
      nodeId: NODE,
      publicKey: PUB,
    });
    expect(params[1]).toEqual([WALLET, NODE, "", "PENDING"]);
  });

  it("SEND_ONLY writes SEND_ONLY wallet + WORKER dest", async () => {
    const calls: { text: string; params: readonly unknown[] | undefined }[] = [];
    const sql = {
      query: vi.fn(async (text: string, params?: readonly unknown[]) => {
        calls.push({ text, params });
        return { rows: [] };
      }),
    };
    await insertNodeGeneratedWalletWithPendingDestination(sql, {
      walletId: WALLET,
      nodeId: NODE,
      publicKey: PUB,
      label: "send-worker",
      role: "SEND_ONLY",
    });
    expect(calls[0]!.params).toEqual([WALLET, NODE, PUB, false, true, true, "SEND_ONLY"]);
    expect(calls[1]!.params).toEqual([WALLET, NODE, "send-worker", "WORKER"]);
  });

  it("RECEIVE_ONLY writes RECEIVE_ONLY wallet + PENDING dest", async () => {
    const params: (readonly unknown[] | undefined)[] = [];
    const sql = {
      query: vi.fn(async (_text: string, p?: readonly unknown[]) => {
        params.push(p);
        return { rows: [] };
      }),
    };
    await insertNodeGeneratedWalletWithPendingDestination(sql, {
      walletId: WALLET,
      nodeId: NODE,
      publicKey: PUB,
      role: "RECEIVE_ONLY",
    });
    expect(params[0]).toEqual([WALLET, NODE, PUB, true, false, true, "RECEIVE_ONLY"]);
    expect(params[1]).toEqual([WALLET, NODE, "", "PENDING"]);
  });
});

describe("deleteNodeGeneratedWalletMint", () => {
  it("deletes dest then wallet (FK first)", async () => {
    const texts: string[] = [];
    const sql = {
      query: vi.fn(async (text: string) => {
        texts.push(text);
        return { rows: [] };
      }),
    };
    await deleteNodeGeneratedWalletMint(sql, WALLET);
    expect(texts).toEqual([
      DELETE_PENDING_DESTINATION_FOR_WALLET_SQL,
      DELETE_NODE_GENERATED_WALLET_SQL,
    ]);
  });
});
