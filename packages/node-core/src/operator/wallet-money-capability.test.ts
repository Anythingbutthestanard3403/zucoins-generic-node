import { describe, expect, it } from "vitest";

import { flagsFromMode } from "@zucoins/generic-node-contracts/wallet-state";

import {
  InMemoryWalletMoneyCapabilityStore,
  WALLET_MONEY_CAPABILITY_AUDIT_ACTION,
  createSqlWalletMoneyCapabilityStore,
  type WalletMoneyCapabilitySetInput,
} from "./wallet-money-capability.js";

const NODE = "11111111-1111-4111-8111-111111111111";
const WALLET = "22222222-2222-4222-8222-222222222222";
const WALLET_B = "33333333-3333-4333-8333-333333333333";
const ACTOR = "op-1";

function baseInput(
  overrides: Partial<WalletMoneyCapabilitySetInput> = {},
): WalletMoneyCapabilitySetInput {
  return {
    walletId: WALLET,
    mode: "SEND_ONLY",
    expectedRowVersion: 1,
    actorId: ACTOR,
    nodeId: NODE,
    ...overrides,
  };
}

describe("InMemoryWalletMoneyCapabilityStore", () => {
  it("sets mode via flagsFromMode, bumps row_version, and audits before→after", async () => {
    const store = new InMemoryWalletMoneyCapabilityStore();
    store.seed({
      wallet_id: WALLET,
      node_id: NODE,
      money_mode: "FULL",
      ...flagsFromMode("FULL"),
      row_version: 1,
    });

    const out = await store.setMode(baseInput({ mode: "INTERNAL_ONLY" }));
    expect(out.ok).toBe(true);
    if (!out.ok) return;

    expect(out.result.money_mode).toBe("INTERNAL_ONLY");
    expect(out.result).toMatchObject(flagsFromMode("INTERNAL_ONLY"));
    expect(out.result.row_version).toBe(2);
    expect(out.result.previous_mode).toBe("FULL");
    expect(out.result.previous_flags).toEqual(flagsFromMode("FULL"));
    expect(store.auditEntries).toHaveLength(1);
    expect(store.auditEntries[0]!.details).toContain("previous_mode=FULL");
    expect(store.auditEntries[0]!.details).toContain("next_mode=INTERNAL_ONLY");
  });

  it("CAS-conflicts when expected_row_version is stale", async () => {
    const store = new InMemoryWalletMoneyCapabilityStore();
    store.seed({
      wallet_id: WALLET,
      node_id: NODE,
      money_mode: "FULL",
      ...flagsFromMode("FULL"),
      row_version: 3,
    });
    const out = await store.setMode(baseInput({ expectedRowVersion: 1 }));
    expect(out).toEqual({ ok: false, reason: "conflict" });
    expect(store.auditEntries).toHaveLength(0);
  });

  it("returns wallet_not_found for unknown id", async () => {
    const store = new InMemoryWalletMoneyCapabilityStore();
    const out = await store.setMode(baseInput());
    expect(out).toEqual({ ok: false, reason: "wallet_not_found" });
  });

  it("allows multiple INTERNAL_ONLY wallets and warns when fleet loses send/receive", async () => {
    const store = new InMemoryWalletMoneyCapabilityStore();
    store.seed({
      wallet_id: WALLET,
      node_id: NODE,
      money_mode: "FULL",
      ...flagsFromMode("FULL"),
      row_version: 1,
    });
    store.seed({
      wallet_id: WALLET_B,
      node_id: NODE,
      money_mode: "FULL",
      ...flagsFromMode("FULL"),
      row_version: 1,
    });

    const a = await store.setMode(baseInput({ mode: "INTERNAL_ONLY" }));
    expect(a.ok).toBe(true);
    if (!a.ok) return;
    expect(a.result.warnings.zero_send_capable).toBe(false);
    expect(a.result.warnings.zero_receive_capable).toBe(false);

    const b = await store.setMode(
      baseInput({ walletId: WALLET_B, mode: "INTERNAL_ONLY", expectedRowVersion: 1 }),
    );
    expect(b.ok).toBe(true);
    if (!b.ok) return;
    expect(b.result.money_mode).toBe("INTERNAL_ONLY");
    expect(b.result.warnings.zero_send_capable).toBe(true);
    expect(b.result.warnings.zero_receive_capable).toBe(true);
  });
});

describe("createSqlWalletMoneyCapabilityStore", () => {
  it("CAS-updates wallets and inserts audit_log with before→after details", async () => {
    const audits: Array<readonly unknown[]> = [];
    let rowVersion = 1;
    let mode = "FULL";
    let allowReceive = true;
    let allowSend = true;
    let allowMove = true;

    const sql = {
      async query(text: string, params?: readonly unknown[]) {
        if (text.includes("FOR UPDATE")) {
          return {
            rows: [
              {
                id: WALLET,
                money_mode: mode,
                allow_external_receive: allowReceive,
                allow_external_send: allowSend,
                allow_internal_move: allowMove,
                row_version: rowVersion,
              },
            ],
          };
        }
        if (text.includes("UPDATE wallets")) {
          const expected = Number(params![6]);
          if (expected !== rowVersion) return { rows: [] };
          mode = String(params![2]);
          allowReceive = Boolean(params![3]);
          allowSend = Boolean(params![4]);
          allowMove = Boolean(params![5]);
          rowVersion += 1;
          return {
            rows: [
              {
                money_mode: mode,
                allow_external_receive: allowReceive,
                allow_external_send: allowSend,
                allow_internal_move: allowMove,
                row_version: rowVersion,
              },
            ],
          };
        }
        if (text.includes("INSERT INTO audit_log")) {
          audits.push(params ?? []);
          return { rows: [] };
        }
        if (text.includes("FROM wallets") && text.includes("node_id")) {
          return {
            rows: [
              {
                allow_external_receive: allowReceive,
                allow_external_send: allowSend,
              },
            ],
          };
        }
        throw new Error(`unexpected SQL: ${text.slice(0, 80)}`);
      },
    };

    const store = createSqlWalletMoneyCapabilityStore(sql as never, {
      newId: () => "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    });
    const out = await store.setMode(baseInput({ mode: "RECEIVE_ONLY" }));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.result.money_mode).toBe("RECEIVE_ONLY");
    expect(out.result.row_version).toBe(2);
    expect(out.result.previous_mode).toBe("FULL");
    expect(out.result.warnings.zero_send_capable).toBe(true);
    expect(out.result.warnings.zero_receive_capable).toBe(false);

    expect(audits).toHaveLength(1);
    expect(audits[0]![3]).toBe(WALLET_MONEY_CAPABILITY_AUDIT_ACTION);
    expect(String(audits[0]![5])).toContain("previous_mode=FULL");
    expect(String(audits[0]![5])).toContain("next_mode=RECEIVE_ONLY");
  });

  it("returns conflict when row_version mismatches", async () => {
    const sql = {
      async query() {
        return {
          rows: [
            {
              id: WALLET,
              money_mode: "FULL",
              allow_external_receive: true,
              allow_external_send: true,
              allow_internal_move: true,
              row_version: 9,
            },
          ],
        };
      },
    };
    const store = createSqlWalletMoneyCapabilityStore(sql as never);
    const out = await store.setMode(baseInput({ expectedRowVersion: 1 }));
    expect(out).toEqual({ ok: false, reason: "conflict" });
  });
});
