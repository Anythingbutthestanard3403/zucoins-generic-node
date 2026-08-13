import { describe, expect, it, vi } from "vitest";
import {
  ARM_SQL_STATEMENTS,
  isArmableWalletStanding,
} from "@zucoins/node-core";
import { createPoolArmTxFactory, createPoolArmWalletGate } from "./arm-wallet-gate.js";

describe("createPoolArmTxFactory / createPoolArmWalletGate", () => {
  it("pins one client: BEGIN → body → COMMIT and releases", async () => {
    const queries: string[] = [];
    const client = {
      query: vi.fn(async (text: string) => {
        queries.push(text);
        if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") {
          return { rows: [] };
        }
        if (text === ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING) {
          return {
            rows: [
              {
                wallet_id: "w1",
                state: "PINNED",
                recovery_verified_at: "2026-01-15T10:00:00.000Z",
                allow_external_receive: true,
              },
            ],
          };
        }
        return { rows: [] };
      }),
      release: vi.fn(),
    };
    const pool = {
      connect: vi.fn(async () => client),
    };

    const factory = createPoolArmTxFactory(pool as never);
    const result = await factory.withTransaction(async (tx) => {
      const locked = await tx.query(ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING, ["w1"]);
      return locked.rows[0];
    });

    expect(pool.connect).toHaveBeenCalledOnce();
    expect(queries[0]).toBe("BEGIN");
    expect(queries[1]).toMatch(/set_config\('statement_timeout'/);
    expect(queries).toContain(ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING);
    expect(queries.at(-1)).toBe("COMMIT");
    expect(client.release).toHaveBeenCalledOnce();
    expect(result).toMatchObject({ state: "PINNED" });
  });

  it("ROLLBACK on body throw and still releases the client", async () => {
    const queries: string[] = [];
    const client = {
      query: vi.fn(async (text: string) => {
        queries.push(text);
        return { rows: [] };
      }),
      release: vi.fn(),
    };
    const pool = { connect: vi.fn(async () => client) };
    const factory = createPoolArmTxFactory(pool as never);
    await expect(
      factory.withTransaction(async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(queries[0]).toBe("BEGIN");
    expect(queries[1]).toMatch(/set_config\('statement_timeout'/);
    expect(queries.at(-1)).toBe("ROLLBACK");
    expect(client.release).toHaveBeenCalledOnce();
  });

  it("createPoolArmWalletGate exposes withWalletLocked and live standing", async () => {
    const client = {
      query: vi.fn(async (text: string) => {
        if (text === "BEGIN" || text === "COMMIT" || text.includes("set_config")) return { rows: [] };
        if (text === ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING) {
          return {
            rows: [
              {
                wallet_id: "w1",
                state: "PINNED",
                recovery_verified_at: "2026-01-15T10:00:00.000Z",
                allow_external_receive: true,
              },
            ],
          };
        }
        return { rows: [] };
      }),
      release: vi.fn(),
    };
    const pool = { connect: vi.fn(async () => client) };
    const gate = createPoolArmWalletGate(pool as never);
    const standing = await gate.withWalletLocked("w1", async (lock) => {
      const s = await lock.readStanding();
      expect(s).not.toBeNull();
      expect(isArmableWalletStanding(s!).ok).toBe(true);
      return s;
    });
    expect(standing!.state).toBe("PINNED");
    expect(client.release).toHaveBeenCalledOnce();
  });
});

describe("createFailClosedPoolArmHandler (acceptance honesty)", () => {
  it("refuses arm until engine injects gate + tx-bound store", async () => {
    const { createFailClosedPoolArmHandler } = await import("./arm-wallet-gate.js");
    const handler = createFailClosedPoolArmHandler();
    await expect(handler("op-x")).rejects.toThrow(/not wired|inject/i);
  });
});

describe("createPoolArmWalletGate requireCommitSession binds sql tx", () => {
  it("session.sqlTx is the same object used for FOR UPDATE queries", async () => {
    const { activeArmTx } = await import("@zucoins/node-core");
    let captured: unknown;
    const client = {
      query: vi.fn(async (text: string) => {
        if (text === "BEGIN" || text === "COMMIT" || text.includes("set_config")) return { rows: [] };
        if (text === ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING) {
          return {
            rows: [
              {
                wallet_id: "w1",
                state: "PINNED",
                recovery_verified_at: "2026-01-15T10:00:00.000Z",
                allow_external_receive: true,
              },
            ],
          };
        }
        return { rows: [] };
      }),
      release: vi.fn(),
    };
    const pool = { connect: vi.fn(async () => client) };
    const gate = createPoolArmWalletGate(pool as never);
    await gate.withWalletLocked("w1", async (lock) => {
      const session = lock.requireCommitSession();
      expect(session.kind).toBe("sql");
      if (session.kind === "sql") {
        expect(session.sqlTx).toBe(activeArmTx());
        captured = session.sqlTx;
      }
    });
    expect(captured).toBeDefined();
  });
});
