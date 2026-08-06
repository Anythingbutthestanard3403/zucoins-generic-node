import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DISCOVER_RESTORE_NODE_IDS_SQL,
  runFailClosedPerNodeHold,
  type HoldDbClient,
} from "../../src/dr/hold-db-orchestration.js";
import {
  forceRestoreHoldOnClient,
  REPORTING_RESTORE_STATE_EXISTS_SQL,
} from "../../src/dr/restore-hold.js";

type QueryCall = { sql: string; values?: unknown[] };

function mockClient(handler: (sql: string, values?: unknown[]) => Promise<unknown>): {
  client: HoldDbClient;
  calls: QueryCall[];
} {
  const calls: QueryCall[] = [];
  return {
    calls,
    client: {
      query: async (sql: string, values?: unknown[]) => {
        calls.push({ sql, values });
        return handler(sql, values) as never;
      },
    },
  };
}

describe("runFailClosedPerNodeHold", () => {
  it("explicit nodeId applies once and skips discovery", async () => {
    const applied: string[] = [];
    const { client, calls } = mockClient(async (sql) => {
      if (sql === "EXISTS") return { rowCount: 1, rows: [{ "?column?": 1 }] };
      throw new Error(`unexpected sql: ${sql}`);
    });

    const result = await runFailClosedPerNodeHold(client, {
      tableExistsSql: "EXISTS",
      explicitNodeId: "  aaa-bbb  ",
      discoverNodeIdsSql: "DISCOVER",
      applyPerNode: async (_c, nodeId) => {
        applied.push(nodeId);
      },
    });

    expect(result).toEqual({ applied: true, nodeIds: ["aaa-bbb"] });
    expect(applied).toEqual(["aaa-bbb"]);
    expect(calls.map((c) => c.sql)).toEqual(["EXISTS"]);
  });

  it("discovers node IDs and deduplicates across restore-state ∪ nodes", async () => {
    const applied: string[] = [];
    const { client } = mockClient(async (sql) => {
      if (sql === "EXISTS") return { rowCount: 1, rows: [{}] };
      if (sql === "DISCOVER") {
        return {
          rowCount: 3,
          rows: [
            { node_id: "n1" },
            { node_id: "n2" },
            { node_id: "n1" },
          ],
        };
      }
      throw new Error(`unexpected sql: ${sql}`);
    });

    const result = await runFailClosedPerNodeHold(client, {
      tableExistsSql: "EXISTS",
      discoverNodeIdsSql: "DISCOVER",
      applyPerNode: async (_c, nodeId) => {
        applied.push(nodeId);
      },
    });

    expect(result).toEqual({ applied: true, nodeIds: ["n1", "n2"] });
    expect(applied).toEqual(["n1", "n2"]);
  });

  it("blank explicit nodeId falls through to discovery", async () => {
    const applied: string[] = [];
    const { client } = mockClient(async (sql) => {
      if (sql === "EXISTS") return { rowCount: 1, rows: [{}] };
      if (sql === "DISCOVER") return { rowCount: 1, rows: [{ node_id: "discovered" }] };
      throw new Error(`unexpected sql: ${sql}`);
    });

    const result = await runFailClosedPerNodeHold(client, {
      tableExistsSql: "EXISTS",
      explicitNodeId: "   ",
      discoverNodeIdsSql: "DISCOVER",
      applyPerNode: async (_c, nodeId) => {
        applied.push(nodeId);
      },
    });

    expect(result).toEqual({ applied: true, nodeIds: ["discovered"] });
    expect(applied).toEqual(["discovered"]);
  });

  it("absent table is a no-op (missing-schema)", async () => {
    const applied: string[] = [];
    const { client, calls } = mockClient(async (sql) => {
      if (sql === "EXISTS") return { rowCount: 0, rows: [] };
      throw new Error(`unexpected sql: ${sql}`);
    });

    const result = await runFailClosedPerNodeHold(client, {
      tableExistsSql: "EXISTS",
      discoverNodeIdsSql: "DISCOVER",
      applyPerNode: async (_c, nodeId) => {
        applied.push(nodeId);
      },
    });

    expect(result).toEqual({ applied: false, nodeIds: [] });
    expect(applied).toEqual([]);
    expect(calls).toHaveLength(1);
  });

  it("present table + empty discovery returns applied=false", async () => {
    const { client } = mockClient(async (sql) => {
      if (sql === "EXISTS") return { rowCount: 1, rows: [{}] };
      if (sql === "DISCOVER") return { rowCount: 0, rows: [] };
      throw new Error(`unexpected sql: ${sql}`);
    });

    await expect(
      runFailClosedPerNodeHold(client, {
        tableExistsSql: "EXISTS",
        discoverNodeIdsSql: "DISCOVER",
        applyPerNode: async () => {
          throw new Error("must not apply");
        },
      }),
    ).resolves.toEqual({ applied: false, nodeIds: [] });
  });

  it("query failure while table exists propagates (fail-closed)", async () => {
    const { client } = mockClient(async (sql) => {
      if (sql === "EXISTS") return { rowCount: 1, rows: [{}] };
      if (sql === "DISCOVER") throw new Error("discover boom");
      throw new Error(`unexpected sql: ${sql}`);
    });

    await expect(
      runFailClosedPerNodeHold(client, {
        tableExistsSql: "EXISTS",
        discoverNodeIdsSql: "DISCOVER",
        applyPerNode: async () => undefined,
      }),
    ).rejects.toThrow("discover boom");
  });

  it("applyPerNode failure propagates after partial work stop (fail-closed)", async () => {
    const applied: string[] = [];
    const { client } = mockClient(async (sql) => {
      if (sql === "EXISTS") return { rowCount: 1, rows: [{}] };
      if (sql === "DISCOVER") {
        return { rowCount: 2, rows: [{ node_id: "a" }, { node_id: "b" }] };
      }
      throw new Error(`unexpected sql: ${sql}`);
    });

    await expect(
      runFailClosedPerNodeHold(client, {
        tableExistsSql: "EXISTS",
        discoverNodeIdsSql: "DISCOVER",
        applyPerNode: async (_c, nodeId) => {
          applied.push(nodeId);
          if (nodeId === "a") throw new Error("apply boom");
        },
      }),
    ).rejects.toThrow("apply boom");
    expect(applied).toEqual(["a"]);
  });
});

describe("forceRestoreHoldOnClient — wires restore-state SQL via shared orchestration", () => {
  it("uses REPORTING_RESTORE_STATE_EXISTS_SQL and DISCOVER_RESTORE_NODE_IDS_SQL", async () => {
    const { client, calls } = mockClient(async (sql) => {
      if (sql === REPORTING_RESTORE_STATE_EXISTS_SQL) return { rowCount: 1, rows: [{}] };
      if (sql === DISCOVER_RESTORE_NODE_IDS_SQL) {
        return { rowCount: 1, rows: [{ node_id: "node-1" }] };
      }
      if (sql.includes("INSERT INTO reporting_restore_state")) {
        return { rowCount: 1, rows: [] };
      }
      throw new Error(`unexpected sql: ${sql.slice(0, 80)}`);
    });

    const result = await forceRestoreHoldOnClient(client, {
      now: new Date("2026-07-26T12:00:00.000Z"),
    });

    expect(result).toEqual({ applied: true, nodeIds: ["node-1"] });
    expect(calls[0]?.sql).toBe(REPORTING_RESTORE_STATE_EXISTS_SQL);
    expect(calls[1]?.sql).toBe(DISCOVER_RESTORE_NODE_IDS_SQL);
    expect(calls[2]?.sql).toMatch(/INSERT INTO reporting_restore_state/);
    expect(calls[2]?.values?.[0]).toBe("node-1");
  });
});

describe("withConnectedPgClient — connect/finally-end lifecycle", () => {
  afterEach(() => {
    vi.doUnmock("pg");
    vi.resetModules();
    vi.unstubAllGlobals();
  });

  it("connects, runs fn, ends client on success", async () => {
    const end = vi.fn(async () => undefined);
    const connect = vi.fn(async () => undefined);
    const query = vi.fn();

    vi.doMock("pg", () => ({
      Client: class {
        connectionString: string;
        constructor(opts: { connectionString: string }) {
          this.connectionString = opts.connectionString;
        }
        connect = connect;
        end = end;
        query = query;
      },
    }));

    vi.resetModules();
    const { withConnectedPgClient: withClient } = await import(
      "../../src/dr/hold-db-orchestration.js"
    );

    const out = await withClient("postgresql://u@h/db", async (client) => {
      expect(client).toBeDefined();
      return 42;
    });

    expect(out).toBe(42);
    expect(connect).toHaveBeenCalledOnce();
    expect(end).toHaveBeenCalledOnce();
  });

  it("ends client even when fn throws (cleanup)", async () => {
    const end = vi.fn(async () => undefined);
    const connect = vi.fn(async () => undefined);

    vi.doMock("pg", () => ({
      Client: class {
        constructor(_opts: { connectionString: string }) {}
        connect = connect;
        end = end;
        query = vi.fn();
      },
    }));

    vi.resetModules();
    const { withConnectedPgClient: withClient } = await import(
      "../../src/dr/hold-db-orchestration.js"
    );

    await expect(
      withClient("postgresql://u@h/db", async () => {
        throw new Error("work failed");
      }),
    ).rejects.toThrow("work failed");

    expect(connect).toHaveBeenCalledOnce();
    expect(end).toHaveBeenCalledOnce();
  });
});
