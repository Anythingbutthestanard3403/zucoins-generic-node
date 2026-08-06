import { describe, expect, it } from "vitest";
import type { Pool } from "pg";

import { PostgresDeadlineExceededError, withPostgresDeadline } from "../src/db/client.js";

describe("withPostgresDeadline", () => {
  it("serializes concurrent statements against remaining monotonic budget and releases after rollback", async () => {
    let now = 0;
    const events: string[] = [];
    let configuredTimeout = 0;
    const client = {
      async query(text: string, params?: readonly unknown[]) {
        if (text === "BEGIN" || text === "ROLLBACK" || text === "COMMIT") {
          events.push(text);
          return { rows: [] };
        }
        if (text.includes("set_config")) {
          configuredTimeout = Number(String(params?.[0]).replace("ms", ""));
          events.push(`timeout:${configuredTimeout}`);
          return { rows: [] };
        }
        events.push(`query:${text}`);
        now += configuredTimeout;
        throw new Error("canceling statement due to statement timeout");
      },
      release() {
        events.push("release");
      },
    };
    const pool = { connect: async () => client } as unknown as Pool;

    await expect(withPostgresDeadline(
      pool,
      20,
      async (db) => Promise.all([db.query("slow-1"), db.query("slow-2")]),
      () => now,
    )).rejects.toThrow();

    expect(events).toEqual([
      "BEGIN",
      "timeout:20",
      "query:slow-1",
      "ROLLBACK",
      "release",
    ]);
  });

  it("times out pool acquisition and releases a client that arrives late", async () => {
    let resolveConnect!: (client: { release(): void }) => void;
    let released = false;
    const pool = {
      connect: () => new Promise((resolve) => {
        resolveConnect = resolve;
      }),
    } as unknown as Pool;

    await expect(withPostgresDeadline(pool, 5, async () => undefined)).rejects.toBeInstanceOf(
      PostgresDeadlineExceededError,
    );
    resolveConnect({ release: () => { released = true; } });
    await Promise.resolve();
    await Promise.resolve();
    expect(released).toBe(true);
  });
});
