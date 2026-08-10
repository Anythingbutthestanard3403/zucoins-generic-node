import { describe, expect, it } from "vitest";

// db/client.ts used to read process.env.DATABASE_URL and throw at MODULE IMPORT time,
// before any composition root's consolidated config validation (loadNodeConfig / loadStage1Config)
// had a chance to run. That meant an empty/malformed environment failed with whichever import was
// reached first instead of one actionable report, and merely importing a DB-backed module (e.g.
// for tooling or a unit test) had an environment side effect. This suite pins the fix: the module
// itself must be import-safe regardless of DATABASE_URL, and must expose only the injected
// createPool(databaseUrl) factory — no env-coupled singleton.
describe("db/client.ts import smoke", () => {
  it("imports cleanly with DATABASE_URL unset — no module-load env read or throw", async () => {
    const prior = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;
    try {
      await expect(import("../../src/db/client.js")).resolves.toBeDefined();
    } finally {
      if (prior === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = prior;
    }
  });

  it("exposes only side-effect-free exports — no eager pool/db singleton", async () => {
    const mod = await import("../../src/db/client.js");
    expect(typeof mod.createPool).toBe("function");
    // Sorted compare: the exact runtime export set, so any new env-coupled singleton
    // export still trips this change-detector. applyMoneyPathStatementTimeout and
    // DEFAULT_CREATE_POOL_OPTIONS are pure (ZTR-1156).
    expect(Object.keys(mod).sort()).toEqual(
      [
        "DEFAULT_CREATE_POOL_OPTIONS",
        "PostgresDeadlineExceededError",
        "applyMoneyPathStatementTimeout",
        "createPool",
        "withPostgresDeadline",
      ].sort(),
    );
  });

  it("createPool never opens a connection merely by constructing the Pool", async () => {
    const { createPool } = await import("../../src/db/client.js");
    const pool = createPool("postgres://user:pass@127.0.0.1:1/does-not-matter");
    try {
      expect(pool.totalCount).toBe(0);
    } finally {
      await pool.end();
    }
  });

  it("createPool applies safe timeouts + keepAlive by default (ZTR-1156)", async () => {
    const { createPool, DEFAULT_CREATE_POOL_OPTIONS } = await import("../../src/db/client.js");
    const pool = createPool("postgres://user:pass@127.0.0.1:1/does-not-matter");
    try {
      // pg stores options on the Pool instance; assert the load-bearing knobs.
      expect(pool.options.max).toBe(DEFAULT_CREATE_POOL_OPTIONS.max);
      expect(pool.options.connectionTimeoutMillis).toBe(
        DEFAULT_CREATE_POOL_OPTIONS.connectionTimeoutMillis,
      );
      expect(pool.options.idleTimeoutMillis).toBe(DEFAULT_CREATE_POOL_OPTIONS.idleTimeoutMillis);
      expect(pool.options.keepAlive).toBe(true);
      expect(pool.options.keepAliveInitialDelayMillis).toBe(
        DEFAULT_CREATE_POOL_OPTIONS.keepAliveInitialDelayMillis,
      );
    } finally {
      await pool.end();
    }
  });

  it("createPool accepts validated option overrides without env reads", async () => {
    const { createPool } = await import("../../src/db/client.js");
    const pool = createPool("postgres://user:pass@127.0.0.1:1/does-not-matter", {
      max: 7,
      connectionTimeoutMillis: 1234,
      idleTimeoutMillis: 4567,
      keepAliveInitialDelayMillis: 890,
    });
    try {
      expect(pool.options.max).toBe(7);
      expect(pool.options.connectionTimeoutMillis).toBe(1234);
      expect(pool.options.idleTimeoutMillis).toBe(4567);
      expect(pool.options.keepAlive).toBe(true);
      expect(pool.options.keepAliveInitialDelayMillis).toBe(890);
    } finally {
      await pool.end();
    }
  });

  it("a pool's unhandled idle-connection 'error' event is logged, not thrown", async () => {
    const { createPool } = await import("../../src/db/client.js");
    const pool = createPool("postgres://user:pass@127.0.0.1:1/does-not-matter");
    try {
      expect(() => pool.emit("error", new Error("simulated idle connection drop"))).not.toThrow();
    } finally {
      await pool.end();
    }
  });
});
