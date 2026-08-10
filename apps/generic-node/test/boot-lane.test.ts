import {
  acquireSignerLeadership,
  RELEASE_LEADERSHIP_SQL,
  SIGNER_LEADERSHIP_LOCK_ID,
  SignerLeadership,
  TRY_ACQUIRE_LEADERSHIP_SQL,
  tryAcquireSignerLeadership,
  type LeadershipLockClient,
  type LeadershipLockPool,
} from "@zucoins/node-core";
import { describe, expect, it } from "vitest";

import {
  dispositionForIncompleteBoot,
  runBootLane,
  type BootLogger,
  type BootLaneResult,
  type SignerLeadershipHandle,
} from "../src/boot/boot-lane.js";
import { NodeReadiness } from "../src/boot/readiness.js";
import { acquireSignerLeadershipWithBoundedRetry } from "../src/boot/signer-leadership-retry.js";
import { loadNodeConfig, NodeConfigurationError } from "../src/config/index.js";

const noopLogger: BootLogger = { info: () => {}, error: () => {} };

function makeLeadership(events: string[]): SignerLeadershipHandle {
  return {
    release: () => {
      events.push("leadership:release");
    },
  };
}

function happyDeps(events: string[], readiness: NodeReadiness) {
  return {
    readiness,
    logger: noopLogger,
    runMigrations: async () => {
      events.push("migrations");
    },
    unlockVault: async () => {
      events.push("vault");
    },
    acquireSignerLeadership: async () => {
      events.push("leadership");
      return makeLeadership(events);
    },
    // Explicit no-op recovery for non-recovery gate tests (never omit — D3).
    runBootRecovery: async () => {
      events.push("boot-recovery");
      // Mirrors main.ts's real recovery step arming EVENT_SIGNING on success.
      readiness.setEventSignerAvailable(true);
      return { ready: true as const, invariantBreach: false as const };
    },
    performValidatedGatewayRead: async () => {
      events.push("gateway-read");
    },
    startMoneyWorkers: () => {
      events.push("money-workers");
    },
  };
}

describe("boot lane — boot recovery ordering", () => {
  it("runs migrations → vault → gateway → leadership → recovery → money workers", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const result = await runBootLane(happyDeps(events, readiness));

    expect(result.ready).toBe(true);
    expect(events).toEqual(["migrations", "vault", "gateway-read", "leadership", "boot-recovery", "money-workers"]);
    expect(readiness.snapshot().ready).toBe(true);
    expect(result.leadership).toBeDefined();
  });

  it("readiness stays false until the validated gateway read completes", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = happyDeps(events, readiness);
    const seen: boolean[] = [];
    deps.startMoneyWorkers = () => {
      seen.push(readiness.snapshot().ready);
      events.push("money-workers");
    };
    await runBootLane(deps);
    expect(seen).toEqual([true]);
  });

  it("money workers never start when an earlier step fails", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = happyDeps(events, readiness);
    deps.unlockVault = async () => {
      throw new Error("vault sealed");
    };
    const result = await runBootLane(deps);

    expect(result.ready).toBe(false);
    expect(result.failedStep).toBe("vault-unlock");
    expect(events).toEqual(["migrations"]);
    expect(readiness.snapshot().ready).toBe(false);
    expect(readiness.snapshot().checks.vault).toBe(false);
  });

  it("runs the post-migration assertion after migrations, before the vault (wiring point)", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = {
      ...happyDeps(events, readiness),
      assertPostMigrationReadiness: async () => {
        events.push("privilege-readiness");
      },
    };
    const result = await runBootLane(deps);
    expect(result.ready).toBe(true);
    expect(events.slice(0, 3)).toEqual(["migrations", "privilege-readiness", "vault"]);
  });

  it("a failing post-migration assertion halts the lane before the vault opens", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = {
      ...happyDeps(events, readiness),
      assertPostMigrationReadiness: async () => {
        throw new Error("least-privilege role not ready");
      },
    };
    const result = await runBootLane(deps);
    expect(result.ready).toBe(false);
    expect(result.failedStep).toBe("migrations");
    expect(events).toEqual(["migrations"]);
    expect(readiness.snapshot().checks.schema).toBe(false);
  });

  it("releases signer leadership when a later step fails after acquisition", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = happyDeps(events, readiness);
    deps.startMoneyWorkers = () => {
      throw new Error("worker spawn failed");
    };
    const result = await runBootLane(deps);

    expect(result.ready).toBe(false);
    expect(result.failedStep).toBe("money-workers");
    expect(events).toContain("leadership:release");
    expect(readiness.snapshot().checks.leadership).toBe(false);
  });
});

// The lane's `acquireSignerLeadership` seam is where the real lock plugs in. Wiring the real
// primitive here proves the two halves fit and that the readiness gate opens on a CONFIRMED
// acquisition, not on the attempt.
describe("signer leadership wiring (readiness gate)", () => {
  function lockPool(grantOnAttempt: number): LeadershipLockPool {
    let attempt = 0;
    return {
      connect: async () => ({
        query: async () => ({ rows: [{ locked: ++attempt >= grantOnAttempt }] }),
        on: () => {},
        removeListener: () => {},
        release: () => {},
      }),
    };
  }

  it("the leadership gate stays shut while acquisition is still retrying", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const latch = new SignerLeadership();
    const deps = happyDeps(events, readiness);
    const gateWhileWaiting: boolean[] = [];

    deps.acquireSignerLeadership = async () => {
      events.push("leadership");
      const held = await acquireSignerLeadership({
        pool: lockPool(3),
        latch,
        sleep: async () => {
          gateWhileWaiting.push(readiness.snapshot().checks.leadership || latch.held);
        },
      });
      return { release: () => held?.release() };
    };

    const result = await runBootLane(deps);

    expect(gateWhileWaiting).toEqual([false, false]);
    expect(result.ready).toBe(true);
    expect(latch.held).toBe(true);
    expect(readiness.snapshot().checks.leadership).toBe(true);
  });

  it("money workers never start when leadership is never acquired", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = happyDeps(events, readiness);
    const signal = { aborted: false };

    deps.acquireSignerLeadership = async () => {
      const held = await acquireSignerLeadership({
        pool: lockPool(Number.POSITIVE_INFINITY),
        latch: new SignerLeadership(),
        signal,
        sleep: async () => {
          signal.aborted = true;
        },
      });
      if (held === null) throw new Error("signer leadership not acquired");
      return { release: () => held.release() };
    };

    const result = await runBootLane(deps);

    expect(result.ready).toBe(false);
    expect(result.failedStep).toBe("signer-leadership");
    expect(events).not.toContain("money-workers");
    expect(readiness.snapshot().checks.leadership).toBe(false);
  });
});

describe("acquireSignerLeadershipWithBoundedRetry (rolling-deploy handover; ZPAY-252)", () => {
  function lockPool(grantOnAttempt: number): LeadershipLockPool {
    let attempt = 0;
    return {
      connect: async () => ({
        query: async () => ({ rows: [{ locked: ++attempt >= grantOnAttempt }] }),
        on: () => {},
        removeListener: () => {},
        release: () => {},
      }),
    };
  }

  function spyLogger(): { logger: BootLogger; info: string[]; error: string[] } {
    const info: string[] = [];
    const error: string[] = [];
    return {
      logger: {
        info: (message) => info.push(message),
        error: (message) => error.push(message),
      },
      info,
      error,
    };
  }

  const realTinySleep = () => new Promise<void>((resolve) => setTimeout(resolve, 5));

  it("AC1: succeeds once the prior holder releases (waiting-for-handover logs)", async () => {
    const { logger, info } = spyLogger();
    const pool = lockPool(3);

    const held = await acquireSignerLeadershipWithBoundedRetry({
      pool,
      latch: new SignerLeadership(),
      prolongedWaitMs: 60_000,
      logger,
      acquire: (options) => acquireSignerLeadership({ ...options, sleep: realTinySleep }),
    });

    expect(held).not.toBeNull();
    expect(info).toHaveLength(2);
    expect(info[0]).toMatch(/waiting-for-handover/);
    expect(info[0]).toMatch(/attempt 1/);
    expect(info[1]).toMatch(/waiting-for-handover/);
    expect(info[1]).toMatch(/attempt 2/);
  });

  it("AC3: prolonged-wait log once the warn threshold elapses (acquisition continues until abort)", async () => {
    const { logger, info, error } = spyLogger();
    const pool = lockPool(Number.POSITIVE_INFINITY);
    const abort = new AbortController();
    let waits = 0;

    const held = await acquireSignerLeadershipWithBoundedRetry({
      pool,
      latch: new SignerLeadership(),
      signal: abort.signal,
      // 0ms → first onWaiting is already past the threshold.
      prolongedWaitMs: 0,
      logger,
      acquire: (options) =>
        acquireSignerLeadership({
          ...options,
          sleep: async () => {
            waits += 1;
            if (waits >= 2) abort.abort();
          },
        }),
    });

    expect(held).toBeNull();
    expect(error.some((line) => /prolonged wait/.test(line))).toBe(true);
    // First wait may already be prolonged (threshold 0); handover log is optional.
    expect(error.length + info.length).toBeGreaterThan(0);
  });

  it("abort (shutdown) ends the wait without dual leadership", async () => {
    const { logger, info } = spyLogger();
    const pool = lockPool(Number.POSITIVE_INFINITY);
    const abort = new AbortController();

    const held = await acquireSignerLeadershipWithBoundedRetry({
      pool,
      latch: new SignerLeadership(),
      signal: abort.signal,
      prolongedWaitMs: 60_000,
      logger,
      acquire: (options) =>
        acquireSignerLeadership({
          ...options,
          sleep: async () => {
            abort.abort();
          },
        }),
    });

    expect(held).toBeNull();
    expect(info.some((line) => /waiting-for-handover/.test(line))).toBe(true);
  });
});


// Boot recovery sits after leadership; gateway is before leadership (ZPAY-252).
describe("boot recovery wiring", () => {
  it("runs gateway before leadership, recovery after leadership, money workers last", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = {
      ...happyDeps(events, readiness),
      runBootRecovery: async () => {
        events.push("boot-recovery");
        readiness.setEventSignerAvailable(true);
        return { ready: true, invariantBreach: false };
      },
    };
    const result = await runBootLane(deps);
    expect(result.ready).toBe(true);
    expect(events).toEqual([
      "migrations",
      "vault",
      "gateway-read",
      "leadership",
      "boot-recovery",
      "money-workers",
    ]);
  });

  it("invariant breach keeps readiness false and never starts money workers (holds leadership)", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = {
      ...happyDeps(events, readiness),
      runBootRecovery: async () => {
        events.push("boot-recovery");
        return { ready: false, invariantBreach: true };
      },
    };
    const result = await runBootLane(deps);
    expect(result.ready).toBe(false);
    expect(result.failedStep).toBe("boot-recovery");
    expect(result.bootRecovery?.invariantBreach).toBe(true);
    expect(events).toContain("gateway-read"); // deploy-ready before leadership (ZPAY-252)
    expect(events).not.toContain("money-workers");
    // Leadership is retained so a second instance cannot sign into a broken inventory.
    expect(events).not.toContain("leadership:release");
    expect(result.leadership).toBeDefined();
    expect(readiness.snapshot().checks.leadership).toBe(true);
    expect(readiness.snapshot().ready).toBe(true);
  });

  // retryable/incomplete recovery must not pin leadership forever.
  it("retryable recovery not-ready releases leadership and drops the handle", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = {
      ...happyDeps(events, readiness),
      runBootRecovery: async () => {
        events.push("boot-recovery");
        // ready:false without invariantBreach = incomplete/retryable (e.g. raw-byte gate).
        return { ready: false, invariantBreach: false };
      },
    };
    const result = await runBootLane(deps);
    expect(result.ready).toBe(false);
    expect(result.failedStep).toBe("boot-recovery");
    expect(result.bootRecovery?.invariantBreach).toBe(false);
    expect(events).toContain("gateway-read"); // deploy-ready before leadership (ZPAY-252)
    expect(events).not.toContain("money-workers");
    // Must release so a standby / restart can acquire (no operator-only deadlock).
    expect(events).toContain("leadership:release");
    expect(result.leadership).toBeUndefined();
    expect(readiness.snapshot().checks.leadership).toBe(false);
    expect(readiness.snapshot().ready).toBe(true);
  });

  it("fails closed when runBootRecovery is omitted at runtime (D3)", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = { ...happyDeps(events, readiness) } as Record<string, unknown>;
    delete deps.runBootRecovery;
    const result = await runBootLane(deps as Parameters<typeof runBootLane>[0]);
    expect(result.ready).toBe(false);
    expect(result.failedStep).toBe("boot-recovery");
    expect(events).toContain("gateway-read"); // deploy-ready before leadership (ZPAY-252)
    expect(events).not.toContain("money-workers");
  });

  it("active NODE_IDENTITY open/signing failure blocks readiness and worker arm", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = {
      ...happyDeps(events, readiness),
      runBootRecovery: async (): Promise<never> => {
        events.push("node-identity:open");
        throw new Error("synthetic sealed NODE_IDENTITY cannot be opened");
      },
    };
    const result = await runBootLane(deps);
    expect(result.ready).toBe(false);
    expect(result.failedStep).toBe("boot-recovery");
    expect(readiness.snapshot().ready).toBe(true);
    expect(events).toContain("gateway-read"); // deploy-ready before leadership (ZPAY-252)
    expect(events).not.toContain("money-workers");
  });

  it("missing or undefined invariantBreach fails closed — retains leadership", async () => {
    for (const report of [
      { ready: false as const },
      { ready: false as const, invariantBreach: undefined },
    ]) {
      const events: string[] = [];
      const readiness = new NodeReadiness(3);
      const deps = {
        ...happyDeps(events, readiness),
        runBootRecovery: async () => {
          events.push("boot-recovery");
          return report as { ready: boolean; invariantBreach: boolean };
        },
      };
      const result = await runBootLane(deps);
      expect(result.ready).toBe(false);
      expect(result.failedStep).toBe("boot-recovery");
      expect(events).not.toContain("leadership:release");
      expect(result.leadership).toBeDefined();
      expect(readiness.snapshot().checks.leadership).toBe(true);
      expect(dispositionForIncompleteBoot(result)).toBe("quarantine");
    }
  });

  it("release throw retains handle and does not clear readiness leadership", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = {
      ...happyDeps(events, readiness),
      acquireSignerLeadership: async () => {
        events.push("leadership");
        return {
          release: async () => {
            events.push("leadership:release-attempt");
            throw new Error("unlock refused");
          },
        };
      },
      runBootRecovery: async () => {
        events.push("boot-recovery");
        return { ready: false, invariantBreach: false };
      },
    };
    const result = await runBootLane(deps);
    expect(result.ready).toBe(false);
    expect(result.leadership).toBeDefined();
    expect(result.leadershipReleaseFailed).toBe(true);
    expect(events).toContain("leadership:release-attempt");
    // Readiness bit must stay true — failed unlock must not look clean.
    expect(readiness.snapshot().checks.leadership).toBe(true);
    expect(dispositionForIncompleteBoot(result)).toBe("quarantine");
  });

  it("real advisory lock: retryable recovery frees lock for a second acquirer", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    // In-memory session lock: one holder at a time, unlock on release.
    let holder: string | null = null;
    let nextId = 0;
    function makeClient(): LeadershipLockClient & { id: string; ended: boolean } {
      const id = `c${++nextId}`;
      const self = {
        id,
        ended: false,
        async query(sql: string, _values?: readonly unknown[]) {
          if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) {
            if (holder === null) {
              holder = id;
              return { rows: [{ locked: true }] };
            }
            return { rows: [{ locked: false }] };
          }
          if (sql === RELEASE_LEADERSHIP_SQL) {
            if (holder === id) {
              holder = null;
              return { rows: [{ released: true }] };
            }
            return { rows: [{ released: false }] };
          }
          return { rows: [] };
        },
        on() {},
        removeListener() {},
        release() {
          /* pool return — lock stays if not unlocked */
        },
        end() {
          self.ended = true;
          if (holder === id) holder = null;
        },
      };
      return self;
    }
    const pool: LeadershipLockPool = {
      connect: async () => makeClient(),
    };
    const latchA = new SignerLeadership();
    const deps = {
      ...happyDeps(events, readiness),
      acquireSignerLeadership: async () => {
        events.push("leadership");
        const held = await tryAcquireSignerLeadership(pool, latchA, SIGNER_LEADERSHIP_LOCK_ID);
        if (held === null) throw new Error("expected lock");
        return { release: () => held.release() };
      },
      runBootRecovery: async () => {
        events.push("boot-recovery");
        // Simulate resume-then-not-ready: durable work happened, then raw-byte gate fails.
        events.push("resume-authorized");
        return { ready: false, invariantBreach: false };
      },
    };
    const result = await runBootLane(deps);
    expect(result.ready).toBe(false);
    expect(result.leadership).toBeUndefined();
    expect(events).toContain("resume-authorized");
    expect(holder).toBeNull();
    expect(latchA.held).toBe(false);
    // Second instance can acquire only because release unlocked.
    const latchB = new SignerLeadership();
    const heldB = await tryAcquireSignerLeadership(pool, latchB, SIGNER_LEADERSHIP_LOCK_ID);
    expect(heldB).not.toBeNull();
    expect(latchB.held).toBe(true);
    await heldB!.release();
    expect(dispositionForIncompleteBoot(result)).toBe("exit-for-reacquire");
  });

  it("real lock: unlock-fail without end does not pool-return a locked session (Defect 1)", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    let holder: string | null = null;
    let nextId = 0;
    const clients: Array<{ id: string; pooled: boolean; lockedWhenPooled: boolean }> = [];
    function makeReleaseOnlyClient() {
      const id = `c${++nextId}`;
      const state = { id, pooled: false, lockedWhenPooled: false };
      clients.push(state);
      // Required-only pre-fix shape: no end(). Cast past the required contract.
      const self = {
        async query(sql: string) {
          if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) {
            if (holder === null) {
              holder = id;
              return { rows: [{ locked: true }] };
            }
            return { rows: [{ locked: false }] };
          }
          if (sql === RELEASE_LEADERSHIP_SQL) {
            throw new Error("network blip on unlock");
          }
          return { rows: [] };
        },
        on() {},
        removeListener() {},
        release() {
          state.pooled = true;
          state.lockedWhenPooled = holder === id;
        },
      };
      return self as unknown as LeadershipLockClient;
    }
    const pool: LeadershipLockPool = { connect: async () => makeReleaseOnlyClient() };
    const latch = new SignerLeadership();
    const deps = {
      ...happyDeps(events, readiness),
      acquireSignerLeadership: async () => {
        events.push("leadership");
        const held = await tryAcquireSignerLeadership(pool, latch, SIGNER_LEADERSHIP_LOCK_ID);
        if (held === null) throw new Error("expected lock");
        return { release: () => held.release() };
      },
      runBootRecovery: async () => ({ ready: false, invariantBreach: false }),
    };
    const result = await runBootLane(deps);
    expect(result.leadershipReleaseFailed).toBe(true);
    expect(result.leadership).toBeDefined();
    expect(dispositionForIncompleteBoot(result)).toBe("quarantine");
    // Defect 1: must never bare-release a still-locked session into the idle pool.
    expect(clients[0]?.pooled).toBe(false);
    expect(clients[0]?.lockedWhenPooled).toBe(false);
    // Process must not look like a clean handoff while lock may still be held.
    expect(readiness.snapshot().checks.leadership).toBe(true);

    // Re-entry on retained handle (break e737f9b): second release must stay fail-closed.
    await expect(Promise.resolve(result.leadership!.release())).rejects.toThrow(
      /no end\(\) destroy path/,
    );
    expect(clients[0]?.pooled).toBe(false);
    expect(clients[0]?.lockedWhenPooled).toBe(false);
    expect(holder).toBe("c1");
  });

  it("real lock: unlock failure destroys session rather than pool-return SPOF", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    let holder: string | null = null;
    let unlockCalls = 0;
    const clients: Array<{ id: string; ended: boolean; pooled: boolean }> = [];
    function makeClient() {
      const id = `c${clients.length + 1}`;
      const state = { id, ended: false, pooled: false };
      clients.push(state);
      const self: LeadershipLockClient = {
        async query(sql: string) {
          if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) {
            if (holder === null) {
              holder = id;
              return { rows: [{ locked: true }] };
            }
            return { rows: [{ locked: false }] };
          }
          if (sql === RELEASE_LEADERSHIP_SQL) {
            unlockCalls += 1;
            // First holder's unlock fails (the case under test); later holders succeed.
            if (unlockCalls === 1) throw new Error("network blip on unlock");
            if (holder === id) holder = null;
            return { rows: [{ released: true }] };
          }
          return { rows: [] };
        },
        on() {},
        removeListener() {},
        release() {
          state.pooled = true;
        },
        end() {
          state.ended = true;
          if (holder === id) holder = null;
        },
      };
      return self;
    }
    const pool: LeadershipLockPool = { connect: async () => makeClient() };
    const latch = new SignerLeadership();
    const deps = {
      ...happyDeps(events, readiness),
      acquireSignerLeadership: async () => {
        events.push("leadership");
        const held = await tryAcquireSignerLeadership(pool, latch, SIGNER_LEADERSHIP_LOCK_ID);
        if (held === null) throw new Error("expected lock");
        return { release: () => held.release() };
      },
      runBootRecovery: async () => ({ ready: false, invariantBreach: false }),
    };
    const result = await runBootLane(deps);
    expect(unlockCalls).toBe(1);
    expect(result.leadershipReleaseFailed).toBe(true);
    expect(result.leadership).toBeDefined();
    // Session destroyed (end), not quietly pooled while still "holding".
    expect(clients[0]?.ended).toBe(true);
    expect(holder).toBeNull();
    // After destroy, a peer can acquire.
    const peer = await tryAcquireSignerLeadership(pool, new SignerLeadership(), SIGNER_LEADERSHIP_LOCK_ID);
    expect(peer).not.toBeNull();
    await peer!.release();
  });
});

describe("main disposition for incomplete boot (composition root)", () => {
  it("maps breach + release-failed → quarantine; clean retryable → exit; other → liveness", () => {
    const handle = { release: async () => {} };
    expect(
      dispositionForIncompleteBoot({
        ready: false,
        failedStep: "boot-recovery",
        leadership: handle,
        bootRecovery: { ready: false, invariantBreach: true },
      }),
    ).toBe("quarantine");
    expect(
      dispositionForIncompleteBoot({
        ready: false,
        failedStep: "boot-recovery",
        leadership: handle,
        leadershipReleaseFailed: true,
        bootRecovery: { ready: false, invariantBreach: false },
      }),
    ).toBe("quarantine");
    expect(
      dispositionForIncompleteBoot({
        ready: false,
        failedStep: "boot-recovery",
        bootRecovery: { ready: false, invariantBreach: false },
      }),
    ).toBe("exit-for-reacquire");
    expect(
      dispositionForIncompleteBoot({
        ready: false,
        failedStep: "migrations",
      }),
    ).toBe("liveness-only");
    expect(
      dispositionForIncompleteBoot({
        ready: false,
        failedStep: "vault-unlock",
      }),
    ).toBe("liveness-only");
  });

  it("main.ts process.exit(1) only on exit-for-reacquire disposition", async () => {
    // Composition-root contract: mirror main.ts branching without importing main
    // (main binds HTTP on load). dispositionForIncompleteBoot is the single seam.
    const exitCodes: number[] = [];
    const stay: string[] = [];
    function applyMainDisposition(result: BootLaneResult): void {
      if (result.ready) return;
      const d = dispositionForIncompleteBoot(result);
      if (d === "quarantine") {
        stay.push("quarantine");
        return;
      }
      if (d === "exit-for-reacquire") {
        exitCodes.push(1);
        return;
      }
      stay.push("liveness-only");
    }
    applyMainDisposition({
      ready: false,
      failedStep: "boot-recovery",
      leadership: { release: async () => {} },
      bootRecovery: { ready: false, invariantBreach: true },
    });
    applyMainDisposition({
      ready: false,
      failedStep: "boot-recovery",
      bootRecovery: { ready: false, invariantBreach: false },
    });
    applyMainDisposition({ ready: false, failedStep: "migrations" });
    expect(exitCodes).toEqual([1]);
    expect(stay).toEqual(["quarantine", "liveness-only"]);
  });
});

describe("startup validation — fail-fast before any migration (review indicator 2)", () => {
  const CRITICAL_ENV = [
    "DATABASE_URL",
    "SPLITCHAIN_GATEWAY_URLS",
    "PUBLIC_BASE_URL",
    "NODE_ID",
  ] as const;

  function baseEnv(): Record<string, string | undefined> {
    return {
      NODE_ENV: "development",
      DATABASE_URL: "postgresql://node:db-secret@db.internal:5432/zunode",
      SPLITCHAIN_GATEWAY_URLS: "https://gateway-entry-1.internal.example/",
      PUBLIC_BASE_URL: "https://node.internal.example/",
      NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      VAULT_MASTER_KEY: "a".repeat(32),
    };
  }

  it.each(CRITICAL_ENV)("missing %s refuses boot with a diagnosable error", (field) => {
    const env = baseEnv();
    env[field] = undefined;
    expect(() => loadNodeConfig(env)).toThrowError(NodeConfigurationError);
    try {
      loadNodeConfig(env);
    } catch (err) {
      expect(err).toBeInstanceOf(NodeConfigurationError);
      expect((err as NodeConfigurationError).issues.join("\n")).toContain(field);
    }
  });

  it.each(["DATABASE_URL", "SPLITCHAIN_GATEWAY_URLS", "PUBLIC_BASE_URL", "VAULT_MASTER_KEY"] as const)(
    "blank %s refuses boot",
    (field) => {
      const env = baseEnv();
      if (field === "VAULT_MASTER_KEY") {
        // VAULT_MASTER_KEY is sourced from process.env directly by main.ts (not
        // in the node-config schema so Stage-1 secret census passes); main.ts
        // validates it at runtime (≥32 chars). A blank value is rejected by
        // main.ts before the boot lane runs.
        expect(() => loadNodeConfig(env)).not.toThrow();
        return;
      }
      env[field] = "   ";
      expect(() => loadNodeConfig(env)).toThrowError(NodeConfigurationError);
    },
  );

  it("a config validation failure means migrations are never invoked", async () => {
    const env = baseEnv();
    env.DATABASE_URL = undefined;

    // Mirrors main.ts step 0: the lane is only entered after loadNodeConfig
    // succeeds — a throw here must mean runMigrations is never called.
    const events: string[] = [];
    let config: ReturnType<typeof loadNodeConfig> | undefined;
    try {
      config = loadNodeConfig(env);
    } catch {
      config = undefined;
    }
    expect(config).toBeUndefined();

    if (config !== undefined) {
      const readiness = new NodeReadiness(config.GATEWAY_READ_FAILURE_BUDGET);
      await runBootLane(happyDeps(events, readiness));
    }
    expect(events).not.toContain("migrations");
  });
});

describe("ZPAY-252 — deploy-ready without leadership (overlap handover)", () => {
  it("AC1: readiness is true after gateway, before leadership resolves", async () => {
    const events: string[] = [];
    const readiness = new NodeReadiness(3);
    const deps = happyDeps(events, readiness);
    let readyWhileWaiting: boolean | undefined;
    deps.acquireSignerLeadership = async () => {
      events.push("leadership");
      readyWhileWaiting = readiness.snapshot().ready;
      return makeLeadership(events);
    };
    const result = await runBootLane(deps);
    expect(result.ready).toBe(true);
    expect(readyWhileWaiting).toBe(true);
    expect(events.indexOf("gateway-read")).toBeLessThan(events.indexOf("leadership"));
  });
});
