// Retry policy, latch, and loss detection against a scripted connection. Mutual EXCLUSION is
// not testable here by construction — it is arbitrated by the database, so its proof lives in
// test/leadership.pg.test.ts against two genuinely concurrent real connections.
import { describe, expect, it, vi } from "vitest";

import {
  acquireSignerLeadership,
  ASSERT_LEADERSHIP_OWNED_SQL,
  RELEASE_LEADERSHIP_SQL,
  SIGNER_LEADERSHIP_LOCK_ID,
  SignerLeadership,
  TRY_ACQUIRE_LEADERSHIP_SQL,
  tryAcquireSignerLeadership,
  type LeadershipLockClient,
  type LeadershipLockPool,
} from "./leadership.js";

interface FakeClient extends LeadershipLockClient {
  readonly queries: Array<{ sql: string; values?: readonly unknown[] }>;
  readonly released: () => boolean;
  readonly ended: () => boolean;
  emit(event: "error" | "end", err?: Error): void;
}

function fakeClient(
  outcome: boolean | Error,
  options: {
    owned?: boolean | (() => boolean) | Error;
  } = {},
): FakeClient {
  const listeners = new Map<string, Array<(err?: Error) => void>>();
  const queries: Array<{ sql: string; values?: readonly unknown[] }> = [];
  let released = false;
  let ended = false;
  return {
    queries,
    released: () => released,
    ended: () => ended,
    async query(sql, values) {
      queries.push({ sql, values });
      if (outcome instanceof Error) throw outcome;
      if (sql === ASSERT_LEADERSHIP_OWNED_SQL) {
        if (options.owned instanceof Error) throw options.owned;
        const owned =
          typeof options.owned === "function" ? options.owned() : (options.owned ?? true);
        return { rows: [{ owned }] };
      }
      return { rows: [{ locked: outcome, released: true }] };
    },
    on(event, listener) {
      const existing = listeners.get(event) ?? [];
      existing.push(listener);
      listeners.set(event, existing);
    },
    removeListener(event, listener) {
      listeners.set(event, (listeners.get(event) ?? []).filter((l) => l !== listener));
    },
    release() {
      released = true;
    },
    end() {
      // Session destroy — marks ended; must NOT be confused with idle pool-return.
      ended = true;
    },
    emit(event, err) {
      for (const listener of [...(listeners.get(event) ?? [])]) listener(err);
    },
  };
}

const NO_OWNERSHIP_WATCH = { ownershipAssertIntervalMs: 0 } as const;

function poolOf(...clients: LeadershipLockClient[]): LeadershipLockPool {
  let index = 0;
  return {
    connect: async () => clients[Math.min(index++, clients.length - 1)] as LeadershipLockClient,
  };
}

describe("signer leadership latch (AC3)", () => {
  it("starts not-held with a non-secret boot reason", () => {
    const latch = new SignerLeadership();
    expect(latch.held).toBe(false);
    expect(latch.reason).toBe(SignerLeadership.UNACQUIRED_REASON);
  });

  // What this latch GATES is proven in test/signer-boundary.test.ts: `signUnderLease` refuses
  // and never reaches the vault while `held` is false. Here only the transitions.
  it("flips held on acquire and back on loss, carrying the non-secret reason", () => {
    const latch = new SignerLeadership();
    latch.markAcquired();
    expect(latch.held).toBe(true);
    expect(latch.reason).toBeUndefined();
    latch.markLost("connection end");
    expect(latch.held).toBe(false);
    expect(latch.reason).toBe("connection end");
  });
});

describe("non-blocking acquisition (AC1)", () => {
  it("acquires with the session advisory lock and pins the connection", async () => {
    const client = fakeClient(true);
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH);

    expect(held).not.toBeNull();
    expect(client.queries).toEqual([
      { sql: TRY_ACQUIRE_LEADERSHIP_SQL, values: [SIGNER_LEADERSHIP_LOCK_ID] },
    ]);
    expect(client.released()).toBe(false);
    expect(latch.held).toBe(true);
  });

  it("returns null and hands the probe connection back when held elsewhere", async () => {
    const client = fakeClient(false);
    const latch = new SignerLeadership();

    expect(await tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH)).toBeNull();
    expect(client.released()).toBe(true);
    expect(latch.held).toBe(false);
  });

  it("rethrows a query fault without ever claiming leadership", async () => {
    const client = fakeClient(new Error("connection refused"));
    const latch = new SignerLeadership();

    await expect(tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH)).rejects.toThrow(
      "connection refused",
    );
    expect(client.released()).toBe(true);
    expect(latch.held).toBe(false);
  });

  it("release unlocks, frees the connection, and drops leadership", async () => {
    const client = fakeClient(true);
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH);

    await held?.release();
    expect(client.queries.at(-1)).toEqual({
      sql: RELEASE_LEADERSHIP_SQL,
      values: [SIGNER_LEADERSHIP_LOCK_ID],
    });
    expect(client.released()).toBe(true);
    expect(latch.held).toBe(false);
  });

  it("unlock failure destroys session via end and rethrows", async () => {
    const listeners = new Map<string, Array<(err?: Error) => void>>();
    const queries: Array<{ sql: string; values?: readonly unknown[] }> = [];
    let released = false;
    let ended = false;
    const client: LeadershipLockClient & {
      queries: typeof queries;
      released: () => boolean;
      ended: () => boolean;
      emit(event: "error" | "end", err?: Error): void;
    } = {
      queries,
      released: () => released,
      ended: () => ended,
      async query(sql, values) {
        queries.push({ sql, values });
        if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) {
          return { rows: [{ locked: true }] };
        }
        if (sql === RELEASE_LEADERSHIP_SQL) {
          throw new Error("unlock network blip");
        }
        return { rows: [] };
      },
      on(event, listener) {
        const existing = listeners.get(event) ?? [];
        existing.push(listener);
        listeners.set(event, existing);
      },
      removeListener(event, listener) {
        listeners.set(event, (listeners.get(event) ?? []).filter((l) => l !== listener));
      },
      release() {
        released = true;
      },
      end() {
        ended = true;
      },
      emit(event, err) {
        for (const listener of [...(listeners.get(event) ?? [])]) listener(err);
      },
    };
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH);
    await expect(held!.release()).rejects.toThrow("unlock network blip");
    expect(ended).toBe(true);
    expect(released).toBe(false); // must not pool-return a still-locked session
    expect(latch.held).toBe(false);
  });

  it("unlock returning released:false destroys session and throws", async () => {
    const listeners = new Map<string, Array<(err?: Error) => void>>();
    let ended = false;
    let released = false;
    const client: LeadershipLockClient = {
      async query(sql) {
        if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) return { rows: [{ locked: true }] };
        if (sql === RELEASE_LEADERSHIP_SQL) return { rows: [{ released: false }] };
        return { rows: [] };
      },
      on(event, listener) {
        const existing = listeners.get(event) ?? [];
        existing.push(listener);
        listeners.set(event, existing);
      },
      removeListener(event, listener) {
        listeners.set(event, (listeners.get(event) ?? []).filter((l) => l !== listener));
      },
      release() {
        released = true;
      },
      end() {
        ended = true;
      },
    };
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH);
    await expect(held!.release()).rejects.toThrow(/did not confirm release/);
    expect(ended).toBe(true);
    expect(released).toBe(false);
    expect(latch.held).toBe(false);
  });

  it("unlock-fail without end must not leave lock held for a standby (Defect 1)", async () => {
    // Models the reviewer's injected proof: a release-only adapter (no end) used to
    // bare-release on unlock failure, returning a still-locked session to the idle
    // pool so tryAcquire forever fails. end is now required on the contract; at
    // runtime we still refuse the bare pool-return if a non-conforming client slips
    // through (structural cast / JS consumer).
    let holder: string | null = null;
    let nextId = 0;
    type Tracked = {
      id: string;
      pooled: boolean;
      lockedWhenPooled: boolean;
      ended: boolean;
      client: LeadershipLockClient;
    };
    const tracked: Tracked[] = [];

    function makeReleaseOnlyClient(): Tracked {
      const id = `c${++nextId}`;
      const state: Tracked = {
        id,
        pooled: false,
        lockedWhenPooled: false,
        ended: false,
        // Build without end, then cast — the unsafe shape the prior contract allowed.
        client: null as unknown as LeadershipLockClient,
      };
      const releaseOnly = {
        async query(sql: string) {
          if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) {
            if (holder === null) {
              holder = id;
              return { rows: [{ locked: true }] };
            }
            return { rows: [{ locked: false }] };
          }
          if (sql === RELEASE_LEADERSHIP_SQL) {
            throw new Error("unlock network blip");
          }
          return { rows: [] };
        },
        on() {},
        removeListener() {},
        release() {
          state.pooled = true;
          // Pool-return of a still-locked session — the SPOF the ticket names.
          state.lockedWhenPooled = holder === id;
        },
        // Intentionally NO end — required-only shape of the pre-fix contract.
      };
      state.client = releaseOnly as unknown as LeadershipLockClient;
      tracked.push(state);
      return state;
    }

    const pool: LeadershipLockPool = {
      connect: async () => makeReleaseOnlyClient().client,
    };

    const latchA = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(pool, latchA, SIGNER_LEADERSHIP_LOCK_ID, NO_OWNERSHIP_WATCH);
    expect(held).not.toBeNull();
    expect(holder).toBe("c1");

    // Current contract requires end; a missing end must surface as destroy failure,
    // never as a quiet pool-return that keeps holder pinned.
    await expect(held!.release()).rejects.toThrow(
      /unlock failed and session has no end\(\) destroy path/,
    );

    const c1 = tracked[0]!;
    // Reviewer proof shape: holder stays c1; pooled===true; lockedWhenPooled===true;
    // second tryAcquire → null. We must NOT produce that triple.
    expect(c1.pooled).toBe(false);
    expect(c1.lockedWhenPooled).toBe(false);
    // holder may still be c1 in this in-memory model (no session death) — that is an
    // operator-visible failed destroy, not a silent idle-pool SPOF. The latch is down.
    expect(latchA.held).toBe(false);

    // Re-entrancy (break e737f9b): boot-lane retains the handle after unlock-fail.
    // A second release must NOT bare-pool the still-locked session just because `lost`
    // already flipped on the first call (unlockErr would be undefined → old client.release).
    await expect(held!.release()).rejects.toThrow(
      /unlock failed and session has no end\(\) destroy path/,
    );
    expect(c1.pooled).toBe(false);
    expect(c1.lockedWhenPooled).toBe(false);
    // Live session may still block peer acquire (operator quarantine) — that is not the
    // idle-pool SPOF. The forbidden triple is pooled && lockedWhenPooled.
    const latchB = new SignerLeadership();
    const peer = await tryAcquireSignerLeadership(pool, latchB, SIGNER_LEADERSHIP_LOCK_ID, NO_OWNERSHIP_WATCH);
    // Peer blocked only if holder still live — never because c1 was idle-pooled locked.
    if (peer === null) {
      expect(c1.pooled).toBe(false);
      expect(holder).toBe("c1");
    } else {
      await peer.release();
    }
  });

  it("second release after unlock-fail without end never pool-returns locked session (re-entry)", async () => {
    // Isolated regression for the break-review injected proof: first throw, second must
    // stay fail-closed (not resolve + pool-return).
    let holder: string | null = null;
    let nextId = 0;
    const tracked: Array<{
      id: string;
      pooled: boolean;
      lockedWhenPooled: boolean;
      releases: number;
    }> = [];

    const pool: LeadershipLockPool = {
      connect: async () => {
        const id = `c${++nextId}`;
        const state = { id, pooled: false, lockedWhenPooled: false, releases: 0 };
        tracked.push(state);
        return {
          async query(sql: string) {
            if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) {
              if (holder === null) {
                holder = id;
                return { rows: [{ locked: true }] };
              }
              return { rows: [{ locked: false }] };
            }
            if (sql === RELEASE_LEADERSHIP_SQL) {
              throw new Error("unlock network blip");
            }
            return { rows: [] };
          },
          on() {},
          removeListener() {},
          release() {
            state.releases += 1;
            state.pooled = true;
            state.lockedWhenPooled = holder === id;
          },
        } as unknown as LeadershipLockClient;
      },
    };

    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(pool, latch, SIGNER_LEADERSHIP_LOCK_ID, NO_OWNERSHIP_WATCH);
    expect(held).not.toBeNull();

    await expect(held!.release()).rejects.toThrow(/no end\(\) destroy path/);
    await expect(held!.release()).rejects.toThrow(/no end\(\) destroy path/);
    await expect(held!.release()).rejects.toThrow(/no end\(\) destroy path/);

    const c1 = tracked[0]!;
    expect(c1.releases).toBe(0);
    expect(c1.pooled).toBe(false);
    expect(c1.lockedWhenPooled).toBe(false);
    expect(holder).toBe("c1");
    // Peer blocked by live non-pooled session, not by idle pooled lock.
    const peer = await tryAcquireSignerLeadership(
      pool,
      new SignerLeadership(),
      SIGNER_LEADERSHIP_LOCK_ID,
      NO_OWNERSHIP_WATCH,
    );
    expect(peer).toBeNull();
  });

  it("second release after unlock-fail+end stays fail-closed without pool-return", async () => {
    let holder: string | null = null;
    let releases = 0;
    let ends = 0;
    const pool: LeadershipLockPool = {
      connect: async () => {
        const id = "c1";
        return {
          async query(sql: string) {
            if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) {
              if (holder === null) {
                holder = id;
                return { rows: [{ locked: true }] };
              }
              return { rows: [{ locked: false }] };
            }
            if (sql === RELEASE_LEADERSHIP_SQL) throw new Error("unlock network blip");
            return { rows: [] };
          },
          on() {},
          removeListener() {},
          release() {
            releases += 1;
          },
          end() {
            ends += 1;
            if (holder === id) holder = null;
          },
        };
      },
    };
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(pool, latch, SIGNER_LEADERSHIP_LOCK_ID, NO_OWNERSHIP_WATCH);
    await expect(held!.release()).rejects.toThrow("unlock network blip");
    await expect(held!.release()).rejects.toThrow("unlock network blip");
    expect(ends).toBe(1); // destroy once
    expect(releases).toBe(0); // never bare pool-return
    expect(holder).toBeNull();
  });

  it("concurrent second release during unlock-fail end must not pool-return", async () => {
    // Break review d72fd92: sequential re-entry was fixed, but releaseOutcome stayed
    // "open" across await client.end. Concurrent second release saw open+lost=true,
    // skipped unlock, took the success path, and bare-pooled the still-locked session.
    let holder: string | null = null;
    let releases = 0;
    let ends = 0;
    let releasesDuringEndWindow = 0;
    let finishEnd!: () => void;
    const endGate = new Promise<void>((resolve) => {
      finishEnd = resolve;
    });
    let endStarted!: () => void;
    const endStartedGate = new Promise<void>((resolve) => {
      endStarted = resolve;
    });

    const pool: LeadershipLockPool = {
      connect: async () => {
        const id = "c1";
        return {
          async query(sql: string) {
            if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) {
              if (holder === null) {
                holder = id;
                return { rows: [{ locked: true }] };
              }
              return { rows: [{ locked: false }] };
            }
            if (sql === RELEASE_LEADERSHIP_SQL) throw new Error("unlock network blip");
            return { rows: [] };
          },
          on() {},
          removeListener() {},
          release() {
            releases += 1;
          },
          async end() {
            ends += 1;
            endStarted();
            await endGate;
            if (holder === id) holder = null;
          },
        };
      },
    };

    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(pool, latch, SIGNER_LEADERSHIP_LOCK_ID, NO_OWNERSHIP_WATCH);
    expect(held).not.toBeNull();

    const p1 = held!.release();
    await endStartedGate; // first is inside end
    const p2 = held!.release(); // concurrent re-entry mid-end
    // Snapshot: any pool-return while first still awaits end is the SPOF.
    releasesDuringEndWindow = releases;
    finishEnd();

    const [r1, r2] = await Promise.allSettled([p1, p2]);
    expect(r1.status).toBe("rejected");
    expect(r2.status).toBe("rejected");
    if (r1.status === "rejected") {
      expect((r1.reason as Error).message).toMatch(/unlock network blip/);
    }
    if (r2.status === "rejected") {
      expect((r2.reason as Error).message).toMatch(/unlock network blip/);
    }
    expect(releasesDuringEndWindow).toBe(0);
    expect(releases).toBe(0);
    expect(ends).toBe(1); // single-flight: one destroy
    expect(holder).toBeNull();

    // Post-flight sequential re-entry still fail-closed.
    await expect(held!.release()).rejects.toThrow(/unlock network blip/);
    expect(releases).toBe(0);
    expect(ends).toBe(1);
  });

  it("unlock-fail with end clears holder so standby can acquire", async () => {
    let holder: string | null = null;
    let nextId = 0;
    const pool: LeadershipLockPool = {
      connect: async () => {
        const id = `c${++nextId}`;
        return {
          async query(sql: string) {
            if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) {
              if (holder === null) {
                holder = id;
                return { rows: [{ locked: true }] };
              }
              return { rows: [{ locked: false }] };
            }
            if (sql === RELEASE_LEADERSHIP_SQL) {
              // Always fail unlock — destroy path must free the lock.
              throw new Error("unlock network blip");
            }
            return { rows: [] };
          },
          on() {},
          removeListener() {},
          release() {
            /* idle pool return — must not run on unlock-fail */
          },
          end() {
            if (holder === id) holder = null;
          },
        };
      },
    };

    const latchA = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(pool, latchA, SIGNER_LEADERSHIP_LOCK_ID, NO_OWNERSHIP_WATCH);
    expect(held).not.toBeNull();
    await expect(held!.release()).rejects.toThrow("unlock network blip");
    expect(holder).toBeNull();

    const latchB = new SignerLeadership();
    const peer = await tryAcquireSignerLeadership(pool, latchB, SIGNER_LEADERSHIP_LOCK_ID, NO_OWNERSHIP_WATCH);
    expect(peer).not.toBeNull();
    expect(latchB.held).toBe(true);
    // Clean unlock for the peer so the test tears down.
    // Peer unlock also throws in this pool — give it a one-shot success via direct holder clear.
    holder = null;
    latchB.markLost("test teardown");
  });

  it("unlock-fail when end also rejects surfaces combined error", async () => {
    const client: LeadershipLockClient = {
      async query(sql) {
        if (sql === TRY_ACQUIRE_LEADERSHIP_SQL) return { rows: [{ locked: true }] };
        if (sql === RELEASE_LEADERSHIP_SQL) throw new Error("unlock network blip");
        return { rows: [] };
      },
      on() {},
      removeListener() {},
      release() {
        throw new Error("must not pool-return");
      },
      end() {
        throw new Error("destroy refused");
      },
    };
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH);
    await expect(held!.release()).rejects.toThrow(
      /unlock failed and session destroy also failed[\s\S]*unlock network blip[\s\S]*destroy refused/,
    );
    expect(latch.held).toBe(false);
  });
});

describe("loss detection is driven by the connection, not the clock (AC5)", () => {
  it.each(["error", "end"] as const)("a connection %s drops leadership synchronously", (event) => {
    const client = fakeClient(true);
    const latch = new SignerLeadership();
    const seen: string[] = [];

    return tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH).then((held) => {
      held?.onLost((reason) => seen.push(reason));
      expect(latch.held).toBe(true);

      client.emit(event, new Error("failover"));

      // Synchronous: no await between the connection event and the latch flip, so no other
      // instance can acquire while this one still believes it holds leadership.
      expect(latch.held).toBe(false);
      expect(latch.reason).toContain(event);
      expect(seen).toHaveLength(1);
    });
  });

  it("fires loss at most once and never resurrects a dead lock", async () => {
    const client = fakeClient(true);
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH);
    const seen: string[] = [];
    held?.onLost((reason) => seen.push(reason));

    client.emit("error", new Error("first"));
    client.emit("end");
    held?.onLost(() => seen.push("late"));
    client.emit("error", new Error("second"));

    expect(seen).toEqual([expect.stringContaining("first")]);
  });

  it("release after loss skips the unlock query the dead connection would reject", async () => {
    const client = fakeClient(true);
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH);

    client.emit("end");
    await held?.release();

    expect(client.queries.map((q) => q.sql)).toEqual([TRY_ACQUIRE_LEADERSHIP_SQL]);
    expect(client.released()).toBe(true);
  });

  it("a lapsed lease age alone never releases or grants leadership", async () => {
    const client = fakeClient(true);
    const latch = new SignerLeadership();
    // Ownership watch disabled — this test pins that wall-clock alone is not a loss signal.
    await tryAcquireSignerLeadership(poolOf(client), latch, NO_OWNERSHIP_WATCH);

    vi.useFakeTimers();
    try {
      vi.advanceTimersByTime(24 * 60 * 60 * 1_000);
      expect(latch.held).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("failed positive ownership assertion latches lost (ZTR-1156)", async () => {
    const handlers: Array<() => void> = [];
    const client = fakeClient(true, { owned: false });
    const latch = new SignerLeadership();
    const seen: string[] = [];
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, {
      ownershipAssertIntervalMs: 1_000,
      setIntervalFn: (handler) => {
        handlers.push(handler);
        return 1;
      },
      clearIntervalFn: () => {},
    });
    held?.onLost((reason) => seen.push(reason));
    expect(latch.held).toBe(true);
    expect(handlers).toHaveLength(1);

    handlers[0]!();
    await Promise.resolve();
    await Promise.resolve();

    expect(latch.held).toBe(false);
    expect(latch.reason).toMatch(/ownership assertion failed/);
    expect(seen).toHaveLength(1);
    expect(client.queries.some((q) => q.sql === ASSERT_LEADERSHIP_OWNED_SQL)).toBe(true);
  });

  it("ownership assert query error destroys session — never bare-pools still-locked (ZTR-1156 SPOF)", async () => {
    // Review A/B @ ddd055d: onLoss("ownership") set lost=true then release() skipped
    // unlock and client.release()'d a live still-locked session → permanent bare-pool SPOF.
    const handlers: Array<() => void> = [];
    const client = fakeClient(true, {
      owned: new Error("transient assert network blip"),
    });
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, {
      ownershipAssertIntervalMs: 1_000,
      setIntervalFn: (handler) => {
        handlers.push(handler);
        return 1;
      },
      clearIntervalFn: () => {},
    });
    expect(held).not.toBeNull();
    expect(latch.held).toBe(true);

    handlers[0]!();
    // Ownership dispose is async (end()); drain microtasks then join releaseFlight.
    await Promise.resolve();
    await Promise.resolve();
    await held!.release();

    expect(latch.held).toBe(false);
    expect(latch.reason).toMatch(/ownership assertion failed/);
    // Must destroy — never idle-pool while the advisory lock may still be held.
    expect(client.ended()).toBe(true);
    expect(client.released()).toBe(false);
    // No graceful unlock attempt required on ownership destroy path; assert ran.
    expect(client.queries.some((q) => q.sql === ASSERT_LEADERSHIP_OWNED_SQL)).toBe(true);
    expect(client.queries.some((q) => q.sql === RELEASE_LEADERSHIP_SQL)).toBe(false);
  });

  it("ownership owned=false destroys session before release joins (ZTR-1156 SPOF)", async () => {
    const handlers: Array<() => void> = [];
    const client = fakeClient(true, { owned: false });
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, {
      ownershipAssertIntervalMs: 1_000,
      setIntervalFn: (handler) => {
        handlers.push(handler);
        return 1;
      },
      clearIntervalFn: () => {},
    });
    handlers[0]!();
    await Promise.resolve();
    await Promise.resolve();
    await held!.release();

    expect(latch.held).toBe(false);
    expect(client.ended()).toBe(true);
    expect(client.released()).toBe(false);
    expect(client.queries.some((q) => q.sql === RELEASE_LEADERSHIP_SQL)).toBe(false);
  });

  it("keepAlive-style connection error still latches lost with ownership watch armed", async () => {
    const client = fakeClient(true, { owned: true });
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(poolOf(client), latch, {
      ownershipAssertIntervalMs: 60_000,
      setIntervalFn: () => 1,
      clearIntervalFn: () => {},
    });
    expect(latch.held).toBe(true);
    client.emit("error", new Error("ECONNRESET keepAlive probe"));
    expect(latch.held).toBe(false);
    expect(latch.reason).toMatch(/error/);
    held?.stopOwnershipWatch();
  });
});

describe("jittered backoff retry (AC2)", () => {
  it("retries until acquisition without blocking, with full jitter under a growing ceiling", async () => {
    const latch = new SignerLeadership();
    const delays: number[] = [];
    const attempts: boolean[] = [false, false, false, true];
    let call = 0;

    const held = await acquireSignerLeadership({
      pool: poolOf(fakeClient(true)),
      latch,
      baseDelayMs: 100,
      maxDelayMs: 800,
      random: () => 0.5,
      sleep: async (ms) => {
        delays.push(ms);
      },
      tryAcquire: async () =>
        attempts[call++] === true
          ? { onLost: () => {}, stopOwnershipWatch: () => {}, release: async () => {} }
          : null,
    });

    expect(held).not.toBeNull();
    // ceilings 200, 400, 800 (capped by maxDelayMs); full jitter halves each at random=0.5.
    expect(delays).toEqual([100, 200, 400]);
  });

  it("jitter is a range, not a constant — two runs at the same attempt differ", async () => {
    const draws = [0.01, 0.99];
    const observed: number[] = [];
    for (const draw of draws) {
      await acquireSignerLeadership({
        pool: poolOf(fakeClient(true)),
        latch: new SignerLeadership(),
        baseDelayMs: 1_000,
        maxDelayMs: 10_000,
        random: () => draw,
        sleep: async (ms) => {
          observed.push(ms);
        },
        tryAcquire: (() => {
          let first = true;
          return async () => {
            if (first) {
              first = false;
              return null;
            }
            return { onLost: () => {}, stopOwnershipWatch: () => {}, release: async () => {} };
          };
        })(),
      });
    }
    expect(observed[0]).toBeLessThan(observed[1] as number);
  });

  it("a transient fault is reported and retried, never fatal and never leadership", async () => {
    const latch = new SignerLeadership();
    const errors: unknown[] = [];
    let call = 0;

    const held = await acquireSignerLeadership({
      pool: poolOf(fakeClient(true)),
      latch,
      sleep: async () => {},
      random: () => 0,
      onError: (err) => errors.push(err),
      tryAcquire: async () => {
        call += 1;
        if (call === 1) throw new Error("database unreachable");
        return { onLost: () => {}, stopOwnershipWatch: () => {}, release: async () => {} };
      },
    });

    expect(errors).toHaveLength(1);
    expect(held).not.toBeNull();
    expect(latch.held).toBe(false); // the injected stub does not touch the latch
  });

  it("abort during the wait resolves null and never claims leadership", async () => {
    const signal = { aborted: false };
    const latch = new SignerLeadership();

    const held = await acquireSignerLeadership({
      pool: poolOf(fakeClient(false)),
      latch,
      signal,
      random: () => 0,
      sleep: async () => {
        signal.aborted = true;
      },
    });

    expect(held).toBeNull();
    expect(latch.held).toBe(false);
  });
});
