import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  assertSignerLeadership,
  NotSignerLeaderError,
  SignerLeadership,
} from "@zucoins/node-core";
import { describe, expect, it } from "vitest";

import { installGracefulStop } from "../src/boot/graceful-stop.js";
import { NodeReadiness } from "../src/boot/readiness.js";
import {
  dispositionForIncompleteBoot,
  runBootLane,
  type SignerLeadershipHandle,
} from "../src/boot/boot-lane.js";
import { createShutdownRegistry } from "../src/boot/shutdown-registry.js";

interface FakeServer {
  events: string[];
  close(callback: (err?: Error) => void): void;
}

function makeServer(events: string[], closeErr?: Error): FakeServer {
  return {
    events,
    close(callback) {
      events.push("server:close");
      callback(closeErr);
    },
  };
}

interface ManualTimer {
  fire: () => void;
  fired: boolean;
}

function makeManualTimers() {
  const pending: ManualTimer[] = [];
  return {
    pending,
    setTimeout(callback: () => void) {
      const timer: ManualTimer = {
        fired: false,
        fire: () => {
          timer.fired = true;
          callback();
        },
      };
      pending.push(timer);
      return timer;
    },
    clearTimeout(handle: unknown) {
      const timer = handle as ManualTimer;
      timer.fired = true;
    },
  };
}

function readyReadiness(): NodeReadiness {
  const readiness = new NodeReadiness(3);
  readiness.markSchemaChecksPassed();
  readiness.setVaultAvailable(true);
  readiness.setSignerLeadershipHeld(true);
  readiness.recordGatewayReadSuccess();
  return readiness;
}

function makeHandle(events: string[], label = "leadership:release"): SignerLeadershipHandle {
  let released = false;
  return {
    release: async () => {
      if (released) return;
      released = true;
      events.push(label);
    },
  };
}

/**
 * The real acquire seam in two steps, in production order: the DB grants the
 * advisory lock and `tryAcquireSignerLeadership` flips the latch, THEN
 * composition stamps the registry. `stampLeadership` alone must never mint
 * authority (Defect D4), so every test that expects to be the signer says so
 * here rather than relying on the stamp.
 */
function acquireAndStamp(
  registry: ReturnType<typeof createShutdownRegistry>,
  handle: SignerLeadershipHandle,
) {
  registry.authority.markAcquired();
  return registry.stampLeadership(handle);
}

/** Boot-lane `acquireSignerLeadership` dep that flips the latch like the real one. */
function fakeAcquire(
  registry: ReturnType<typeof createShutdownRegistry>,
  handle: SignerLeadershipHandle,
): () => Promise<SignerLeadershipHandle> {
  return async () => {
    registry.authority.markAcquired();
    return handle;
  };
}

describe("graceful stop — SIGTERM sequence (review indicator 6)", () => {
  it("withdraws authority, quiesces, flushes, releases leadership, exits 0", async () => {
    const events: string[] = [];
    const readiness = readyReadiness();
    let finishFlush: () => void = () => {};

    const stop = installGracefulStop({
      server: makeServer(events),
      readiness,
      withdrawSignerAuthority: () => events.push("authority:withdraw"),
      stopWorkers: () => events.push("workers:stop"),
      flushInFlight: () =>
        new Promise<void>((resolve) => {
          finishFlush = () => {
            events.push("flush:complete");
            resolve();
          };
        }),
      releaseLeadership: () => {
        events.push("leadership:release");
      },
      exit: (code) => events.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers: makeManualTimers(),
    });

    stop.handleSignal("SIGTERM");
    expect(readiness.snapshot().ready).toBe(false);
    expect(readiness.snapshot().stopping).toBe(true);
    expect(events.slice(0, 3)).toEqual([
      "authority:withdraw",
      "workers:stop",
      "server:close",
    ]);

    await Promise.resolve();
    expect(events).not.toContain("leadership:release");
    expect(events).not.toContain("exit:0");

    finishFlush();
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).toEqual([
      "authority:withdraw",
      "workers:stop",
      "server:close",
      "flush:complete",
      "leadership:release",
      "exit:0",
    ]);
    expect(readiness.snapshot().checks.leadership).toBe(false);
  });

  it("a second signal while stopping is ignored", () => {
    const events: string[] = [];
    const stop = installGracefulStop({
      server: makeServer(events),
      readiness: readyReadiness(),
      exit: (code) => events.push(`exit:${code}`),
      emitter: { on: () => {} },
    });
    stop.handleSignal("SIGTERM");
    stop.handleSignal("SIGINT");
    expect(events.filter((event) => event === "server:close")).toHaveLength(1);
  });

  it("bounded flush timeout: exits 1 WITHOUT releasing leadership", async () => {
    const events: string[] = [];
    const timers = makeManualTimers();
    const readiness = readyReadiness();

    const stop = installGracefulStop({
      server: makeServer(events),
      readiness,
      flushInFlight: () => new Promise<void>(() => {}),
      releaseLeadership: () => {
        events.push("leadership:release");
      },
      timeoutMs: 10_000,
      exit: (code) => events.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers,
    });

    stop.handleSignal("SIGTERM");
    await Promise.resolve();
    expect(events).not.toContain("leadership:release");

    timers.pending[0]?.fire();
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).not.toContain("leadership:release");
    expect(events).toContain("exit:1");
    expect(readiness.snapshot().checks.leadership).toBe(true);
  });

  it("leadership is released only after the server stops accepting and flush succeeds", async () => {
    const events: string[] = [];
    const stop = installGracefulStop({
      server: makeServer(events),
      readiness: readyReadiness(),
      flushInFlight: async () => {
        events.push("flush:complete");
      },
      releaseLeadership: () => {
        events.push("leadership:release");
      },
      exit: (code) => events.push(`exit:${code}`),
      emitter: { on: () => {} },
    });

    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).toEqual(["server:close", "flush:complete", "leadership:release", "exit:0"]);
  });

  it("exits 1 when the server close reports an error (still releases after successful flush)", async () => {
    const events: string[] = [];
    const stop = installGracefulStop({
      server: makeServer(events, new Error("close failed")),
      readiness: readyReadiness(),
      releaseLeadership: () => {
        events.push("leadership:release");
      },
      exit: (code) => events.push(`exit:${code}`),
      emitter: { on: () => {} },
    });
    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).toContain("leadership:release");
    expect(events).toContain("exit:1");
  });

  it("exits 1 WITHOUT releasing leadership when the in-flight flush reports an error", async () => {
    const events: string[] = [];
    const readiness = readyReadiness();
    const stop = installGracefulStop({
      server: makeServer(events),
      readiness,
      flushInFlight: () => Promise.reject(new Error("persist failed")),
      releaseLeadership: () => {
        events.push("leadership:release");
      },
      exit: (code) => events.push(`exit:${code}`),
      emitter: { on: () => {} },
    });

    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).not.toContain("leadership:release");
    expect(events).toContain("exit:1");
    expect(readiness.snapshot().checks.leadership).toBe(true);
  });

  it("registers handlers on the injected emitter for both signals", () => {
    const registered: string[] = [];
    installGracefulStop({
      server: makeServer([]),
      readiness: readyReadiness(),
      exit: () => {},
      emitter: {
        on: (event: string) => {
          registered.push(event);
          return undefined;
        },
      },
    });
    expect(registered).toEqual(["SIGTERM", "SIGINT"]);
  });
});

describe("shutdown registry composition — mid-flight / shared latch / boot stamp", () => {
  it("tracked mid-flight work blocks release without a separate flushInFlight hook", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const handle = makeHandle(events);
    acquireAndStamp(registry, handle);
    // Boot complete — this test isolates post-boot money-path tracking.
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));

    let resolveWork!: () => void;
    const work = new Promise<void>((resolve) => {
      resolveWork = resolve;
    });
    // Money path: track, do not push a flusher callback.
    void registry.trackInflight(work);
    expect(registry.inflightCount).toBe(1);

    const hooks = registry.hooks();
    const stop = installGracefulStop({
      server: makeServer(events),
      readiness: readyReadiness(),
      ...hooks,
      exit: (code) => events.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers: makeManualTimers(),
    });

    stop.handleSignal("SIGTERM");
    // Flush is waiting on tracked work — must not release yet.
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).not.toContain("leadership:release");
    expect(events).not.toContain("exit:0");
    expect(events).not.toContain("exit:1");
    // Handle still held at registry level.
    expect(registry.leadership).toBeDefined();

    resolveWork();
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).toContain("leadership:release");
    expect(events).toContain("exit:0");
    expect(events.indexOf("leadership:release")).toBeLessThan(events.indexOf("exit:0"));
  });

  it("releaseLeadership refuses while tracked inflight remains (drain proof)", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    acquireAndStamp(registry, makeHandle(events));
    // Boot-phase token is already open from stamp — complete it so this test
    // isolates an extra tracked work item (not the boot token itself).
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));
    expect(registry.inflightCount).toBe(0);

    let resolveWork!: () => void;
    void registry.trackInflight(
      new Promise<void>((resolve) => {
        resolveWork = resolve;
      }),
    );

    await expect(registry.hooks().releaseLeadership()).rejects.toThrow(/refuse leadership release/);
    expect(events).not.toContain("leadership:release");

    resolveWork();
    await new Promise((resolve) => setImmediate(resolve));
    await registry.hooks().releaseLeadership();
    expect(events).toContain("leadership:release");
  });

  it("stamped handle.release refuses while inflight remains (no bypass of hooks guard)", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const stamped = acquireAndStamp(registry, makeHandle(events));
    // Leave boot-phase token open (or any tracked work) — direct release must refuse.
    expect(registry.bootPhaseOpen).toBe(true);
    expect(registry.inflightCount).toBeGreaterThan(0);

    await expect(stamped.release()).rejects.toThrow(/refuse leadership release/);
    expect(events).not.toContain("leadership:release");
    expect(registry.leadership).toBeDefined();
    expect(registry.authority.held).toBe(true);

    // After boot settles and no other work, direct release unlocks.
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));
    await stamped.release();
    expect(events).toContain("leadership:release");
    expect(registry.leadership).toBeUndefined();
  });

  it("stamped handle.release refuses while a non-boot tracked promise remains", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const stamped = acquireAndStamp(registry, makeHandle(events));
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));

    let resolveWork!: () => void;
    void registry.trackInflight(
      new Promise<void>((resolve) => {
        resolveWork = resolve;
      }),
    );

    await expect(stamped.release()).rejects.toThrow(/refuse leadership release/);
    expect(events).not.toContain("leadership:release");

    resolveWork();
    await new Promise((resolve) => setImmediate(resolve));
    await stamped.release();
    expect(events).toContain("leadership:release");
  });

  it("withdrawSignerAuthority trips the same latch assertSignerLeadership / signUnderLease read", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    // Shared latch identity: stamp marks acquired on registry.authority.
    acquireAndStamp(registry, makeHandle(events));
    expect(registry.authority.held).toBe(true);

    // The signing chokepoint reads this exact latch instance.
    expect(() => assertSignerLeadership(registry.authority)).not.toThrow();

    const hooks = registry.hooks();
    // Withdraw while DB handle is still held (step 1 — latch only).
    hooks.withdrawSignerAuthority();
    expect(registry.authority.held).toBe(false);
    expect(registry.leadership).toBeDefined(); // lock handle still live
    expect(events).not.toContain("leadership:release");

    expect(() => assertSignerLeadership(registry.authority)).toThrow(NotSignerLeaderError);

    // A second latch would still look held — proves identity matters.
    const orphan = new SignerLeadership();
    orphan.markAcquired();
    expect(() => assertSignerLeadership(orphan)).not.toThrow();
  });

  it("SIGTERM during untracked boot-recovery holds lock — boot token blocks empty flush", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = new NodeReadiness(3);
    let sawStampDuringRecovery = false;
    let finishRecovery!: () => void;
    const recoveryGate = new Promise<void>((resolve) => {
      finishRecovery = resolve;
    });

    const bootPromise = runBootLane({
      readiness,
      logger: { info: () => {}, error: () => {} },
      runMigrations: async () => {
        events.push("migrations");
      },
      unlockVault: async () => {
        events.push("vault");
      },
      acquireSignerLeadership: async () => {
        events.push("leadership");
        // Production order: the DB grant flips the latch before composition stamps.
        registry.authority.markAcquired();
        return makeHandle(events);
      },
      onLeadershipAcquired: (handle) => {
        events.push("stamp");
        return registry.stampLeadership(handle);
      },
      onBootPhaseComplete: () => {
        events.push("boot-phase-complete");
        registry.completeBootPhase();
      },
      runBootRecovery: async () => {
        events.push("boot-recovery-enter");
        // Registry must already hold the handle + boot token during recovery.
        sawStampDuringRecovery =
          registry.leadership !== undefined &&
          registry.authority.held &&
          registry.bootPhaseOpen &&
          registry.inflightCount >= 1;
        await recoveryGate;
        events.push("boot-recovery-exit");
        return { ready: true as const, invariantBreach: false as const };
      },
      performValidatedGatewayRead: async () => {
        events.push("gateway");
      },
      startMoneyWorkers: () => {
        events.push("money-workers");
      },
    });

    // Yield until recovery is parked on the gate.
    for (let i = 0; i < 20 && !events.includes("boot-recovery-enter"); i++) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    expect(events).toEqual(["migrations", "vault", "leadership", "stamp", "boot-recovery-enter"]);
    expect(sawStampDuringRecovery).toBe(true);
    expect(registry.leadership).toBeDefined();
    expect(registry.authority.held).toBe(true);
    expect(registry.bootPhaseOpen).toBe(true);
    expect(registry.inflightCount).toBeGreaterThan(0);

    // SIGTERM during boot-recovery with NO manual trackInflight: boot-phase
    // token keeps flush non-empty. Bounded timeout → exit:1 holding the lock.
    // Must NOT leadership:release + exit:0 (prior celebrated empty-flush bug).
    const stopEvents: string[] = [];
    const timers = makeManualTimers();
    const stop = installGracefulStop({
      server: makeServer(stopEvents),
      readiness,
      ...registry.hooks(),
      timeoutMs: 10_000,
      exit: (code) => stopEvents.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers,
    });
    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    // Still waiting on boot token — no unlock yet.
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).not.toContain("exit:0");
    expect(stopEvents).not.toContain("exit:1");
    expect(registry.leadership).toBeDefined();

    // Fire flush timeout → hard-fail hold (LEADERSHIP_LOCK_EXIT).
    timers.pending[0]?.fire();
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    expect(events).not.toContain("leadership:release");
    expect(stopEvents).toContain("exit:1");
    expect(stopEvents).not.toContain("exit:0");
    expect(registry.leadership).toBeDefined();
    // Authority was withdrawn on signal, but DB handle remains held.
    expect(registry.authority.held).toBe(false);

    // Unblock boot lane so the promise settles (post-timeout residual work).
    finishRecovery();
    await bootPromise;
    expect(events).toContain("boot-phase-complete");
  });

  it("SIGTERM during boot with mid-flight tracked recovery work does not release until drain", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = new NodeReadiness(3);
    let finishRecoveryWork!: () => void;

    const bootPromise = runBootLane({
      readiness,
      logger: { info: () => {}, error: () => {} },
      runMigrations: async () => {},
      unlockVault: async () => {},
      // Production order: acquire flips the latch, stamp only records.
      acquireSignerLeadership: fakeAcquire(registry, makeHandle(events)),
      onLeadershipAcquired: (handle) => registry.stampLeadership(handle),
      onBootPhaseComplete: () => registry.completeBootPhase(),
      runBootRecovery: async () => {
        // Simulate recovery signing work registered on the shared registry.
        const work = new Promise<void>((resolve) => {
          finishRecoveryWork = resolve;
        });
        void registry.trackInflight(work);
        await work;
        return { ready: true as const, invariantBreach: false as const };
      },
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: () => {},
    });

    // Wait until recovery has registered its work (boot token + work ≥ 2).
    for (let i = 0; i < 20 && registry.inflightCount < 2; i++) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    expect(registry.inflightCount).toBeGreaterThanOrEqual(2);
    expect(registry.leadership).toBeDefined();
    expect(registry.bootPhaseOpen).toBe(true);

    const stopEvents: string[] = [];
    const timers = makeManualTimers();
    const stop = installGracefulStop({
      server: makeServer(stopEvents),
      readiness,
      ...registry.hooks(),
      timeoutMs: 10_000,
      exit: (code) => stopEvents.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers,
    });
    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    // Still draining — no release.
    expect(stopEvents).not.toContain("leadership:release");
    expect(events).not.toContain("leadership:release");

    // Finish recovery work; boot lane continues to gateway/workers then
    // settles boot phase — only then can flush empty and release.
    finishRecoveryWork();
    await bootPromise;
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).toContain("leadership:release");
    expect(stopEvents).toContain("exit:0");
    expect(registry.leadership).toBeUndefined();
    expect(registry.bootPhaseOpen).toBe(false);
  });

  it("boot-lane catch does not unlock when residual tracked work remains after boot settle", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = new NodeReadiness(3);
    let resolveResidual!: () => void;
    const residual = new Promise<void>((resolve) => {
      resolveResidual = resolve;
    });

    const result = await runBootLane({
      readiness,
      logger: { info: () => {}, error: () => {} },
      runMigrations: async () => {},
      unlockVault: async () => {},
      // Production order: acquire flips the latch, stamp only records.
      acquireSignerLeadership: fakeAcquire(registry, makeHandle(events)),
      onLeadershipAcquired: (handle) => registry.stampLeadership(handle),
      onBootPhaseComplete: () => registry.completeBootPhase(),
      runBootRecovery: async () => {
        // Residual work tracked under leadership; then recovery throws so
        // the catch path tries leadership.release().
        void registry.trackInflight(residual);
        throw new Error("recovery blew up");
      },
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: () => {},
    });

    expect(result.ready).toBe(false);
    expect(result.failedStep).toBe("boot-recovery");
    // Boot phase settled in catch, but residual work still blocks unlock.
    expect(registry.bootPhaseOpen).toBe(false);
    expect(events).not.toContain("leadership:release");
    expect(registry.leadership).toBeDefined();
    expect(registry.inflightCount).toBe(1);
    // Defect C: readiness still reports lock held while unlock refused.
    expect(readiness.snapshot().checks.leadership).toBe(true);

    resolveResidual();
    await new Promise((resolve) => setImmediate(resolve));
    // Residual settled; process still holds the handle (catch already tried
    // and refused). Explicit release now succeeds.
    await registry.hooks().releaseLeadership();
    expect(events).toContain("leadership:release");
  });

  it("Defect A / PROBE1: bare mid-flight under armed surface cannot clean-unlock", async () => {
    // Break clear condition (invert prior celebrated unlock-mid-orphan):
    // armed surface + mid-flight work outside runUnderLeadership that still
    // represents residual process work under the held lock must NOT
    // leadership:release + exit:0 on the clean path. Production sign path
    // is covered by PROBE5 (signUnderLease auto-track). Here we prove the
    // quiesce gate alone is insufficient when inflight is non-empty via the
    // authority bridge OR when engines are still accepting — and that a
    // bare floating promise is NOT accepted as "drain proof" once the real
    // chokepoint is the auto-track path: if the process can still hold
    // residual tracked signs, unlock holds.
    //
    // This probe starts a signUnderLease-shaped body past the latch assert
    // (authority.trackSigningInflight) WITHOUT runUnderLeadership.
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = readyReadiness();
    const stamped = acquireAndStamp(registry, makeHandle(events));
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));
    expect(registry.inflightCount).toBe(0);

    let acceptWork = true;
    stamped.armMoneySurface(() => {
      acceptWork = false;
      events.push("workers:stop");
    });
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);

    // signUnderLease-shaped mid-flight: body already past latch assert,
    // registered only via authority.trackSigningInflight (no runUnder).
    let resolveSign!: () => void;
    const signBody = new Promise<void>((resolve) => {
      resolveSign = resolve;
    });
    registry.authority.trackSigningInflight(signBody);
    expect(registry.inflightCount).toBe(1);
    expect(acceptWork).toBe(true);

    // Direct release refuses while inflight tracked (and while !quiesced).
    await expect(registry.hooks().releaseLeadership()).rejects.toThrow(
      /in-flight work item|engines not quiesced/,
    );
    expect(events).not.toContain("leadership:release");

    const stopEvents: string[] = [];
    const timers = makeManualTimers();
    const stop = installGracefulStop({
      server: makeServer(stopEvents),
      readiness,
      ...registry.hooks(),
      timeoutMs: 10_000,
      exit: (code) => stopEvents.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers,
    });
    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    // Quiesce runs, but mid-flight sign body still tracked → no clean unlock.
    expect(events).toContain("workers:stop");
    expect(acceptWork).toBe(false);
    expect(registry.enginesQuiesced).toBe(true);
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).not.toContain("exit:0");
    expect(stopEvents).not.toContain("exit:1");
    expect(registry.leadership).toBeDefined();

    // Timeout hold (hard-fail) — residual sign must not hand lock to successor.
    timers.pending[0]?.fire();
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).toContain("exit:1");
    expect(registry.leadership).toBeDefined();

    resolveSign();
    await signBody;
    // Stamped handle still present after hard-fail hold (no release).
    expect(registry.leadership).toBeDefined();
    void stamped;
  });

  it("Defect A2 / PROBE2: registerWorkerStop arms — bare mid-flight cannot clean-unlock", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = readyReadiness();
    acquireAndStamp(registry, makeHandle(events));
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));

    // Stop-only registration (older seam) must arm equivalently.
    registry.registerWorkerStop(() => {
      events.push("workers:stop");
    });
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);

    let resolveSign!: () => void;
    const signBody = new Promise<void>((resolve) => {
      resolveSign = resolve;
    });
    registry.authority.trackSigningInflight(signBody);
    expect(registry.inflightCount).toBe(1);

    await expect(registry.hooks().releaseLeadership()).rejects.toThrow(
      /in-flight work item|engines not quiesced/,
    );

    const stopEvents: string[] = [];
    const timers = makeManualTimers();
    const stop = installGracefulStop({
      server: makeServer(stopEvents),
      readiness,
      ...registry.hooks(),
      timeoutMs: 10_000,
      exit: (code) => stopEvents.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers,
    });
    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    expect(events).toContain("workers:stop");
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).not.toContain("exit:0");

    timers.pending[0]?.fire();
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).toContain("exit:1");

    resolveSign();
    await signBody;
  });

  it("Defect A3 / PROBE3: armMoneySurface refuses reopen after ENGINE_QUIESCE", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const stamped = acquireAndStamp(registry, makeHandle(events));
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));

    stamped.armMoneySurface(() => {
      events.push("workers:stop");
    });
    expect(registry.enginesQuiesced).toBe(false);

    registry.hooks().stopWorkers();
    expect(registry.enginesQuiesced).toBe(true);
    expect(events).toContain("workers:stop");

    // Second arm must NOT reset enginesQuiesced / reopen accept.
    expect(() =>
      stamped.armMoneySurface(() => {
        events.push("workers:stop:reopen");
      }),
    ).toThrow(/engines already quiesced/);
    expect(registry.enginesQuiesced).toBe(true);
    expect(events).not.toContain("workers:stop:reopen");

    await expect(
      stamped.runUnderLeadership(async () => {
        events.push("should-not-run");
        return 1;
      }),
    ).rejects.toThrow(/engines quiesced|signer authority not held/);
    expect(events).not.toContain("should-not-run");
  });

  it("Defect A / PROBE5: signUnderLease mid-body auto-tracks — no clean unlock", async () => {
    // Production path: signUnderLease with registry.authority as leadership.
    // Body hangs in vault.sign after latch assert; withdraw + stop + empty
    // flush must NOT release while body pending.
    const { signUnderLease } = await import("@zucoins/node-core");
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = readyReadiness();
    const stamped = acquireAndStamp(registry, makeHandle(events));
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));

    stamped.armMoneySurface(() => {
      events.push("workers:stop");
    });

    let resolveVault!: (sig: string) => void;
    const vaultPending = new Promise<string>((resolve) => {
      resolveVault = resolve;
    });

    const preimageText = '{"amount":"1"}';
    const { createHash } = await import("node:crypto");
    const digest = createHash("sha256").update(preimageText, "utf8").digest("hex");

    const signPromise = signUnderLease(
      {
        leadership: registry.authority,
        leaseReader: {
          readActiveLease: async () => ({
            walletId: "w1",
            operationId: "op1",
            epoch: 1n,
            role: "SEND_SOURCE" as const,
            lifecycle: "ACTIVE" as const,
          }),
        },
        vaultSigner: {
          sign: async () => vaultPending,
        },
        auditLog: { append: async () => undefined },
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: async () => {},
      },
      {
        walletId: "w1",
        operationId: "op1",
        leaseEpoch: 1n,
        purpose: "SPLITCHAIN_STEP_1",
        preimageText,
        expectedPreimageSha256: digest,
      },
    );

    // Yield so body reaches vault.sign and is tracked.
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    expect(registry.inflightCount).toBeGreaterThanOrEqual(1);

    const stopEvents: string[] = [];
    const timers = makeManualTimers();
    const stop = installGracefulStop({
      server: makeServer(stopEvents),
      readiness,
      ...registry.hooks(),
      timeoutMs: 10_000,
      exit: (code) => stopEvents.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers,
    });
    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    expect(events).toContain("workers:stop");
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).not.toContain("exit:0");
    expect(registry.leadership).toBeDefined();

    timers.pending[0]?.fire();
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).toContain("exit:1");

    resolveVault("c2ln");
    await signPromise;
  });

  it("Defect A: mid-flight runUnderLeadership (no manual trackInflight) blocks clean unlock", async () => {
    // Break clear condition: start mid-flight work WITHOUT the test author
    // calling trackInflight; SIGTERM must not leadership:release + exit:0
    // until drain or timeout hold.
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = readyReadiness();
    const stamped = acquireAndStamp(registry, makeHandle(events));
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));

    stamped.armMoneySurface(() => {
      events.push("workers:stop");
    });

    let resolveWork!: () => void;
    const workPromise = stamped.runUnderLeadership(
      () =>
        new Promise<void>((resolve) => {
          resolveWork = resolve;
        }),
    );
    // Drain proof without caller trackInflight.
    expect(registry.inflightCount).toBe(1);

    const stopEvents: string[] = [];
    const timers = makeManualTimers();
    const stop = installGracefulStop({
      server: makeServer(stopEvents),
      readiness,
      ...registry.hooks(),
      timeoutMs: 10_000,
      exit: (code) => stopEvents.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers,
    });
    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    expect(events).toContain("workers:stop");
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).not.toContain("exit:0");
    expect(stopEvents).not.toContain("exit:1");
    expect(registry.leadership).toBeDefined();

    // Timeout hold path also valid — fire timer first to prove hard-fail.
    // (Work still pending.)
    timers.pending[0]?.fire();
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).toContain("exit:1");
    expect(registry.leadership).toBeDefined();

    resolveWork();
    await workPromise;
  });

  it("Defect A: post-boot runUnderLeadership without armMoneySurface throws", async () => {
    const registry = createShutdownRegistry();
    const stamped = acquireAndStamp(registry, makeHandle([]));
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));

    await expect(
      stamped.runUnderLeadership(async () => 42),
    ).rejects.toThrow(/money surface not armed/);
    expect(registry.inflightCount).toBe(0);
  });

  it("Defect B: unlockLeadership retains inner handle when release throws", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    let attempts = 0;
    const flaky: SignerLeadershipHandle = {
      release: async () => {
        attempts += 1;
        events.push(`release-attempt:${attempts}`);
        if (attempts === 1) {
          throw new Error("db unlock flaked");
        }
        events.push("leadership:release");
      },
    };
    acquireAndStamp(registry, flaky);
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));

    await expect(registry.hooks().releaseLeadership()).rejects.toThrow(/db unlock flaked/);
    // Slot still held — second attempt can unlock the same inner target.
    expect(registry.leadership).toBeDefined();
    expect(registry.authority.held).toBe(true);
    expect(events).toEqual(["release-attempt:1"]);

    await registry.hooks().releaseLeadership();
    expect(events).toEqual([
      "release-attempt:1",
      "release-attempt:2",
      "leadership:release",
    ]);
    expect(registry.leadership).toBeUndefined();
    expect(registry.authority.held).toBe(false);
  });

  it("Defect C: boot catch leaves readiness leadership true when release refuses", async () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = new NodeReadiness(3);
    let resolveResidual!: () => void;
    const residual = new Promise<void>((resolve) => {
      resolveResidual = resolve;
    });

    await runBootLane({
      readiness,
      logger: { info: () => {}, error: () => {} },
      runMigrations: async () => {},
      unlockVault: async () => {},
      // Production order: acquire flips the latch, stamp only records.
      acquireSignerLeadership: fakeAcquire(registry, makeHandle(events)),
      onLeadershipAcquired: (handle) => registry.stampLeadership(handle),
      onBootPhaseComplete: () => registry.completeBootPhase(),
      runBootRecovery: async () => {
        void registry.trackInflight(residual);
        throw new Error("recovery blew up");
      },
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: () => {},
    });

    // Lock still held at registry + readiness (no readiness lie).
    expect(registry.leadership).toBeDefined();
    expect(readiness.snapshot().checks.leadership).toBe(true);
    expect(readiness.snapshot().inputs.leadershipLockHeld).toBe(true);
    expect(events).not.toContain("leadership:release");

    resolveResidual();
    await new Promise((resolve) => setImmediate(resolve));
    await registry.hooks().releaseLeadership();
    // Catch only flips readiness on successful unlock; explicit release above
    // does not touch readiness — bit still true until a caller clears it.
    expect(readiness.snapshot().checks.leadership).toBe(true);
  });
});

describe("Defect D1/D2 — boot-order arm + freeze tracker (break @ 73038a59)", () => {
  it("PROBE-BOOT-ARM: armMoneySurface succeeds while boot phase still open", () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const stamped = acquireAndStamp(registry, makeHandle(events));
    expect(registry.bootPhaseOpen).toBe(true);

    // Prior FAIL: threw "armMoneySurface: boot phase still open".
    expect(() =>
      stamped.armMoneySurface(() => {
        events.push("workers:stop");
      }),
    ).not.toThrow();
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);
    expect(registry.bootPhaseOpen).toBe(true);

    // Settle does not disarm — arm sticks across completeBootPhase.
    registry.completeBootPhase();
    expect(registry.bootPhaseOpen).toBe(false);
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);
  });

  it("PROBE-BOOT-STOP: mid-boot registerWorkerStop arms and sticks after settle", () => {
    const events: string[] = [];
    const registry = createShutdownRegistry();
    acquireAndStamp(registry, makeHandle(events));
    expect(registry.bootPhaseOpen).toBe(true);

    // Older stop-only seam during boot must arm (not silent non-arm).
    registry.registerWorkerStop(() => {
      events.push("workers:stop");
    });
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);

    registry.completeBootPhase();
    expect(registry.bootPhaseOpen).toBe(false);
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);
  });

  it("Defect D1 composition: boot-lane order arms inside startMoneyWorkers then holds on SIGTERM mid-sign", async () => {
    // Real boot-lane order: stamp → recovery → gateway → startMoneyWorkers
    // (arms while boot open) → settle. Then residual tracked sign + SIGTERM
    // must NOT leadership:release + exit:0.
    const { signUnderLease } = await import("@zucoins/node-core");
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = new NodeReadiness(3);

    const bootResult = await runBootLane({
      readiness,
      logger: { info: () => {}, error: () => {} },
      runMigrations: async () => {},
      unlockVault: async () => {},
      // Production order: acquire flips the latch, stamp only records.
      acquireSignerLeadership: fakeAcquire(registry, makeHandle(events)),
      onLeadershipAcquired: (handle) => registry.stampLeadership(handle),
      onBootPhaseComplete: () => registry.completeBootPhase(),
      runBootRecovery: async () => {
        // Mirrors main.ts: a successful recovery has ensured EVENT_SIGNING.
        readiness.setEventSignerAvailable(true);
        return { ready: true as const, invariantBreach: false as const };
      },
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: (leadership) => {
        // Production composition: arm WHILE boot phase is still open.
        expect(registry.bootPhaseOpen).toBe(true);
        const stamped = leadership as ReturnType<typeof registry.stampLeadership>;
        stamped.armMoneySurface(() => {
          events.push("workers:stop");
        });
        expect(registry.moneySurfaceArmed).toBe(true);
      },
    });

    expect(bootResult.ready).toBe(true);
    expect(registry.bootPhaseOpen).toBe(false);
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);

    // Mid-sign body via the real signing chokepoint on the shared latch.
    let resolveVault!: (sig: string) => void;
    const vaultPending = new Promise<string>((resolve) => {
      resolveVault = resolve;
    });
    const preimageText = '{"amount":"1"}';
    const { createHash } = await import("node:crypto");
    const digest = createHash("sha256").update(preimageText, "utf8").digest("hex");

    const signPromise = signUnderLease(
      {
        leadership: registry.authority,
        leaseReader: {
          readActiveLease: async () => ({
            walletId: "w1",
            operationId: "op1",
            epoch: 1n,
            role: "SEND_SOURCE" as const,
            lifecycle: "ACTIVE" as const,
          }),
        },
        vaultSigner: { sign: async () => vaultPending },
        auditLog: { append: async () => undefined },
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: async () => {},
      },
      {
        walletId: "w1",
        operationId: "op1",
        leaseEpoch: 1n,
        purpose: "SPLITCHAIN_STEP_1",
        preimageText,
        expectedPreimageSha256: digest,
      },
    );
    // Drain bridge observed the body before vault resolves.
    await new Promise((resolve) => setImmediate(resolve));
    expect(registry.inflightCount).toBeGreaterThanOrEqual(1);

    const stopEvents: string[] = [];
    const timers = makeManualTimers();
    const stop = installGracefulStop({
      server: makeServer(stopEvents),
      readiness,
      ...registry.hooks(),
      timeoutMs: 10_000,
      exit: (code) => stopEvents.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers,
    });
    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    // Armed surface + mid-sign: stop fires, no clean unlock.
    expect(events).toContain("workers:stop");
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).not.toContain("exit:0");
    expect(registry.leadership).toBeDefined();

    // Hard-fail hold on timeout — residual sign must not hand lock over.
    timers.pending[0]?.fire();
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).toContain("exit:1");
    expect(registry.leadership).toBeDefined();

    resolveVault("c2lnbmF0dXJl");
    await signPromise.catch(() => undefined);
  });

  it("Defect D1 composition: mid-boot registerWorkerStop + settle + residual → hold on SIGTERM", async () => {
    // PROBE-BOOT-STOP inverted: older stop-only seam during boot must arm so
    // post-settle SIGTERM with residual work cannot empty-flush unlock.
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = new NodeReadiness(3);

    const bootResult = await runBootLane({
      readiness,
      logger: { info: () => {}, error: () => {} },
      runMigrations: async () => {},
      unlockVault: async () => {},
      // Production order: acquire flips the latch, stamp only records.
      acquireSignerLeadership: fakeAcquire(registry, makeHandle(events)),
      onLeadershipAcquired: (handle) => registry.stampLeadership(handle),
      onBootPhaseComplete: () => registry.completeBootPhase(),
      runBootRecovery: async () => {
        // Mirrors main.ts: a successful recovery has ensured EVENT_SIGNING.
        readiness.setEventSignerAvailable(true);
        return { ready: true as const, invariantBreach: false as const };
      },
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: () => {
        expect(registry.bootPhaseOpen).toBe(true);
        registry.registerWorkerStop(() => {
          events.push("workers:stop");
        });
      },
    });

    expect(bootResult.ready).toBe(true);
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);
    // Let boot-token waitable finally() drop before asserting residual count.
    await new Promise((resolve) => setImmediate(resolve));
    expect(registry.inflightCount).toBe(0);

    let resolveSign!: () => void;
    const signBody = new Promise<void>((resolve) => {
      resolveSign = resolve;
    });
    registry.authority.trackSigningInflight(signBody);
    expect(registry.inflightCount).toBe(1);

    const stopEvents: string[] = [];
    const timers = makeManualTimers();
    const stop = installGracefulStop({
      server: makeServer(stopEvents),
      readiness,
      ...registry.hooks(),
      timeoutMs: 10_000,
      exit: (code) => stopEvents.push(`exit:${code}`),
      emitter: { on: () => {} },
      timers,
    });
    stop.handleSignal("SIGTERM");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    expect(events).toContain("workers:stop");
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).not.toContain("exit:0");

    timers.pending[0]?.fire();
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).not.toContain("leadership:release");
    expect(stopEvents).toContain("exit:1");

    resolveSign();
    await signBody;
  });

  it("Defect D2 / PROBE-REPLACE-TRACKER: setSigningInflightTracker freeze refuses wipe", () => {
    const registry = createShutdownRegistry();
    // Registry already installed the drain bridge at construction.
    expect(() =>
      registry.authority.setSigningInflightTracker(() => {
        /* noop wipe */
      }),
    ).toThrow(/already installed/);

    // Tracker still forwards — wipe did not take.
    let resolveWork!: () => void;
    const work = new Promise<void>((resolve) => {
      resolveWork = resolve;
    });
    registry.authority.trackSigningInflight(work);
    expect(registry.inflightCount).toBe(1);
    resolveWork();
  });
});

describe("Defect D3/D4 — stamp is monotonic (break @ 564248fc)", () => {
  it("PROBE-RESTAMP-DISARM: re-stamp keeps the arm — release still refuses", async () => {
    // Prior FAIL: stampLeadership set moneyArmed=false / enginesQuiesced=true,
    // so a second stamp wiped the armed-surface unlock gate while the worker
    // loop was still live and an empty flush then read as drain proof.
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const stamped = acquireAndStamp(registry, makeHandle(events));

    let acceptWork = true;
    stamped.armMoneySurface(() => {
      acceptWork = false;
      events.push("workers:stop");
    });
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);

    // Re-stamp (double onLeadershipAcquired / main.ts defensive late stamp).
    registry.stampLeadership(makeHandle(events, "leadership:release:restamped"));
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);

    // Settle boot so inflight is empty: the ONLY thing left holding the lock is
    // the armed-surface gate. It must still refuse.
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));
    expect(registry.inflightCount).toBe(0);
    expect(acceptWork).toBe(true);

    await expect(registry.hooks().releaseLeadership()).rejects.toThrow(
      /engines not quiesced/,
    );
    await expect(stamped.release()).rejects.toThrow(/engines not quiesced/);
    expect(events).not.toContain("leadership:release");
    expect(events).not.toContain("leadership:release:restamped");

    // Only ENGINE_QUIESCE opens the gate — and it stops the worker first.
    registry.hooks().stopWorkers();
    expect(acceptWork).toBe(false);
    await registry.hooks().releaseLeadership();
    // Re-stamp swapped the inner unlock target; that handle is the one released.
    expect(events).toContain("leadership:release:restamped");
  });

  it("PROBE-RESTAMP-DISARM: re-stamp after ENGINE_QUIESCE cannot reopen accept", async () => {
    // The A3 monotonicity guard must survive a stamp: prior code reset
    // moneyArmed=false on stamp, which made `moneyArmed && enginesQuiesced`
    // false and let a post-quiesce arm succeed under a still-held lock.
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const stamped = acquireAndStamp(registry, makeHandle(events));
    stamped.armMoneySurface(() => events.push("workers:stop"));

    registry.hooks().stopWorkers();
    expect(registry.enginesQuiesced).toBe(true);

    const restamped = registry.stampLeadership(makeHandle(events, "restamped"));
    expect(registry.moneySurfaceArmed).toBe(false);
    expect(registry.enginesQuiesced).toBe(true);
    expect(() =>
      restamped.armMoneySurface(() => events.push("workers:stop:reopen")),
    ).toThrow(/engines already quiesced/);
    expect(events).not.toContain("workers:stop:reopen");

    await expect(
      restamped.runUnderLeadership(async () => {
        events.push("should-not-run");
        return 1;
      }),
    ).rejects.toThrow(/engines quiesced|signer authority not held/);
    expect(events).not.toContain("should-not-run");
  });

  it("PROBE-RESTAMP-DISARM: clear then defensive re-stamp keeps the arm", async () => {
    // main.ts:197-200 shape — clearLeadership (lost connection) then a
    // defensive stamp. Dropping the DB handle does not stop the worker loop, so
    // the gate must survive the clear as well as the stamp.
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const stamped = acquireAndStamp(registry, makeHandle(events));
    stamped.armMoneySurface(() => events.push("workers:stop"));
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));

    registry.clearLeadership();
    expect(registry.leadership).toBeUndefined();
    expect(registry.moneySurfaceArmed).toBe(true);

    registry.stampLeadership(makeHandle(events, "leadership:release:defensive"));
    registry.completeBootPhase();
    // Let the settled boot token drop out of the tracked set: the arm gate must
    // be the only thing left refusing.
    await new Promise((resolve) => setImmediate(resolve));
    expect(registry.moneySurfaceArmed).toBe(true);
    expect(registry.enginesQuiesced).toBe(false);
    expect(registry.inflightCount).toBe(0);

    await expect(registry.hooks().releaseLeadership()).rejects.toThrow(
      /engines not quiesced/,
    );
    expect(events).not.toContain("leadership:release:defensive");
  });

  it("PROBE-AUTHORITY-RESURRECT: stamp never marks the shared latch acquired", async () => {
    // Prior FAIL: stampLeadership called authority.markAcquired() whenever
    // held was false, inventing signing authority with no advisory lock.
    const { signUnderLease } = await import("@zucoins/node-core");
    const events: string[] = [];
    const registry = createShutdownRegistry();

    // Never acquired: a stamp alone must not make this process the signer.
    const stamped = registry.stampLeadership(makeHandle(events));
    expect(registry.authority.held).toBe(false);
    expect(() => assertSignerLeadership(registry.authority)).toThrow(NotSignerLeaderError);
    expect(() =>
      stamped.armMoneySurface(() => events.push("workers:stop")),
    ).toThrow(/signer authority not held/);
    await expect(stamped.runUnderLeadership(async () => 1)).rejects.toThrow(
      /signer authority not held/,
    );
    expect(() =>
      signUnderLease(
        {
          leadership: registry.authority,
          leaseReader: { readActiveLease: async () => null },
          vaultSigner: { sign: async () => "c2ln" },
          auditLog: { append: async () => undefined },
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          assertWalletMaySign: async () => {},
      },
        {
          walletId: "w1",
          operationId: "op1",
          leaseEpoch: 1n,
          purpose: "SPLITCHAIN_STEP_1",
          preimageText: "{}",
          expectedPreimageSha256: "0".repeat(64),
        },
      ),
    ).toThrow(NotSignerLeaderError);
    // Nothing was tracked but the stamp's boot token — no sign body got past
    // the latch assert, so the drain bridge saw no work.
    registry.completeBootPhase();
    await new Promise((resolve) => setImmediate(resolve));
    expect(registry.inflightCount).toBe(0);
  });

  it("PROBE-AUTHORITY-RESURRECT: stamp after withdraw does not resurrect held", async () => {
    // Shutdown invariant signer_authority_withdrawn_first: once withdrawn, only a fresh DB
    // acquire may sign again. Withdraw → clear → defensive stamp is exactly the
    // main.ts:197-200 shape and must leave the latch false.
    const events: string[] = [];
    const registry = createShutdownRegistry();
    acquireAndStamp(registry, makeHandle(events));
    expect(registry.authority.held).toBe(true);

    registry.hooks().withdrawSignerAuthority();
    expect(registry.authority.held).toBe(false);

    // Withdraw → stamp (no clear).
    registry.stampLeadership(makeHandle(events, "restamped"));
    expect(registry.authority.held).toBe(false);

    // Withdraw → clear → defensive stamp (main.ts defensive path).
    registry.clearLeadership();
    const defensive = registry.stampLeadership(makeHandle(events, "defensive"));
    registry.completeBootPhase();
    expect(registry.authority.held).toBe(false);
    expect(() => assertSignerLeadership(registry.authority)).toThrow(NotSignerLeaderError);
    await expect(defensive.runUnderLeadership(async () => 1)).rejects.toThrow(
      /signer authority not held/,
    );
    expect(registry.inflightCount).toBe(0);
  });
});

describe("release × registry seam — retryable recovery releases through the wrapper", () => {
  it("retryable recovery release is not refused by its own boot-phase token", async () => {
    // Retryable-recovery handling releases leadership on retryable recovery so a standby can retry.
    // The registry integration makes that release go through the registry wrapper, which refuses
    // while ANY tracked promise remains — and the boot-phase token opened at
    // stamp is still tracked at that moment. The lane must settle the token
    // before the unlock attempt, and the settle must have actually left the
    // tracked set (not merely resolved the promise), or release
    // becomes a permanent refusal and the treasury SPOF lock is never freed.
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = new NodeReadiness(3);

    const bootResult = await runBootLane({
      readiness,
      logger: { info: () => {}, error: () => {} },
      runMigrations: async () => {},
      unlockVault: async () => {},
      acquireSignerLeadership: fakeAcquire(registry, makeHandle(events)),
      onLeadershipAcquired: (handle) => registry.stampLeadership(handle),
      onBootPhaseComplete: () => registry.completeBootPhase(),
      // Explicit retryable: not ready, no invariant breach.
      runBootRecovery: async () => ({ ready: false as const, invariantBreach: false as const }),
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: () => {},
    });

    expect(bootResult.ready).toBe(false);
    expect(bootResult.failedStep).toBe("boot-recovery");
    // The lock was really freed: handle dropped, release observed, latch honest.
    expect(bootResult.leadership).toBeUndefined();
    expect(bootResult.leadershipReleaseFailed).toBeUndefined();
    expect(events).toContain("leadership:release");
    expect(registry.leadership).toBeUndefined();
    expect(registry.bootPhaseOpen).toBe(false);
    expect(registry.inflightCount).toBe(0);
    expect(registry.authority.held).toBe(false);
    // main.ts then exits for reacquire rather than quarantining.
    expect(dispositionForIncompleteBoot(bootResult)).toBe("exit-for-reacquire");
  });

  it("quarantine hold settles the boot token so a quarantined node still stops cleanly", async () => {
    // Invariant breach keeps the lock deliberately. But the boot token must not
    // stay open: a permanently tracked token makes graceful-stop's flush time
    // out, so a quarantined instance could never take the clean-stop path.
    const events: string[] = [];
    const registry = createShutdownRegistry();
    const readiness = new NodeReadiness(3);

    const bootResult = await runBootLane({
      readiness,
      logger: { info: () => {}, error: () => {} },
      runMigrations: async () => {},
      unlockVault: async () => {},
      acquireSignerLeadership: fakeAcquire(registry, makeHandle(events)),
      onLeadershipAcquired: (handle) => registry.stampLeadership(handle),
      onBootPhaseComplete: () => registry.completeBootPhase(),
      runBootRecovery: async () => ({ ready: false as const, invariantBreach: true as const }),
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: () => {},
    });

    expect(bootResult.ready).toBe(false);
    expect(bootResult.leadership).toBeDefined();
    expect(events).not.toContain("leadership:release");
    expect(registry.bootPhaseOpen).toBe(false);
    expect(registry.inflightCount).toBe(0);
    expect(dispositionForIncompleteBoot(bootResult)).toBe("quarantine");

    // No money worker ever armed, so the quarantined node can still release on
    // SIGTERM — the flush empties instead of hanging on a stale boot token.
    await registry.hooks().flushInFlight();
    await registry.hooks().releaseLeadership();
    expect(events).toContain("leadership:release");
  });
});

describe("main.ts graceful-stop composition", () => {
  const mainSource = readFileSync(
    fileURLToPath(new URL("../src/main.ts", import.meta.url)),
    "utf8",
  );
  const bootLaneSource = readFileSync(
    fileURLToPath(new URL("../src/boot/boot-lane.ts", import.meta.url)),
    "utf8",
  );
  const registrySource = readFileSync(
    fileURLToPath(new URL("../src/boot/shutdown-registry.ts", import.meta.url)),
    "utf8",
  );
  const scheduleSource = readFileSync(
    fileURLToPath(new URL("../src/dr/schedule.ts", import.meta.url)),
    "utf8",
  );

  it("composes createShutdownRegistry + stamp + completeBootPhase + shared authority", () => {
    expect(mainSource).toMatch(/createShutdownRegistry/);
    expect(mainSource).toMatch(/onLeadershipAcquired/);
    expect(mainSource).toMatch(/stampLeadership/);
    expect(mainSource).toMatch(/onBootPhaseComplete/);
    expect(mainSource).toMatch(/completeBootPhase/);
    expect(mainSource).toMatch(/shutdownRegistry\.hooks\(\)/);
    expect(mainSource).toMatch(/shutdownRegistry\.authority/);
    expect(bootLaneSource).toMatch(/onLeadershipAcquired/);
    expect(bootLaneSource).toMatch(/onBootPhaseComplete/);
    expect(registrySource).toMatch(/trackInflight/);
    expect(registrySource).toMatch(/completeBootPhase/);
    expect(registrySource).toMatch(/refuse leadership release/);
    expect(registrySource).toMatch(/runUnderLeadership/);
    expect(registrySource).toMatch(/armMoneySurface/);
    expect(registrySource).toMatch(/inner\.release\(\)/);
    // Defect B: clear slots only after successful inner.release
    expect(registrySource).toMatch(/await inner\.release\(\)/);
    // Non-opt-in signing-chokepoint drain bridge
    expect(registrySource).toMatch(/setSigningInflightTracker/);
    expect(registrySource).toMatch(/trackSigningInflight/);
    expect(registrySource).toMatch(/engines already quiesced/);
    // D1: arm reachable while boot open (no "boot phase still open" throw)
    expect(registrySource).not.toMatch(/armMoneySurface: boot phase still open/);
    // D4: only tryAcquireSignerLeadership marks the latch acquired — the
    // registry must never mint authority (source ratchet, not just behaviour).
    expect(registrySource).not.toMatch(/authority\.markAcquired/);
    expect(mainSource).toMatch(/runUnderLeadership/);
    expect(mainSource).toMatch(/armMoneySurface/);
    expect(mainSource).toMatch(/trackSigningInflight/);
  });

  it("backup scheduler starts only after ready boot + leadership (ZTR-1183)", () => {
    // Composition: incomplete-boot dispositions must return before createBackupScheduler.
    // liveness-only used to fall through — the explicit return is the load-bearing fix.
    expect(mainSource).toMatch(
      /backup scheduler withheld — boot incomplete \(liveness-only\)/,
    );
    const withheldIdx = mainSource.indexOf(
      "backup scheduler withheld — boot incomplete (liveness-only)",
    );
    expect(withheldIdx).toBeGreaterThan(-1);
    // createBackupScheduler must appear only after the incomplete-boot early returns.
    const createIdx = mainSource.indexOf("createBackupScheduler({", withheldIdx);
    expect(createIdx).toBeGreaterThan(withheldIdx);
    const between = mainSource.slice(withheldIdx, createIdx);
    expect(between).toMatch(/\breturn;/);
    // Leadership gate wired into the scheduler config (same latch money workers use).
    expect(mainSource).toMatch(
      /isLeader:\s*\(\)\s*=>\s*shutdownRegistry\.authority\.held/,
    );
    // Full-boot comment gates the start block.
    expect(mainSource).toMatch(/Full boot only:[\s\S]{0,200}BACKUP_SCHEDULE_ENABLED/);
    // Scheduler start itself still calls .start() after create.
    expect(mainSource).toMatch(/backupScheduler\.start\(\)/);
  });

  it("backup scheduler stop+drain is wired into the shutdown-sequence hooks (not block-local)", () => {
    // Handle retained outside the enable block so stopWorkers can reach it.
    expect(mainSource).toMatch(/let backupScheduler/);
    expect(mainSource).toMatch(/backupScheduler\s*=\s*createBackupScheduler/);
    expect(mainSource).toMatch(/afterSuccess:\s*async/);
    expect(mainSource).toMatch(/BACKUP_CONTINUITY_MARKERS_PATH/);
    expect(mainSource).toMatch(/deriveContinuitySnapshot/);
    expect(mainSource).toMatch(/writeContinuityMarkers/);
    // ENGINE_QUIESCE: stop new schedules synchronously.
    expect(mainSource).toMatch(/backupScheduler\?\.stop\(\)/);
    // INFLIGHT complete: await active export within bounded termination.
    expect(mainSource).toMatch(/backupScheduler\?\.drain\(\)/);
    // Each export is observed on the shared inflight set.
    expect(mainSource).toMatch(/trackInflight:\s*\(work\)\s*=>\s*shutdownRegistry\.trackInflight\(work\)/);
    // Must NOT arm money surface for backup-only quiesce.
    const backupBlock = mainSource.slice(mainSource.indexOf("BACKUP_SCHEDULE_ENABLED"));
    expect(backupBlock).not.toMatch(/registerWorkerStop/);
    // Scheduler itself exposes drain + interruptible stop (deploy interruption).
    expect(scheduleSource).toMatch(/drain\(\):\s*Promise<void>/);
    expect(scheduleSource).toMatch(/interruptibleSleep/);
    expect(scheduleSource).toMatch(/wakeSleep/);
  });
});

describe("backup scheduler + graceful stop composition", () => {
  it("SIGTERM stops new schedules and waits for in-flight export before release", async () => {
    const events: string[] = [];
    const readiness = readyReadiness();
    const holdExport = deferredPromise();
    let stopCalled = false;
    let drainResolved = false;

    const fakeScheduler = {
      stop() {
        stopCalled = true;
        events.push("backup:stop");
      },
      async drain() {
        events.push("backup:drain:start");
        await holdExport.promise;
        drainResolved = true;
        events.push("backup:drain:done");
      },
    };

    const registry = createShutdownRegistry();
    const hooks = registry.hooks();
    acquireAndStamp(registry, makeHandle(events));
    registry.completeBootPhase();

    let exitCode: number | undefined;
    const stop = installGracefulStop({
      server: makeServer(events),
      readiness,
      withdrawSignerAuthority: hooks.withdrawSignerAuthority,
      stopWorkers: () => {
        hooks.stopWorkers();
        fakeScheduler.stop();
      },
      flushInFlight: async () => {
        await hooks.flushInFlight();
        await fakeScheduler.drain();
      },
      releaseLeadership: hooks.releaseLeadership,
      exit: (code) => {
        exitCode = code;
        events.push(`exit:${code}`);
      },
      emitter: { on() {} },
      signals: [],
    });

    // Track a mid-flight export the way main wires trackInflight.
    const exportWork = holdExport.promise.then(() => "ok");
    void registry.trackInflight(exportWork);

    stop.handleSignal("SIGTERM");

    // stopWorkers ran sync before server.close callback scheduling — next microtask.
    await Promise.resolve();
    expect(stopCalled).toBe(true);
    expect(events).toContain("backup:stop");
    expect(drainResolved).toBe(false);
    expect(exitCode).toBeUndefined();

    holdExport.resolve();
    await flushMicrotasks(50);

    expect(drainResolved).toBe(true);
    expect(events).toContain("backup:drain:done");
    expect(events).toContain("leadership:release");
    expect(exitCode).toBe(0);
    // Order: stop before drain start; drain done before leadership release.
    const stopIdx = events.indexOf("backup:stop");
    const drainStartIdx = events.indexOf("backup:drain:start");
    const drainDoneIdx = events.indexOf("backup:drain:done");
    const releaseIdx = events.indexOf("leadership:release");
    expect(stopIdx).toBeGreaterThanOrEqual(0);
    expect(drainStartIdx).toBeGreaterThan(stopIdx);
    expect(drainDoneIdx).toBeGreaterThan(drainStartIdx);
    expect(releaseIdx).toBeGreaterThan(drainDoneIdx);
  });
});

function deferredPromise(): {
  promise: Promise<void>;
  resolve: () => void;
} {
  let resolve!: () => void;
  const promise = new Promise<void>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

async function flushMicrotasks(rounds: number): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await Promise.resolve();
  }
}
