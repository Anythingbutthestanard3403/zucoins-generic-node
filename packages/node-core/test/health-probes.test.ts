import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildLivenessResponse,
  livenessHttp,
  evaluateReadinessFromProbes,
  readinessHttp,
  CachedDbProbe,
  createHealthHandlers,
  DEFAULT_DB_PING_TTL_MS,
  DEFAULT_DB_PING_TIMEOUT_MS,
  GATING_READINESS_CHECK_IDS,
  type ReadinessStateInputs,
} from "../src/api/health.js";
import { NodeCoreReadinessState } from "../src/core/readiness-state.js";
import { acquireLeadershipWithBackoff } from "../src/core/leadership-acquire.js";
import { createNodeCore } from "../src/core/runtime.js";
import {
  createGatewayReadCredentials,
  type GatewayConfiguration,
} from "../src/gateway/index.js";
import {
  createOfflineDatabaseAdapter,
  createOfflineReadTransport,
} from "../src/testkit/index.js";
import type { GatewayResponse } from "../src/protocol/index.js";

const FIXED_TIME = "2026-01-15T10:00:00.000Z";
const now = () => FIXED_TIME;
const VERSION = "0.0.0";

function baseState(overrides: Partial<ReadinessStateInputs> = {}): ReadinessStateInputs {
  return {
    schemaMigrated: true,
    vaultKeyRingLoaded: true,
    vaultCensusVerified: true,
    observationReadCapable: true,
    restoreHoldClear: true,
    leadershipLockHeld: true,
    eventSignerAvailable: true,
    halted: false,
    storagePressure: false,
    stopping: false,
    observationDegraded: false,
    ...overrides,
  };
}

describe("readiness — EVENT_SIGNING availability (money-only, outside the frozen check census; ZTR-1179 / ZPAY-252)", () => {
  it("eventSignerAvailable:false does NOT force not-ready (deploy-ready independent of post-leadership ensure)", () => {
    const verdict = evaluateReadinessFromProbes(baseState({ eventSignerAvailable: false }), true);
    expect(verdict.ready).toBe(true);
    expect(verdict.status).toBe("ready");
    expect(verdict.checks.map((c) => c.name)).not.toContain("event_signer_available");
  });

  it("NodeCoreReadinessState defaults open and stamps through setEventSignerAvailable", () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    // Open by default: only a composition that installs an EVENT_SIGNING
    // authority closes it (the custody shell stamps false at construction).
    expect(state.snapshot().eventSignerAvailable).toBe(true);
    state.setEventSignerAvailable(false);
    expect(state.snapshot().eventSignerAvailable).toBe(false);
    state.setEventSignerAvailable(true);
    expect(state.snapshot().eventSignerAvailable).toBe(true);
  });
});

describe("liveness — zero dependency", () => {
  it("returns alive with version and timestamp", () => {
    expect(buildLivenessResponse(VERSION, now)).toEqual({
      status: "alive",
      version: VERSION,
      timestamp: FIXED_TIME,
    });
  });

  it("livenessHttp is always 200 and never consults probes", () => {
    const result = livenessHttp(VERSION, now);
    expect(result.statusCode).toBe(200);
    expect(result.body.status).toBe("alive");
  });
});

describe("readiness gating", () => {
  it("gates on the five frozen checks (incl. restore_hold_clear / ZTR-1172)", () => {
    expect([...GATING_READINESS_CHECK_IDS]).toEqual([
      "schema_migrated",
      "database_reachable",
      "vault_available",
      "observation_read_capable",
      "restore_hold_clear",
    ]);
  });

  it("returns 503 when restore_hold is held", () => {
    const verdict = evaluateReadinessFromProbes(
      baseState({ restoreHoldClear: false }),
      true,
    );
    expect(verdict.ready).toBe(false);
    expect(verdict.failing).toContain("restore_hold_clear");
  });

  it("returns ready when every gating check passes (leadership optional)", () => {
    const verdict = evaluateReadinessFromProbes(
      baseState({ leadershipLockHeld: false }),
      true,
    );
    expect(verdict.ready).toBe(true);
    expect(verdict.status).toBe("ready");
    const leadership = verdict.checks.find((c) => c.name === "signer_leadership");
    expect(leadership).toEqual({
      name: "signer_leadership",
      ready: false,
      gating: false,
    });
  });

  it("returns 503 when any gating check fails", () => {
    for (const override of [
      { schemaMigrated: false },
      { vaultKeyRingLoaded: false },
      { observationReadCapable: false },
      { restoreHoldClear: false },
    ] as const) {
      const verdict = evaluateReadinessFromProbes(baseState(override), true);
      expect(verdict.ready).toBe(false);
      expect(verdict.status).toBe("not_ready");
    }
    const dbDown = evaluateReadinessFromProbes(baseState(), false);
    expect(dbDown.ready).toBe(false);
    expect(dbDown.failing).toContain("database_reachable");
  });

  it("reports halt and storage_pressure as non-gating detail", () => {
    const verdict = evaluateReadinessFromProbes(
      baseState({ halted: true, storagePressure: true }),
      true,
    );
    expect(verdict.ready).toBe(true);
    expect(verdict.checks.find((c) => c.name === "halt")).toMatchObject({
      ready: false,
      gating: false,
    });
    expect(verdict.checks.find((c) => c.name === "storage_pressure")).toMatchObject({
      ready: false,
      gating: false,
    });
  });

  it("reports degraded when observation failure budget was exceeded", () => {
    const verdict = evaluateReadinessFromProbes(
      baseState({
        observationReadCapable: false,
        observationDegraded: true,
      }),
      true,
    );
    expect(verdict.ready).toBe(false);
    expect(verdict.status).toBe("degraded");
  });

  it("forces not-ready while stopping", () => {
    const verdict = evaluateReadinessFromProbes(baseState({ stopping: true }), true);
    expect(verdict.ready).toBe(false);
  });
});

describe("CachedDbProbe — flood protection + recovery", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("uses monotonic time so a wall-clock rollback cannot extend a cached result", async () => {
    let wallNow = 1_000;
    let monotonicNow = 0;
    vi.spyOn(Date, "now").mockImplementation(() => wallNow);
    vi.spyOn(performance, "now").mockImplementation(() => monotonicNow);
    let calls = 0;
    const probe = new CachedDbProbe(async () => {
      calls += 1;
    }, 5_000);

    expect(await probe.probe()).toBe(true);
    wallNow = 0;
    monotonicNow = 5_000;
    expect(await probe.probe()).toBe(true);
    expect(calls).toBe(2);
  });

  it("fails closed within its deadline when the DB ping never settles", async () => {
    const probe = new CachedDbProbe(
      () => new Promise<void>(() => {}),
      5_000,
      () => 0,
      20,
    );
    const result = await Promise.race([
      probe.probe(),
      new Promise<"watchdog">((resolve) => setTimeout(() => resolve("watchdog"), 500)),
    ]);
    expect(result).toBe(false);
  });

  it("keeps a timed-out late success unavailable and coalesces concurrent callers", async () => {
    let resolvePing!: () => void;
    let calls = 0;
    const t = 0;
    const probe = new CachedDbProbe(
      () => {
        calls += 1;
        return new Promise<void>((resolve) => {
          resolvePing = resolve;
        });
      },
      1_000,
      () => t,
      20,
    );

    const [first, concurrent] = await Promise.all([probe.probe(), probe.probe()]);
    expect([first, concurrent]).toEqual([false, false]);
    expect(calls).toBe(1);

    resolvePing();
    await Promise.resolve();
    expect(await probe.probe()).toBe(false);
    expect(calls).toBe(1);
  });

  it("caches a successful probe within the TTL", async () => {
    let calls = 0;
    let t = 0;
    const probe = new CachedDbProbe(
      async () => {
        calls += 1;
      },
      5_000,
      () => t,
    );
    expect(await probe.probe()).toBe(true);
    t = 4_999;
    expect(await probe.probe()).toBe(true);
    expect(calls).toBe(1);
    t = 5_000;
    expect(await probe.probe()).toBe(true);
    expect(calls).toBe(2);
  });

  it("surfaces DB failure as false within the cache TTL window, then recovers", async () => {
    let shouldFail = true;
    let t = 0;
    let calls = 0;
    const probe = new CachedDbProbe(
      async () => {
        calls += 1;
        if (shouldFail) throw new Error("db down");
      },
      1_000,
      () => t,
    );
    expect(await probe.probe()).toBe(false);
    expect(calls).toBe(1);
    // Within TTL — still false, no re-probe.
    t = 500;
    expect(await probe.probe()).toBe(false);
    expect(calls).toBe(1);
    // After TTL + recovery.
    shouldFail = false;
    t = 1_000;
    expect(await probe.probe()).toBe(true);
    expect(calls).toBe(2);
  });

  it("refresh() re-pings and re-dates inside the TTL, where probe() short-circuits", async () => {
    // ZTR-1178. probe()'s cache hit returns the old verdict AND leaves cachedAtMs where it
    // was, so a keep-warm timer built on probe() cannot hold cachedReachable() open: the
    // ticks that land before expiry do nothing, and the tick that finally re-pings arrives
    // after the verdict has already aged out. refresh() is the path that re-dates.
    let calls = 0;
    let t = 0;
    const probe = new CachedDbProbe(
      async () => {
        calls += 1;
      },
      1_000,
      () => t,
    );
    expect(await probe.probe()).toBe(true);

    t = 500;
    expect(await probe.probe()).toBe(true);
    expect(calls).toBe(1); // swallowed by the TTL, cachedAtMs still 0
    expect(await probe.refresh()).toBe(true);
    expect(calls).toBe(2); // re-pinged despite the live cache…

    t = 1_400;
    expect(probe.cachedReachable()).toBe(true); // …and re-dated to 500, so 900ms old
    expect(calls).toBe(2); // cachedReachable never probes
  });

  it("refresh() leaves the last verdict readable while its ping is in flight", async () => {
    // Why the keep-warm refresh is refresh() and not invalidate() + probe(): invalidate()
    // clears cachedOk, so the money-admission gate would read closed for the duration of
    // every refresh ping — a self-inflicted outage once per cadence (ZTR-1178).
    // pingDb is invoked from a microtask, so the resolver only exists a tick later.
    const pending: Array<() => void> = [];
    const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
    let t = 0;
    const probe = new CachedDbProbe(
      () => new Promise<void>((resolve) => pending.push(resolve)),
      1_000,
      () => t,
    );

    const armed = probe.refresh();
    await tick();
    pending.shift()?.();
    expect(await armed).toBe(true);
    expect(probe.cachedReachable()).toBe(true);

    t = 500;
    const inFlight = probe.refresh();
    await tick();
    expect(pending.length).toBe(1); // a real ping is out, inside the TTL…
    expect(probe.cachedReachable()).toBe(true); // …and the gate stayed open through it
    pending.shift()?.();
    expect(await inFlight).toBe(true);
  });

  it("cachedReachable sticky-opens past TTL while a last-true refresh is in flight", async () => {
    // ZTR-1178 D1. refresh() leaves the old stamp in place until settle. Under production
    // constants half-TTL slack (2.5s) < ping deadline (4.5s), so age can cross ttlMs while
    // a healthy keep-warm ping is still out. Sticky-open on inFlight + last-true closes
    // that gap without widening the idle freshness bound.
    const pending: Array<() => void> = [];
    const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
    let t = 0;
    const probe = new CachedDbProbe(
      () => new Promise<void>((resolve) => pending.push(resolve)),
      1_000,
      () => t,
    );

    const armed = probe.refresh();
    await tick();
    pending.shift()?.();
    expect(await armed).toBe(true);
    expect(probe.cachedReachable()).toBe(true);

    const inFlight = probe.refresh();
    await tick();
    expect(pending.length).toBe(1);

    t = 1_000;
    expect(probe.cachedReachable()).toBe(true); // age == TTL, but sticky while pending
    t = 1_001;
    expect(probe.cachedReachable()).toBe(true); // past TTL mid-flight still open

    pending.shift()?.();
    expect(await inFlight).toBe(true);
    expect(probe.cachedReachable()).toBe(true); // re-dated on settle
    t = 2_000;
    expect(probe.cachedReachable()).toBe(true); // idle age from settle stamp (1001)
    t = 2_002;
    expect(probe.cachedReachable()).toBe(false); // idle stale once inFlight cleared
  });

  it("cachedReachable does not sticky-open on last-false while a retry is in flight", async () => {
    // Fail-closed on a known-bad verdict: a flapping DB must not look admitted during
    // every retry just because a refresh is pending.
    const pending: Array<() => void> = [];
    const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
    let t = 0;
    let shouldFail = true;
    const probe = new CachedDbProbe(
      () =>
        new Promise<void>((resolve, reject) => {
          pending.push(() => {
            if (shouldFail) reject(new Error("down"));
            else resolve();
          });
        }),
      1_000,
      () => t,
    );

    const failed = probe.refresh();
    await tick();
    pending.shift()?.();
    expect(await failed).toBe(false);
    expect(probe.cachedReachable()).toBe(false);

    shouldFail = false;
    const retry = probe.refresh();
    await tick();
    expect(pending.length).toBe(1);
    t = 500;
    expect(probe.cachedReachable()).toBe(false); // still closed on last-false mid-flight
    t = 2_000;
    expect(probe.cachedReachable()).toBe(false);

    pending.shift()?.();
    expect(await retry).toBe(true);
    expect(probe.cachedReachable()).toBe(true); // opens only after successful settle
  });

  it("timeout settle clears sticky-open on a hung last-true refresh", async () => {
    // timeoutMs is wall setTimeout, not the fake clock — use a short real timeout and
    // await the in-flight promise (same pattern as readinessHttp timeout cases above).
    // Do not "advance fake clock past timeoutMs" alone; that never fires the race.
    const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
    let t = 0;
    let n = 0;
    const probe = new CachedDbProbe(
      () => {
        n += 1;
        if (n === 1) return Promise.resolve();
        return new Promise<void>(() => {}); // hang thereafter
      },
      1_000,
      () => t,
      30,
    );
    expect(await probe.refresh()).toBe(true);
    expect(probe.cachedReachable()).toBe(true);

    const hung = probe.refresh();
    await tick();
    t = 5_000; // well past TTL; sticky holds only while inFlight is set
    expect(probe.cachedReachable()).toBe(true);
    expect(await hung).toBe(false); // wall timeout race settles false
    expect(probe.cachedReachable()).toBe(false); // sticky cleared with completed false
  });

  it("matches the default TTL", () => {
    expect(DEFAULT_DB_PING_TTL_MS).toBe(5_000);
    expect(DEFAULT_DB_PING_TIMEOUT_MS).toBe(5_000);
  });
});

describe("readinessHttp — integrated handler", () => {
  it("returns fail-closed 503 when the shared DB probe never settles", async () => {
    const result = await Promise.race([
      readinessHttp({
        version: VERSION,
        getState: () => baseState(),
        pingDb: () => new Promise<void>(() => {}),
        dbPingTimeoutMs: 20,
        now,
      }),
      new Promise<"watchdog">((resolve) => setTimeout(() => resolve("watchdog"), 500)),
    ]);
    expect(result).not.toBe("watchdog");
    expect(result).toMatchObject({
      statusCode: 503,
      body: { status: "not_ready" },
    });
  });

  it("does not turn a late-resolving timed-out readiness ping into stale success", async () => {
    let resolvePing!: () => void;
    let calls = 0;
    const dbProbe = new CachedDbProbe(
      () => {
        calls += 1;
        return new Promise<void>((resolve) => {
          resolvePing = resolve;
        });
      },
      1_000,
      () => 0,
      20,
    );
    const deps = {
      version: VERSION,
      getState: () => baseState(),
      pingDb: async () => {},
      dbProbe,
      now,
    };

    expect(await readinessHttp(deps)).toMatchObject({ statusCode: 503 });
    resolvePing();
    await Promise.resolve();
    expect(await readinessHttp(deps)).toMatchObject({ statusCode: 503 });
    expect(calls).toBe(1);
  });

  it("returns 200 when stamps + DB are healthy even without leadership", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    state.markSchemaMigrated();
    state.setVaultAvailable(true);
    state.recordObservationReadSuccess();
    // leadership deliberately left false
    const result = await readinessHttp({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
    });
    expect(result.statusCode).toBe(200);
    expect(result.body).toMatchObject({ status: "ready" });
    const body = result.body as { checks: Array<{ name: string; ready: boolean; gating: boolean }> };
    expect(body.checks.find((c) => c.name === "signer_leadership")).toMatchObject({
      ready: false,
      gating: false,
    });
  });

  it("returns 503 within TTL when DB fails (negative path)", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    state.markSchemaMigrated();
    state.setVaultAvailable(true);
    state.recordObservationReadSuccess();
    state.setLeadershipHeld(true);
    const result = await readinessHttp({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {
        throw new Error("ECONNREFUSED");
      },
      now,
    });
    expect(result.statusCode).toBe(503);
    expect(result.body).toMatchObject({ status: "not_ready" });
  });

  it("onBeforeEvaluate runs before getState so storage_pressure stamp is visible", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    state.markSchemaMigrated();
    state.setVaultAvailable(true);
    state.recordObservationReadSuccess();
    let hookCalls = 0;
    const result = await readinessHttp({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
      onBeforeEvaluate: () => {
        hookCalls += 1;
        state.setStoragePressure(true);
      },
    });
    expect(hookCalls).toBe(1);
    expect(result.statusCode).toBe(200);
    const body = result.body as {
      checks: Array<{ name: string; ready: boolean; gating: boolean }>;
    };
    expect(body.checks.find((c) => c.name === "storage_pressure")).toMatchObject({
      ready: false,
      gating: false,
    });
  });

  it("onBeforeEvaluate errors are swallowed (optional stamp cannot poison readiness)", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    state.markSchemaMigrated();
    state.setVaultAvailable(true);
    state.recordObservationReadSuccess();
    const result = await readinessHttp({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
      onBeforeEvaluate: async () => {
        throw new Error("collector offline");
      },
    });
    expect(result.statusCode).toBe(200);
  });

  it("negative path: forced signer-lock loss is reported but non-gating", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    state.markSchemaMigrated();
    state.setVaultAvailable(true);
    state.recordObservationReadSuccess();
    state.setLeadershipHeld(true);

    const handlers = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
    });

    const before = await handlers.readiness();
    expect(before.statusCode).toBe(200);

    // Simulate lock loss (connection drop / failover).
    state.setLeadershipHeld(false);
    const after = await handlers.readiness();
    expect(after.statusCode).toBe(200);
    const body = after.body as { checks: Array<{ name: string; ready: boolean }> };
    expect(body.checks.find((c) => c.name === "signer_leadership")?.ready).toBe(false);

    // Liveness never flaps.
    expect(handlers.liveness().statusCode).toBe(200);
  });

  it("does not leak sensitive fields", async () => {
    const result = await readinessHttp({
      version: VERSION,
      getState: () => baseState(),
      pingDb: async () => {
        throw new Error("password=supersecret host=db.internal");
      },
      now,
    });
    const json = JSON.stringify(result.body);
    expect(json).not.toMatch(/password|supersecret|db\.internal|ECONN|stack/i);
    expect(json).not.toMatch(/wallet|private_key|credential/i);
  });
});

describe("acquireLeadershipWithBackoff — non-blocking overlap pattern", () => {
  it("returns the handle once tryAcquire succeeds", async () => {
    let attempts = 0;
    const sleeps: number[] = [];
    const handle = { id: "A" };
    const result = await acquireLeadershipWithBackoff({
      tryAcquire: async () => {
        attempts += 1;
        return attempts >= 3 ? handle : null;
      },
      sleep: async (ms) => {
        sleeps.push(ms);
      },
      random: () => 0.5,
      baseDelayMs: 100,
      maxDelayMs: 400,
    });
    expect(result).toBe(handle);
    expect(attempts).toBe(3);
    expect(sleeps.length).toBe(2);
  });

  it("aborts without assuming leadership (overlap deploy / SIGTERM)", async () => {
    const signal = { aborted: false };
    let attempts = 0;
    const p = acquireLeadershipWithBackoff({
      tryAcquire: async () => {
        attempts += 1;
        if (attempts >= 2) signal.aborted = true;
        return null;
      },
      signal,
      sleep: async () => {},
      random: () => 0,
      baseDelayMs: 10,
      maxDelayMs: 10,
    });
    const result = await p;
    expect(result).toBeNull();
    expect(attempts).toBeGreaterThanOrEqual(2);
  });

  it("retries transient tryAcquire errors and never silently assumes leadership", async () => {
    let attempts = 0;
    const errors: unknown[] = [];
    const handle = { id: "B" };
    const result = await acquireLeadershipWithBackoff({
      tryAcquire: async () => {
        attempts += 1;
        if (attempts < 3) throw new Error("transient");
        return handle;
      },
      onError: (err) => errors.push(err),
      sleep: async () => {},
      random: () => 0,
    });
    expect(result).toBe(handle);
    expect(errors).toHaveLength(2);
  });

  it("two waiters: only one wins; the other keeps waiting (no dual leadership)", async () => {
    let held: string | null = null;
    const tryAcquire = async (): Promise<{ owner: string } | null> => {
      if (held !== null) return null;
      held = "A";
      return { owner: "A" };
    };
    const a = await acquireLeadershipWithBackoff({
      tryAcquire,
      sleep: async () => {},
      random: () => 0,
    });
    const bAttempts: number[] = [];
    const signal = { aborted: false };
    const bPromise = acquireLeadershipWithBackoff({
      tryAcquire: async () => {
        bAttempts.push(1);
        if (bAttempts.length >= 3) signal.aborted = true;
        return held === null ? { owner: "B" } : null;
      },
      signal,
      sleep: async () => {},
      random: () => 0,
    });
    const b = await bPromise;
    expect(a).toEqual({ owner: "A" });
    expect(b).toBeNull();
    expect(held).toBe("A");
  });
});

describe("createNodeCore — readiness surface on runtime", () => {
  it("exposes readiness stamps alongside database and gateway", () => {
    const response: GatewayResponse = {
      statusCode: 200,
      bodyBytes: Uint8Array.from([1]),
    };
    const gateway: GatewayConfiguration = {
      gatewayUrls: "https://gateway-a.invalid/rpc",
      readTransport: createOfflineReadTransport(createGatewayReadCredentials(), [response]),
    };
    const runtime = createNodeCore({
      database: {
        connectionString: "opaque-test-connection",
        adapter: createOfflineDatabaseAdapter(),
      },
      gateway,
      readiness: { observationFailureBudget: 2 },
    });
    expect(runtime.readiness).toBeInstanceOf(NodeCoreReadinessState);
    runtime.readiness.markSchemaMigrated();
    runtime.readiness.setVaultAvailable(true);
    expect(runtime.readiness.snapshot().schemaMigrated).toBe(true);
    expect(runtime.readiness.snapshot().vaultKeyRingLoaded).toBe(true);
  });
});
