// deployment-health fault-injection suite.
//
// Exercises the real/ discovery + liveness + readiness handlers
// through the full fault matrix:
//
//   1. Boot            — readiness false through every pre-ready stamp; liveness true
//   2. DB down         — 503 without throw; CachedDbProbe TTL neither masks forever
//                        nor hammers a down DB inside the window
//   3. Gateway degraded— status "degraded" vs plain "not_ready" after budget breach
//   4. Signer waiting/lost — NON-gating (explicit cross-check)
//   5. Halted / storage pressure — reported-only; the spec is silent on gating
//   6. Overlap deploy  — two instances; both bind liveness; readiness without leadership
//   7. Proxy/static route order — health/discovery matched before catch-all (v1 regression)
//
// Plus: no credentials / wallets / tenants / secrets leak under any fault condition.
//

import { describe, expect, it } from "vitest";

import {
  buildNodeIdentityDocument,
  createHealthHandlers,
  CachedDbProbe,
  DEFAULT_DB_PING_TTL_MS,
  GATING_READINESS_CHECK_IDS,
  REPORTED_READINESS_CHECK_IDS,
  type DiscoveryConfig,
  type HealthHttpResult,
  type ReadinessResponse,
} from "../src/api/index.js";
import { NodeCoreReadinessState } from "../src/core/readiness-state.js";
import { acquireLeadershipWithBackoff } from "../src/core/leadership-acquire.js";

const FIXED_TIME = "2026-07-26T12:00:00.000Z";
const VERSION = "0.0.0-fixture";
const now = () => FIXED_TIME;

const LEAK_PATTERN =
  /password|supersecret|private_key|credential|wallet_|tenant_|connectionString|DATABASE_URL|ECONNREFUSED|stack|db\.internal|postgresql:\/\//i;

function fullyStamped(state: NodeCoreReadinessState, leadership = true): void {
  state.markSchemaMigrated();
  state.setVaultAvailable(true);
  state.recordObservationReadSuccess();
  state.setLeadershipHeld(leadership);
}

function assertNoLeak(result: HealthHttpResult): void {
  const json = JSON.stringify(result.body);
  expect(json).not.toMatch(LEAK_PATTERN);
  if ("checks" in result.body) {
    for (const check of (result.body as ReadinessResponse).checks) {
      expect(Object.keys(check).sort()).toEqual(["gating", "name", "ready"]);
    }
  }
}

function discoveryConfig(): DiscoveryConfig {
  return {
    nodeId: "0192e3a4-b5c6-7d8e-9f0a-1b2c3d4e5f6a",
    apiVersion: "v1",
    supportedOperations: ["RECEIVE_EXTERNAL", "MOVE_INTERNAL", "SEND_EXTERNAL"],
    canonicalSuites: [
      "zp-receive-expected-v1",
      "zp-move-internal-expected-v1",
      "zp-send-external-expected-v1",
      "zp-node-event-v1",
    ],
    eventSigningKeys: [
      {
        keyId: "0192e3a4-b5c6-7d8e-9f0a-1b2c3d4e5f6a",
        publicKey: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
        validFrom: FIXED_TIME,
        validUntil: null,
      },
    ],
    artifactSigningKeys: [],
  };
}

describe("fault matrix 1 — boot sequence", () => {
  it("readiness stays not_ready through every pre-ready stamp; liveness is true from the first probe", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    let dbOk = false;
    const handlers = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {
        if (!dbOk) throw new Error("password=supersecret host=db.internal ECONNREFUSED");
      },
      now,
    });

    expect(handlers.liveness().statusCode).toBe(200);
    expect(handlers.liveness().body).toMatchObject({ status: "alive", version: VERSION });
    let ready = await handlers.readiness();
    expect(ready.statusCode).toBe(503);
    expect(ready.body).toMatchObject({ status: "not_ready" });
    assertNoLeak(ready);

    state.markSchemaMigrated();
    ready = await handlers.readiness();
    expect(ready.statusCode).toBe(503);
    expect((ready.body as ReadinessResponse).checks.find((c) => c.name === "schema_migrated")?.ready).toBe(
      true,
    );

    state.setVaultAvailable(true);
    ready = await handlers.readiness();
    expect(ready.statusCode).toBe(503);

    state.setLeadershipHeld(true);
    ready = await handlers.readiness();
    expect(ready.statusCode).toBe(503);
    expect(
      (ready.body as ReadinessResponse).checks.find((c) => c.name === "signer_leadership"),
    ).toMatchObject({ ready: true, gating: false });

    state.recordObservationReadSuccess();
    ready = await handlers.readiness();
    expect(ready.statusCode).toBe(503);
    expect(
      (ready.body as ReadinessResponse).checks.find((c) => c.name === "database_reachable")?.ready,
    ).toBe(false);

    expect(handlers.liveness().statusCode).toBe(200);
    dbOk = true;
    handlers.dbProbe.invalidate();
    ready = await handlers.readiness();
    expect(ready.statusCode).toBe(200);
    expect(ready.body).toMatchObject({ status: "ready" });
    const gating = (ready.body as ReadinessResponse).checks.filter((c) => c.gating);
    expect(gating.every((c) => c.ready)).toBe(true);
    assertNoLeak(ready);
  });

  it("negative: leaving any single gating stamp closed keeps readiness 503", async () => {
    for (const closed of GATING_READINESS_CHECK_IDS) {
      if (closed === "schema_migrated") {
        const s = new NodeCoreReadinessState({ observationFailureBudget: 3 });
        s.setVaultAvailable(true);
        s.recordObservationReadSuccess();
        s.setLeadershipHeld(true);
        const h = createHealthHandlers({
          version: VERSION,
          getState: () => s.snapshot(),
          pingDb: async () => {},
          now,
        });
        const r = await h.readiness();
        expect(r.statusCode).toBe(503);
        expect((r.body as ReadinessResponse).checks.find((c) => c.name === closed)?.ready).toBe(false);
        continue;
      }
      if (closed === "observation_read_capable") {
        const s = new NodeCoreReadinessState({ observationFailureBudget: 3 });
        s.markSchemaMigrated();
        s.setVaultAvailable(true);
        s.setLeadershipHeld(true);
        const h = createHealthHandlers({
          version: VERSION,
          getState: () => s.snapshot(),
          pingDb: async () => {},
          now,
        });
        const r = await h.readiness();
        expect(r.statusCode).toBe(503);
        expect((r.body as ReadinessResponse).checks.find((c) => c.name === closed)?.ready).toBe(false);
        continue;
      }

      const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
      fullyStamped(state, true);
      let dbOk = true;
      if (closed === "vault_available") state.setVaultAvailable(false);
      if (closed === "database_reachable") dbOk = false;
      const h = createHealthHandlers({
        version: VERSION,
        getState: () => state.snapshot(),
        pingDb: async () => {
          if (!dbOk) throw new Error("db down");
        },
        now,
      });
      const r = await h.readiness();
      expect(r.statusCode).toBe(503);
      expect((r.body as ReadinessResponse).checks.find((c) => c.name === closed)?.ready).toBe(false);
    }
  });
});

describe("fault matrix 2 — DB down (CachedDbProbe TTL)", () => {
  it("DB failure yields 503 readiness signal, never a thrown request", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    fullyStamped(state);
    const handlers = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {
        throw new Error("password=supersecret host=db.internal ECONNREFUSED");
      },
      now,
    });
    const result = await handlers.readiness();
    expect(result.statusCode).toBe(503);
    expect(result.body).toMatchObject({ status: "not_ready" });
    assertNoLeak(result);
    expect(handlers.liveness().statusCode).toBe(200);
  });

  it("TTL caches a down result so a flood does not re-probe inside the window, then re-probes after", async () => {
    let calls = 0;
    let t = 0;
    let shouldFail = true;
    const probe = new CachedDbProbe(
      async () => {
        calls += 1;
        if (shouldFail) throw new Error("db down");
      },
      DEFAULT_DB_PING_TTL_MS,
      () => t,
    );
    expect(DEFAULT_DB_PING_TTL_MS).toBe(5_000);

    expect(await probe.probe()).toBe(false);
    expect(calls).toBe(1);
    t = DEFAULT_DB_PING_TTL_MS - 1;
    expect(await probe.probe()).toBe(false);
    expect(calls).toBe(1);

    t = DEFAULT_DB_PING_TTL_MS;
    expect(await probe.probe()).toBe(false);
    expect(calls).toBe(2);

    shouldFail = false;
    t = DEFAULT_DB_PING_TTL_MS * 2;
    expect(await probe.probe()).toBe(true);
    expect(calls).toBe(3);
  });

  it("negative: a successful cache does not outlive the TTL after the DB dies", async () => {
    let calls = 0;
    let t = 0;
    let shouldFail = false;
    const probe = new CachedDbProbe(
      async () => {
        calls += 1;
        if (shouldFail) throw new Error("db down");
      },
      1_000,
      () => t,
    );
    expect(await probe.probe()).toBe(true);
    shouldFail = true;
    t = 500;
    expect(await probe.probe()).toBe(true);
    expect(calls).toBe(1);
    t = 1_000;
    expect(await probe.probe()).toBe(false);
    expect(calls).toBe(2);
  });
});

describe("fault matrix 3 — gateway degraded", () => {
  it("distinguishes degraded (budget exceeded after success) from plain not_ready (never observed)", async () => {
    const neverObserved = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    neverObserved.markSchemaMigrated();
    neverObserved.setVaultAvailable(true);
    neverObserved.setLeadershipHeld(true);
    const h1 = createHealthHandlers({
      version: VERSION,
      getState: () => neverObserved.snapshot(),
      pingDb: async () => {},
      now,
    });
    const pre = await h1.readiness();
    expect(pre.statusCode).toBe(503);
    expect(pre.body).toMatchObject({ status: "not_ready" });
    assertNoLeak(pre);

    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    fullyStamped(state, true);
    const h2 = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
    });
    expect((await h2.readiness()).statusCode).toBe(200);

    state.recordObservationReadFailure();
    state.recordObservationReadFailure();
    expect((await h2.readiness()).statusCode).toBe(200);

    state.recordObservationReadFailure();
    const degraded = await h2.readiness();
    expect(degraded.statusCode).toBe(503);
    expect(degraded.body).toMatchObject({ status: "degraded" });
    expect(
      (degraded.body as ReadinessResponse).checks.find((c) => c.name === "observation_read_capable"),
    ).toMatchObject({ ready: false, gating: true });
    assertNoLeak(degraded);
  });

  it("negative: success after degradation re-opens the observation gate", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 2 });
    fullyStamped(state, true);
    const h = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
    });
    state.recordObservationReadFailure();
    state.recordObservationReadFailure();
    expect((await h.readiness()).body).toMatchObject({ status: "degraded" });

    state.recordObservationReadSuccess();
    const recovered = await h.readiness();
    expect(recovered.statusCode).toBe(200);
    expect(recovered.body).toMatchObject({ status: "ready" });
  });
});

describe("fault matrix 4 — signer waiting/lost (non-gating)", () => {
  /**
   * CROSS-CHECK — resolution (Done):
   * An earlier draft gated readiness on signer
   * leadership. The canonical policy supersedes that: signer_leadership is reported
   * but NON-gating so a Railway overlap deploy cannot deadlock. This suite
   * asserts the canonical (non-gating) policy, not the superseded draft.
   */
  it("lock loss flips signer_leadership ready=false but keeps top-level ready=200", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    fullyStamped(state, true);
    const handlers = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
    });

    const before = await handlers.readiness();
    expect(before.statusCode).toBe(200);
    expect(
      (before.body as ReadinessResponse).checks.find((c) => c.name === "signer_leadership"),
    ).toMatchObject({ ready: true, gating: false });

    state.setLeadershipHeld(false);
    const after = await handlers.readiness();
    expect(after.statusCode).toBe(200);
    expect(after.body).toMatchObject({ status: "ready" });
    expect(
      (after.body as ReadinessResponse).checks.find((c) => c.name === "signer_leadership"),
    ).toMatchObject({ ready: false, gating: false });
    expect(handlers.liveness().statusCode).toBe(200);
    assertNoLeak(after);
  });

  it("waiting for leadership (boot overlap) still reports ready once gating stamps pass", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    fullyStamped(state, /* leadership */ false);
    const handlers = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
    });
    const result = await handlers.readiness();
    expect(result.statusCode).toBe(200);
    expect(
      (result.body as ReadinessResponse).checks.find((c) => c.name === "signer_leadership"),
    ).toMatchObject({ ready: false, gating: false });
  });

  it("negative: leadership alone never rescues a DB-down 503", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    fullyStamped(state, true);
    const handlers = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {
        throw new Error("db down");
      },
      now,
    });
    const result = await handlers.readiness();
    expect(result.statusCode).toBe(503);
    expect(
      (result.body as ReadinessResponse).checks.find((c) => c.name === "signer_leadership")?.ready,
    ).toBe(true);
    expect(
      (result.body as ReadinessResponse).checks.find((c) => c.name === "database_reachable")?.ready,
    ).toBe(false);
  });
});

describe("fault matrix 5 — halt / storage pressure (spec silent → reported non-gating)", () => {
  /**
   * SPEC GAP (the implementation makes the call):
   * Neither node-core rules nor the recovery rules names halt or
   * storage_pressure as readiness gates. src/http/health.ts therefore reports
   * them as non-gating detail (same posture as signer_leadership under the non-gating leadership policy).
   * The frozen HALT_ADMIN_ROUTES surface remains orthogonal to readiness.
   * This test freezes that judgment so a future re-gating is an intentional change.
   */
  it("halted + storage pressure keep top-level ready; checks report ready=false, gating=false", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    fullyStamped(state, true);
    state.setHalted(true);
    state.setStoragePressure(true);
    const handlers = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
    });
    const result = await handlers.readiness();
    expect(result.statusCode).toBe(200);
    expect(result.body).toMatchObject({ status: "ready" });
    const body = result.body as ReadinessResponse;
    expect(body.checks.find((c) => c.name === "halt")).toMatchObject({
      ready: false,
      gating: false,
    });
    expect(body.checks.find((c) => c.name === "storage_pressure")).toMatchObject({
      ready: false,
      gating: false,
    });
    assertNoLeak(result);
  });

  it("negative: halt does not open a closed gating check", async () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    state.setVaultAvailable(true);
    state.recordObservationReadSuccess();
    state.setHalted(false);
    const handlers = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
    });
    const result = await handlers.readiness();
    expect(result.statusCode).toBe(503);
  });
});

describe("fault matrix 6 — overlap deploy (two instances)", () => {
  it("old and new instances both serve liveness; new is ready without leadership; only one holds the lock", async () => {
    let heldBy: "old" | "new" | null = null;

    const oldState = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    fullyStamped(oldState, true);
    heldBy = "old";
    const oldHandlers = createHealthHandlers({
      version: "1.0.0-old",
      getState: () => {
        oldState.setLeadershipHeld(heldBy === "old");
        return oldState.snapshot();
      },
      pingDb: async () => {},
      now,
    });

    const newState = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    fullyStamped(newState, false);
    const newHandlers = createHealthHandlers({
      version: "1.0.1-new",
      getState: () => {
        newState.setLeadershipHeld(heldBy === "new");
        return newState.snapshot();
      },
      pingDb: async () => {},
      now,
    });

    expect(oldHandlers.liveness().statusCode).toBe(200);
    expect(newHandlers.liveness().statusCode).toBe(200);
    expect((await oldHandlers.readiness()).statusCode).toBe(200);
    const newReady = await newHandlers.readiness();
    expect(newReady.statusCode).toBe(200);
    expect(
      (newReady.body as ReadinessResponse).checks.find((c) => c.name === "signer_leadership"),
    ).toMatchObject({ ready: false, gating: false });

    const signal = { aborted: false };
    let newAttempts = 0;
    const waitPromise = acquireLeadershipWithBackoff({
      tryAcquire: async () => {
        newAttempts += 1;
        if (heldBy !== null) return null;
        heldBy = "new";
        return { owner: "new" as const };
      },
      signal,
      sleep: async () => {},
      random: () => 0,
      baseDelayMs: 1,
      maxDelayMs: 1,
    });

    expect(heldBy).toBe("old");
    expect((await oldHandlers.readiness()).statusCode).toBe(200);
    heldBy = null;
    oldState.setLeadershipHeld(false);

    const acquired = await waitPromise;
    expect(acquired).toEqual({ owner: "new" });
    expect(heldBy).toBe("new");
    expect(newAttempts).toBeGreaterThanOrEqual(1);

    expect((await newHandlers.readiness()).statusCode).toBe(200);
    expect(
      ((await newHandlers.readiness()).body as ReadinessResponse).checks.find(
        (c) => c.name === "signer_leadership",
      )?.ready,
    ).toBe(true);
    expect(
      ((await oldHandlers.readiness()).body as ReadinessResponse).checks.find(
        (c) => c.name === "signer_leadership",
      )?.ready,
    ).toBe(false);
    assertNoLeak(await newHandlers.readiness());
  });

  it("negative: abort during wait never silently assumes leadership", async () => {
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
      baseDelayMs: 1,
      maxDelayMs: 1,
    });
    expect(await p).toBeNull();
    expect(attempts).toBeGreaterThanOrEqual(2);
  });
});

describe("fault matrix 7 — proxy/static-route ordering (v1 catch-all regression)", () => {
  type RouteResult = { status: number; body: unknown; via: string };

  function buildDispatcher(order: "health-first" | "catch-all-first") {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    fullyStamped(state, true);
    const handlers = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {},
      now,
    });
    const discovery = buildNodeIdentityDocument(discoveryConfig());

    const healthRoutes = async (method: string, path: string): Promise<RouteResult | null> => {
      if (method === "GET" && path === "/health") {
        const r = handlers.liveness();
        return { status: r.statusCode, body: r.body, via: "health" };
      }
      if (method === "GET" && path === "/health/ready") {
        const r = await handlers.readiness();
        return { status: r.statusCode, body: r.body, via: "health" };
      }
      if (method === "GET" && path === "/.well-known/zupay-node") {
        return { status: 200, body: discovery, via: "discovery" };
      }
      return null;
    };

    const catchAll = (_method: string, _path: string): RouteResult => ({
      status: 200,
      body: "<!doctype html><title>spa</title>",
      via: "catch-all",
    });

    return async (method: string, path: string): Promise<RouteResult> => {
      if (order === "health-first") {
        return (await healthRoutes(method, path)) ?? catchAll(method, path);
      }
      return catchAll(method, path);
    };
  }

  it("health-first order serves liveness, readiness, and discovery as JSON (not SPA HTML)", async () => {
    const dispatch = buildDispatcher("health-first");
    for (const path of ["/health", "/health/ready", "/.well-known/zupay-node"] as const) {
      const res = await dispatch("GET", path);
      expect(res.via).not.toBe("catch-all");
      expect(typeof res.body).toBe("object");
      expect(JSON.stringify(res.body)).not.toContain("<!doctype html>");
      expect(JSON.stringify(res.body)).not.toMatch(LEAK_PATTERN);
    }
    expect((await dispatch("GET", "/health")).body).toMatchObject({ status: "alive" });
    expect((await dispatch("GET", "/health/ready")).status).toBe(200);
    expect((await dispatch("GET", "/.well-known/zupay-node")).body).toMatchObject({
      api_version: "v1",
    });
    expect((await dispatch("GET", "/admin")).via).toBe("catch-all");
  });

  it("negative: catch-all-first would reintroduce the v1 ordering bug (this test fails if inverted)", async () => {
    const dispatch = buildDispatcher("catch-all-first");
    for (const path of ["/health", "/health/ready", "/.well-known/zupay-node"] as const) {
      const res = await dispatch("GET", path);
      expect(res.via).toBe("catch-all");
      expect(res.body).toContain("<!doctype html>");
    }
  });
});

describe("cross-cutting — no sensitive leak under any fault condition", () => {
  it("reported check id set is exactly the frozen list (no surprise fields)", () => {
    expect([...REPORTED_READINESS_CHECK_IDS]).toEqual([
      "schema_migrated",
      "database_reachable",
      "vault_available",
      "observation_read_capable",
      "signer_leadership",
      "halt",
      "storage_pressure",
    ]);
    expect([...GATING_READINESS_CHECK_IDS]).toEqual([
      "schema_migrated",
      "database_reachable",
      "vault_available",
      "observation_read_capable",
    ]);
  });

  it("discovery document never embeds private configuration", () => {
    const doc = buildNodeIdentityDocument(discoveryConfig());
    const json = JSON.stringify(doc);
    expect(json).not.toMatch(LEAK_PATTERN);
    expect(json).not.toContain("private");
    expect(Object.keys(doc).sort()).toEqual([
      "api_version",
      "canonical_suite_versions",
      "event_signing_public_keys",
      "expected_artifact_public_keys",
      "key_validity_intervals",
      "node_id",
      "supported_operation_types",
    ]);
  });

  it("liveness body is exactly {status, version, timestamp}", () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 1 });
    const handlers = createHealthHandlers({
      version: VERSION,
      getState: () => state.snapshot(),
      pingDb: async () => {
        throw new Error("password=supersecret");
      },
      now,
    });
    const live = handlers.liveness();
    expect(Object.keys(live.body).sort()).toEqual(["status", "timestamp", "version"]);
    assertNoLeak(live);
  });
});
