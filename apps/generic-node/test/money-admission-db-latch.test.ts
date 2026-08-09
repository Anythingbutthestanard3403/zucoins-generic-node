// Regression guard: ZTR-1178. The money-path database conjunct used to be a shell-local
// `let databaseReachableForMoney` in main.ts, assigned `true` after the ping's await and
// never assigned `false` anywhere. After the first successful ping it was permanently
// satisfied, so a failover / connection storm / partition was invisible to admission —
// work was admitted and then died a layer deeper as a raw driver error instead of a named
// MoneyAdmissionRefusedError. /health/ready reacted correctly the whole time, because
// CachedDbProbe owns its own state; only the money flag was stuck.
//
// The fix reads that same probe, so this suite is the pair the ticket asks for:
//   * a source census over main.ts's wiring — the latch is gone and isDatabaseReachable
//     reads the shared probe, neither of which tsc or any behavioural test would notice;
//   * a behavioural drill over the real composition (CachedDbProbe +
//     createMoneyPathAdmissionPortsFromRuntime) proving admission flips allowed → refused
//     when the database goes away, and back, inside one process.
//
// Governing: packages/node-core/src/core/readiness-state.ts:5 — database_reachable is
// deliberately NOT a stamped input, it is live-probed, "because a stamp cannot represent a
// condition that changes". The deleted latch was exactly such a stamp.
//
// Ceiling: this file does not run main() and does not touch a real pool. It pins the
// wiring expression and the semantics of what that expression reads.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  CachedDbProbe,
  createMoneyPathAdmissionPortsFromRuntime,
  createStorageBackpressure,
  MoneyAdmissionRefusedError,
  NodeCoreReadinessState,
} from "@zucoins/node-core";

const here = dirname(fileURLToPath(import.meta.url));
const mainSrc = readFileSync(join(here, "../src/main.ts"), "utf8");

const TTL_MS = 5_000;

/**
 * The production composition, assembled the way main.ts assembles it: one probe over a
 * caller-controlled ping, read synchronously by the admission port. Every stamped
 * conjunct is open, so a refusal can only come from the database one.
 */
function harness() {
  let dbUp = true;
  let nowMs = 0;
  const pings: number[] = [];
  const readiness = new NodeCoreReadinessState({ observationFailureBudget: 3 });
  readiness.markSchemaMigrated();
  readiness.setVaultAvailable(true);
  readiness.recordObservationReadSuccess();
  const probe = new CachedDbProbe(
    async () => {
      pings.push(nowMs);
      if (!dbUp) throw new Error("connection terminated unexpectedly");
    },
    TTL_MS,
    () => nowMs,
  );
  const ports = createMoneyPathAdmissionPortsFromRuntime({
    snapshotReadiness: () => readiness.snapshot(),
    isDatabaseReachable: () => probe.cachedReachable(),
    backpressure: createStorageBackpressure(),
  });
  return {
    ports,
    probe,
    pings,
    advance: (ms: number) => {
      nowMs += ms;
    },
    setDbUp: (up: boolean) => {
      dbUp = up;
    },
  };
}

function refusalCode(run: () => void): string | null {
  try {
    run();
    return null;
  } catch (err) {
    if (err instanceof MoneyAdmissionRefusedError) return err.code;
    throw err;
  }
}

describe("money-admission database conjunct (ZTR-1178)", () => {
  it("refuses before anything has probed — no boot-time free pass", () => {
    const { ports } = harness();
    expect(refusalCode(() => ports.assertMoneyAdmitted())).toBe("database_unreachable");
  });

  it("admits after a successful probe, then re-closes when the database goes away", async () => {
    const h = harness();

    expect(await h.probe.probe()).toBe(true);
    expect(refusalCode(() => h.ports.assertMoneyAdmitted())).toBeNull();

    // The database goes away. No restart, no re-wiring — the next probe of the SAME
    // instance records the failure and admission must follow it down.
    h.setDbUp(false);
    h.advance(TTL_MS);
    expect(await h.probe.probe()).toBe(false);

    expect(refusalCode(() => h.ports.assertMoneyAdmitted())).toBe("database_unreachable");
  });

  it("re-opens once the database comes back, in the same process", async () => {
    const h = harness();
    await h.probe.probe();
    h.setDbUp(false);
    h.advance(TTL_MS);
    await h.probe.probe();
    expect(refusalCode(() => h.ports.assertMoneyAdmitted())).toBe("database_unreachable");

    h.setDbUp(true);
    h.advance(TTL_MS);
    expect(await h.probe.probe()).toBe(true);
    expect(refusalCode(() => h.ports.assertMoneyAdmitted())).toBeNull();
  });

  it("a verdict older than one probe TTL reads closed, not stale-open", async () => {
    const h = harness();
    await h.probe.probe();
    h.advance(TTL_MS - 1);
    expect(refusalCode(() => h.ports.assertMoneyAdmitted())).toBeNull();

    h.advance(1);
    expect(refusalCode(() => h.ports.assertMoneyAdmitted())).toBe("database_unreachable");
  });

  it("admission issues no database round-trip of its own", async () => {
    const h = harness();
    await h.probe.probe();
    expect(h.pings.length).toBe(1);

    for (let i = 0; i < 50; i += 1) h.ports.assertMoneyAdmitted();
    // Fifty admissions, still one ping: the money path reads a cached boolean and never
    // pings inline. Tightening this to a live probe would put a query — and, with no
    // statement_timeout on the pool, a stall — on every SERIALIZABLE money transaction.
    expect(h.pings.length).toBe(1);
  });
});

describe("main.ts wiring census (ZTR-1178)", () => {
  it("the shell latch is gone — no second copy of DB reachability survives", () => {
    expect(mainSrc).not.toContain("databaseReachableForMoney");
    // A `let` assigned true after an await is the shape that latched; nothing in main.ts
    // may reintroduce one under a different name.
    expect(mainSrc).not.toMatch(/let\s+\w*[Rr]eachable\w*\s*(:|=)/);
  });

  it("money admission is wired to the same probe /health/ready reads", () => {
    const call = mainSrc.slice(
      mainSrc.indexOf("createMoneyPathAdmissionPortsFromRuntime({"),
      mainSrc.indexOf("createMoneyPathAdmissionPortsFromRuntime({") + 2000,
    );
    expect(call).toContain("isDatabaseReachable: () => dbProbe.cachedReachable()");
    // …and that probe is the one handed to the runtime listener (health + metrics), not a
    // second instance constructed for money.
    expect(mainSrc.match(/new CachedDbProbe\(/g)?.length).toBe(1);
    expect(mainSrc).toContain("dbProbe,");
  });

  it("the probe is refreshed on a cadence inside its own TTL", () => {
    // Without this the money workers — which consult neither /health/ready nor /metrics —
    // would read a verdict nobody refreshes, and stale-closed would wedge the money path
    // on a perfectly healthy node.
    expect(mainSrc).toContain("const DB_PROBE_KEEP_WARM_MS = DEFAULT_DB_PING_TTL_MS / 2");
    expect(mainSrc).toMatch(/setInterval\([\s\S]{0,400}?dbProbe\.probe\(\)[\s\S]{0,200}?DB_PROBE_KEEP_WARM_MS/);
  });
});
