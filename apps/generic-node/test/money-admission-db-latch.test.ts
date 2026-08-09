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
/** Mirrors main.ts's DB_PROBE_KEEP_WARM_MS = DEFAULT_DB_PING_TTL_MS / 2. */
const KEEP_WARM_MS = TTL_MS / 2;

/**
 * The production composition, assembled the way main.ts assembles it: one probe over a
 * caller-controlled ping, read synchronously by the admission port. Every stamped
 * conjunct is open, so a refusal can only come from the database one.
 *
 * `pingCostMs` charges the virtual clock for the round trip. It defaults to 0 for the
 * cases that only care about the verdict, but a real ping is never free, and δ = 0 is the
 * single degenerate case where the staleness window this suite has to police vanishes —
 * the keep-warm drill below therefore passes a non-zero cost.
 */
function harness(opts: { pingCostMs?: number } = {}) {
  const pingCostMs = opts.pingCostMs ?? 0;
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
      nowMs += pingCostMs;
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
    now: () => nowMs,
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

  it("the boot arm re-pings after a failed keep-warm tick inside the TTL", async () => {
    // The keep-warm timer starts at boot, before assertPostMigrationReadiness runs, so one
    // failed tick during boot plants a `false`. A TTL-cached probe() arm would be served
    // that failure straight back with no re-ping and crash a boot whose pool
    // assertSchemaCompleteness and assertPrivilegeReadiness had both just passed — turning
    // a self-healing blip into a crash loop. The arm has to be a real ping.
    const h = harness();

    h.setDbUp(false);
    h.advance(2_500);
    await h.probe.refresh(); // the blip: one failed keep-warm tick
    expect(h.pings.length).toBe(1);

    h.setDbUp(true);
    h.advance(500); // still well inside the TTL — probe() would answer `false` from cache
    expect(await h.probe.refresh()).toBe(true);
    expect(h.pings.length).toBe(2);
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

  it("stays admitted across keep-warm cycles while the database is up", async () => {
    // The converse of "a stale verdict reads closed", and the case the first cut of this
    // ticket got wrong: fail-closed on staleness is only safe if something actually keeps
    // the verdict fresh. Driving the timer through probe() cannot — probe() short-circuits
    // on its own cache and leaves cachedAtMs where it was, so every tick before expiry is
    // swallowed and the first tick that re-pings is, by construction, one that lands after
    // the verdict already read closed. No cadence fixes that; only re-dating does. Charge
    // the clock for the ping (δ > 0): a free ping is the one degenerate case where the
    // window closes on its own and the bug hides.
    const PING_COST_MS = 120;
    const SAMPLE_MS = 50;
    // main.ts starts the keep-warm timer at boot (before migrations) and arms the probe
    // later, from assertPostMigrationReadiness. The tick schedule is therefore NOT phase
    // locked to the arm — modelling it as if it were is what makes an expiry land exactly
    // on a tick and hides the window.
    const ARM_AT_MS = 300;
    const h = harness({ pingCostMs: PING_COST_MS });

    let nextTickAt = KEEP_WARM_MS;
    h.advance(ARM_AT_MS);
    await h.probe.refresh(); // the boot arm

    const refusedAt: number[] = [];
    const until = KEEP_WARM_MS * 4; // four cadences ≫ the three cycles asked for

    while (h.now() < until) {
      if (h.now() >= nextTickAt) {
        await h.probe.refresh(); // the keep-warm tick, charged PING_COST_MS
        nextTickAt += KEEP_WARM_MS;
      }
      if (refusalCode(() => h.ports.assertMoneyAdmitted()) !== null) refusedAt.push(h.now());
      h.advance(SAMPLE_MS);
    }

    // A healthy database must never refuse a money operation. Not once, at any sample.
    expect(refusedAt).toEqual([]);
    // …and the cadence really did re-ping, rather than passing by never being consulted.
    expect(h.pings.length).toBeGreaterThanOrEqual(4);
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

  it("the keep-warm timer calls refresh(), not probe()", () => {
    // The behavioural drill above proves refresh() holds the verdict open on a healthy
    // node; this pins that main.ts is the thing calling it. A probe() timer type-checks,
    // reads correctly, and silently reinstates the ~32%-refusal window — nothing but this
    // assertion notices the one-word difference.
    expect(mainSrc).toContain("const DB_PROBE_KEEP_WARM_MS = DEFAULT_DB_PING_TTL_MS / 2");
    expect(mainSrc).toMatch(
      /setInterval\([\s\S]{0,400}?dbProbe\.refresh\(\)[\s\S]{0,200}?DB_PROBE_KEEP_WARM_MS/,
    );
  });

  it("the post-migration arm is a real ping, not a cached verdict", () => {
    // The keep-warm timer starts before assertPostMigrationReadiness runs, so one failed
    // tick during boot would otherwise be replayed from cache here and crash a boot whose
    // pool assertSchemaCompleteness and assertPrivilegeReadiness both just passed.
    const arm = mainSrc.slice(
      mainSrc.indexOf("assertPostMigrationReadiness:"),
      mainSrc.indexOf("boot: database probe failed after migrations"),
    );
    expect(arm).toContain("await dbProbe.refresh()");
    expect(arm).not.toContain("await dbProbe.probe()");
  });
});
