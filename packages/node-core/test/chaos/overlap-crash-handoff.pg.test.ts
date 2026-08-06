// Prove graceful overlap and crash handoff.
//
// This suite is the proof artifact for leadership acquisition and
// (deterministic boot recovery). "Exactly one signer leader is active" is a concurrency property: it cannot be established by
// inspection, and a single-threaded field comparison cannot fail, so it would be
// unfalsifiable in memory. Every exclusion assertion below is decided by a REAL PostgreSQL
// session advisory lock across two dedicated connections.
//
// Under test: the boot-recovery procedure, the per-phase recovery tables the crash cases
// assert against, and the obligation that a crash at every durable phase boundary produces
// neither two submit calls for one attempt nor two distinct external partials for one
// operation. Also one active lease per wallet, and one process-wide signer leadership lock
// with its readiness contract.
//
// Checklist coverage:
//   1 two instances / one PostgreSQL ....... "two instances contend"
//   2 A leads, B non-leader, B health binds  "overlap deploy"
//   3 SIGTERM A mid-operation ............... "graceful drain"
//   4 lock connection dropped, no SIGTERM ... "database failover"
//   5 crash at every durable phase boundary . "crash matrix"
//   6 one lease per wallet / one submit ..... asserted in every block + "invariants"
//
// Connectivity: TEST_DATABASE_URL is provisioned by vitest.global-setup.ts under the ROOT
// vitest project. Under PG_REQUIRED=1 an unreachable PostgreSQL is a hard failure, never a
// silent skip.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { NotSignerLeaderError } from "../../src/core/signer-boundary.ts";
import type {
  BootRecoveryClassification,
  OperationKind,
} from "../../src/workers/boot-recovery.ts";
import {
  advisoryLockHolders,
  ageHeartbeat,
  armCrashHook,
  countRows,
  CRASH_HOOK,
  createChaosDatabase,
  disarmCrashHook,
  dropChaosDatabase,
  makeChaosSqlQuery,
  NodeInstance,
  psqlMust,
  runPsql,
  seedOperation,
  sqlstateOf,
  waitUntilHookReached,
  walletsWithDuplicateLeases,
  wipeFixtures,
  type SeedOperationOptions,
} from "./node-instance-harness.ts";
import {
  makeSubmitDecisionClaimStore,
  readSubmitAttemptEvidence,
} from "../../src/core/submit-decision-claim-store.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

const scratchDb = `overlap_crash_handoff_chaos_${Date.now()}_${process.pid}`;
let url = "";
let schemaReady = false;
/** Incremented by every live chaos drill that completed — PG_REQUIRED hard-gate. */
let drillsRun = 0;
const EXPECTED_MIN_DRILLS = 20;

// Advisory locks are database-scoped and TEST_DATABASE_URL may be a shared instance, so the
// lock id is per-run — a fixed id could interlock with a concurrent lane.
const LOCK_ID = 0x350000 + (process.pid % 0x00ffff);

/** Instances created by a test; disposed after it whether it passed or not. */
const live: NodeInstance[] = [];

function instance(name: string): NodeInstance {
  const node = new NodeInstance({ name, url, lockId: LOCK_ID });
  live.push(node);
  return node;
}

beforeAll(async () => {
  if (TEST_DATABASE_URL === "") return;
  url = await createChaosDatabase(TEST_DATABASE_URL, scratchDb);
  schemaReady = true;
}, 60_000);

afterAll(async () => {
  if (!schemaReady) return;
  await dropChaosDatabase(TEST_DATABASE_URL, scratchDb);
});

afterEach(async () => {
  while (live.length > 0) live.pop()?.dispose();
  if (schemaReady) await wipeFixtures(url);
});

/* ─── the durable phase boundaries ── */

interface PhaseCase {
  /** Spec row this case is the crash state of. */
  readonly id: string;
  readonly kind: OperationKind;
  readonly seed: Omit<SeedOperationOptions, "kind">;
  readonly classification: BootRecoveryClassification;
  /** `AuthorizedResumeAction["kind"]`, or null when recovery must resume nothing. */
  readonly resume: string | null;
}

const PHASE_CASES: readonly PhaseCase[] = [
  {
    id: "phase 3.1 receive — crash before wallet assignment (CREATED, no receiver, no lease)",
    kind: "RECEIVE_EXTERNAL",
    seed: { status: "CREATED", leased: false, queuedReceive: true },
    classification: "PROVEN_NOT_STARTED",
    resume: "RESUME_T0_AND_CODE_FORMATION",
  },
  {
    id: "phase 3.2 r1 receive — lease exists; no T0, code, artifact preimage, or signer audit",
    kind: "RECEIVE_EXTERNAL",
    seed: { status: "CREATED" },
    classification: "PROVEN_NOT_STARTED",
    resume: "RESUME_T0_AND_CODE_FORMATION",
  },
  {
    id: "phase 3.2 r2 / 3.4 PREIMAGE_PERSISTED receive — exact preimage persisted, signature absent",
    kind: "RECEIVE_EXTERNAL",
    seed: { status: "READY", formationComplete: true, exactPreimagePersisted: true },
    classification: "PROVEN_NOT_STARTED",
    resume: "SIGN_PERSISTED_STEP2_PREIMAGE",
  },
  {
    id: "phase 3.2 r4 receive — expected exact bytes missing while a signer audit indicates use",
    kind: "RECEIVE_EXTERNAL",
    seed: { status: "READY", signerAuditIndicatesCall: true },
    classification: "INVARIANT_BREACH",
    resume: null,
  },
  {
    id: "phase 3.4 SIGNED_PERSISTED receive — signature persisted, no submit claim",
    kind: "RECEIVE_EXTERNAL",
    seed: {
      status: "READY",
      formationComplete: true,
      exactPreimagePersisted: true,
      signaturePersisted: true,
    },
    classification: "PROVEN_NOT_STARTED",
    resume: "SUBMIT_ONCE",
  },
  {
    id: "phase 3.4 submit-claim receive — submit claim recorded, response unknown",
    kind: "RECEIVE_EXTERNAL",
    seed: {
      status: "SUBMITTED",
      formationComplete: true,
      exactPreimagePersisted: true,
      signaturePersisted: true,
      submitBoundaryRecorded: true,
    },
    classification: "INDETERMINATE",
    resume: null,
  },
  {
    id: "phase 4.1 r2 move — both leases, no preimage / sign audit",
    kind: "MOVE_INTERNAL",
    seed: { status: "CREATED" },
    classification: "PROVEN_NOT_STARTED",
    resume: "FIRST_FORMATION",
  },
  {
    id: "phase 4.1 r3 move — exact preimage persisted, signature missing",
    kind: "MOVE_INTERNAL",
    seed: { status: "FORMED", exactPreimagePersisted: true },
    classification: "PROVEN_NOT_STARTED",
    resume: "SIGN_PERSISTED_PREIMAGE",
  },
  {
    id: "phase 4.1 r4 move — full exact transaction persisted, no submit claim",
    kind: "MOVE_INTERNAL",
    seed: { status: "SIGNED", exactPreimagePersisted: true, signaturePersisted: true },
    classification: "PROVEN_NOT_STARTED",
    resume: "SUBMIT_ONCE",
  },
  {
    id: "phase 4.1 r5 move — submit call may have occurred",
    kind: "MOVE_INTERNAL",
    seed: {
      status: "SUBMITTED",
      exactPreimagePersisted: true,
      signaturePersisted: true,
      submitBoundaryRecorded: true,
    },
    classification: "INDETERMINATE",
    resume: null,
  },
  {
    id: "phase 5.2 r1 send — APPROVED; no sign intent or signer audit",
    kind: "SEND_EXTERNAL",
    seed: { status: "APPROVED" },
    classification: "PROVEN_NOT_STARTED",
    resume: "FIRST_FORMATION",
  },
  {
    id: "phase 5.2 r3 send — exact sign intent persisted, signature absent",
    kind: "SEND_EXTERNAL",
    seed: { status: "APPROVED", exactPreimagePersisted: true },
    classification: "PROVEN_NOT_STARTED",
    resume: "SIGN_PERSISTED_PREIMAGE",
  },
  {
    id: "phase 5.2 r4 / 5.3 send — signature/partial persisted, awaiting redemption",
    kind: "SEND_EXTERNAL",
    seed: {
      status: "AWAITING_REDEMPTION",
      exactPreimagePersisted: true,
      signaturePersisted: true,
    },
    classification: "WAITING",
    resume: "CONTINUE_WAITING",
  },
  {
    id: "phase 5.2 send — sign intent absent but signer audit indicates a call",
    kind: "SEND_EXTERNAL",
    seed: { status: "APPROVED", signerAuditIndicatesCall: true },
    classification: "INVARIANT_BREACH",
    resume: null,
  },
];

/* ─── suite ───────────────────────────────────────────────────────── */

describe.skipIf(TEST_DATABASE_URL === "")(
  "graceful overlap and crash handoff (real PostgreSQL, two instances)",
  { timeout: 120_000 },
  () => {
    describe("two instances contend for one leadership lock (checklist 1, 2)", () => {
      it("exactly one instance holds leadership; both attempts are in flight together", async () => {
        const a = instance("A");
        const b = instance("B");

        // Server-side sleep barrier forces both backends into pg_try_advisory_lock concurrently
        // — Promise.all alone is not a concurrency proof (B3).
        const [aWon, bWon] = await Promise.all([
          a.tryAcquireLeadershipConcurrent(0.2),
          b.tryAcquireLeadershipConcurrent(0.2),
        ]);

        expect([aWon, bWon].filter(Boolean)).toHaveLength(1);
        expect([a.leadershipHeld, b.leadershipHeld].filter(Boolean)).toEqual([true]);
        expect(await advisoryLockHolders(url, LOCK_ID)).toBe(1);
        drillsRun += 1;
      });

      it("the non-leader still serves liveness 200 and reports leadership non-held (no overlap-deploy deadlock)", async () => {
        const a = instance("A");
        const b = instance("B");
        expect(await a.tryAcquireLeadership()).toBe(true);

        // B never blocks on the incumbent: one non-blocking attempt, then the health surface
        // answers while A is STILL holding the lock.
        expect(await b.tryAcquireLeadership()).toBe(false);
        expect(a.leadershipHeld).toBe(true);

        const liveness = b.health.liveness();
        expect(liveness.statusCode).toBe(200);
        expect(liveness.body).toMatchObject({ status: "alive" });

        const readiness = await b.health.readiness();
        expect(readiness.statusCode).toBe(503);
        const checks = (readiness.body as { checks: Array<{ name: string; ready: boolean; gating: boolean }> })
.checks;
        const leadershipCheck = checks.find((c) => c.name === "signer_leadership");
        expect(leadershipCheck).toEqual({ name: "signer_leadership", ready: false, gating: false });
        // The database probe is a real query on B's own connection — the standby is healthy,
        // it simply is not the leader.
        expect(checks.find((c) => c.name === "database_reachable")?.ready).toBe(true);
        expect(a.leadershipHeld).toBe(true);
        drillsRun += 1;
      });

      it("no observed instant has two leaders across a full graceful handoff", async () => {
        const a = instance("A");
        const b = instance("B");
        expect(await a.tryAcquireLeadership()).toBe(true);

        type Obs = { a: boolean; b: boolean; holders: number };
        const observations: Obs[] = [];
        let sampling = true;
        const sampler = (async () => {
          while (sampling) {
            observations.push({
              a: a.leadershipHeld,
              b: b.leadershipHeld,
              holders: await advisoryLockHolders(url, LOCK_ID),
            });
            await new Promise((r) => setTimeout(r, 2));
          }
        })();

        // B waits with jittered backoff (never blocking) while A drains.
        const bAcquire = b.acquireLeadership();
        await new Promise((r) => setTimeout(r, 60));
        expect(b.leadershipHeld).toBe(false);

        await a.sigterm();
        expect(await bAcquire).toBe(true);

        sampling = false;
        await sampler;
        observations.push({
          a: a.leadershipHeld,
          b: b.leadershipHeld,
          holders: await advisoryLockHolders(url, LOCK_ID),
        });

        expect(observations.length).toBeGreaterThan(2);
        // Two process latches true, or holders>=1 with both latches true, is dual-leader.
        expect(observations.filter((o) => o.a && o.b)).toEqual([]);
        expect(observations.filter((o) => o.holders >= 1 && o.a && o.b)).toEqual([]);
        expect(b.leadershipHeld).toBe(true);
        expect(a.leadershipHeld).toBe(false);
        drillsRun += 1;
      });
    });

    describe("SIGTERM mid-operation (checklist 3)", () => {
      it("the drained leader keeps its lease; the successor classifies rather than resubmits", async () => {
        const a = instance("A");
        expect(await a.tryAcquireLeadership()).toBe(true);

        // A is mid-operation: preimage persisted, signature not yet written. Arm a live
        // barrier on the sign path so SIGTERM hits while resume is in flight (B1).
        const op = await seedOperation(url, {
          kind: "MOVE_INTERNAL",
          status: "FORMED",
          exactPreimagePersisted: true,
        });
        await armCrashHook(url, CRASH_HOOK.BEFORE_SIGNATURE_PERSIST);
        // Attach rejection handler immediately — crash/sigterm aborts the parked path.
        const aResume = a.runBootRecovery().then(
          (v) => ({ ok: true as const, v }),
          (err: unknown) => ({ ok: false as const, err }),
        );
        await waitUntilHookReached(url, CRASH_HOOK.BEFORE_SIGNATURE_PERSIST);

        await a.sigterm();
        expect(a.leadershipHeld).toBe(false);
        expect((await aResume).ok).toBe(false);

        // Boot does not delete a stale lease based on time — a drain is not a release.
        expect(await countRows(url, "wallet_active_leases")).toBe(2);
        // No signature was persisted mid-drain.
        expect(
          await countRows(url, "operations", `id = '${op.operationId}' AND signature_persisted`),
        ).toBe(0);

        const b = instance("B");
        expect(await b.acquireLeadership()).toBe(true);
        await disarmCrashHook(url, CRASH_HOOK.BEFORE_SIGNATURE_PERSIST);
        const { report, actions } = await b.runBootRecovery();

        expect(report.invariantBreach).toBe(false);
        const classified = report.classifications.find((c) => c.operationId === op.operationId);
        expect(classified?.classification).toBe("PROVEN_NOT_STARTED");
        expect(classified?.authorizedResume?.kind).toBe("SIGN_PERSISTED_PREIMAGE");
        expect(actions.submitCalls).toEqual([]);
        expect(actions.gatewayPosts).toEqual([]);
        expect(await countRows(url, "submit_calls")).toBe(0);
        expect(await walletsWithDuplicateLeases(url)).toEqual([]);
        drillsRun += 1;
      });

      it("a stale heartbeat never releases a lease and never grants leadership", async () => {
        const a = instance("A");
        expect(await a.tryAcquireLeadership()).toBe(true);
        const op = await seedOperation(url, { kind: "SEND_EXTERNAL", status: "APPROVED" });
        await ageHeartbeat(url, op.walletIds[0] as string, 48);

        // The incumbent is idle far past any heartbeat threshold; the challenger still loses.
        const b = instance("B");
        expect(await b.tryAcquireLeadership()).toBe(false);
        expect(a.leadershipHeld).toBe(true);

        const { report } = await a.runBootRecovery();
        const finding = report.leaseFindings.find((f) => f.walletId === op.walletIds[0]);
        expect(finding?.staleHeartbeatObserved).toBe(true);
        expect(finding?.severity).toBe("ok");
        expect(await countRows(url, "wallet_active_leases")).toBe(1);
        expect(report.counters.leaseDeletes).toBe(0);
        drillsRun += 1;
      });
    });

    describe("lock connection dropped without SIGTERM — database failover (checklist 4)", () => {
      it("the latch flips to not-held from the connection event, before any successor holds the lock", async () => {
        const a = instance("A");
        expect(await a.tryAcquireLeadership()).toBe(true);
        expect(await advisoryLockHolders(url, LOCK_ID)).toBe(1);

        // The SERVER kills A's backend from a third session. A's process is untouched — no
        // SIGTERM, no release path, no unlock statement. This is the failover a client-side
        // kill cannot model.
        await a.dropLockConnection();

        // Loss is derived from the dead connection, not from a heartbeat age or a wall clock.
        expect(a.leadershipHeld).toBe(false);
        expect(a.lossReasons).toHaveLength(1);
        expect(a.lossReasons[0]).toMatch(/signer leadership lock connection (end|error)/);
        // PostgreSQL freed the lock at backend death: no session holds it at this instant, so
        // A's latch went false while the successor still could not be leading.
        expect(await advisoryLockHolders(url, LOCK_ID)).toBe(0);

        const b = instance("B");
        expect(await b.acquireLeadership()).toBe(true);
        expect(await advisoryLockHolders(url, LOCK_ID)).toBe(1);
        expect([a.leadershipHeld, b.leadershipHeld]).toEqual([false, true]);
        drillsRun += 1;
      });

      it("a successor racing the failover never coexists with the ex-leader", async () => {
        const a = instance("A");
        expect(await a.tryAcquireLeadership()).toBe(true);

        const b = instance("B");
        // B is already retrying with jittered backoff when the failover hits.
        const bAcquire = b.acquireLeadership();
        await new Promise((r) => setTimeout(r, 50));
        expect(b.leadershipHeld).toBe(false);

        type Sample = {
          a: boolean;
          b: boolean;
          holders: number;
          aSign: "signed" | "not_leader" | "rejected" | "skipped";
        };
        const samples: Sample[] = [];
        let sampling = true;
        const sampler = (async () => {
          while (sampling) {
            const holders = await advisoryLockHolders(url, LOCK_ID);
            // signUnderLease on the ex-leader during the residual window (B3).
            const aSign = a.leadershipHeld || holders >= 0
              ? await a.signProbe()
: ("skipped" as const);
            samples.push({
              a: a.leadershipHeld,
              b: b.leadershipHeld,
              holders,
              aSign,
            });
            await new Promise((r) => setTimeout(r, 5));
          }
        })();

        // drop without auto-probe first so residual window can exist, then probe.
        await a.dropLockConnection({ probe: false });
        // Tight residual: probe to flip latch while sampler + B race.
        const probe = a.probeLockConnection();
        expect(await bAcquire).toBe(true);
        await probe;

        sampling = false;
        await sampler;

        // No sample may show dual latch true.
        expect(samples.filter((s) => s.a && s.b)).toEqual([]);
        expect(samples.filter((s) => s.holders >= 1 && s.a && s.b)).toEqual([]);
        // Residual window: lock free while A still believes held — signUnderLease may still
        // pass until the latch flips. Forbidden: A signs after B holds, or after A lost latch.
        expect(
          samples.filter((s) => s.aSign === "signed" && (s.b || !s.a)),
        ).toEqual([]);
        // At least one sample must show A refused once non-leader (latch flipped).
        expect(samples.some((s) => s.aSign === "not_leader")).toBe(true);
        expect(a.leadershipHeld).toBe(false);
        expect(b.leadershipHeld).toBe(true);
        expect(await advisoryLockHolders(url, LOCK_ID)).toBe(1);
        drillsRun += 1;
      });

      it("the ex-leader's signing seam refuses the instant the connection is gone", async () => {
        const a = instance("A");
        expect(await a.tryAcquireLeadership()).toBe(true);
        const op = await seedOperation(url, {
          kind: "SEND_EXTERNAL",
          status: "APPROVED",
          exactPreimagePersisted: true,
        });

        await a.dropLockConnection();
        expect(a.leadershipHeld).toBe(false);

        // runDeterministicBootRecovery asserts leadership first (its precondition),
        // so a node that lost the lock cannot classify-or-resume as leader at all.
        await expect(a.runBootRecovery()).rejects.toBeInstanceOf(NotSignerLeaderError);
        expect(await countRows(url, "external_partials")).toBe(0);
        expect(await countRows(url, "operations", `id = '${op.operationId}' AND signature_persisted`)).toBe(0);
        drillsRun += 1;
      });
    });

    describe("crash at every durable phase boundary (checklist 5)", () => {
      it.each(PHASE_CASES.map((c) => [c.id, c] as const))(
        "%s",
        async (_id, phase) => {
          const a = instance("A");
          expect(await a.tryAcquireLeadership()).toBe(true);
          const op = await seedOperation(url, { kind: phase.kind, ...phase.seed });
          const leasesBefore = await countRows(url, "wallet_active_leases");

          // SIGKILL: no unlock, no release path. What is on disk IS the crash state.
          // crash() awaits latch loss so the ex-leader is observably non-leader (B4).
          await a.crash();
          expect(a.leadershipHeld).toBe(false);

          const b = instance("B");
          expect(await b.acquireLeadership()).toBe(true);
          const { report, actions } = await b.runBootRecovery();

          const classified = report.classifications.find((c) => c.operationId === op.operationId);
          expect(classified?.classification).toBe(phase.classification);
          expect(classified?.authorizedResume?.kind ?? null).toBe(phase.resume);

          // Classification itself is pure — it never signs and never submits.
          expect(report.counters.signCalls).toBe(0);
          expect(report.counters.submitCalls).toBe(0);
          expect(report.counters.leaseDeletes).toBe(0);
          expect(report.counters.attentionClears).toBe(0);
          expect(report.counters.externalPartialReforms).toBe(0);

          if (phase.classification === "INVARIANT_BREACH") {
            expect(report.invariantBreach).toBe(true);
            expect(report.ready).toBe(false);
            expect(actions.moneyEnginesStopped).toHaveLength(1);
            expect(actions.resumed).toEqual([]);
            expect(actions.attention.map((x) => x.operationId)).toContain(op.operationId);
          } else {
            expect(report.invariantBreach).toBe(false);
            expect(actions.moneyEnginesStopped).toEqual([]);
          }
          if (phase.classification === "INDETERMINATE") {
            // Park and retain — never submit, never release.
            expect(actions.attention.map((x) => x.operationId)).toContain(op.operationId);
            expect(actions.submitCalls).toEqual([]);
          }

          // Leases survive every crash; the one-row-per-wallet invariant holds throughout.
          expect(await countRows(url, "wallet_active_leases")).toBe(leasesBefore);
          expect(await walletsWithDuplicateLeases(url)).toEqual([]);
          expect(await countRows(url, "submit_calls")).toBeLessThanOrEqual(1);
          drillsRun += 1;
        },
      );
    });

    describe("crash mid-signature: only the identical persisted preimage is ever signed", () => {
      it("live crash between preimage and signature: successor re-signs identical bytes only", async () => {
        const a = instance("A");
        expect(await a.tryAcquireLeadership()).toBe(true);
        const preimage = '{"inner":{"amount__zkz":"0.01"},"nonce":"fixed-bytes-under-test"}';
        const op = await seedOperation(url, {
          kind: "SEND_EXTERNAL",
          status: "APPROVED",
          exactPreimagePersisted: true,
          exactPreimageText: preimage,
        });

        // Drive the REAL resume path under A; park after preimage is known, before signature.
        await armCrashHook(url, CRASH_HOOK.BEFORE_SIGNATURE_PERSIST);
        const aResume = a.runBootRecovery().then(
          (v) => ({ ok: true as const, v }),
          (err: unknown) => ({ ok: false as const, err }),
        );
        await waitUntilHookReached(url, CRASH_HOOK.BEFORE_SIGNATURE_PERSIST);
        // Live kill at the boundary (B1) — not seed-then-crash of an idle leader.
        await a.crash();
        expect(a.leadershipHeld).toBe(false);
        expect((await aResume).ok).toBe(false);

        // Signature must not have landed under A.
        expect(
          await countRows(url, "operations", `id = '${op.operationId}' AND signature_persisted`),
        ).toBe(0);
        expect(await countRows(url, "external_partials", `operation_id = '${op.operationId}'`)).toBe(0);

        const b = instance("B");
        expect(await b.acquireLeadership()).toBe(true);
        await disarmCrashHook(url, CRASH_HOOK.BEFORE_SIGNATURE_PERSIST);
        const { report, actions } = await b.runBootRecovery();

        const classified = report.classifications.find((c) => c.operationId === op.operationId);
        expect(classified?.classification).toBe("PROVEN_NOT_STARTED");
        expect(classified?.authorizedResume?.kind).toBe("SIGN_PERSISTED_PREIMAGE");

        // Exactly one signer call, over byte-identical input, through the signing chokepoint.
        expect(actions.signatures).toHaveLength(1);
        expect(actions.signatures[0]?.preimageText).toBe(preimage);
        expect(actions.signerAudit.filter((e) => e.outcome === "SIGNED")).toHaveLength(1);
        expect(actions.signerAudit.filter((e) => e.outcome === "REJECTED")).toHaveLength(0);
        expect(await countRows(url, "external_partials", `operation_id = '${op.operationId}'`)).toBe(1);

        // A second boot recovery over the now-signed state produces WAITING, not a second
        // partial: a second step-1 signature over different bytes is forbidden.
        const second = await b.runBootRecovery();
        const again = second.report.classifications.find((c) => c.operationId === op.operationId);
        expect(again?.classification).toBe("WAITING");
        expect(second.actions.signatures).toEqual([]);
        expect(await countRows(url, "external_partials", `operation_id = '${op.operationId}'`)).toBe(1);

        // And the structural backstop: a second, DIFFERENT partial cannot be stored at all.
        const duplicate = await runPsql(
          url,
          `INSERT INTO external_partials (operation_id, step_1_signature, preimage_sha256)
           VALUES ('${op.operationId}', 'OTHER-SIG', '${"b".repeat(64)}')`,
        );
        expect(duplicate.ok).toBe(false);
        expect(sqlstateOf(duplicate.stderr)).toBe("23505");
        drillsRun += 1;
      });
    });

    describe("crash mid-submit: no second submit call for one attempt", () => {
      it("live crash between claim and exchange: zero POSTs on every successor restart", async () => {
        const a = instance("A");
        expect(await a.tryAcquireLeadership()).toBe(true);
        const op = await seedOperation(url, {
          kind: "MOVE_INTERNAL",
          status: "SIGNED",
          exactPreimagePersisted: true,
          signaturePersisted: true,
          // Valid JSON so executeMoveSubmitClaim receives real action data (the byte-exact signing rule).
          exactPreimageText: JSON.stringify({
            inner: { amount__zkz: "0.01" },
            step_1_signature: "sig-under-test",
          }),
        });

        // Drive production SUBMIT_ONCE under A; park after claimSubmitOnce, before exchange.
        await armCrashHook(url, CRASH_HOOK.AFTER_CLAIM_BEFORE_EXCHANGE);
        const aResume = a.runBootRecovery().then(
          (v) => ({ ok: true as const, v }),
          (err: unknown) => ({ ok: false as const, err }),
        );
        await waitUntilHookReached(url, CRASH_HOOK.AFTER_CLAIM_BEFORE_EXCHANGE);

        // Claim must already be durable; zero gateway POSTs yet (B2).
        const query = makeChaosSqlQuery(url);
        const evidenceMid = await readSubmitAttemptEvidence(query, op.operationId, 1);
        expect(evidenceMid.status).toBe("CLAIMED_UNRETURNED");
        expect(await countRows(url, "submit_decisions", `operation_id = '${op.operationId}'`)).toBe(1);
        expect(await countRows(url, "gateway_submit_attempts", `operation_id = '${op.operationId}'`)).toBe(0);

        await a.crash();
        expect(a.leadershipHeld).toBe(false);
        expect((await aResume).ok).toBe(false);

        // Still zero exchanges after the kill.
        expect(await countRows(url, "gateway_submit_attempts")).toBe(0);
        expect(await countRows(url, "submit_calls")).toBe(0);

        // Successor: claim exists → classifier INDETERMINATE → zero further exchanges.
        const b = instance("B");
        expect(await b.acquireLeadership()).toBe(true);
        await disarmCrashHook(url, CRASH_HOOK.AFTER_CLAIM_BEFORE_EXCHANGE);
        const second = await b.runBootRecovery();
        const classified = second.report.classifications.find((x) => x.operationId === op.operationId);
        expect(classified?.classification).toBe("INDETERMINATE");
        expect(classified?.authorizedResume).toBeNull();
        expect(second.actions.submitCalls).toEqual([]);
        expect(second.actions.gatewayPosts).toEqual([]);
        expect(second.actions.attention.map((x) => x.operationId)).toContain(op.operationId);
        expect(await countRows(url, "submit_decisions", `operation_id = '${op.operationId}'`)).toBe(1);
        expect(await countRows(url, "gateway_submit_attempts")).toBe(0);
        expect(await countRows(url, "submit_calls")).toBe(0);

        // Third restart still ambiguous — stable, not a one-shot.
        await b.crash();
        const c = instance("C");
        expect(await c.acquireLeadership()).toBe(true);
        const third = await c.runBootRecovery();
        expect(third.actions.submitCalls).toEqual([]);
        expect(third.actions.gatewayPosts).toEqual([]);
        expect(await countRows(url, "gateway_submit_attempts")).toBe(0);

        // Production mint loser path: claimSubmitOnce returns minted=false.
        const claimStore = makeSubmitDecisionClaimStore(query);
        const relitigate = await claimStore.claimSubmitOnce({
          attemptId: op.operationId,
          claimedAt: new Date().toISOString(),
          operationId: op.operationId,
          transactionAttemptNo: 1,
        });
        expect(relitigate.minted).toBe(false);

        // Structural backstop on chaos table + frozen UNIQUE on submit_decisions.
        const duplicate = await runPsql(
          url,
          `INSERT INTO submit_decisions
             (id, operation_id, transaction_attempt_no, decision, decided_at, details)
           VALUES ('${op.operationId}', '${op.operationId}', 1, 'INITIAL_SINGLE_SHOT', now(), 'x')`,
        );
        expect(duplicate.ok).toBe(false);
        expect(sqlstateOf(duplicate.stderr)).toBe("23505");
        drillsRun += 1;
      });

      it("live crash after exchange before recorder: one POST, never a second", async () => {
        const a = instance("A");
        expect(await a.tryAcquireLeadership()).toBe(true);
        const op = await seedOperation(url, {
          kind: "MOVE_INTERNAL",
          status: "SIGNED",
          exactPreimagePersisted: true,
          signaturePersisted: true,
          exactPreimageText: JSON.stringify({
            inner: { amount__zkz: "0.01" },
            step_1_signature: "sig-under-test",
          }),
        });

        // Exchange succeeds; recorder is blocked by crash hook → kill after the POST.
        await armCrashHook(url, CRASH_HOOK.AFTER_EXCHANGE_BEFORE_RECORDER);
        const aResume = a.runBootRecovery().then(
          (v) => ({ ok: true as const, v }),
          (err: unknown) => ({ ok: false as const, err }),
        );
        await waitUntilHookReached(url, CRASH_HOOK.AFTER_EXCHANGE_BEFORE_RECORDER);

        // One POST already happened; claim durable.
        expect(await countRows(url, "submit_decisions", `operation_id = '${op.operationId}'`)).toBe(1);
        expect(await countRows(url, "submit_calls")).toBe(1);

        await a.crash();
        expect(a.leadershipHeld).toBe(false);
        expect((await aResume).ok).toBe(false);

        const b = instance("B");
        expect(await b.acquireLeadership()).toBe(true);
        await disarmCrashHook(url, CRASH_HOOK.AFTER_EXCHANGE_BEFORE_RECORDER);
        const recovery = await b.runBootRecovery();
        // Boundary recorded (claim) → INDETERMINATE; zero additional POSTs.
        expect(
          recovery.report.classifications.find((c) => c.operationId === op.operationId)
            ?.classification,
        ).toBe("INDETERMINATE");
        expect(recovery.actions.gatewayPosts).toEqual([]);
        expect(recovery.actions.submitCalls).toEqual([]);
        // At most the one exchange from A.
        expect(await countRows(url, "submit_calls")).toBe(1);
        drillsRun += 1;
      });

      it("happy-path SUBMIT_ONCE through production claim+exchange records exactly one POST", async () => {
        const a = instance("A");
        expect(await a.tryAcquireLeadership()).toBe(true);
        const op = await seedOperation(url, {
          kind: "MOVE_INTERNAL",
          status: "SIGNED",
          exactPreimagePersisted: true,
          signaturePersisted: true,
          exactPreimageText: JSON.stringify({
            inner: { amount__zkz: "0.01" },
            step_1_signature: "sig-under-test",
          }),
        });
        const { report, actions } = await a.runBootRecovery();
        expect(
          report.classifications.find((c) => c.operationId === op.operationId)?.authorizedResume
            ?.kind,
        ).toBe("SUBMIT_ONCE");
        expect(actions.gatewayPosts).toHaveLength(1);
        expect(actions.submitCalls).toEqual([op.operationId]);
        expect(await countRows(url, "submit_decisions", `operation_id = '${op.operationId}'`)).toBe(1);
        expect(await countRows(url, "gateway_submit_attempts", `operation_id = '${op.operationId}'`)).toBe(1);
        expect(await countRows(url, "submit_calls")).toBe(1);

        // Second recovery: claim+attempt exist → INDETERMINATE, zero further POSTs.
        const second = await a.runBootRecovery();
        expect(second.actions.gatewayPosts).toEqual([]);
        expect(second.actions.submitCalls).toEqual([]);
        expect(await countRows(url, "gateway_submit_attempts")).toBe(1);
        drillsRun += 1;
      });
    });

    describe("one active lease per wallet at every instant (checklist 6)", () => {
      it("a second active lease row for the same wallet is rejected by the database", async () => {
        const op = await seedOperation(url, { kind: "SEND_EXTERNAL", status: "APPROVED" });
        const walletId = op.walletIds[0] as string;

        const duplicate = await runPsql(
          url,
          `INSERT INTO wallet_active_leases (
             wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
             lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
           ) VALUES (
             '${walletId}', gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
             'RECONCILIATION', 1, now(), now(), gen_random_uuid()
           )`,
        );
        expect(duplicate.ok).toBe(false);
        expect(sqlstateOf(duplicate.stderr)).toBe("23505");
        expect(await walletsWithDuplicateLeases(url)).toEqual([]);
        drillsRun += 1;
      });

      it("a duplicate lease planted past the constraint is an invariant breach, not a release", async () => {
        // The PK makes two rows unreachable through normal writes, so the duplicate-detection
        // branch of the lease audit is otherwise unfalsifiable. Two leases whose required
        // roles disagree with the operation model the same corruption the audit must catch.
        const a = instance("A");
        expect(await a.tryAcquireLeadership()).toBe(true);
        const op = await seedOperation(url, { kind: "SEND_EXTERNAL", status: "APPROVED" });
        const walletId = op.walletIds[0] as string;
        await psqlMust(
          url,
          `UPDATE wallet_active_leases SET lease_role = 'MOVE_DESTINATION' WHERE wallet_id = '${walletId}'`,
        );

        const { report, actions } = await a.runBootRecovery();
        expect(report.invariantBreach).toBe(true);
        expect(report.ready).toBe(false);
        expect(
          report.leaseFindings.find((f) => f.walletId === walletId)?.severity,
        ).toBe("invariant_breach");
        expect(actions.moneyEnginesStopped).toHaveLength(1);
        // Quarantined, never released: the lease row survives the breach.
        expect(await countRows(url, "wallet_active_leases", `wallet_id = '${walletId}'`)).toBe(1);
        expect(
          await countRows(url, "wallets", `id = '${walletId}' AND state = 'QUARANTINED'`),
        ).toBe(1);
        expect(report.counters.leaseDeletes).toBe(0);
        drillsRun += 1;
      });
    });
  },
);

/* ─── fail-closed obligation guard (B6 / pattern) ───────────
 * Top-level so it runs even when the suite is skipIf'd. PG_REQUIRED=1 + no URL
 * or zero drills = hard failure, never silent green. */
it("guard: overlap/crash handoff drills must execute under PG_REQUIRED=1", () => {
  if (!TEST_DATABASE_URL) {
    if (PG_REQUIRED) {
      throw new Error(
        "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts " +
          "provisions it when Postgres is reachable. The overlap/crash suite " +
          "cannot silently skip.",
      );
    }
    return;
  }
  if (!schemaReady && PG_REQUIRED) {
    throw new Error(
      "PG_REQUIRED=1 but the chaos schema never became ready — " +
        "overlap/crash handoff drills did not run.",
    );
  }
  if (schemaReady) {
    expect(
      drillsRun,
      "PostgreSQL was reachable but too few chaos drills completed",
    ).toBeGreaterThanOrEqual(EXPECTED_MIN_DRILLS);
  }
});
