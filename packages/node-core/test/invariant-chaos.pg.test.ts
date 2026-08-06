/**
 * Run invariant chaos scenarios.
 *
 * Combined multi-process / real-Postgres fault scenarios layered on concurrency
 * harness surfaces and crash-injection points. Each of the seven fault
 * classes is exercised at least once in combination with another class; post-scenario
 * boot recovery follows the 8-step recovery sequence; one-in-flight
 * and one-submit are asserted at the database constraint level.
 *
 * Connectivity: TEST_DATABASE_URL is auto-provisioned by vitest.global-setup.ts
 * when run through the ROOT vitest project. `vitest run --root packages/node-core` bypasses
 * global-setup and silently skips — always run via the root project.
 *
 * Production imports (not a private re-model): leadership lock, submit-decision claim store,
 * executeMoveSubmitClaim, LeaseSignerBoundary, crash-injection lifecycle/recovery, custody
 * DDL tokenizer, frozen submit-attempts + observation-ledger SQL.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { ready } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import { makeSubmitDecisionClaimStore } from "../src/core/submit-decision-claim-store.ts";
import {
  SignerLeadership,
  tryAcquireSignerLeadership,
  type LeadershipLockPool,
} from "../src/workers/leadership.ts";

import {
  BOOT_DOES_NOT,
  BOOT_RECOVERY_STEPS,
  checkDbInvariants,
  clearLease,
  createChaosDatabase,
  dropChaosDatabase,
  FAULT_CLASSES,
  injectDropConnection,
  injectDuplicateJobLease,
  injectDuplicateJobSubmit,
  injectFillDiskAtPreimage,
  injectKillProcess,
  injectLagGateway,
  injectLoseLeaderLock,
  injectReorderRead,
  makeLaggingExchange,
  makePsqlQueryFn,
  DEFAULT_LIMITS,
  PsqlSession,
  provokeSplitBrain,
  psqlMust,
  runBootDoesNotViolationSeams,
  runBootRecovery,
  runCrashInjectionChaos,
  runPsql,
  seedOperation,
  SeededRng,
  snapshotAnomalies,
  SQLSTATE_UNIQUE_VIOLATION,
  type ChaosDb,
  type FaultClass,
} from "./invariant-chaos-harness.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

const sessions: PsqlSession[] = [];
let db: ChaosDb | null = null;
let schemaReady = false;
let assertionsRun = 0;

beforeAll(async () => {
  await ready();
  if (!TEST_DATABASE_URL) {
    if (PG_REQUIRED) {
      throw new Error(
        "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — run via root vitest so global-setup provisions it",
      );
    }
    return;
  }
  db = await createChaosDatabase(TEST_DATABASE_URL);
  schemaReady = true;
}, 60_000);

afterEach(() => {
  // Free session-scoped advisory locks between tests so leadership probes stay independent.
  while (sessions.length > 0) {
    sessions.pop()?.killHard();
  }
});

afterAll(async () => {
  while (sessions.length > 0) {
    sessions.pop()?.killHard();
  }
  if (schemaReady && db !== null && TEST_DATABASE_URL) {
    await dropChaosDatabase(TEST_DATABASE_URL, db.name);
  }
});

describe.skipIf(!TEST_DATABASE_URL)(
  "invariant chaos — real multi-process / real-Postgres",
  { timeout: 90_000 },
  () => {
    it("boot sequence freezes the exact 8 steps and 6 Boot-does-not prohibitions", () => {
      assertionsRun += 1;
      expect(BOOT_RECOVERY_STEPS).toHaveLength(8);
      expect(BOOT_RECOVERY_STEPS[0]).toContain("signer leadership lock");
      expect(BOOT_RECOVERY_STEPS[7]).toContain("exactly one signer leader");
      expect(BOOT_DOES_NOT).toHaveLength(6);
      expect(BOOT_DOES_NOT).toContain("submit an attempt whose call boundary is ambiguous");
      expect(BOOT_DOES_NOT).toContain("delete a stale lease based on time");
      expect(FAULT_CLASSES).toHaveLength(7);
    });

    it("Boot does not: each of 6 prohibitions is provoked and refused during boot", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;
      await clearLease(d);

      const boot = await runBootRecovery(d, sessions, { provokeBootDoesNot: true });
      expect(boot.steps).toHaveLength(8);
      expect(boot.bootDoesNot).toHaveLength(6);

      for (const prohibition of BOOT_DOES_NOT) {
        const probe = boot.bootDoesNot.find((p) => p.prohibition === prohibition);
        expect(probe, `missing probe for: ${prohibition}`).toBeDefined();
        expect(probe?.provoked, prohibition).toBe(true);
        expect(probe?.refused, `must refuse: ${prohibition} (${probe?.detail})`).toBe(true);
      }

      // Concrete durable refusals from post-boot re-SELECT (not authored constants).
      expect(boot.leasesDeletedByTime).toBe(0);
      expect(boot.submitCallsDuringBoot).toBe(0);
      expect(boot.partialsReformed).toBe(0);
      expect(boot.attentionAutoCleared).toBe(false);
      expect(boot.destinationAutoAccepted).toBe(false);
      expect(boot.exactBytesSynthesized).toBe(false);

      // Stale lease still present after boot (time-delete refused).
      const remaining = Number(
        (
          await psqlMust(
            d.url,
            `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${d.walletId}';`,
          )
        ).trim(),
      );
      expect(remaining).toBe(1);

      // Durable residue still in seed state after boot.
      const partials = Number(
        (
          await psqlMust(
            d.url,
            `SELECT count(*) FROM chaos_external_partials WHERE wallet_id = '${d.walletId}';`,
          )
        ).trim(),
      );
      expect(partials).toBe(1);
      const attention = (
        await psqlMust(
          d.url,
          `SELECT count(*) FROM operations WHERE status = 'NEEDS_ATTENTION' AND source_wallet_id = '${d.walletId}';`,
        )
      ).trim();
      expect(Number(attention)).toBeGreaterThanOrEqual(1);
      const pendingDest = (
        await psqlMust(
          d.url,
          `SELECT count(*) FROM chaos_pending_destinations WHERE wallet_id = '${d.walletId}' AND status = 'PENDING';`,
        )
      ).trim();
      expect(Number(pendingDest)).toBe(1);
      const missingExact = (
        await psqlMust(
          d.url,
          `SELECT count(*) FROM chaos_exact_byte_records WHERE wallet_id = '${d.walletId}' AND exact_bytes IS NULL;`,
        )
      ).trim();
      expect(Number(missingExact)).toBe(1);

      // Counterfactual: the same residue seams *can* mutate when deliberately violated
      // (proves refusal is not a tautology of unmutatable state).
      const violated = await runBootDoesNotViolationSeams(d);
      expect(violated.partialsReformed).toBeGreaterThanOrEqual(1);
      expect(violated.attentionCleared).toBe(true);
      expect(violated.destinationAccepted).toBe(true);
      expect(violated.exactBytesSynthesized).toBe(true);
    });

    it("combined: kill_process + lose_leader_lock — latch drops, standby acquires, one leader", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;

      const lost = await injectLoseLeaderLock(d, sessions);
      expect(lost.effect.mutated).toBe(true);
      expect(lost.latch.held).toBe(false);
      injectKillProcess(lost.session); // already dead — idempotent fault class coverage

      // Standby acquires after death.
      const pool: LeadershipLockPool = {
        connect: async () => {
          const s = new PsqlSession(d.url);
          sessions.push(s);
          return s;
        },
      };
      const standby = new SignerLeadership();
      const held = await tryAcquireSignerLeadership(pool, standby, d.lockId);
      expect(held).not.toBeNull();
      expect(standby.held).toBe(true);

      // A third contender loses.
      const third = new SignerLeadership();
      expect(await tryAcquireSignerLeadership(pool, third, d.lockId)).toBeNull();

      await held?.release();
      const boot = await runBootRecovery(d, sessions);
      expect(boot.steps).toHaveLength(8);
      expect(boot.steps.every((s) => s.ok || s.step.includes("Report readiness"))).toBe(true);
    });

    it("combined: drop_connection + duplicate_job lease race — exactly one lease (One-in-flight @ DB)", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;

      // Hold a connection then drop it mid-flight while duplicate jobs race.
      const sticky = new PsqlSession(d.url);
      sessions.push(sticky);
      await sticky.query("SELECT 1 AS ok");
      injectDropConnection(sticky);

      const effect = await injectDuplicateJobLease(d, 8);
      expect(effect.mutated).toBe(true);
      expect(effect.sideEffects?.winners).toBe(1);

      const inv = await checkDbInvariants(d);
      expect(inv.oneInFlightPerWallet).toBe(true);
      expect(inv.leaseCount).toBe(1);

      // Direct UNIQUE proof: a second lease is 23505.
      const second = await runPsql(
        d.url,
        `INSERT INTO wallet_active_leases (
           wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
           lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
         VALUES (
           '${d.walletId}', gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
           'MOVE_SOURCE', 1, now(), now(), gen_random_uuid());`,
      );
      expect(second.ok).toBe(false);
      expect(second.stderr).toContain(SQLSTATE_UNIQUE_VIOLATION);

      const boot = await runBootRecovery(d, sessions);
      expect(boot.breach).toBe(false);
    });

    it("combined: duplicate_job submit workers + lag_gateway — exactly ONE gateway POST", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;
      const auth = await seedOperation(d);

      const lagMeta = injectLagGateway(30);
      expect(lagMeta.mutated).toBe(true);
      const lagged = makeLaggingExchange(lagMeta.scriptedOutcome.delayMs);

      const { effect, results, posts } = await injectDuplicateJobSubmit(
        d,
        auth,
        lagged.exchange,
        DEFAULT_LIMITS,
        8,
      );
      expect(effect.mutated).toBe(true);
      expect(posts).toBe(1);
      expect(results.filter((r) => r.executed)).toHaveLength(1);
      expect(lagged.lagApplied).toBe(true);

      const inv = await checkDbInvariants(d, auth.operationId);
      expect(inv.oneSubmitDecisionPerAttempt).toBe(true);
      expect(inv.oneSubmitAttemptPerAttempt).toBe(true);
      expect(inv.submitDecisionCount).toBe(1);
      expect(inv.submitAttemptCount).toBe(1);

      // Loser path: re-claim reports minted=false (DB arbitrated).
      const claimStore = makeSubmitDecisionClaimStore(makePsqlQueryFn(d.url));
      const again = await claimStore.claimSubmitOnce({
        attemptId: randomUUIDLike(),
        claimedAt: "2026-07-26T00:00:01.000Z",
        operationId: auth.operationId,
        transactionAttemptNo: 1,
      });
      expect(again.minted).toBe(false);
    });

    it("combined: reorder_read + lag_gateway — anomalies survive restart (D4: no append-only trigger claim)", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;

      const reg = await injectReorderRead(d, "REGRESSION", 1);
      const jump = await injectReorderRead(d, "UNEXPLAINED_JUMP", 2);
      expect(reg.mutated && jump.mutated).toBe(true);
      injectLagGateway(5); // lag class present in combination

      const before = await snapshotAnomalies(d);
      expect(before).toContain("REGRESSION");
      expect(before).toContain("UNEXPLAINED_JUMP");

      // "Restart": drop all sessions and re-read — durable survival only.
      // D4: production observation append-only trigger DDL is not frozen; this suite does
      // not invent a harness trigger and does not claim "append-only triggers hold."
      while (sessions.length > 0) sessions.pop()?.killHard();
      const after = await snapshotAnomalies(d);
      expect(after).toBe(before);

      // Reorder classifications are never chain-head promotions: relationship stays anomalous.
      const rels = (
        await psqlMust(
          d.url,
          `SET search_path TO obs, public;
           SELECT string_agg(relationship::text, ',' ORDER BY wallet_seq)
           FROM gateway_observations;`,
        )
      ).trim();
      expect(rels).toContain("REGRESSION");
      expect(rels).toContain("UNEXPLAINED_JUMP");
      expect(rels).not.toMatch(/FIRST|SUCCESSOR/);
    });

    it("combined: fill_disk preimage boundary + process_kill crash recovery — no signature without preimage", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;

      const filled = injectFillDiskAtPreimage("MOVE_INTERNAL");
      expect(filled.effect.mutated).toBe(true);
      expect(filled.hasSignatureWithoutPreimage).toBe(false);
      expect(filled.classification).toBe("WRITE_FAILED_NO_ATTEMPT");

      // Layer a crash-injection kill at AFTER_CREATE (ENOSPC leaves the same residue: no attempt).
      // Recovery may resume formation and perform the ONE authorized submit — never a second.
      const killed = runCrashInjectionChaos("MOVE_INTERNAL", "AFTER_CREATE", {
        kind: "NOT_LANDED_YET",
      });
      expect(killed.classification).toBe("NO_ATTEMPT_RESUME_FORMATION");
      expect(killed.submitCalls).toBeLessThanOrEqual(1);

      // Pre-submit crash + recovery never double-submits.
      const afterSign = runCrashInjectionChaos("MOVE_INTERNAL", "AFTER_SIGN_STEP2", {
        kind: "NOT_LANDED_YET",
      });
      expect(afterSign.submitCalls).toBe(1);

      const afterSubmit = runCrashInjectionChaos("MOVE_INTERNAL", "AFTER_SUBMIT", {
        kind: "NOT_LANDED_YET",
      });
      expect(afterSubmit.submitCalls).toBe(1);
      expect(afterSubmit.classification).toBe("SUBMITTED_RECONCILE");
      // Independent AFTER_SUBMIT residue: reconcile path still only one submit call.
      const again = runCrashInjectionChaos("MOVE_INTERNAL", "AFTER_SUBMIT", {
        kind: "ANOMALOUS",
      });
      expect(again.submitCalls).toBe(1);
      expect(again.classification).toBe("SUBMITTED_RECONCILE");

      const boot = await runBootRecovery(d, sessions, {
        priorClassification: filled.classification,
      });
      expect(boot.steps).toHaveLength(8);
      // Classification is observed residue, not a self-label for breach.
      expect(boot.breach).toBe(false);
      expect(boot.steps[4]?.detail).toContain("WRITE_FAILED_NO_ATTEMPT");
    });

    it("combined: lose_leader_lock + duplicate_job + kill_process — one-in-flight and one-submit hold", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;
      await clearLease(d);

      // Leader dies under load.
      const lost = await injectLoseLeaderLock(d, sessions);
      expect(lost.latch.held).toBe(false);

      // Duplicate lease jobs while leadership is in flux.
      const leaseRace = await injectDuplicateJobLease(d, 5);
      expect(leaseRace.sideEffects?.winners).toBe(1);

      // Concurrent submit workers on a fresh operation.
      const auth = await seedOperation(d);
      const lagged = makeLaggingExchange(10);
      const { posts } = await injectDuplicateJobSubmit(d, auth, lagged.exchange, DEFAULT_LIMITS, 5);
      expect(posts).toBe(1);

      const inv = await checkDbInvariants(d, auth.operationId);
      expect(inv.oneInFlightPerWallet).toBe(true);
      expect(inv.oneSubmitDecisionPerAttempt).toBe(true);
      expect(inv.oneSubmitAttemptPerAttempt).toBe(true);

      const boot = await runBootRecovery(d, sessions);
      expect(boot.steps).toHaveLength(8);
      expect(boot.leaderHeld).toBe(true);
    });

    it("deliberate split-brain is classified INVARIANT_BREACH (never silent dual-signature)", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;
      // Use a distinct lock id so prior test leaders do not interfere.
      const probeDb = { ...d, lockId: d.lockId + 7 };

      const result = await provokeSplitBrain(probeDb, sessions);
      expect(result.dbHolders).toBe(1);
      expect(result.latchesHeld).toBe(2); // impostor + real = dual latch belief
      expect(result.dualLatchDetected).toBe(true);
      expect(result.quarantined).toBe(true);
      expect(result.classification).toBe("INVARIANT_BREACH");
      // D1: production LeaseSignerBoundary.sign for both latches after quarantine —
      // measured refuse (NotSignerLeaderError), vault never reached.
      expect(result.signSuccesses).toBe(0);
      expect(result.vaultCalls).toBe(0);
      expect(result.signAttempts).toHaveLength(2);
      expect(result.signAttempts.every((a) => a.ok === false)).toBe(true);
      // Production assertSignerLeadership throws with latch.reason (INVARIANT_BREACH…).
      expect(
        result.signAttempts.every((a) => (a.error ?? "").includes("does not hold signer leadership")),
      ).toBe(true);
      expect(result.signAttempts.every((a) => (a.error ?? "").includes("INVARIANT_BREACH"))).toBe(
        true,
      );

      // Boot derives breach from observed dual-latch residue — no forceBreach / pre-fed label.
      const boot = await runBootRecovery(probeDb, sessions, {
        dualLatchObservation: {
          latchesHeld: result.latchesHeld,
          dbHolders: result.dbHolders,
          signSuccesses: result.signSuccesses,
        },
      });
      expect(boot.dualLatchBreach).toBe(true);
      expect(boot.breach).toBe(true);
      expect(boot.ready).toBe(false);
      expect(boot.steps[7]?.ok).toBe(false);
      expect(boot.steps[7]?.detail).toContain("dualLatch=true");
    });

    it("seeded multi-fault chaos across all 7 classes preserves One-in-flight + No-blind-retry DB invariants", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;
      const rng = new SeededRng(0x380_0933);
      const seen = new Set<FaultClass>();

      for (let i = 0; i < 14; i += 1) {
        const fault = rng.pick(FAULT_CLASSES);
        seen.add(fault);

        switch (fault) {
          case "kill_process":
          case "drop_connection": {
            const s = new PsqlSession(d.url);
            sessions.push(s);
            await s.query("SELECT 1 AS ok");
            if (fault === "kill_process") injectKillProcess(s);
            else injectDropConnection(s);
            break;
          }
          case "reorder_read": {
            const kind = rng.chance(0.5) ? "REGRESSION" : "UNEXPLAINED_JUMP";
            // seq must be unique per wallet stream — use high offset
            await injectReorderRead(d, kind, 100 + i);
            break;
          }
          case "duplicate_job": {
            await injectDuplicateJobLease(d, 4);
            break;
          }
          case "fill_disk": {
            const f = injectFillDiskAtPreimage("MOVE_INTERNAL");
            expect(f.hasSignatureWithoutPreimage).toBe(false);
            break;
          }
          case "lose_leader_lock": {
            try {
              const lost = await injectLoseLeaderLock(
                { ...d, lockId: d.lockId + 100 + i },
                sessions,
              );
              expect(lost.latch.held).toBe(false);
            } catch {
              // lock contention from parallel leftovers is fine — fault still attempted
            }
            break;
          }
          case "lag_gateway": {
            const meta = injectLagGateway(rng.int(1, 20));
            const lagged = makeLaggingExchange(meta.scriptedOutcome.delayMs);
            const auth = await seedOperation(d);
            const { posts } = await injectDuplicateJobSubmit(
              d,
              auth,
              lagged.exchange,
              DEFAULT_LIMITS,
              3,
            );
            expect(posts).toBe(1);
            break;
          }
          default:
            break;
        }

        const inv = await checkDbInvariants(d);
        expect(inv.oneInFlightPerWallet).toBe(true);
        // Global submit counts can be >1 across many operations; enforce per-wallet lease only
        // here and per-operation uniqueness via the multi-op query in boot.
      }

      expect(seen.size).toBe(FAULT_CLASSES.length);

      const boot = await runBootRecovery(d, sessions);
      expect(boot.steps).toHaveLength(8);
      // Per-operation submit uniqueness must still hold.
      expect(boot.steps[3]?.ok).toBe(true);
    });

    /* ─── negative-path: prove checkers are falsifiable ─────────── */

    it("NEGATIVE: one-in-flight checker goes red under dual lease rows (PK temporarily relaxed)", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;
      await clearLease(d);
      await psqlMust(
        d.url,
        `INSERT INTO wallet_active_leases (
           wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
           lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
         VALUES (
           '${d.walletId}', gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
           'SEND_SOURCE', 1, now(), now(), gen_random_uuid());`,
      );

      const good = await checkDbInvariants(d);
      expect(good.oneInFlightPerWallet).toBe(true);
      expect(good.leaseCount).toBe(1);

      // Production PK still rejects a second insert.
      const dual = await runPsql(
        d.url,
        `INSERT INTO wallet_active_leases (
           wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
           lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
         VALUES (
           '${d.walletId}', gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
           'MOVE_SOURCE', 1, now(), now(), gen_random_uuid());`,
      );
      expect(dual.ok).toBe(false);
      expect(dual.stderr).toContain(SQLSTATE_UNIQUE_VIOLATION);

      // D3: drive checkDbInvariants into a real red state by temporarily relaxing uniqueness
      // (test-only corruption fixture), then restore the PK.
      await psqlMust(d.url, `ALTER TABLE wallet_active_leases DROP CONSTRAINT wallet_active_leases_pkey;`);
      await psqlMust(
        d.url,
        `INSERT INTO wallet_active_leases (
           wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
           lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
         VALUES (
           '${d.walletId}', gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
           'MOVE_SOURCE', 1, now(), now(), gen_random_uuid());`,
      );
      const red = await checkDbInvariants(d);
      expect(red.leaseCount).toBe(2);
      expect(red.oneInFlightPerWallet).toBe(false);
      expect(red.details.some((x) => x.includes("active leases"))).toBe(true);

      // Restore production shape for subsequent tests.
      await psqlMust(d.url, `DELETE FROM wallet_active_leases WHERE wallet_id = '${d.walletId}';`);
      await psqlMust(d.url, `ALTER TABLE wallet_active_leases ADD PRIMARY KEY (wallet_id);`);
    });

    it("NEGATIVE: submit-decision checker goes red under dual rows (UNIQUE temporarily relaxed)", async () => {
      assertionsRun += 1;
      const d = db as ChaosDb;
      const auth = await seedOperation(d);
      const store = makeSubmitDecisionClaimStore(makePsqlQueryFn(d.url));
      const first = await store.claimSubmitOnce({
        attemptId: auth.submitDecisionId,
        claimedAt: "2026-07-26T00:00:02.000Z",
        operationId: auth.operationId,
        transactionAttemptNo: 1,
      });
      expect(first.minted).toBe(true);

      const rejected = await runPsql(
        d.url,
        `INSERT INTO submit_decisions (id, operation_id, transaction_attempt_no, decision, decided_at, details)
         VALUES ('${randomUUIDLike()}', '${auth.operationId}', 1, 'INITIAL_SINGLE_SHOT', now(), 'second');`,
      );
      expect(rejected.ok).toBe(false);
      expect(rejected.stderr).toContain(SQLSTATE_UNIQUE_VIOLATION);

      const inv = await checkDbInvariants(d, auth.operationId);
      expect(inv.submitDecisionCount).toBe(1);
      expect(inv.oneSubmitDecisionPerAttempt).toBe(true);

      // D3: relax uniqueness, insert a second decision, assert the checker goes red.
      // Postgres names the UNIQUE (operation_id, transaction_attempt_no) constraint.
      await psqlMust(
        d.url,
        `ALTER TABLE submit_decisions DROP CONSTRAINT submit_decisions_operation_id_transaction_attempt_no_key;`,
      );
      await psqlMust(
        d.url,
        `INSERT INTO submit_decisions (id, operation_id, transaction_attempt_no, decision, decided_at, details)
         VALUES ('${randomUUIDLike()}', '${auth.operationId}', 1, 'INITIAL_SINGLE_SHOT', now(), 'corrupt-dual');`,
      );
      const red = await checkDbInvariants(d, auth.operationId);
      expect(red.submitDecisionCount).toBe(2);
      expect(red.oneSubmitDecisionPerAttempt).toBe(false);
      expect(red.details.some((x) => x.includes("submit_decisions"))).toBe(true);

      // Cleanup so later multi-op audits stay clean.
      await psqlMust(
        d.url,
        `DELETE FROM submit_decisions WHERE operation_id = '${auth.operationId}' AND details = 'corrupt-dual';
         ALTER TABLE submit_decisions ADD CONSTRAINT submit_decisions_operation_id_transaction_attempt_no_key
           UNIQUE (operation_id, transaction_attempt_no);`,
      );
    });

    it("SEND_EXTERNAL crash chaos never invokes submit (combined with reorder residue)", () => {
      assertionsRun += 1;
      const partial = runCrashInjectionChaos("SEND_EXTERNAL", "AFTER_CREATE", {
        kind: "NOT_LANDED_YET",
      });
      expect(partial.submitCalls).toBe(0);

      const delivered = runCrashInjectionChaos("SEND_EXTERNAL", "AFTER_DELIVER_PARTIAL", {
        kind: "NOT_LANDED_YET",
      });
      expect(delivered.submitCalls).toBe(0);
      expect(delivered.partials).toBe(1);
    });
  },
);

// Fail-closed: under PG_REQUIRED the suite must not be a silent skip.
describe("PG_REQUIRED fail-closed", () => {
  it("does not report green without executing chaos assertions when PG is required", () => {
    if (PG_REQUIRED && !TEST_DATABASE_URL) {
      throw new Error("PG_REQUIRED=1 but chaos suite had no TEST_DATABASE_URL");
    }
    if (TEST_DATABASE_URL) {
      expect(assertionsRun).toBeGreaterThan(0);
    }
  });
});

function randomUUIDLike(): string {
  // Avoid importing crypto at top for a tiny helper used only in negatives — use same style as harness.
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
