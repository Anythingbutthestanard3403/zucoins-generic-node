// Adversarial concurrency and stress over the receive pool.
//
// Governing: (the single-active-lease invariant) and (the limits under
// test); (the sequence being raced);
// (backpressure under test); (real
// database concurrency, "not mocked locks").
//
// WHAT MAKES THIS A REAL RACE. Every contender is a separate `psql` OS process holding its own
// server-side transaction, so two allocators genuinely sit inside overlapping transactions and
// the winner is decided by PostgreSQL. An in-process fake — a Map guarded by `Promise.resolve()`
// microtasks — cannot interleave on a single-threaded event loop, so "exactly one winner" holds
// there trivially and can never falsify a lock defect. That is why the prior in-memory attempt
// at this ticket was unfalsifiable rather than merely thin.
//
// WHAT MAKES THE ASSERTIONS BIND. Every race asserts the TYPED failure the mechanism under test
// produces — `RECEIVE_ALREADY_ASSIGNED`, `LeaseError[ALREADY_LEASED]` — never a bare
// unique-violation SQLSTATE. A suite that only asserts "the second one failed somehow" stays
// green when the lock is deleted, because `operation_wallets`' UNIQUE catches the loser anyway;
// it would then be passing for a reason unrelated to the mechanism it claims to prove. The
// mutation evidence in the PR body shows each typed assertion going red when its lock is removed.
//
// Connectivity: TEST_DATABASE_URL (root vitest.global-setup) or PG_REQUIRED fail-closed.
// DB-TEST-03: second active lease fails including cross-operation-kind races


import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  LeaseError,
  assertLeaseFoundationReady,
  migrateLeaseFoundation,
  releaseLease,
} from "../../src/leases/index.ts";
import {
  RECEIVE_ALLOCATOR_STATEMENTS,
  ReceiveAllocatorError,
  admitReceive,
  assignReceiveWallet,
  countUnassignedReceives,
  promoteQueuedReceives,
  selectQueuedReceivesFifo,
  type AssignReceiveWalletOutcome,
  type ReceiveQueueLimits,
} from "../../src/receive/pool-allocator.ts";
import {
  MINT_BATCH_LIMIT,
  collectPoolPressureMetrics,
  expireQueueAgedReceives,
  planPoolScaleUp,
  runPoolScaleUp,
  selectQueueExpiredReceives,
  type PoolScalerLimits,
} from "../../src/receive/pool-scaler.ts";
import {
  PsqlExecutor,
  PsqlSessionExecutor,
  psqlMust,
  runPsql,
  withDatabase,
  withTx,
} from "../psql-harness.ts";
import {
  LEASES,
  OP,
  OWNER,
  RESET_POOL,
  applyPoolSchema,
  countRows,
  driveReceiveToLanded,
  insertReceiveOnTx,
  mintingPort,
  readPoolInvariants,
  releaseWithLandedProof,
  seedReceive,
  seedReceives,
  seedRegistry,
  seedWallets,
  walletState,
  type ReleasableLease,
  type SeededPool,
} from "./pool-fixture.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const POOL_CAP = 40;
const ELIGIBLE = 24;
const SEEDED_TOTAL = ELIGIBLE + 2;
const QUEUE_CAP = 8;
const MAX_WAIT_SECS = 30;

const QUEUE_LIMITS: ReceiveQueueLimits = {
  receiveQueueCap: QUEUE_CAP,
  receiveQueueMaxWaitSecs: MAX_WAIT_SECS,
};
const SCALER_LIMITS: PoolScalerLimits = {
  poolCapTotal: POOL_CAP,
  receiveQueueMaxWaitSecs: MAX_WAIT_SECS,
};

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;
let pool: SeededPool;

/** Opens `count` independent psql sessions, runs `body` on all of them at once, then closes. */
async function withConcurrentSessions<T>(
  count: number,
  body: (sessions: readonly PsqlSessionExecutor[]) => Promise<T>,
): Promise<T> {
  const sessions = Array.from({ length: count }, () => new PsqlSessionExecutor(dbUrl));
  try {
    for (const s of sessions) s.start();
    return await body(sessions);
  } finally {
    for (const s of sessions) s.stop();
  }
}

/** One allocator worker: its own transaction, committed or rolled back independently. */
async function allocateOn(
  session: PsqlSessionExecutor,
  operationId: string,
): Promise<AssignReceiveWalletOutcome | Error> {
  await session.begin();
  try {
    const outcome = await assignReceiveWallet(session, {
      operationId,
      ownerInstanceId: OWNER,
      leases: LEASES,
    });
    await session.commit();
    return outcome;
  } catch (err) {
    await session.rollback();
    return err as Error;
  }
}

/** Re-asserts the aggregate invariant: one lease per wallet, one RECEIVER per receive, cap held. */
function expectPoolInvariants(expected: { readonly activeLeases?: number } = {}): void {
  const inv = readPoolInvariants(dbUrl);
  // "at most one active lease row per wallet_id".
  expect(inv.distinctLeasedWallets).toBe(inv.activeLeases);
  // step 2 — one RECEIVER attachment per receive, never two.
  expect(inv.distinctReceiverOperations).toBe(inv.receiverAttachments);
  // leased and PINNED move together; neither half survives alone.
  expect(inv.pinnedWithoutLease).toBe(0);
  expect(inv.leasedNotPinned).toBe(0);
  // rule 2 — cap counts every wallet, pinned included, and is never exceeded.
  expect(inv.capCount).toBeLessThanOrEqual(POOL_CAP);
  // no receive row survived in a shape the frozen CHECK forbids.
  expect(inv.illegalReceiveRows).toBe(0);
  if (expected.activeLeases !== undefined) expect(inv.activeLeases).toBe(expected.activeLeases);
}

describe("receive-pool admission and reservation races (real PG / separate processes)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error(
          "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup provisioned no test database",
        );
      }
      return;
    }
    dbName = `pool_race_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);
    applyPoolSchema(dbUrl);
    seedRegistry(dbUrl);
    pool = seedWallets(dbUrl, { eligibleCount: ELIGIBLE });
    await migrateLeaseFoundation(db);
    await assertLeaseFoundationReady(db);
  }, 120_000);

  afterAll(() => {
    // Scoped to this run's own database only — a broader DROP takes out concurrent lanes
    // sharing the server.
    if (!live || dbName === "") return;
    try {
      runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    } catch {
      // Best-effort cleanup under shared PostgreSQL test contention.
    }
  });

  it("skips cleanly only when Postgres is absent and not required", () => {
    if (live) {
      expect(dbUrl.length).toBeGreaterThan(0);
      return;
    }
    expect(PG_REQUIRED).toBe(false);
  });

  // ── S1. Burst create → assign → land → release ────────────────────────────

  it.skipIf(!live)(
    "S1 burst: 18 receives created, assigned, landed and released concurrently end in exactly one legal state each",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const burst = Array.from({ length: 18 }, (_v, i) => OP(2000 + i));
      seedReceives(dbUrl, burst.map((operationId) => ({ operationId })));

      // Six allocator workers drain the burst in parallel, three receives each.
      const assignments = await withConcurrentSessions(6, async (sessions) =>
        (
          await Promise.all(
            sessions.map(async (session, w) => {
              const mine: Array<{ operationId: string; outcome: AssignReceiveWalletOutcome }> = [];
              for (let i = w; i < burst.length; i += sessions.length) {
                const outcome = await allocateOn(session, burst[i]!);
                if (outcome instanceof Error) throw outcome;
                mine.push({ operationId: burst[i]!, outcome });
              }
              return mine;
            }),
          )
        ).flat(),
      );

      expect(assignments).toHaveLength(18);
      const assigned = assignments.filter((a) => a.outcome.kind === "ASSIGNED");
      expect(assigned).toHaveLength(18); // 24 eligible wallets, 18 receives — none starved

      // No wallet was handed to two receives. This is the duplicate-assignment assertion the
      // whole family exists for, measured over a real 18-way concurrent drain.
      const walletIds = assigned.map((a) =>
        a.outcome.kind === "ASSIGNED" ? a.outcome.walletId : "",
      );
      expect(new Set(walletIds).size).toBe(18);
      expectPoolInvariants({ activeLeases: 18 });

      // Land and release every one of them, concurrently, through the proof-backed path.
      const releasable: ReleasableLease[] = assigned.map((a) => {
        const o = a.outcome as Extract<AssignReceiveWalletOutcome, { kind: "ASSIGNED" }>;
        driveReceiveToLanded(dbUrl, a.operationId, o.walletId);
        return {
          operationId: a.operationId,
          walletId: o.walletId,
          membershipId: o.membershipId,
          leaseGroupId: o.leaseGroupId,
          leaseEpoch: o.leaseEpoch,
        };
      });
      await withConcurrentSessions(6, async (sessions) => {
        await Promise.all(
          sessions.map(async (session, w) => {
            for (let i = w; i < releasable.length; i += sessions.length) {
              await session.begin();
              await releaseWithLandedProof(session, releasable[i]!);
              await session.commit();
            }
          }),
        );
      });

      // The pool is whole again: no lease anywhere, every wallet back to AVAILABLE, and every
      // receive in the one terminal shape permits.
      expectPoolInvariants({ activeLeases: 0 });
      expect(countRows(dbUrl, "wallets", "state <> 'AVAILABLE'")).toBe(0);
      expect(
        countRows(dbUrl, "operations", `kind = 'RECEIVE_EXTERNAL' AND status = 'RECEIVE_LANDED'`),
      ).toBe(18);
      expect(countRows(dbUrl, "operations", `status NOT IN ('RECEIVE_LANDED')`)).toBe(0);
      psqlMust(dbUrl, RESET_POOL);
    },
    180_000,
  );

  it.skipIf(!live)(
    "S1 negative: a release without its TRUSTED_VERIFIER proof is refused — no impatience path exists",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const operationId = OP(2100);
      seedReceive(dbUrl, operationId);
      const outcome = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
      );
      expect(outcome.kind).toBe("ASSIGNED");
      if (outcome.kind !== "ASSIGNED") return;
      driveReceiveToLanded(dbUrl, operationId, outcome.walletId);

      // One in-flight claim per wallet: heartbeat expiry, process death and operator impatience never release a
      // lease. A caller inventing a proof id gets a typed refusal, not a release.
      const failure = await withTx(dbUrl, async (tx) => {
        try {
          await releaseLease(tx, {
            walletId: outcome.walletId,
            ownerInstanceId: OWNER,
            operationId,
            membershipId: outcome.membershipId,
            leaseGroupId: outcome.leaseGroupId,
            leaseEpoch: outcome.leaseEpoch,
            releaseProofId: randomUUID(),
            releaseReason: "impatience",
          });
          return null;
        } catch (err) {
          return err as Error;
        }
      });
      expect(failure).toBeInstanceOf(LeaseError);
      expect((failure as LeaseError).reason).toBe("PROOF_NOT_FOUND");
      expect(walletState(dbUrl, outcome.walletId)).toBe("PINNED");
      expectPoolInvariants({ activeLeases: 1 });
      psqlMust(dbUrl, RESET_POOL);
    },
    90_000,
  );

  it.skipIf(!live)(
    "S1 expire: queue-age past RECEIVE_QUEUE_MAX_WAIT flips CREATED→EXPIRED in FIFO order under concurrent assign",
    async () => {
      // AC bullet 1 — create/arm/expire/release. The scaler suite covers the unit path;
      // here the stress case is age-out racing assignment: expired ids leave the queue
      // without a wallet or lease, and a concurrent assigner cannot revive them.
      psqlMust(dbUrl, RESET_POOL);
      const aged = [
        { operationId: OP(2151), age: MAX_WAIT_SECS + 40 },
        { operationId: OP(2152), age: MAX_WAIT_SECS + 30 },
        { operationId: OP(2153), age: MAX_WAIT_SECS + 20 },
      ];
      const fresh = OP(2154);
      const assignedHold = OP(2155);
      seedReceives(dbUrl, [
        ...aged.map((r) => ({
          operationId: r.operationId,
          createdAtSql: `now() - interval '${r.age} seconds'`,
        })),
        { operationId: fresh, createdAtSql: "now()" },
        {
          operationId: assignedHold,
          createdAtSql: `now() - interval '${MAX_WAIT_SECS + 50} seconds'`,
        },
      ]);
      // Pin one old receive to a wallet first — queue-age expiry must never touch it
      // (READY→EXPIRED is a different path).
      const held = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, {
          operationId: assignedHold,
          ownerInstanceId: OWNER,
          leases: LEASES,
        }),
      );
      expect(held.kind).toBe("ASSIGNED");

      const selected = await selectQueueExpiredReceives(db, { limits: SCALER_LIMITS });
      expect(selected.map((e) => e.operationId)).toEqual(aged.map((r) => r.operationId));
      expect(selected.every((e) => e.waitedSecs > MAX_WAIT_SECS)).toBe(true);

      const emitted: string[] = [];
      const [expireResult, lateAssign] = await Promise.all([
        withTx(dbUrl, (tx) =>
          expireQueueAgedReceives(tx, {
            limits: SCALER_LIMITS,
            emitExpired: async (_db, p) => {
              emitted.push(p.operationId);
            },
          }),
        ),
        // A concurrent allocator racing the expire pass must not resurrect an aged id.
        withConcurrentSessions(1, async ([session]) => {
          const outcome = await allocateOn(session!, fresh);
          return outcome;
        }),
      ]);

      expect(expireResult.expired.map((e) => e.operationId)).toEqual(
        aged.map((r) => r.operationId),
      );
      expect(emitted).toEqual(aged.map((r) => r.operationId));
      expect(expireResult.skipped).toEqual([]);

      for (const r of aged) {
        expect(countRows(dbUrl, "operations", `id = '${r.operationId}' AND status = 'EXPIRED'`)).toBe(
          1,
        );
        expect(
          countRows(
            dbUrl,
            "operations",
            `id = '${r.operationId}' AND receiver_wallet_id IS NULL
               AND expiry_unix_time_secs IS NULL AND t0_observation_id IS NULL`,
          ),
        ).toBe(1);
        expect(countRows(dbUrl, "operation_wallets", `operation_id = '${r.operationId}'`)).toBe(0);
      }
      // Fresh receive either assigned or still CREATED — never EXPIRED.
      expect(countRows(dbUrl, "operations", `id = '${fresh}' AND status = 'EXPIRED'`)).toBe(0);
      if (!(lateAssign instanceof Error) && lateAssign.kind === "ASSIGNED") {
        expect(countRows(dbUrl, "operations", `id = '${fresh}' AND status = 'CREATED'`)).toBe(1);
      }
      // Held assigned receive still leased, not expired.
      expect(
        countRows(dbUrl, "operations", `id = '${assignedHold}' AND status = 'EXPIRED'`),
      ).toBe(0);
      expectPoolInvariants({
        activeLeases:
          1 + (!(lateAssign instanceof Error) && lateAssign.kind === "ASSIGNED" ? 1 : 0),
      });
      // Idempotent second pass.
      const again = await withTx(dbUrl, (tx) =>
        expireQueueAgedReceives(tx, {
          limits: SCALER_LIMITS,
          emitExpired: async () => {
            throw new Error("must not re-emit");
          },
        }),
      );
      expect(again.expired).toEqual([]);
      psqlMust(dbUrl, RESET_POOL);
    },
    180_000,
  );

  // ── S2. Exhaust the pool ──────────────────────────────────────────────────

  it.skipIf(!live)(
    "S2 exhaustion: with the pool drained, concurrent admissions fill the queue to RECEIVE_QUEUE_CAP and no further",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // Drain the pool by quarantining every eligible wallet. Quarantine, not PIN, is how the
      // fixtures narrow the pool throughout this suite: a PINNED wallet with no lease row is the
      // split-brain `expectPoolInvariants` exists to catch, so faking one to shrink the
      // pool would blind the very invariant under test.
      psqlMust(
        dbUrl,
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'fixture: pool drained'
          WHERE state = 'AVAILABLE';`,
      );
      expect(countRows(dbUrl, "wallets", "state = 'AVAILABLE'")).toBe(0);

      // Twelve admissions race for eight queue slots, each from its own OS process.
      // Every session COMMITS — including QUEUE_FULL. Rolling the refusal back would hide an
      // insert-then-refuse defect in admitReceive (M5): the orphan row dies with the rollback
      // and `operations == QUEUE_CAP` stays green for the wrong reason. Committing is what
      // makes "rejected admission creates NOTHING" falsifiable against the live code path.
      const candidates = Array.from({ length: 12 }, (_v, i) => OP(2200 + i));
      const outcomes = await withConcurrentSessions(12, async (sessions) =>
        Promise.all(
          sessions.map(async (session, i) => {
            await session.begin();
            try {
              const result = await admitReceive(session, {
                limits: QUEUE_LIMITS,
                insertOperation: insertReceiveOnTx(candidates[i]!),
              });
              await session.commit();
              return result;
            } catch (err) {
              await session.rollback();
              throw err;
            }
          }),
        ),
      );

      const admitted = outcomes.filter((o) => o.kind === "ADMITTED");
      const refused = outcomes.filter((o) => o.kind === "QUEUE_FULL");
      expect(admitted).toHaveLength(QUEUE_CAP);
      expect(refused).toHaveLength(12 - QUEUE_CAP);

      // The refusal is the typed 503 shape step 3 requires, with a Retry-After a caller
      // can act on — not a generic error.
      for (const r of refused) {
        expect(r.kind).toBe("QUEUE_FULL");
        if (r.kind !== "QUEUE_FULL") continue;
        expect(r.httpStatus).toBe(503);
        expect(r.errorCode).toBe("receive_queue_full");
        expect(r.retryAfterSecs).toBe(MAX_WAIT_SECS);
      }
      for (const a of admitted) {
        if (a.kind === "ADMITTED") expect(a.httpStatus).toBe(202);
      }

      // "Queue overflow returns 503 and creates NOTHING" — exactly the admitted receives exist
      // after every contender committed, and no lease or attachment was left behind by a
      // rejected admission. If insertOperation ran before the cap gate, the four refused
      // sessions would each leave an orphan CREATED row and this count would be 12.
      expect(countRows(dbUrl, "operations")).toBe(QUEUE_CAP);
      expect(countRows(dbUrl, "operation_wallets")).toBe(0);
      expect(await countUnassignedReceives(db)).toBe(QUEUE_CAP);
      // No refused candidate id may appear in the table — the insert never ran for them.
      const admittedIds = new Set(
        outcomes.flatMap((o, i) => (o.kind === "ADMITTED" ? [candidates[i]!] : [])),
      );
      expect(admittedIds.size).toBe(QUEUE_CAP);
      for (const id of candidates) {
        if (!admittedIds.has(id)) {
          expect(countRows(dbUrl, "operations", `id = '${id}'`)).toBe(0);
        }
      }
      expectPoolInvariants({ activeLeases: 0 });

      // Allocation genuinely cannot proceed while the pool is empty — the queue is the only
      // outcome, and the cap is what bounds it.
      const head = (await selectQueuedReceivesFifo(db, 1))[0]!;
      const starved = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId: head, ownerInstanceId: OWNER, leases: LEASES }),
      );
      expect(starved.kind).toBe("NO_ELIGIBLE_WALLET");
      expectPoolInvariants({ activeLeases: 0 });
      psqlMust(dbUrl, RESET_POOL);
    },
    180_000,
  );

  // ── S3. Allocators racing allocators, and allocators racing the scaler ────

  it.skipIf(!live)(
    "S3 reservation race: eight allocators contend for two wallets — exactly two win, six get NO_ELIGIBLE_WALLET",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // Shrink the eligible pool to two wallets; eight receives chase them at once.
      const keep = pool.eligible.slice(0, 2);
      psqlMust(
        dbUrl,
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'fixture: pool narrowed'
          WHERE state = 'AVAILABLE' AND id NOT IN (${keep.map((id) => `'${id}'`).join(",")});`,
      );
      const contenders = Array.from({ length: 8 }, (_v, i) => OP(2300 + i));
      seedReceives(dbUrl, contenders.map((operationId) => ({ operationId })));

      const results = await withConcurrentSessions(8, async (sessions) =>
        Promise.all(sessions.map((session, i) => allocateOn(session, contenders[i]!))),
      );

      const won = results.filter(
        (r): r is Extract<AssignReceiveWalletOutcome, { kind: "ASSIGNED" }> =>
          !(r instanceof Error) && r.kind === "ASSIGNED",
      );
      const starved = results.filter((r) => !(r instanceof Error) && r.kind === "NO_ELIGIBLE_WALLET");
      const errored = results.filter((r) => r instanceof Error);

      expect(won).toHaveLength(2);
      expect(new Set(won.map((w) => w.walletId))).toEqual(new Set(keep));
      // Under contention the losers report "pool empty". Final-state alone does not distinguish
      // SKIP LOCKED from plain FOR UPDATE (losers block then re-evaluate under READ COMMITTED);
      // the next test binds the non-serialising half.
      expect(starved).toHaveLength(6);
      expect(errored).toHaveLength(0);
      expectPoolInvariants({ activeLeases: 2 });
      psqlMust(dbUrl, RESET_POOL);
    },
    180_000,
  );

  it.skipIf(!live)(
    "S3 SKIP LOCKED: a second allocator takes a different wallet while the first still holds its row lock",
    async () => {
      // D2 / M1. Final-state alone cannot distinguish SKIP LOCKED from plain FOR UPDATE
      // losers block, re-evaluate under READ COMMITTED after the winner commits, and still
      // report NO_ELIGIBLE_WALLET / distinct wallets. The observable difference is whether a
      // second session can SELECT while the first's row lock is still held:
      // - WITH SKIP LOCKED: B skips A's locked row, takes the next free wallet, returns.
      // - WITHOUT: B blocks on A's row until statement_timeout (or A commits).
      // This is the same binding pattern negative control uses; the stress suite
      // re-proves it through assignReceiveWallet (full path), not the bare SELECT.
      psqlMust(dbUrl, RESET_POOL);
      const keep = pool.eligible.slice(0, 2);
      psqlMust(
        dbUrl,
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'fixture: pool narrowed'
          WHERE state = 'AVAILABLE' AND id NOT IN (${keep.map((id) => `'${id}'`).join(",")});`,
      );
      const opA = OP(2310);
      const opB = OP(2311);
      seedReceives(dbUrl, [{ operationId: opA }, { operationId: opB }]);

      const a = new PsqlSessionExecutor(dbUrl);
      const b = new PsqlSessionExecutor(dbUrl);
      try {
        a.start();
        b.start();
        await a.begin();
        await b.begin();

        // A selects and locks one eligible wallet but does not commit — the row lock stays.
        // Drive only the SELECT half so the lock is held without finishing the full assign
        // (which would PIN the wallet and make B's eligibility predicate skip it for a reason
        // unrelated to SKIP LOCKED).
        const first = await a.query<{ id: string }>(
          RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
        );
        expect(first.rows[0]?.id).toBeDefined();
        const lockedId = first.rows[0]!.id;

        // B must not block. statement_timeout turns a plain-FOR-UPDATE hang into a fast red.
        await b.query("SET LOCAL statement_timeout = '2s'");
        const started = Date.now();
        const second = await b.query<{ id: string }>(
          RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
        );
        const elapsedMs = Date.now() - started;

        expect(second.rows[0]?.id).toBeDefined();
        expect(second.rows[0]!.id).not.toBe(lockedId);
        expect([lockedId, second.rows[0]!.id].sort()).toEqual([...keep].sort());
        expect(elapsedMs).toBeLessThan(1_500);

        await a.rollback();
        await b.rollback();
      } finally {
        a.stop();
        b.stop();
      }
      expectPoolInvariants({ activeLeases: 0 });
      psqlMust(dbUrl, RESET_POOL);
    },
    60_000,
  );

  it.skipIf(!live)(
    "S3 lost-update race: six allocators on the SAME receive — one assigns, five raise RECEIVE_ALREADY_ASSIGNED",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const operationId = OP(2400);
      seedReceive(dbUrl, operationId);

      const results = await withConcurrentSessions(6, async (sessions) =>
        Promise.all(sessions.map((session) => allocateOn(session, operationId))),
      );

      const won = results.filter((r) => !(r instanceof Error) && r.kind === "ASSIGNED");
      const losers = results.filter((r): r is Error => r instanceof Error);
      expect(won).toHaveLength(1);
      expect(losers).toHaveLength(5);

      // The typed assertion, deliberately: every loser must die on the allocator's own
      // CREATED/unassigned recheck, taken while it holds the operation row lock. Asserting only
      // "it threw" would stay green with the FOR UPDATE deleted, because operation_wallets'
      // UNIQUE would catch the loser anyway — passing for a reason unrelated to the lock.
      for (const err of losers) {
        expect(err).toBeInstanceOf(ReceiveAllocatorError);
        expect((err as ReceiveAllocatorError).reason).toBe("RECEIVE_ALREADY_ASSIGNED");
        expect((err as ReceiveAllocatorError).operationId).toBe(operationId);
        expect(err.message).not.toMatch(/duplicate key value|unique constraint/i);
      }

      // Exactly one wallet was consumed, not six, and exactly one attachment exists.
      expect(countRows(dbUrl, "operation_wallets", `operation_id = '${operationId}'`)).toBe(1);
      expectPoolInvariants({ activeLeases: 1 });
      psqlMust(dbUrl, RESET_POOL);
    },
    180_000,
  );

  it.skipIf(!live)(
    "DB-TEST-03: second active lease fails including cross-operation-kind races (ALREADY_LEASED)",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const first = OP(2500);
      const second = OP(2501);
      seedReceives(dbUrl, [{ operationId: first }, { operationId: second }]);
      // One eligible wallet, two receives: the second must be refused the wallet, not share it.
      const keep = pool.eligible[0]!;
      psqlMust(
        dbUrl,
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'fixture: pool narrowed'
          WHERE state = 'AVAILABLE' AND id <> '${keep}';`,
      );

      const held = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId: first, ownerInstanceId: OWNER, leases: LEASES }),
      );
      expect(held.kind).toBe("ASSIGNED");

      // The wallet is PINNED now, so the eligibility predicate no longer returns it and the
      // second receive falls through the backpressure ladder rather than colliding.
      const next = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId: second, ownerInstanceId: OWNER, leases: LEASES }),
      );
      expect(next.kind).toBe("NO_ELIGIBLE_WALLET");

      // And if a caller reaches around the predicate and demands that exact wallet, the database
      // refuses with the typed reason — the invariant is structural, not merely upstream.
      const direct = await withTx(dbUrl, async (tx) => {
        try {
          await LEASES.acquireReceiveWindowLease(tx, {
            walletId: held.kind === "ASSIGNED" ? held.walletId : "",
            leaseGroupId: await LEASES.createLeaseGroup(tx, second),
            operationId: second,
            ownerInstanceId: OWNER,
          });
          return null;
        } catch (err) {
          return err as Error;
        }
      });
      expect(direct).toBeInstanceOf(LeaseError);
      expect((direct as LeaseError).reason).toBe("ALREADY_LEASED");
      expectPoolInvariants({ activeLeases: 1 });
      psqlMust(dbUrl, RESET_POOL);
    },
    180_000,
  );

  it.skipIf(!live)(
    "S3 allocator-vs-scaler: allocators and the scaler run against one pool and the cap still holds",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // Fill toward the cap so a stale mint decision WOULD cross it, and leave a handful of
      // eligible wallets for the allocators to fight over at the same time.
      const headroom = MINT_BATCH_LIMIT;
      const filler = POOL_CAP - headroom - SEEDED_TOTAL;
      psqlMust(
        dbUrl,
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
           VALUES ${Array.from({ length: filler }, (_v, i) => i)
             .map(
               (i) =>
                 `('f0000000-0000-4000-8000-${String(2600 + i).padStart(12, "0")}',
                   (SELECT node_id FROM wallets LIMIT 1),
                   '${"A".repeat(38)}RS${String(i).padStart(3, "0")}=',
                   'node_generated', 'AVAILABLE')`,
             )
             .join(",")};`,
      );
      const keep = pool.eligible.slice(0, 4);
      psqlMust(
        dbUrl,
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'fixture: pool narrowed'
          WHERE state = 'AVAILABLE'
            AND recovery_verified_at IS NOT NULL
            AND id NOT IN (${keep.map((id) => `'${id}'`).join(",")});`,
      );
      const receives = Array.from({ length: 6 }, (_v, i) => OP(2600 + i));
      seedReceives(dbUrl, receives.map((operationId) => ({ operationId })));
      // A standing backlog, so `open_sessions` actually drives the target up to the cap.
      // Without it the target sits far below the current pool and the scaler correctly decides
      // zero — which would make the minting half of this race vacuous rather than proven.
      seedReceives(
        dbUrl,
        Array.from({ length: 36 }, (_v, i) => ({ operationId: OP(2650 + i) })),
      );
      const startCap = countRows(dbUrl, "wallets");
      expect(startCap).toBe(POOL_CAP - headroom);
      // Demand really does reach the cap, so `mint_count` is bounded by headroom, not by target.
      expect((await withTx(dbUrl, (tx) => planPoolScaleUp(tx, SCALER_LIMITS))).poolTargetTotal).toBe(
        POOL_CAP,
      );

      // Six allocators and two scalers, all at once, all in separate processes.
      const [allocResults, scaleResults] = await Promise.all([
        withConcurrentSessions(6, async (sessions) =>
          Promise.all(sessions.map((session, i) => allocateOn(session, receives[i]!))),
        ),
        withConcurrentSessions(2, async (sessions) =>
          Promise.all(
            sessions.map(async (session, i) => {
              await session.begin();
              try {
                const result = await runPoolScaleUp(session, {
                  limits: SCALER_LIMITS,
                  mint: mintingPort(3000 + i * 100).mint,
                });
                await session.commit();
                return result;
              } catch (err) {
                await session.rollback();
                throw err;
              }
            }),
          ),
        ),
      ]);

      // Four wallets, six contenders: four assign, two find the pool empty, none error.
      const won = allocResults.filter(
        (r): r is Extract<AssignReceiveWalletOutcome, { kind: "ASSIGNED" }> =>
          !(r instanceof Error) && r.kind === "ASSIGNED",
      );
      expect(won).toHaveLength(4);
      expect(new Set(won.map((w) => w.walletId)).size).toBe(4);
      expect(allocResults.filter((r) => r instanceof Error)).toHaveLength(0);

      // The two scalers serialised on the advisory lock: their mint counts sum to the headroom
      // that actually existed, never to twice it. Concurrent Promise.all is the load case;
      // the next test binds LOCK_SCALE_UP deterministically (blocking, not timing-lucky).
      const minted = scaleResults.reduce((n, r) => n + r.mintedWalletIds.length, 0);
      expect(minted).toBe(headroom);
      expect(scaleResults.map((r) => r.plan.mintCount).reduce((a, b) => a + b, 0)).toBe(headroom);
      expect(countRows(dbUrl, "wallets")).toBe(POOL_CAP);

      // The aggregate invariant, re-verified after the composite race.
      expectPoolInvariants({ activeLeases: 4 });
      const settled = await withTx(dbUrl, (tx) => planPoolScaleUp(tx, SCALER_LIMITS));
      expect(settled.capCount).toBe(POOL_CAP);
      expect(settled.mintCount).toBe(0);

      psqlMust(dbUrl, RESET_POOL);
      psqlMust(dbUrl, `DELETE FROM wallets WHERE id::text LIKE 'f0000000-%';`);
      expect(countRows(dbUrl, "wallets")).toBe(SEEDED_TOTAL);
    },
    240_000,
  );

  it.skipIf(!live)(
    "S3 LOCK_SCALE_UP: a second scaler blocks on the advisory lock and then sees the first one's mint",
    async () => {
      // Deterministic serialisation proof — not a timing race. A holds the
      // transaction-scoped lock across plan+mint; B's plan must not resolve until A commits.
      // Dropping LOCK_SCALE_UP to `SELECT $1::bigint` makes bSettled true before A commits
      // (and, if both mint under stale plans, cap overshoots). Runs every time, not 2/3.
      psqlMust(dbUrl, RESET_POOL);
      seedReceives(
        dbUrl,
        Array.from({ length: 36 }, (_v, i) => ({ operationId: OP(2680 + i) })),
      );
      const headroom = MINT_BATCH_LIMIT;
      const filler = POOL_CAP - headroom - SEEDED_TOTAL;
      psqlMust(
        dbUrl,
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
           VALUES ${Array.from({ length: filler }, (_v, i) => i)
             .map(
               (i) =>
                 `('f0000000-0000-4000-8000-${String(2680 + i).padStart(12, "0")}',
                   (SELECT node_id FROM wallets LIMIT 1),
                   '${"A".repeat(38)}LK${String(i).padStart(3, "0")}=',
                   'node_generated', 'AVAILABLE')`,
             )
             .join(",")};`,
      );
      expect(countRows(dbUrl, "wallets")).toBe(POOL_CAP - headroom);

      const a = new PsqlSessionExecutor(dbUrl);
      const b = new PsqlSessionExecutor(dbUrl);
      try {
        a.start();
        b.start();
        await a.begin();
        await b.begin();

        const aResult = await runPoolScaleUp(a, {
          limits: SCALER_LIMITS,
          mint: mintingPort(3100).mint,
        });
        expect(aResult.plan.mintCount).toBe(headroom);
        expect(aResult.mintedWalletIds).toHaveLength(headroom);

        // B asks for its plan while A still holds the lock. Do not await yet.
        const bPlan = planPoolScaleUp(b, SCALER_LIMITS);
        let bSettled = false;
        void bPlan.then(() => {
          bSettled = true;
        });
        await new Promise((r) => setTimeout(r, 400));
        expect(bSettled).toBe(false);

        await a.commit();
        const planB = await bPlan;
        expect(planB.capCount).toBe(POOL_CAP);
        expect(planB.mintCount).toBe(0);
        await b.commit();
      } finally {
        a.stop();
        b.stop();
      }

      expect(countRows(dbUrl, "wallets")).toBe(POOL_CAP);
      expectPoolInvariants({ activeLeases: 0 });
      psqlMust(dbUrl, RESET_POOL);
      psqlMust(dbUrl, `DELETE FROM wallets WHERE id::text LIKE 'f0000000-%';`);
    },
    180_000,
  );

  // ── S4. Restart the queue promoter mid-promotion ──────────────────────────

  it.skipIf(!live)(
    "S4 restart: a promoter that dies mid-pass resumes in FIFO sequence, promoting nothing twice and skipping nothing",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // Nine queued receives with a deliberately scrambled insertion sequence and two sharing a
      // creation instant, so only `(created_at, operation_id)` gives a reproducible answer.
      const base = [
        { operationId: OP(2707), age: 90 },
        { operationId: OP(2701), age: 120 },
        { operationId: OP(2705), age: 100 },
        { operationId: OP(2702), age: 120 },
        { operationId: OP(2709), age: 60 },
        { operationId: OP(2703), age: 110 },
        { operationId: OP(2708), age: 70 },
        { operationId: OP(2704), age: 110 },
        { operationId: OP(2706), age: 95 },
      ];
      seedReceives(
        dbUrl,
        base.map((r) => ({
          operationId: r.operationId,
          createdAtSql: `now() - interval '${r.age} seconds'`,
        })),
      );
      const expectedSequence = await selectQueuedReceivesFifo(db, 20);
      expect(expectedSequence).toEqual([
        OP(2701),
        OP(2702),
        OP(2703),
        OP(2704),
        OP(2705),
        OP(2706),
        OP(2707),
        OP(2708),
        OP(2709),
      ]);
      // FIFO is genuinely different from insertion sequence, so the assertion has content.
      expect(expectedSequence).not.toEqual(base.map((r) => r.operationId));

      // Pass one: the promoter dies after four promotions.
      const promotedBeforeCrash: string[] = [];
      await expect(
        promoteQueuedReceives(db, {
          limits: { ...QUEUE_LIMITS, receiveQueueCap: 20 },
          allocate: async (operationId) => {
            if (promotedBeforeCrash.length === 4) throw new Error("injected promoter crash");
            const outcome = await withTx(dbUrl, (tx) =>
              assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
            );
            promotedBeforeCrash.push(operationId);
            return outcome;
          },
        }),
      ).rejects.toThrow(/injected promoter crash/);
      expect(promotedBeforeCrash).toEqual(expectedSequence.slice(0, 4));
      expectPoolInvariants({ activeLeases: 4 });

      // Pass two: a fresh promoter, no resume state. It re-reads the queue, which no longer
      // contains the four already promoted, and continues from exactly where the crash left off.
      const promotedAfterRestart: string[] = [];
      const resumed = await promoteQueuedReceives(db, {
        limits: { ...QUEUE_LIMITS, receiveQueueCap: 20 },
        allocate: async (operationId) => {
          const outcome = await withTx(dbUrl, (tx) =>
            assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
          );
          promotedAfterRestart.push(operationId);
          return outcome;
        },
      });

      expect(promotedAfterRestart).toEqual(expectedSequence.slice(4));
      expect(resumed.remaining).toEqual([]);
      // Nothing promoted twice, nothing skipped: the two passes concatenate to the exact FIFO
      // sequence, with no repeats.
      const allPromoted = [...promotedBeforeCrash, ...promotedAfterRestart];
      expect(allPromoted).toEqual(expectedSequence);
      expect(new Set(allPromoted).size).toBe(allPromoted.length);
      expect(await countUnassignedReceives(db)).toBe(0);
      expectPoolInvariants({ activeLeases: 9 });
      psqlMust(dbUrl, RESET_POOL);
    },
    240_000,
  );

  // ── S5. Quarantine injection ──────────────────────────────────────────────

  it.skipIf(!live)(
    "S5 quarantine: a quarantined wallet leaves the eligible set, keeps its one cap slot, and is never double-counted",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const target = pool.eligible[0]!;
      const capBefore = countRows(dbUrl, "wallets");

      // Enumerate eligibility by the three conjuncts directly — do not string-edit
      // SELECT_ELIGIBLE_WALLET. A replace of " FOR UPDATE SKIP LOCKED LIMIT 1" breaks when
      // SKIP LOCKED is deleted (M1) and the test fails for a text-coupling reason rather than
      // for the quarantine behaviour under test.
      const eligibleIds = async (): Promise<string[]> =>
        (
          await db.query<{ id: string }>(
            `SELECT id FROM wallets
              WHERE key_origin = 'node_generated'
                AND recovery_verified_at IS NOT NULL
                AND state = 'AVAILABLE'
              ORDER BY id`,
          )
        ).rows.map((r) => r.id);
      expect(await eligibleIds()).toContain(target);

      // Quarantine, the way an observation anomaly would.
      psqlMust(
        dbUrl,
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'unexpected head movement'
          WHERE id = '${target}';`,
      );
      expect(await eligibleIds()).not.toContain(target);

      // Cap accounting is untouched: it still holds exactly one slot, and the state census sums
      // to the cap count — a wallet cannot be counted as both pinned and retired because `state`
      // is one column, and this measures that rather than assuming it.
      expect(countRows(dbUrl, "wallets")).toBe(capBefore);
      const census = (
        await db.query<{ state: string; wallets: number }>(
          `SELECT state::text AS state, count(*)::int AS wallets FROM wallets GROUP BY state`,
        )
      ).rows;
      expect(census.reduce((n, r) => n + Number(r.wallets), 0)).toBe(capBefore);
      expect(new Set(census.map((r) => r.state)).size).toBe(census.length);

      const metrics = await collectPoolPressureMetrics(db, SCALER_LIMITS);
      expect(metrics.attentionWalletCount).toBe(1);
      expect(metrics.capCount).toBe(capBefore);
      expect(metrics.availableWalletCount).toBe(ELIGIBLE - 1);

      // A quarantined wallet is never handed out, however hard the pool is driven, and the
      // pressure surfaces never return it to AVAILABLE.
      const contenders = Array.from({ length: 6 }, (_v, i) => OP(2800 + i));
      seedReceives(dbUrl, contenders.map((operationId) => ({ operationId })));
      const results = await withConcurrentSessions(6, async (sessions) =>
        Promise.all(sessions.map((session, i) => allocateOn(session, contenders[i]!))),
      );
      const walletsTaken = results
        .filter((r): r is Extract<AssignReceiveWalletOutcome, { kind: "ASSIGNED" }> =>
          !(r instanceof Error) && r.kind === "ASSIGNED",
        )
        .map((r) => r.walletId);
      expect(walletsTaken).not.toContain(target);
      expect(new Set(walletsTaken).size).toBe(walletsTaken.length);
      expect(walletState(dbUrl, target)).toBe("QUARANTINED");
      expectPoolInvariants({ activeLeases: walletsTaken.length });
      psqlMust(dbUrl, RESET_POOL);
    },
    180_000,
  );

  it.skipIf(!live)(
    "S5 mid-lease: quarantining a leased wallet cannot silently drop its lease",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const operationId = OP(2900);
      seedReceive(dbUrl, operationId);
      const outcome = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
      );
      expect(outcome.kind).toBe("ASSIGNED");
      if (outcome.kind !== "ASSIGNED") return;

      const attempt = runPsql(
        dbUrl,
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'anomaly mid-lease'
          WHERE id = '${outcome.walletId}';`,
      );

      // Whichever way the schema rules on PINNED→QUARANTINED, the lease row must survive: a
      // quarantine that silently dropped the active lease would be a one-in-flight-per-wallet breach
      // dressed up as a safety action.
      expect(countRows(dbUrl, "wallet_active_leases", `wallet_id = '${outcome.walletId}'`)).toBe(1);
      if (attempt.ok) {
        // The transition is permitted: the wallet is now flagged for attention but still leased,
        // so the invariant "leased implies not AVAILABLE" holds and the lease is untouched.
        expect(walletState(dbUrl, outcome.walletId)).toBe("QUARANTINED");
        expect(countRows(dbUrl, "wallets", `id = '${outcome.walletId}' AND state = 'AVAILABLE'`)).toBe(
          0,
        );
      } else {
        // The transition is refused: the wallet stays PINNED and the quarantine must wait for a
        // proof-backed release. Either rule is safe; silently losing the lease is not.
        expect(walletState(dbUrl, outcome.walletId)).toBe("PINNED");
      }
      expect(countRows(dbUrl, "wallets")).toBe(SEEDED_TOTAL);
      psqlMust(dbUrl, RESET_POOL);
    },
    120_000,
  );

  // ── S6. The aggregate invariant, under sustained mixed load ──────────────

  it.skipIf(!live)(
    "S6 sustained mixed load: admission, allocation, scaling and release together never breach cap or double-lease",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      let opSeq = 3000;
      const mintSeq = mintingPort(5000);
      const mintedByRound: number[] = [];
      // A standing backlog drives `open_sessions` high enough that the target reaches the
      // cap, so the scaler leg of this mixed load genuinely mints instead of trivially deciding
      // zero. These never take a wallet; they are pure demand.
      seedReceives(
        dbUrl,
        Array.from({ length: 32 }, (_v, i) => ({ operationId: OP(4000 + i) })),
      );
      // Admission here runs under its own, larger cap: S2 is the cap test, this is the
      // invariant-under-load test, and the standing backlog would otherwise refuse every burst.
      const BURST_LIMITS: ReceiveQueueLimits = { ...QUEUE_LIMITS, receiveQueueCap: 64 };

      for (let round = 0; round < 4; round += 1) {
        // Admit a burst under the queue cap.
        const admitted: string[] = [];
        await withConcurrentSessions(QUEUE_CAP, async (sessions) => {
          await Promise.all(
            sessions.map(async (session) => {
              const operationId = OP((opSeq += 1));
              await session.begin();
              try {
                const result = await admitReceive(session, {
                  limits: BURST_LIMITS,
                  insertOperation: insertReceiveOnTx(operationId),
                });
                if (result.kind === "ADMITTED") {
                  await session.commit();
                  admitted.push(operationId);
                } else {
                  await session.rollback();
                }
              } catch (err) {
                await session.rollback();
                throw err;
              }
            }),
          );
        });
        expect(admitted.length).toBeGreaterThan(0);

        // Allocate and scale at the same time.
        const held: ReleasableLease[] = [];
        await Promise.all([
          withConcurrentSessions(4, async (sessions) => {
            await Promise.all(
              sessions.map(async (session, w) => {
                for (let i = w; i < admitted.length; i += sessions.length) {
                  const outcome = await allocateOn(session, admitted[i]!);
                  if (outcome instanceof Error) throw outcome;
                  if (outcome.kind === "ASSIGNED") {
                    held.push({
                      operationId: admitted[i]!,
                      walletId: outcome.walletId,
                      membershipId: outcome.membershipId,
                      leaseGroupId: outcome.leaseGroupId,
                      leaseEpoch: outcome.leaseEpoch,
                    });
                  }
                }
              }),
            );
          }),
          withTx(dbUrl, (tx) => runPoolScaleUp(tx, { limits: SCALER_LIMITS, mint: mintSeq.mint })),
        ]);

        expectPoolInvariants();
        expect(new Set(held.map((h) => h.walletId)).size).toBe(held.length);

        // Land and release everything held this round, concurrently.
        for (const lease of held) driveReceiveToLanded(dbUrl, lease.operationId, lease.walletId);
        await withConcurrentSessions(4, async (sessions) => {
          await Promise.all(
            sessions.map(async (session, w) => {
              for (let i = w; i < held.length; i += sessions.length) {
                await session.begin();
                await releaseWithLandedProof(session, held[i]!);
                await session.commit();
              }
            }),
          );
        });

        expectPoolInvariants({ activeLeases: 0 });
        expect(countRows(dbUrl, "wallets")).toBeLessThanOrEqual(POOL_CAP);
        mintedByRound.push(countRows(dbUrl, "wallets", `id::text LIKE 'f0000000-%'`));
      }
      // The scaler really did mint across the rounds and then stopped at the cap, rather than
      // deciding zero throughout.
      expect(mintedByRound[mintedByRound.length - 1]).toBeGreaterThan(0);

      // Four rounds of full-throttle admission, allocation, scaling and release, and the two
      // family exit criteria still hold: the hard cap was never exceeded, and no wallet was
      // released except through its landed proof.
      const final = readPoolInvariants(dbUrl);
      expect(final.capCount).toBeLessThanOrEqual(POOL_CAP);
      expect(final.activeLeases).toBe(0);
      expect(final.pinnedWithoutLease).toBe(0);
      expect(final.illegalReceiveRows).toBe(0);
      expect(countRows(dbUrl, "wallets", "state = 'PINNED'")).toBe(0);

      psqlMust(dbUrl, RESET_POOL);
      psqlMust(dbUrl, `DELETE FROM wallets WHERE id::text LIKE 'f0000000-%';`);
    },
    300_000,
  );
});
