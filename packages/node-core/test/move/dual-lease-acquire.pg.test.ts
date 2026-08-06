// MOVE_INTERNAL dual-lease acquisition against REAL PostgreSQL.
//
// Governing: step 1; ("Two-wallet acquisition
// atomic ordered by ascending binary UUID value. If either wallet cannot be leased, neither
// lease acquired"); ("acquire both rows in ascending `wallet_id` byte
// order inside one database transaction. either insert conflicts, transaction rolls back
// holds neither").
//
// Every contender is a separate `psql` OS process (PsqlSessionExecutor), so a race is decided
// at the database transaction boundary rather than by an in-process event loop — an in-memory
// simulation cannot exercise the PK, the UNIQUE(operation_id, wallet_id) backstop, the
// BEFORE INSERT custody trigger, or a real ROLLBACK. node-core carries no SQL driver
// so psql subprocesses are the only real-PG path available.
//
// No private key, gateway call, submit or signing payload is touched; the
// lease IS the capability, and this suite only proves who holds it.

import { createHash, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  LeaseError,
  STATEMENTS as LEASE_STATEMENTS,
  acquireLeases,
  assertLeaseFoundationReady,
  assertSignCapability,
  completeGroupOperation,
  createLeaseGroup,
  joinLeaseGroupOperation,
  migrateLeaseFoundation,
  mintReleaseProof,
  releaseLease,
  transferLeaseWithinGroup,
  sortWalletIdsAscending,
  type AcquiredLease,
  type ActiveLeaseRow,
  type SqlExecutor,
  type SqlQueryResult,
} from "../../src/leases/index.ts";
import {
  acquireMoveLeases,
  type MoveLeaseOutcome,
  type MoveLeaseRequest,
  type MoveLeaseTxFn,
} from "../../src/move/acquire-leases.ts";
import { PsqlExecutor, psqlMust, runPsql, withDatabase, withTx } from "../psql-harness.ts";
import {
  NODE,
  OWNER,
  RESET_POOL,
  W,
  applyPoolSchema,
  countRows,
  seedRegistry,
  seedWallets,
} from "../receive/pool-fixture.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

// ─── fixture layout ─────────────────────────────────────────────────────────
//
// pool-fixture seeds W(1)..W(8) as node_generated + recovery-verified + AVAILABLE. The pairs
// below are chosen so BOTH acquisition orders are exercised: for (SRC_LOW, DST_HIGH) the
// destination is the second leg, for (SRC_HIGH, DST_LOW) the source is. A bug that only ever
// fails the last-listed wallet would pass one and fail the other.

const ELIGIBLE = 8;
const SRC_LOW = W(1);
const DST_HIGH = W(2);
const DST_LOW = W(3);
const SRC_HIGH = W(4);
/** Recovery-verified but deliberately NOT blessed — the DB-level second-leg failure. */
const DST_UNBLESSED = W(5);
/** Destination for the receive→child hand-off case. */
const DST_CHILD = W(6);
/** Competitor wallets: hold a lease so the pair under test finds one leg occupied. */
const RIVAL_OWNER = "c0000000-0000-4000-8000-000000000286";

const BLESSED_DESTINATIONS = [DST_HIGH, DST_LOW, DST_CHILD] as const;

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

const destinationId = (walletId: string): string =>
  `d0000000-0000-4000-8000-2860${walletId.slice(-8)}`;

/** / automatic sink: MOVE_DESTINATION needs a BLESSED destinations row. */
function blessDestinations(url: string): void {
  const rows = BLESSED_DESTINATIONS.map(
    (walletId) =>
      `('${destinationId(walletId)}', '${NODE}', '${walletId}', 'BLESSED', now(), ` +
      `'${randomUUID()}', '${randomUUID()}')`,
  ).join(",\n");
  psqlMust(
    url,
    `INSERT INTO destinations
       (id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id)
     VALUES ${rows}
     ON CONFLICT DO NOTHING;`,
  );
}

// ─── executors ──────────────────────────────────────────────────────────────

/** Delegating executor that records the wallet ids the acquisition locks, in sequence. */
class LockOrderRecorder implements SqlExecutor {
  constructor(
    private readonly inner: SqlExecutor,
    readonly lockedWalletIds: string[],
  ) {}

  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    if (text === LEASE_STATEMENTS.LOCK_WALLET) {
      this.lockedWalletIds.push(String(params[0]));
    }
    return this.inner.query<R>(text, params);
  }
}

/** One BEGIN/COMMIT per acquisition, on its own psql process. */
const txFn = (): MoveLeaseTxFn => (body) => withTx(dbUrl, (tx) => body(tx));

const recordingTxFn = (log: string[]): MoveLeaseTxFn => (body) =>
  withTx(dbUrl, (tx) => body(new LockOrderRecorder(tx, log)));

// ─── helpers ────────────────────────────────────────────────────────────────

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;

const activeLeaseRows = (where = "true"): number =>
  countRows(dbUrl, "wallet_active_leases", where);

const readActive = (walletId: string): ActiveLeaseRow | null => {
  const json = psqlMust(
    dbUrl,
    `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
       SELECT wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
              lease_role, lease_epoch::text AS lease_epoch
         FROM wallet_active_leases WHERE wallet_id = '${walletId}') t;`,
  ).trim();
  const rows = JSON.parse(json) as ActiveLeaseRow[];
  return rows[0] ?? null;
};

/** A top-level move request against a fresh lease group created by admission. */
async function admittedMove(
  sourceWalletId: string,
  destinationWalletId: string,
  operationId: string = randomUUID(),
): Promise<MoveLeaseRequest> {
  const leaseGroupId = await withTx(dbUrl, (tx) => createLeaseGroup(tx, operationId));
  return {
    operationId,
    leaseGroupId,
    sourceWalletId,
    destinationWalletId,
    ownerInstanceId: OWNER,
    spawnedFromOperationId: null,
  };
}

/** Asserts a typed LeaseError rather than "something threw", and returns its reason. */
async function leaseErrorReason(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (err) {
    if (err instanceof LeaseError) return err.reason;
    throw err;
  }
  throw new Error("expected a LeaseError, but the call resolved");
}

/**
 * Proof-backed release of one move lease — the only path the one-in-flight rule permits. The group
 * operation is completed first, then a TRUSTED_VERIFIER `INTERNAL_MOVE_LANDED` proof for the
 * exact tuple is minted and consumed.
 */
async function releaseMoveLease(params: {
  readonly operationId: string;
  readonly leaseGroupId: string;
  readonly walletId: string;
  readonly membershipId: string;
  readonly leaseEpoch: bigint;
}): Promise<void> {
  const proofId = randomUUID();
  await withTx(dbUrl, async (tx) => {
    await completeGroupOperation(tx, {
      leaseGroupId: params.leaseGroupId,
      operationId: params.operationId,
    });
    await mintReleaseProof(tx, {
      proofId,
      walletId: params.walletId,
      operationId: params.operationId,
      membershipId: params.membershipId,
      leaseGroupId: params.leaseGroupId,
      leaseEpoch: params.leaseEpoch,
      proofKind: "INTERNAL_MOVE_LANDED",
      proofDigest: sha(`landed-${params.operationId}-${params.walletId}`),
    });
    await releaseLease(tx, {
      walletId: params.walletId,
      ownerInstanceId: OWNER,
      operationId: params.operationId,
      membershipId: params.membershipId,
      leaseGroupId: params.leaseGroupId,
      leaseEpoch: params.leaseEpoch,
      releaseProofId: proofId,
      releaseReason: "INTERNAL_MOVE_LANDED",
    });
  });
}

/** Occupies a wallet with an unrelated operation's lease, the way a real rival worker would. */
async function occupy(
  walletId: string,
  leaseRole: "SEND_SOURCE" | "MOVE_SOURCE",
  operationId: string = randomUUID(),
): Promise<{ operationId: string; leaseGroupId: string; lease: AcquiredLease }> {
  const leaseGroupId = await withTx(dbUrl, (tx) => createLeaseGroup(tx, operationId));
  const [lease] = await withTx(dbUrl, (tx) =>
    acquireLeases(tx, {
      wallets: [{ walletId, leaseRole }],
      leaseGroupId,
      rootOperationId: operationId,
      operationId,
      ownerInstanceId: RIVAL_OWNER,
    }),
  );
  if (lease === undefined) throw new Error("rival acquisition returned no lease");
  return { operationId, leaseGroupId, lease };
}

/**
 * Drives the receive → automatic child-move hand-off (step 2) so the child
 * operation genuinely owns the source lease inside the parent's group before this
 * destination-only acquisition runs.
 */
async function handOffSourceToChild(sourceWalletId: string): Promise<{
  receiveOperationId: string;
  childOperationId: string;
  leaseGroupId: string;
  sourceMembershipId: string;
  sourceLeaseEpoch: bigint;
}> {
  const receiveOperationId = randomUUID();
  const childOperationId = randomUUID();
  const leaseGroupId = await withTx(dbUrl, (tx) =>
    createLeaseGroup(tx, { rootOperationId: receiveOperationId, childDisposition: "PENDING" }),
  );
  const [receiveLease] = await withTx(dbUrl, (tx) =>
    acquireLeases(tx, {
      wallets: [{ walletId: sourceWalletId, leaseRole: "RECEIVE_WINDOW" }],
      leaseGroupId,
      rootOperationId: receiveOperationId,
      operationId: receiveOperationId,
      ownerInstanceId: OWNER,
    }),
  );
  if (receiveLease === undefined) throw new Error("receive-window acquisition returned no lease");

  await withTx(dbUrl, (tx) =>
    joinLeaseGroupOperation(tx, { leaseGroupId, operationId: childOperationId }),
  );

  const proofId = randomUUID();
  await withTx(dbUrl, (tx) =>
    mintReleaseProof(tx, {
      proofId,
      walletId: sourceWalletId,
      operationId: receiveOperationId,
      membershipId: receiveLease.membershipId,
      leaseGroupId,
      leaseEpoch: receiveLease.leaseEpoch,
      proofKind: "RECEIVE_LANDED",
      proofDigest: sha(`landed-${receiveOperationId}`),
    }),
  );
  const transferred = await withTx(dbUrl, (tx) =>
    transferLeaseWithinGroup(tx, {
      walletId: sourceWalletId,
      ownerInstanceId: OWNER,
      leaseGroupId,
      fromOperationId: receiveOperationId,
      toOperationId: childOperationId,
      membershipId: receiveLease.membershipId,
      leaseEpoch: receiveLease.leaseEpoch,
      toLeaseRole: "MOVE_SOURCE",
      releaseProofId: proofId,
      releaseReason: "RECEIVE_LANDED",
    }),
  );

  return {
    receiveOperationId,
    childOperationId,
    leaseGroupId,
    sourceMembershipId: transferred.membershipId,
    sourceLeaseEpoch: transferred.leaseEpoch,
  };
}

// ─── suite ──────────────────────────────────────────────────────────────────

describe("MOVE_INTERNAL dual-lease acquisition (real PG / separate processes)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error(
          "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup provisioned no test database",
        );
      }
      return;
    }
    dbName = `dual_lease_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);
    applyPoolSchema(dbUrl);
    seedRegistry(dbUrl);
    seedWallets(dbUrl, { eligibleCount: ELIGIBLE });
    blessDestinations(dbUrl);
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

  // ── 1. the comparator is the database's own uuid order ────────────────────

  it.skipIf(!live)(
    "sortWalletIdsAscending reproduces PostgreSQL's own uuid ORDER BY, not a text collation",
    () => {
      const ids = Array.from({ length: 200 }, () => randomUUID());
      const values = ids.map((id) => `('${id}'::uuid)`).join(",");
      const pgOrdered = psqlMust(
        dbUrl,
        `SELECT string_agg(id::text, ',' ORDER BY id) FROM (VALUES ${values}) AS v(id);`,
      )
        .trim()
        .split(",");
      expect(sortWalletIdsAscending(ids)).toEqual(pgOrdered);
    },
  );

  // ── 2. acquisition order is the sorted order, never the caller's ──────────

  it.skipIf(!live)(
    "both request orders lock the same pair in the same ascending sequence",
    async () => {
      psqlMust(dbUrl, RESET_POOL);

      const forward: string[] = [];
      const forwardRequest = await admittedMove(SRC_LOW, DST_HIGH);
      const forwardOutcome = await acquireMoveLeases(recordingTxFn(forward), forwardRequest);
      expect(forwardOutcome.outcome).toBe("HELD");

      psqlMust(dbUrl, RESET_POOL);

      // Same wallet pair, opposite roles — so the source is now the HIGHER uuid and the
      // caller's source-first listing is the reverse of the required order.
      const reverse: string[] = [];
      const reverseRequest = await admittedMove(SRC_HIGH, DST_LOW);
      const reverseOutcome = await acquireMoveLeases(recordingTxFn(reverse), reverseRequest);
      expect(reverseOutcome.outcome).toBe("HELD");

      expect(forward).toEqual([SRC_LOW, DST_HIGH]);
      expect(forward).toEqual(sortWalletIdsAscending(forward));
      // The bug this catches: caller order would give [SRC_HIGH, DST_LOW] here.
      expect(reverse).toEqual([DST_LOW, SRC_HIGH]);
      expect(reverse).toEqual(sortWalletIdsAscending(reverse));
    },
  );

  // ── 3. the happy path holds exactly two rows ──────────────────────────────

  it.skipIf(!live)("step 1: a top-level move holds source and destination", async () => {
    psqlMust(dbUrl, RESET_POOL);
    const request = await admittedMove(SRC_LOW, DST_HIGH);
    const outcome = await acquireMoveLeases(txFn(), request);

    expect(outcome.outcome).toBe("HELD");
    if (outcome.outcome !== "HELD") return;
    expect(outcome.source.walletId).toBe(SRC_LOW);
    expect(outcome.destination.walletId).toBe(DST_HIGH);
    expect(outcome.source.leaseEpoch).toBeGreaterThan(0n);
    expect(outcome.destination.leaseEpoch).toBeGreaterThan(0n);

    expect(activeLeaseRows(`operation_id = '${request.operationId}'`)).toBe(2);
    expect(readActive(SRC_LOW)?.lease_role).toBe("MOVE_SOURCE");
    expect(readActive(DST_HIGH)?.lease_role).toBe("MOVE_DESTINATION");
    expect(readActive(SRC_LOW)?.lease_group_id).toBe(request.leaseGroupId);
    expect(readActive(DST_HIGH)?.lease_group_id).toBe(request.leaseGroupId);
  });

  // ── 4/5. partial acquisition is impossible, at EITHER leg ─────────────────

  it.skipIf(!live)(
    "all-or-nothing: a busy SECOND leg (destination) leaves the source unleased",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const rival = await occupy(DST_HIGH, "MOVE_SOURCE");
      const request = await admittedMove(SRC_LOW, DST_HIGH);

      const outcome = await acquireMoveLeases(txFn(), request);

      expect(outcome).toEqual({ outcome: "WALLET_BUSY", walletId: DST_HIGH });
      expect(activeLeaseRows(`operation_id = '${request.operationId}'`)).toBe(0);
      expect(readActive(SRC_LOW)).toBeNull();
      // The rival's row is untouched — the rollback is ours alone.
      expect(readActive(DST_HIGH)?.operation_id).toBe(rival.operationId);
    },
  );

  it.skipIf(!live)(
    "all-or-nothing: a busy SECOND leg (source, higher uuid) leaves the destination unleased",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      await occupy(SRC_HIGH, "SEND_SOURCE");
      const request = await admittedMove(SRC_HIGH, DST_LOW);

      const outcome = await acquireMoveLeases(txFn(), request);

      expect(outcome).toEqual({ outcome: "WALLET_BUSY", walletId: SRC_HIGH });
      expect(activeLeaseRows(`operation_id = '${request.operationId}'`)).toBe(0);
      expect(readActive(DST_LOW)).toBeNull();
    },
  );

  it.skipIf(!live)(
    "all-or-nothing: a busy FIRST leg never reaches the second insert",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      await occupy(SRC_LOW, "SEND_SOURCE");
      const request = await admittedMove(SRC_LOW, DST_HIGH);

      const outcome = await acquireMoveLeases(txFn(), request);

      expect(outcome).toEqual({ outcome: "WALLET_BUSY", walletId: SRC_LOW });
      expect(activeLeaseRows(`operation_id = '${request.operationId}'`)).toBe(0);
      expect(readActive(DST_HIGH)).toBeNull();
    },
  );

  // ── 6. a DATABASE-enforced failure at the second insert rolls the first back ──

  it.skipIf(!live)(
    "custody trigger: a RAISE on the second insert leaves ZERO lease rows",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // DST_UNBLESSED is recovery-verified and AVAILABLE, so nothing in the application layer
      // rejects it; only the BEFORE INSERT trigger does — and only on the MOVE_DESTINATION
      // insert, which sorts second. The first insert has therefore already happened.
      const request = await admittedMove(SRC_LOW, DST_UNBLESSED);

      const outcome = await acquireMoveLeases(txFn(), request);

      expect(outcome.outcome).toBe("NOT_ELIGIBLE");
      if (outcome.outcome !== "NOT_ELIGIBLE") return;
      expect(outcome.reason).toBe("CUSTODY_REJECTED");
      expect(outcome.detail).toContain("CUSTODY_LEASE_DESTINATION_NOT_BLESSED");

      expect(activeLeaseRows(`operation_id = '${request.operationId}'`)).toBe(0);
      expect(readActive(SRC_LOW)).toBeNull();
      expect(readActive(DST_UNBLESSED)).toBeNull();
      // Memberships are written in the same transaction and must have rolled back with it.
      expect(countRows(dbUrl, "wallet_lease_memberships", `operation_id = '${request.operationId}'`)).toBe(0);
    },
  );

  it.skipIf(!live)("rejects a quarantined source with a typed eligibility outcome", async () => {
    psqlMust(dbUrl, RESET_POOL);
    psqlMust(
      dbUrl,
      `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'dual-lease-drill'
        WHERE id = '${SRC_LOW}';`,
    );
    const request = await admittedMove(SRC_LOW, DST_HIGH);

    const outcome = await acquireMoveLeases(txFn(), request);

    expect(outcome.outcome).toBe("NOT_ELIGIBLE");
    if (outcome.outcome !== "NOT_ELIGIBLE") return;
    expect(outcome.reason).toBe("WALLET_NOT_ELIGIBLE");
    expect(outcome.walletId).toBe(SRC_LOW);
    expect(activeLeaseRows(`operation_id = '${request.operationId}'`)).toBe(0);
    expect(readActive(DST_HIGH)).toBeNull();
  });

  // ── 7. cross-operation exclusion on the shared source ─────────────────────

  it.skipIf(!live)(
    "a SEND_EXTERNAL holding the source excludes the move, and vice versa",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      await occupy(SRC_LOW, "SEND_SOURCE");
      const blocked = await acquireMoveLeases(txFn(), await admittedMove(SRC_LOW, DST_HIGH));
      expect(blocked).toEqual({ outcome: "WALLET_BUSY", walletId: SRC_LOW });

      psqlMust(dbUrl, RESET_POOL);
      const moveRequest = await admittedMove(SRC_LOW, DST_HIGH);
      expect((await acquireMoveLeases(txFn(), moveRequest)).outcome).toBe("HELD");
      expect(await leaseErrorReason(() => occupy(SRC_LOW, "SEND_SOURCE"))).toBe("ALREADY_LEASED");
    },
  );

  // ── 8. N-way race on one pair ─────────────────────────────────────────────

  it.skipIf(!live)(
    "six concurrent moves on one pair produce exactly one winner and no deadlock",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const requests = await Promise.all(
        Array.from({ length: 6 }, () => admittedMove(SRC_LOW, DST_HIGH)),
      );

      const outcomes = await Promise.all(
        requests.map(async (request): Promise<MoveLeaseOutcome | { outcome: "THREW"; message: string }> => {
          try {
            return await acquireMoveLeases(txFn(), request);
          } catch (err) {
            return { outcome: "THREW", message: err instanceof Error ? err.message : String(err) };
          }
        }),
      );

      const held = outcomes.filter((o) => o.outcome === "HELD");
      const busy = outcomes.filter((o) => o.outcome === "WALLET_BUSY");
      const threw = outcomes.filter((o) => o.outcome === "THREW");

      // Every loser is a TYPED wallet_busy — not an untyped throw, and not a deadlock (40P01).
      expect(threw.map((o) => (o.outcome === "THREW" ? o.message : ""))).toEqual([]);
      expect(held).toHaveLength(1);
      expect(busy).toHaveLength(5);

      // Exactly two rows exist in the whole table, both owned by the one winner.
      expect(activeLeaseRows()).toBe(2);
      const sourceRow = readActive(SRC_LOW);
      const destRow = readActive(DST_HIGH);
      expect(sourceRow?.operation_id).toBe(destRow?.operation_id);
      expect(requests.map((r) => r.operationId)).toContain(sourceRow?.operation_id);
      expect(activeLeaseRows(`operation_id = '${sourceRow?.operation_id}'`)).toBe(2);
    },
    60_000,
  );

  // ── 9/10/11. receive-spawned child: destination only ──────────────────────

  it.skipIf(!live)(
    "step 3: the child adds ONLY the destination and never re-acquires the source",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const handoff = await handOffSourceToChild(SRC_LOW);
      const before = readActive(SRC_LOW);

      const outcome = await acquireMoveLeases(txFn(), {
        operationId: handoff.childOperationId,
        leaseGroupId: handoff.leaseGroupId,
        sourceWalletId: SRC_LOW,
        destinationWalletId: DST_CHILD,
        ownerInstanceId: OWNER,
        spawnedFromOperationId: handoff.receiveOperationId,
      });

      expect(outcome.outcome).toBe("HELD");
      if (outcome.outcome !== "HELD") return;
      // The source lease is the one the hand-off produced — same membership, same epoch. A
      // re-acquisition would have minted a new membership_id and bumped lease_epoch (or, more
      // likely, died on the wallet_active_leases primary key and rolled the hand-off back).
      expect(outcome.source.membershipId).toBe(handoff.sourceMembershipId);
      expect(outcome.source.leaseEpoch).toBe(handoff.sourceLeaseEpoch);
      expect(readActive(SRC_LOW)?.membership_id).toBe(before?.membership_id);
      expect(readActive(SRC_LOW)?.lease_epoch).toBe(before?.lease_epoch);

      expect(outcome.destination.walletId).toBe(DST_CHILD);
      expect(readActive(DST_CHILD)?.operation_id).toBe(handoff.childOperationId);
      expect(activeLeaseRows(`lease_group_id = '${handoff.leaseGroupId}'`)).toBe(2);
      // One open membership per wallet in the group; the source's is the child's, not a second.
      expect(
        countRows(
          dbUrl,
          "wallet_lease_memberships",
          `lease_group_id = '${handoff.leaseGroupId}' AND wallet_id = '${SRC_LOW}' AND released_at IS NULL`,
        ),
      ).toBe(1);
    },
  );

  it.skipIf(!live)(
    "step 3: a busy destination leaves the child queued with its source still held",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const handoff = await handOffSourceToChild(SRC_LOW);
      await occupy(DST_CHILD, "MOVE_SOURCE");
      const before = readActive(SRC_LOW);

      const outcome = await acquireMoveLeases(txFn(), {
        operationId: handoff.childOperationId,
        leaseGroupId: handoff.leaseGroupId,
        sourceWalletId: SRC_LOW,
        destinationWalletId: DST_CHILD,
        ownerInstanceId: OWNER,
        spawnedFromOperationId: handoff.receiveOperationId,
      });

      // NOT wallet_busy: gives the automatic child a visibly queued CREATED instead.
      expect(outcome).toEqual({ outcome: "CHILD_WAITING", walletId: DST_CHILD });
      // "the source lease remains continuously held" — byte-identical row, not re-acquired.
      const after = readActive(SRC_LOW);
      expect(after?.membership_id).toBe(before?.membership_id);
      expect(after?.lease_epoch).toBe(before?.lease_epoch);
      expect(after?.operation_id).toBe(handoff.childOperationId);
      expect(activeLeaseRows(`lease_group_id = '${handoff.leaseGroupId}'`)).toBe(1);
    },
  );

  it.skipIf(!live)(
    "a child that does not hold the source acquires no destination at all",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // A group whose child joined but never received the source hand-off.
      const receiveOperationId = randomUUID();
      const childOperationId = randomUUID();
      const leaseGroupId = await withTx(dbUrl, (tx) =>
        createLeaseGroup(tx, { rootOperationId: receiveOperationId, childDisposition: "PENDING" }),
      );
      await withTx(dbUrl, (tx) =>
        acquireLeases(tx, {
          wallets: [{ walletId: SRC_LOW, leaseRole: "RECEIVE_WINDOW" }],
          leaseGroupId,
          rootOperationId: receiveOperationId,
          operationId: receiveOperationId,
          ownerInstanceId: OWNER,
        }),
      );
      await withTx(dbUrl, (tx) =>
        joinLeaseGroupOperation(tx, { leaseGroupId, operationId: childOperationId }),
      );

      const outcome = await acquireMoveLeases(txFn(), {
        operationId: childOperationId,
        leaseGroupId,
        sourceWalletId: SRC_LOW,
        destinationWalletId: DST_CHILD,
        ownerInstanceId: OWNER,
        spawnedFromOperationId: receiveOperationId,
      });

      expect(outcome.outcome).toBe("SOURCE_NOT_HELD");
      if (outcome.outcome !== "SOURCE_NOT_HELD") return;
      expect(outcome.walletId).toBe(SRC_LOW);
      expect(readActive(DST_CHILD)).toBeNull();
      expect(activeLeaseRows(`lease_group_id = '${leaseGroupId}'`)).toBe(1);
    },
  );

  it.skipIf(!live)(
    "a child holding a DIFFERENT wallet in its group cannot lease a destination for the declared source",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // The hand-off gave the child SRC_LOW, so the group-ownership predicate the lease
      // repository enforces (the operation holds SOME lease here) is satisfied. Only the
      // move-level check that the held wallet IS the declared source can reject this
      // without it the signer would later be handed a capability for an unleased wallet.
      const handoff = await handOffSourceToChild(SRC_LOW);
      const undeclaredSource = W(7);

      const outcome = await acquireMoveLeases(txFn(), {
        operationId: handoff.childOperationId,
        leaseGroupId: handoff.leaseGroupId,
        sourceWalletId: undeclaredSource,
        destinationWalletId: DST_CHILD,
        ownerInstanceId: OWNER,
        spawnedFromOperationId: handoff.receiveOperationId,
      });

      expect(outcome.outcome).toBe("SOURCE_NOT_HELD");
      if (outcome.outcome !== "SOURCE_NOT_HELD") return;
      expect(outcome.walletId).toBe(undeclaredSource);
      // The destination insert is rolled back with it — no lease for an unleased source.
      expect(readActive(DST_CHILD)).toBeNull();
      expect(readActive(undeclaredSource)).toBeNull();
      expect(activeLeaseRows(`lease_group_id = '${handoff.leaseGroupId}'`)).toBe(1);
    },
  );

  // ── 12. a capability minted before release cannot survive re-acquisition ──

  it.skipIf(!live)(
    "a capability from the previous epoch fails after re-acquisition (ABA)",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const first = await admittedMove(SRC_LOW, DST_HIGH);
      const firstOutcome = await acquireMoveLeases(txFn(), first);
      expect(firstOutcome.outcome).toBe("HELD");
      if (firstOutcome.outcome !== "HELD") return;
      const staleEpoch = firstOutcome.source.leaseEpoch;

      // The capability is valid while the lease is held.
      await withTx(dbUrl, (tx) =>
        assertSignCapability(tx, {
          walletId: SRC_LOW,
          operationId: first.operationId,
          leaseEpoch: staleEpoch,
          ownerInstanceId: OWNER,
        }),
      );

      for (const lease of [firstOutcome.source, firstOutcome.destination]) {
        await releaseMoveLease({
          operationId: first.operationId,
          leaseGroupId: first.leaseGroupId,
          walletId: lease.walletId,
          membershipId: lease.membershipId,
          leaseEpoch: lease.leaseEpoch,
        });
      }

      const second = await admittedMove(SRC_LOW, DST_HIGH);
      const secondOutcome = await acquireMoveLeases(txFn(), second);
      expect(secondOutcome.outcome).toBe("HELD");
      if (secondOutcome.outcome !== "HELD") return;
      expect(secondOutcome.source.leaseEpoch).toBeGreaterThan(staleEpoch);

      // The pre-release capability is permanently dead even though the wallet is leased again.
      expect(
        await leaseErrorReason(() =>
          withTx(dbUrl, (tx) =>
            assertSignCapability(tx, {
              walletId: SRC_LOW,
              operationId: first.operationId,
              leaseEpoch: staleEpoch,
              ownerInstanceId: OWNER,
            }),
          ),
        ),
      ).toBe("LEASE_OPERATION_MISMATCH");
      expect(
        await leaseErrorReason(() =>
          withTx(dbUrl, (tx) =>
            assertSignCapability(tx, {
              walletId: SRC_LOW,
              operationId: second.operationId,
              leaseEpoch: staleEpoch,
              ownerInstanceId: OWNER,
            }),
          ),
        ),
      ).toBe("SIGN_CAPABILITY_MISMATCH");

      // The successor epoch signs.
      await withTx(dbUrl, (tx) =>
        assertSignCapability(tx, {
          walletId: SRC_LOW,
          operationId: second.operationId,
          leaseEpoch: secondOutcome.source.leaseEpoch,
          ownerInstanceId: OWNER,
        }),
      );
    },
    60_000,
  );
});
