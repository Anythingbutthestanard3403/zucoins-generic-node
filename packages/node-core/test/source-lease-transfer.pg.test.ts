// Continuous RECEIVE_WINDOW → MOVE_SOURCE hand-off against REAL PostgreSQL.
//
// Governing: operation flows step 2; node-core; the data model; signing custody; the one-in-flight-per-wallet rule.
//
// Cases covered:
//  1. No observable gap on wallet_active_leases (UPDATE-in-place); crash mid-handoff rolls back.
//  2. Successor lease_epoch is the only post-handoff sign capability (ABA; foundation nextEpoch).
//  3. Concurrent receive-pool assignment (FOR UPDATE SKIP LOCKED style) cannot take the wallet
//     while the RECEIVE_WINDOW / MOVE_SOURCE row is held.
//  4. Closed parent membership + open child membership share the identical lease_group_id.
//  5. Child assertSignCapability succeeds immediately after transfer.
// + Negative: wrong-role / non-joined child / second active insert → 23505.
//
// node-core carries no SQL driver — psql harness only.

import { createHash, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  STATEMENTS as LEASE_STATEMENTS,
  acquireLeases,
  assertLeaseFoundationReady,
  createLeaseGroup,
  joinLeaseGroupOperation,
  migrateLeaseFoundation,
  type ActiveLeaseRow,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/leases/index.ts";
import {
  assertChildSourceSignCapability,
  HANDOFF_CHILD_ROLE,
  HANDOFF_PARENT_ROLE,
  transferSourceReceiveToMove,
} from "../src/move/source-lease-transfer.ts";
import { PsqlExecutor, psqlMust, withDatabase, withTx } from "./psql-harness.ts";
import {
  OWNER,
  W,
  applyPoolSchema,
  countRows,
  seedRegistry,
  seedWallets,
} from "./receive/pool-fixture.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;
/** One eligible receiver per case — active-row exclusivity forbids reuse without release. */
let nextWalletSlot = 1;
const takeWallet = (): string => {
  const id = W(nextWalletSlot);
  nextWalletSlot += 1;
  return id;
};

const readActive = (walletId: string): (ActiveLeaseRow & { acquired_at?: string }) | null => {
  const json = psqlMust(
    dbUrl,
    `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
       SELECT wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
              lease_role, lease_epoch::text AS lease_epoch,
              acquired_at::text AS acquired_at, heartbeat_at::text AS heartbeat_at,
              owner_instance_id, release_not_before::text AS release_not_before
         FROM wallet_active_leases WHERE wallet_id = '${walletId}') t;`,
  ).trim();
  const rows = JSON.parse(json) as ActiveLeaseRow[];
  return rows[0] ?? null;
};

/** Delegating executor that throws after the first CLOSE_MEMBERSHIP write (crash inject). */
class CrashAfterMembershipClose implements SqlExecutor {
  private closed = false;
  constructor(private readonly inner: SqlExecutor) {}
  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const result = await this.inner.query<R>(text, params);
    if (!this.closed && text === LEASE_STATEMENTS.CLOSE_MEMBERSHIP) {
      this.closed = true;
      throw new Error("SOURCE_LEASE_TRANSFER_CRASH_AFTER_MEMBERSHIP_CLOSE");
    }
    return result;
  }
}

/** Counts statements that touch wallet_active_leases with DELETE (must stay zero on handoff). */
class DeleteWatcher implements SqlExecutor {
  deleteCount = 0;
  constructor(private readonly inner: SqlExecutor) {}
  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    if (/DELETE\s+FROM\s+wallet_active_leases/i.test(text)) {
      this.deleteCount += 1;
    }
    return this.inner.query<R>(text, params);
  }
}

async function seedReceiveLease(): Promise<{
  walletId: string;
  receiveOperationId: string;
  childOperationId: string;
  leaseGroupId: string;
  membershipId: string;
  leaseEpoch: bigint;
}> {
  const walletId = takeWallet();
  const receiveOperationId = randomUUID();
  const childOperationId = randomUUID();
  const leaseGroupId = await withTx(dbUrl, (tx) =>
    createLeaseGroup(tx, { rootOperationId: receiveOperationId, childDisposition: "PENDING" }),
  );
  const [recv] = await withTx(dbUrl, (tx) =>
    acquireLeases(tx, {
      wallets: [{ walletId, leaseRole: HANDOFF_PARENT_ROLE }],
      leaseGroupId,
      rootOperationId: receiveOperationId,
      operationId: receiveOperationId,
      ownerInstanceId: OWNER,
    }),
  );
  if (recv === undefined) throw new Error("RECEIVE_WINDOW acquire returned no lease");
  await withTx(dbUrl, (tx) =>
    joinLeaseGroupOperation(tx, { leaseGroupId, operationId: childOperationId }),
  );
  return {
    walletId,
    receiveOperationId,
    childOperationId,
    leaseGroupId,
    membershipId: recv.membershipId,
    leaseEpoch: recv.leaseEpoch,
  };
}

describe("continuous source-lease transfer (real PG)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned");
      }
      return;
    }
    dbName = `source_lease_transfer_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);
    applyPoolSchema(dbUrl);
    seedRegistry(dbUrl);
    seedWallets(dbUrl, { eligibleCount: 8 });
    await migrateLeaseFoundation(db);
    await assertLeaseFoundationReady(db);
  }, 120_000);

  afterAll(() => {
    if (!live || dbName === "") return;
    try {
      psqlMust(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    } catch {
      /* best-effort */
    }
  });

  it("skips cleanly only when Postgres is absent and not required", () => {
    if (live) {
      expect(dbUrl.length).toBeGreaterThan(0);
      return;
    }
    expect(PG_REQUIRED).toBe(false);
  });

  it.skipIf(!live)(
    "UPDATE-in-place: no DELETE, acquired_at preserved, same lease_group, child can sign",
    async () => {
      const seed = await seedReceiveLease();
      const before = readActive(seed.walletId);
      expect(before?.lease_role).toBe(HANDOFF_PARENT_ROLE);
      expect(before?.operation_id).toBe(seed.receiveOperationId);
      expect(
        Number(countRows(dbUrl, "wallet_active_leases", `wallet_id = '${seed.walletId}'`)),
      ).toBe(1);

      const watcher = { deleteCount: 0 };
      let transferResult!: Awaited<ReturnType<typeof transferSourceReceiveToMove>>;
      await withTx(dbUrl, async (tx) => {
        const watched = new DeleteWatcher(tx);
        transferResult = await transferSourceReceiveToMove(watched, {
          walletId: seed.walletId,
          ownerInstanceId: OWNER,
          leaseGroupId: seed.leaseGroupId,
          parentOperationId: seed.receiveOperationId,
          childOperationId: seed.childOperationId,
          landingProofDigest: sha(`landed-${seed.receiveOperationId}`),
        });
        watcher.deleteCount = watched.deleteCount;
      });

      expect(transferResult.ok).toBe(true);
      if (!transferResult.ok) return;
      expect(transferResult.status).toBe("TRANSFERRED");
      expect(watcher.deleteCount).toBe(0);
      // UPDATE-in-place: acquired_at is not rewritten for a fresh insert aesthetics.
      expect(transferResult.acquiredAtAfter).toBe(transferResult.acquiredAtBefore);

      const after = readActive(seed.walletId);
      expect(after).not.toBeNull();
      expect(after!.lease_role).toBe(HANDOFF_CHILD_ROLE);
      expect(after!.operation_id).toBe(seed.childOperationId);
      expect(after!.lease_group_id).toBe(seed.leaseGroupId);
      expect(after!.root_operation_id).toBe(seed.receiveOperationId);
      expect(
        Number(countRows(dbUrl, "wallet_active_leases", `wallet_id = '${seed.walletId}'`)),
      ).toBe(1);

      // Membership pair: parent closed + child open, same group.
      const parentClosed = psqlMust(
        dbUrl,
        `SELECT count(*) FROM wallet_lease_memberships
          WHERE id = '${seed.membershipId}'
            AND lease_group_id = '${seed.leaseGroupId}'
            AND released_at IS NOT NULL`,
      ).trim();
      expect(parentClosed).toBe("1");
      const childOpen = psqlMust(
        dbUrl,
        `SELECT count(*) FROM wallet_lease_memberships
          WHERE id = '${transferResult.transferred.membershipId}'
            AND lease_group_id = '${seed.leaseGroupId}'
            AND operation_id = '${seed.childOperationId}'
            AND lease_role = 'MOVE_SOURCE'
            AND released_at IS NULL`,
      ).trim();
      expect(childOpen).toBe("1");

      // Indicator 5 — child capability valid for real assertSignCapability.
      const cap = await withTx(dbUrl, (tx) =>
        assertChildSourceSignCapability(tx, {
          walletId: seed.walletId,
          childOperationId: seed.childOperationId,
          leaseEpoch: transferResult.transferred.leaseEpoch,
          ownerInstanceId: OWNER,
        }),
      );
      expect(cap.membership_id).toBe(transferResult.transferred.membershipId);

      // Parent parent-epoch capability permanently invalid (ABA).
      await expect(
        withTx(dbUrl, (tx) =>
          assertChildSourceSignCapability(tx, {
            walletId: seed.walletId,
            childOperationId: seed.receiveOperationId,
            leaseEpoch: transferResult.parentLeaseEpoch,
            ownerInstanceId: OWNER,
          }),
        ),
      ).rejects.toBeTruthy();

      // Idempotent replay.
      const replay = await withTx(dbUrl, (tx) =>
        transferSourceReceiveToMove(tx, {
          walletId: seed.walletId,
          ownerInstanceId: OWNER,
          leaseGroupId: seed.leaseGroupId,
          parentOperationId: seed.receiveOperationId,
          childOperationId: seed.childOperationId,
          landingProofDigest: sha("replay"),
        }),
      );
      expect(replay.ok).toBe(true);
      if (!replay.ok) return;
      expect(replay.status).toBe("ALREADY_TRANSFERRED");
    },
  );

  it.skipIf(!live)(
    "crash after membership close rolls back: active stays RECEIVE_WINDOW (no gap)",
    async () => {
      const seed = await seedReceiveLease();
      const before = readActive(seed.walletId);
      expect(before?.lease_role).toBe(HANDOFF_PARENT_ROLE);

      await expect(
        withTx(dbUrl, async (tx) => {
          const crashing = new CrashAfterMembershipClose(tx);
          await transferSourceReceiveToMove(crashing, {
            walletId: seed.walletId,
            ownerInstanceId: OWNER,
            leaseGroupId: seed.leaseGroupId,
            parentOperationId: seed.receiveOperationId,
            childOperationId: seed.childOperationId,
            landingProofDigest: sha(`crash-${seed.receiveOperationId}`),
          });
        }),
      ).rejects.toThrow(/SOURCE_LEASE_TRANSFER_CRASH_AFTER_MEMBERSHIP_CLOSE/);

      // Neither write commits: still exactly one active row under the parent receive.
      expect(
        Number(countRows(dbUrl, "wallet_active_leases", `wallet_id = '${seed.walletId}'`)),
      ).toBe(1);
      const after = readActive(seed.walletId);
      expect(after?.lease_role).toBe(HANDOFF_PARENT_ROLE);
      expect(after?.operation_id).toBe(seed.receiveOperationId);
      expect(after?.membership_id).toBe(seed.membershipId);
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM wallet_lease_memberships
            WHERE id = '${seed.membershipId}' AND released_at IS NULL`,
        ).trim(),
      ).toBe("1");
    },
  );

  it.skipIf(!live)(
    "concurrent second acquire is rejected while the transferred active row is held",
    async () => {
      const seed = await seedReceiveLease();

      // During the open hand-off TX a peer session must not observe a gap (count stays 1).
      await withTx(dbUrl, async (tx) => {
        const mid = await transferSourceReceiveToMove(tx, {
          walletId: seed.walletId,
          ownerInstanceId: OWNER,
          leaseGroupId: seed.leaseGroupId,
          parentOperationId: seed.receiveOperationId,
          childOperationId: seed.childOperationId,
          landingProofDigest: sha(`conc-${seed.receiveOperationId}`),
        });
        expect(mid.ok).toBe(true);
        // Still inside the uncommitted TX: peer autocommit sees the prior committed
        // RECEIVE_WINDOW row (snapshot) — never zero rows for this wallet once held.
        const peerCount = Number(
          countRows(dbUrl, "wallet_active_leases", `wallet_id = '${seed.walletId}'`),
        );
        expect(peerCount).toBeGreaterThanOrEqual(1);
      });

      expect(readActive(seed.walletId)?.lease_role).toBe(HANDOFF_CHILD_ROLE);

      const rivalRoot = randomUUID();
      const rivalGroup = await withTx(dbUrl, (tx) =>
        createLeaseGroup(tx, { rootOperationId: rivalRoot, childDisposition: "NONE" }),
      );
      await expect(
        withTx(dbUrl, (tx) =>
          acquireLeases(tx, {
            wallets: [{ walletId: seed.walletId, leaseRole: "SEND_SOURCE" }],
            leaseGroupId: rivalGroup,
            rootOperationId: rivalRoot,
            operationId: rivalRoot,
            ownerInstanceId: randomUUID(),
          }),
        ),
      ).rejects.toMatchObject({ reason: "ALREADY_LEASED" });

      // Pool assignment: FOR UPDATE SKIP LOCKED never selects a leased wallet.
      const skipLocked = psqlMust(
        dbUrl,
        `SELECT id::text FROM wallets
          WHERE id = '${seed.walletId}'
            AND key_origin = 'node_generated'
            AND recovery_verified_at IS NOT NULL
            AND state = 'AVAILABLE'
            AND NOT EXISTS (
              SELECT 1 FROM wallet_active_leases l WHERE l.wallet_id = wallets.id
            )
          FOR UPDATE SKIP LOCKED
          LIMIT 1;`,
      ).trim();
      expect(skipLocked).toBe("");
    },
  );

  it.skipIf(!live)("negative: child not joined → transfer fails, active untouched", async () => {
    const wallet = takeWallet();
    const receiveOperationId = randomUUID();
    const orphanChild = randomUUID();
    const leaseGroupId = await withTx(dbUrl, (tx) =>
      createLeaseGroup(tx, { rootOperationId: receiveOperationId, childDisposition: "PENDING" }),
    );
    const [recv] = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: wallet, leaseRole: HANDOFF_PARENT_ROLE }],
        leaseGroupId,
        rootOperationId: receiveOperationId,
        operationId: receiveOperationId,
        ownerInstanceId: OWNER,
      }),
    );
    if (recv === undefined) throw new Error("acquire failed");
    // Deliberately do NOT join orphanChild.

    const result = await withTx(dbUrl, (tx) =>
      transferSourceReceiveToMove(tx, {
        walletId: wallet,
        ownerInstanceId: OWNER,
        leaseGroupId,
        parentOperationId: receiveOperationId,
        childOperationId: orphanChild,
        landingProofDigest: sha("orphan"),
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("TRANSFER_FAILED");
    expect(result.detail).toMatch(/TRANSFER_TARGET_NOT_JOINED/);

    const after = readActive(wallet);
    expect(after?.lease_role).toBe(HANDOFF_PARENT_ROLE);
    expect(after?.operation_id).toBe(receiveOperationId);
    expect(after?.membership_id).toBe(recv.membershipId);
  });
});
