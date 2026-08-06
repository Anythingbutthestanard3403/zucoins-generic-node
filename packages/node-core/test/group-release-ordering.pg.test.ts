// group-release ordering against REAL production lease + predicate SUTs
// on real PostgreSQL.
//
//
// This file imports only
// from `../src/leases/index.ts`, `../src/move/source-lease-transfer.ts`, and
// `../src/verification/index.ts` — the production barrels landed by the verification barrel PRs.
//
// Cases covered:
//   1. Only one leg terminal → releaseLease refused, group.released_at stays null
//   3. lease_groups.released_at + release_proof_id set together same commit (row read after TX)
//   4. Crash between both-legs-terminal and release-commit → re-evaluable; no double-release
//   6. Dest busy mid-handoff; child fail before join/terminal; membership not released early;
//      multi-wallet last-membership stamps the group once.

import { createHash, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  LeaseError,
  STATEMENTS as LEASE_STATEMENTS,
  acquireGroupDestinationLeases,
  acquireLeases,
  assertLeaseFoundationReady,
  completeGroupOperation,
  createLeaseGroup,
  joinLeaseGroupOperation,
  migrateLeaseFoundation,
  mintReleaseProof,
  releaseLease,
  type AcquiredLease,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/leases/index.ts";
import {
  HANDOFF_PARENT_ROLE,
  transferSourceReceiveToMove,
} from "../src/move/source-lease-transfer.ts";
import { evaluateGroupRelease, type GroupReleaseFacts } from "../src/verification/index.ts";
import { PsqlExecutor, psqlMust, withDatabase, withTx } from "./psql-harness.ts";
import {
  NODE as POOL_NODE,
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
const RIVAL_OWNER = "c0000000-0000-4000-8000-000000000284";

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;
let nextWallet = 1;
const takeWallet = (): string => {
  const id = W(nextWallet);
  nextWallet += 1;
  return id;
};

/** data-model / MOVE_DESTINATION needs a BLESSED destinations row. */
function blessDestination(walletId: string): void {
  const destId = `d2840000-0000-4000-8000-${walletId.slice(-12)}`;
  psqlMust(
    dbUrl,
    `INSERT INTO destinations
       (id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id)
     VALUES ('${destId}', '${POOL_NODE}', '${walletId}', 'BLESSED', now(),
             '${randomUUID()}', '${randomUUID()}')
     ON CONFLICT DO NOTHING;`,
  );
}

/** Crash after every membership close — before RELEASE_LEASE_GROUP — then reclaim. */
class CrashBeforeGroupStamp implements SqlExecutor {
  private closes = 0;
  constructor(
    private readonly inner: SqlExecutor,
    private readonly crashOnCloseNumber: number,
  ) {}
  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const result = await this.inner.query<R>(text, params);
    if (text === LEASE_STATEMENTS.CLOSE_MEMBERSHIP) {
      this.closes += 1;
      if (this.closes === this.crashOnCloseNumber) {
        throw new Error("GROUP_RELEASE_ORDERING_CRASH_BEFORE_GROUP_STAMP");
      }
    }
    return result;
  }
}

function readGroupStamp(groupId: string): {
  released_at: string | null;
  release_proof_id: string | null;
  child_disposition: string;
} {
  const json = psqlMust(
    dbUrl,
    `SELECT row_to_json(t) FROM (
       SELECT released_at::text AS released_at,
              release_proof_id::text AS release_proof_id,
              child_disposition
         FROM lease_groups WHERE id = '${groupId}'
     ) t;`,
  ).trim();
  return JSON.parse(json) as {
    released_at: string | null;
    release_proof_id: string | null;
    child_disposition: string;
  };
}

async function seedReceiveChildGroup(params?: {
  readonly destWalletId?: string;
  /** When true (default), try phase-B dest acquire; false leaves group source-only. */
  readonly acquireDest?: boolean;
}): Promise<{
  sourceWalletId: string;
  destWalletId: string;
  receiveOperationId: string;
  childOperationId: string;
  leaseGroupId: string;
  source: AcquiredLease;
  dest: AcquiredLease | null;
  destBusy: boolean;
}> {
  const sourceWalletId = takeWallet();
  const destWalletId = params?.destWalletId ?? takeWallet();
  blessDestination(destWalletId);
  const receiveOperationId = randomUUID();
  const childOperationId = randomUUID();
  const acquireDest = params?.acquireDest ?? true;

  const leaseGroupId = await withTx(dbUrl, (tx) =>
    createLeaseGroup(tx, {
      rootOperationId: receiveOperationId,
      childDisposition: "PENDING",
    }),
  );
  const [parent] = await withTx(dbUrl, (tx) =>
    acquireLeases(tx, {
      wallets: [{ walletId: sourceWalletId, leaseRole: HANDOFF_PARENT_ROLE }],
      leaseGroupId,
      rootOperationId: receiveOperationId,
      operationId: receiveOperationId,
      ownerInstanceId: OWNER,
    }),
  );
  if (parent === undefined) throw new Error("receive acquire returned no lease");

  await withTx(dbUrl, (tx) =>
    joinLeaseGroupOperation(tx, { leaseGroupId, operationId: childOperationId }),
  );

  const transfer = await withTx(dbUrl, (tx) =>
    transferSourceReceiveToMove(tx, {
      walletId: sourceWalletId,
      ownerInstanceId: OWNER,
      leaseGroupId,
      parentOperationId: receiveOperationId,
      childOperationId,
      landingProofDigest: sha(`landed-${receiveOperationId}`),
    }),
  );
  if (!transfer.ok) {
    throw new Error(`source transfer failed: ${transfer.reason} ${transfer.detail}`);
  }

  let dest: AcquiredLease | null = null;
  let destBusy = false;
  if (acquireDest) {
    try {
      const destLeases = await withTx(dbUrl, (tx) =>
        acquireGroupDestinationLeases(tx, {
          leaseGroupId,
          operationId: childOperationId,
          ownerInstanceId: OWNER,
          destinations: [{ walletId: destWalletId, leaseRole: "MOVE_DESTINATION" }],
        }),
      );
      dest = destLeases[0] ?? null;
    } catch (err) {
      if (err instanceof LeaseError && err.reason === "ALREADY_LEASED") {
        destBusy = true;
        dest = null;
      } else {
        throw err;
      }
    }
  }

  return {
    sourceWalletId,
    destWalletId,
    receiveOperationId,
    childOperationId,
    leaseGroupId,
    source: {
      walletId: sourceWalletId,
      membershipId: transfer.transferred.membershipId,
      leaseEpoch: transfer.transferred.leaseEpoch,
    },
    dest,
    destBusy,
  };
}

async function releaseOne(params: {
  readonly walletId: string;
  readonly operationId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
  readonly proofKind: "RECEIVE_LANDED" | "INTERNAL_MOVE_LANDED";
  readonly executor?: SqlExecutor;
}): Promise<{ groupReleased: boolean; proofId: string }> {
  const proofId = randomUUID();
  const run = async (tx: SqlExecutor) => {
    await mintReleaseProof(tx, {
      proofId,
      walletId: params.walletId,
      operationId: params.operationId,
      membershipId: params.membershipId,
      leaseGroupId: params.leaseGroupId,
      leaseEpoch: params.leaseEpoch,
      proofKind: params.proofKind,
      proofDigest: sha(`rel-${params.operationId}-${params.walletId}-${proofId}`),
    });
    const released = await releaseLease(tx, {
      walletId: params.walletId,
      ownerInstanceId: OWNER,
      operationId: params.operationId,
      membershipId: params.membershipId,
      leaseGroupId: params.leaseGroupId,
      leaseEpoch: params.leaseEpoch,
      releaseProofId: proofId,
      releaseReason: params.proofKind,
    });
    return released.groupReleased;
  };
  if (params.executor !== undefined) {
    const groupReleased = await run(params.executor);
    return { groupReleased, proofId };
  }
  const groupReleased = await withTx(dbUrl, run);
  return { groupReleased, proofId };
}

describe("group-release ordering (real PG production SUT)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned");
      }
      return;
    }
    dbName = `group_release_ordering_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    applyPoolSchema(dbUrl);
    seedRegistry(dbUrl);
    seedWallets(dbUrl, { eligibleCount: 24, unverifiedCount: 1, importedCount: 1 });
    db = new PsqlExecutor(dbUrl);
    await migrateLeaseFoundation(db);
    await assertLeaseFoundationReady(db);
  }, 120_000);

  afterAll(() => {
    if (live && dbName !== "") {
      try {
        psqlMust(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
      } catch {
        // best-effort teardown
      }
    }
  });

  it("skips cleanly when Postgres is not provisioned", () => {
    if (live) return;
    expect(TEST_DATABASE_URL).toBe("");
  });

  /* ── AC2 / RI-1: only one leg terminal → no group release ────────── */

  it("only receive (root) terminal → release refused; group stays unreleased", async ({
    skip,
  }) => {
    if (!live) {
      skip();
      return;
    }
    // HOLD/NONE single-leg group: root holds one membership through receive status.
    // Multileg JOINED with only root completed must refuse.
    const g = await seedReceiveChildGroup();
    expect(g.dest).not.toBeNull();

    await withTx(dbUrl, (tx) =>
      completeGroupOperation(tx, {
        leaseGroupId: g.leaseGroupId,
        operationId: g.childOperationId,
      }),
    );
    // Intentionally DO NOT complete the receive root that transferred out — child source leg
    // is complete, but receive root lease_group_operations row is still open.
    await expect(
      releaseOne({
        walletId: g.sourceWalletId,
        operationId: g.childOperationId,
        membershipId: g.source.membershipId,
        leaseGroupId: g.leaseGroupId,
        leaseEpoch: g.source.leaseEpoch,
        proofKind: "INTERNAL_MOVE_LANDED",
      }),
    ).rejects.toMatchObject({ reason: "GROUP_NOT_TERMINAL" });

    const stamp = readGroupStamp(g.leaseGroupId);
    expect(stamp.released_at).toBeNull();
    expect(stamp.release_proof_id).toBeNull();
    expect(countRows(dbUrl, "wallet_active_leases", `wallet_id = '${g.sourceWalletId}'`)).toBe(1);
  });

  it("both legs present but only one completed_at → GROUP_NOT_TERMINAL (conjunctive)", async ({
    skip,
  }) => {
    if (!live) {
      skip();
      return;
    }
    const g = await seedReceiveChildGroup();
    await withTx(dbUrl, (tx) =>
      completeGroupOperation(tx, {
        leaseGroupId: g.leaseGroupId,
        operationId: g.receiveOperationId,
      }),
    );
    // child left non-terminal
    await expect(
      releaseOne({
        walletId: g.sourceWalletId,
        operationId: g.childOperationId,
        membershipId: g.source.membershipId,
        leaseGroupId: g.leaseGroupId,
        leaseEpoch: g.source.leaseEpoch,
        proofKind: "INTERNAL_MOVE_LANDED",
      }),
    ).rejects.toMatchObject({ reason: "GROUP_NOT_TERMINAL" });
    expect(readGroupStamp(g.leaseGroupId).released_at).toBeNull();
  });

  /* ── AC4 / RI-3: couple stamp released_at + release_proof_id ─────── */

  it("stamps lease_groups.released_at and release_proof_id together on last membership close", async ({
    skip,
  }) => {
    if (!live) {
      skip();
      return;
    }
    const g = await seedReceiveChildGroup();
    if (g.dest === null) throw new Error("expected dest membership");

    await withTx(dbUrl, async (tx) => {
      await completeGroupOperation(tx, {
        leaseGroupId: g.leaseGroupId,
        operationId: g.receiveOperationId,
      });
      await completeGroupOperation(tx, {
        leaseGroupId: g.leaseGroupId,
        operationId: g.childOperationId,
      });
    });

    // First wallet — group stays open until last membership closes.
    const first = await releaseOne({
      walletId: g.sourceWalletId,
      operationId: g.childOperationId,
      membershipId: g.source.membershipId,
      leaseGroupId: g.leaseGroupId,
      leaseEpoch: g.source.leaseEpoch,
      proofKind: "INTERNAL_MOVE_LANDED",
    });
    expect(first.groupReleased).toBe(false);
    const mid = readGroupStamp(g.leaseGroupId);
    expect(mid.released_at).toBeNull();
    expect(mid.release_proof_id).toBeNull();

    // CHECK-coupled pairability enforced at DB even without app stamp:
    const oneSided = psqlMust(
      dbUrl,
      `DO $$
       BEGIN
         BEGIN
           UPDATE lease_groups SET released_at = now() WHERE id = '${g.leaseGroupId}';
           RAISE EXCEPTION 'SHOULD_HAVE_FAILED';
         EXCEPTION WHEN check_violation THEN
           NULL; -- expected
         END;
       END $$;
       SELECT 'ok';`,
    ).trim();
    expect(oneSided).toContain("ok");

    const last = await releaseOne({
      walletId: g.dest.walletId,
      operationId: g.childOperationId,
      membershipId: g.dest.membershipId,
      leaseGroupId: g.leaseGroupId,
      leaseEpoch: g.dest.leaseEpoch,
      proofKind: "INTERNAL_MOVE_LANDED",
    });
    expect(last.groupReleased).toBe(true);

    const stamp = readGroupStamp(g.leaseGroupId);
    expect(stamp.released_at).not.toBeNull();
    expect(stamp.release_proof_id).toBe(last.proofId);
    // Coupled nullability: both set together this commit
    expect(stamp.release_proof_id).not.toBeNull();
    expect(
      countRows(dbUrl, "wallet_lease_memberships", `lease_group_id = '${g.leaseGroupId}' AND released_at IS NULL`),
    ).toBe(0);
  });

  /* ── AC5 / RI-4: crash before group stamp, re-eval, no double-release ─ */

  it("crash between both-terminal and group-stamp commit is re-evaluable; no double-release", async ({
    skip,
  }) => {
    if (!live) {
      skip();
      return;
    }
    const g = await seedReceiveChildGroup();
    if (g.dest === null) throw new Error("expected dest");

    await withTx(dbUrl, async (tx) => {
      await completeGroupOperation(tx, {
        leaseGroupId: g.leaseGroupId,
        operationId: g.receiveOperationId,
      });
      await completeGroupOperation(tx, {
        leaseGroupId: g.leaseGroupId,
        operationId: g.childOperationId,
      });
    });

    // Wallet 1 closes cleanly.
    await releaseOne({
      walletId: g.sourceWalletId,
      operationId: g.childOperationId,
      membershipId: g.source.membershipId,
      leaseGroupId: g.leaseGroupId,
      leaseEpoch: g.source.leaseEpoch,
      proofKind: "INTERNAL_MOVE_LANDED",
    });
    expect(readGroupStamp(g.leaseGroupId).released_at).toBeNull();

    // Wallet 2: crash on CLOSE (only remaining open membership) — entire TX rolls back.
    await expect(
      withTx(dbUrl, async (tx) => {
        const crashing = new CrashBeforeGroupStamp(tx, 1);
        await releaseOne({
          walletId: g.dest!.walletId,
          operationId: g.childOperationId,
          membershipId: g.dest!.membershipId,
          leaseGroupId: g.leaseGroupId,
          leaseEpoch: g.dest!.leaseEpoch,
          proofKind: "INTERNAL_MOVE_LANDED",
          executor: crashing,
        });
      }),
    ).rejects.toThrow(/GROUP_RELEASE_ORDERING_CRASH_BEFORE_GROUP_STAMP/);

    // Group still open; dest membership + active lease intact; predicate remains releasable.
    expect(readGroupStamp(g.leaseGroupId).released_at).toBeNull();
    expect(
      countRows(dbUrl, "wallet_active_leases", `wallet_id = '${g.dest.walletId}'`),
    ).toBe(1);
    expect(
      countRows(
        dbUrl,
        "wallet_lease_memberships",
        `id = '${g.dest.membershipId}' AND released_at IS NULL`,
      ),
    ).toBe(1);

    // Recovery pass: same release succeeds once and stamps the pair.
    const recovered = await releaseOne({
      walletId: g.dest.walletId,
      operationId: g.childOperationId,
      membershipId: g.dest.membershipId,
      leaseGroupId: g.leaseGroupId,
      leaseEpoch: g.dest.leaseEpoch,
      proofKind: "INTERNAL_MOVE_LANDED",
    });
    expect(recovered.groupReleased).toBe(true);
    const stamp = readGroupStamp(g.leaseGroupId);
    expect(stamp.released_at).not.toBeNull();
    expect(stamp.release_proof_id).toBe(recovered.proofId);

    // Double-release refused.
    await expect(
      releaseOne({
        walletId: g.dest.walletId,
        operationId: g.childOperationId,
        membershipId: g.dest.membershipId,
        leaseGroupId: g.leaseGroupId,
        leaseEpoch: g.dest.leaseEpoch,
        proofKind: "INTERNAL_MOVE_LANDED",
      }),
    ).rejects.toMatchObject({ reason: "GROUP_ALREADY_RELEASED" });
  });

  /* ── AC6: dest busy mid-handoff ──────────────────────────────────── */

  it("destination busy mid-handoff keeps source held and group unreleased", async ({ skip }) => {
    if (!live) {
      skip();
      return;
    }
    const destWalletId = takeWallet();
    // Rival occupies destination first.
    const rivalOp = randomUUID();
    const rivalGroup = await withTx(dbUrl, (tx) => createLeaseGroup(tx, rivalOp));
    await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: destWalletId, leaseRole: "SEND_SOURCE" }],
        leaseGroupId: rivalGroup,
        rootOperationId: rivalOp,
        operationId: rivalOp,
        ownerInstanceId: RIVAL_OWNER,
      }),
    );

    const g = await seedReceiveChildGroup({ destWalletId });
    // Source transfer landed; dest acquire failed ALREADY_LEASED → dest null.
    expect(g.destBusy).toBe(true);
    expect(g.dest).toBeNull();
    expect(countRows(dbUrl, "wallet_active_leases", `wallet_id = '${g.sourceWalletId}'`)).toBe(1);
    expect(readGroupStamp(g.leaseGroupId).child_disposition).toBe("JOINED");
    // Source stays held under our owner — no release gap while dest is busy.
    const srcOwner = psqlMust(
      dbUrl,
      `SELECT owner_instance_id || '|' || lease_role FROM wallet_active_leases
        WHERE wallet_id = '${g.sourceWalletId}'`,
    ).trim();
    expect(srcOwner).toBe(`${OWNER}|MOVE_SOURCE`);
    const destOwner = psqlMust(
      dbUrl,
      `SELECT owner_instance_id FROM wallet_active_leases WHERE wallet_id = '${destWalletId}'`,
    ).trim();
    expect(destOwner).toBe(RIVAL_OWNER);
    // Group cannot be stamp-released while source membership is still open (and we have not
    // proven terminal+acks). Explicit early release attempt is still gated on both terminals.
    await expect(
      releaseOne({
        walletId: g.sourceWalletId,
        operationId: g.childOperationId,
        membershipId: g.source.membershipId,
        leaseGroupId: g.leaseGroupId,
        leaseEpoch: g.source.leaseEpoch,
        proofKind: "INTERNAL_MOVE_LANDED",
      }),
    ).rejects.toMatchObject({ reason: "GROUP_NOT_TERMINAL" });
    expect(readGroupStamp(g.leaseGroupId).released_at).toBeNull();
  });

  /* ── AC6: child pending disposition / not joined ─────────────────── */

  it("child disposition PENDING refuses release until join (child fail-before-join phase)", async ({
    skip,
  }) => {
    if (!live) {
      skip();
      return;
    }
    const sourceWalletId = takeWallet();
    const receiveOperationId = randomUUID();
    const leaseGroupId = await withTx(dbUrl, (tx) =>
      createLeaseGroup(tx, {
        rootOperationId: receiveOperationId,
        childDisposition: "PENDING",
      }),
    );
    const [source] = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: sourceWalletId, leaseRole: HANDOFF_PARENT_ROLE }],
        leaseGroupId,
        rootOperationId: receiveOperationId,
        operationId: receiveOperationId,
        ownerInstanceId: OWNER,
      }),
    );
    if (source === undefined) throw new Error("no source");
    await withTx(dbUrl, (tx) =>
      completeGroupOperation(tx, { leaseGroupId, operationId: receiveOperationId }),
    );
    await expect(
      releaseOne({
        walletId: sourceWalletId,
        operationId: receiveOperationId,
        membershipId: source.membershipId,
        leaseGroupId,
        leaseEpoch: source.leaseEpoch,
        proofKind: "RECEIVE_LANDED",
      }),
    ).rejects.toMatchObject({ reason: "GROUP_NOT_TERMINAL" });
    expect(readGroupStamp(leaseGroupId).released_at).toBeNull();
  });

  /* ── Predicate SUT still consulted for attention/pin facts (AC3) ─── */

  it("production evaluateGroupRelease pins attention on REJECTED alongside durable PG legs", () => {
    // Wiring check: this path still routes through the production module (not a local stub).
    const facts: GroupReleaseFacts = {
      childDisposition: "JOINED",
      operations: [
        {
          operationId: "d0000000-0000-4000-8000-000000000291",
          kind: "RECEIVE_EXTERNAL",
          verdict: "VERIFIED",
          completed: true,
          expectedWallets: [
            {
              role: "RECEIVER",
              walletId: W(1),
              walletPublicKey: "A".repeat(43) + "=",
            },
          ],
          evidence: [
            {
              role: "RECEIVER",
              walletId: W(1),
              walletPublicKey: "A".repeat(43) + "=",
            },
          ],
          evidenceRoles: ["RECEIVER"],
        },
        {
          operationId: "d0000000-0000-4000-8000-000000000292",
          kind: "MOVE_INTERNAL",
          verdict: "REJECTED",
          completed: true,
          expectedWallets: [
            {
              role: "SOURCE",
              walletId: W(2),
              walletPublicKey: "B".repeat(43) + "=",
            },
            {
              role: "DESTINATION",
              walletId: W(3),
              walletPublicKey: "C".repeat(43) + "=",
            },
          ],
          evidence: [
            {
              role: "SOURCE",
              walletId: W(2),
              walletPublicKey: "B".repeat(43) + "=",
            },
            {
              role: "DESTINATION",
              walletId: W(3),
              walletPublicKey: "C".repeat(43) + "=",
            },
          ],
          evidenceRoles: ["SOURCE", "DESTINATION"],
        },
      ],
    };
    const decided = evaluateGroupRelease(facts);
    expect(decided.status).toBe("PINNED_FOR_ATTENTION");
    expect(decided.reason).toBe("LEG_VERDICT_NOT_VERIFIED");
  });

  /* ── Complete-order permutation (receive terminal first vs child first) ─ */

  it("terminal completion order does not change final group release", async ({ skip }) => {
    if (!live) {
      skip();
      return;
    }
    for (const order of ["receive-first", "child-first"] as const) {
      const g = await seedReceiveChildGroup();
      if (g.dest === null) throw new Error("dest required");

      if (order === "receive-first") {
        await withTx(dbUrl, (tx) =>
          completeGroupOperation(tx, {
            leaseGroupId: g.leaseGroupId,
            operationId: g.receiveOperationId,
          }),
        );
        await withTx(dbUrl, (tx) =>
          completeGroupOperation(tx, {
            leaseGroupId: g.leaseGroupId,
            operationId: g.childOperationId,
          }),
        );
      } else {
        await withTx(dbUrl, (tx) =>
          completeGroupOperation(tx, {
            leaseGroupId: g.leaseGroupId,
            operationId: g.childOperationId,
          }),
        );
        await withTx(dbUrl, (tx) =>
          completeGroupOperation(tx, {
            leaseGroupId: g.leaseGroupId,
            operationId: g.receiveOperationId,
          }),
        );
      }

      await releaseOne({
        walletId: g.sourceWalletId,
        operationId: g.childOperationId,
        membershipId: g.source.membershipId,
        leaseGroupId: g.leaseGroupId,
        leaseEpoch: g.source.leaseEpoch,
        proofKind: "INTERNAL_MOVE_LANDED",
      });
      const last = await releaseOne({
        walletId: g.dest.walletId,
        operationId: g.childOperationId,
        membershipId: g.dest.membershipId,
        leaseGroupId: g.leaseGroupId,
        leaseEpoch: g.dest.leaseEpoch,
        proofKind: "INTERNAL_MOVE_LANDED",
      });
      expect(last.groupReleased).toBe(true);
      const stamp = readGroupStamp(g.leaseGroupId);
      expect(stamp.released_at).not.toBeNull();
      expect(stamp.release_proof_id).toBe(last.proofId);
    }
  });
});
