// real-PostgreSQL proof of steps 3–4.
//
// Governing: steps 3–4 and (lease owned before the first
// fresh gateway read) and (genesis is exact, INDETERMINATE is never zero);
// row 1.
//
// Real PG only, and for a specific reason: every property here is a database predicate. The
// lease fence, the exactly-once T0 and the epoch check are decided by `wallet_active_leases`
// and `operation_observation_bindings`, none of which an in-memory slot store can express — a
// mock would prove only that the module calls itself in the order it was written in.
//
// Each positive property is paired with the negative that shows the guard produces the green:
// the un-fenced INSERT DOES bind without a lease, the epoch-less variant DOES bind across a
// re-acquisition, and the second RECEIVER_T0 row IS rejected by the schema rather than by
// application logic.
//
// Connectivity: TEST_DATABASE_URL (vitest.global-setup) or PG_REQUIRED fail-closed.

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  assertLeaseFoundationReady,
  createLeaseGroup,
  migrateLeaseFoundation,
} from "../../src/leases/index.ts";
import {
  RECEIVE_T0_STATEMENTS,
  captureReceiveT0,
  classifyReceiveT0Phase,
  type ReceiveT0Observation,
  type ReceiveT0Observer,
} from "../../src/receive/t0-capture.ts";
import { PsqlExecutor, PsqlSessionExecutor, psqlMust, runPsql, withDatabase } from "../psql-harness.ts";
import {
  LEASES,
  OP,
  OWNER,
  RESET_POOL,
  applyPoolSchema,
  driveReceiveToLanded,
  releaseWithLandedProof,
  seedReceive,
  seedRegistry,
  seedWallets,
  type SeededPool,
} from "./pool-fixture.ts";

const here = dirname(fileURLToPath(import.meta.url));
const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

/**
 * `operation_observation_bindings` lives in move-baseline-binding.sql, whose CREATE DOMAIN
 * block collides with base-enums-domains. Lift the one table the way every other suite here
 * lifts an out-of-slice block.
 */
const bindingsDdl = ((): string => {
  const sql = readFileSync(
    resolve(here, "../../src/schema/move-baseline-binding.sql"),
    "utf8",
  );
  const m = /^CREATE TABLE operation_observation_bindings \([\s\S]*?^\);$/m.exec(sql);
  if (m === null) throw new Error("operation_observation_bindings: block not found");
  return m[0];
})();

const applyBindingsDdl = (url: string): void => {
  execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: `${bindingsDdl}\n`,
    encoding: "utf-8",
    timeout: 60_000,
  });
};

// ─── observer doubles ───────────────────────────────────────────────────────
//
// The observation service is a port (no operation worker calls the gateway client).
// These doubles stand in for its four answers and, crucially, count their invocations — the
// "no lease, no read" property is only provable by asserting the read never happened.

interface RecordingObserver extends ReceiveT0Observer {
  readonly calls: Array<{ walletPublicKey: string; role: string }>;
}

function observerReturning(outcome: ReceiveT0Observation): RecordingObserver {
  const calls: Array<{ walletPublicKey: string; role: string }> = [];
  return {
    calls,
    observe: async (walletPublicKey, role) => {
      calls.push({ walletPublicKey, role });
      return outcome;
    },
  };
}

/** exact genesis: a validated never-used node-generated wallet. */
const genesisObservation = (observationId: string): ReceiveT0Observation => ({
  kind: "VERIFIED",
  observationId,
  projection: { role: "genesis", S: "", P: "", B: "0", I: null },
});

/** A settled head, so the suite does not only ever exercise the genesis shape. */
const headObservation = (observationId: string): ReceiveT0Observation => ({
  kind: "VERIFIED",
  observationId,
  projection: {
    role: "receiver",
    S: "head-state-signature",
    P: "previous-step-2-state-signature",
    B: "12.5",
    I: "a".repeat(64),
  },
});

/**
 * An observer that lets the test act on the database in the window between the lease gate and
 * the bind — the exact window in which a lease can move under a read that is already in flight.
 */
function observerDuring(
  outcome: ReceiveT0Observation,
  duringRead: () => Promise<void> | void,
): RecordingObserver {
  const calls: Array<{ walletPublicKey: string; role: string }> = [];
  return {
    calls,
    observe: async (walletPublicKey, role) => {
      calls.push({ walletPublicKey, role });
      await duringRead();
      return outcome;
    },
  };
}

// ─── suite ──────────────────────────────────────────────────────────────────

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;
let pool: SeededPool;

const OP_1 = OP(1);
const OP_2 = OP(2);

const bindingRows = (operationId: string): Array<{ observation_id: string; wallet_public_key: string; evidence_role: string }> =>
  JSON.parse(
    psqlMust(
      dbUrl,
      `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
         SELECT observation_id::text AS observation_id, wallet_public_key, evidence_role
           FROM operation_observation_bindings WHERE operation_id = '${operationId}') t;`,
    ).trim() || "[]",
  ) as Array<{ observation_id: string; wallet_public_key: string; evidence_role: string }>;

const walletPublicKey = (walletId: string): string =>
  psqlMust(dbUrl, `SELECT public_key FROM wallets WHERE id = '${walletId}';`).trim();

const activeLeaseEpoch = (walletId: string): string =>
  psqlMust(dbUrl, `SELECT lease_epoch::text FROM wallet_active_leases WHERE wallet_id = '${walletId}';`).trim();

/** step-2 transaction, run here so this suite starts from a lawfully assigned receive. */
async function assign(
  operationId: string,
  walletId: string,
): Promise<{ membershipId: string; leaseGroupId: string; leaseEpoch: bigint }> {
  const leaseGroupId = await createLeaseGroup(db, { rootOperationId: operationId });
  const lease = await LEASES.acquireReceiveWindowLease(db, {
    walletId,
    leaseGroupId,
    operationId,
    ownerInstanceId: OWNER,
  });
  await db.query(
    `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role) VALUES ('${operationId}', '${walletId}', 'RECEIVER')`,
  );
  return { membershipId: lease.membershipId, leaseGroupId, leaseEpoch: lease.leaseEpoch };
}

function reset(): void {
  psqlMust(dbUrl, `DELETE FROM operation_observation_bindings;`);
  psqlMust(dbUrl, RESET_POOL);
}

describe("receive T0 capture under a fenced lease (real PG)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error(
          "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup provisioned no test database",
        );
      }
      return;
    }
    dbName = `t0_capture_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);
    applyPoolSchema(dbUrl);
    applyBindingsDdl(dbUrl);
    seedRegistry(dbUrl);
    pool = seedWallets(dbUrl, { eligibleCount: 4, unverifiedCount: 1 });
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

  // ── 1. Frozen statement shape ─────────────────────────────────────────────

  it("step 3: the gate reads the pubkey out of the leased wallet row, never from a parameter", () => {
    const sql = RECEIVE_T0_STATEMENTS.SELECT_HELD_RECEIVE_LEASE;
    expect(sql).toContain("FROM wallet_active_leases l");
    expect(sql).toContain("JOIN wallets w ON w.id = l.wallet_id");
    expect(sql).toContain("w.public_key AS wallet_public_key");
    expect(sql).toContain("l.lease_role = 'RECEIVE_WINDOW'");
    // bigint through a JSON number silently loses precision.
    expect(sql).toContain("l.lease_epoch::text");
    // Only wallet_id and operation_id are bound; the pubkey is never $n.
    expect(sql.match(/\$\d/g)).toEqual(["$1", "$2"]);
  });

  it("step 3: the T0 bind is one lease-predicated INSERT. SELECT, fenced on lease_epoch", () => {
    const sql = RECEIVE_T0_STATEMENTS.BIND_RECEIVER_T0;
    expect(sql).toContain("INSERT INTO operation_observation_bindings");
    // INSERT... SELECT, not VALUES: the lease predicate and the write are one statement, so
    // there is no check-then-write window for a concurrent release to slip through.
    expect(sql).toContain("SELECT l.operation_id, $3, 'RECEIVER_T0', w.public_key");
    expect(sql).not.toContain("VALUES");
    expect(sql).toContain("l.lease_epoch = $4");
    expect(sql).toContain("l.lease_role = 'RECEIVE_WINDOW'");
  });

  // ── 2. The lease gates the read itself ──────────────────────────

  it.skipIf(!live)(
    "step 3: without a lease the gateway read is never issued and nothing is bound",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const observer = observerReturning(genesisObservation(randomUUID()));

      const outcome = await captureReceiveT0(db, {
        operationId: OP_1,
        walletId: pool.eligible[0]!,
        observer,
        assertMoneyAdmitted: () => undefined,
      });

      expect(outcome.kind).toBe("LEASE_NOT_HELD");
      // The property is not "it returned an error" — it is that no read happened at all.
      expect(observer.calls).toEqual([]);
      expect(bindingRows(OP_1)).toEqual([]);
      expect(await classifyReceiveT0Phase(db, OP_1)).toBe("NO_LEASE");
    },
    60_000,
  );

  it.skipIf(!live)(
    "negative control: the same bind WITHOUT the lease predicate does persist a leaseless T0",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      const observationId = randomUUID();

      // Strip the lease join and its predicate — what the module would be if the fence were
      // application-side only. It binds happily with no lease anywhere in the database, which
      // is precisely the state the fenced form refuses.
      const unfenced = `INSERT INTO operation_observation_bindings
             (operation_id, observation_id, evidence_role, wallet_public_key)
           VALUES ('${OP_1}', '${observationId}', 'RECEIVER_T0', '${walletPublicKey(walletId)}')`;
      const wrote = await db.query(unfenced);

      expect(wrote.rowCount).toBe(1);
      expect(bindingRows(OP_1)).toHaveLength(1);
      expect(
        Number(psqlMust(dbUrl, `SELECT count(*)::int FROM wallet_active_leases;`).trim()),
      ).toBe(0);
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 3: a lawfully assigned receive observes ITS OWN wallet's key and binds RECEIVER_T0",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[1]!;
      const assigned = await assign(OP_1, walletId);
      const observationId = randomUUID();
      const observer = observerReturning(headObservation(observationId));

      const outcome = await captureReceiveT0(db, { operationId: OP_1, walletId, observer,
        assertMoneyAdmitted: () => undefined,
});

      expect(outcome).toEqual({
        kind: "CAPTURED",
        t0: {
          observationId,
          s0: "head-state-signature",
          p0: "previous-step-2-state-signature",
          b0: "12.5",
        },
        walletPublicKey: walletPublicKey(walletId),
        leaseGroupId: assigned.leaseGroupId,
        leaseEpoch: assigned.leaseEpoch,
      });
      // The observed key came from the leased wallet row, not from the caller.
      expect(observer.calls).toEqual([
        { walletPublicKey: walletPublicKey(walletId), role: "RECEIVE_T0" },
      ]);
      expect(bindingRows(OP_1)).toEqual([
        {
          observation_id: observationId,
          wallet_public_key: walletPublicKey(walletId),
          evidence_role: "RECEIVER_T0",
        },
      ]);
    },
    60_000,
  );

  // ── 3. Genesis is exact ─────────────────────────────────────────

  it.skipIf(!live)(
    "a never-used wallet yields exactly S0=\"\", P0=\"\", B0=\"0\" — not null, not omitted",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      await assign(OP_1, walletId);
      const observationId = randomUUID();

      const outcome = await captureReceiveT0(db, {
        operationId: OP_1,
        walletId,
        observer: observerReturning(genesisObservation(observationId)),
        assertMoneyAdmitted: () => undefined,
      });

      expect(outcome.kind).toBe("CAPTURED");
      if (outcome.kind !== "CAPTURED") return;
      expect(outcome.t0).toEqual({ observationId, s0: "", p0: "", b0: "0" });
      // Explicit: the fields are present and empty, which is a different fact from absent.
      expect(Object.keys(outcome.t0).sort()).toEqual(["b0", "observationId", "p0", "s0"]);
      expect(outcome.t0.s0).not.toBeNull();
      expect(outcome.t0.b0).not.toBeNull();
    },
    60_000,
  );

  // ── 4. Step 4 — the not-verified branch ───────────────────────────────────

  it.skipIf(!live)(
    "step 4: an INDETERMINATE read binds no T0 and is never coerced into genesis",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      await assign(OP_1, walletId);

      const outcome = await captureReceiveT0(db, {
        operationId: OP_1,
        walletId,
        observer: observerReturning({ kind: "INDETERMINATE", detail: "truncated gateway body" }),
        assertMoneyAdmitted: () => undefined,
      });

      expect(outcome).toEqual({
        kind: "NOT_VERIFIED",
        reason: "observation_indeterminate",
        detail: "truncated gateway body",
      });
      expect(bindingRows(OP_1)).toEqual([]);
      // row 1: still a safe resumable state, not an anomaly.
      expect(await classifyReceiveT0Phase(db, OP_1)).toBe("PROVEN_NOT_STARTED");
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 4: an UNVERIFIED read binds no T0 either",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      await assign(OP_1, walletId);

      const outcome = await captureReceiveT0(db, {
        operationId: OP_1,
        walletId,
        observer: observerReturning({ kind: "UNVERIFIED", detail: "step_2 signature mismatch" }),
        assertMoneyAdmitted: () => undefined,
      });

      expect(outcome).toEqual({
        kind: "NOT_VERIFIED",
        reason: "observation_unverified",
        detail: "step_2 signature mismatch",
      });
      expect(bindingRows(OP_1)).toEqual([]);
      expect(await classifyReceiveT0Phase(db, OP_1)).toBe("PROVEN_NOT_STARTED");
    },
    60_000,
  );

  // ── 5. The epoch fence: the lease moves while the read is in flight ───────

  it.skipIf(!live)(
    "step 3: a lease released mid-read voids the T0 — LEASE_LOST, zero rows bound",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      const assigned = await assign(OP_1, walletId);

      // The verification-complete barrier releases the group while an orphaned T0 read is
      // still outstanding: real release path, real terminal proof, no fixture shortcut.
      const observer = observerDuring(genesisObservation(randomUUID()), async () => {
        driveReceiveToLanded(dbUrl, OP_1, walletId);
        await releaseWithLandedProof(db, {
          operationId: OP_1,
          walletId,
          membershipId: assigned.membershipId,
          leaseGroupId: assigned.leaseGroupId,
          leaseEpoch: assigned.leaseEpoch,
        });
      });

      const outcome = await captureReceiveT0(db, { operationId: OP_1, walletId, observer,
        assertMoneyAdmitted: () => undefined,
});

      expect(outcome.kind).toBe("LEASE_LOST");
      expect(observer.calls).toHaveLength(1);
      expect(bindingRows(OP_1)).toEqual([]);
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 3: a lease at a NEWER epoch mid-read voids the T0 even though the row still matches",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      const first = await assign(OP_1, walletId);

      // The foundation bumps `lease_epoch` to a strictly greater value on every hand-off
      // (`nextEpoch`, "strictly greater epoch (ABA safety)"), which is how a capability from
      // before a hand-off is recognised as stale. Bumped directly here so the row keeps the
      // SAME (wallet_id, operation_id, lease_role) triple — that isolation is the point: the
      // only thing that can reject this bind is the epoch itself.
      const observer = observerDuring(genesisObservation(randomUUID()), () => {
        psqlMust(
          dbUrl,
          `UPDATE wallet_active_leases SET lease_epoch = lease_epoch + 1 WHERE wallet_id = '${walletId}';`,
        );
      });

      const outcome = await captureReceiveT0(db, { operationId: OP_1, walletId, observer,
        assertMoneyAdmitted: () => undefined,
});

      expect(activeLeaseEpoch(walletId)).toBe((first.leaseEpoch + 1n).toString());
      expect(outcome.kind).toBe("LEASE_LOST");
      expect(bindingRows(OP_1)).toEqual([]);
    },
    60_000,
  );

  it.skipIf(!live)(
    "negative control: drop the lease_epoch conjunct and the stale-epoch capture DOES bind",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      const first = await assign(OP_1, walletId);
      psqlMust(
        dbUrl,
        `UPDATE wallet_active_leases SET lease_epoch = lease_epoch + 1 WHERE wallet_id = '${walletId}';`,
      );

      const unfenced = RECEIVE_T0_STATEMENTS.BIND_RECEIVER_T0.replace(
        " AND l.lease_epoch = $4",
        "",
      );
      expect(unfenced).not.toContain("lease_epoch");
      const wrote = await db.query<{ observation_id: string }>(unfenced, [
        walletId,
        OP_1,
        randomUUID(),
        first.leaseEpoch.toString(),
      ]);

      // The stale worker persists a T0 it has no standing to take: exactly the defect the
      // conjunct removes.
      expect(wrote.rows).toHaveLength(1);
      expect(bindingRows(OP_1)).toHaveLength(1);
    },
    60_000,
  );

  // ── 6. Exactly-once T0 under real cross-process concurrency ───────────────

  it.skipIf(!live)(
    "step 3: two concurrent captures of one receive bind exactly one T0; the winner is never overwritten",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      await assign(OP_1, walletId);

      // Two separate psql OS processes: the race is decided by the database, not by this
      // event loop interleaving two awaits on one connection.
      const a = new PsqlSessionExecutor(dbUrl);
      const b = new PsqlSessionExecutor(dbUrl);
      const idA = randomUUID();
      const idB = randomUUID();
      try {
        a.start();
        b.start();
        const [outA, outB] = await Promise.all([
          captureReceiveT0(a, {
            operationId: OP_1,
            walletId,
            observer: observerReturning(genesisObservation(idA)),
            assertMoneyAdmitted: () => undefined,
          }),
          captureReceiveT0(b, {
            operationId: OP_1,
            walletId,
            observer: observerReturning(headObservation(idB)),
            assertMoneyAdmitted: () => undefined,
          }),
        ]);

        const kinds = [outA.kind, outB.kind].sort();
        expect(kinds).toEqual(["ALREADY_CAPTURED", "CAPTURED"]);

        const rows = bindingRows(OP_1);
        expect(rows).toHaveLength(1);
        const durable = rows[0]!.observation_id;
        expect([idA, idB]).toContain(durable);

        // The loser reports the DURABLE T0, not its own — the node does not
        // overwrite T0 in place, so the arm barrier compares against one stable value.
        const loser = outA.kind === "ALREADY_CAPTURED" ? outA : outB;
        expect(loser.kind === "ALREADY_CAPTURED" && loser.t0ObservationId).toBe(durable);
      } finally {
        a.stop();
        b.stop();
      }
    },
    90_000,
  );

  it.skipIf(!live)(
    "schema test: a second RECEIVER_T0 row for one operation is rejected by the database itself",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      await assign(OP_1, walletId);
      await captureReceiveT0(db, {
        operationId: OP_1,
        walletId,
        observer: observerReturning(genesisObservation(randomUUID())),
        assertMoneyAdmitted: () => undefined,
      });

      // Straight at the DB layer, bypassing the module entirely.
      const second = await db
        .query(
          `INSERT INTO operation_observation_bindings
             (operation_id, observation_id, evidence_role, wallet_public_key)
           VALUES ('${OP_1}', '${randomUUID()}', 'RECEIVER_T0', '${walletPublicKey(walletId)}')`,
        )
        .then(
          () => null,
          (e: unknown) => e as { code?: string },
        );
      expect(second?.code).toBe("23505");
      expect(bindingRows(OP_1)).toHaveLength(1);
    },
    60_000,
  );

  it.skipIf(!live)(
    "schema test: a second active lease row for one wallet is rejected by the PRIMARY KEY",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      seedReceive(dbUrl, OP_2);
      const walletId = pool.eligible[0]!;
      const held = await assign(OP_1, walletId);

      // `RECONCILIATION` so the eligibility trigger returns early and the PRIMARY KEY is
      // the only thing left that can reject the row — the constraint proof is the point,
      // not the trigger's.
      const clash = await db
        .query(
          `INSERT INTO wallet_active_leases
             (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
              lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
           VALUES ('${walletId}', '${randomUUID()}', '${held.leaseGroupId}', '${OP_2}', '${OP_2}',
                   'RECONCILIATION', 99, now(), now(), '${OWNER}')`,
        )
        .then(
          () => null,
          (e: unknown) => e as { code?: string },
        );
      expect(clash?.code).toBe("23505");
      expect(String(clash)).toContain("wallet_active_leases_pkey");
    },
    60_000,
  );

  // ── 7. row 1 — crash between the lease TX and the read ────────────

  it.skipIf(!live)(
    "lease with no T0 classifies PROVEN_NOT_STARTED and the capture safely resumes",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      await assign(OP_1, walletId);

      // The crash window: the assignment DB-TX committed, OBSERVE never completed. Nothing
      // beyond the lease is durable.
      expect(await classifyReceiveT0Phase(db, OP_1)).toBe("PROVEN_NOT_STARTED");
      expect(bindingRows(OP_1)).toEqual([]);
      // The wallet is PINNED and T0-less — resumable, not anomalous.
      expect(
        psqlMust(dbUrl, `SELECT state::text FROM wallets WHERE id = '${walletId}';`).trim(),
      ).toBe("PINNED");

      const resumed = await captureReceiveT0(db, {
        operationId: OP_1,
        walletId,
        observer: observerReturning(genesisObservation(randomUUID())),
        assertMoneyAdmitted: () => undefined,
      });

      expect(resumed.kind).toBe("CAPTURED");
      expect(await classifyReceiveT0Phase(db, OP_1)).toBe("T0_DURABLE");
    },
    60_000,
  );

  it.skipIf(!live)(
    "a re-run after T0 is durable returns the SAME observation, never a fresh one",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const walletId = pool.eligible[0]!;
      await assign(OP_1, walletId);
      const original = randomUUID();
      await captureReceiveT0(db, {
        operationId: OP_1,
        walletId,
        observer: observerReturning(genesisObservation(original)),
        assertMoneyAdmitted: () => undefined,
      });

      const rerun = await captureReceiveT0(db, {
        operationId: OP_1,
        walletId,
        observer: observerReturning(headObservation(randomUUID())),
        assertMoneyAdmitted: () => undefined,
      });

      expect(rerun).toEqual({ kind: "ALREADY_CAPTURED", t0ObservationId: original });
      expect(bindingRows(OP_1).map((r) => r.observation_id)).toEqual([original]);
    },
    60_000,
  );

  // ── 8./B-08 recovery gate still holds at T0 time ────────────────────

  it.skipIf(!live)(
    "B-08: a never-recovery-verified wallet cannot be leased, so it can never reach a T0 read",
    async () => {
      reset();
      seedReceive(dbUrl, OP_1);
      const unverified = pool.unverified[0]!;

      const rejected = await assign(OP_1, unverified).then(
        () => null,
        (e: unknown) => e as Error,
      );
      expect(rejected).toBeInstanceOf(Error);
      expect(String(rejected)).toMatch(/RECOVERY|recovery/);

      const observer = observerReturning(genesisObservation(randomUUID()));
      const outcome = await captureReceiveT0(db, {
        operationId: OP_1,
        walletId: unverified,
        observer,
        assertMoneyAdmitted: () => undefined,
      });
      expect(outcome.kind).toBe("LEASE_NOT_HELD");
      expect(observer.calls).toEqual([]);
    },
    60_000,
  );
});
