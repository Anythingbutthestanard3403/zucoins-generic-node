// real-PostgreSQL bounded receive-pool allocator.
//
// Governing: (admission) and steps 1–2 (wallet assignment);
// (RECEIVE_QUEUE_CAP ladder, FIFO promotion);
// B-08.
//
// Every contender in a concurrency case is a separate `psql` OS process, so the race is at
// the database transaction boundary. `SKIP LOCKED` semantics and the CREATED-recheck
// lost-update race are not observable against a mock — an in-memory slot store cannot
// express either, which is why this suite is real-PG only.
//
// Each positive property has a paired negative that shows the guard is what produces the
// green: the widened predicate DOES select an ineligible wallet, plain FOR UPDATE DOES
// block, and the FIFO expectation is asserted to differ from insertion order.
//
// Connectivity: TEST_DATABASE_URL (vitest.global-setup) or PG_REQUIRED fail-closed.

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  acquireLeases,
  assertLeaseFoundationReady,
  createLeaseGroup,
  migrateLeaseFoundation,
} from "../../src/leases/index.ts";
import { INSERT_PENDING_DESTINATION_FOR_WALLET_SQL } from "../../src/api/insert-node-generated-wallet.ts";
import {
  RECEIVE_ALLOCATOR_STATEMENTS,
  ReceiveAllocatorError,
  admitReceive,
  assignReceiveWallet,
  assignReceiveWalletThenObserve,
  countUnassignedReceives,
  promoteQueuedReceives,
  selectQueuedReceivesFifo,
  type AssignReceiveWalletOutcome,
  type ReceiveLeasePort,
  type ReceiveQueueLimits,
} from "../../src/receive/pool-allocator.ts";
import {
  PsqlExecutor,
  PsqlSessionExecutor,
  psqlMust,
  runPsql,
  withDatabase,
  withTx,
} from "../psql-harness.ts";
import { tokenizeCustodySql } from "../custody-eligibility-sql-statements.js";
import { verificationModeFixtureSql } from "../verification-mode-fixture.js";

const here = dirname(fileURLToPath(import.meta.url));
const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const schemaDir = resolve(here, "../../src/schema");
const readSchema = (name: string): string => readFileSync(resolve(schemaDir, name), "utf8");

// ─── prerequisite DDL ───────────────────────────────────────────────────────
//
// base-enums-domains already defines every domain and enum operations.sql restates, so
// only operations.sql's three object blocks are lifted out — applying the file whole would
// fail on duplicate CREATE DOMAIN. Same extract-the-block pattern the lease foundation
// suites use for `nodes`.

const blockFrom = (sql: string, header: RegExp, label: string): string => {
  const m = header.exec(sql);
  if (m === null) throw new Error(`${label}: block not found`);
  return m[0];
};

const prerequisiteDdl = ((): string => {
  const base = readSchema("base-enums-domains.sql");
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = blockFrom(registry, /^CREATE TABLE nodes \([\s\S]*?^\);$/m, "nodes");
  const implementers = blockFrom(
    registry,
    /^CREATE TABLE implementers \([\s\S]*?^\);$/m,
    "implementers",
  );
  return `${base}\n${nodes}\n${implementers}\n`;
})();

const custodySql = tokenizeCustodySql(readSchema("custody-eligibility.sql"))
  .map((s) => s.raw)
  .join("\n");

const operationsSql = ((): string => {
  const sql = readSchema("operations.sql");
  return [
    blockFrom(sql, /^CREATE TABLE operations \([\s\S]*?^\);$/m, "operations"),
    blockFrom(sql, /^CREATE TABLE operation_wallets \([\s\S]*?^\);$/m, "operation_wallets"),
    blockFrom(
      sql,
      /^CREATE UNIQUE INDEX operations_one_spawn_per_parent_uidx[\s\S]*?;$/m,
      "spawn index",
    ),
  ].join("\n");
})();

const receiveReleaseProofsSql = `
CREATE TABLE receive_release_proofs (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  release_kind text NOT NULL CHECK (release_kind IN (
    'VERIFICATION_COMPLETE','EXPIRED_T0_UNCHANGED','EXPIRED_PROVEN_NOT_STARTED')),
  t0_observation_id uuid,
  fresh_observation_id uuid,
  verification_acknowledgement_id uuid,
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 sha256_hex NOT NULL,
  released_at timestamptz NOT NULL,
  CHECK (
    (release_kind = 'VERIFICATION_COMPLETE'
      AND verification_acknowledgement_id IS NOT NULL
      AND t0_observation_id IS NOT NULL AND fresh_observation_id IS NOT NULL)
    OR
    (release_kind = 'EXPIRED_T0_UNCHANGED'
      AND verification_acknowledgement_id IS NULL
      AND t0_observation_id IS NOT NULL AND fresh_observation_id IS NOT NULL)
    OR
    (release_kind = 'EXPIRED_PROVEN_NOT_STARTED'
      AND verification_acknowledgement_id IS NULL
      AND t0_observation_id IS NULL AND fresh_observation_id IS NULL)
  )
);
`;

const applySchema = (url: string): void => {
  try {
    execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      input: `${prerequisiteDdl}${custodySql}\n${readSchema("wallet-money-capability.sql")}\n${operationsSql}\n${receiveReleaseProofsSql}\n${verificationModeFixtureSql()}\n`,
      encoding: "utf-8",
      timeout: 60_000,
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`schema apply failed: ${(e.stderr ?? "").trim()}`);
  }
};

// ─── fixtures ───────────────────────────────────────────────────────────────

const NODE = "b0000000-0000-4000-8000-000000000264";
const IMPLEMENTER = "b0000000-0000-4000-8000-000000000265";
const OWNER = "c0000000-0000-4000-8000-000000000264";

/** Deterministic wallet UUIDs whose binary order matches the numeric suffix. */
const W = (n: number): string => `a0000000-0000-4000-8000-${n.toString().padStart(12, "0")}`;
/** Deterministic operation UUIDs, likewise ordered. */
const OP = (n: number): string => `d0000000-0000-4000-8000-${n.toString().padStart(12, "0")}`;

const pubkey = (suffix: string): string =>
  `${"A".repeat(43 - suffix.length)}${suffix}=`;

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

/**
 * Pool shape. Wallets 1..ELIGIBLE_COUNT satisfy all three/B-08 conjuncts. The two
 * negatives below are permanent rows, not per-test mutations: recovery_verified_at is
 * monotonic and key_origin is immutable (custody triggers), so neither conjunct can be
 * dropped by an UPDATE. Keeping them resident means EVERY case in this file — not just the
 * predicate case — also proves the allocator never reaches them.
 */
const ELIGIBLE_COUNT = 12;
/** node_generated + AVAILABLE, but never recovery-verified. */
const UNVERIFIED_WALLET = W(ELIGIBLE_COUNT + 1);
/** recovery-verified + AVAILABLE, but imported rather than node_generated. */
const IMPORTED_WALLET = W(ELIGIBLE_COUNT + 2);
const ELIGIBLE_WALLETS = Array.from({ length: ELIGIBLE_COUNT }, (_v, i) => W(i + 1));

/**
 * Returns the pool to its seeded shape. `state` carries companion columns
 * (wallets_retired_at_iff, wallets_quarantine_reason_iff), so all three reset together or
 * the CHECK fires.
 */
const RESET_STATE = `
TRUNCATE receive_release_proofs, operation_wallets, wallet_active_leases, wallet_lease_memberships,
         lease_group_operations, lease_groups, lease_release_proofs,
         lease_audit_events, wallet_lease_epoch_highwater
  RESTART IDENTITY CASCADE;
DELETE FROM operations;
DELETE FROM destinations;
UPDATE wallets
   SET state = 'AVAILABLE', retired_at = NULL, quarantine_reason = NULL
 WHERE state <> 'AVAILABLE';
`;

function seedRegistry(url: string): void {
  psqlMust(
    url,
    `INSERT INTO nodes (id, display_name, identity_public_key)
       VALUES ('${NODE}', 'pool-allocator-node', '${pubkey("ALLOCATOR_NODE")}')
       ON CONFLICT DO NOTHING;
     INSERT INTO implementers (id, name)
       VALUES ('${IMPLEMENTER}', 'pool-allocator-implementer')
       ON CONFLICT DO NOTHING;`,
  );
}

const verificationId = (n: number): string =>
  `e0000000-0000-4000-8000-${n.toString().padStart(12, "0")}`;

/** Stamps recovery through a real verification row — recovery_verified_at has no default. */
function verifyRecovery(url: string, walletId: string, n: number, key: string): void {
  psqlMust(
    url,
    `INSERT INTO wallet_recovery_verifications
       (id, wallet_id, method, public_key, export_sha256, audit_event_id, verified_at, verifier_identity)
       VALUES ('${verificationId(n)}', '${walletId}', 'AUDITED_EXPORT', '${key}',
               '${sha(`export-${n}`)}', '${randomUUID()}', now(), 'pool-allocator-test')
       ON CONFLICT DO NOTHING;
     UPDATE wallets
        SET recovery_verified_at = now(), recovery_verification_id = '${verificationId(n)}'
      WHERE id = '${walletId}'
        AND recovery_verified_at IS NULL;`,
  );
}

function seedWallets(url: string): void {
  const rows: string[] = [];
  for (let n = 1; n <= ELIGIBLE_COUNT; n += 1) {
    rows.push(`('${W(n)}', '${NODE}', '${pubkey(`W${n}`)}', 'node_generated', 'AVAILABLE')`);
  }
  rows.push(
    `('${UNVERIFIED_WALLET}', '${NODE}', '${pubkey("WUNVER")}', 'node_generated', 'AVAILABLE')`,
  );
  rows.push(`('${IMPORTED_WALLET}', '${NODE}', '${pubkey("WIMPORT")}', 'imported', 'AVAILABLE')`);
  psqlMust(
    url,
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ${rows.join(",\n")}
       ON CONFLICT DO NOTHING;`,
  );

  for (let n = 1; n <= ELIGIBLE_COUNT; n += 1) {
    verifyRecovery(url, W(n), n, pubkey(`W${n}`));
  }
  // The imported wallet IS recovery-verified: its only defect is key_origin, which keeps
  // that conjunct isolated.
  verifyRecovery(url, IMPORTED_WALLET, ELIGIBLE_COUNT + 2, pubkey("WIMPORT"));
  // UNVERIFIED_WALLET is deliberately left unstamped.
}

function insertPendingDest(url: string, walletId: string, label = "pool"): void {
  psqlMust(
    url,
    INSERT_PENDING_DESTINATION_FOR_WALLET_SQL.replace(/\$1::uuid/g, `'${walletId}'::uuid`)
      .replace(/\$2::uuid/g, `'${NODE}'::uuid`)
      .replace("$3", `'${label}'`)
      .replace("$4", `'PENDING'`),
  );
}

function blessDest(url: string, walletId: string): void {
  psqlMust(
    url,
    `UPDATE destinations
        SET state = 'BLESSED',
            blessed_at = now(),
            blessed_by_device_key_id = '${randomUUID()}',
            blessing_artifact_id = '${randomUUID()}',
            retired_at = NULL
      WHERE wallet_id = '${walletId}';`,
  );
}

function retireDest(url: string, walletId: string): void {
  psqlMust(
    url,
    `UPDATE destinations
        SET state = 'RETIRED',
            blessed_at = COALESCE(blessed_at, now()),
            blessed_by_device_key_id = COALESCE(blessed_by_device_key_id, '${randomUUID()}'),
            blessing_artifact_id = COALESCE(blessing_artifact_id, '${randomUUID()}'),
            retired_at = now()
      WHERE wallet_id = '${walletId}';`,
  );
}

/**
 * Shrinks the eligible pool to the first `keep` wallets by PINNING the rest. PIN is the
 * realistic way the pool narrows (wallets busy on other receives) and, unlike RETIRED or
 * QUARANTINED, carries no companion column to reset.
 */
function keepEligible(url: string, keep: number): void {
  const kept = ELIGIBLE_WALLETS.slice(0, keep).map((id) => `'${id}'`).join(", ");
  const exclusion = kept === "" ? "" : ` AND id NOT IN (${kept})`;
  psqlMust(
    url,
    `UPDATE wallets SET state = 'PINNED'
      WHERE key_origin = 'node_generated'
        AND state = 'AVAILABLE'${exclusion};`,
  );
}

/**
 * A `RECEIVE_EXTERNAL/CREATED` receive with no wallet. The CHECKs force
 * discriminator = id, an anchor, after_landing, and NULL receiver/expiry/t0 while CREATED.
 */
function receiveValues(operationId: string, createdAt?: string): string {
  const created = createdAt === undefined ? "now()" : `'${createdAt}'::timestamptz`;
  return `('${operationId}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'CREATED',
           '1.5', 'HOLD', '${operationId}', 'anchor-${operationId.slice(-12)}',
           '${operationId}-idem-key', '${sha(operationId)}', ${created})`;
}

const INSERT_RECEIVE_COLUMNS = `INSERT INTO operations
  (id, node_id, implementer_id, kind, status, amount_zkz, after_landing,
   discriminator, anchor, idempotency_key, request_sha256, created_at)
VALUES `;

function seedReceive(url: string, operationId: string, createdAt?: string): void {
  psqlMust(url, `${INSERT_RECEIVE_COLUMNS}${receiveValues(operationId, createdAt)};`);
}

/**
 * The binding the composition root supplies: node-core's persisted lease repository. The
 * allocator injects it rather than importing it because `receive` is a leaf module
 * (test/boundaries.test.ts); this file may import both freely, as the gate scans src/ only.
 */
const LEASES: ReceiveLeasePort = {
  createLeaseGroup: (db, rootOperationId) => createLeaseGroup(db, { rootOperationId }),
  acquireReceiveWindowLease: async (db, p) => {
    const [lease] = await acquireLeases(db, {
      wallets: [{ walletId: p.walletId, leaseRole: "RECEIVE_WINDOW" }],
      leaseGroupId: p.leaseGroupId,
      rootOperationId: p.operationId,
      operationId: p.operationId,
      ownerInstanceId: p.ownerInstanceId,
    });
    if (lease === undefined) throw new Error("acquireLeases returned no membership");
    return { membershipId: lease.membershipId, leaseEpoch: lease.leaseEpoch };
  },
};

const LIMITS: ReceiveQueueLimits = { receiveQueueCap: 3, receiveQueueMaxWaitSecs: 45 };

const countRows = (url: string, table: string, where = "true"): number =>
  Number(psqlMust(url, `SELECT count(*)::int FROM ${table} WHERE ${where};`).trim());

const walletState = (url: string, walletId: string): string =>
  psqlMust(url, `SELECT state::text FROM wallets WHERE id = '${walletId}';`).trim();

// ─── suite ──────────────────────────────────────────────────────────────────

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;

describe("bounded receive-pool allocator (real PG / separate processes)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error(
          "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup provisioned no test database",
        );
      }
      return;
    }
    dbName = `pool_allocator_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);
    applySchema(dbUrl);
    seedRegistry(dbUrl);
    seedWallets(dbUrl);
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

  // ── 1. eligibility predicate ────────────────────────────────────────

  it("step 1: frozen literal carries eligibility, release exclusion, SKIP LOCKED and LIMIT 1", () => {
    const sql = RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET;
    expect(sql).toContain("w.key_origin = 'node_generated'");
    expect(sql).toContain("w.recovery_verified_at IS NOT NULL");
    expect(sql).toContain("w.state = 'AVAILABLE'");
    expect(sql).toContain("w.allow_external_receive IS TRUE");
    expect(sql).toContain("FROM destinations d");
    expect(sql).toContain("d.state = 'BLESSED'");
    expect(sql).not.toContain("IS DISTINCT FROM 'RETIRED'");
    expect(sql).toContain("FROM receive_release_proofs rrp");
    expect(sql).toContain("JOIN operation_wallets ow");
    expect(sql).toContain("ow.wallet_id = w.id");
    expect(sql).toContain("FROM lease_release_proofs lrp");
    expect(sql).toContain("lrp.proof_kind = 'RECEIVE_EXPIRED_T0'");
    expect(sql).toContain("FOR UPDATE SKIP LOCKED");
    expect(sql).toContain("LIMIT 1");
    // Dest exclusion is "already a BLESSED sink". Automatic-sink must not leak in as a
    // positive conjunct (that would require blessing to receive).
    const destExclusion =
      "NOT EXISTS ( SELECT 1 FROM destinations d WHERE d.wallet_id = w.id AND d.state = 'BLESSED')";
    expect(sql).toContain(destExclusion);
    expect(sql.replace(destExclusion, "")).not.toContain("BLESSED");
  });

  it.skipIf(!live)(
    "dest-on-mint PENDING dest still assigns as a receive worker",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      keepEligible(dbUrl, 1);
      insertPendingDest(dbUrl, W(1));
      expect(
        psqlMust(dbUrl, `SELECT state::text FROM destinations WHERE wallet_id = '${W(1)}';`).trim(),
      ).toBe("PENDING");

      const operationId = OP(80);
      seedReceive(dbUrl, operationId);
      const outcome = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
      );
      expect(outcome.kind).toBe("ASSIGNED");
      if (outcome.kind !== "ASSIGNED") return;
      expect(outcome.walletId).toBe(W(1));
    },
    60_000,
  );

  it.skipIf(!live)(
    "backfill PENDING dest does not poison a receive-eligible wallet",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      keepEligible(dbUrl, 1);
      expect(countRows(dbUrl, "destinations", `wallet_id = '${W(1)}'`)).toBe(0);

      execFileSync("psql", [dbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
        input: readSchema("destinations-pending-backfill.sql"),
        encoding: "utf-8",
        timeout: 30_000,
      });

      expect(
        psqlMust(dbUrl, `SELECT state::text FROM destinations WHERE wallet_id = '${W(1)}';`).trim(),
      ).toBe("PENDING");
      expect(countRows(dbUrl, "destinations", `wallet_id = '${IMPORTED_WALLET}'`)).toBe(0);

      const selected = await db.query<{ id: string }>(
        RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
      );
      expect(selected.rows[0]?.id).toBe(W(1));
    },
    60_000,
  );

  it.skipIf(!live)(
    "BLESSED dest is excluded; PENDING dest is admitted",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      keepEligible(dbUrl, 1);
      insertPendingDest(dbUrl, W(1));

      const pending = await db.query<{ id: string }>(
        RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
      );
      expect(pending.rows[0]?.id).toBe(W(1));

      const oldConjunct = RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET.replace(
        "d.state = 'BLESSED'",
        "d.state IS DISTINCT FROM 'RETIRED'",
      );
      const poisoned = await db.query<{ id: string }>(oldConjunct);
      expect(poisoned.rows).toEqual([]);

      blessDest(dbUrl, W(1));
      const blessed = await db.query<{ id: string }>(
        RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
      );
      expect(blessed.rows).toEqual([]);
    },
    60_000,
  );

  it.skipIf(!live)(
    "RETIRED dest stays receive-eligible",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      keepEligible(dbUrl, 1);
      insertPendingDest(dbUrl, W(1));
      retireDest(dbUrl, W(1));
      expect(
        psqlMust(dbUrl, `SELECT state::text FROM destinations WHERE wallet_id = '${W(1)}';`).trim(),
      ).toBe("RETIRED");

      const selected = await db.query<{ id: string }>(
        RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
      );
      expect(selected.rows[0]?.id).toBe(W(1));
    },
    60_000,
  );

  it.skipIf(!live)(
    "a released AVAILABLE wallet is permanently excluded from a later receive T0",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      keepEligible(dbUrl, 1);
      const releasedOperation = OP(90);
      seedReceive(dbUrl, releasedOperation);
      psqlMust(
        dbUrl,
        `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role)
           VALUES ('${releasedOperation}', '${W(1)}', 'RECEIVER');
         INSERT INTO receive_release_proofs
           (id, operation_id, release_kind, t0_observation_id, fresh_observation_id,
            proof_manifest_text, proof_manifest_sha256, released_at)
           VALUES ('${OP(91)}', '${releasedOperation}', 'EXPIRED_T0_UNCHANGED',
                   '${OP(92)}', '${OP(93)}', '{}', '${sha("released-wallet-proof")}', now());`,
      );

      expect(walletState(dbUrl, W(1))).toBe("AVAILABLE");
      const selected = await db.query<{ id: string }>(
        RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
      );
      expect(selected.rows).toEqual([]);

      psqlMust(dbUrl, `DELETE FROM receive_release_proofs WHERE operation_id = '${releasedOperation}';`);
      const withoutProof = await db.query<{ id: string }>(
        RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
      );
      expect(withoutProof.rows[0]?.id).toBe(W(1));

      psqlMust(
        dbUrl,
        `INSERT INTO lease_release_proofs
           (proof_id, wallet_id, operation_id, membership_id, lease_group_id,
            lease_epoch, proof_kind, proof_digest, issuer, created_at, consumed_at)
           VALUES ('${OP(94)}', '${W(1)}', '${releasedOperation}', '${OP(95)}', '${OP(96)}',
                   1, 'RECEIVE_EXPIRED_T0', '${sha("lease-release-proof")}',
                   'TRUSTED_VERIFIER', now(), now());`,
      );
      const leaseProofSelected = await db.query<{ id: string }>(
        RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
      );
      expect(leaseProofSelected.rows).toEqual([]);

      psqlMust(dbUrl, `DELETE FROM lease_release_proofs WHERE operation_id = '${releasedOperation}';`);
      const withoutEitherProof = await db.query<{ id: string }>(
        RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
      );
      expect(withoutEitherProof.rows[0]?.id).toBe(W(1));
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 1: rejects each dropped conjunct — imported origin, unverified recovery, non-AVAILABLE state",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      // One PINNED wallet supplies the state negative; the other two negatives are the
      // permanent resident rows.
      const pinned = W(3);
      psqlMust(dbUrl, `UPDATE wallets SET state = 'PINNED' WHERE id = '${pinned}';`);

      // Enumerate the whole candidate set rather than the LIMIT 1 head, so the assertion is
      // over every wallet the predicate admits.
      const enumerated = RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET.replace(
        " FOR UPDATE SKIP LOCKED LIMIT 1",
        " ORDER BY id",
      );
      const admitted = (await db.query<{ id: string }>(enumerated)).rows.map((r) => r.id);

      expect(admitted).toEqual(ELIGIBLE_WALLETS.filter((id) => id !== pinned));
      expect(admitted).not.toContain(IMPORTED_WALLET);
      expect(admitted).not.toContain(UNVERIFIED_WALLET);
      expect(admitted).not.toContain(pinned);

      // Negative controls: each widened variant DOES surface exactly the wallet its dropped
      // conjunct was excluding, so the green above is produced by the conjunct rather than
      // by an empty candidate set.
      const widened = async (dropped: string): Promise<string[]> => {
        const sql = enumerated.replace(dropped, "");
        return (await db.query<{ id: string }>(sql)).rows.map((r) => r.id);
      };
      expect(await widened(" w.key_origin = 'node_generated' AND")).toContain(IMPORTED_WALLET);
      expect(await widened(" AND w.recovery_verified_at IS NOT NULL")).toContain(UNVERIFIED_WALLET);
      expect(await widened(" AND w.state = 'AVAILABLE'")).toContain(pinned);
    },
    60_000,
  );

  // ── 2. SKIP LOCKED under real cross-process concurrency ───────────────────

  it.skipIf(!live)(
    "step 1: two concurrent allocators take DIFFERENT wallets instead of serialising",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      keepEligible(dbUrl, 2);

      const a = new PsqlSessionExecutor(dbUrl);
      const b = new PsqlSessionExecutor(dbUrl);
      try {
        a.start();
        b.start();
        await a.begin();
        await b.begin();

        const first = await a.query<{ id: string }>(
          RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
        );
        // B must not block on A's locked row and must not hand back the same wallet.
        const second = await b.query<{ id: string }>(
          RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
        );

        const firstId = first.rows[0]?.id;
        const secondId = second.rows[0]?.id;
        expect(firstId).toBeDefined();
        expect(secondId).toBeDefined();
        expect(secondId).not.toBe(firstId);
        expect([firstId, secondId].sort()).toEqual([W(1), W(2)]);

        await a.rollback();
        await b.rollback();
      } finally {
        a.stop();
        b.stop();
      }
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 1 negative control: dropping SKIP LOCKED makes the second allocator block",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      keepEligible(dbUrl, 1);

      const blocking = RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET.replace(
        "FOR UPDATE SKIP LOCKED",
        "FOR UPDATE",
      );
      const a = new PsqlSessionExecutor(dbUrl);
      const b = new PsqlSessionExecutor(dbUrl);
      try {
        a.start();
        b.start();
        await a.begin();
        await b.begin();
        await a.query(blocking);

        // Same wallet, no SKIP LOCKED: B waits on A's row lock. The harness session times
        // out at 20s, so a short statement_timeout turns the block into a fast, legible
        // failure rather than a hung test.
        await b.query("SET LOCAL statement_timeout = '2s'");
        await expect(b.query(blocking)).rejects.toThrow(/statement timeout|canceling statement/i);

        await b.rollback();
        await a.rollback();
      } finally {
        a.stop();
        b.stop();
      }
    },
    60_000,
  );

  // ── 3. The assignment DB-TX (step 2) ─────────────────────────────────

  it.skipIf(!live)(
    "step 2: one transaction leases the wallet, pins it, and attaches the RECEIVER role",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      const operationId = OP(1);
      seedReceive(dbUrl, operationId);

      const outcome = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
      );
      expect(outcome.kind).toBe("ASSIGNED");
      if (outcome.kind !== "ASSIGNED") return;

      expect(countRows(dbUrl, "wallet_active_leases", `wallet_id = '${outcome.walletId}'`)).toBe(1);
      expect(
        psqlMust(
          dbUrl,
          `SELECT lease_role FROM wallet_active_leases WHERE wallet_id = '${outcome.walletId}';`,
        ).trim(),
      ).toBe("RECEIVE_WINDOW");
      expect(walletState(dbUrl, outcome.walletId)).toBe("PINNED");
      expect(
        countRows(
          dbUrl,
          "operation_wallets",
          `operation_id = '${operationId}' AND wallet_id = '${outcome.walletId}'
             AND operation_role = 'RECEIVER'`,
        ),
      ).toBe(1);
      // The lease sits under the receive's own group.
      expect(
        psqlMust(
          dbUrl,
          `SELECT lease_group_id FROM wallet_active_leases WHERE wallet_id = '${outcome.walletId}';`,
        ).trim(),
      ).toBe(outcome.leaseGroupId);
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 2: a rolled-back assignment leaves no lease, no pin and no role attachment",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      const operationId = OP(2);
      seedReceive(dbUrl, operationId);

      await expect(
        withTx(dbUrl, async (tx) => {
          const assigned = await assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES });
          expect(assigned.kind).toBe("ASSIGNED");
          throw new Error("injected post-assignment failure");
        }),
      ).rejects.toThrow(/injected post-assignment failure/);

      expect(countRows(dbUrl, "wallet_active_leases")).toBe(0);
      expect(countRows(dbUrl, "wallet_lease_memberships")).toBe(0);
      expect(countRows(dbUrl, "lease_groups")).toBe(0);
      expect(countRows(dbUrl, "operation_wallets")).toBe(0);
      expect(countRows(dbUrl, "wallets", "state = 'PINNED'")).toBe(0);
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 2: a receive that is no longer CREATED is refused inside the transaction",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      const operationId = OP(3);
      seedReceive(dbUrl, operationId);
      // operations_check1 admits a RECEIVE_EXTERNAL row in exactly two shapes:
      // (CREATED, no wallet) or (wallet + expiry + t0). A receive past assignment is the
      // second, so drive it to READY the way step 8 would.
      psqlMust(
        dbUrl,
        `UPDATE operations
            SET status = 'READY',
                receiver_wallet_id = '${W(1)}',
                expiry_unix_time_secs = '1900000000',
                t0_observation_id = '${randomUUID()}'
          WHERE id = '${operationId}';`,
      );

      await expect(
        withTx(dbUrl, (tx) => assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES })),
      ).rejects.toThrow(/RECEIVE_NOT_CREATED/);

      expect(countRows(dbUrl, "wallet_active_leases")).toBe(0);
      expect(countRows(dbUrl, "operation_wallets")).toBe(0);
      expect(countRows(dbUrl, "wallets", "state = 'PINNED'")).toBe(0);
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 2: a receive that already holds a RECEIVER attachment is refused a second wallet",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      const operationId = OP(8);
      seedReceive(dbUrl, operationId);

      const first = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
      );
      expect(first.kind).toBe("ASSIGNED");

      // Step 2 leaves status CREATED (receiver_wallet_id lands only at step 8), so the
      // attachment is the only thing that can catch the second allocator.
      await expect(
        withTx(dbUrl, (tx) => assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES })),
      ).rejects.toThrow(/RECEIVE_ALREADY_ASSIGNED/);

      expect(countRows(dbUrl, "wallet_active_leases")).toBe(1);
      expect(countRows(dbUrl, "operation_wallets", `operation_id = '${operationId}'`)).toBe(1);
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 2: two allocators racing ONE receive — exactly one assigns (lost-update guard)",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      const operationId = OP(4);
      seedReceive(dbUrl, operationId);

      const attempt = async (): Promise<AssignReceiveWalletOutcome | Error> => {
        try {
          return await withTx(dbUrl, (tx) =>
            assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
          );
        } catch (err) {
          return err as Error;
        }
      };
      const [x, y] = await Promise.all([attempt(), attempt()]);

      const assigned = [x, y].filter(
        (r): r is AssignReceiveWalletOutcome => !(r instanceof Error) && r.kind === "ASSIGNED",
      );
      expect(assigned).toHaveLength(1);

      // The loser must fail as a typed RECEIVE_ALREADY_ASSIGNED, not as a raw unique
      // violation. That distinction is exactly what the operation-row FOR UPDATE buys:
      // without it the loser races past the recheck on a stale read, leases a second wallet,
      // and only dies later on operation_wallets' UNIQUE — correct by accident, and one
      // wasted lease acquisition rolled back per collision.
      const losers = [x, y].filter((r) => r instanceof Error) as Error[];
      expect(losers).toHaveLength(1);
      expect(losers[0]).toBeInstanceOf(ReceiveAllocatorError);
      expect((losers[0] as ReceiveAllocatorError).reason).toBe("RECEIVE_ALREADY_ASSIGNED");
      // Exactly one wallet leased and one RECEIVER row — one in-flight claim per wallet, held structurally.
      expect(countRows(dbUrl, "wallet_active_leases")).toBe(1);
      expect(countRows(dbUrl, "operation_wallets", `operation_id = '${operationId}'`)).toBe(1);
      expect(countRows(dbUrl, "wallets", "state = 'PINNED'")).toBe(1);
    },
    60_000,
  );

  it.skipIf(!live)("step 1: an exhausted pool reports NO_ELIGIBLE_WALLET, never widens", async () => {
    psqlMust(dbUrl, RESET_STATE);
    keepEligible(dbUrl, 0);
    const operationId = OP(5);
    seedReceive(dbUrl, operationId);

    const outcome = await withTx(dbUrl, (tx) =>
      assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
    );
    expect(outcome.kind).toBe("NO_ELIGIBLE_WALLET");
    expect(countRows(dbUrl, "wallet_active_leases")).toBe(0);
  }, 60_000);

  // ── 4. Lease exists before the fresh head read (steps 2→3) ───────────

  it.skipIf(!live)(
    "steps 2→3: the lease row is already durable when the T0 OBSERVE call fires",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      const operationId = OP(6);
      seedReceive(dbUrl, operationId);

      const sequence: string[] = [];
      let leaseRowsAtObserve = -1;

      const result = await assignReceiveWalletThenObserve(
        async () => {
          const outcome = await withTx(dbUrl, (tx) =>
            assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
          );
          sequence.push("assign");
          return outcome;
        },
        async (assigned) => {
          // Stands in for OBSERVE(receiver_pubkey, RECEIVE_T0): read the world as the
          // observer would see it at the instant the read is issued.
          leaseRowsAtObserve = countRows(
            dbUrl,
            "wallet_active_leases",
            `wallet_id = '${assigned.walletId}'`,
          );
          sequence.push("observe");
          return "T0";
        },
      );

      expect(sequence).toEqual(["assign", "observe"]);
      expect(leaseRowsAtObserve).toBe(1);
      expect(result.observation).toBe("T0");
    },
    60_000,
  );

  it.skipIf(!live)(
    "steps 2→3 negative control: with no wallet the T0 read never fires at all",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      keepEligible(dbUrl, 0);
      const operationId = OP(7);
      seedReceive(dbUrl, operationId);

      let observed = false;
      const result = await assignReceiveWalletThenObserve(
        () => withTx(dbUrl, (tx) => assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES })),
        async () => {
          observed = true;
          return "T0";
        },
      );

      expect(result.assignment.kind).toBe("NO_ELIGIBLE_WALLET");
      expect(observed).toBe(false);
      expect(result.observation).toBeNull();
    },
    60_000,
  );

  // ── 5. Bounded admission (steps 2–3) ────────────────────────

  it.skipIf(!live)(
    "step 2: admissions below RECEIVE_QUEUE_CAP return 202 and create the CREATED row",
    async () => {
      psqlMust(dbUrl, RESET_STATE);

      for (let i = 1; i <= LIMITS.receiveQueueCap; i += 1) {
        const operationId = OP(100 + i);
        const outcome = await withTx(dbUrl, (tx) =>
          admitReceive(tx, {
            limits: LIMITS,
            insertOperation: async (inner) => {
              await inner.query(`${INSERT_RECEIVE_COLUMNS}${receiveValues(operationId)}`);
            },
          }),
        );
        expect(outcome.kind).toBe("ADMITTED");
        expect(outcome.httpStatus).toBe(202);
      }

      expect(countRows(dbUrl, "operations")).toBe(LIMITS.receiveQueueCap);
      expect(await withTx(dbUrl, (tx) => countUnassignedReceives(tx))).toBe(
        LIMITS.receiveQueueCap,
      );
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 3: admission at capacity returns 503 receive_queue_full with Retry-After and leaves ZERO rows",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      for (let i = 1; i <= LIMITS.receiveQueueCap; i += 1) {
        seedReceive(dbUrl, OP(200 + i));
      }
      const before = countRows(dbUrl, "operations");
      expect(before).toBe(LIMITS.receiveQueueCap);

      let insertCalled = false;
      const outcome = await withTx(dbUrl, (tx) =>
        admitReceive(tx, {
          limits: LIMITS,
          insertOperation: async (inner) => {
            insertCalled = true;
            await inner.query(`${INSERT_RECEIVE_COLUMNS}${receiveValues(OP(299))}`);
          },
        }),
      );

      expect(outcome.kind).toBe("QUEUE_FULL");
      if (outcome.kind !== "QUEUE_FULL") return;
      expect(outcome.httpStatus).toBe(503);
      expect(outcome.errorCode).toBe("receive_queue_full");
      expect(outcome.retryAfterSecs).toBe(LIMITS.receiveQueueMaxWaitSecs);

      // No partial row of any kind survives the rejection.
      expect(insertCalled).toBe(false);
      expect(countRows(dbUrl, "operations")).toBe(before);
      expect(countRows(dbUrl, "operations", `id = '${OP(299)}'`)).toBe(0);
      expect(countRows(dbUrl, "wallet_active_leases")).toBe(0);
      expect(countRows(dbUrl, "wallet_lease_memberships")).toBe(0);
      expect(countRows(dbUrl, "lease_groups")).toBe(0);
      expect(countRows(dbUrl, "operation_wallets")).toBe(0);
    },
    60_000,
  );

  it.skipIf(!live)(
    "steps 2–3: assigned receives do not occupy the queue, so the cap bounds only the waiting set",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      for (let i = 1; i <= LIMITS.receiveQueueCap; i += 1) {
        seedReceive(dbUrl, OP(300 + i));
      }
      // Drain the queue by assigning every waiting receive.
      for (let i = 1; i <= LIMITS.receiveQueueCap; i += 1) {
        const outcome = await withTx(dbUrl, (tx) =>
          assignReceiveWallet(tx, { operationId: OP(300 + i), ownerInstanceId: OWNER, leases: LEASES }),
        );
        expect(outcome.kind).toBe("ASSIGNED");
      }
      expect(await withTx(dbUrl, (tx) => countUnassignedReceives(tx))).toBe(0);

      const outcome = await withTx(dbUrl, (tx) =>
        admitReceive(tx, {
          limits: LIMITS,
          insertOperation: async (inner) => {
            await inner.query(`${INSERT_RECEIVE_COLUMNS}${receiveValues(OP(399))}`);
          },
        }),
      );
      expect(outcome.kind).toBe("ADMITTED");
    },
    90_000,
  );

  it.skipIf(!live)(
    "step 3: concurrent admissions at the cap boundary never overshoot the cap",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      const cap = 4;
      const limits: ReceiveQueueLimits = { receiveQueueCap: cap, receiveQueueMaxWaitSecs: 30 };

      const admit = async (n: number): Promise<string> => {
        const outcome = await withTx(dbUrl, (tx) =>
          admitReceive(tx, {
            limits,
            insertOperation: async (inner) => {
              await inner.query(`${INSERT_RECEIVE_COLUMNS}${receiveValues(OP(400 + n))}`);
            },
          }),
        );
        return outcome.kind;
      };

      const results = await Promise.all(
        Array.from({ length: 8 }, (_v, i) => admit(i + 1)),
      );
      expect(results.filter((k) => k === "ADMITTED")).toHaveLength(cap);
      expect(results.filter((k) => k === "QUEUE_FULL")).toHaveLength(8 - cap);
      expect(countRows(dbUrl, "operations")).toBe(cap);
    },
    120_000,
  );

  // ── 6. FIFO promotion by (created_at, operation_id) ──────────────────────

  it.skipIf(!live)(
    "step 4: promotion follows (created_at, operation_id), not insertion order",
    async () => {
      psqlMust(dbUrl, RESET_STATE);

      // Insertion order is deliberately scrambled and the two OP(502)/OP(501) rows share a
      // created_at, so only the id tiebreak can make the order total.
      const t0 = "2026-01-01T00:00:00Z";
      const t1 = "2026-01-01T00:00:01Z";
      const seeded: Array<{ id: string; createdAt: string }> = [
        { id: OP(503), createdAt: t1 },
        { id: OP(502), createdAt: t0 },
        { id: OP(504), createdAt: t0 },
        { id: OP(501), createdAt: t1 },
      ];
      for (const row of seeded) seedReceive(dbUrl, row.id, row.createdAt);

      const expected = [OP(502), OP(504), OP(501), OP(503)];
      // The property is only meaningful if the two orders actually differ.
      expect(expected).not.toEqual(seeded.map((r) => r.id));

      const queued = await withTx(dbUrl, (tx) => selectQueuedReceivesFifo(tx, 10));
      expect(queued).toEqual(expected);

      const result = await promoteQueuedReceives(db, {
        limits: { receiveQueueCap: 10, receiveQueueMaxWaitSecs: 30 },
        allocate: (operationId) =>
          withTx(dbUrl, (tx) => assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES })),
      });

      expect(result.promoted).toEqual(expected);
      expect(result.remaining).toEqual([]);
      expect(await withTx(dbUrl, (tx) => countUnassignedReceives(tx))).toBe(0);
    },
    120_000,
  );

  it.skipIf(!live)(
    "step 4: a pool that runs dry stops the drain in FIFO order and leaves the rest queued",
    async () => {
      psqlMust(dbUrl, RESET_STATE);
      // Exactly two eligible wallets for four queued receives.
      keepEligible(dbUrl, 2);

      const t = (s: number): string => `2026-02-01T00:00:0${s}Z`;
      const ids = [OP(601), OP(602), OP(603), OP(604)];
      ids.forEach((id, i) => seedReceive(dbUrl, id, t(i)));

      const result = await promoteQueuedReceives(db, {
        limits: { receiveQueueCap: 10, receiveQueueMaxWaitSecs: 30 },
        allocate: (operationId) =>
          withTx(dbUrl, (tx) => assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES })),
      });

      expect(result.promoted).toEqual([ids[0], ids[1]]);
      expect(result.remaining).toEqual([ids[2], ids[3]]);
      expect(countRows(dbUrl, "wallet_active_leases")).toBe(2);
      expect(await withTx(dbUrl, (tx) => countUnassignedReceives(tx))).toBe(2);
    },
    120_000,
  );

  it.skipIf(!live)("rejects a nonsense RECEIVE_QUEUE_CAP rather than admitting unbounded", async () => {
    psqlMust(dbUrl, RESET_STATE);
    await expect(
      withTx(dbUrl, (tx) =>
        admitReceive(tx, {
          limits: { receiveQueueCap: -1, receiveQueueMaxWaitSecs: 30 },
          insertOperation: async () => {
            throw new Error("must not be called");
          },
        }),
      ),
    ).rejects.toThrow(ReceiveAllocatorError);
  }, 60_000);
});
