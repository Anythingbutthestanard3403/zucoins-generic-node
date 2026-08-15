// Shared real-PostgreSQL fixture for the receive-pool suites (scaler, stress).
//
// The DDL/seed shape is the one pool-allocator.pg.test.ts established; it is lifted
// into a module here rather than copied a third time, and parameterised (pool size, receive
// seeding) because the scaler and stress suites need pools of different shapes. own
// suite is deliberately left untouched — it is mid-QA.
//
// Everything here talks to a real database through `psql` subprocesses (node-core carries no
// SQL driver,), so each contender in a concurrency case is a separate OS process and
// the race is decided at the database transaction boundary rather than by the event loop.

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  acquireLeases,
  completeGroupOperation,
  createLeaseGroup,
  mintReleaseProof,
  releaseLease,
} from "../../src/leases/index.ts";
import type { ReceiveLeasePort, SqlExecutor } from "../../src/receive/pool-allocator.ts";
import type { MintWallet } from "../../src/receive/pool-scaler.ts";
import { psqlMust } from "../psql-harness.ts";
import { tokenizeCustodySql } from "../custody-eligibility-sql-statements.js";
import { verificationModeFixtureSql } from "../verification-mode-fixture.js";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../../src/schema");
const readSchema = (name: string): string => readFileSync(resolve(schemaDir, name), "utf8");

// ─── prerequisite DDL ───────────────────────────────────────────────────────
//
// base-enums-domains already defines every domain and enum operations.sql restates, so only
// operations.sql's object blocks are lifted out — applying the file whole fails on duplicate
// CREATE DOMAIN. Same extract-the-block pattern the lease-foundation suites use for `nodes`.

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

const receiveReleaseProofSql = blockFrom(
  readSchema("receive-expiry-release.sql"),
  /^CREATE TABLE receive_release_proofs \([\s\S]*?^\);$/m,
  "receive_release_proofs",
);

export const applyPoolSchema = (url: string): void => {
  try {
    execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      input: `${prerequisiteDdl}${custodySql}\n${readSchema("wallet-money-capability.sql")}\n${operationsSql}\n${receiveReleaseProofSql}\n${verificationModeFixtureSql()}\n`,
      encoding: "utf-8",
      timeout: 60_000,
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`schema apply failed: ${(e.stderr ?? "").trim()}`);
  }
};

// ─── deterministic identifiers ──────────────────────────────────────────────

export const NODE = "b0000000-0000-4000-8000-000000000265";
export const IMPLEMENTER = "b0000000-0000-4000-8000-000000000266";
export const OWNER = "c0000000-0000-4000-8000-000000000265";

/** Wallet UUIDs whose binary sequence matches the numeric suffix. */
export const W = (n: number): string =>
  `a0000000-0000-4000-8000-${n.toString().padStart(12, "0")}`;
/** Operation UUIDs, likewise sequenced. */
export const OP = (n: number): string =>
  `d0000000-0000-4000-8000-${n.toString().padStart(12, "0")}`;

const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

const verificationId = (n: number): string =>
  `e0000000-0000-4000-8000-${n.toString().padStart(12, "0")}`;

// ─── seeding ────────────────────────────────────────────────────────────────

export function seedRegistry(url: string): void {
  psqlMust(
    url,
    `INSERT INTO nodes (id, display_name, identity_public_key)
       VALUES ('${NODE}', 'pool-fixture-node', '${pubkey("POOL_NODE")}')
       ON CONFLICT DO NOTHING;
     INSERT INTO implementers (id, name)
       VALUES ('${IMPLEMENTER}', 'pool-fixture-implementer')
       ON CONFLICT DO NOTHING;`,
  );
}

/** Stamps recovery through a real verification row — recovery_verified_at has no default. */
export function verifyRecovery(url: string, walletId: string, n: number, key: string): void {
  psqlMust(
    url,
    `INSERT INTO wallet_recovery_verifications
       (id, wallet_id, method, public_key, export_sha256, audit_event_id, verified_at, verifier_identity)
       VALUES ('${verificationId(n)}', '${walletId}', 'AUDITED_EXPORT', '${key}',
               '${sha(`export-${n}`)}', '${randomUUID()}', now(), 'pool-fixture-test')
       ON CONFLICT DO NOTHING;
     UPDATE wallets
        SET recovery_verified_at = now(), recovery_verification_id = '${verificationId(n)}'
      WHERE id = '${walletId}'
        AND recovery_verified_at IS NULL;`,
  );
}

export interface PoolShape {
  /** Wallets satisfying all three/B-08 conjuncts. */
  readonly eligibleCount: number;
  /** node_generated + AVAILABLE but never recovery-verified — a minted-not-yet-blessed wallet. */
  readonly unverifiedCount?: number;
  /** recovery-verified + AVAILABLE but `imported` rather than node_generated. */
  readonly importedCount?: number;
}

export interface SeededPool {
  readonly eligible: readonly string[];
  readonly unverified: readonly string[];
  readonly imported: readonly string[];
  /** Every seeded wallet, in the sequence it was created. */
  readonly all: readonly string[];
}

/**
 * Seeds the wallet pool. The unverified and imported rows are permanent residents rather than
 * per-test mutations: recovery_verified_at is monotonic and key_origin is immutable (custody
 * triggers), so neither conjunct can be dropped by an UPDATE. Keeping them resident means every
 * case in a suite — not just the predicate case — re-proves the allocator never reaches them,
 * and that the scaler's cap count DOES.
 */
export function seedWallets(url: string, shape: PoolShape): SeededPool {
  const eligible: string[] = [];
  const unverified: string[] = [];
  const imported: string[] = [];
  const rows: string[] = [];
  // wallet id -> its public key, so the recovery-verification row records the SAME key the
  // wallet carries (the two columns are not tied by a constraint, so a mismatch would be a
  // silent fixture lie rather than a database error).
  const keyOf = new Map<string, string>();
  let n = 0;

  const add = (bucket: string[], tag: string, keyOrigin: string): void => {
    n += 1;
    const id = W(n);
    const key = pubkey(`${tag}${n}`);
    bucket.push(id);
    keyOf.set(id, key);
    rows.push(`('${id}', '${NODE}', '${key}', '${keyOrigin}', 'AVAILABLE')`);
  };

  for (let i = 0; i < shape.eligibleCount; i += 1) add(eligible, "WE", "node_generated");
  for (let i = 0; i < (shape.unverifiedCount ?? 1); i += 1) add(unverified, "WU", "node_generated");
  for (let i = 0; i < (shape.importedCount ?? 1); i += 1) add(imported, "WI", "imported");

  psqlMust(
    url,
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ${rows.join(",\n")}
       ON CONFLICT DO NOTHING;`,
  );

  let v = 0;
  // The imported wallets ARE recovery-verified: their only defect is key_origin, which keeps
  // that conjunct isolated. The unverified ones are deliberately left unstamped.
  for (const id of [...eligible, ...imported]) {
    v += 1;
    verifyRecovery(url, id, v, keyOf.get(id)!);
  }

  return { eligible, unverified, imported, all: [...eligible, ...unverified, ...imported] };
}

/**
 * Returns the pool to its seeded shape. `state` carries companion columns
 * (wallets_retired_at_iff, wallets_quarantine_reason_iff), so all three reset together or the
 * CHECK fires. Wallets minted by a scaler pass are removed so a suite's cap arithmetic starts
 * from the seeded count again.
 */
export const RESET_POOL = `
TRUNCATE receive_release_proofs, operation_wallets, wallet_active_leases, wallet_lease_memberships,
         lease_group_operations, lease_groups, lease_release_proofs,
         lease_audit_events, wallet_lease_epoch_highwater
  RESTART IDENTITY CASCADE;
DELETE FROM operations;
DELETE FROM wallets WHERE id::text LIKE 'f0000000-%';
UPDATE wallets
   SET state = 'AVAILABLE', retired_at = NULL, quarantine_reason = NULL
 WHERE state <> 'AVAILABLE';
`;

/** UUID band reserved for wallets a test scaler mints, so cleanup never touches seeded rows. */
export const MINTED = (n: number): string =>
  `f0000000-0000-4000-8000-${n.toString().padStart(12, "0")}`;

// ─── receives ───────────────────────────────────────────────────────────────

const INSERT_RECEIVE_COLUMNS = `INSERT INTO operations
  (id, node_id, implementer_id, kind, status, amount_zkz, after_landing,
   discriminator, anchor, idempotency_key, request_sha256, created_at)
VALUES `;

/**
 * A `RECEIVE_EXTERNAL/CREATED` receive with no wallet. The CHECKs force
 * discriminator = id, an anchor, after_landing, and NULL receiver/expiry/t0 while CREATED.
 * `createdAtSql` is raw SQL so a caller can age a receive with `now() - interval '90 seconds'`.
 */
export function receiveValues(operationId: string, createdAtSql = "now()"): string {
  return `('${operationId}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'CREATED',
           '1.5', 'HOLD', '${operationId}', 'anchor-${operationId.slice(-12)}',
           '${operationId}-idem-key', '${sha(operationId)}', ${createdAtSql})`;
}

export function seedReceive(url: string, operationId: string, createdAtSql = "now()"): void {
  psqlMust(url, `${INSERT_RECEIVE_COLUMNS}${receiveValues(operationId, createdAtSql)};`);
}

export function seedReceives(
  url: string,
  receives: ReadonlyArray<{ readonly operationId: string; readonly createdAtSql?: string }>,
): void {
  if (receives.length === 0) return;
  psqlMust(
    url,
    `${INSERT_RECEIVE_COLUMNS}${receives
      .map((r) => receiveValues(r.operationId, r.createdAtSql))
      .join(",\n")};`,
  );
}

/** The `insertOperation` callback `admitReceive` delegates to once the cap gate passes. */
export const insertReceiveOnTx =
  (operationId: string, createdAtSql = "now()") =>
  async (db: SqlExecutor): Promise<void> => {
    await db.query(`${INSERT_RECEIVE_COLUMNS}${receiveValues(operationId, createdAtSql)}`);
  };

// ─── ports ──────────────────────────────────────────────────────────────────

/**
 * The lease binding the composition root supplies: node-core's persisted lease repository. The
 * allocator injects it rather than importing it because `receive` is a boundary leaf; a test
 * file may import both freely, as the gate scans src/ only.
 */
export const LEASES: ReceiveLeasePort = {
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

/**
 * A mint port that inserts one node-generated wallet row, born recovery-UNVERIFIED:
 * a freshly minted keypair is NOT receive-eligible until the ceremony stamps it. No key
 * material is involved — the public key is a deterministic test literal, and the scaler under
 * test never sees either half of a keypair.
 */
export function mintingPort(startAt = 1): {
  readonly mint: MintWallet;
  readonly minted: string[];
} {
  const minted: string[] = [];
  let next = startAt;
  return {
    minted,
    mint: async (db, _batchIndex) => {
      // Keyed off the id counter, not the per-port mint count: two ports running concurrently
      // must not both produce `WM1`, or UNIQUE (node_id, public_key) fails the race fixture
      // for a reason that has nothing to do with the race.
      const id = MINTED(next);
      const key = pubkey(`WM${next}`);
      next += 1;
      await db.query(
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
         VALUES ('${id}', '${NODE}', '${key}', 'node_generated', 'AVAILABLE')`,
      );
      minted.push(id);
      return id;
    },
  };
}

// ─── read helpers ───────────────────────────────────────────────────────────

export const countRows = (url: string, table: string, where = "true"): number =>
  Number(psqlMust(url, `SELECT count(*)::int FROM ${table} WHERE ${where};`).trim());

export const walletState = (url: string, walletId: string): string =>
  psqlMust(url, `SELECT state::text FROM wallets WHERE id = '${walletId}';`).trim();

/** Shrinks the eligible pool to `keep` wallets by PINNING the rest — the realistic narrowing. */
export function keepEligible(url: string, pool: SeededPool, keep: number): void {
  const kept = pool.eligible.slice(0, keep).map((id) => `'${id}'`).join(", ");
  const exclusion = kept === "" ? "" : ` AND id NOT IN (${kept})`;
  psqlMust(
    url,
    `UPDATE wallets SET state = 'PINNED'
      WHERE key_origin = 'node_generated'
        AND recovery_verified_at IS NOT NULL
        AND state = 'AVAILABLE'${exclusion};`,
  );
}

// ─── full receive lifecycle ───────────────────────────────────────

/**
 * Drives an assigned receive to its landed terminal shape the way step 8 would: the
 * CHECK admits a RECEIVE_EXTERNAL row only as `(CREATED, no wallet)` or
 * `(wallet AND expiry AND t0)`, so the wallet, the expiry and the T0 observation land together
 * or not at all. Nothing here signs or reads a gateway — the observation concern owns that; this
 * is the row shape the lease-release path needs to exist.
 */
export function driveReceiveToLanded(url: string, operationId: string, walletId: string): void {
  psqlMust(
    url,
    `UPDATE operations
        SET status = 'RECEIVE_LANDED',
            receiver_wallet_id = '${walletId}',
            expiry_unix_time_secs = '1900000000',
            t0_observation_id = '${randomUUID()}',
            terminal_at = now()
      WHERE id = '${operationId}';`,
  );
}

export interface ReleasableLease {
  readonly operationId: string;
  readonly walletId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
}

/**
 * Releases a lease the only way the one-in-flight rule permits: the group operation is completed, a
 * TRUSTED_VERIFIER `RECEIVE_LANDED` proof exists for the exact lease tuple, and only then does
 * `releaseLease` run. There is no heartbeat-expiry or impatience path here because there is none
 * in the foundation — a release without the proof throws `PROOF_NOT_FOUND`.
 */
export async function releaseWithLandedProof(
  db: SqlExecutor,
  lease: ReleasableLease,
  ownerInstanceId: string = OWNER,
): Promise<void> {
  await completeGroupOperation(db, {
    leaseGroupId: lease.leaseGroupId,
    operationId: lease.operationId,
  });
  const proofId = randomUUID();
  await mintReleaseProof(db, {
    proofId,
    walletId: lease.walletId,
    operationId: lease.operationId,
    membershipId: lease.membershipId,
    leaseGroupId: lease.leaseGroupId,
    leaseEpoch: lease.leaseEpoch,
    proofKind: "RECEIVE_LANDED",
    proofDigest: sha(`landed-${lease.operationId}`),
  });
  await releaseLease(db, {
    walletId: lease.walletId,
    ownerInstanceId,
    operationId: lease.operationId,
    membershipId: lease.membershipId,
    leaseGroupId: lease.leaseGroupId,
    leaseEpoch: lease.leaseEpoch,
    releaseProofId: proofId,
    releaseReason: "RECEIVE_LANDED",
  });
}

// ─── invariants re-checked after every stress scenario ──────────────────────

export interface PoolInvariantReport {
  readonly capCount: number;
  readonly activeLeases: number;
  readonly distinctLeasedWallets: number;
  readonly receiverAttachments: number;
  readonly distinctReceiverOperations: number;
  readonly pinnedWithoutLease: number;
  readonly leasedNotPinned: number;
  readonly illegalReceiveRows: number;
}

/**
 * The aggregate invariant every scenario independently re-verifies (
 * rule 2). Returned as data rather than asserted here so each scenario states its own
 * expectations against the same measurements.
 */
export function readPoolInvariants(url: string): PoolInvariantReport {
  const n = (sql: string): number => Number(psqlMust(url, sql).trim());
  return {
    capCount: n(`SELECT count(*)::int FROM wallets;`),
    activeLeases: n(`SELECT count(*)::int FROM wallet_active_leases;`),
    distinctLeasedWallets: n(`SELECT count(DISTINCT wallet_id)::int FROM wallet_active_leases;`),
    receiverAttachments: n(
      `SELECT count(*)::int FROM operation_wallets WHERE operation_role = 'RECEIVER';`,
    ),
    distinctReceiverOperations: n(
      `SELECT count(DISTINCT operation_id)::int FROM operation_wallets WHERE operation_role = 'RECEIVER';`,
    ),
    // A wallet PINNED with no active lease, or leased while not PINNED, is the split-brain the
    // acquire sequence exists to prevent.
    pinnedWithoutLease: n(
      `SELECT count(*)::int FROM wallets w
        WHERE w.state = 'PINNED'
          AND NOT EXISTS (SELECT 1 FROM wallet_active_leases l WHERE l.wallet_id = w.id);`,
    ),
    leasedNotPinned: n(
      `SELECT count(*)::int FROM wallet_active_leases l
         JOIN wallets w ON w.id = l.wallet_id
        WHERE w.state <> 'PINNED';`,
    ),
    // Belt and braces over the frozen / CHECK: no RECEIVE_EXTERNAL row in a
    // shape the schema forbids could have survived. Walletless EXPIRED is lawful;
    // the earlier form `status = 'CREATED'` alone would mis-fire every queue-age expiry.
    illegalReceiveRows: n(
      `SELECT count(*)::int FROM operations
        WHERE kind = 'RECEIVE_EXTERNAL'
          AND NOT (
            (status IN ('CREATED','EXPIRED') AND receiver_wallet_id IS NULL
              AND expiry_unix_time_secs IS NULL AND t0_observation_id IS NULL)
            OR (receiver_wallet_id IS NOT NULL
              AND expiry_unix_time_secs IS NOT NULL AND t0_observation_id IS NOT NULL));`,
    ),
  };
}
