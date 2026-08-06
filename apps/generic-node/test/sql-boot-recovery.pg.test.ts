// SQL-backed BootRecoveryStore + BootRecoveryActions PG tests.
// Boot-recovery steps 2–8; One-in-flight (one in-flight
// tx per wallet — exercised by the two-wallet MOVE_INTERNAL epoch scenario below).
//
// Scaffolding mirrors test/receive-landing-step.pg.test.ts (disposable createdb/dropdb
// database, runMigrationsOnPool + migrateLeaseFoundation in beforeAll).

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  EncryptedWalletKeyStore,
  InMemoryVaultAccessAuditLog,
  migrateLeaseFoundation,
  runDeterministicBootRecovery,
  sealWalletSecret,
  VaultSqlStore,
  type VaultAccessAuditLog,
  type VaultRecord,
  type VaultStore,
} from "@zucoins/node-core";

import { ensureNodeRow } from "../src/bootstrap/genesis.js";
import { publicKeyFromSeed } from "../src/ops/ed25519-ops.js";
import { createSqlBootRecovery } from "../src/boot/sql-boot-recovery.js";
import { runBootLane } from "../src/boot/boot-lane.js";
import { NodeReadiness } from "../src/boot/readiness.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const ROOT_KEY = randomBytes(32);

// padded_base64url_signature: CHECK (length = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$').
const DUMMY_SIGNATURE = `${"A".repeat(86)}==`;

function sha256HexOfText(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function hasClientTool(name: string): boolean {
  try {
    execFileSync(name, ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const HAS_CREATEDB = hasClientTool("createdb");
const PG_AVAILABLE = (() => {
  try {
    if (hasClientTool("pg_isready")) {
      execFileSync(
        "pg_isready",
        ["-q", "-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER],
        { stdio: "ignore" },
      );
      return true;
    }
  } catch {
    /* fall through */
  }
  try {
    execFileSync(
      "node",
      [
        "-e",
        `const {Client}=require("pg");const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:"postgres",password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      { stdio: "ignore", env: process.env },
    );
    return true;
  } catch {
    return false;
  }
})();

function adminClientConfig(database = "postgres") {
  return { host: PG_HOST, port: PG_PORT, user: PG_USER, database, password: process.env.PGPASSWORD };
}

function assertSafeDbName(dbName: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(dbName)) {
    throw new Error(`unsafe test db name: ${dbName}`);
  }
}

async function createTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_CREATEDB) {
    execFileSync("createdb", ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, dbName], {
      env: process.env,
    });
    return;
  }
  const admin = new Client(adminClientConfig("postgres"));
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${dbName}`);
  } finally {
    await admin.end();
  }
}

async function dropTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  const admin = new Client(adminClientConfig("postgres"));
  await admin.connect();
  try {
    // Do not shell out to dropdb here. Under Vitest, another worker can briefly retain a
    // connection to the disposable database and the synchronous child blocks this worker's
    // event loop until PostgreSQL's client-side timeout. Terminate any straggler explicitly,
    // then use PostgreSQL's forced drop as a final race-safe guard. Teardown errors propagate:
    // a leaked database or failed cleanup must fail the suite, never be swallowed.
    await admin.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
        WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [dbName],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  } finally {
    await admin.end();
  }
}

function pgPool(dbName: string): Pool {
  return new Pool({ host: PG_HOST, port: PG_PORT, user: PG_USER, database: dbName, password: process.env.PGPASSWORD });
}

function pgDatabaseUrl(dbName: string): string {
  const auth = process.env.PGPASSWORD
    ? `${encodeURIComponent(PG_USER)}:${encodeURIComponent(process.env.PGPASSWORD)}`
    : encodeURIComponent(PG_USER);
  const host = PG_HOST === "/tmp" ? "localhost" : PG_HOST;
  return `postgres://${auth}@${host}:${PG_PORT}/${dbName}`;
}

const logger = {
  lines: [] as string[],
  info(message: string) {
    this.lines.push(message);
  },
  error(message: string) {
    this.lines.push(`ERROR ${message}`);
  },
};

describe.skipIf(!PG_AVAILABLE)("SQL boot recovery store/actions (disposable PG)", () => {
  const dbName = `boot_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let prevDatabaseUrl: string | undefined;
  let nodeId: string;
  let implementerId: string;
  let vault: EncryptedWalletKeyStore;

  beforeAll(async () => {
    await createTestDatabase(dbName);
    pool = pgPool(dbName);
    prevDatabaseUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);
    const { runMigrationsOnPool } = await import("../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });
    await migrateLeaseFoundation({
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await pool.query(text, params as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    });
    vault = new EncryptedWalletKeyStore({
      rootKey: ROOT_KEY,
      store: new VaultSqlStore(pool),
      auditLog: new InMemoryVaultAccessAuditLog(),
    });

    nodeId = randomUUID();
    implementerId = randomUUID();
    await ensureNodeRow(pool, {
      nodeId,
      displayName: "fixture-boot-recovery",
      identityPublicKey: publicKeyFromSeed(randomBytes(32)),
    });
    await pool.query(
      `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-impl', now())`,
      [implementerId],
    );
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    try {
      await pool?.end();
      await dropTestDatabase(dbName);
    } finally {
      if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = prevDatabaseUrl;
    }
  }, PG_TEST_TIMEOUT_MS);

  // ── seed helpers ─────────────────────────────────────────────────────────────

  async function seedWallet(state: string): Promise<string> {
    const walletId = randomUUID();
    const seed = randomBytes(32);
    const publicKey = publicKeyFromSeed(seed);
    const secret64 = Buffer.concat([seed, Buffer.from(publicKey, "base64url")]);
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ($1::uuid, $2::uuid, $3, 'node_generated', $4)`,
      [walletId, nodeId, publicKey, state],
    );
    try {
      await vault.seal(
        { nodeId, walletId, keyVersion: 1, publicKey, keyOrigin: "node_generated" },
        secret64,
      );
    } finally {
      seed.fill(0);
      secret64.fill(0);
    }
    return walletId;
  }

  /** Sets recovery_verified_at/recovery_verification_id together (wallets_recovery_fields_together). */
  async function verifyRecovery(walletId: string): Promise<void> {
    const verificationId = randomUUID();
    const pubkey = (
      await pool.query<{ public_key: string }>(`SELECT public_key FROM wallets WHERE id = $1::uuid`, [walletId])
    ).rows[0]!.public_key;
    await pool.query(
      `INSERT INTO wallet_recovery_verifications
         (id, wallet_id, method, public_key, export_sha256, audit_event_id, verified_at, verifier_identity)
       VALUES ($1::uuid, $2::uuid, 'AUDITED_EXPORT', $3, $4, $5::uuid, now(), 'fixture-suite')`,
      [verificationId, walletId, pubkey, sha256HexOfText(walletId), randomUUID()],
    );
    await pool.query(
      `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = $2::uuid
        WHERE id = $1::uuid`,
      [walletId, verificationId],
    );
  }

  /** Blesses a destination for walletId, seeding the real destination_blessing_artifacts FK
   * target first (signer-support.sql: destinations.blessing_artifact_id FK). */
  async function blessDestination(walletId: string): Promise<string> {
    const destinationId = randomUUID();
    await pool.query(
      `INSERT INTO destinations (id, node_id, wallet_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
      [destinationId, nodeId, walletId],
    );
    const pubkey = (
      await pool.query<{ public_key: string }>(`SELECT public_key FROM wallets WHERE id = $1::uuid`, [walletId])
    ).rows[0]!.public_key;
    const artifactId = randomUUID();
    const preimageText = `fixture-bless-${destinationId}`;
    await pool.query(
      `INSERT INTO destination_blessing_artifacts
         (id, purpose, canonical_version, node_id, destination_id, wallet_id, wallet_pubkey,
          nonce, issued_at, expires_at, device_signature, preimage_text, preimage_sha256, created_at)
       VALUES ($1::uuid, 'zp-destination-bless-v1', 1, $2::uuid, $3::uuid, $4::uuid, $5,
               $6::uuid, now(), now() + interval '60 seconds', $7, $8, $9, now())`,
      [artifactId, nodeId, destinationId, walletId, pubkey, randomUUID(), DUMMY_SIGNATURE, preimageText, sha256HexOfText(preimageText)],
    );
    // destinations_blessed_iff + destinations_blessing_requires_device_artifact: all three
    // blessing columns move together in one statement.
    await pool.query(
      `UPDATE destinations
          SET state = 'BLESSED', blessed_at = now(), blessed_by_device_key_id = $2::uuid,
              blessing_artifact_id = $3::uuid
        WHERE id = $1::uuid`,
      [destinationId, randomUUID(), artifactId],
    );
    return destinationId;
  }

  async function seedLease(
    leaseGroupId: string,
    operationId: string,
    walletId: string,
    role: string,
    epoch: number,
  ): Promise<void> {
    const membershipId = randomUUID();
    await pool.query(
      `INSERT INTO wallet_lease_memberships
         (id, lease_group_id, wallet_id, operation_id, lease_role, lease_epoch, acquired_at)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, now())`,
      [membershipId, leaseGroupId, walletId, operationId, role, epoch],
    );
    await pool.query(
      `INSERT INTO wallet_active_leases
         (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
          lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $4::uuid, $5, $6, now(), now(), $7::uuid)`,
      [walletId, membershipId, leaseGroupId, operationId, role, epoch, randomUUID()],
    );
  }

  async function seedReceiveExternalCreated(): Promise<{ operationId: string; walletId: string; leaseGroupId: string }> {
    const operationId = randomUUID();
    const walletId = await seedWallet("AVAILABLE");
    await verifyRecovery(walletId);
    await pool.query(
      `INSERT INTO operations
         (id, node_id, implementer_id, kind, status, amount_zkz, discriminator, anchor,
          after_landing, idempotency_key, request_sha256)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'CREATED', '1', $1::uuid,
               'recv', 'HOLD', $4, $5)`,
      [operationId, nodeId, implementerId, `idem-${operationId}`, sha256HexOfText(operationId)],
    );
    const leaseGroupId = randomUUID();
    await pool.query(
      `INSERT INTO lease_groups (id, root_operation_id, created_at) VALUES ($1::uuid, $2::uuid, now())`,
      [leaseGroupId, operationId],
    );
    await seedLease(leaseGroupId, operationId, walletId, "RECEIVE_WINDOW", 1);
    await pool.query(
      `INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at)
       VALUES ($1::uuid, $2::uuid, now())`,
      [leaseGroupId, operationId],
    );
    return { operationId, walletId, leaseGroupId };
  }

  // ── scenarios ────────────────────────────────────────────────────────────────

  it("greenfield: empty DB reports empty inventory from every store method", async () => {
    const { store } = createSqlBootRecovery(pool, logger, vault);
    expect(await store.listActiveLeases()).toEqual([]);
    expect(await store.listNonterminalOperations()).toEqual([]);
    expect(await store.listLeaseGroupOperations()).toEqual([]);
    expect(await store.listKeyCorrespondence()).toEqual([]);
    expect(await store.listObservationCursors()).toEqual([]);
    expect(await store.listQueuedReceiveOperationIds()).toEqual([]);
    expect(await store.readRawResponseBytes(randomUUID())).toBeNull();
  });

  it("transient vault fault (non-custody IO error) fails readiness without quarantining (D2)", async () => {
    const transientWalletId = await seedWallet("AVAILABLE");
    const realStore = new VaultSqlStore(pool);
    // Wraps the real VaultSqlStore (not a hand-rolled stub) so the fault flows through the
    // real EncryptedWalletKeyStore.open() -> listKeyCorrespondence() path.
    const flakyStore: VaultStore = {
      insert: (record: VaultRecord) => realStore.insert(record),
      update: (record: VaultRecord) => realStore.update(record),
      findByWalletId: (walletId: string) =>
        walletId === transientWalletId
          ? Promise.reject(new Error("simulated transient IO fault"))
          : realStore.findByWalletId(walletId),
    };
    const flakyVault = new EncryptedWalletKeyStore({
      rootKey: ROOT_KEY,
      store: flakyStore,
      auditLog: new InMemoryVaultAccessAuditLog(),
    });

    try {
      const { store, actions } = createSqlBootRecovery(pool, logger, flakyVault);
      const report = await runDeterministicBootRecovery({
        leadership: { held: true },
        store,
        actions,
      });

      expect(report.ready).toBe(false);
      expect(report.invariantBreach).toBe(false);
      expect(report.keyFindings.find((f) => f.walletId === transientWalletId)).toEqual({
        walletId: transientWalletId,
        ok: false,
        reason: "vault_open_transient_fault",
      });

      const row = await pool.query<{ state: string }>(
        `SELECT state::text FROM wallets WHERE id = $1::uuid`,
        [transientWalletId],
      );
      expect(row.rows[0]!.state).toBe("AVAILABLE");
    } finally {
      await pool.query(`DELETE FROM vault WHERE wallet_id = $1::uuid`, [transientWalletId]);
      await pool.query(`DELETE FROM wallets WHERE id = $1::uuid`, [transientWalletId]);
    }
  });

  it("masking regression: a rejecting audit sink must not downgrade a missing-key verdict to transient (D1)", async () => {
    const maskedWalletId = await seedWallet("AVAILABLE");
    await pool.query(`DELETE FROM vault WHERE wallet_id = $1::uuid`, [maskedWalletId]);

    const alwaysRejectingAuditLog: VaultAccessAuditLog = {
      record: () => Promise.reject(new Error("audit sink unavailable")),
    };
    const maskedVault = new EncryptedWalletKeyStore({
      rootKey: ROOT_KEY,
      store: new VaultSqlStore(pool),
      auditLog: alwaysRejectingAuditLog,
    });

    try {
      const { store, actions } = createSqlBootRecovery(pool, logger, maskedVault);
      const report = await runDeterministicBootRecovery({
        leadership: { held: true },
        store,
        actions,
      });

      // Pre-fix (store.ts:93-97 unguarded await): recordAccess's rejection replaces
      // VaultRecordNotFoundError, the instanceof check at sql-boot-recovery.ts:216 goes
      // false, and this wallet is misclassified transientFault:true — never quarantined.
      expect(report.invariantBreach).toBe(true);
      expect(report.keyFindings.find((f) => f.walletId === maskedWalletId)).toEqual({
        walletId: maskedWalletId,
        ok: false,
        reason: "vault_open_failed",
      });

      const row = await pool.query<{ state: string; quarantine_reason: string | null }>(
        `SELECT state::text, quarantine_reason FROM wallets WHERE id = $1::uuid`,
        [maskedWalletId],
      );
      expect(row.rows[0]!.state).toBe("QUARANTINED");
      expect(row.rows[0]!.quarantine_reason).not.toBeNull();
    } finally {
      await pool.query(`DELETE FROM wallets WHERE id = $1::uuid`, [maskedWalletId]);
    }
  });

  it("restored boot opens every wallet and quarantines unreadable, wrong-version, mismatched, and missing vault material", async () => {
    const goodWalletId = await seedWallet("AVAILABLE");
    const goodPublicKey = (
      await pool.query<{ public_key: string }>(
        `SELECT public_key FROM wallets WHERE id = $1::uuid`,
        [goodWalletId],
      )
    ).rows[0]!.public_key;

    const goodRecovery = createSqlBootRecovery(pool, logger, vault);
    const goodReport = await runDeterministicBootRecovery({
      leadership: { held: true },
      store: goodRecovery.store,
      actions: goodRecovery.actions,
    });
    expect(goodReport.ready).toBe(true);
    expect(goodReport.keyFindings).toEqual([
      { walletId: goodWalletId, ok: true, reason: "match" },
    ]);

    const unreadableWalletId = await seedWallet("AVAILABLE");
    const wrongVersionWalletId = await seedWallet("AVAILABLE");
    const mismatchedWalletId = randomUUID();
    const mismatchSeed = randomBytes(32);
    const otherSeed = randomBytes(32);
    const sealedPublicKey = publicKeyFromSeed(mismatchSeed);
    const otherPublicKey = publicKeyFromSeed(otherSeed);
    const mismatchSecret64 = Buffer.concat([
      mismatchSeed,
      Buffer.from(sealedPublicKey, "base64url"),
    ]);
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
      [mismatchedWalletId, nodeId, otherPublicKey],
    );
    try {
      const envelope = sealWalletSecret(
        ROOT_KEY,
        {
          nodeId,
          walletId: mismatchedWalletId,
          keyVersion: 1,
          publicKey: sealedPublicKey,
          keyOrigin: "node_generated",
        },
        mismatchSecret64,
      );
      await new VaultSqlStore(pool).insert({
        ...envelope,
        createdAt: new Date(),
        rotatedAt: null,
      });
    } finally {
      mismatchSeed.fill(0);
      otherSeed.fill(0);
      mismatchSecret64.fill(0);
    }
    const missingWalletId = await seedWallet("AVAILABLE");

    await pool.query(
      `UPDATE vault
          SET ciphertext = set_byte(ciphertext, 0, (get_byte(ciphertext, 0) # 255))
        WHERE wallet_id = $1::uuid`,
      [unreadableWalletId],
    );
    await pool.query(
      `UPDATE vault SET key_version = key_version + 1 WHERE wallet_id = $1::uuid`,
      [wrongVersionWalletId],
    );
    await pool.query(`DELETE FROM vault WHERE wallet_id = $1::uuid`, [missingWalletId]);

    logger.lines.length = 0;
    let workersStarted = 0;
    const brokenRecovery = createSqlBootRecovery(pool, logger, vault);
    const boot = await runBootLane({
      readiness: new NodeReadiness(3),
      logger,
      runMigrations: async () => {},
      unlockVault: async () => {},
      acquireSignerLeadership: async () => ({ release: async () => {} }),
      runBootRecovery: async () => {
        const report = await runDeterministicBootRecovery({
          leadership: { held: true },
          store: brokenRecovery.store,
          actions: brokenRecovery.actions,
        });
        return { ready: report.ready, invariantBreach: report.invariantBreach };
      },
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: () => {
        workersStarted += 1;
      },
    });

    expect(boot.ready).toBe(false);
    expect(boot.bootRecovery).toEqual({ ready: false, invariantBreach: true });
    expect(workersStarted).toBe(0);
    const quarantined = await pool.query<{ id: string; state: string; quarantine_reason: string | null }>(
      `SELECT id::text, state::text, quarantine_reason
         FROM wallets
        WHERE id = ANY($1::uuid[])
        ORDER BY id`,
      [[unreadableWalletId, wrongVersionWalletId, mismatchedWalletId, missingWalletId]],
    );
    expect(quarantined.rows).toHaveLength(4);
    expect(quarantined.rows.every((row) => row.state === "QUARANTINED")).toBe(true);
    expect(quarantined.rows.every((row) => row.quarantine_reason !== null)).toBe(true);
    expect(logger.lines.join("\n")).not.toContain(goodPublicKey);
    expect(logger.lines.join("\n")).not.toContain(otherPublicKey);
  });

  it("populated recovery: single-wallet RECEIVE_EXTERNAL CREATED with a live RECEIVE_WINDOW lease", async () => {
    const seeded = await seedReceiveExternalCreated();
    const { store } = createSqlBootRecovery(pool, logger, vault);

    const leases = await store.listActiveLeases();
    const lease = leases.find((l) => l.walletId === seeded.walletId);
    expect(lease).toBeDefined();
    expect(lease!.operationId).toBe(seeded.operationId);
    expect(lease!.leaseGroupId).toBe(seeded.leaseGroupId);
    expect(lease!.role).toBe("RECEIVE_WINDOW");
    expect(lease!.epoch).toBe(1);
    expect(lease!.walletState).toBe("AVAILABLE");
    expect(typeof lease!.lastHeartbeatAtMs).toBe("number");

    const ops = await store.listNonterminalOperations();
    const op = ops.find((o) => o.operationId === seeded.operationId);
    expect(op).toBeDefined();
    expect(op!.kind).toBe("RECEIVE_EXTERNAL");
    expect(op!.status).toBe("CREATED");
    expect(op!.attentionRequired).toBe(false);
    expect(op!.rowVersion).toBe(1);
    expect(op!.leaseEpoch).toBe(1);
    expect(op!.leasedWalletIds).toEqual([seeded.walletId]);
    expect(op!.requiredRoles).toEqual(["RECEIVE_WINDOW"]);
    // No operation_transactions / submit_decisions / receive_codes rows seeded.
    expect(op!.submitBoundaryRecorded).toBe(false);
    expect(op!.signerAuditIndicatesCall).toBe(false);
    expect(op!.formationComplete).toBe(false);

    const groups = await store.listLeaseGroupOperations();
    expect(
      groups.some((g) => g.leaseGroupId === seeded.leaseGroupId && g.operationId === seeded.operationId),
    ).toBe(true);
  });

  // Regression: an armed receive signs its EXPECTED_ARTIFACT and writes a signer_audit row,
  // while operation_transactions stays empty until a candidate is intaken. Counting every
  // signer_audit purpose made auditPhaseBoundaries see "signer called, exact preimage absent"
  // and force a GLOBAL invariant breach, so the node quarantined itself on the next boot and
  // money engines never started — observed live: a node that had armed one receive could not
  // reboot at all (readiness false, healthcheck fail, container torn down).
  //
  // EXPECTED_ARTIFACT bytes are persisted in operation_expected_artifacts in the same
  // transaction as the signing call, so they can never be signed-but-unprovable and must not
  // be measured against operation_transactions.
  it("EXPECTED_ARTIFACT signer audit alone is not a signer call for the phase-boundary invariant", async () => {
    const seeded = await seedReceiveExternalCreated();
    await pool.query(
      `INSERT INTO signer_audit (id, node_id, operation_id, preimage_sha256, called_at, outcome, purpose)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4, now(), 'SUCCEEDED', 'EXPECTED_ARTIFACT')`,
      [randomUUID(), nodeId, seeded.operationId, sha256HexOfText(`artifact-${seeded.operationId}`)],
    );

    const { store } = createSqlBootRecovery(pool, logger);
    const ops = await store.listNonterminalOperations();
    const op = ops.find((o) => o.operationId === seeded.operationId);
    expect(op).toBeDefined();
    // No operation_transactions row exists, so were EXPECTED_ARTIFACT counted this pair
    // (true, false) would force a breach in auditPhaseBoundaries.
    expect(op!.exactPreimagePersisted).toBe(false);
    expect(op!.signerAuditIndicatesCall).toBe(false);
  });

  it("STEP_1 signer audit without an exact preimage still reports a signer call", async () => {
    const seeded = await seedReceiveExternalCreated();
    await pool.query(
      `INSERT INTO signer_audit (id, node_id, operation_id, preimage_sha256, called_at, outcome, purpose)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4, now(), 'SUCCEEDED', 'STEP_1')`,
      [randomUUID(), nodeId, seeded.operationId, sha256HexOfText(`step1-${seeded.operationId}`)],
    );

    const { store } = createSqlBootRecovery(pool, logger);
    const ops = await store.listNonterminalOperations();
    const op = ops.find((o) => o.operationId === seeded.operationId);
    expect(op).toBeDefined();
    // The real invariant is preserved: transaction-signing purposes still surface the breach.
    expect(op!.exactPreimagePersisted).toBe(false);
    expect(op!.signerAuditIndicatesCall).toBe(true);
  });

  it("two-wallet MOVE_INTERNAL: each wallet keeps its own independent lease epoch", async () => {
    const operationId = randomUUID();
    const sourceWalletId = await seedWallet("AVAILABLE"); // MOVE_SOURCE: no extra eligibility
    const destWalletId = await seedWallet("AVAILABLE");
    await verifyRecovery(destWalletId); // MOVE_DESTINATION requires recovery_verified_at + BLESSED
    const destinationId = await blessDestination(destWalletId);

    await pool.query(
      `INSERT INTO operations
         (id, node_id, implementer_id, kind, status, amount_zkz, source_wallet_id,
          destination_id, idempotency_key, request_sha256)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'MOVE_INTERNAL', 'CREATED', '1', $4::uuid,
               $5::uuid, $6, $7)`,
      [operationId, nodeId, implementerId, sourceWalletId, destinationId, `idem-${operationId}`, sha256HexOfText(operationId)],
    );

    const leaseGroupId = randomUUID();
    await pool.query(
      `INSERT INTO lease_groups (id, root_operation_id, created_at) VALUES ($1::uuid, $2::uuid, now())`,
      [leaseGroupId, operationId],
    );
    // Different epochs per wallet — proves the source/destination epochs are tracked
    // independently (leases/repository.ts nextEpoch() is per-wallet, not per-operation).
    await seedLease(leaseGroupId, operationId, sourceWalletId, "MOVE_SOURCE", 5);
    await seedLease(leaseGroupId, operationId, destWalletId, "MOVE_DESTINATION", 7);

    const { store } = createSqlBootRecovery(pool, logger, vault);
    const leases = await store.listActiveLeases();
    const srcLease = leases.find((l) => l.walletId === sourceWalletId);
    const dstLease = leases.find((l) => l.walletId === destWalletId);
    expect(srcLease?.role).toBe("MOVE_SOURCE");
    expect(srcLease?.epoch).toBe(5);
    expect(dstLease?.role).toBe("MOVE_DESTINATION");
    expect(dstLease?.epoch).toBe(7);

    const ops = await store.listNonterminalOperations();
    const moveOp = ops.find((o) => o.operationId === operationId);
    expect(moveOp).toBeDefined();
    expect(moveOp!.kind).toBe("MOVE_INTERNAL");
    expect(moveOp!.requiredRoles).toEqual(["MOVE_SOURCE", "MOVE_DESTINATION"]);
    expect(moveOp!.requiredRoles.length).toBeGreaterThan(1); // gates the op-wide epoch check off
    expect(new Set(moveOp!.leasedWalletIds)).toEqual(new Set([sourceWalletId, destWalletId]));
    // leaseEpoch is a single approximate pick across two independently-epoched wallets
    // (documented in sql-boot-recovery.ts) — assert it's one of the two real values, not
    // a fabricated third number.
    expect([5, 7]).toContain(moveOp!.leaseEpoch);
  });

  it("quarantineWallet: writes state+reason together from every legal pre-quarantine state", async () => {
    const { actions } = createSqlBootRecovery(pool, logger, vault);

    const pinnedWalletId = await seedWallet("PINNED");
    await actions.quarantineWallet(pinnedWalletId, "boot-recovery lease audit failure");
    const row = await pool.query<{ state: string; quarantine_reason: string | null }>(
      `SELECT state::text, quarantine_reason FROM wallets WHERE id = $1::uuid`,
      [pinnedWalletId],
    );
    expect(row.rows[0]!.state).toBe("QUARANTINED");
    expect(row.rows[0]!.quarantine_reason).toBe("boot-recovery lease audit failure");

    // Restored wallets commonly re-enter boot as AVAILABLE; they must quarantine too.
    const availableWalletId = await seedWallet("AVAILABLE");
    await actions.quarantineWallet(availableWalletId, "should apply");
    const guarded = await pool.query<{ state: string }>(
      `SELECT state::text FROM wallets WHERE id = $1::uuid`,
      [availableWalletId],
    );
    expect(guarded.rows[0]!.state).toBe("QUARANTINED");
  });

  it("repairWalletState: only understates AVAILABLE -> PINNED, never touches other source states", async () => {
    const { actions } = createSqlBootRecovery(pool, logger, vault);

    logger.lines.length = 0;
    const availableWalletId = await seedWallet("AVAILABLE");
    await actions.repairWalletState(availableWalletId, "PINNED");
    const row = await pool.query<{ state: string }>(
      `SELECT state::text FROM wallets WHERE id = $1::uuid`,
      [availableWalletId],
    );
    expect(row.rows[0]!.state).toBe("PINNED");
    expect(logger.lines.some((l) => l === `boot-recovery: repair wallet=${availableWalletId} state=PINNED`)).toBe(
      true,
    );
    expect(logger.lines.some((l) => l.includes("repair no-op") && l.includes(availableWalletId))).toBe(false);

    // Guard: a QUARANTINED wallet's state is untouched (source state must be AVAILABLE).
    // Seed AVAILABLE then move state+reason together in one statement — wallets_quarantine_
    // reason_iff requires both columns to change atomically, so the insert itself can't
    // land in QUARANTINED without a reason already present.
    logger.lines.length = 0;
    const quarantinedWalletId = await seedWallet("AVAILABLE");
    await pool.query(
      `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'pre-existing' WHERE id = $1::uuid`,
      [quarantinedWalletId],
    );
    await actions.repairWalletState(quarantinedWalletId, "PINNED");
    const guarded = await pool.query<{ state: string }>(
      `SELECT state::text FROM wallets WHERE id = $1::uuid`,
      [quarantinedWalletId],
    );
    expect(guarded.rows[0]!.state).toBe("QUARANTINED");
    // a blocked write must log repair no-op, never a completed repair line.
    expect(
      logger.lines.some((l) => l === `boot-recovery: repair no-op wallet=${quarantinedWalletId} state=PINNED`),
    ).toBe(true);
    expect(
      logger.lines.some((l) => l === `boot-recovery: repair wallet=${quarantinedWalletId} state=PINNED`),
    ).toBe(false);
  });

  it("setAttention: writes required+reason together on CAS hit, logs and no-ops on CAS miss", async () => {
    const { actions } = createSqlBootRecovery(pool, logger, vault);
    const operationId = randomUUID();
    await pool.query(
      `INSERT INTO operations
         (id, node_id, implementer_id, kind, status, amount_zkz, discriminator, anchor,
          after_landing, idempotency_key, request_sha256)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'CREATED', '1', $1::uuid,
               'recv', 'HOLD', $4, $5)`,
      [operationId, nodeId, implementerId, `idem-${operationId}`, sha256HexOfText(operationId)],
    );

    await actions.setAttention(operationId, "boot recovery invariant breach", 1);
    const afterHit = await pool.query<{
      attention_required: boolean;
      attention_reason: string | null;
      row_version: string;
    }>(
      `SELECT attention_required, attention_reason, row_version::text FROM operations WHERE id = $1::uuid`,
      [operationId],
    );
    expect(afterHit.rows[0]!.attention_required).toBe(true);
    expect(afterHit.rows[0]!.attention_reason).toBe("boot recovery invariant breach");

    // CAS miss: expectedRowVersion no longer matches the row's current row_version.
    logger.lines.length = 0;
    await actions.setAttention(operationId, "should not overwrite", 999);
    const afterMiss = await pool.query<{ attention_reason: string | null }>(
      `SELECT attention_reason FROM operations WHERE id = $1::uuid`,
      [operationId],
    );
    expect(afterMiss.rows[0]!.attention_reason).toBe("boot recovery invariant breach");
    expect(logger.lines.some((l) => l.includes("CAS miss") && l.includes(operationId))).toBe(true);
  });
});

describe("boot vault correspondence PG gate", () => {
  it("does not silently skip under PG_REQUIRED", () => {
    if (process.env.PG_REQUIRED === "1" && !PG_AVAILABLE) {
      throw new Error("PG_REQUIRED=1 but no reachable PostgreSQL");
    }
    expect(true).toBe(true);
  });
});

// The lease-eligible census. A landed operation KEEPS its lease: release happens
// only on the consumer's verification-complete acknowledgement, proof-backed (that leg is proven in
// apps/generic-node/src/operations/verification-complete-store.test.ts). Resolving active
// leases against a nonterminal-only operation census therefore reported every landed receive
// as `lease_operation_missing` — a global invariant breach that quarantined the wallet and
// stopped money engines on every subsequent boot.
//
// Own disposable database on purpose: the block above deliberately leaves wallets with
// unreadable vault material behind, so `invariantBreach === false` is unassertable inside it.
describe.skipIf(!PG_AVAILABLE)("boot census keeps landed-operation leases (disposable PG)", () => {
  const dbName = `bootlate_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let prevDatabaseUrl: string | undefined;
  let nodeId: string;
  let implementerId: string;
  let vault: EncryptedWalletKeyStore;

  beforeAll(async () => {
    await createTestDatabase(dbName);
    pool = pgPool(dbName);
    prevDatabaseUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);
    const { runMigrationsOnPool } = await import("../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });
    await migrateLeaseFoundation({
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await pool.query(text, params as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    });
    vault = new EncryptedWalletKeyStore({
      rootKey: ROOT_KEY,
      store: new VaultSqlStore(pool),
      auditLog: new InMemoryVaultAccessAuditLog(),
    });

    nodeId = randomUUID();
    implementerId = randomUUID();
    await ensureNodeRow(pool, {
      nodeId,
      displayName: "fixture-b-boot-census",
      identityPublicKey: publicKeyFromSeed(randomBytes(32)),
    });
    await pool.query(
      `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-b-impl', now())`,
      [implementerId],
    );
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    try {
      await pool?.end();
      await dropTestDatabase(dbName);
    } finally {
      if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = prevDatabaseUrl;
    }
  }, PG_TEST_TIMEOUT_MS);

  /** Wallet with real sealed vault material, so step 2 key correspondence passes. */
  async function seedVerifiedWallet(): Promise<string> {
    const walletId = randomUUID();
    const seed = randomBytes(32);
    const publicKey = publicKeyFromSeed(seed);
    const secret64 = Buffer.concat([seed, Buffer.from(publicKey, "base64url")]);
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
      [walletId, nodeId, publicKey],
    );
    try {
      await vault.seal(
        { nodeId, walletId, keyVersion: 1, publicKey, keyOrigin: "node_generated" },
        secret64,
      );
    } finally {
      seed.fill(0);
      secret64.fill(0);
    }
    const verificationId = randomUUID();
    await pool.query(
      `INSERT INTO wallet_recovery_verifications
         (id, wallet_id, method, public_key, export_sha256, audit_event_id, verified_at, verifier_identity)
       VALUES ($1::uuid, $2::uuid, 'AUDITED_EXPORT', $3, $4, $5::uuid, now(), 'fixture-b-suite')`,
      [verificationId, walletId, publicKey, sha256HexOfText(walletId), randomUUID()],
    );
    await pool.query(
      `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = $2::uuid
        WHERE id = $1::uuid`,
      [walletId, verificationId],
    );
    return walletId;
  }

  async function seedHeldLease(
    leaseGroupId: string,
    operationId: string,
    walletId: string,
  ): Promise<void> {
    const membershipId = randomUUID();
    await pool.query(
      `INSERT INTO wallet_lease_memberships
         (id, lease_group_id, wallet_id, operation_id, lease_role, lease_epoch, acquired_at)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'RECEIVE_WINDOW', 1, now())`,
      [membershipId, leaseGroupId, walletId, operationId],
    );
    await pool.query(
      `INSERT INTO wallet_active_leases
         (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
          lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $4::uuid, 'RECEIVE_WINDOW', 1, now(), now(), $5::uuid)`,
      [walletId, membershipId, leaseGroupId, operationId, randomUUID()],
    );
    // Acquisition requires an AVAILABLE wallet (custody-eligibility
    // CUSTODY_LEASE_WALLET_STATE_REJECTED); the pin follows it, as in the real path.
    await pool.query(`UPDATE wallets SET state = 'PINNED' WHERE id = $1::uuid`, [walletId]);
  }

  /**
   * A settled receive exactly as the landing transaction leaves it: status RECEIVE_LANDED,
   * lease still held. `receiver_wallet_id` / `expiry_unix_time_secs` / `t0_observation_id`
   * are the (wallet, expiry, T0) triple operations.sql requires past CREATED.
   */
  async function seedLandedReceiveHoldingItsLease(): Promise<{
    operationId: string;
    walletId: string;
    leaseGroupId: string;
  }> {
    const operationId = randomUUID();
    const walletId = await seedVerifiedWallet();
    await pool.query(
      `INSERT INTO operations
         (id, node_id, implementer_id, kind, status, amount_zkz, discriminator, anchor,
          after_landing, idempotency_key, request_sha256,
          receiver_wallet_id, expiry_unix_time_secs, t0_observation_id, terminal_at)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'RECEIVE_LANDED', '1', $1::uuid,
               'recv', 'HOLD', $4, $5, $6::uuid, '1700000000', $7::uuid, now())`,
      [
        operationId,
        nodeId,
        implementerId,
        `idem-${operationId}`,
        sha256HexOfText(operationId),
        walletId,
        randomUUID(),
      ],
    );
    const leaseGroupId = randomUUID();
    await pool.query(
      `INSERT INTO lease_groups (id, root_operation_id, created_at) VALUES ($1::uuid, $2::uuid, now())`,
      [leaseGroupId, operationId],
    );
    await seedHeldLease(leaseGroupId, operationId, walletId);
    await pool.query(
      `INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at)
       VALUES ($1::uuid, $2::uuid, now())`,
      [leaseGroupId, operationId],
    );
    return { operationId, walletId, leaseGroupId };
  }

  async function clearOperationalState(): Promise<void> {
    await pool.query(
      `TRUNCATE wallet_active_leases, wallet_lease_memberships, lease_group_operations,
                lease_groups, lease_release_proofs, lease_audit_events,
                wallet_lease_epoch_highwater RESTART IDENTITY CASCADE`,
    );
    await pool.query(`DELETE FROM operations`);
  }

  async function runRecovery() {
    const { store, actions } = createSqlBootRecovery(pool, logger, vault);
    return runDeterministicBootRecovery({ leadership: { held: true }, store, actions });
  }

  it(
    "a landed receive keeps its lease and boot recovery reports NO invariant breach",
    async () => {
      await clearOperationalState();
      const seeded = await seedLandedReceiveHoldingItsLease();

      const report = await runRecovery();

      expect(report.invariantBreach).toBe(false);
      expect(report.leaseFindings.filter((f) => f.reason === "lease_operation_missing")).toEqual([]);
      expect(report.leaseFindings.filter((f) => f.severity === "invariant_breach")).toEqual([]);
      expect(report.ready).toBe(true);

      // The wallet is untouched: still PINNED, never quarantined.
      const wallet = await pool.query<{ state: string; quarantine_reason: string | null }>(
        `SELECT state::text, quarantine_reason FROM wallets WHERE id = $1::uuid`,
        [seeded.walletId],
      );
      expect(wallet.rows[0]!.state).toBe("PINNED");
      expect(wallet.rows[0]!.quarantine_reason).toBeNull();

      // AC1' — the lease is still HELD, and no release proof was minted. Release is the
      // verification-complete leg's job and no consumer has acknowledged.
      const held = await pool.query<{ operation_id: string; lease_role: string }>(
        `SELECT operation_id::text, lease_role::text FROM wallet_active_leases WHERE wallet_id = $1::uuid`,
        [seeded.walletId],
      );
      expect(held.rows).toHaveLength(1);
      expect(held.rows[0]!.operation_id).toBe(seeded.operationId);
      expect(held.rows[0]!.lease_role).toBe("RECEIVE_WINDOW");
      expect((await pool.query(`SELECT 1 FROM lease_release_proofs`)).rowCount).toBe(0);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "the landed operation is audited by step 3 but never reaches step 5 classification",
    async () => {
      await clearOperationalState();
      const seeded = await seedLandedReceiveHoldingItsLease();

      const { store } = createSqlBootRecovery(pool, logger, vault);
      const census = await store.listNonterminalOperations();
      const censusRow = census.find((o) => o.operationId === seeded.operationId);
      expect(censusRow).toBeDefined();
      expect(censusRow!.status).toBe("RECEIVE_LANDED");
      expect(censusRow!.leasedWalletIds).toEqual([seeded.walletId]);

      const report = await runRecovery();

      expect(report.leaseFindings.some((f) => f.walletId === seeded.walletId)).toBe(true);
      // Without the partition the landed op classifies INDETERMINATE /
      // submit_boundary_recorded_awaiting_observation and gets attention parked on it.
      expect(report.classifications.map((c) => c.operationId)).not.toContain(seeded.operationId);
      const attention = await pool.query<{ attention_required: boolean }>(
        `SELECT attention_required FROM operations WHERE id = $1::uuid`,
        [seeded.operationId],
      );
      expect(attention.rows[0]!.attention_required).toBe(false);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "a genuinely orphaned lease — operation row absent entirely — still breaches and quarantines",
    async () => {
      await clearOperationalState();
      const walletId = await seedVerifiedWallet();
      const missingOperationId = randomUUID(); // no `operations` row is ever written for it
      const leaseGroupId = randomUUID();
      await pool.query(
        `INSERT INTO lease_groups (id, root_operation_id, created_at) VALUES ($1::uuid, $2::uuid, now())`,
        [leaseGroupId, missingOperationId],
      );
      await seedHeldLease(leaseGroupId, missingOperationId, walletId);
      await pool.query(
        `INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at)
         VALUES ($1::uuid, $2::uuid, now())`,
        [leaseGroupId, missingOperationId],
      );

      const report = await runRecovery();

      expect(report.invariantBreach).toBe(true);
      expect(report.ready).toBe(false);
      expect(
        report.leaseFindings.some(
          (f) => f.walletId === walletId && f.reason === "lease_operation_missing",
        ),
      ).toBe(true);
      const wallet = await pool.query<{ state: string }>(
        `SELECT state::text FROM wallets WHERE id = $1::uuid`,
        [walletId],
      );
      expect(wallet.rows[0]!.state).toBe("QUARANTINED");
      // One-in-flight: quarantine never deletes the lease row.
      expect((await pool.query(`SELECT 1 FROM wallet_active_leases`)).rowCount).toBe(1);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "replay is idempotent — a second boot over the same landed state repeats the report exactly",
    async () => {
      await clearOperationalState();
      const seeded = await seedLandedReceiveHoldingItsLease();

      const first = await runRecovery();
      const second = await runRecovery();

      expect(second.invariantBreach).toBe(first.invariantBreach);
      expect(second.ready).toBe(first.ready);
      expect(second.leaseFindings).toEqual(first.leaseFindings);
      expect(second.classifications).toEqual(first.classifications);
      expect(second.counters).toEqual(first.counters);
      expect((await pool.query(`SELECT 1 FROM wallet_active_leases`)).rowCount).toBe(1);
      expect((await pool.query(`SELECT 1 FROM lease_release_proofs`)).rowCount).toBe(0);
      const wallet = await pool.query<{ state: string }>(
        `SELECT state::text FROM wallets WHERE id = $1::uuid`,
        [seeded.walletId],
      );
      expect(wallet.rows[0]!.state).toBe("PINNED");
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "QUARANTINED leased wallet (live-incident shape): no breach, no repair attempt, stays QUARANTINED",
    async () => {
      // gn_ceremony_v2: RECEIVE_LANDED + RECEIVE_WINDOW lease + stale QUARANTINED reason.
      // Pre-fix projection said PINNED → boot-audit REPAIR_TO_PROJECTION → false repair log
      // while the AVAILABLE-only SQL guard left the row QUARANTINED.
      await clearOperationalState();
      const seeded = await seedLandedReceiveHoldingItsLease();
      await pool.query(
        `UPDATE wallets
            SET state = 'QUARANTINED',
                quarantine_reason = 'boot: lease operation missing'
          WHERE id = $1::uuid`,
        [seeded.walletId],
      );

      logger.lines.length = 0;
      const report = await runRecovery();

      expect(report.invariantBreach).toBe(false);
      expect(report.ready).toBe(true);
      expect(report.leaseFindings.filter((f) => f.severity === "repair")).toEqual([]);
      expect(report.leaseFindings.filter((f) => f.severity === "invariant_breach")).toEqual([]);
      expect(
        report.leaseFindings.some(
          (f) => f.walletId === seeded.walletId && f.severity === "ok",
        ),
      ).toBe(true);

      const wallet = await pool.query<{ state: string; quarantine_reason: string | null }>(
        `SELECT state::text, quarantine_reason FROM wallets WHERE id = $1::uuid`,
        [seeded.walletId],
      );
      expect(wallet.rows[0]!.state).toBe("QUARANTINED");
      expect(wallet.rows[0]!.quarantine_reason).toBe("boot: lease operation missing");

      // No completed repair log and no no-op either — disposition is CONSISTENT so
      // repairWalletState is never called.
      expect(logger.lines.some((l) => l.includes(`repair wallet=${seeded.walletId}`))).toBe(false);
      expect(logger.lines.some((l) => l.includes(`repair no-op wallet=${seeded.walletId}`))).toBe(
        false,
      );

      // One-in-flight: lease retained.
      expect(
        (
          await pool.query(`SELECT 1 FROM wallet_active_leases WHERE wallet_id = $1::uuid`, [
            seeded.walletId,
          ])
        ).rowCount,
      ).toBe(1);
      expect((await pool.query(`SELECT 1 FROM lease_release_proofs`)).rowCount).toBe(0);
    },
    PG_TEST_TIMEOUT_MS,
  );
});
