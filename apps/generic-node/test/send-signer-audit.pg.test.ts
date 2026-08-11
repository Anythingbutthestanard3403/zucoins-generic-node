// Production SEND signer_audit wiring against a real disposable Postgres.
//
// Prior to this ticket, start-money-workers.ts's resolveSendSignerDeps wired
// createNoopSignerAuditLog for SEND's SignerBoundaryDeps.auditLog (same defect as MOVE — see
// apps/generic-node/test/move-advanced-ports.pg.test.ts's "signer_audit" suite for the
// MOVE half of this proof). Every SEND signUnderLease call — success or rejection — left zero
// rows in signer_audit, so boot recovery's signer_audit_present check (createSqlBootRecovery)
// was always false for SEND_EXTERNAL operations regardless of whether the vault was actually
// invoked.
//
// This suite composes SEND's exact production SignerBoundaryDeps — createMoneySignerBoundaryDeps
// + createPoolVaultSigner + createSqlLeaseReader + createSqlSignerAuditLog(createSqlQueryFn(pool))
// (apps/generic-node/src/money-workers/start-money-workers.ts:738-748) — and calls signUnderLease
// directly against a real SEND_EXTERNAL operation with an ACTIVE SEND_SOURCE lease and a real
// sealed vault key, then proves the durable row lands and boot recovery observes it. The signer-audit
// formation ceremony (external_send_sign_intents / transfer-code construction) is out of scope:
// this suite only proves the signer-audit adapter this ticket touched, not SEND formation.

import { createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  createMoneySignerBoundaryDeps,
  createSqlSignerAuditLog,
  deriveRootKey,
  EncryptedWalletKeyStore,
  InMemoryVaultAccessAuditLog,
  LEASE_STATEMENTS,
  migrateLeaseFoundation,
  signUnderLease,
  VaultSqlStore,
  type SigningCapabilityOf,
  type SignerBoundaryDeps,
  type SigningPurpose,
  type SqlQueryFn,
} from "@zucoins/node-core";

import { ensureNodeRow } from "../src/bootstrap/genesis.js";
import { publicKeyFromSeed } from "../src/ops/ed25519-ops.js";
import { createSqlBootRecovery } from "../src/boot/sql-boot-recovery.js";
import {
  createSqlLeaseReader,
  createSqlSignUnderLeaseTransaction,
} from "../src/money-workers/send-signer-deps.js";
import { createPoolVaultSigner } from "../src/money-workers/send-vault-signer.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const VAULT_MASTER = "send-signer-audit-master-key!!!!!!!!!!!";
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function sha256HexOfText(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** Same seed||pubkey derivation as move-advanced-ports.pg.test.ts's signer_audit suite. */
function sealedSecret64FromSeed(seed: Buffer): Buffer {
  const priv = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(priv).export({ type: "spki", format: "der" });
  return Buffer.concat([seed, Buffer.from(spki).subarray(-32)]);
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
const HAS_DROPDB = hasClientTool("dropdb");
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
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(dbName)) throw new Error(`unsafe test db name: ${dbName}`);
}

async function createTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_CREATEDB) {
    execFileSync("createdb", ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, dbName], { env: process.env });
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
  if (HAS_DROPDB) {
    execFileSync("dropdb", ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, "--if-exists", dbName], {
      env: process.env,
      stdio: "ignore",
    });
    return;
  }
  const admin = new Client(adminClientConfig("postgres"));
  await admin.connect();
  try {
    await admin.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [dbName],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
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

describe.skipIf(!PG_AVAILABLE)("signer_audit — SEND production wiring (real PG)", () => {
  const dbName = `send_signer_audit_send_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let prevDatabaseUrl: string | undefined;

  beforeAll(async () => {
    await createTestDatabase(dbName);
    pool = pgPool(dbName);
    // db/client.ts reads process.env.DATABASE_URL at import time (module-level, before
    // runMigrationsOnPool's own databaseUrl option is ever consulted), so it must be set
    // before the dynamic import below — same convention as move-advanced-ports.pg.test.ts /
    // sql-boot-recovery.pg.test.ts's beforeAll.
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
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    await pool?.end().catch(() => {});
    await dropTestDatabase(dbName).catch(() => {});
    if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = prevDatabaseUrl;
  }, PG_TEST_TIMEOUT_MS);

  const query: SqlQueryFn = async (text, values) => {
    const result = await pool.query(text, values as never[]);
    return result.rows as readonly Record<string, unknown>[];
  };

  /** Exactly the SignerBoundaryDeps composition start-money-workers.ts's resolveSendSignerDeps
   * builds in production (createMoneySignerBoundaryDeps + createPoolVaultSigner +
   * createSqlLeaseReader + createSqlSignerAuditLog over the same SqlQueryFn shape). */
  function productionSendSignerDeps(nodeId: string, vault: EncryptedWalletKeyStore): SignerBoundaryDeps {
    return createMoneySignerBoundaryDeps(
      {
        leadership: { held: true },
        leaseReader: createSqlLeaseReader(pool),
        vaultSigner: createPoolVaultSigner({ pool, vault, nodeId }),
        auditLog: createSqlSignerAuditLog(query),
        // ZTR-1160: production SEND pins lease FOR UPDATE across vault + audit.
        withSignTransaction: createSqlSignUnderLeaseTransaction(pool),
      },
      {
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: () => {},
      },
    );
  }

  async function seedSendForSigning(): Promise<{
    readonly nodeId: string;
    readonly operationId: string;
    readonly walletId: string;
    readonly leaseGroupId: string;
    readonly vault: EncryptedWalletKeyStore;
  }> {
    const nodeId = randomUUID();
    const implementerId = randomUUID();
    const operationId = randomUUID();
    const walletId = randomUUID();
    const leaseGroupId = randomUUID();
    const seed = randomBytes(32);
    const publicKey = publicKeyFromSeed(seed);

    await ensureNodeRow(pool, {
      nodeId,
      displayName: "fixture-send-signer-audit",
      identityPublicKey: publicKeyFromSeed(randomBytes(32)),
    });
    await pool.query(
      `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-send-impl', now())`,
      [implementerId],
    );
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ($1::uuid, $3::uuid, $2, 'node_generated', 'PINNED')`,
      [walletId, publicKey, nodeId],
    );
    // destination_address is the padded_base64url_pubkey domain (44 chars); never resolved to a
    // real wallet on this path — signUnderLease never reads it, only the source lease/wallet.
    const destinationAddress = publicKeyFromSeed(randomBytes(32));
    await pool.query(
      `INSERT INTO operations (
         id, node_id, implementer_id, kind, status, amount_zkz,
         source_wallet_id, destination_address, idempotency_key, request_sha256, formation_state)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'SEND_EXTERNAL', 'APPROVED', '1.0',
               $4::uuid, $5, $6, $7, 'SIGNING_CLAIMED')`,
      [
        operationId, nodeId, implementerId, walletId, destinationAddress,
        `idem-${operationId}`, sha256HexOfText(operationId),
      ],
    );
    await pool.query(
      `INSERT INTO lease_groups (id, root_operation_id, created_at) VALUES ($1::uuid, $2::uuid, now())`,
      [leaseGroupId, operationId],
    );

    const vault = new EncryptedWalletKeyStore({
      rootKey: deriveRootKey(VAULT_MASTER, VAULT_ROOT_KDF_SALT),
      store: new VaultSqlStore(pool),
      auditLog: new InMemoryVaultAccessAuditLog(),
    });
    await vault.seal(
      { nodeId, walletId, keyVersion: 1, publicKey, keyOrigin: "node_generated" },
      sealedSecret64FromSeed(seed),
    );

    return { nodeId, operationId, walletId, leaseGroupId, vault };
  }

  async function seedActiveSendSourceLease(params: {
    readonly leaseGroupId: string;
    readonly operationId: string;
    readonly walletId: string;
  }): Promise<void> {
    const membershipId = randomUUID();
    const acquiredAt = new Date().toISOString();
    await pool.query(LEASE_STATEMENTS.INSERT_MEMBERSHIP, [
      membershipId, params.leaseGroupId, params.walletId, params.operationId, "SEND_SOURCE", 1, acquiredAt,
    ]);
    await pool.query(LEASE_STATEMENTS.INSERT_ACTIVE, [
      params.walletId, membershipId, params.leaseGroupId, params.operationId, params.operationId,
      "SEND_SOURCE", 1, acquiredAt, acquiredAt, randomUUID(),
    ]);
  }

  const readAudit = async (operationId: string): Promise<readonly Record<string, unknown>[]> =>
    query(
      `SELECT node_id::text AS node_id, outcome, purpose, lease_epoch::text AS lease_epoch, preimage_sha256
         FROM signer_audit WHERE operation_id = $1 ORDER BY called_at`,
      [operationId],
    );

  function capability(operationId: string, walletId: string): SigningCapabilityOf<SigningPurpose> {
    const preimageText = JSON.stringify({ stub: "fixture-send-inner", operationId });
    return {
      walletId,
      operationId,
      leaseEpoch: 1n,
      purpose: "SPLITCHAIN_STEP_1",
      preimageText,
      expectedPreimageSha256: sha256HexOfText(preimageText),
    };
  }

  it(
    "SIGNED: signUnderLease with SEND's production deps writes a SUCCEEDED row, and boot recovery observes the call",
    async () => {
      const seeded = await seedSendForSigning();

      const before = await createSqlBootRecovery(pool, logger, {} as never).store.listNonterminalOperations();
      expect(before.find((o) => o.operationId === seeded.operationId)?.signerAuditIndicatesCall).toBe(false);

      await seedActiveSendSourceLease(seeded);
      const deps = productionSendSignerDeps(seeded.nodeId, seeded.vault);

      const result = await signUnderLease(deps, capability(seeded.operationId, seeded.walletId));
      expect(result.signature.length).toBeGreaterThan(0);

      const audit = await readAudit(seeded.operationId);
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({
        node_id: seeded.nodeId, outcome: "SUCCEEDED", purpose: "STEP_1", lease_epoch: "1",
      });

      const after = await createSqlBootRecovery(pool, logger, {} as never).store.listNonterminalOperations();
      expect(after.find((o) => o.operationId === seeded.operationId)?.signerAuditIndicatesCall).toBe(true);
    },
  );

  it(
    "REJECTED: signing with no active lease writes a FAILED row instead of silently dropping the attempt",
    async () => {
      const seeded = await seedSendForSigning();
      const deps = productionSendSignerDeps(seeded.nodeId, seeded.vault);
      // Deliberately no seedActiveSendSourceLease call — validateLease reads back "no active lease".

      await expect(signUnderLease(deps, capability(seeded.operationId, seeded.walletId))).rejects.toThrow();

      const audit = await readAudit(seeded.operationId);
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ node_id: seeded.nodeId, outcome: "FAILED", purpose: "STEP_1" });

      const after = await createSqlBootRecovery(pool, logger, {} as never).store.listNonterminalOperations();
      expect(after.find((o) => o.operationId === seeded.operationId)?.signerAuditIndicatesCall).toBe(true);
    },
  );
});
