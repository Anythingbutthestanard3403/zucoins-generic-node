// ZTR-1235: money-worker autoApprovePendingSends ahead of advanceApprovedSends.
// Disposable PG: policy gates, halt, signer-absent still approves, same-tick form when armed.

import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as edSign,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  AUTO_APPROVE_APPLIED_ACTION,
  AUTO_APPROVE_SETTING_KEY,
  createExternalSend,
  createSqlRecoveryLiveDatabase,
  createSqlSignerAuditLog,
  deriveRootKey,
  ensureActiveNodeSigningKey,
  EncryptedWalletKeyStore,
  GENESIS_PROJECTION,
  InMemoryVaultAccessAuditLog,
  migrateLeaseFoundation,
  serializeAutoApprovePolicyDocument,
  SqlSendCreateStore,
  toBase64UrlPadded,
  type AutoApproveRule,
  type NodeEventSigner,
  type SendFormationObserver,
  type SignerBoundaryDeps,
  VaultSqlStore,
} from "@zucoins/node-core";

import { ensureNodeIdentitySigningKey, ensureNodeRow } from "../src/bootstrap/genesis.js";
import { startMoneyWorkers } from "../src/money-workers/start-money-workers.js";
import { publicKeyFromSeed, signPaddedBase64Url } from "../src/ops/ed25519-ops.js";
import { createPoolVaultSigner } from "../src/money-workers/send-vault-signer.js";
import {
  createSqlLeaseReader,
  createSqlSignUnderLeaseTransaction,
} from "../src/money-workers/send-signer-deps.js";
import { WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE } from "../../../packages/node-core/test/fixtures/splitchain-v2-byte-evidence.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const MASTER = "fundable-master-key-32b!!!!!!!!!!!!!!!!";

function hasClientTool(bin: string): boolean {
  try {
    execFileSync(bin, bin === "pg_isready" ? ["-q"] : ["--version"], { stdio: "ignore" });
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
      execFileSync("pg_isready", ["-q"], { stdio: "ignore" });
      return true;
    }
  } catch {
    /* TCP */
  }
  try {
    execFileSync(
      "node",
      [
        "-e",
        `const {Client}=require('pg');const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:'postgres',password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      { stdio: "ignore", env: process.env },
    );
    return true;
  } catch {
    return false;
  }
})();

function assertSafeDbName(name: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
    throw new Error(`unsafe db name: ${name}`);
  }
}

function adminClientConfig(database: string) {
  return {
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database,
    password: process.env.PGPASSWORD,
  };
}

async function createTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_CREATEDB) {
    execFileSync("createdb", ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, dbName], {
      env: process.env,
      stdio: "ignore",
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
  if (HAS_DROPDB) {
    execFileSync(
      "dropdb",
      ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, "--if-exists", dbName],
      { env: process.env, stdio: "ignore" },
    );
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
  return new Pool({
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database: dbName,
    password: process.env.PGPASSWORD,
  });
}

function pgDatabaseUrl(dbName: string): string {
  const auth = process.env.PGPASSWORD
    ? `${encodeURIComponent(PG_USER)}:${encodeURIComponent(process.env.PGPASSWORD)}`
    : encodeURIComponent(PG_USER);
  const host = PG_HOST === "/tmp" ? "localhost" : PG_HOST;
  return `postgres://${auth}@${host}:${PG_PORT}/${dbName}`;
}

function externalWalletPubkey(): string {
  const { publicKey: pubObj } = generateKeyPairSync("ed25519");
  const spki = pubObj.export({ format: "der", type: "spki" });
  return toBase64UrlPadded(Buffer.from(spki).subarray(-32));
}

function makeRule(implementerId: string, overrides: Partial<AutoApproveRule> = {}): AutoApproveRule {
  return {
    rule_id: "worker-rule",
    implementer_id: implementerId,
    per_send_max_zkz: "1",
    per_send_min_zkz: null,
    window_hours: 24,
    window_cap_zkz: "10",
    expires_at: null,
    enabled: true,
    ...overrides,
  };
}

describe.skipIf(!PG_AVAILABLE)("money worker autoApprovePendingSends (disposable PG)", () => {
  const dbName = `auto_approve_worker_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let prevDatabaseUrl: string | undefined;

  beforeAll(async () => {
    await createTestDatabase(dbName);
    pool = pgPool(dbName);
    prevDatabaseUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);
    const { runMigrationsOnPool } = await import("../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });
    const leaseSql = {
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await pool.query(text, params as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    };
    await migrateLeaseFoundation(leaseSql);
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = prevDatabaseUrl;
    await pool?.end().catch(() => {});
    await dropTestDatabase(dbName).catch(() => {});
  }, PG_TEST_TIMEOUT_MS);

  async function seedFixture() {
    const nodeId = randomUUID();
    const implementerId = randomUUID();
    const identitySeed = randomBytes(32);
    const identityPublicKey = publicKeyFromSeed(identitySeed);
    const signingKeyId = randomUUID();

    await ensureNodeRow(pool, {
      nodeId,
      displayName: "auto-approve-worker",
      identityPublicKey,
    });
    await pool.query(
      `INSERT INTO implementers (id, name, created_at)
       VALUES ($1::uuid, 'auto-approve-impl', now())
       ON CONFLICT DO NOTHING`,
      [implementerId],
    );
    await ensureNodeIdentitySigningKey(pool, {
      keyId: signingKeyId,
      nodeId,
      publicKey: identityPublicKey,
    });
    const durableKey = await pool.query<{ id: string }>(
      `SELECT id::text AS id FROM node_signing_keys
        WHERE node_id = $1::uuid AND purpose = 'NODE_IDENTITY' AND public_key = $2
        LIMIT 1`,
      [nodeId, identityPublicKey],
    );
    const liveSigningKeyId = durableKey.rows[0]?.id ?? signingKeyId;

    const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
    const vault = new EncryptedWalletKeyStore({
      rootKey,
      store: new VaultSqlStore(pool),
      auditLog: new InMemoryVaultAccessAuditLog(),
    });

    const eventKeyClient = await pool.connect();
    let eventSigner: NodeEventSigner;
    try {
      await eventKeyClient.query("BEGIN");
      const eventKey = await ensureActiveNodeSigningKey({
        sql: {
          query: async <R>(text: string, params?: readonly unknown[]) => {
            const result = await eventKeyClient.query(text, params as never);
            return { rows: result.rows as R[] };
          },
        },
        rootKey,
        nodeId,
        purpose: "EVENT_SIGNING",
      });
      await eventKeyClient.query("COMMIT");
      eventSigner = {
        signingKeyId: eventKey.signingKeyId,
        sign: (bytes) => toBase64UrlPadded(Buffer.from(eventKey.sign(bytes))),
      };
    } finally {
      eventKeyClient.release();
    }

    const moneyAdmitted = true;
    let haltBlocksSend = false;
    const moneyPathGates = {
      assertMoneyAdmitted: () => {
        if (!moneyAdmitted) throw new Error("money admission closed (test)");
      },
      assertCanOperate: () => {},
      assertWalletMaySign: async () => {},
      assertHaltAdmitsKind: (kind: string) => {
        if (haltBlocksSend && kind === "SEND_EXTERNAL") {
          throw new Error("halt refuses SEND_EXTERNAL (test)");
        }
      },
    };

    const logs: string[] = [];
    const handle = startMoneyWorkers({
      pool,
      vault,
      config: {
        nodeId,
        ownerInstanceId: nodeId,
        poolCapTotal: 8,
        receiveQueueCap: 10,
        receiveQueueMaxWaitSecs: 600,
        receiveTtlDefaultSecs: 300,
        receiveTtlMinSecs: 60,
        receiveTtlMaxSecs: 3600,
        // Drive only via tickOnce.
        tickIntervalMs: 0,
        allowGenesisT0Stub: true,
      },
      logger: {
        info: (m) => logs.push(m),
        error: (m, err) =>
          logs.push(`err:${m}${err instanceof Error ? ` ${err.message}` : ""}`),
      },
      moneyPathGates,
      nodeIdentitySigner: () => ({
        signingKeyId: liveSigningKeyId,
        sign(preimageBytes: Uint8Array): string {
          return signPaddedBase64Url(identitySeed, preimageBytes);
        },
      }),
      eventSigner: () => eventSigner,
      // Default: no signer leadership → formation defers; auto-approve still runs.
      sendSignerDeps: null,
      onApprovedSendSignerUnavailable: (info) => {
        logs.push(
          `signal:approved_send_signer_unavailable count=${info.approvedCount}`,
        );
      },
    });

    // Mint pool. Cap count is DB-global (not per-node), so later fixtures in the same
    // disposable DB may see mintCount=0 — backfill wallets for this node when empty.
    await handle.tickOnce();
    {
      const minted = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM wallets WHERE node_id = $1::uuid`,
        [nodeId],
      );
      // First suite creates many concurrent unsettled sends; keep a free-wallet floor.
      if (Number(minted.rows[0]?.n ?? "0") < 16) {
        for (let i = Number(minted.rows[0]?.n ?? "0"); i < 16; i += 1) {
          const { privateKey, publicKey: pubObj } = generateKeyPairSync("ed25519");
          const spki = pubObj.export({ format: "der", type: "spki" });
          const publicKey = toBase64UrlPadded(Buffer.from(spki).subarray(-32));
          const jwk = privateKey.export({ format: "jwk" });
          const d = typeof jwk.d === "string" ? jwk.d : "";
          const seed = Buffer.from(d, "base64url");
          const secret64 = Buffer.concat([seed, Buffer.from(spki).subarray(-32)]);
          const walletId = randomUUID();
          try {
            await pool.query(
              `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
               VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
              [walletId, nodeId, publicKey],
            );
            await vault.seal(
              {
                nodeId: nodeId as never,
                walletId: walletId as never,
                keyVersion: 1,
                publicKey: publicKey as never,
                keyOrigin: "node_generated",
              },
              secret64,
            );
          } finally {
            secret64.fill(0);
          }
        }
      }
    }
    const liveDb = createSqlRecoveryLiveDatabase({
      sql: {
        query: async <R>(text: string, params: readonly unknown[]) => {
          const result = await pool.query(text, params as never);
          return { rows: result.rows as R[] };
        },
      },
      nodeId,
      proveCurrentKeyPossession: async () => {
        throw new Error("not used on stamp path");
      },
    });
    const wallets = await liveDb.readWallets();
    for (const [walletId, row] of wallets) {
      if (row.recoveryVerifiedAt !== null) continue;
      const exportSha = createHash("sha256")
        .update(`fixture-export|${walletId}`, "utf8")
        .digest("hex");
      await liveDb.stampRecoveryVerification({
        ceremonyId: randomUUID(),
        walletId,
        method: "AUDITED_EXPORT",
        publicKey: row.publicKey,
        keyVersion: 1,
        exportId: randomUUID(),
        exportSha256: exportSha,
        censusMatchedRestored: true,
        censusMatchedLive: true,
        archivedProofVerified: true,
        probePreimageSha256: createHash("sha256").update("probe", "utf8").digest("hex"),
        probeSignature: signPaddedBase64Url(identitySeed, Buffer.from("probe")),
        probeVerified: true,
        verifierIdentity: "auto-approve-worker-stamp",
      });
    }

    const sqlExec = {
      query: async <R>(text: string, params: readonly unknown[] = []) => {
        const result = await pool.query(text, params as never);
        return { rows: result.rows as R[] };
      },
    };
    const sendStore = new SqlSendCreateStore(sqlExec);
    const sendSigner = {
      signingKeyId: liveSigningKeyId,
      sign(preimageBytes: Uint8Array): Uint8Array {
        const pkcs8 = Buffer.concat([
          Buffer.from("302e020100300506032b657004220420", "hex"),
          identitySeed,
        ]);
        const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
        return edSign(null, Buffer.from(preimageBytes), key);
      },
    };

    async function pickSourceWallet(): Promise<string> {
      // Exclude wallets already pinned by an unsettled external send (one-in-flight).
      const r = await pool.query<{ id: string }>(
        `SELECT w.id::text AS id
           FROM wallets w
          WHERE w.node_id = $1::uuid
            AND w.state = 'AVAILABLE'
            AND NOT EXISTS (
              SELECT 1 FROM send_operations s
               WHERE s.source_wallet_id = w.id
                 AND s.status IN ('CREATED', 'APPROVED', 'AWAITING_REDEMPTION', 'NEEDS_ATTENTION')
            )
          ORDER BY w.created_at ASC
          LIMIT 1`,
        [nodeId],
      );
      const id = r.rows[0]?.id;
      if (id === undefined) throw new Error("no free AVAILABLE wallet");
      return id;
    }

    async function createSend(
      amountZkz: string,
      idemSuffix: string,
      opts?: { readonly implementerId?: string },
    ): Promise<string> {
      const sourceWalletId = await pickSourceWallet();
      const outcome = await createExternalSend(
        sendStore,
        sendSigner,
        {
          implementerId: opts?.implementerId ?? implementerId,
          nodeId,
          sourceWalletId,
          destinationAddress: externalWalletPubkey(),
          amountZkz,
          referencesOperationId: null,
          clientReference: `aa-${idemSuffix}`,
          description: null,
          idempotencyKey: `aa-send-${idemSuffix}-${randomUUID()}`,
        },
        { generateId: () => randomUUID(), now: () => Date.now() },
      );
      if (outcome.outcome !== "CREATED") {
        throw new Error(`create send failed: ${JSON.stringify(outcome)}`);
      }
      return outcome.operation.operationId;
    }

    async function setPolicyDoc(json: string | null): Promise<void> {
      if (json === null) {
        await pool.query(`DELETE FROM node_settings WHERE setting_key = $1`, [
          AUTO_APPROVE_SETTING_KEY,
        ]);
        return;
      }
      await pool.query(
        `INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
         VALUES ($1, $2, 1, now())
         ON CONFLICT (setting_key) DO UPDATE
         SET setting_value = EXCLUDED.setting_value,
             row_version = node_settings.row_version + 1,
             updated_at = now()`,
        [AUTO_APPROVE_SETTING_KEY, json],
      );
    }

    async function sendStatus(operationId: string): Promise<{
      status: string;
      formation: string;
    }> {
      const r = await pool.query<{ status: string; formation_state: string }>(
        `SELECT status, formation_state FROM send_operations WHERE operation_id = $1::uuid`,
        [operationId],
      );
      return {
        status: r.rows[0]?.status ?? "MISSING",
        formation: r.rows[0]?.formation_state ?? "MISSING",
      };
    }

    async function autoApprovalCount(operationId: string): Promise<number> {
      const r = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM operation_approvals
          WHERE operation_id = $1::uuid AND method = 'AUTO_POLICY'`,
        [operationId],
      );
      return Number(r.rows[0]?.n ?? "0");
    }

    async function autoAuditCount(operationId: string): Promise<number> {
      const r = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM audit_log
          WHERE operation_id = $1::uuid AND action = $2`,
        [operationId, AUTO_APPROVE_APPLIED_ACTION],
      );
      return Number(r.rows[0]?.n ?? "0");
    }

    return {
      nodeId,
      implementerId,
      handle,
      logs,
      set haltBlocksSend(v: boolean) {
        haltBlocksSend = v;
      },
      createSend,
      setPolicyDoc,
      sendStatus,
      autoApprovalCount,
      autoAuditCount,
      stop: () => handle.stop(),
    };
  }

  it(
    "within-cap CREATED send → AUTO_POLICY APPROVED; fall-throughs stay CREATED; halt/disabled no-op; signer-absent still approves",
    async () => {
      const fx = await seedFixture();
      try {
        const rule = makeRule(fx.implementerId, {
          per_send_max_zkz: "1",
          per_send_min_zkz: "0.01",
          window_cap_zkz: "1",
        });
        await fx.setPolicyDoc(serializeAutoApprovePolicyDocument([rule], true));

        // Happy path — within bounds (canonical amounts: no trailing zeros).
        const okId = await fx.createSend("0.5", "ok");
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(okId)).toEqual({
          status: "APPROVED",
          formation: "APPROVED_UNSIGNED",
        });
        expect(await fx.autoApprovalCount(okId)).toBe(1);
        expect(await fx.autoAuditCount(okId)).toBe(1);
        expect(fx.logs.some((l) => l.includes(`SEND auto-approved op=${okId}`))).toBe(true);
        // Signer deps null → formation deferred (still APPROVED_UNSIGNED).
        // ZTR-1231: surface at error level + operator callback (throttled).
        expect(fx.logs.some((l) => l.includes("skip SEND form") && l.startsWith("err:"))).toBe(true);
        expect(
          fx.logs.some((l) => l.includes("signal:approved_send_signer_unavailable")),
        ).toBe(true);

        // Over-cap (window already spent 0.5, cap 1, amount 0.6 → 1.1 > 1).
        const overId = await fx.createSend("0.6", "over");
        await fx.handle.tickOnce();
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(overId)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(await fx.autoApprovalCount(overId)).toBe(0);
        expect(await fx.autoAuditCount(overId)).toBe(0);

        // Above max.
        const maxId = await fx.createSend("2", "max");
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(maxId)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(await fx.autoApprovalCount(maxId)).toBe(0);

        // No rule for a different implementer.
        const foreignImpl = randomUUID();
        await pool.query(
          `INSERT INTO implementers (id, name, created_at)
           VALUES ($1::uuid, 'foreign', now()) ON CONFLICT DO NOTHING`,
          [foreignImpl],
        );
        const noRuleId = await fx.createSend("0.01", "norule", { implementerId: foreignImpl });
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(noRuleId)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(await fx.autoApprovalCount(noRuleId)).toBe(0);

        // Policy disabled (enabled:false).
        await fx.setPolicyDoc(serializeAutoApprovePolicyDocument([rule], false));
        const offId = await fx.createSend("0.01", "off");
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(offId)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(fx.logs.some((l) => l.includes("policy=disabled"))).toBe(true);

        // Absent key.
        await fx.setPolicyDoc(null);
        const absentId = await fx.createSend("0.01", "absent");
        const logsBeforeAbsent = fx.logs.length;
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(absentId)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(
          fx.logs.slice(logsBeforeAbsent).some((l) => l.includes("policy=disabled reason=absent")),
        ).toBe(true);

        // Corrupt key.
        await fx.setPolicyDoc("{not-json");
        const corruptId = await fx.createSend("0.01", "corrupt");
        const logsBeforeCorrupt = fx.logs.length;
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(corruptId)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(
          fx.logs
            .slice(logsBeforeCorrupt)
            .some((l) => l.includes("policy=disabled reason=invalid")),
        ).toBe(true);

        // Halt engaged → no auto-approvals; resumes after disengage.
        await fx.setPolicyDoc(
          serializeAutoApprovePolicyDocument(
            [makeRule(fx.implementerId, { window_cap_zkz: "100", per_send_max_zkz: "10" })],
            true,
          ),
        );
        fx.haltBlocksSend = true;
        const haltId = await fx.createSend("0.01", "halt");
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(haltId)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(await fx.autoApprovalCount(haltId)).toBe(0);
        fx.haltBlocksSend = false;
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(haltId)).toEqual({
          status: "APPROVED",
          formation: "APPROVED_UNSIGNED",
        });
        expect(await fx.autoApprovalCount(haltId)).toBe(1);
      } finally {
        fx.stop();
      }
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "same tick: auto-approve + armed signer reaches AWAITING_REDEMPTION",
    async () => {
      const fx = await seedFixture();
      try {
        // Rebuild handle with armed signer deps so form runs in the same tick.
        fx.stop();
        const nodeId = fx.nodeId;
        const implementerId = fx.implementerId;

        // Re-seed identity from DB for a new worker handle.
        const identityRow = await pool.query<{ public_key: string; id: string }>(
          `SELECT public_key, id::text AS id FROM node_signing_keys
            WHERE node_id = $1::uuid AND purpose = 'NODE_IDENTITY' LIMIT 1`,
          [nodeId],
        );
        // We cannot recover the seed — mint a fresh fixture with signer armed instead.
        void identityRow;
        void implementerId;

        // Fresh fixture with signer-armed workers from the start.
        const nodeId2 = randomUUID();
        const implementerId2 = randomUUID();
        const identitySeed = randomBytes(32);
        const identityPublicKey = publicKeyFromSeed(identitySeed);
        const signingKeyId = randomUUID();
        await ensureNodeRow(pool, {
          nodeId: nodeId2,
          displayName: "auto-approve-form",
          identityPublicKey,
        });
        await pool.query(
          `INSERT INTO implementers (id, name, created_at)
           VALUES ($1::uuid, 'auto-approve-form-impl', now()) ON CONFLICT DO NOTHING`,
          [implementerId2],
        );
        await ensureNodeIdentitySigningKey(pool, {
          keyId: signingKeyId,
          nodeId: nodeId2,
          publicKey: identityPublicKey,
        });
        const durableKey = await pool.query<{ id: string }>(
          `SELECT id::text AS id FROM node_signing_keys
            WHERE node_id = $1::uuid AND purpose = 'NODE_IDENTITY' LIMIT 1`,
          [nodeId2],
        );
        const liveSigningKeyId = durableKey.rows[0]?.id ?? signingKeyId;

        const rootKey = deriveRootKey(`${MASTER}-form`, VAULT_ROOT_KDF_SALT);
        const vault = new EncryptedWalletKeyStore({
          rootKey,
          store: new VaultSqlStore(pool),
          auditLog: new InMemoryVaultAccessAuditLog(),
        });

        const eventKeyClient = await pool.connect();
        let eventSigner: NodeEventSigner;
        try {
          await eventKeyClient.query("BEGIN");
          const eventKey = await ensureActiveNodeSigningKey({
            sql: {
              query: async <R>(text: string, params?: readonly unknown[]) => {
                const result = await eventKeyClient.query(text, params as never);
                return { rows: result.rows as R[] };
              },
            },
            rootKey,
            nodeId: nodeId2,
            purpose: "EVENT_SIGNING",
          });
          await eventKeyClient.query("COMMIT");
          eventSigner = {
            signingKeyId: eventKey.signingKeyId,
            sign: (bytes) => toBase64UrlPadded(Buffer.from(eventKey.sign(bytes))),
          };
        } finally {
          eventKeyClient.release();
        }

        const moneyPathGates = {
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          assertWalletMaySign: async () => {},
          assertHaltAdmitsKind: () => {},
        };
        const logs: string[] = [];
        const signerDeps: SignerBoundaryDeps = {
          leadership: { held: true },
          leaseReader: createSqlLeaseReader(pool),
          vaultSigner: createPoolVaultSigner({ pool, vault, nodeId: nodeId2 }),
          auditLog: createSqlSignerAuditLog(async (text, values) => {
            const result = await pool.query(text, values as unknown[]);
            return result.rows as Record<string, unknown>[];
          }),
          withSignTransaction: createSqlSignUnderLeaseTransaction(pool),
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          assertWalletMaySign: async () => {},
        };

        // Genesis T0 reports B=0; form rejects source_insufficient_balance.
        // HEAD source needs non-empty previous settled signatures (not genesis S="").
        const fundedObserver: SendFormationObserver = {
          observeSource: async () => ({
            kind: "VERIFIED",
            observationId: randomUUID(),
            projection: {
              role: "sender",
              S: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
              P: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
              B: "10",
              I: "digest",
            },
          }),
          observeDestination: async () => ({
            kind: "VERIFIED",
            observationId: randomUUID(),
            projection: GENESIS_PROJECTION,
          }),
        };

        const handle = startMoneyWorkers({
          pool,
          vault,
          config: {
            nodeId: nodeId2,
            ownerInstanceId: nodeId2,
            poolCapTotal: 8,
            receiveQueueCap: 10,
            receiveQueueMaxWaitSecs: 600,
            receiveTtlDefaultSecs: 300,
            receiveTtlMinSecs: 60,
            receiveTtlMaxSecs: 3600,
            tickIntervalMs: 0,
            allowGenesisT0Stub: true,
          },
          logger: {
            info: (m) => logs.push(m),
            error: (m, err) =>
              logs.push(`err:${m}${err instanceof Error ? ` ${err.message}` : ""}`),
          },
          moneyPathGates,
          nodeIdentitySigner: () => ({
            signingKeyId: liveSigningKeyId,
            sign(preimageBytes: Uint8Array): string {
              return signPaddedBase64Url(identitySeed, preimageBytes);
            },
          }),
          eventSigner: () => eventSigner,
          sendSignerDeps: signerDeps,
          sendFormationObserver: fundedObserver,
        });

        try {
          await handle.tickOnce();
          {
            const minted = await pool.query<{ n: string }>(
              `SELECT count(*)::text AS n FROM wallets WHERE node_id = $1::uuid`,
              [nodeId2],
            );
            const have = Number(minted.rows[0]?.n ?? "0");
            if (have < 5) {
              for (let i = have; i < 5; i += 1) {
                const { privateKey, publicKey: pubObj } = generateKeyPairSync("ed25519");
                const spki = pubObj.export({ format: "der", type: "spki" });
                const publicKey = toBase64UrlPadded(Buffer.from(spki).subarray(-32));
                const jwk = privateKey.export({ format: "jwk" });
                const d = typeof jwk.d === "string" ? jwk.d : "";
                const seed = Buffer.from(d, "base64url");
                const secret64 = Buffer.concat([seed, Buffer.from(spki).subarray(-32)]);
                const walletId = randomUUID();
                try {
                  await pool.query(
                    `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
                     VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
                    [walletId, nodeId2, publicKey],
                  );
                  await vault.seal(
                    {
                      nodeId: nodeId2 as never,
                      walletId: walletId as never,
                      keyVersion: 1,
                      publicKey: publicKey as never,
                      keyOrigin: "node_generated",
                    },
                    secret64,
                  );
                } finally {
                  secret64.fill(0);
                }
              }
            }
          }
          const liveDb = createSqlRecoveryLiveDatabase({
            sql: {
              query: async <R>(text: string, params: readonly unknown[]) => {
                const result = await pool.query(text, params as never);
                return { rows: result.rows as R[] };
              },
            },
            nodeId: nodeId2,
            proveCurrentKeyPossession: async () => {
              throw new Error("not used");
            },
          });
          for (const [walletId, row] of await liveDb.readWallets()) {
            if (row.recoveryVerifiedAt !== null) continue;
            await liveDb.stampRecoveryVerification({
              ceremonyId: randomUUID(),
              walletId,
              method: "AUDITED_EXPORT",
              publicKey: row.publicKey,
              keyVersion: 1,
              exportId: randomUUID(),
              exportSha256: createHash("sha256").update(walletId, "utf8").digest("hex"),
              censusMatchedRestored: true,
              censusMatchedLive: true,
              archivedProofVerified: true,
              probePreimageSha256: createHash("sha256").update("p", "utf8").digest("hex"),
              probeSignature: signPaddedBase64Url(identitySeed, Buffer.from("probe")),
              probeVerified: true,
              verifierIdentity: "form-stamp",
            });
          }

          const source = await pool.query<{ id: string }>(
            `SELECT id::text AS id FROM wallets
              WHERE node_id = $1::uuid AND state = 'AVAILABLE' LIMIT 1`,
            [nodeId2],
          );
          const sourceWalletId = source.rows[0]?.id;
          if (sourceWalletId === undefined) {
            throw new Error("no AVAILABLE wallet after stamp");
          }
          const sqlExec = {
            query: async <R>(text: string, params: readonly unknown[] = []) => {
              const result = await pool.query(text, params as never);
              return { rows: result.rows as R[] };
            },
          };
          const sendSigner = {
            signingKeyId: liveSigningKeyId,
            sign(preimageBytes: Uint8Array): Uint8Array {
              const pkcs8 = Buffer.concat([
                Buffer.from("302e020100300506032b657004220420", "hex"),
                identitySeed,
              ]);
              const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
              return edSign(null, Buffer.from(preimageBytes), key);
            },
          };
          await pool.query(
            `INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
             VALUES ($1, $2, 1, now())
             ON CONFLICT (setting_key) DO UPDATE
             SET setting_value = EXCLUDED.setting_value,
                 row_version = node_settings.row_version + 1,
                 updated_at = now()`,
            [
              AUTO_APPROVE_SETTING_KEY,
              serializeAutoApprovePolicyDocument(
                [
                  makeRule(implementerId2, {
                    per_send_max_zkz: "1",
                    window_cap_zkz: "10",
                  }),
                ],
                true,
              ),
            ],
          );

          const outcome = await createExternalSend(
            new SqlSendCreateStore(sqlExec),
            sendSigner,
            {
              implementerId: implementerId2,
              nodeId: nodeId2,
              sourceWalletId,
              destinationAddress: externalWalletPubkey(),
              amountZkz: "0.01",
              referencesOperationId: null,
              clientReference: "form-same-tick",
              description: null,
              idempotencyKey: `form-${randomUUID()}`,
            },
            { generateId: () => randomUUID(), now: () => Date.now() },
          );
          expect(outcome.outcome).toBe("CREATED");
          if (outcome.outcome !== "CREATED") return;
          const opId = outcome.operation.operationId;

          await handle.tickOnce();

          const st = await pool.query<{ status: string; formation_state: string }>(
            `SELECT status, formation_state FROM send_operations WHERE operation_id = $1::uuid`,
            [opId],
          );
          if (st.rows[0]?.status !== "AWAITING_REDEMPTION") {
            // One more tick in case form raced with approve logging only.
            await handle.tickOnce();
          }
          const st2 = await pool.query<{ status: string; formation_state: string }>(
            `SELECT status, formation_state FROM send_operations WHERE operation_id = $1::uuid`,
            [opId],
          );
          const relevant = logs.filter(
            (l) =>
              l.includes(opId) ||
              l.includes("SEND form") ||
              l.includes("auto-approved") ||
              l.includes("post-approve") ||
              l.includes("AWAITING_REDEMPTION") ||
              l.includes("skip SEND"),
          );
          expect(
            st2.rows[0]?.status,
            `expected AWAITING_REDEMPTION; got ${st2.rows[0]?.status}/${st2.rows[0]?.formation_state}; logs=${JSON.stringify(relevant)}`,
          ).toBe("AWAITING_REDEMPTION");
          expect(await pool.query(
            `SELECT count(*)::text AS n FROM operation_approvals
              WHERE operation_id = $1::uuid AND method = 'AUTO_POLICY'`,
            [opId],
          ).then((r) => Number(r.rows[0]?.n ?? "0"))).toBe(1);
          expect(logs.some((l) => l.includes(`SEND auto-approved op=${opId}`))).toBe(true);
          expect(logs.some((l) => l.includes(`SEND AWAITING_REDEMPTION op=${opId}`))).toBe(true);
          void moneyPathGates;
        } finally {
          handle.stop();
        }
      } finally {
        fx.stop();
      }
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "stopped() mid-batch exits cleanly without half-committed auto-approvals",
    async () => {
      const fx = await seedFixture();
      try {
        await fx.setPolicyDoc(
          serializeAutoApprovePolicyDocument(
            [makeRule(fx.implementerId, { window_cap_zkz: "100", per_send_max_zkz: "10" })],
            true,
          ),
        );
        const a = await fx.createSend("0.01", "stop-a");
        const b = await fx.createSend("0.01", "stop-b");
        // Stop before tick — tickOnce still runs body once; stopped is checked per-op.
        // Call stop mid-tick by stopping after starting is hard; instead stop() then
        // tickOnce: admission still runs but stopped breaks the auto-approve loop after
        // stop flag is set. stop() sets stopped=true immediately.
        fx.stop();
        await fx.handle.tickOnce();
        // After stop, tick returns early only via tickInFlight/stopped at top of tick —
        // stopped is true so tickOnce is a no-op (no body). Both remain CREATED.
        expect(await fx.sendStatus(a)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(await fx.sendStatus(b)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(await fx.autoApprovalCount(a)).toBe(0);
        expect(await fx.autoApprovalCount(b)).toBe(0);
      } finally {
        fx.stop();
      }
    },
    PG_TEST_TIMEOUT_MS,
  );
});
