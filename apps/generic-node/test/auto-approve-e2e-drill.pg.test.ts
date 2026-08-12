// ZTR-1241: end-to-end drill for auto-approved external sends across Route 2
// (public intake → operator approve → one-time claim → send → auto-approve →
// form) and Route 1 (operator-created implementer + credential + rule).
// Boundary probes: over-cap, halt, disable/re-enable, wallet-in-flight, one-time claim.
//
// Uses production ports over a disposable PG (same shape as auto-approve-worker.pg.test.ts).
// HTTP handlers for Route 2 are exercised via handleCreate/GetIntegrationRequest;
// send create + money-worker tick cover the money path. The node never submits.

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
  CredentialService,
  createExternalSend,
  createSqlAutoApprovePolicy,
  createSqlImplementerRegistry,
  createSqlIntegrationRequestStore,
  createSqlRecoveryLiveDatabase,
  createSqlSignerAuditLog,
  deriveRootKey,
  ensureActiveNodeSigningKey,
  EncryptedWalletKeyStore,
  GENESIS_PROJECTION,
  handleCreateIntegrationRequest,
  handleGetIntegrationRequest,
  InMemoryVaultAccessAuditLog,
  migrateLeaseFoundation,
  PublicSqlIntegrationRequestStore,
  serializeAutoApprovePolicyDocument,
  SqlCredentialStore,
  SqlSendCreateStore,
  toBase64UrlPadded,
  type AutoApproveRule,
  type NodeEventSigner,
  type PipelineContext,
  type SendFormationObserver,
  type SignerBoundaryDeps,
  VaultSqlStore,
  _resetIntegrationRequestRateLimitForTests,
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
import { registerPgRequiredGuard } from "../../../packages/node-core/test/pg-required-guard.js";

const PG_TEST_TIMEOUT_MS = 240_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const MASTER = "e2e-auto-approve-master-key-32b!!!!!!!!";

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

function pipelineCtx(
  method: "POST" | "GET",
  path: string,
  body: unknown,
  headers: Record<string, string | undefined> = {},
): PipelineContext {
  return {
    requestId: randomUUID(),
    request: {
      method,
      path,
      rawBody: new Uint8Array(),
      headers,
      query: {},
    },
    routeSchema: {
      method,
      path,
      requiresIdempotencyKey: false,
    },
    parsedBody: body,
  };
}

let e2eSchemaReady = false;

describe.skipIf(!PG_AVAILABLE)("auto-approve e2e drill (disposable PG)", () => {
  const dbName = `auto_approve_e2e_${process.pid}_${Date.now()}`;
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
    e2eSchemaReady = true;
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = prevDatabaseUrl;
    await pool?.end().catch(() => {});
    await dropTestDatabase(dbName).catch(() => {});
  }, PG_TEST_TIMEOUT_MS);

  async function seedArmedNode(label: string) {
    const nodeId = randomUUID();
    const identitySeed = randomBytes(32);
    const identityPublicKey = publicKeyFromSeed(identitySeed);
    const signingKeyId = randomUUID();

    await ensureNodeRow(pool, {
      nodeId,
      displayName: label,
      identityPublicKey,
    });
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

    const rootKey = deriveRootKey(`${MASTER}-${label}`, VAULT_ROOT_KDF_SALT);
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

    let haltBlocksSend = false;
    const moneyPathGates = {
      assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: async () => {},
      assertHaltAdmitsKind: (kind: string) => {
        if (haltBlocksSend && kind === "SEND_EXTERNAL") {
          throw new Error("halt refuses SEND_EXTERNAL (e2e)");
        }
      },
    };

    const logs: string[] = [];
    const signerDeps: SignerBoundaryDeps = {
      leadership: { held: true },
      leaseReader: createSqlLeaseReader(pool),
      vaultSigner: createPoolVaultSigner({ pool, vault, nodeId }),
      auditLog: createSqlSignerAuditLog(async (text, values) => {
        const result = await pool.query(text, values as unknown[]);
        return result.rows as Record<string, unknown>[];
      }),
      withSignTransaction: createSqlSignUnderLeaseTransaction(pool),
      assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: async () => {},
    };

    const fundedObserver: SendFormationObserver = {
      observeSource: async () => ({
        kind: "VERIFIED",
        observationId: randomUUID(),
        projection: {
          role: "sender",
          S: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
          P: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
          B: "100",
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
        nodeId,
        ownerInstanceId: nodeId,
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

    // Mint / backfill free wallets for concurrent unsettled sends.
    await handle.tickOnce();
    {
      const minted = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM wallets WHERE node_id = $1::uuid`,
        [nodeId],
      );
      const have = Number(minted.rows[0]?.n ?? "0");
      if (have < 24) {
        for (let i = have; i < 24; i += 1) {
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
    for (const [walletId, row] of await liveDb.readWallets()) {
      if (row.recoveryVerifiedAt !== null) continue;
      await liveDb.stampRecoveryVerification({
        ceremonyId: randomUUID(),
        walletId,
        method: "AUDITED_EXPORT",
        publicKey: row.publicKey,
        keyVersion: 1,
        exportId: randomUUID(),
        exportSha256: createHash("sha256").update(`e2e|${walletId}`, "utf8").digest("hex"),
        censusMatchedRestored: true,
        censusMatchedLive: true,
        archivedProofVerified: true,
        probePreimageSha256: createHash("sha256").update("probe", "utf8").digest("hex"),
        probeSignature: signPaddedBase64Url(identitySeed, Buffer.from("probe")),
        probeVerified: true,
        verifierIdentity: `e2e-stamp-${label}`,
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

    async function createSend(input: {
      readonly implementerId: string;
      readonly amountZkz: string;
      readonly idemSuffix: string;
      readonly sourceWalletId?: string;
    }) {
      const sourceWalletId = input.sourceWalletId ?? (await pickSourceWallet());
      return createExternalSend(
        sendStore,
        sendSigner,
        {
          implementerId: input.implementerId,
          nodeId,
          sourceWalletId,
          destinationAddress: externalWalletPubkey(),
          amountZkz: input.amountZkz,
          referencesOperationId: null,
          clientReference: `e2e-${input.idemSuffix}`,
          description: null,
          idempotencyKey: `e2e-send-${input.idemSuffix}-${randomUUID()}`,
        },
        { generateId: () => randomUUID(), now: () => Date.now() },
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

    async function autoApprovalRow(operationId: string) {
      const r = await pool.query<{ method: string; n: string }>(
        `SELECT method, count(*)::text AS n FROM operation_approvals
          WHERE operation_id = $1::uuid
          GROUP BY method`,
        [operationId],
      );
      return r.rows;
    }

    async function autoAuditRow(operationId: string) {
      const r = await pool.query<{
        actor_kind: string;
        action: string;
        n: string;
      }>(
        `SELECT actor_kind, action, count(*)::text AS n FROM audit_log
          WHERE operation_id = $1::uuid AND action = $2
          GROUP BY actor_kind, action`,
        [operationId, AUTO_APPROVE_APPLIED_ACTION],
      );
      return r.rows;
    }

    async function transferCodeText(operationId: string): Promise<string | null> {
      const r = await pool.query<{ transfer_code_text: string | null }>(
        `SELECT transfer_code_text FROM external_send_partials
          WHERE operation_id = $1::uuid`,
        [operationId],
      );
      return r.rows[0]?.transfer_code_text ?? null;
    }

    async function awaitAwaitingRedemption(operationId: string, ticks = 3): Promise<void> {
      for (let i = 0; i < ticks; i += 1) {
        await handle.tickOnce();
        const st = await sendStatus(operationId);
        if (st.status === "AWAITING_REDEMPTION") return;
      }
      const st = await sendStatus(operationId);
      const relevant = logs.filter(
        (l) =>
          l.includes(operationId) ||
          l.includes("auto-approved") ||
          l.includes("SEND form") ||
          l.includes("AWAITING_REDEMPTION") ||
          l.includes("skip SEND"),
      );
      throw new Error(
        `expected AWAITING_REDEMPTION for ${operationId}; got ${st.status}/${st.formation}; logs=${JSON.stringify(relevant)}`,
      );
    }

    const policyPort = createSqlAutoApprovePolicy(pool);
    const adminIrStore = createSqlIntegrationRequestStore(sqlExec);
    const implementerRegistry = createSqlImplementerRegistry(sqlExec);
    const credentialService = new CredentialService(new SqlCredentialStore(pool, nodeId));

    const publicIrStore = new PublicSqlIntegrationRequestStore(sqlExec, async (body) => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const txSql = {
          query: async <R extends Record<string, unknown> = Record<string, unknown>>(
            text: string,
            params?: readonly unknown[],
          ) => {
            const result = await client.query(text, params as never);
            return { rows: result.rows as R[] };
          },
        };
        const out = await body(txSql);
        await client.query("COMMIT");
        return out;
      } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    });

    return {
      nodeId,
      handle,
      logs,
      set haltBlocksSend(v: boolean) {
        haltBlocksSend = v;
      },
      createSend,
      pickSourceWallet,
      sendStatus,
      autoApprovalRow,
      autoAuditRow,
      transferCodeText,
      awaitAwaitingRedemption,
      policyPort,
      adminIrStore,
      implementerRegistry,
      credentialService,
      publicIrStore,
      stop: () => handle.stop(),
    };
  }

  it(
    "Route 2 spine + boundary probes: intake → tightened approve → claim once → auto-approve form; over-cap/halt/disable/wallet-in-flight",
    async () => {
      _resetIntegrationRequestRateLimitForTests();
      const fx = await seedArmedNode("route2");
      try {
        // 1. Platform POSTs integration request with proposed rule (cap 100 / 288h).
        const proposed = {
          rule_id: "platform-proposed",
          per_send_max_zkz: "0.001",
          per_send_min_zkz: null,
          window_hours: 288,
          window_cap_zkz: "100",
          expires_at: null,
        };
        const createRes = await handleCreateIntegrationRequest(
          pipelineCtx("POST", "/v1/integration-requests", {
            display_name: "E2E Rewards Platform",
            requested_scopes: ["send:create", "send:read"],
            proposed_rule: proposed,
          }),
          {
            store: fx.publicIrStore,
            nodeId: fx.nodeId,
            sourceIp: "10.42.0.1",
          },
        );
        expect(createRes.ok).toBe(true);
        if (!createRes.ok) return;
        expect(createRes.status).toBe(201);
        const created = JSON.parse(createRes.body) as {
          request_id: string;
          claim_token: string;
        };
        expect(created.claim_token.startsWith("irq_")).toBe(true);

        const pending = await fx.adminIrStore.get(created.request_id);
        expect(pending?.status).toBe("PENDING");
        expect(pending?.row_version).toBe(1);
        const proposedStored = JSON.parse(pending!.proposed_rule_json) as {
          window_cap_zkz: string;
        };
        expect(proposedStored.window_cap_zkz).toBe("100");

        // 2. Operator approves with TIGHTENED caps (50 per 288h) — operator values bind.
        const impl = await fx.implementerRegistry.create({
          name: pending!.display_name,
          actorId: randomUUID(),
          nodeId: fx.nodeId,
        });
        const operatorRule: AutoApproveRule = {
          rule_id: "operator-tightened",
          implementer_id: impl.id,
          per_send_max_zkz: "0.001",
          per_send_min_zkz: null,
          window_hours: 288,
          window_cap_zkz: "50",
          expires_at: null,
          enabled: true,
        };
        const approvedRuleJson = JSON.stringify(operatorRule);
        await fx.policyPort.setPolicy!(
          serializeAutoApprovePolicyDocument([operatorRule], true),
          { actorId: randomUUID(), nodeId: fx.nodeId },
        );
        const approved = await fx.adminIrStore.approve({
          id: created.request_id,
          nodeId: fx.nodeId,
          expectedRowVersion: pending!.row_version,
          approvedRuleJson,
          implementerId: impl.id,
          decidedBy: randomUUID(),
          actorId: randomUUID(),
        });
        expect(approved.status).toBe("APPROVED");
        expect(JSON.parse(approved.approved_rule_json!).window_cap_zkz).toBe("50");
        expect(JSON.parse(approved.approved_rule_json!).implementer_id).toBe(impl.id);

        const livePolicy = await fx.policyPort.getPolicy();
        expect(livePolicy.status).toBe("enabled");
        if (livePolicy.status === "enabled") {
          expect(livePolicy.rules).toHaveLength(1);
          expect(livePolicy.rules[0]!.window_cap_zkz).toBe("50");
          expect(livePolicy.rules[0]!.implementer_id).toBe(impl.id);
        }

        // 3. Platform claims the key once.
        const claimFirst = await handleGetIntegrationRequest(
          pipelineCtx(
            "GET",
            "/v1/integration-requests/:id",
            null,
            { authorization: `Bearer ${created.claim_token}` },
          ),
          {
            store: fx.publicIrStore,
            nodeId: fx.nodeId,
            sourceIp: "10.42.0.1",
          },
          created.request_id,
        );
        expect(claimFirst.ok).toBe(true);
        if (!claimFirst.ok) return;
        const claimBody = JSON.parse(claimFirst.body) as {
          status: string;
          api_key?: string;
          implementer_id?: string;
          approved_rule?: { window_cap_zkz: string };
        };
        expect(claimBody.status).toBe("CLAIMED");
        expect(claimBody.api_key?.startsWith("ik_")).toBe(true);
        expect(claimBody.implementer_id).toBe(impl.id);
        expect(claimBody.approved_rule?.window_cap_zkz).toBe("50");
        const apiKey = claimBody.api_key!;
        // Credential is durable; plaintext key is never re-readable after claim.
        void apiKey;

        // One-time claim: second GET is status-only (no api_key).
        const claimSecond = await handleGetIntegrationRequest(
          pipelineCtx(
            "GET",
            "/v1/integration-requests/:id",
            null,
            { authorization: `Bearer ${created.claim_token}` },
          ),
          {
            store: fx.publicIrStore,
            nodeId: fx.nodeId,
            sourceIp: "10.42.0.1",
          },
          created.request_id,
        );
        expect(claimSecond.ok).toBe(true);
        if (!claimSecond.ok) return;
        const claim2 = JSON.parse(claimSecond.body) as {
          status: string;
          api_key?: string;
        };
        expect(claim2.status).toBe("CLAIMED");
        expect(claim2.api_key).toBeUndefined();

        // 4. Happy path send within caps → AUTO_POLICY + SYSTEM audit → AWAITING_REDEMPTION.
        //    Transfer code durable on partial; node never submits.
        const okOutcome = await fx.createSend({
          implementerId: impl.id,
          amountZkz: "0.001",
          idemSuffix: "ok",
        });
        expect(okOutcome.outcome).toBe("CREATED");
        if (okOutcome.outcome !== "CREATED") return;
        const okId = okOutcome.operation.operationId;

        await fx.awaitAwaitingRedemption(okId);
        expect(await fx.autoApprovalRow(okId)).toEqual([
          expect.objectContaining({ method: "AUTO_POLICY", n: "1" }),
        ]);
        expect(await fx.autoAuditRow(okId)).toEqual([
          expect.objectContaining({
            actor_kind: "SYSTEM",
            action: AUTO_APPROVE_APPLIED_ACTION,
            n: "1",
          }),
        ]);
        const code = await fx.transferCodeText(okId);
        expect(typeof code).toBe("string");
        expect((code ?? "").length).toBeGreaterThan(8);
        expect(fx.logs.some((l) => l.includes(`SEND auto-approved op=${okId}`))).toBe(true);
        expect(fx.logs.some((l) => l.includes(`SEND AWAITING_REDEMPTION op=${okId}`))).toBe(
          true,
        );
        // Formation log pins the custody rule: node never submits SEND_EXTERNAL.
        expect(fx.logs.some((l) => l.includes("node never submits"))).toBe(true);

        // 5a. wallet-in-flight: second concurrent send from the same source wallet refused.
        const inFlightWallet = (
          await pool.query<{ source_wallet_id: string }>(
            `SELECT source_wallet_id::text AS source_wallet_id
               FROM send_operations WHERE operation_id = $1::uuid`,
            [okId],
          )
        ).rows[0]!.source_wallet_id;
        const inflight = await fx.createSend({
          implementerId: impl.id,
          amountZkz: "0.001",
          idemSuffix: "inflight",
          sourceWalletId: inFlightWallet,
        });
        expect(inflight.outcome).toBe("REJECTED");
        if (inflight.outcome === "REJECTED") {
          expect(inflight.code).toBe("wallet_in_flight");
        }

        // 5b. Over-cap parks CREATED (manual queue) — window already spent 0.001, cap 50
        //     still admits small amounts; tighten window_cap to force over-cap.
        await fx.policyPort.setPolicy!(
          serializeAutoApprovePolicyDocument(
            [
              {
                ...operatorRule,
                window_cap_zkz: "0.001", // already fully spent by ok send
              },
            ],
            true,
          ),
          { actorId: randomUUID(), nodeId: fx.nodeId },
        );
        const overOutcome = await fx.createSend({
          implementerId: impl.id,
          amountZkz: "0.001",
          idemSuffix: "over",
        });
        expect(overOutcome.outcome).toBe("CREATED");
        if (overOutcome.outcome !== "CREATED") return;
        const overId = overOutcome.operation.operationId;
        await fx.handle.tickOnce();
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(overId)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(await fx.autoApprovalRow(overId)).toEqual([]);

        // Restore a usable window for halt/disable probes.
        await fx.policyPort.setPolicy!(
          serializeAutoApprovePolicyDocument(
            [{ ...operatorRule, window_cap_zkz: "50", per_send_max_zkz: "1" }],
            true,
          ),
          { actorId: randomUUID(), nodeId: fx.nodeId },
        );

        // 5c. Engage halt ⇒ nothing auto-approves.
        fx.haltBlocksSend = true;
        const haltOutcome = await fx.createSend({
          implementerId: impl.id,
          amountZkz: "0.001",
          idemSuffix: "halt",
        });
        expect(haltOutcome.outcome).toBe("CREATED");
        if (haltOutcome.outcome !== "CREATED") return;
        const haltId = haltOutcome.operation.operationId;
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(haltId)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(await fx.autoApprovalRow(haltId)).toEqual([]);

        // 5d. Disable policy ⇒ nothing auto-approves (even with halt clear).
        fx.haltBlocksSend = false;
        await fx.policyPort.setPolicy!(
          serializeAutoApprovePolicyDocument(
            [{ ...operatorRule, window_cap_zkz: "50", per_send_max_zkz: "1" }],
            false,
          ),
          { actorId: randomUUID(), nodeId: fx.nodeId },
        );
        const offOutcome = await fx.createSend({
          implementerId: impl.id,
          amountZkz: "0.001",
          idemSuffix: "off",
        });
        expect(offOutcome.outcome).toBe("CREATED");
        if (offOutcome.outcome !== "CREATED") return;
        const offId = offOutcome.operation.operationId;
        await fx.handle.tickOnce();
        expect(await fx.sendStatus(offId)).toEqual({
          status: "CREATED",
          formation: "APPROVAL_PENDING",
        });
        expect(await fx.autoApprovalRow(offId)).toEqual([]);
        expect(fx.logs.some((l) => l.includes("policy=disabled"))).toBe(true);

        // 5e. Re-enable + halt already clear ⇒ previously parked halt/off/over
        //     auto-approve where window/rule admits (haltId + offId within restored cap).
        await fx.policyPort.setPolicy!(
          serializeAutoApprovePolicyDocument(
            [{ ...operatorRule, window_cap_zkz: "50", per_send_max_zkz: "1" }],
            true,
          ),
          { actorId: randomUUID(), nodeId: fx.nodeId },
        );
        await fx.awaitAwaitingRedemption(haltId);
        expect(await fx.autoApprovalRow(haltId)).toEqual([
          expect.objectContaining({ method: "AUTO_POLICY", n: "1" }),
        ]);
        await fx.awaitAwaitingRedemption(offId);
        expect(await fx.autoApprovalRow(offId)).toEqual([
          expect.objectContaining({ method: "AUTO_POLICY", n: "1" }),
        ]);
        // Over-cap send still CREATED if window already spent past 0.001 remaining —
        // after ok+halt+off spend, remaining room under 50 still admits overId if we
        // re-evaluate with restored cap 50. overId amount 0.001 under 50 → should clear.
        await fx.awaitAwaitingRedemption(overId);
        expect(await fx.autoApprovalRow(overId)).toEqual([
          expect.objectContaining({ method: "AUTO_POLICY", n: "1" }),
        ]);
      } finally {
        fx.stop();
      }
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "Route 1 variant: operator creates implementer + key + rule; send auto-approves to AWAITING_REDEMPTION",
    async () => {
      const fx = await seedArmedNode("route1");
      try {
        const impl = await fx.implementerRegistry.create({
          name: "Operator Direct Integration",
          actorId: randomUUID(),
          nodeId: fx.nodeId,
        });
        const issued = await fx.credentialService.create(impl.id, [
          "send:create",
          "send:read",
        ]);
        expect(issued.raw_key.startsWith("ik_")).toBe(true);

        const rule: AutoApproveRule = {
          rule_id: "route1-direct",
          implementer_id: impl.id,
          per_send_max_zkz: "0.01",
          per_send_min_zkz: null,
          window_hours: 24,
          window_cap_zkz: "1",
          expires_at: null,
          enabled: true,
        };
        await fx.policyPort.setPolicy!(serializeAutoApprovePolicyDocument([rule], true), {
          actorId: randomUUID(),
          nodeId: fx.nodeId,
        });

        // Credential is what the platform would present as Bearer; send path binds
        // implementer_id from the validated credential (createExternalSend takes it).
        void issued.raw_key;

        const outcome = await fx.createSend({
          implementerId: impl.id,
          amountZkz: "0.01",
          idemSuffix: "route1",
        });
        expect(outcome.outcome).toBe("CREATED");
        if (outcome.outcome !== "CREATED") return;
        const opId = outcome.operation.operationId;

        await fx.awaitAwaitingRedemption(opId);
        expect(await fx.autoApprovalRow(opId)).toEqual([
          expect.objectContaining({ method: "AUTO_POLICY", n: "1" }),
        ]);
        expect(await fx.autoAuditRow(opId)).toEqual([
          expect.objectContaining({
            actor_kind: "SYSTEM",
            action: AUTO_APPROVE_APPLIED_ACTION,
            n: "1",
          }),
        ]);
        const code = await fx.transferCodeText(opId);
        expect(typeof code).toBe("string");
        expect((code ?? "").length).toBeGreaterThan(8);

        // Setting key present under canonical name.
        const setting = await pool.query<{ setting_value: string }>(
          `SELECT setting_value FROM node_settings WHERE setting_key = $1`,
          [AUTO_APPROVE_SETTING_KEY],
        );
        expect(setting.rows[0]?.setting_value).toContain(impl.id);
        expect(setting.rows[0]?.setting_value).toContain("route1-direct");
      } finally {
        fx.stop();
      }
    },
    PG_TEST_TIMEOUT_MS,
  );
});

// Guard after live describe so beforeAll sets e2eSchemaReady before this it runs.
registerPgRequiredGuard({
  name: "auto-approve e2e drill (disposable PG)",
  databaseUrl: process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL,
  isReady: () => e2eSchemaReady,
});
