import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { Client, Pool } from "pg";

import {
  SqlProofBodyStore,
  handleGetVerificationMaterial,
  persistProofBody,
  type ProofBodyStore,
  type ReportingRateLimiter,
  type VaultAccessAuditLog,
  type VerificationAccessWindowRecord,
} from "@zucoins/node-core";
import {
  SqlReportingRateLimiter,
  SqlVerificationAccessStore,
  SqlVaultAccessAuditLog,
  createPoolSqlExecutor,
  createPoolSqlTransactionRunner,
} from "../../src/reporting/durable-security-ports.js";
import { createProductionRouteSurface } from "../../src/full-http-mount.js";
import { createVerificationMaterialSource } from "../../src/reporting/live-reporting-reads.js";

/** Non-zero 32-byte test vault root for SqlAdminUserStore composition (ZTR-1134 B3). */
const ZTR_1134_TEST_VAULT_ROOT = Buffer.alloc(32, 0xa7);

const HOST = process.env.PGHOST ?? "127.0.0.1";
const PORT = Number(process.env.PGPORT ?? "5432");
const USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const PASSWORD = process.env.PGPASSWORD;
const has = (bin: string): boolean => {
  try { execFileSync(bin, bin === "pg_isready" ? ["-q"] : ["--version"], { stdio: "ignore" }); return true; }
  catch { return false; }
};
const PG_AVAILABLE = has("pg_isready");
const adminConfig = (database = "postgres") => ({ host: HOST, port: PORT, user: USER, password: PASSWORD, database });
const urlFor = (database: string) => `postgres://${encodeURIComponent(USER)}${PASSWORD ? `:${encodeURIComponent(PASSWORD)}` : ""}@${HOST}:${PORT}/${database}`;

const fakePool = { query: async () => ({ rows: [] }), connect: async () => ({}) } as never;
const fakeRate: ReportingRateLimiter = { consume: async () => true };
const fakeProof = { findByPathProof: async () => [] } as unknown as ProofBodyStore;
const fakeAccess = {} as SqlVerificationAccessStore;
const fakeAudit: VaultAccessAuditLog = { record: async () => {} };

function completeConfig(overrides: Record<string, unknown> = {}) {
  return {
    nodeId: randomUUID(), pool: fakePool, env: { NODE_ENV: "production" },
    rateLimiter: fakeRate, proofBodyStore: fakeProof, verificationAccessStore: fakeAccess,
    vaultAccessAuditLog: fakeAudit,
    // Required when defaulting SqlAdminUserStore (ZTR-1134); production always supplies it.
    vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
    ...overrides,
  } as never;
}

describe("production composition hard-stop", () => {
  for (const key of ["rateLimiter", "proofBodyStore", "verificationAccessStore", "vaultAccessAuditLog"] as const) {
    it(`refuses production composition when ${key} is absent`, () => {
      const config = completeConfig();
      delete (config as Record<string, unknown>)[key];
      expect(() => createProductionRouteSurface(config)).toThrow(new RegExp(key));
    });
  }
  it("retains every injected durable port", () => {
    const surface = createProductionRouteSurface(completeConfig());
    expect(surface.reportingRateLimiter).toBe(fakeRate);
    expect(surface.proofBodyStore).toBe(fakeProof);
    expect(surface.verificationAccessStore).toBe(fakeAccess);
    expect(surface.vaultAccessAuditLog).toBe(fakeAudit);
  });

  it("propagates SQL failure from every durable security port", async () => {
    const failure = new Error("db down");
    const brokenPool = { query: async () => { throw failure; } } as never;
    const nodeId = randomUUID();
    const operationId = randomUUID();
    const proof = new SqlProofBodyStore(createPoolSqlExecutor(brokenPool));

    await expect(new SqlReportingRateLimiter(brokenPool, 60_000, 3).consume(nodeId, "principal", 0)).rejects.toBe(failure);
    await expect(proof.findByPathProofAndIndex(randomUUID(), 0)).rejects.toBe(failure);
    await expect(new SqlVerificationAccessStore(brokenPool).read(operationId, 0)).rejects.toBe(failure);
    await expect(new SqlVaultAccessAuditLog(brokenPool, nodeId).record({
      walletId: randomUUID(), keyVersion: 1, purpose: "TEST", outcome: "OPEN_OK", at: new Date(0),
    })).rejects.toBe(failure);
  });

  it("production verification handler uses the injected proof and access ports", async () => {
    const operationId = randomUUID();
    const implementerId = randomUUID();
    const pathId = randomUUID();
    const query = vi.fn(async (text: string) => {
      if (text.includes("FROM proof_channel_candidate_bodies")) {
        throw new Error("parallel proof-body SQL projection must not be used");
      }
      if (text.includes("FROM operations o")) return { rows: [{ id: operationId, implementer_id: implementerId, kind: "RECEIVE_EXTERNAL", status: "RECEIVE_LANDED", verification_material_available_until_ms: 20_000, landed_attempt_no: 0 }] };
      if (text.includes("FROM operation_expected_artifacts")) return { rows: [{ signing_key_id: randomUUID(), preimage_text: "exact-preimage", preimage_sha256: "aa".repeat(32), signature: `${"A".repeat(86)}==` }] };
      if (text.includes("FROM lineage_path_proofs")) return { rows: [{ path_id: pathId, path_role: "RECEIVER", wallet_public_key: `${"B".repeat(43)}=`, verdict: "LANDED_COMPLETE_PATH", expected_step_2_signature: `${"C".repeat(86)}==`, fresh_head_step_2_signature: `${"D".repeat(86)}==`, fresh_head_completed_transaction_sha256: "bb".repeat(32) }] };
      return { rows: [] };
    });
    const proofRead = vi.fn(async () => [{ path_index: 0, step_2_signature: `${"D".repeat(86)}==`, p_signature: "", completed_transaction_sha256: "bb".repeat(32), completed_transaction_text: "EXACT-CANDIDATE" }]);
    const record: VerificationAccessWindowRecord = {
      id: randomUUID(), nodeId: randomUUID(), implementerId, operationId, status: "OPEN",
      nonceHash: "cc".repeat(32), issuedAtMs: 1_000, expiresAtMs: 20_000, revokedAtMs: null,
    };
    const accessRead = vi.fn(async (): Promise<VerificationAccessWindowRecord | null> => record);
    const source = createVerificationMaterialSource(
      { query } as never,
      { findByPathProof: proofRead } as unknown as ProofBodyStore,
      { findByOperation: accessRead } as unknown as SqlVerificationAccessStore,
      () => 10_000,
    );
    const request = { requestId: randomUUID(), operationId, tenantId: implementerId, nowMs: 10_000 };
    const ok = await handleGetVerificationMaterial(request, source);
    expect(ok.status).toBe(200);
    expect(ok.body).toContain("EXACT-CANDIDATE");
    expect(proofRead).toHaveBeenCalledWith(pathId);
    expect(accessRead).toHaveBeenCalledWith(operationId, implementerId);

    accessRead.mockResolvedValueOnce(null);
    expect((await handleGetVerificationMaterial(request, source)).status).toBe(409);
    accessRead.mockResolvedValueOnce({ ...record, status: "REVOKED", revokedAtMs: 9_000 });
    expect((await handleGetVerificationMaterial(request, source)).status).toBe(410);
    accessRead.mockResolvedValueOnce({ ...record, expiresAtMs: 9_000 });
    expect((await handleGetVerificationMaterial(request, source)).status).toBe(410);
  });
});

describe.skipIf(!PG_AVAILABLE)("durable reporting security ports (real PostgreSQL)", () => {
  const db = `security_ports_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  let pool: Pool;
  const nodeId = randomUUID();
  const walletId = randomUUID();
  const implementerId = randomUUID();
  const registeredKeyId = randomUUID();

  beforeAll(async () => {
    const admin = new Client(adminConfig()); await admin.connect();
    try { await admin.query(`CREATE DATABASE ${db}`); } finally { await admin.end(); }
    pool = new Pool(adminConfig(db));
    process.env.DATABASE_URL = urlFor(db);
    const { runMigrationsOnPool } = await import("../../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });
    await pool.query("INSERT INTO nodes(id,display_name,identity_public_key) VALUES ($1,'security-ports',$2)", [nodeId, `${"A".repeat(43)}=`]);
    await pool.query("INSERT INTO wallets(id,node_id,public_key,key_origin,state) VALUES ($1,$2,$3,'node_generated','AVAILABLE')", [walletId, nodeId, `${"B".repeat(43)}=`]);
    await pool.query("INSERT INTO implementers(id,name) VALUES ($1,'security-ports-implementer')", [implementerId]);
    await pool.query(
      "INSERT INTO implementer_reporting_keys(id,node_id,implementer_id,public_key,registered_at) VALUES ($1,$2,$3,$4,now())",
      [registeredKeyId, nodeId, implementerId, `${"K".repeat(43)}=`],
    );
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    const admin = new Client(adminConfig()); await admin.connect();
    try { await admin.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1", [db]); await admin.query(`DROP DATABASE IF EXISTS ${db}`); }
    finally { await admin.end(); }
  });

  it("shares one atomic fixed-window limit across instances and restart", async () => {
    const a = new SqlReportingRateLimiter(pool, 60_000, 3);
    const b = new SqlReportingRateLimiter(pool, 60_000, 3);
    const at = 1_800_000;
    const results = await Promise.all([a.consume(nodeId, registeredKeyId, at), b.consume(nodeId, registeredKeyId, at), a.consume(nodeId, registeredKeyId, at), b.consume(nodeId, registeredKeyId, at)]);
    expect(results.filter(Boolean)).toHaveLength(3);
    expect(await new SqlReportingRateLimiter(pool, 60_000, 3).consume(nodeId, registeredKeyId, at)).toBe(false);
    expect(await b.consume(nodeId, registeredKeyId, at + 60_000)).toBe(true);
  });

  it("B1: unregistered principals never accumulate durable rows; registered principal stays at one row", async () => {
    const limiter = new SqlReportingRateLimiter(pool, 60_000, 3);
    const at = 3_600_000;
    for (let i = 0; i < 200; i += 1) {
      await limiter.consume(nodeId, randomUUID(), at);
    }
    const unregisteredCount = await pool.query("SELECT count(*)::int AS n FROM reporting_rate_limit_buckets WHERE principal != $1", [registeredKeyId]);
    expect(unregisteredCount.rows[0]?.n).toBe(0);

    await limiter.consume(nodeId, registeredKeyId, at);
    await limiter.consume(nodeId, registeredKeyId, at + 60_000);
    await limiter.consume(nodeId, registeredKeyId, at + 120_000);
    const registeredRows = await pool.query("SELECT count(*)::int AS n FROM reporting_rate_limit_buckets WHERE node_id = $1 AND principal = $2", [nodeId, registeredKeyId]);
    expect(registeredRows.rows[0]?.n).toBe(1);

    await limiter.consume(nodeId, registeredKeyId, at + 120_000);
    await limiter.consume(nodeId, registeredKeyId, at + 120_000);
    const over = await limiter.consume(nodeId, registeredKeyId, at + 120_000);
    expect(over).toBe(false);
    const stillOneRow = await pool.query("SELECT count(*)::int AS n FROM reporting_rate_limit_buckets WHERE node_id = $1 AND principal = $2", [nodeId, registeredKeyId]);
    expect(stillOneRow.rows[0]?.n).toBe(1);
  });

  it("C1: two racing window resets merge into one count, neither loses the other", async () => {
    const limiter = new SqlReportingRateLimiter(pool, 60_000, 3);
    const principal = randomUUID();
    await pool.query(
      "INSERT INTO implementer_reporting_keys(id,node_id,implementer_id,public_key,registered_at) VALUES ($1,$2,$3,$4,now())",
      [principal, nodeId, implementerId, `${"D".repeat(43)}=`],
    );
    const oldWindow = 9_000_000;
    const newWindow = oldWindow + 60_000;
    await limiter.consume(nodeId, principal, oldWindow);
    await limiter.consume(nodeId, principal, oldWindow);

    const [first, second] = await Promise.all([
      limiter.consume(nodeId, principal, newWindow),
      limiter.consume(nodeId, principal, newWindow),
    ]);
    expect(first).toBe(true);
    expect(second).toBe(true);

    const row = await pool.query<{ window_start_ms: string; request_count: string }>(
      "SELECT window_start_ms, request_count FROM reporting_rate_limit_buckets WHERE node_id = $1 AND principal = $2",
      [nodeId, principal],
    );
    expect(row.rows).toHaveLength(1);
    expect(Number(row.rows[0]?.window_start_ms)).toBe(newWindow);
    expect(Number(row.rows[0]?.request_count)).toBe(2);
  });

  it("persists exact proof bytes and access state across fresh port instances", async () => {
    const store = new SqlProofBodyStore(createPoolSqlExecutor(pool), createPoolSqlTransactionRunner(pool));
    const exact = "{\"z\":1,\"a\":\"é\"}";
    const row = {
      path_proof_id: randomUUID(), path_index: 0, source_kind: "PROOF_CHANNEL" as const,
      completed_transaction_text: exact, completed_transaction_sha256: "11".repeat(32),
      completed_transaction_octets: Buffer.byteLength(exact), wallet_role: "sender" as const,
      s_signature: `${"C".repeat(86)}==`, p_signature: "", b_amount: "0",
      inner_preimage_text: "{\"exact\":true}", inner_sha256: "22".repeat(32),
      step_1_signature: `${"D".repeat(86)}==`, step_2_signature: `${"E".repeat(86)}==`,
      verification_manifest_text: "{\"order\":[2,1]}", verification_manifest_sha256: "33".repeat(32),
      raw_bytes_sha256: "44".repeat(32), tenant_id: randomUUID(), operation_id: randomUUID(),
      idempotency_key: "idem-exact", persisted_at: new Date().toISOString(),
    };
    await store.insert(row);
    expect((await new SqlProofBodyStore(createPoolSqlExecutor(pool)).findByPathProofAndIndex(row.path_proof_id, 0))?.completed_transaction_text).toBe(exact);

    const access = new SqlVerificationAccessStore(pool);
    const accessId = randomUUID();
    await access.open({ id: accessId, nodeId, implementerId: randomUUID(), operationId: row.operation_id, nonceHash: "55".repeat(32), issuedAt: new Date(0), expiresAt: new Date(60_000) });
    expect((await new SqlVerificationAccessStore(pool).read(row.operation_id, 30_000))?.status).toBe("OPEN");
    await access.revoke(row.operation_id, new Date(40_000));
    expect((await new SqlVerificationAccessStore(pool).read(row.operation_id, 30_000))?.status).toBe("REVOKED");
  });

  it("rolls back exact body and both sighting counters after every injected statement failure", async () => {
    const base = {
      path_proof_id: randomUUID(), path_index: 7, source_kind: "PROOF_CHANNEL" as const,
      completed_transaction_text: "exact", completed_transaction_sha256: "66".repeat(32),
      completed_transaction_octets: 5, wallet_role: "sender" as const,
      s_signature: `${"F".repeat(86)}==`, p_signature: "", b_amount: "1",
      inner_preimage_text: "inner", inner_sha256: "77".repeat(32),
      step_1_signature: `${"G".repeat(86)}==`, step_2_signature: `${"H".repeat(86)}==`,
      verification_manifest_text: "[]", verification_manifest_sha256: "88".repeat(32),
      raw_bytes_sha256: "99".repeat(32), tenant_id: randomUUID(), operation_id: randomUUID(),
      idempotency_key: "atomic", persisted_at: new Date().toISOString(),
    };
    for (const failAfter of [1, 2, 3]) {
      const row = { ...base, path_proof_id: randomUUID(), tenant_id: randomUUID(), operation_id: randomUUID() };
      const runner = {
        async transaction<T>(body: (sql: ReturnType<typeof createPoolSqlExecutor>) => Promise<T>): Promise<T> {
          const client = await pool.connect();
          let writes = 0;
          try {
            await client.query("BEGIN");
            const sql = {
              async query<R>(text: string, params: readonly unknown[] = []) {
                const result = await client.query(text, params as unknown[]);
                if (/^(INSERT INTO proof_channel_candidate_bodies|INSERT INTO proof_body_)/.test(text)) {
                  writes += 1;
                  if (writes === failAfter) throw new Error(`fault-after-${failAfter}`);
                }
                return { rows: result.rows as R[] };
              },
            };
            const result = await body(sql);
            await client.query("COMMIT");
            return result;
          } catch (error) {
            await client.query("ROLLBACK");
            throw error;
          } finally { client.release(); }
        },
      };
      const store = new SqlProofBodyStore(createPoolSqlExecutor(pool), runner);
      const rawBytes = new TextEncoder().encode(row.completed_transaction_text);
      await expect(persistProofBody(store, {
        accepted: {
          accepted: true,
          body: {
            path_index: row.path_index,
            source_kind: row.source_kind,
            completed_transaction_text: row.completed_transaction_text,
            completed_transaction_sha256: row.completed_transaction_sha256,
            completed_transaction_octets: row.completed_transaction_octets,
            wallet_role: row.wallet_role,
            s_signature: row.s_signature,
            p_signature: row.p_signature,
            b_amount: row.b_amount,
            inner_preimage_text: row.inner_preimage_text,
            inner_sha256: row.inner_sha256,
            step_1_signature: row.step_1_signature,
            step_2_signature: row.step_2_signature,
            verification_manifest_text: row.verification_manifest_text,
            verification_manifest_sha256: row.verification_manifest_sha256,
          },
          rawBytes,
          rawSha256: row.raw_bytes_sha256,
        },
        identity: {
          tenant_id: row.tenant_id,
          operation_id: row.operation_id,
          wallet_role: row.wallet_role,
        },
        path_proof_id: row.path_proof_id,
        idempotency_key: row.idempotency_key,
      })).rejects.toThrow(`fault-after-${failAfter}`);
      expect(await new SqlProofBodyStore(createPoolSqlExecutor(pool)).findByPathProofAndIndex(row.path_proof_id, row.path_index)).toBeNull();
      expect(await new SqlProofBodyStore(createPoolSqlExecutor(pool)).countSightingsBySlot(row.path_proof_id, row.path_index)).toBe(0);
      expect(await new SqlProofBodyStore(createPoolSqlExecutor(pool)).countSightingsByTenant(row.tenant_id)).toBe(0);
    }
  });

  it("persists secret-free vault access audit across fresh instances and propagates DB failure", async () => {
    const audit = new SqlVaultAccessAuditLog(pool, nodeId);
    await audit.record({ walletId, keyVersion: 7, purpose: "SEND_SIGN", outcome: "OPEN_OK", at: new Date(0) });
    const result = await pool.query("SELECT action, details_text FROM audit_log WHERE wallet_id=$1", [walletId]);
    expect(result.rows[0]).toEqual({ action: "VAULT_ACCESS", details_text: JSON.stringify({ key_version: 7, purpose: "SEND_SIGN", outcome: "OPEN_OK" }) });
    const fresh = new SqlVaultAccessAuditLog(pool, nodeId);
    await fresh.record({ walletId, keyVersion: 7, purpose: "RECOVERY", outcome: "AUTH_TAG_FAILURE", at: new Date(1) });
    expect((await pool.query("SELECT count(*)::int AS n FROM audit_log WHERE wallet_id=$1", [walletId])).rows[0].n).toBe(2);
    await expect(new SqlVaultAccessAuditLog({ query: async () => { throw new Error("db down"); } } as never, nodeId).record({ walletId, keyVersion: 1, purpose: "X", outcome: "OPEN_OK", at: new Date() })).rejects.toThrow("db down");
  });
});
