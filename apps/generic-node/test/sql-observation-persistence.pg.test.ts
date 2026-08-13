// Real-PostgreSQL proof for persistSqlObservation (ZTR-1127/1128/1132):
// - deferred observation_anomaly_pairing_complete commits paired rows
// - UNEXPLAINED_JUMP with no lease keeps observation+anomaly (no rollback)
// - REGRESSION quarantines wallet, preserves lease, blocks canAcquireNewLease
// - intentional mid-tx failure rolls back observation+anomaly together
//
// Connectivity: local psql -d postgres (same posture as node-core observation-stores).
// PG_REQUIRED=1 → hard FAIL when unreachable.

import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import { canAcquireNewLease } from "@zucoins/node-core";

import { persistSqlObservation } from "../src/money-workers/sql-observation-persistence.js";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../../../packages/node-core/src/schema");
const MAINTENANCE_DB = "postgres";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const NODE_ID = "b2540000-0000-4000-8000-0000000000aa";
const HEX = "a".repeat(64);
const WALLET_PK = `${"G".repeat(43)}=`;
const LEASE_ID = "44444444-4444-4444-8444-444444444444";
const OP_ID = "55555555-5555-4555-8555-555555555555";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

function runPsql(db: string, sql: string): PsqlOutcome {
  try {
    const stdout = execFileSync(
      "psql",
      ["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] },
    );
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? String(err) };
  }
}

function psqlMust(db: string, sql: string): string {
  const out = runPsql(db, sql);
  if (!out.ok) throw new Error(`psql failed: ${out.stderr || out.stdout}`);
  return out.stdout;
}

function applyFile(db: string, file: string): void {
  try {
    execFileSync(
      "psql",
      ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, file)],
      { encoding: "utf-8", timeout: 60_000, stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim()}`);
  }
}

const PG_AVAILABLE = runPsql(MAINTENANCE_DB, "SELECT 1").ok;
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

const fp = (label: string): string => createHash("sha256").update(label).digest("hex");
const sig = (ch: string): string => `${ch.repeat(86)}==`;

function headCapture(label: string, s: string, p: string) {
  return {
    parseResult: "VERIFIED_HEAD" as const,
    rawResponseBytes: new TextEncoder().encode(label),
    isGenesis: false,
    sSignature: s,
    pSignature: p,
    semanticFingerprint: fp(label),
  };
}

const emptyProjection = {
  walletRole: "sender" as const,
  bAmount: "1",
  innerPreimageText: null,
  step1Signature: null,
  step2Signature: null,
  completedTransactionText: null,
  completedTransactionSha256: null,
};

let assertionsRun = 0;

describeIfPg("persistSqlObservation real-PG pairing + quarantine", () => {
  const scratchDb = `obs_persist_${Date.now()}_${process.pid}`;
  let pool: Pool;
  let walletId: string;

  beforeAll(async () => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    // observation-ledger requires wallets(id). Extend after apply for quarantine surface.
    psqlMust(scratchDb, "CREATE TABLE wallets (id uuid PRIMARY KEY);");
    applyFile(scratchDb, "observation-ledger.sql");
    applyFile(scratchDb, "observation-anomaly-indexes.sql");
    applyFile(scratchDb, "observation-stores.sql");
    psqlMust(
      scratchDb,
      `
      CREATE TABLE nodes (id uuid PRIMARY KEY);
      ALTER TABLE wallets
        ADD COLUMN public_key text,
        ADD COLUMN state text NOT NULL DEFAULT 'AVAILABLE',
        ADD COLUMN quarantine_reason text;
      ALTER TABLE wallets
        ADD CONSTRAINT wallets_quarantine_reason_iff
          CHECK ((state = 'QUARANTINED') = (quarantine_reason IS NOT NULL));
      CREATE UNIQUE INDEX wallets_public_key_uidx ON wallets (public_key);
      CREATE TABLE wallet_active_leases (
        wallet_id uuid PRIMARY KEY REFERENCES wallets(id),
        membership_id uuid NOT NULL,
        operation_id uuid NOT NULL
      );
      CREATE TABLE operations (
        id uuid PRIMARY KEY,
        kind text NOT NULL DEFAULT 'RECEIVE_EXTERNAL',
        status text NOT NULL DEFAULT 'READY',
        attention_required boolean NOT NULL DEFAULT false,
        attention_reason text,
        source_wallet_id uuid,
        receiver_wallet_id uuid,
        row_version int NOT NULL DEFAULT 0,
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE TABLE audit_log (
        id uuid PRIMARY KEY,
        node_id uuid NOT NULL REFERENCES nodes(id),
        actor_kind text NOT NULL,
        actor_id uuid,
        action text NOT NULL,
        operation_id uuid,
        wallet_id uuid,
        details_text text NOT NULL,
        details_sha256 text NOT NULL,
        created_at timestamptz NOT NULL
      );
      `,
    );

    walletId = randomUUID();
    psqlMust(
      scratchDb,
      `
      INSERT INTO nodes (id) VALUES ('${NODE_ID}');
      INSERT INTO wallets (id, public_key, state) VALUES ('${walletId}', '${WALLET_PK}', 'PINNED');
      INSERT INTO operations (id, kind, status, receiver_wallet_id)
        VALUES ('${OP_ID}', 'RECEIVE_EXTERNAL', 'READY', '${walletId}');
      INSERT INTO wallet_active_leases (wallet_id, membership_id, operation_id)
        VALUES ('${walletId}', '${LEASE_ID}', '${OP_ID}');
      `,
    );

    pool = new Pool({ connectionString: `postgresql:///${scratchDb}` });
  }, 120_000);

  afterAll(async () => {
    if (!PG_AVAILABLE) return;
    await pool?.end().catch(() => {});
    runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  it("UNEXPLAINED_JUMP with no lease commits observation+anomaly pair under deferred guard", async () => {
    const pk = `${"H".repeat(43)}=`;
    await persistSqlObservation({
      pool,
      nodeId: NODE_ID,
      walletPublicKey: pk,
      endpointFingerprint: HEX,
      httpStatus: 200,
      capture: headCapture("first", sig("A"), ""),
      projection: emptyProjection,
    });
    const jump = await persistSqlObservation({
      pool,
      nodeId: NODE_ID,
      walletPublicKey: pk,
      endpointFingerprint: HEX,
      httpStatus: 200,
      capture: headCapture("jump", sig("Z"), sig("Y")),
      projection: emptyProjection,
    });
    expect(jump.relationship).toBe("UNEXPLAINED_JUMP");

    const nObs = psqlMust(
      scratchDb,
      `SELECT count(*) FROM gateway_observations WHERE wallet_public_key='${pk}';`,
    ).trim();
    const nAnom = psqlMust(
      scratchDb,
      `SELECT count(*) FROM observation_anomalies a
         JOIN gateway_observations o ON o.id = a.observation_id
        WHERE o.wallet_public_key='${pk}' AND a.kind='UNEXPLAINED_JUMP';`,
    ).trim();
    expect(nObs).toBe("2");
    expect(nAnom).toBe("1");
    const nextSeq = psqlMust(
      scratchDb,
      `SELECT next_wallet_seq FROM wallet_observation_cursors WHERE wallet_public_key='${pk}';`,
    ).trim();
    expect(nextSeq).toBe("3");
    assertionsRun += 1;
  });

  it("REGRESSION commits pair + quarantines wallet + preserves lease + canAcquireNewLease false", async () => {
    await persistSqlObservation({
      pool,
      nodeId: NODE_ID,
      walletPublicKey: WALLET_PK,
      endpointFingerprint: HEX,
      httpStatus: 200,
      capture: headCapture("r1", sig("A"), ""),
      projection: emptyProjection,
    });
    await persistSqlObservation({
      pool,
      nodeId: NODE_ID,
      walletPublicKey: WALLET_PK,
      endpointFingerprint: HEX,
      httpStatus: 200,
      capture: headCapture("r2", sig("B"), sig("A")),
      projection: emptyProjection,
    });
    const reg = await persistSqlObservation({
      pool,
      nodeId: NODE_ID,
      walletPublicKey: WALLET_PK,
      endpointFingerprint: HEX,
      httpStatus: 200,
      capture: headCapture("r3", sig("A"), ""),
      projection: emptyProjection,
    });
    expect(reg.relationship).toBe("REGRESSION");

    const wallet = psqlMust(
      scratchDb,
      `SELECT state || '|' || coalesce(quarantine_reason,'') FROM wallets WHERE id='${walletId}';`,
    ).trim();
    expect(wallet).toBe("QUARANTINED|REGRESSION");
    const lease = psqlMust(
      scratchDb,
      `SELECT membership_id::text FROM wallet_active_leases WHERE wallet_id='${walletId}';`,
    ).trim();
    expect(lease).toBe(LEASE_ID);
    const nAnom = psqlMust(
      scratchDb,
      `SELECT count(*) FROM observation_anomalies WHERE kind='REGRESSION';`,
    ).trim();
    expect(Number(nAnom)).toBeGreaterThanOrEqual(1);
    expect(
      canAcquireNewLease({
        walletId,
        state: "QUARANTINED",
        quarantineReason: "REGRESSION",
        activeLeaseId: LEASE_ID,
        signingHalted: true,
      }),
    ).toBe(false);
    assertionsRun += 1;
  });

  it("mid-tx action failure after anomaly insert rolls back observation+anomaly", async () => {
    const pk = `${"I".repeat(43)}=`;
    await persistSqlObservation({
      pool,
      nodeId: NODE_ID,
      walletPublicKey: pk,
      endpointFingerprint: HEX,
      httpStatus: 200,
      capture: headCapture("ok1", sig("A"), ""),
      projection: emptyProjection,
    });

    // Inject failure at audit append (after observation+anomaly INSERTs, before COMMIT).
    // Restore the client query method on release so the shared pool is not poisoned.
    const failingPool = {
      connect: async () => {
        const client = await pool.connect();
        const originalQuery = client.query.bind(client);
        const originalRelease = client.release.bind(client);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (client as any).query = (text: unknown, params?: unknown) => {
          if (typeof text === "string" && text.includes("INSERT INTO audit_log")) {
            return Promise.reject(new Error("injected audit failure"));
          }
          return originalQuery(text as never, params as never);
        };
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (client as any).release = (err?: Error | boolean) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (client as any).query = originalQuery;
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (client as any).release = originalRelease;
          return originalRelease(err as never);
        };
        return client;
      },
    } as unknown as Pool;

    await expect(
      persistSqlObservation({
        pool: failingPool,
        nodeId: NODE_ID,
        walletPublicKey: pk,
        endpointFingerprint: HEX,
        httpStatus: 200,
        capture: headCapture("bad-jump", sig("Z"), sig("Y")),
        projection: emptyProjection,
      }),
    ).rejects.toThrow(/injected audit failure/);

    const nObs = psqlMust(
      scratchDb,
      `SELECT count(*) FROM gateway_observations WHERE wallet_public_key='${pk}';`,
    ).trim();
    const nAnom = psqlMust(
      scratchDb,
      `SELECT count(*) FROM observation_anomalies a
         JOIN gateway_observations o ON o.id = a.observation_id
        WHERE o.wallet_public_key='${pk}';`,
    ).trim();
    // Only the successful FIRST remains; JUMP obs+anomaly rolled back together.
    expect(nObs).toBe("1");
    expect(nAnom).toBe("0");
    assertionsRun += 1;
  });

  it("identical malformed bodies append two observation+anomaly pairs (doc 08 §17.1.4)", async () => {
    const pk = `${"J".repeat(43)}=`;
    const bytes = new TextEncoder().encode("not-json{");
    for (let i = 0; i < 2; i += 1) {
      await persistSqlObservation({
        pool,
        nodeId: NODE_ID,
        walletPublicKey: pk,
        endpointFingerprint: HEX,
        httpStatus: 200,
        capture: {
          parseResult: "MALFORMED_ENVELOPE",
          rawResponseBytes: bytes,
          isGenesis: false,
          sSignature: "",
          pSignature: "",
          semanticFingerprint: "",
        },
        projection: {
          walletRole: null,
          bAmount: null,
          innerPreimageText: null,
          step1Signature: null,
          step2Signature: null,
          completedTransactionText: null,
          completedTransactionSha256: null,
        },
      });
    }
    const nObs = psqlMust(
      scratchDb,
      `SELECT count(*) FROM gateway_observations WHERE wallet_public_key='${pk}';`,
    ).trim();
    const nAnom = psqlMust(
      scratchDb,
      `SELECT count(*) FROM observation_anomalies a
         JOIN gateway_observations o ON o.id = a.observation_id
        WHERE o.wallet_public_key='${pk}' AND a.kind='MALFORMED_ENVELOPE';`,
    ).trim();
    expect(nObs).toBe("2");
    expect(nAnom).toBe("2");
    const bodies = psqlMust(
      scratchDb,
      `SELECT encode(raw_response_bytes,'escape') FROM gateway_observations
        WHERE wallet_public_key='${pk}' ORDER BY wallet_seq`,
    )
      .trim()
      .split("\n");
    expect(bodies[0]).toContain("not-json{");
    expect(bodies[1]).toContain("not-json{");
    assertionsRun += 1;
  });

  // ZTR-1275: appendExactRepeat appends DUPLICATE on exact byte-identical verified repeat.
  it("appendExactRepeat true → second identical verified head is DUPLICATE row, no anomaly", async () => {
    const pk = `${"K".repeat(43)}=`;
    const cap = headCapture("exact-repeat-body", sig("A"), "");
    const first = await persistSqlObservation({
      pool,
      nodeId: NODE_ID,
      walletPublicKey: pk,
      endpointFingerprint: HEX,
      httpStatus: 200,
      capture: cap,
      projection: emptyProjection,
    });
    expect(first.relationship).toBe("FIRST");

    // Default (flag off): suppress returns tip id, no new row.
    const suppressed = await persistSqlObservation({
      pool,
      nodeId: NODE_ID,
      walletPublicKey: pk,
      endpointFingerprint: HEX,
      httpStatus: 200,
      capture: cap,
      projection: emptyProjection,
    });
    expect(suppressed.observationId).toBe(first.observationId);
    expect(suppressed.relationship).toBe("NOT_APPLICABLE");
    expect(
      psqlMust(
        scratchDb,
        `SELECT count(*) FROM gateway_observations WHERE wallet_public_key='${pk}';`,
      ).trim(),
    ).toBe("1");

    // Flag on: append DUPLICATE with previous_recorded = tip, no anomaly.
    const dup = await persistSqlObservation({
      pool,
      nodeId: NODE_ID,
      walletPublicKey: pk,
      endpointFingerprint: HEX,
      httpStatus: 200,
      capture: cap,
      projection: emptyProjection,
      appendExactRepeat: true,
    });
    expect(dup.relationship).toBe("DUPLICATE");
    expect(dup.observationId).not.toBe(first.observationId);

    const rows = psqlMust(
      scratchDb,
      `SELECT wallet_seq::text || '|' || relationship::text || '|' ||
              coalesce(previous_recorded_observation_id::text,'')
         FROM gateway_observations
        WHERE wallet_public_key='${pk}'
        ORDER BY wallet_seq`,
    )
      .trim()
      .split("\n");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toBe(`1|FIRST|`);
    expect(rows[1]).toBe(`2|DUPLICATE|${first.observationId}`);

    const nAnom = psqlMust(
      scratchDb,
      `SELECT count(*) FROM observation_anomalies a
         JOIN gateway_observations o ON o.id = a.observation_id
        WHERE o.wallet_public_key='${pk}'`,
    ).trim();
    expect(nAnom).toBe("0");

    const cursor = psqlMust(
      scratchDb,
      `SELECT next_wallet_seq::text || '|' || consecutive_repeat_count::text || '|' ||
              last_recorded_observation_id::text
         FROM wallet_observation_cursors WHERE wallet_public_key='${pk}'`,
    ).trim();
    expect(cursor).toBe(`3|0|${dup.observationId}`);
    assertionsRun += 1;
  });
});

it("obligation guard: real-PG persistSqlObservation drills must execute", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error("PG_REQUIRED=1 but PostgreSQL unreachable for persistSqlObservation drills");
    }
    return;
  }
  expect(assertionsRun).toBeGreaterThanOrEqual(5);
});
