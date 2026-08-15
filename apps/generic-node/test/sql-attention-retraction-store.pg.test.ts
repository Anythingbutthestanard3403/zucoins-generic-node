// SQL-backed AttentionRetractionStore against a real PostgreSQL server.
// Invariants: attention_required/attention_reason co-presence;
// audit-log.sql (append-only provenance). The one-in-flight-per-wallet and byte-exact signing rules, 4.
//
// Mirrors sql-recovery-store.pg.test.ts's conventions (own schema, PACK_SLICES
// composition, FK_TARGET_STUBS, pgcrypto-race retry, beforeAll/afterAll/beforeEach
// boilerplate) so this store's transaction (BEGIN/lock/CAS/audit-insert/COMMIT) runs
// against the frozen contract DDL rather than a fake SqlQueryFn. No nonce/TOTP cases —
// this store has none, unlike RecoveryActionStore.

import { randomUUID, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { sha256HexUtf8 } from "@zucoins/node-core";

import { registerPgRequiredGuard } from "../../../packages/node-core/test/pg-required-guard.ts";
import { createSqlAttentionRetractionStore } from "../src/operations/sql-attention-retraction-store.js";

const SCHEMA = "sql_attention_attention_retraction";
const databaseUrl = process.env.TEST_DATABASE_URL;
const PG_TEST_TIMEOUT_MS = 180_000;

const NODE_ID = "00000000-0000-4000-8000-000000010290";
const IMPLEMENTER_ID = "00000000-0000-4000-8000-000000010291";

// ── schema composition (verbatim frozen contract text, dependency order) ───────────────────

const schemaDir = fileURLToPath(new URL("../../../packages/node-core/src/schema/", import.meta.url));
const PACK_SLICES = [
  "base-enums-domains",
  "custody-eligibility",
  "signer-support",
  "operations",
  "audit-log",
  "move-baseline-binding",
  "receive-external-landing",
] as const;
const VERIFICATION_MODE_SLICE = readFileSync(`${schemaDir}verification-mode.sql`, "utf8");

function packSql(): string {
  const declared = new Set<string>();
  const declarations: string[] = [];
  const tables = PACK_SLICES.map((slice) => readFileSync(`${schemaDir}${slice}.sql`, "utf8"))
    .join("\n")
    .replace(/^CREATE (DOMAIN|TYPE) ([a-z0-9_]+)[\s\S]*?;\n/gm, (statement, _kind: string, name: string) => {
      if (!declared.has(name)) {
        declared.add(name);
        declarations.push(statement);
      }
      return "";
    });
  const extras = `
CREATE TABLE IF NOT EXISTS receive_operations (operation_id uuid PRIMARY KEY);
CREATE TABLE IF NOT EXISTS send_operations (operation_id uuid PRIMARY KEY);
CREATE TABLE IF NOT EXISTS node_settings (
  setting_key text PRIMARY KEY,
  setting_value text NOT NULL,
  row_version bigint NOT NULL DEFAULT 1
);
ALTER TABLE operations ADD COLUMN IF NOT EXISTS receive_release_status text;
`;
  return `${declarations.join("\n")}\n${tables}\n${extras}\n${VERIFICATION_MODE_SLICE}`;
}

// CREATE EXTENSION IF NOT EXISTS is not safe under concurrent DDL: two test files racing
// against the same shared TEST_DATABASE_URL can both pass the existence check before either
// commits, and the loser hits a duplicate-key error on pg_extension's name index. packSql()
// re-declares pgcrypto (via base-enums-domains.sql) every run, so retry once past that
// specific, benign collision rather than failing the whole suite.
async function applySchema(target: Pool, sql: string): Promise<void> {
  try {
    await target.query(sql);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes("pg_extension_name_index")) throw error;
    await target.query(sql);
  }
}

const FK_TARGET_STUBS = ["nodes", "implementers"]
  .map((t) => `CREATE TABLE ${t} (id uuid PRIMARY KEY);`)
  .join("\n");

// ── fixture helpers ─────────────────────────────────────────────────────────────────────────

let pool: Pool;
let reachable = false;
let store: ReturnType<typeof createSqlAttentionRetractionStore>;

function pubkey(): string {
  const hex = randomUUID().replace(/-/g, "");
  return `${hex.padEnd(43, "a")}=`;
}

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

async function insertWallet(): Promise<string> {
  const walletId = randomUUID();
  await pool.query(
    `INSERT INTO wallets (id, node_id, public_key, key_origin)
     VALUES ($1::uuid, $2::uuid, $3, 'node_generated')`,
    [walletId, NODE_ID, pubkey()],
  );
  return walletId;
}

async function insertDestination(walletId: string): Promise<string> {
  const destinationId = randomUUID();
  await pool.query(
    `INSERT INTO destinations (id, node_id, wallet_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
    [destinationId, NODE_ID, walletId],
  );
  return destinationId;
}

// operations.sql:205 is a biconditional: CHECK (attention_required = (attention_reason IS
// NOT NULL)). A NEEDS_ATTENTION seed with a non-null attentionReason (mirroring
// sql-recovery-store.pg.test.ts:142 seedMoveOperation) is the only legal "flagged" row; a
// CREATED seed with no reason is the only legal "not flagged" row. There is no legal seed
// for attention_required=true with attention_reason=null (or the reverse), so that half of
// the store's not_flagged branch is unreachable here — covered instead by the FakeStore unit
// test.
async function seedMoveOperation(opts: {
  status: string;
  attentionReason?: string;
  sourceWalletId: string;
  destinationId: string;
}): Promise<string> {
  const operationId = randomUUID();
  await pool.query(
    `INSERT INTO operations
       (id, node_id, implementer_id, kind, status, attention_required, attention_reason,
        source_wallet_id, destination_id, amount_zkz, idempotency_key, request_sha256, created_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, 'MOVE_INTERNAL', $4, $5, $6, $7::uuid, $8::uuid,
             '0.01', $9, $10, now())`,
    [
      operationId,
      NODE_ID,
      IMPLEMENTER_ID,
      opts.status,
      opts.attentionReason !== undefined,
      opts.attentionReason ?? null,
      opts.sourceWalletId,
      opts.destinationId,
      randomUUID(),
      sha256(randomUUID()),
    ],
  );
  return operationId;
}

async function auditRowsFor(operationId: string): Promise<readonly { details_text: string; details_sha256: string }[]> {
  const result = await pool.query(
    `SELECT details_text, details_sha256 FROM audit_log WHERE operation_id = $1::uuid ORDER BY seq`,
    [operationId],
  );
  return result.rows as { details_text: string; details_sha256: string }[];
}

async function operationRow(operationId: string): Promise<{
  attention_required: boolean;
  attention_reason: string | null;
  row_version: number;
}> {
  const result = await pool.query(
    `SELECT attention_required, attention_reason, row_version::int AS row_version
       FROM operations WHERE id = $1::uuid`,
    [operationId],
  );
  return result.rows[0] as { attention_required: boolean; attention_reason: string | null; row_version: number };
}

// ── suite ────────────────────────────────────────────────────────────────────────────────────

describe.skipIf(databaseUrl === undefined)("SQL attention-retraction store against a live PostgreSQL", () => {
  beforeAll(async () => {
    const url = new URL(databaseUrl as string);
    pool = new Pool({
      host: url.hostname,
      port: Number(url.port || "5432"),
      user: decodeURIComponent(url.username),
      password: decodeURIComponent(url.password),
      database: url.pathname.replace(/^\//, ""),
      options: `-c search_path=${SCHEMA},public`,
    });
    await pool.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    await pool.query(`CREATE SCHEMA ${SCHEMA}`);
    await pool.query(`SET search_path TO ${SCHEMA}, public`);
    await pool.query(FK_TARGET_STUBS);
    await applySchema(pool, packSql());
    await pool.query(`INSERT INTO nodes (id) VALUES ($1::uuid)`, [NODE_ID]);
    await pool.query(`INSERT INTO implementers (id) VALUES ($1::uuid)`, [IMPLEMENTER_ID]);
    store = createSqlAttentionRetractionStore(pool);
    reachable = true;
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    if (reachable) await pool.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    await pool?.end().catch(() => undefined);
  }, PG_TEST_TIMEOUT_MS);

  beforeEach(async () => {
    await pool.query(`SET search_path TO ${SCHEMA}, public`);
  });

  it("rejects operation_not_found for a random id, no audit row written", async () => {
    const operationId = randomUUID();

    const result = await store.commit({
      operationId,
      reason: "classifier fixed",
      supersededBy: null,
      expectedRowVersion: 1,
      actorId: "operator-sql-attention",
    });

    expect(result).toMatchObject({ ok: false, reason: "operation_not_found" });
    expect(await auditRowsFor(operationId)).toHaveLength(0);
  });

  it("rejects not_flagged for an operation that was never flagged, no audit row, row unchanged", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({ status: "CREATED", sourceWalletId, destinationId });

    const result = await store.commit({
      operationId,
      reason: "classifier fixed",
      supersededBy: null,
      expectedRowVersion: 1,
      actorId: "operator-sql-attention",
    });

    expect(result).toMatchObject({ ok: false, reason: "not_flagged" });
    expect(await auditRowsFor(operationId)).toHaveLength(0);
    expect(await operationRow(operationId)).toMatchObject({
      attention_required: false,
      attention_reason: null,
      row_version: 1,
    });
  });

  it("rejects a stale expected_row_version with conflict, no audit row, row unchanged", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({
      status: "NEEDS_ATTENTION", attentionReason: "classifier flagged this", sourceWalletId, destinationId,
    });

    const result = await store.commit({
      operationId,
      reason: "classifier fixed",
      supersededBy: null,
      expectedRowVersion: 99,
      actorId: "operator-sql-attention",
    });

    expect(result).toMatchObject({ ok: false, reason: "conflict" });
    expect(await auditRowsFor(operationId)).toHaveLength(0);
    expect(await operationRow(operationId)).toMatchObject({
      attention_required: true,
      attention_reason: "classifier flagged this",
      row_version: 1,
    });
  });

  it("commits a retraction end to end: audit_log row byte-exact, post-state cleared, audit_log append-only", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({
      status: "NEEDS_ATTENTION", attentionReason: "classifier flagged this", sourceWalletId, destinationId,
    });

    const result = await store.commit({
      operationId,
      reason: "classifier bug fixed in PR-42",
      supersededBy: "classifier-v2",
      expectedRowVersion: 1,
      actorId: "operator-sql-attention",
    });

    expect(result).toMatchObject({
      ok: true,
      rowVersion: 2,
      priorAttentionReason: "classifier flagged this",
    });

    expect(await operationRow(operationId)).toMatchObject({
      attention_required: false,
      attention_reason: null,
      row_version: 2,
    });

    const expectedDetails =
      `action=operation.attention_retracted;operation_id=${operationId};` +
      `prior_attention_reason=classifier flagged this;reason=classifier bug fixed in PR-42;` +
      `superseded_by=classifier-v2`;
    const auditRows = await auditRowsFor(operationId);
    expect(auditRows).toHaveLength(1);
    expect(auditRows[0]!.details_text).toBe(expectedDetails);
    expect(auditRows[0]!.details_sha256).toBe(sha256HexUtf8(expectedDetails));
    expect(auditRows[0]!.details_sha256).toBe(sha256(expectedDetails));

    await expect(pool.query(`UPDATE audit_log SET details_text = 'tampered' WHERE operation_id = $1::uuid`, [operationId])).rejects.toMatchObject({
      code: "55000",
    });
    await expect(pool.query(`DELETE FROM audit_log WHERE operation_id = $1::uuid`, [operationId])).rejects.toMatchObject({
      code: "55000",
    });
    await expect(pool.query(`TRUNCATE audit_log`)).rejects.toMatchObject({ code: "55000" });
  });

  it("replaying the identical retraction after success returns not_flagged, not conflict — exactly one audit row, row_version incremented exactly once", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({
      status: "NEEDS_ATTENTION", attentionReason: "classifier flagged this", sourceWalletId, destinationId,
    });
    const input = {
      operationId,
      reason: "classifier bug fixed in PR-42",
      supersededBy: null,
      expectedRowVersion: 1,
      actorId: "operator-sql-attention",
    };

    const first = await store.commit(input);
    expect(first).toMatchObject({ ok: true, rowVersion: 2 });

    // Same expectedRowVersion as the first call (a naive blind replay of the original
    // request) — the flag is already clear, so this must hit not_flagged, not conflict:
    // the store checks not-found -> not_flagged -> conflict, and a cleared row never
    // reaches the stale-version branch.
    const replay = await store.commit(input);
    expect(replay).toMatchObject({ ok: false, reason: "not_flagged" });

    expect(await auditRowsFor(operationId)).toHaveLength(1);
    expect(await operationRow(operationId)).toMatchObject({
      attention_required: false,
      attention_reason: null,
      row_version: 2,
    });
  });
});

registerPgRequiredGuard({
  name: "sql-attention-retraction-store.pg",
  databaseUrl,
  isReady: () => reachable,
});
