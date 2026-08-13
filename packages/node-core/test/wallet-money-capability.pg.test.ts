// Real-PostgreSQL proof for wallet-money-capability.sql (ZTR-1267).
//
// Engine-only properties:
//   1. Slice applies after custody-eligibility (wallets exist).
//   2. Column defaults + INSERT without capability cols yield FULL.
//   3. CHECK wallets_money_mode_flags_consistent rejects illegal triples
//      (including all-false) and mode/flag mismatches.
//   4. wallets_money_mode_closed rejects unknown mode labels.
//   5. wallets_row_version_positive rejects non-positive row_version.
//   6. Explicit backfill UPDATE converges non-FULL rows to FULL.
//
// Apply sequence mirrors custody-eligibility.pg.test.ts: base-enums-domains +
// nodes table only (not full registry — it re-declares padded_base64url_pubkey)
// + custody-eligibility + wallet-money-capability.
import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { registerPgRequiredGuard } from "./pg-required-guard.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";

const SQLSTATE_CHECK_VIOLATION = "23514";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

const prerequisiteDdl = ((): string => {
  const base = readSchema("base-enums-domains.sql");
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  return `${base}\n${nodes[0]}\n`;
})();

const custodyDdl = readSchema("custody-eligibility.sql");
const capabilityDdl = readSchema("wallet-money-capability.sql");
const schemaDdl = `${prerequisiteDdl}${custodyDdl}\n${capabilityDdl}\n`;

const scratchDb = `wallet_money_cap_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;

const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

const adminPsql = (url: string, sql: string): void => {
  execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
    encoding: "utf-8",
    timeout: 60_000,
  });
};

const runPsql = (sql: string, timeoutMs = 20_000): Promise<PsqlOutcome> =>
  new Promise((resolve) => {
    execFile(
      "psql",
      [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: timeoutMs },
      (err, stdout, stderr) => {
        resolve({ ok: !err, stdout: stdout ?? "", stderr: stderr ?? (err ? String(err) : "") });
      },
    );
  });

const must = async (sql: string): Promise<string> => {
  const outcome = await runPsql(sql);
  if (!outcome.ok) {
    throw new Error(`psql failed for [${sql}]: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout.trim();
};

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const mustReject = async (sql: string, sqlstate: string): Promise<void> => {
  const outcome = await runPsql(sql);
  expect(outcome.ok, `expected rejection but succeeded: ${sql}\n${outcome.stderr}`).toBe(false);
  expect(extractSqlstate(outcome.stderr), `SQLSTATE for: ${sql}\n${outcome.stderr}`).toBe(
    sqlstate,
  );
};

const NODE_ID = "b0000000-0000-4000-8000-000000000001";
const W1 = "c0000000-0000-4000-8000-000000000001";
const W2 = "c0000000-0000-4000-8000-000000000002";
const W3 = "c0000000-0000-4000-8000-000000000003";
const WR = "c0000000-0000-4000-8000-000000000011";
const WS = "c0000000-0000-4000-8000-000000000012";
const WI = "c0000000-0000-4000-8000-000000000013";
const WB = "c0000000-0000-4000-8000-0000000000bf";
const PUB = (ch: string) => `${ch.repeat(43)}=`;

beforeAll(() => {
  if (!TEST_DATABASE_URL) return;
  adminPsql(TEST_DATABASE_URL, `CREATE DATABASE ${scratchDb}`);
  scratchDbUrl = withDatabase(TEST_DATABASE_URL, scratchDb);
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: schemaDdl,
    encoding: "utf-8",
    timeout: 60_000,
  });
  execFileSync(
    "psql",
    [
      scratchDbUrl,
      "-v",
      "ON_ERROR_STOP=1",
      "-qAt",
      "-c",
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${NODE_ID}', 'wallet-money-cap', '${PUB("N")}') ON CONFLICT (id) DO NOTHING;`,
    ],
    { encoding: "utf-8", timeout: 15_000 },
  );
  schemaReady = true;
}, 90_000);

afterAll(() => {
  if (!schemaReady) return;
  try {
    adminPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  } catch {
    /* best-effort teardown */
  }
});

registerPgRequiredGuard({
  name: "wallet-money-capability.pg",
  databaseUrl: TEST_DATABASE_URL,
  isReady: () => schemaReady,
});

describe("wallet money capability PG drills (ZTR-1267)", () => {
  it("INSERT without capability columns defaults to FULL + all allows true + row_version 1", async () => {
    if (!schemaReady) return;
    await must(`DELETE FROM wallets WHERE id = '${W1}'`);
    await must(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ('${W1}', '${NODE_ID}', '${PUB("A")}', 'node_generated', 'AVAILABLE')`,
    );
    const row = await must(
      `SELECT money_mode || '|' ||
              allow_external_receive::text || '|' ||
              allow_external_send::text || '|' ||
              allow_internal_move::text || '|' ||
              row_version::text
         FROM wallets WHERE id = '${W1}'`,
    );
    expect(row).toBe("FULL|true|true|true|1");
  });

  it("explicit FULL mint write is accepted", async () => {
    if (!schemaReady) return;
    await must(`DELETE FROM wallets WHERE id = '${W2}'`);
    await must(
      `INSERT INTO wallets (
         id, node_id, public_key, key_origin, state,
         allow_external_receive, allow_external_send, allow_internal_move, money_mode
       ) VALUES (
         '${W2}', '${NODE_ID}', '${PUB("B")}', 'node_generated', 'AVAILABLE',
         true, true, true, 'FULL'
       )`,
    );
    expect(await must(`SELECT money_mode FROM wallets WHERE id = '${W2}'`)).toBe("FULL");
  });

  it("legal presets RECEIVE_ONLY / SEND_ONLY / INTERNAL_ONLY insert cleanly", async () => {
    if (!schemaReady) return;
    for (const [id, mode, recv, send, move, pubCh] of [
      [WR, "RECEIVE_ONLY", "true", "false", "true", "C"],
      [WS, "SEND_ONLY", "false", "true", "true", "D"],
      [WI, "INTERNAL_ONLY", "false", "false", "true", "E"],
    ] as const) {
      await must(`DELETE FROM wallets WHERE id = '${id}'`);
      await must(
        `INSERT INTO wallets (
           id, node_id, public_key, key_origin, state,
           allow_external_receive, allow_external_send, allow_internal_move, money_mode
         ) VALUES (
           '${id}', '${NODE_ID}', '${PUB(pubCh)}', 'node_generated', 'AVAILABLE',
           ${recv}, ${send}, ${move}, '${mode}'
         )`,
      );
      expect(await must(`SELECT money_mode FROM wallets WHERE id = '${id}'`)).toBe(mode);
    }
  });

  it("CHECK rejects illegal triples including all-false and mode/flag mismatch", async () => {
    if (!schemaReady) return;
    await mustReject(
      `INSERT INTO wallets (
         id, node_id, public_key, key_origin, state,
         allow_external_receive, allow_external_send, allow_internal_move, money_mode
       ) VALUES (
         '${W3}', '${NODE_ID}', '${PUB("F")}', 'node_generated', 'AVAILABLE',
         false, false, false, 'FULL'
       )`,
      SQLSTATE_CHECK_VIOLATION,
    );

    await mustReject(
      `INSERT INTO wallets (
         id, node_id, public_key, key_origin, state,
         allow_external_receive, allow_external_send, allow_internal_move, money_mode
       ) VALUES (
         '${W3}', '${NODE_ID}', '${PUB("G")}', 'node_generated', 'AVAILABLE',
         true, false, true, 'INTERNAL_ONLY'
       )`,
      SQLSTATE_CHECK_VIOLATION,
    );

    await mustReject(
      `INSERT INTO wallets (
         id, node_id, public_key, key_origin, state,
         allow_external_receive, allow_external_send, allow_internal_move, money_mode
       ) VALUES (
         '${W3}', '${NODE_ID}', '${PUB("H")}', 'node_generated', 'AVAILABLE',
         true, true, true, 'HUB'
       )`,
      SQLSTATE_CHECK_VIOLATION,
    );
  });

  it("row_version CHECK rejects non-positive values", async () => {
    if (!schemaReady) return;
    await mustReject(
      `INSERT INTO wallets (
         id, node_id, public_key, key_origin, state, row_version
       ) VALUES (
         '${W3}', '${NODE_ID}', '${PUB("I")}', 'node_generated', 'AVAILABLE', 0
       )`,
      SQLSTATE_CHECK_VIOLATION,
    );
  });

  it("backfill UPDATE converges non-default rows to FULL (idempotent re-apply path)", async () => {
    if (!schemaReady) return;
    await must(`DELETE FROM wallets WHERE id = '${WB}'`);
    await must(
      `INSERT INTO wallets (
         id, node_id, public_key, key_origin, state,
         allow_external_receive, allow_external_send, allow_internal_move, money_mode
       ) VALUES (
         '${WB}', '${NODE_ID}', '${PUB("J")}', 'node_generated', 'AVAILABLE',
         false, false, true, 'INTERNAL_ONLY'
       )`,
    );
    expect(await must(`SELECT money_mode FROM wallets WHERE id = '${WB}'`)).toBe("INTERNAL_ONLY");

    await must(`
UPDATE wallets
   SET allow_external_receive = true,
       allow_external_send = true,
       allow_internal_move = true,
       money_mode = 'FULL'
 WHERE allow_external_receive IS DISTINCT FROM true
    OR allow_external_send IS DISTINCT FROM true
    OR allow_internal_move IS DISTINCT FROM true
    OR money_mode IS DISTINCT FROM 'FULL';
`);
    const row = await must(
      `SELECT money_mode || '|' ||
              allow_external_receive::text || '|' ||
              allow_external_send::text || '|' ||
              allow_internal_move::text
         FROM wallets WHERE id = '${WB}'`,
    );
    expect(row).toBe("FULL|true|true|true");
  });
});
