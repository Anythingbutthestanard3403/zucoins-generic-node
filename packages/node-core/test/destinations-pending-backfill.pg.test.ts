// Real-PostgreSQL proof for destinations-pending-backfill.sql + mint composition (ZTR-1306).
//
//   1. Mint helper inserts wallet + exactly one PENDING dest.
//   2. Register-style dest insert ON CONFLICT (wallet_id) does not double-row.
//   3. Backfill inserts PENDING for a missing dest; leaves existing rows alone.
//   4. Imported-origin wallets stay dest-less.
//   5. Slice re-apply is a no-op.
import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  INSERT_NODE_GENERATED_WALLET_SQL,
  INSERT_PENDING_DESTINATION_FOR_WALLET_SQL,
} from "../src/api/insert-node-generated-wallet.js";
import { registerPgRequiredGuard } from "./pg-required-guard.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";

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
const backfillDdl = readSchema("destinations-pending-backfill.sql");
const schemaDdl = `${prerequisiteDdl}${custodyDdl}\n${capabilityDdl}\n`;

const scratchDb = `dest_pending_bf_${Date.now()}_${process.pid}`;
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

const NODE_ID = "b0000000-0000-4000-8000-000000000001";
const WMINT = "c0000000-0000-4000-8000-0000000000a1";
const WMISS = "c0000000-0000-4000-8000-0000000000a2";
const WKEEP = "c0000000-0000-4000-8000-0000000000a3";
const WIMP = "c0000000-0000-4000-8000-0000000000a4";
const DKEEP = "d0000000-0000-4000-8000-0000000000a3";
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
         ('${NODE_ID}', 'dest-pending-bf', '${PUB("N")}') ON CONFLICT (id) DO NOTHING;`,
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
  name: "destinations-pending-backfill.pg",
  databaseUrl: TEST_DATABASE_URL,
  isReady: () => schemaReady,
});

describe("destinations pending backfill + mint composition PG (ZTR-1306)", () => {
  it("mint SQL inserts wallet + exactly one PENDING dest", async () => {
    if (!schemaReady) return;
    await must(`DELETE FROM destinations WHERE wallet_id = '${WMINT}'`);
    await must(`DELETE FROM wallets WHERE id = '${WMINT}'`);
    await must(
      INSERT_NODE_GENERATED_WALLET_SQL.replace(/\$1::uuid/g, `'${WMINT}'::uuid`)
        .replace(/\$2::uuid/g, `'${NODE_ID}'::uuid`)
        .replace("$3", `'${PUB("A")}'`)
        .replace("$4", "true")
        .replace("$5", "true")
        .replace("$6", "true")
        .replace("$7", `'FULL'`),
    );
    await must(
      INSERT_PENDING_DESTINATION_FOR_WALLET_SQL.replace(/\$1::uuid/g, `'${WMINT}'::uuid`)
        .replace(/\$2::uuid/g, `'${NODE_ID}'::uuid`)
        .replace("$3", `'pool'`)
        .replace("$4", `'PENDING'`),
    );
    const row = await must(
      `SELECT count(*)::text || '|' || min(state::text) || '|' || min(label)
         FROM destinations WHERE wallet_id = '${WMINT}'`,
    );
    expect(row).toBe("1|PENDING|pool");
  });

  it("register-style dest insert does not create a second row", async () => {
    if (!schemaReady) return;
    const destId = "e0000000-0000-4000-8000-0000000000e1";
    await must(
      `INSERT INTO destinations (id, node_id, wallet_id, label, state, created_at)
       VALUES ('${destId}', '${NODE_ID}', '${WMINT}', 'operator-label', 'PENDING', now())
       ON CONFLICT (wallet_id) DO UPDATE
          SET label = CASE
                        WHEN destinations.state = 'PENDING' THEN EXCLUDED.label
                        ELSE destinations.label
                      END`,
    );
    const row = await must(
      `SELECT count(*)::text || '|' || min(label)
         FROM destinations WHERE wallet_id = '${WMINT}'`,
    );
    expect(row).toBe("1|operator-label");
  });

  it("backfill inserts PENDING for a missing dest and skips existing + imported", async () => {
    if (!schemaReady) return;
    await must(`DELETE FROM destinations WHERE wallet_id IN ('${WMISS}', '${WKEEP}', '${WIMP}')`);
    await must(`DELETE FROM wallets WHERE id IN ('${WMISS}', '${WKEEP}', '${WIMP}')`);
    await must(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ('${WMISS}', '${NODE_ID}', '${PUB("B")}', 'node_generated', 'AVAILABLE'),
              ('${WKEEP}', '${NODE_ID}', '${PUB("C")}', 'node_generated', 'AVAILABLE'),
              ('${WIMP}', '${NODE_ID}', '${PUB("D")}', 'imported', 'AVAILABLE')`,
    );
    await must(
      `INSERT INTO destinations (id, node_id, wallet_id, label, state)
       VALUES ('${DKEEP}', '${NODE_ID}', '${WKEEP}', 'keep-me', 'PENDING')`,
    );
    const applied = await runPsql(backfillDdl);
    expect(applied.ok, applied.stderr).toBe(true);
    const missing = await must(
      `SELECT count(*)::text || '|' || min(state::text)
         FROM destinations WHERE wallet_id = '${WMISS}'`,
    );
    expect(missing).toBe("1|PENDING");
    expect(await must(`SELECT label FROM destinations WHERE id = '${DKEEP}'`)).toBe("keep-me");
    expect(await must(`SELECT count(*)::text FROM destinations WHERE wallet_id = '${WIMP}'`)).toBe(
      "0",
    );
    const reapplied = await runPsql(backfillDdl);
    expect(reapplied.ok, reapplied.stderr).toBe(true);
    expect(await must(`SELECT count(*)::text FROM destinations WHERE wallet_id = '${WMISS}'`)).toBe(
      "1",
    );
  });
});
