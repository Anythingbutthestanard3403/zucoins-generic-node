// ZTR-1330 connector_configs slice against PostgreSQL.
// Proves the appended pack slice creates the row, defaults policy_mode, and
// refuses a scope label outside the connector vocabulary.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import { createSqlConnectorConfigStore } from "@zucoins/node-core";
import { CONNECTOR_CONFIGS_SCHEMA_FILE } from "../../../packages/node-core/src/schema/connector-configs.contract.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const SCHEMA = "ztr1330_connectors";
const IMPL = "33333333-3333-4333-8333-333333333330";

const here = dirname(fileURLToPath(import.meta.url));
const sliceSql = readFileSync(
  resolve(here, "../../../packages/node-core/src/schema", CONNECTOR_CONFIGS_SCHEMA_FILE),
  "utf8",
);

const STUBS = `
CREATE TABLE implementers (
  id uuid PRIMARY KEY,
  name text NOT NULL
);
CREATE TABLE integration_requests (
  id uuid PRIMARY KEY
);
`;

let pool: Pool | undefined;

function psql(sql: string): void {
  execFileSync("psql", [TEST_DATABASE_URL, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql], {
    stdio: ["ignore", "pipe", "pipe"],
  });
}

describe("connector config slice (real PG)", () => {
  beforeAll(() => {
    if (!live) {
      if (PG_REQUIRED) throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned");
      return;
    }
    psql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
    psql(`SET search_path TO ${SCHEMA}; ${STUBS}`);
    psql(`SET search_path TO ${SCHEMA}; ${sliceSql}`);
    psql(
      `SET search_path TO ${SCHEMA}; INSERT INTO implementers (id, name) VALUES ('${IMPL}', 'promo-engine');`,
    );
    pool = new Pool({ connectionString: TEST_DATABASE_URL });
  }, 120_000);

  afterAll(async () => {
    await pool?.end();
    if (!live) return;
    try {
      psql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    } catch {
      // Shared PostgreSQL may already be dropping the schema.
    }
  });

  it("defaults policy_mode to NODE_VERIFIED and stores the hook target", async () => {
    if (!live || pool === undefined) return;
    const db = pool;
    const store = createSqlConnectorConfigStore({
      async query(text, params) {
        const client = await db.connect();
        try {
          await client.query(`SET search_path TO ${SCHEMA}`);
          const result = await client.query(text, params as unknown[] | undefined);
          return { rows: result.rows as Record<string, unknown>[] };
        } finally {
          client.release();
        }
      },
    });
    const saved = await store.upsert({
      implementerId: IMPL,
      displayName: "promo-engine",
      scopes: ["sends:write", "wallets:read_linked"],
      webhookUrl: "https://hooks.example/promo",
      webhookEnabled: true,
    });
    expect(saved.policy_mode).toBe("NODE_VERIFIED");
    expect(saved.scopes).toEqual(["sends:write", "wallets:read_linked"]);
    expect(saved.webhook_enabled).toBe(true);
    const client = await db.connect();
    try {
      await client.query(`SET search_path TO ${SCHEMA}`);
      await client.query(
        `INSERT INTO implementers (id, name) VALUES
           ('44444444-4444-4444-8444-444444444444', 'defaults-only'),
           ('55555555-5555-4555-8555-555555555555', 'bad-scope')`,
      );
      const defaults = await client.query<{ policy_mode: string }>(
        `INSERT INTO connector_configs (implementer_id, display_name)
         VALUES ('44444444-4444-4444-8444-444444444444', 'defaults-only')
         RETURNING policy_mode`,
      );
      expect(defaults.rows[0]?.policy_mode).toBe("NODE_VERIFIED");
      await expect(
        client.query(
          `INSERT INTO connector_configs (implementer_id, display_name, scopes)
           VALUES ('55555555-5555-4555-8555-555555555555', 'bad', '["nope"]'::jsonb)`,
        ),
      ).rejects.toThrow(/connector_configs_scopes_chk/);
    } finally {
      client.release();
    }
  });
});
