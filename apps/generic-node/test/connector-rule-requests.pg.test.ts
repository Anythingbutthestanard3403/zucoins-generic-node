// ZTR-1331 connector_rule_requests slice against PostgreSQL.
// Proves a valid insert writes the row and an audit row, and that a
// window_hours of 0 fails the check.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import { createSqlConnectorRuleRequestStore } from "@zucoins/node-core";
import { CONNECTOR_RULE_REQUESTS_SCHEMA_FILE } from "../../../packages/node-core/src/schema/connector-rule-requests.contract.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const SCHEMA = "ztr1331_rule_requests";
const NODE = "11111111-1111-4111-8111-111111111111";
const IMPL = "22222222-2222-4222-8222-222222222222";

const here = dirname(fileURLToPath(import.meta.url));
const sliceSql = readFileSync(
  resolve(here, "../../../packages/node-core/src/schema", CONNECTOR_RULE_REQUESTS_SCHEMA_FILE),
  "utf8",
);

const STUBS = `
CREATE TABLE nodes (
  id uuid PRIMARY KEY
);
CREATE TABLE implementers (
  id uuid PRIMARY KEY,
  name text NOT NULL
);
CREATE TABLE wallets (
  id uuid PRIMARY KEY
);
CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');
CREATE TABLE audit_log (
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id uuid NOT NULL UNIQUE,
  node_id uuid NOT NULL REFERENCES nodes(id),
  actor_kind text NOT NULL CHECK (actor_kind IN
    ('SYSTEM','OPERATOR_SESSION','ACTION_KEY','DEVICE_KEY','IMPLEMENTER')),
  actor_id text,
  action text NOT NULL,
  operation_id uuid,
  wallet_id uuid,
  details_text text NOT NULL,
  details_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL
);
`;

let pool: Pool | undefined;

function psql(sql: string): void {
  execFileSync("psql", [TEST_DATABASE_URL, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql], {
    stdio: ["ignore", "pipe", "pipe"],
  });
}

describe("connector rule request slice (real PG)", () => {
  beforeAll(() => {
    if (!live) {
      if (PG_REQUIRED) throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned");
      return;
    }
    psql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
    psql(`SET search_path TO ${SCHEMA}; ${STUBS}`);
    psql(`SET search_path TO ${SCHEMA}; ${sliceSql}`);
    psql(
      `SET search_path TO ${SCHEMA};
       INSERT INTO nodes (id) VALUES ('${NODE}');
       INSERT INTO implementers (id, name) VALUES ('${IMPL}', 'promo-engine');`,
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

  it("writes the request row and an audit row, and rejects window_hours 0", async () => {
    if (!live || pool === undefined) return;
    const db = pool;
    const store = createSqlConnectorRuleRequestStore({
      async query(text, params) {
        const client = await db.connect();
        try {
          await client.query("BEGIN");
          await client.query(`SET LOCAL search_path TO ${SCHEMA}`);
          const result = await client.query(text, params as unknown[] | undefined);
          await client.query("COMMIT");
          return { rows: result.rows as Record<string, unknown>[] };
        } catch (error) {
          await client.query("ROLLBACK");
          throw error;
        } finally {
          client.release();
        }
      },
    });
    const saved = await store.create({
      nodeId: NODE,
      implementerId: IMPL,
      ruleId: "winter-promo-2026",
      label: "Winter Promo",
      reserveWalletId: null,
      totalCapZkz: "200",
      perSendMaxZkz: "20",
      perSendMinZkz: null,
      windowHours: 24,
      windowCapZkz: "100",
      expiresAt: null,
      webhookEnabled: true,
      actorId: IMPL,
    });
    expect(saved.status).toBe("PENDING");
    expect(saved.rule_id).toBe("winter-promo-2026");
    const client = await db.connect();
    try {
      await client.query(`SET search_path TO ${SCHEMA}`);
      const audit = await client.query<{ action: string; actor_kind: string; details_text: string }>(
        `SELECT action, actor_kind, details_text FROM audit_log WHERE node_id = $1`,
        [NODE],
      );
      expect(audit.rows[0]?.action).toBe("connector_rule_request.created");
      expect(audit.rows[0]?.actor_kind).toBe("IMPLEMENTER");
      expect(audit.rows[0]?.details_text).toContain("\"webhook_enabled\":true");
      expect(audit.rows[0]?.details_text).not.toContain("http");
      await expect(
        client.query(
          `INSERT INTO connector_rule_requests (
             request_id, node_id, implementer_id, rule_id, label,
             per_send_max_zkz, window_hours, window_cap_zkz
           ) VALUES (
             '44444444-4444-4444-8444-444444444444', $1, $2, 'bad-window', 'Bad',
             '20', 0, '100'
           )`,
          [NODE, IMPL],
        ),
      ).rejects.toThrow(/connector_rule_requests_window_hours_chk/);
    } finally {
      client.release();
    }
  });
});
