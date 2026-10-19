// ZTR-1333 webhook_deliveries slice against PostgreSQL.
// Proves a signed insert, a claim-and-mark tick, a manual requeue, and the
// source unique constraint.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import { createSqlWebhookDeliveryStore } from "@zucoins/node-core";
import { WEBHOOK_DELIVERIES_SCHEMA_FILE } from "../../../packages/node-core/src/schema/webhook-deliveries.contract.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const SCHEMA = "ztr1333_webhook_deliveries";
const NODE = "11111111-1111-4111-8111-111111111111";
const IMPL = "22222222-2222-4222-8222-222222222222";
const SOURCE = "33333333-3333-4333-8333-333333333333";

const here = dirname(fileURLToPath(import.meta.url));
const sliceSql = readFileSync(
  resolve(here, "../../../packages/node-core/src/schema", WEBHOOK_DELIVERIES_SCHEMA_FILE),
  "utf8",
);

const STUBS = `
CREATE TABLE implementers (
  id uuid PRIMARY KEY
);
`;

let pool: Pool | undefined;

function psql(sql: string): void {
  execFileSync("psql", [TEST_DATABASE_URL, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql], {
    stdio: ["ignore", "pipe", "pipe"],
  });
}

describe("hook delivery slice (real PG)", () => {
  beforeAll(() => {
    if (!live) {
      if (PG_REQUIRED) throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned");
      return;
    }
    psql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
    psql(`SET search_path TO ${SCHEMA}; ${STUBS}`);
    psql(`SET search_path TO ${SCHEMA}; ${sliceSql}`);
    psql(`SET search_path TO ${SCHEMA}; INSERT INTO implementers (id) VALUES ('${IMPL}');`);
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

  it("claims a due row, marks it delivered, and requeues it", async () => {
    if (!live || pool === undefined) return;
    const db = pool;
    const store = createSqlWebhookDeliveryStore({
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
    const saved = await store.enqueue(
      {
        nodeId: NODE,
        implementerId: IMPL,
        eventType: "receive.settled",
        operationId: null,
        externalRef: null,
        occurredAt: "2026-10-19T09:00:00.000Z",
        data: { amount: "15" },
        sourceKind: "DURABLE_EVENT",
        sourceId: SOURCE,
      },
      { sign: () => "c2ln" },
    );
    expect(saved?.status).toBe("PENDING");
    const again = await store.enqueue(
      {
        nodeId: NODE,
        implementerId: IMPL,
        eventType: "receive.settled",
        operationId: null,
        externalRef: null,
        occurredAt: "2026-10-19T09:00:00.000Z",
        data: { amount: "15" },
        sourceKind: "DURABLE_EVENT",
        sourceId: SOURCE,
      },
      { sign: () => "c2ln" },
    );
    expect(again).toBeNull();
    const posted = await store.deliverDue(NODE, {
      now: () => new Date("2026-10-19T09:00:01.000Z"),
      signer: () => null,
      targetFor: async () => ({ url: "https://hooks.example/promo" }),
      validateTarget: async () => undefined,
      post: async () => ({ status: 200 }),
    });
    expect(posted).toBe(1);
    const delivered = await store.get(saved!.delivery_id);
    expect(delivered?.status).toBe("DELIVERED");
    expect(delivered?.attempt_count).toBe(1);
    const reset = await store.requeue({
      nodeId: NODE,
      implementerId: IMPL,
      deliveryId: saved!.delivery_id,
      now: new Date("2026-10-19T09:05:00.000Z"),
    });
    expect(reset?.status).toBe("PENDING");
    expect(reset?.attempt_count).toBe(0);
    expect(reset?.last_error).toBeNull();
    const foreign = await store.requeue({
      nodeId: NODE,
      implementerId: "55555555-5555-4555-8555-555555555555",
      deliveryId: saved!.delivery_id,
      now: new Date("2026-10-19T09:06:00.000Z"),
    });
    expect(foreign).toBeNull();
  });
});
