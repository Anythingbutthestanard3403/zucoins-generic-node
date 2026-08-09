// §16.33 mandatory database test — deferred parent/child correlation for completed
// reporting mutations, against a database built by the PRODUCTION migrator
// (runMigrationsOnPool: reporting drizzle prefix + the money schema pack).
//
// `reporting_mutation_idempotency` is what makes `POST /v1/operations/:id/armed` and
// `POST /v1/operations/:id/verification-complete` idempotent: a replayed Idempotency-Key
// returns the stored `response_bytes` and status from that row. `child_record_id` is
// NOT NULL UNIQUE but takes no FOREIGN KEY, because the child table varies by route. The
// five objects in mutation-correlation.sql are the polymorphic substitute; until they
// shipped, the node could hold a completed row naming a child that never landed and answer
// a retry with a confident 200.
//
// The existence check reads pg_proc / pg_trigger — never the .sql file — so a slice that
// is defined but excluded from the pack fails here.
//
// The child used throughout is `verification_acknowledgements`. `receive_arms` needs a
// receive_codes/wallets/gateway_observations seed an order of magnitude larger and would
// prove the same trigger body; its attachment is proven structurally (pg_trigger) and the
// route→relation split is proven by the wrong-route case.
//
// Connectivity: TEST_DATABASE_URL (vitest.global-setup provisions one) with a
// registerPgRequiredGuard so PG_REQUIRED=1 cannot silently skip. Teardown drops only the
// scratch database this file created.

import { createHash, randomUUID } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import { registerPgRequiredGuard } from "../../../packages/node-core/test/pg-required-guard.ts";

const databaseUrl = process.env.TEST_DATABASE_URL;
const PG_TEST_TIMEOUT_MS = 180_000;

/** Set only at the END of a successful beforeAll — registerPgRequiredGuard reads it. */
let ready = false;

const NODE_ID = "00000000-0000-4000-8000-000000011330";
const IMPLEMENTER_ID = "00000000-0000-4000-8000-000000011331";
const KEY_ID = "00000000-0000-4000-8000-000000011332";

const CORRELATION_TRIGGERS = [
  { name: "reporting_completed_parent_has_child", table: "reporting_mutation_idempotency" },
  { name: "reporting_arm_has_completed_parent", table: "receive_arms" },
  { name: "reporting_ack_has_completed_parent", table: "verification_acknowledgements" },
] as const;

const CORRELATION_FUNCTIONS = [
  "reporting_assert_completed_mutation",
  "reporting_validate_mutation_deferred",
] as const;

/** 23514 check_violation is what the correlation function raises on a broken correlation. */
const CHECK_VIOLATION = "23514";
/** SELECT … INTO STRICT with no row (child committed, parent absent) raises P0002. */
const NO_DATA_FOUND = "P0002";

const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

const pubkey = (suffix: string): string => `${"C".repeat(43 - suffix.length)}${suffix}=`;
const signature88 = (seed: string): string => `${seed.repeat(86).slice(0, 86)}==`;

function scratchDatabaseName(): string {
  return `mutation_correlation_${process.pid}_${Date.now()}`;
}

function urlForDatabase(base: string, database: string): string {
  const url = new URL(base);
  url.pathname = `/${database}`;
  return url.toString();
}

interface PgError {
  readonly code?: string;
  readonly message?: string;
}

const pgCode = (err: unknown): string | undefined => (err as PgError | null)?.code;

/** One request's worth of correlated identity: a nonce, a parent id, and a child id. */
interface Scenario {
  readonly operationId: string;
  readonly nonceId: string;
  readonly parentId: string;
  readonly childId: string;
  readonly rawTarget: string;
  readonly bodySha256: string;
  readonly idempotencyKey: string;
}

describe.skipIf(databaseUrl === undefined || databaseUrl === "")(
  "deferred parent/child correlation on the production schema (real PG)",
  () => {
    const scratchDb = scratchDatabaseName();
    let pool: Pool;
    let burnSequence = 0;

    /**
     * Seeds the tenant registry plus one RECEIVE_EXTERNAL operation and one reporting nonce
     * per scenario. The operation is CREATED/HOLD, which is the only operations shape whose
     * CHECK closure needs no wallet, destination or observation row.
     */
    async function newScenario(label: string): Promise<Scenario> {
      const operationId = randomUUID();
      const nonceId = randomUUID();
      const rawTarget = `/v1/operations/${operationId}/verification-complete`;
      const bodySha256 = sha256Hex(`body-${label}-${operationId}`);
      burnSequence += 1;

      await pool.query(
        `INSERT INTO operations (
           id, node_id, implementer_id, kind, status, amount_zkz, after_landing,
           discriminator, anchor, idempotency_key, request_sha256)
         VALUES ($1, $2, $3, 'RECEIVE_EXTERNAL', 'CREATED', '1.5', 'HOLD',
                 $1, $4, $5, $6)`,
        [
          operationId,
          NODE_ID,
          IMPLEMENTER_ID,
          `anchor-${label}-${burnSequence}`,
          `correlation-${label}-${operationId}`,
          sha256Hex(`request-${operationId}`),
        ],
      );
      await insertNonce(nonceId, "verification_complete", rawTarget, bodySha256);

      return {
        operationId,
        nonceId,
        parentId: randomUUID(),
        childId: randomUUID(),
        rawTarget,
        bodySha256,
        idempotencyKey: `idem-${randomUUID()}`,
      };
    }

    async function insertNonce(
      nonceId: string,
      routeId: string,
      rawTarget: string,
      bodySha256: string,
    ): Promise<void> {
      burnSequence += 1;
      await pool.query(
        `INSERT INTO reporting_request_nonces (
           id, node_id, implementer_id, nonce, purpose, route_id, request_class,
           reporting_key_id, lifecycle_epoch, nonce_burn_sequence, request_preimage_text,
           request_preimage_sha256, request_signature, method, raw_target, body_sha256,
           issued_at, expires_at, received_at, consumed_at, retention_class)
         VALUES ($1, $2, $3, $4, 'zp-report-request-v1', $5, 'MUTATION',
                 $6, 1, $7, $8,
                 $9, $10, 'POST', $11, $12,
                 now(), now() + interval '30 seconds', now(), now(), 'PERMANENT_MUTATION')`,
        [
          nonceId,
          NODE_ID,
          IMPLEMENTER_ID,
          randomUUID(),
          routeId,
          KEY_ID,
          burnSequence,
          `preimage-${nonceId}`,
          sha256Hex(`preimage-${nonceId}`),
          signature88("s"),
          rawTarget,
          bodySha256,
        ],
      );
    }

    const INSERT_PARENT = `
      INSERT INTO reporting_mutation_idempotency (
        id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id,
        child_record_id, method, raw_target, body_sha256, response_status, response_bytes,
        completed_at, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'POST', $8, $9, 200, '\\x7b7d'::bytea, now(), now())`;

    const INSERT_ACK = `
      INSERT INTO verification_acknowledgements (
        id, operation_id, node_id, implementer_id, raw_target, consumed_cursor, verdict,
        evidence_set_sha256, request_body_sha256, reporting_nonce_id, mutation_idempotency_id,
        acknowledged_at)
      VALUES ($1, $2, $3, $4, $5, 0, 'VERIFIED', $6, $7, $8, $9, now())`;

    const parentParams = (
      s: Scenario,
      overrides: {
        readonly routeId?: string;
        readonly childRecordId?: string;
        readonly nonceId?: string;
      } = {},
    ): readonly unknown[] => [
      s.parentId,
      NODE_ID,
      IMPLEMENTER_ID,
      overrides.routeId ?? "verification_complete",
      s.idempotencyKey,
      overrides.nonceId ?? s.nonceId,
      overrides.childRecordId ?? s.childId,
      s.rawTarget,
      s.bodySha256,
    ];

    const ackParams = (
      s: Scenario,
      overrides: { readonly nonceId?: string } = {},
    ): readonly unknown[] => [
      s.childId,
      s.operationId,
      NODE_ID,
      IMPLEMENTER_ID,
      s.rawTarget,
      sha256Hex(`evidence-${s.childId}`),
      s.bodySha256,
      overrides.nonceId ?? s.nonceId,
      s.parentId,
    ];

    /**
     * Runs `steps` inside ONE transaction and returns how it ended. Every statement is
     * expected to succeed; the deferred constraint triggers only speak at COMMIT, so
     * `committed: false` with a SQLSTATE is the shape a correlation refusal takes.
     */
    async function commitInOneTransaction(
      steps: readonly (readonly [string, readonly unknown[]])[],
    ): Promise<{ readonly committed: boolean; readonly code?: string; readonly midStatement: boolean }> {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        for (const [text, params] of steps) {
          try {
            await client.query(text, params as never);
          } catch (err) {
            await client.query("ROLLBACK").catch(() => {});
            return { committed: false, code: pgCode(err), midStatement: true };
          }
        }
        try {
          await client.query("COMMIT");
          return { committed: true, midStatement: false };
        } catch (err) {
          await client.query("ROLLBACK").catch(() => {});
          return { committed: false, code: pgCode(err), midStatement: false };
        }
      } finally {
        client.release();
      }
    }

    beforeAll(async () => {
      const admin = new Client({ connectionString: databaseUrl });
      await admin.connect();
      try {
        await admin.query(`DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
        await admin.query(`CREATE DATABASE ${scratchDb}`);
      } finally {
        await admin.end();
      }

      const scratchUrl = urlForDatabase(databaseUrl as string, scratchDb);
      pool = new Pool({ connectionString: scratchUrl });
      const { runMigrationsOnPool } = await import("../src/db/migrate.js");
      await runMigrationsOnPool(pool, { databaseUrl: scratchUrl });

      await pool.query(
        `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`,
        [NODE_ID, "mutation-correlation", pubkey("n1")],
      );
      await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
        IMPLEMENTER_ID,
        "mutation-correlation-impl",
      ]);
      await pool.query(
        `INSERT INTO implementer_reporting_keys
           (id, node_id, implementer_id, public_key, registered_at)
         VALUES ($1, $2, $3, $4, now())`,
        [KEY_ID, NODE_ID, IMPLEMENTER_ID, pubkey("k1")],
      );

      ready = true;
    }, PG_TEST_TIMEOUT_MS);

    afterAll(async () => {
      await pool?.end().catch(() => {});
      if (databaseUrl === undefined || databaseUrl === "") return;
      const admin = new Client({ connectionString: databaseUrl });
      await admin.connect().catch(() => {});
      await admin.query(`DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`).catch(() => {});
      await admin.end().catch(() => {});
    }, PG_TEST_TIMEOUT_MS);

    it("the production pack materialises all five correlation objects", async () => {
      const functions = await pool.query<{ proname: string }>(
        `SELECT proname FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public' AND p.proname = ANY($1::text[])
          ORDER BY proname`,
        [[...CORRELATION_FUNCTIONS]],
      );
      expect(functions.rows.map((r) => r.proname)).toEqual([...CORRELATION_FUNCTIONS].sort());

      const triggers = await pool.query<{
        tgname: string;
        relname: string;
        tgdeferrable: boolean;
        tginitdeferred: boolean;
        tgconstraint: string;
      }>(
        `SELECT t.tgname, c.relname, t.tgdeferrable, t.tginitdeferred,
                t.tgconstraint::text AS tgconstraint
           FROM pg_trigger t
           JOIN pg_class c ON c.oid = t.tgrelid
          WHERE NOT t.tgisinternal AND t.tgname = ANY($1::text[])`,
        [[...CORRELATION_TRIGGERS.map((t) => t.name)]],
      );
      const byName = new Map(triggers.rows.map((row) => [row.tgname, row]));
      for (const expected of CORRELATION_TRIGGERS) {
        const row = byName.get(expected.name);
        expect(row, `${expected.name} must exist in pg_trigger`).toBeDefined();
        expect(row?.relname, expected.name).toBe(expected.table);
        expect(row?.tgdeferrable, `${expected.name} DEFERRABLE`).toBe(true);
        expect(row?.tginitdeferred, `${expected.name} INITIALLY DEFERRED`).toBe(true);
        // A CONSTRAINT TRIGGER carries a pg_constraint oid; a plain trigger carries 0.
        expect(row?.tgconstraint, `${expected.name} is a constraint trigger`).not.toBe("0");
      }
    });

    it("rejects a completed parent whose child_record_id names no row, at COMMIT", async () => {
      const s = await newScenario("orphan");
      const outcome = await commitInOneTransaction([
        [INSERT_PARENT, parentParams(s, { childRecordId: randomUUID() })],
      ]);
      expect(outcome.committed).toBe(false);
      // Deferred, not immediate: the INSERT itself has to succeed.
      expect(outcome.midStatement).toBe(false);
      expect(outcome.code).toBe(CHECK_VIOLATION);

      const survivors = await pool.query(
        `SELECT 1 FROM reporting_mutation_idempotency WHERE id = $1`,
        [s.parentId],
      );
      expect(survivors.rowCount).toBe(0);
    });

    it("rejects a parent and child whose reporting_nonce_id disagree", async () => {
      const s = await newScenario("nonce-split");
      const otherNonce = randomUUID();
      await insertNonce(otherNonce, "verification_complete", s.rawTarget, s.bodySha256);

      const outcome = await commitInOneTransaction([
        [INSERT_PARENT, parentParams(s)],
        [INSERT_ACK, ackParams(s, { nonceId: otherNonce })],
      ]);
      expect(outcome.committed).toBe(false);
      expect(outcome.midStatement).toBe(false);
      expect(outcome.code).toBe(CHECK_VIOLATION);
    });

    it("rejects a child_record_id belonging to the wrong route", async () => {
      // A committed, fully correlated verification_complete pair …
      const landed = await newScenario("wrong-route-landed");
      const good = await commitInOneTransaction([
        [INSERT_PARENT, parentParams(landed)],
        [INSERT_ACK, ackParams(landed)],
      ]);
      expect(good.committed).toBe(true);

      // … then an operation_armed parent pointing at that acknowledgement. The route selects
      // receive_arms, so the ack id resolves to zero matching children.
      const armed = await newScenario("wrong-route-armed");
      const armedNonce = randomUUID();
      await insertNonce(armedNonce, "operation_armed", armed.rawTarget, armed.bodySha256);

      const outcome = await commitInOneTransaction([
        [
          INSERT_PARENT,
          parentParams(armed, {
            routeId: "operation_armed",
            nonceId: armedNonce,
            childRecordId: landed.childId,
          }),
        ],
      ]);
      expect(outcome.committed).toBe(false);
      expect(outcome.midStatement).toBe(false);
      expect(outcome.code).toBe(CHECK_VIOLATION);
    });

    it("accepts parent-then-child and child-then-parent within one transaction", async () => {
      const parentFirst = await newScenario("parent-first");
      const forward = await commitInOneTransaction([
        [INSERT_PARENT, parentParams(parentFirst)],
        [INSERT_ACK, ackParams(parentFirst)],
      ]);
      expect(forward.code).toBeUndefined();
      expect(forward.committed).toBe(true);

      const childFirst = await newScenario("child-first");
      const reversed = await commitInOneTransaction([
        [INSERT_ACK, ackParams(childFirst)],
        [INSERT_PARENT, parentParams(childFirst)],
      ]);
      expect(reversed.code).toBeUndefined();
      expect(reversed.committed).toBe(true);

      for (const s of [parentFirst, childFirst]) {
        const row = await pool.query<{ child_record_id: string }>(
          `SELECT child_record_id::text AS child_record_id
             FROM reporting_mutation_idempotency WHERE id = $1`,
          [s.parentId],
        );
        expect(row.rows[0]?.child_record_id).toBe(s.childId);
      }
    });

    it("rejects a child whose completion parent never lands", async () => {
      const s = await newScenario("orphan-child");
      const outcome = await commitInOneTransaction([[INSERT_ACK, ackParams(s)]]);
      expect(outcome.committed).toBe(false);
      expect(outcome.midStatement).toBe(false);
      // The child→parent composite FK and the correlation trigger both refuse here; either
      // SQLSTATE is a lawful refusal, and both are deferred to COMMIT.
      expect([NO_DATA_FOUND, "23503"]).toContain(outcome.code);
    });
  },
);

registerPgRequiredGuard({
  name: "mutation-correlation.pg",
  databaseUrl,
  isReady: () => ready,
});
