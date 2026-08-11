// D4 — the evidence-immutability triggers on the event and audit halves of 04
// mandatory test 15 ("observation/event/audit append-only triggers reject update and
// delete"): node_events (event-ledger.sql) and audit_log (audit-log.sql).
//
// audit log | permanent | append-only", "no nonce, idempotency, enrolment, lifecycle,
// event, or audit evidence may be pruned while held"); appendix state/event (events are never
// edited or deleted); the node-global hash chain is the gap/tamper detector.
//
// The observation third of item 15 (gateway_observations, observation_anomalies) is NOT
// covered here — see the note at the foot of this file.
//
// The census block binds the frozen invariant inventory to the literal SQL and runs always.
// The live block is gated on TEST_DATABASE_URL and runs psql as a child process
// (node:child_process), which keeps the in-process network-containment guard
// (setup-network-guard.ts) intact — the pattern established by proof-body-store.pg.test.ts.
//
// Each fragment is applied into its OWN schema: both re-declare the sha256_hex domain
// and the rejector function (CONVENTIONS.md), so applying them side by side into one
// namespace would collide before any guard could be exercised.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// DB-TEST-15: observation/event/audit append-only triggers reject update and delete


import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  AUDIT_LOG_INVARIANTS,
  AUDIT_LOG_SCHEMA_FILE,
  SCHEMA_AUDIT_LOG_OBLIGATIONS,
} from "../src/schema/audit-log.contract.ts";
import {
  EVENT_LEDGER_INVARIANTS,
  EVENT_LEDGER_SCHEMA_FILE,
  SCHEMA_EVENT_LEDGER_OBLIGATIONS,
} from "../src/schema/event-ledger.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaPath = (file: string): string => resolve(here, "../src/schema", file);
const eventLedgerSql = readFileSync(schemaPath(EVENT_LEDGER_SCHEMA_FILE), "utf8");
const auditLogSql = readFileSync(schemaPath(AUDIT_LOG_SCHEMA_FILE), "utf8");

const EVENT_GUARDS = [
  "EVENTS_APPEND_ONLY_UPDATE_GUARD",
  "EVENTS_APPEND_ONLY_DELETE_GUARD",
  "EVENTS_APPEND_ONLY_TRUNCATE_GUARD",
  "EVENTS_APPEND_ONLY_REJECTOR_IS_THE_DOC_FUNCTION",
];

const AUDIT_GUARDS = [
  "AUDIT_APPEND_ONLY_UPDATE_GUARD",
  "AUDIT_APPEND_ONLY_DELETE_GUARD",
  "AUDIT_APPEND_ONLY_TRUNCATE_GUARD",
  "AUDIT_APPEND_ONLY_REJECTOR_IS_THE_DOC_FUNCTION",
];

const missingAnchors = (
  invariants: readonly { readonly id: string; readonly sqlAnchor: string }[],
  ids: readonly string[],
  sql: string,
): string[] =>
  invariants
    .filter((invariant) => ids.includes(invariant.id) && !sql.includes(invariant.sqlAnchor))
    .map((invariant) => invariant.id);

describe("D4 append-only guard census (mandatory DB test 15: event + audit)", () => {
  it("every node_events guard invariant anchors to the literal SQL text", () => {
    expect(missingAnchors(EVENT_LEDGER_INVARIANTS, EVENT_GUARDS, eventLedgerSql)).toEqual([]);
  });

  it("every audit_log guard invariant anchors to the literal SQL text", () => {
    expect(missingAnchors(AUDIT_LOG_INVARIANTS, AUDIT_GUARDS, auditLogSql)).toEqual([]);
  });

  it("neither contract still defers the guards to a later phase", () => {
    for (const obligations of [SCHEMA_EVENT_LEDGER_OBLIGATIONS, SCHEMA_AUDIT_LOG_OBLIGATIONS]) {
      const guard = obligations.find((entry) => entry.startsWith("guards"));
      expect(guard).toBeDefined();
      expect(guard).toContain("DISCHARGED");
      expect(guard).not.toContain("No trigger DDL is frozen in this file");
    }
  });

  it("node_event_seq_counters is deliberately left unguarded (mutable allocation counter, data-model)", () => {
    expect(eventLedgerSql).not.toMatch(
      /BEFORE (UPDATE|DELETE|TRUNCATE) ON node_event_seq_counters/,
    );
  });

  it("mutation negative: dropping the TRUNCATE guard is caught by the census", () => {
    const mutated = eventLedgerSql.replace("  BEFORE TRUNCATE ON node_events\n", "");
    expect(mutated).not.toBe(eventLedgerSql);
    expect(missingAnchors(EVENT_LEDGER_INVARIANTS, EVENT_GUARDS, mutated)).toEqual([
      "EVENTS_APPEND_ONLY_TRUNCATE_GUARD",
    ]);
  });

  it("mutation negative: renaming the rejector away from the doc function is caught", () => {
    const mutated = auditLogSql.replaceAll(
      "reporting_reject_immutable_change",
      "audit_reject_change",
    );
    expect(mutated).not.toBe(auditLogSql);
    expect(missingAnchors(AUDIT_LOG_INVARIANTS, AUDIT_GUARDS, mutated).sort()).toEqual(
      [...AUDIT_GUARDS].sort(),
    );
  });
});

// ---------------------------------------------------------------------------
// Live PostgreSQL
// ---------------------------------------------------------------------------

const databaseUrl = process.env.TEST_DATABASE_URL;
const EVENT_SCHEMA = "evidence_append_only_event_ledger";
const AUDIT_SCHEMA = "evidence_append_only_audit_log";

const NODE_ID = "00000000-0000-0000-0000-000000000001";
const WALLET_ID = "00000000-0000-0000-0000-000000000002";
const OPERATION_ID = "00000000-0000-0000-0000-000000000003";
const SIGNING_KEY_ID = "00000000-0000-0000-0000-000000000004";
const AUDIT_ID = "00000000-0000-0000-0000-000000000005";
const SHA = "a".repeat(64);
const SHA_2 = "b".repeat(64);
const SIGNATURE = `${"C".repeat(86)}==`;

// The FK targets data-model point at, reduced to the columns the references need. The real
// relations belong to other frozen fragments; standing them up here would re-declare their
// domains and defeat the point of applying each fragment standalone.
const FK_STUBS = `CREATE TABLE nodes (id uuid PRIMARY KEY);
CREATE TABLE wallets (id uuid PRIMARY KEY);
CREATE TABLE operations (id uuid PRIMARY KEY);
CREATE TABLE node_signing_keys (id uuid PRIMARY KEY);
INSERT INTO nodes (id) VALUES ('${NODE_ID}');
INSERT INTO wallets (id) VALUES ('${WALLET_ID}');
INSERT INTO operations (id) VALUES ('${OPERATION_ID}');
INSERT INTO node_signing_keys (id) VALUES ('${SIGNING_KEY_ID}');`;

const pgEnv = (): Record<string, string> => {
  const url = new URL(databaseUrl as string);
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  env.PGHOST = url.hostname;
  env.PGPORT = url.port || "5432";
  env.PGUSER = decodeURIComponent(url.username);
  env.PGPASSWORD = decodeURIComponent(url.password);
  env.PGDATABASE = url.pathname.replace(/^\//, "");
  return env;
};

interface PsqlResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

const psql = (args: readonly string[]): PsqlResult => {
  try {
    const stdout = execFileSync("psql", ["-v", "ON_ERROR_STOP=1", "-q", ...args], {
      env: pgEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout: stdout.toString(), stderr: "" };
  } catch (error) {
    const err = error as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      status: err.status ?? 1,
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? String(error),
    };
  }
};

let reachable = false;

const run = (schema: string, statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${schema}`, "-c", statement]);

const scalar = (schema: string, query: string): string =>
  psql(["-t", "-A", "-c", `SET search_path TO ${schema}`, "-c", query]).stdout.trim();

const INSERT_EVENT = (seq: number, eventId: string, eventHash: string): string =>
  `INSERT INTO node_events (
     seq, event_id, canonical_version, node_id, operation_id, wallet_id, event_type,
     data_text, data_sha256, preimage_text, preimage_sha256, signing_key_id, signature,
     previous_event_hash, event_hash, created_at
   ) VALUES (
     ${seq}, '${eventId}', 1, '${NODE_ID}', '${OPERATION_ID}', '${WALLET_ID}',
     'internal_move.landed', '{"landed_at":"2026-07-25T01:00:00.000Z"}', '${SHA}',
     '{"seq":"${seq}"}', '${SHA_2}', '${SIGNING_KEY_ID}', '${SIGNATURE}',
     NULL, '${eventHash}', '2026-07-25T01:00:00Z'
   )`;

const INSERT_AUDIT = (id: string): string =>
  `INSERT INTO audit_log (
     id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
     details_text, details_sha256, created_at
   ) VALUES (
     '${id}', '${NODE_ID}', 'OPERATOR_SESSION', 'session-1', 'move.landed',
     '${OPERATION_ID}', '${WALLET_ID}', '{"detail":"landed"}', '${SHA}',
     '2026-07-25T01:00:00Z'
   )`;

describe.skipIf(databaseUrl === undefined)("against a live PostgreSQL", () => {
  beforeAll(() => {
    reachable = psql(["-c", "SELECT 1"]).status === 0;
    if (!reachable) return;
    for (const [schema, file, seed] of [
      [EVENT_SCHEMA, schemaPath(EVENT_LEDGER_SCHEMA_FILE), INSERT_EVENT(1, "00000000-0000-0000-0000-0000000000e1", SHA)],
      [AUDIT_SCHEMA, schemaPath(AUDIT_LOG_SCHEMA_FILE), INSERT_AUDIT(AUDIT_ID)],
    ] as const) {
      psql(["-c", `DROP SCHEMA IF EXISTS ${schema} CASCADE`]);
      const applied = psql([
        "-c",
        `CREATE SCHEMA ${schema}`,
        "-c",
        `SET search_path TO ${schema}`,
        "-c",
        FK_STUBS,
        "-f",
        file,
      ]);
      expect(applied.stderr, `${schema} apply should be clean`).toBe("");
      expect(applied.status, `${schema} apply should succeed`).toBe(0);
      const seeded = run(schema, seed);
      expect(seeded.stderr, `${schema} seed should insert`).toBe("");
      expect(seeded.status).toBe(0);
    }
  });

  afterAll(() => {
    if (!reachable) return;
    for (const schema of [EVENT_SCHEMA, AUDIT_SCHEMA]) {
      psql(["-c", `DROP SCHEMA IF EXISTS ${schema} CASCADE`]);
    }
  });

  // --- node_events (mandatory DB test 15, "event") -------------------------------------------

  it("D4: UPDATE of a signed event column is rejected by the trigger", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      EVENT_SCHEMA,
      `UPDATE node_events SET data_text = '{"landed_at":"tampered"}' WHERE seq = 1`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
    expect(result.stderr).toContain("UPDATE is forbidden");
  });

  it("D4: rewriting the chain link (event_hash) is rejected — detector stays intact", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      EVENT_SCHEMA,
      `UPDATE node_events SET event_hash = '${SHA_2}' WHERE seq = 1`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
  });

  it("D4: a no-op UPDATE that changes nothing is still rejected", (ctx) => {
    if (!reachable) ctx.skip();
    // The guard is unconditional: no "harmless rewrite" carve-out to shape tampering into.
    const result = run(EVENT_SCHEMA, `UPDATE node_events SET seq = seq WHERE seq = 1`);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
  });

  it("D4: DELETE of an event is rejected by the trigger", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(EVENT_SCHEMA, `DELETE FROM node_events WHERE seq = 1`);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
    expect(result.stderr).toContain("DELETE is forbidden");
  });

  it("D4: a WHERE-less DELETE of the whole ledger is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(EVENT_SCHEMA, `DELETE FROM node_events`);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
  });

  it("D4: TRUNCATE of the ledger is rejected — the row-level guards leave that bypass open", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(EVENT_SCHEMA, `TRUNCATE node_events`);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
    expect(result.stderr).toContain("TRUNCATE is forbidden");
  });

  it("D4: the event rejection carries the doc's 55000 SQLSTATE", (ctx) => {
    if (!reachable) ctx.skip();
    const result = psql([
      "-v",
      "VERBOSITY=verbose",
      "-c",
      `SET search_path TO ${EVENT_SCHEMA}`,
      "-c",
      `DELETE FROM node_events WHERE seq = 1`,
    ]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("55000");
  });

  // --- audit_log (mandatory DB test 15, "audit") ---------------------------------------------

  it("D4: UPDATE of an audit entry is rejected by the trigger", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      AUDIT_SCHEMA,
      `UPDATE audit_log SET action = 'rewritten' WHERE id = '${AUDIT_ID}'`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
    expect(result.stderr).toContain("UPDATE is forbidden");
  });

  it("D4: DELETE of an audit entry is rejected — the trail cannot be pruned", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(AUDIT_SCHEMA, `DELETE FROM audit_log WHERE id = '${AUDIT_ID}'`);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
    expect(result.stderr).toContain("DELETE is forbidden");
  });

  it("D4: TRUNCATE of the audit trail is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(AUDIT_SCHEMA, `TRUNCATE audit_log`);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
    expect(result.stderr).toContain("TRUNCATE is forbidden");
  });

  it("D4: the audit rejection carries the doc's 55000 SQLSTATE", (ctx) => {
    if (!reachable) ctx.skip();
    const result = psql([
      "-v",
      "VERBOSITY=verbose",
      "-c",
      `SET search_path TO ${AUDIT_SCHEMA}`,
      "-c",
      `DELETE FROM audit_log WHERE id = '${AUDIT_ID}'`,
    ]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("55000");
  });

  // --- the guards do not over-reach -----------------------------------------------------

  it("the seeded evidence survives every rejected mutation, byte-for-byte", (ctx) => {
    if (!reachable) ctx.skip();
    expect(
      scalar(
        EVENT_SCHEMA,
        `SELECT data_text || ' ' || event_hash FROM node_events WHERE seq = 1`,
      ),
    ).toBe(`{"landed_at":"2026-07-25T01:00:00.000Z"} ${SHA}`);
    expect(scalar(EVENT_SCHEMA, "SELECT count(*) FROM node_events")).toBe("1");
    expect(
      scalar(AUDIT_SCHEMA, `SELECT action FROM audit_log WHERE id = '${AUDIT_ID}'`),
    ).toBe("move.landed");
    expect(scalar(AUDIT_SCHEMA, "SELECT count(*) FROM audit_log")).toBe("1");
  });

  it("INSERT still works on both tables — append-only, not read-only", (ctx) => {
    if (!reachable) ctx.skip();
    const event = run(
      EVENT_SCHEMA,
      INSERT_EVENT(2, "00000000-0000-0000-0000-0000000000e2", "c".repeat(64)),
    );
    expect(event.stderr).toBe("");
    expect(event.status).toBe(0);
    expect(scalar(EVENT_SCHEMA, "SELECT count(*) FROM node_events")).toBe("2");

    const audit = run(AUDIT_SCHEMA, INSERT_AUDIT("00000000-0000-0000-0000-000000000006"));
    expect(audit.stderr).toBe("");
    expect(audit.status).toBe(0);
    expect(scalar(AUDIT_SCHEMA, "SELECT count(*) FROM audit_log")).toBe("2");
  });

  it("the allocation counter stays mutable: advancing next_seq still works", (ctx) => {
    if (!reachable) ctx.skip();
    const inserted = run(
      EVENT_SCHEMA,
      `INSERT INTO node_event_seq_counters (node_id, next_seq) VALUES ('${NODE_ID}', 1)`,
    );
    expect(inserted.status).toBe(0);
    const advanced = run(
      EVENT_SCHEMA,
      `UPDATE node_event_seq_counters SET next_seq = next_seq + 1 WHERE node_id = '${NODE_ID}'`,
    );
    expect(advanced.stderr).toBe("");
    expect(advanced.status).toBe(0);
    expect(
      scalar(
        EVENT_SCHEMA,
        `SELECT next_seq FROM node_event_seq_counters WHERE node_id = '${NODE_ID}'`,
      ),
    ).toBe("2");
  });
});

/* ─── fail-closed harness guard ─────────────────────────────
 * Top-level so it runs even when the gated describe skips: under PG_REQUIRED=1 an unassigned
 * TEST_DATABASE_URL or an unreachable server is a broken harness rather than an absent
 * Postgres. The D4 guards are real-PostgreSQL properties; a skipped run proves none of them. */
it("the D4 append-only guards must run against real PostgreSQL under PG_REQUIRED=1", () => {
  if (process.env.PG_REQUIRED !== "1") return;
  expect(
    databaseUrl,
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts provisioned no test database, so the live block skipped",
  ).toBeDefined();
  expect(
    reachable,
    "PG_REQUIRED=1 but the live block never reached the server — the append-only guards went unproven",
  ).toBe(true);
});

// COVERED — observation append-only for gateway_observations,
// observation_anomalies, and observers is enforced by BEFORE UPDATE/DELETE/TRUNCATE
// triggers in observation-ledger.sql / observation-anomaly-indexes.sql (ERRCODE 55000).
// capture.concurrency.test.ts no longer UPDATEs/DELETEs observation rows: relationship is
// set at INSERT by ExactRepeatService, and per-test isolation uses unique wallet PKs
// instead of wipeStream DELETEs. Behavioural proof: observation-migration-integrity.test.ts
// (b2)–(b5). Residual tracker, if any, is for non-observation evidence tables only.
