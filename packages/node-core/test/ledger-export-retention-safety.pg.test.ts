/**
 * ledger-export-retention-safety.pg.test.ts
 *
 * real-PostgreSQL proof of the full terminal-state retention matrix
 * for the canonical ledger and proof-access expiry.
 *
 *
 * Acceptance drills (each against a live PostgreSQL instance, never a mock):
 *   1. Round-trip exact bytes — insert/read; digests recomputed from READ-BACK bytes
 *   2. MOVE_INTERNAL dual-wallet ledger rows (SOURCE + DESTINATION) on one attempt body
 *   3. Settlement replay never doubles or mutates ledger rows
 *   4. GET verification-material 409 → 200 → 410; 410 body carries zero evidence bytes
 *   5. Retention / proof-access expiry revokes access only — permanent row count+bytes hold
 *   6. pg_dump / restore preserves every evidence row byte and verification_material window
 *   7. Direct UPDATE/DELETE against each guarded evidence table is trigger-rejected;
 * bad digest / truncated body / broken FK is caught; redaction may touch only
 *      operations.description / client_reference
 *   8. gateway_observations A,B,C,A via the writer path yields four rows (final REGRESSION)
 *   9. node-core retention surface has zero executable DELETE against evidence
 *  10. Per-wallet ledger export covers every settled leg with recomputed digests
 *
 * Composition: base-enums-domains + minimal FK stubs + frozen fragments applied verbatim.
 * Harness mirrors wallet-settled-ledger.pg.test.ts / observation-stores.pg.test.ts.
 * PG unreachable → skip unless PG_REQUIRED=1.
 */
import {
  execFileSync,
  spawn,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { SequenceCapture } from "@zucoins/generic-node-contracts/observation";

import {
  handleGetVerificationMaterial,
  type VerificationMaterialRow,
  type VerificationMaterialSource,
} from "../src/api/verification-material.js";
import {
  DEFAULT_PROOF_ACCESS_WINDOW_MS,
  verificationMaterialAvailableUntilMs,
} from "../src/data/retention.js";
import {
  createSerializedStreamWriter,
  type ObservationStreamKey,
} from "../src/observation/capture-writer.js";
import {
  createSqlStreamWriterEffects,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/observation/stream-writer-sql.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "../src/schema");
const SRC_DIR = join(HERE, "../src");
const MAINTENANCE_DB = "postgres";
const DB_PREFIX = "ledger_export_retention_";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const EXPECTED_DRILLS = 10;

const WALLET_A = "a0000000-0000-4000-8000-000000000001";
const WALLET_B = "a0000000-0000-4000-8000-000000000002";
const OP_MOVE = "a0000000-0000-4000-8000-000000000010";
const OP_RECEIVE = "a0000000-0000-4000-8000-000000000011";
const PROOF_MOVE = "a0000000-0000-4000-8000-000000000020";
const PROOF_RECEIVE = "a0000000-0000-4000-8000-000000000021";
const NODE_ID = "a0000000-0000-4000-8000-000000000030";
const SIGNING_KEY_ID = "a0000000-0000-4000-8000-000000000031";
const OBSERVER_ID = "a0000000-0000-4000-8000-000000000040";
const APPROVAL_ID = "a0000000-0000-4000-8000-000000000050";
const ARTIFACT_ID = "a0000000-0000-4000-8000-000000000051";
const EVENT_ID = "a0000000-0000-4000-8000-000000000060";
const AUDIT_ID = "a0000000-0000-4000-8000-000000000061";

const pubkey = (letter: string): string => `${letter.repeat(43)}=`;
const KEY_A = pubkey("A");
const KEY_B = pubkey("B");
const SIG = `${"S".repeat(86)}==`;
const INNER_SHA = "a".repeat(64);
const HEX_B = "b".repeat(64);
const SETTLED_AT = "2026-07-27 12:00:00+00";
const ENDPOINT_FP = "c".repeat(64);

/**
 * Settled body with awkward key sequence and single-space-after-colon so a
 * JSON.parse/JSON.stringify round-trip would silently rewrite the octets.
 */
const SETTLED_TEXT =
  '{"transaction": {"unix_time_secs": "1784880000", "amount": "0.01000000"},' +
  '"step_1_signature": "' +
  SIG +
  '", "step_2_signature": "' +
  SIG +
  '"}';
const SETTLED_SHA = createHash("sha256").update(SETTLED_TEXT, "utf8").digest("hex");

/** Distinct body for RECEIVE so WALLET_A can hold both a MOVE SOURCE and a RECEIVE leg. */
const RECEIVE_TEXT = SETTLED_TEXT.replace('"0.01000000"', '"0.01000001"');
const RECEIVE_SHA = createHash("sha256").update(RECEIVE_TEXT, "utf8").digest("hex");

const PARTIAL_TEXT = "transfer-code-exact-bytes-v1\nwith\tcontrol";
const PARTIAL_SHA = createHash("sha256").update(PARTIAL_TEXT, "utf8").digest("hex");
const ARTIFACT_PREIMAGE = 'purpose\n{"k": "v", "n": 1}';
const ARTIFACT_SHA = createHash("sha256").update(ARTIFACT_PREIMAGE, "utf8").digest("hex");
const APPROVAL_PREIMAGE = 'zp-send-external-approval-v1\n{"op":1}';
const APPROVAL_SHA = createHash("sha256").update(APPROVAL_PREIMAGE, "utf8").digest("hex");
const EVENT_DATA = '{"landed_at":"2026-07-27T12:00:00.000Z"}';
const EVENT_DATA_SHA = createHash("sha256").update(EVENT_DATA, "utf8").digest("hex");
const EVENT_PREIMAGE = '{"seq":"1"}';
const EVENT_PREIMAGE_SHA = createHash("sha256").update(EVENT_PREIMAGE, "utf8").digest("hex");
const AUDIT_DETAILS = '{"detail":"landed","amount":"0.01000000"}';
const AUDIT_SHA = createHash("sha256").update(AUDIT_DETAILS, "utf8").digest("hex");

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) args.push("--set=VERBOSITY=verbose");
  args.push("-qAt", "-c", sql);
  try {
    const stdout = execFileSync("psql", args, {
      encoding: "utf-8",
      timeout: 20_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): string => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const applyDdl = (db: string, sql: string, label: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-c", sql], {
      encoding: "utf-8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`DDL apply ${label} failed: ${(e.stderr ?? "").trim() || "unknown"}`);
  }
};

const applyFile = (
  db: string,
  file: string,
  opts: { stripDomainsTypes?: boolean; stripRejector?: boolean } = {},
): void => {
  try {
    if (opts.stripDomainsTypes || opts.stripRejector) {
      let cleaned = readFileSync(resolve(SCHEMA_DIR, file), "utf8");
      if (opts.stripDomainsTypes) cleaned = stripTypes(stripDomains(cleaned));
      // Only drop the rejector when a prior fragment already installed it.
      if (opts.stripRejector) cleaned = stripRejector(cleaned);
      execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-c", cleaned], {
        encoding: "utf-8",
        timeout: 30_000,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } else {
      execFileSync(
        "psql",
        ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(SCHEMA_DIR, file)],
        { encoding: "utf-8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] },
      );
    }
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim() || "unknown"}`);
  }
};

const probePostgres = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;
const lit = (value: string): string => `'${value.replaceAll("'", "''")}'`;
const hexOf = (text: string): string => Buffer.from(text, "utf8").toString("hex");
const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

const stripDomains = (sql: string): string => sql.replace(/^CREATE DOMAIN [\s\S]*?;$/gm, "");
const stripTypes = (sql: string): string => sql.replace(/^CREATE TYPE [\s\S]*?;$/gm, "");
const stripRejector = (sql: string): string =>
  sql.replace(/^CREATE FUNCTION reporting_reject_immutable_change\(\)[\s\S]*?^\$\$;$/gm, "");

const frozenTable = (file: string, table: string): string => {
  const sql = readFileSync(join(SCHEMA_DIR, file), "utf8");
  const block = new RegExp(`^CREATE TABLE ${table} \\([\\s\\S]*?^\\);$`, "m").exec(sql)?.[0];
  if (block === undefined) throw new Error(`${file}: CREATE TABLE ${table} not found`);
  return block;
};

const ledgerDdl = (): string =>
  stripDomains(readFileSync(join(SCHEMA_DIR, "wallet-settled-ledger.sql"), "utf8"));

/**
 * Retention surface DELETE/TRUNCATE ban via AST. Pre-change stripComments treated a
 * string-borne block-comment opener as real and blanked through a later terminator, hiding a
 * real executable DELETE/TRUNCATE or batchedDelete. The tree walks identifiers and string /
 * template literal contents only.
 */
const parseTs = (src: string): ts.SourceFile =>
  ts.createSourceFile("retention-surface.ts", src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);

const visitEvery = (sourceFile: ts.SourceFile, visit: (node: ts.Node) => void): void => {
  const walk = (node: ts.Node): void => {
    visit(node);
    ts.forEachChild(node, walk);
  };
  walk(sourceFile);
};

const DELETE_FROM = /\bDELETE\s+FROM\b/i;
const TRUNCATE_RE = /\bTRUNCATE\s+/i;
const UPDATE_WORD = /\bUPDATE\s+\w+/i;

type RetentionSurfaceHit = "DELETE_FROM" | "TRUNCATE" | "UPDATE" | "batchedDelete";

const retentionSurfaceHits = (src: string): RetentionSurfaceHit[] => {
  const hits = new Set<RetentionSurfaceHit>();
  const considerText = (value: string): void => {
    if (DELETE_FROM.test(value)) hits.add("DELETE_FROM");
    if (TRUNCATE_RE.test(value)) hits.add("TRUNCATE");
    if (UPDATE_WORD.test(value)) hits.add("UPDATE");
    if (value.includes("batchedDelete")) hits.add("batchedDelete");
  };
  visitEvery(parseTs(src), (node) => {
    if (ts.isIdentifier(node)) {
      if (node.text === "batchedDelete") hits.add("batchedDelete");
      return;
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      considerText(node.text);
      return;
    }
    if (ts.isTemplateExpression(node)) {
      considerText(node.head.text);
      for (const span of node.templateSpans) {
        considerText(span.literal.text);
      }
    }
  });
  return [...hits];
};

/** Legacy stripper retained only for the mutual-blindness plant. */
const legacyStripComments = (src: string): string =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/`[\s\S]*?`/g, '""')
    .replace(/"[^"]*"/g, '""')
    .replace(/'[^']*'/g, '""');

const sqlLiteral = (value: unknown): string => {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (value instanceof Date) return `'${value.toISOString()}'::timestamptz`;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return `E'\\\\x${Buffer.from(value).toString("hex")}'::bytea`;
  }
  if (typeof value === "string") return `'${value.replaceAll("'", "''")}'`;
  throw new Error(`unsupported sql param type: ${typeof value}`);
};

const fp = (label: string): string => createHash("sha256").update(label).digest("hex");
const headCapture = (opts: {
  bytes: string;
  s: string;
  p: string;
  fpLabel: string;
}): SequenceCapture => ({
  parseResult: "VERIFIED_HEAD",
  rawResponseBytes: new TextEncoder().encode(opts.bytes),
  isGenesis: false,
  sSignature: opts.s,
  pSignature: opts.p,
  semanticFingerprint: fp(opts.fpLabel),
});
const sig = (ch: string): string => `${ch.repeat(86)}==`;
const CAP_A = headCapture({ bytes: "response-A", s: sig("A"), p: "", fpLabel: "fpA" });
const CAP_B = headCapture({
  bytes: "response-B",
  s: sig("B"),
  p: sig("A"),
  fpLabel: "fpB",
});
const CAP_C = headCapture({
  bytes: "response-C",
  s: sig("C"),
  p: sig("B"),
  fpLabel: "fpC",
});
const CAP_A_RET = headCapture({ bytes: "response-A", s: sig("A"), p: "", fpLabel: "fpA" });

const project = (capture: SequenceCapture) => ({
  endpointFingerprint: ENDPOINT_FP,
  walletId: null as string | null,
  httpStatus: 200,
  walletRole: "sender" as const,
  bAmount: "5.5",
  innerPreimageText: "inner",
  step1Signature: capture.sSignature,
  step2Signature: capture.sSignature,
  completedTransactionText: "body",
  completedTransactionSha256: INNER_SHA,
});

describe("ledger export + retention safety (real PostgreSQL)", () => {
  let db: string | null = null;
  let reachable = false;
  let drillsRun = 0;

  const countSql = `
    SELECT json_build_object(
      'wallet_settled_ledger', (SELECT count(*)::int FROM wallet_settled_ledger),
      'operation_transactions', (SELECT count(*)::int FROM operation_transactions),
      'external_send_partials', (SELECT count(*)::int FROM external_send_partials),
      'gateway_observations', (SELECT count(*)::int FROM gateway_observations),
      'observation_anomalies', (SELECT count(*)::int FROM observation_anomalies),
      'operation_expected_artifacts', (SELECT count(*)::int FROM operation_expected_artifacts),
      'operation_approvals', (SELECT count(*)::int FROM operation_approvals),
      'node_events', (SELECT count(*)::int FROM node_events),
      'audit_log', (SELECT count(*)::int FROM audit_log),
      'operations', (SELECT count(*)::int FROM operations)
    )::text`;

  beforeAll(() => {
    reachable = probePostgres();
    if (!reachable) {
      if (PG_REQUIRED) throw new Error("PG_REQUIRED=1 but Postgres is unreachable");
      return;
    }
    db = `${DB_PREFIX}${Date.now()}_${process.pid}`;
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE "${db}"`);

    applyFile(db, "base-enums-domains.sql");

    applyDdl(
      db,
      `
      CREATE TABLE nodes (id uuid PRIMARY KEY);
      CREATE TABLE wallets (
        id uuid PRIMARY KEY,
        public_key padded_base64url_pubkey NOT NULL
      );
      CREATE TABLE node_signing_keys (id uuid PRIMARY KEY);
      CREATE TABLE operations (
        id uuid PRIMARY KEY,
        kind operation_kind NOT NULL,
        status operation_status NOT NULL DEFAULT 'CREATED',
        amount_zkz zkz_amount_positive_text,
        client_reference text,
        description text,
        verification_material_available_until timestamptz,
        terminal_at timestamptz
      );
      CREATE TABLE operation_approvals (
        id uuid PRIMARY KEY,
        operation_id uuid UNIQUE REFERENCES operations(id),
        preimage_text text NOT NULL,
        preimage_sha256 sha256_hex NOT NULL,
        purpose text NOT NULL DEFAULT 'zp-send-external-approval-v1',
        created_at timestamptz NOT NULL DEFAULT now()
      );
      ${frozenTable("operations.sql", "operation_wallets")}
      ${frozenTable("transaction-material.sql", "operation_transactions")}
      ${frozenTable("transaction-material.sql", "external_send_partials")}
      CREATE TABLE operation_verifications (
        id uuid PRIMARY KEY,
        operation_id uuid NOT NULL REFERENCES operations(id),
        landing_proof_id uuid,
        verdict verification_verdict NOT NULL
      );
      CREATE TABLE operation_expected_artifacts (
        id uuid PRIMARY KEY,
        operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
        purpose text NOT NULL,
        canonical_version integer NOT NULL DEFAULT 1,
        signing_key_id uuid NOT NULL REFERENCES node_signing_keys(id),
        preimage_text text NOT NULL,
        preimage_sha256 sha256_hex NOT NULL,
        signature padded_base64url_signature NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CHECK (octet_length(preimage_text) > 0)
      );
      `,
      "prerequisites",
    );

    // observation-ledger owns reporting_reject_immutable_change — keep the function.
    applyFile(db, "observation-ledger.sql", { stripDomainsTypes: true });
    // anomaly-indexes depends on the rejector already present; do not re-create it.
    applyFile(db, "observation-anomaly-indexes.sql", {
      stripDomainsTypes: true,
      stripRejector: true,
    });
    applyFile(db, "observation-stores.sql", { stripDomainsTypes: true });

    applyDdl(
      db,
      stripRejector(
        stripDomains(stripTypes(readFileSync(join(SCHEMA_DIR, "event-ledger.sql"), "utf8"))),
      ),
      "event-ledger",
    );
    applyDdl(
      db,
      stripRejector(
        stripDomains(stripTypes(readFileSync(join(SCHEMA_DIR, "audit-log.sql"), "utf8"))),
      ),
      "audit-log",
    );
    applyDdl(db, ledgerDdl(), "wallet-settled-ledger");

    psqlMust(
      db,
      `INSERT INTO nodes (id) VALUES ('${NODE_ID}');
       INSERT INTO node_signing_keys (id) VALUES ('${SIGNING_KEY_ID}');
       INSERT INTO wallets (id, public_key) VALUES
         ('${WALLET_A}', '${KEY_A}'), ('${WALLET_B}', '${KEY_B}');
       INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
         VALUES ('${OBSERVER_ID}', 'NODE', '${NODE_ID}', '${ENDPOINT_FP}', now());
       INSERT INTO node_event_seq_counters (node_id, next_seq) VALUES ('${NODE_ID}', 2);`,
    );

    const untilIso = "2026-08-26 12:00:00+00";
    psqlMust(
      db,
      `INSERT INTO operations (id, kind, status, amount_zkz, client_reference, description,
          verification_material_available_until, terminal_at)
         VALUES
         ('${OP_MOVE}', 'MOVE_INTERNAL', 'INTERNAL_MOVE_LANDED', '0.01000000',
          'client-ref-move', 'desc-move', '${untilIso}', '${SETTLED_AT}'),
         ('${OP_RECEIVE}', 'RECEIVE_EXTERNAL', 'RECEIVE_LANDED', '0.01000000',
          'client-ref-recv', 'desc-recv', '${untilIso}', '${SETTLED_AT}');
       INSERT INTO operation_wallets (operation_id, wallet_id, operation_role) VALUES
         ('${OP_MOVE}', '${WALLET_A}', 'SOURCE'),
         ('${OP_MOVE}', '${WALLET_B}', 'DESTINATION'),
         ('${OP_RECEIVE}', '${WALLET_A}', 'RECEIVER');
       INSERT INTO operation_transactions (
         operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
         step_1_signature, step_2_preimage_text, step_2_preimage_sha256, step_2_signature,
         completed_transaction_text, completed_transaction_sha256, settled_at, formed_at
       ) VALUES
         ('${OP_MOVE}', 1, 'SETTLED_BODY_PERSISTED', 'inner', '${INNER_SHA}',
          '${SIG}', 'step2', '${INNER_SHA}', '${SIG}',
          ${lit(SETTLED_TEXT)}, '${SETTLED_SHA}', '${SETTLED_AT}', now()),
         ('${OP_RECEIVE}', 1, 'SETTLED_BODY_PERSISTED', 'inner', '${INNER_SHA}',
          '${SIG}', 'step2', '${INNER_SHA}', '${SIG}',
          ${lit(RECEIVE_TEXT)}, '${RECEIVE_SHA}', '${SETTLED_AT}', now());
       INSERT INTO operation_verifications (id, operation_id, landing_proof_id, verdict)
         VALUES (gen_random_uuid(), '${OP_MOVE}', '${PROOF_MOVE}', 'VERIFIED'),
                (gen_random_uuid(), '${OP_RECEIVE}', '${PROOF_RECEIVE}', 'VERIFIED');
       INSERT INTO operation_approvals (id, operation_id, preimage_text, preimage_sha256)
         VALUES ('${APPROVAL_ID}', '${OP_RECEIVE}', ${lit(APPROVAL_PREIMAGE)}, '${APPROVAL_SHA}');
       INSERT INTO external_send_partials (
         operation_id, approval_id, inner_sha256, step_1_signature,
         transfer_code_text, transfer_code_sha256, persisted_at
       ) VALUES (
         '${OP_RECEIVE}', '${APPROVAL_ID}', '${INNER_SHA}', '${SIG}',
         ${lit(PARTIAL_TEXT)}, '${PARTIAL_SHA}', now()
       );
       INSERT INTO operation_expected_artifacts (
         id, operation_id, purpose, canonical_version, signing_key_id,
         preimage_text, preimage_sha256, signature
       ) VALUES (
         '${ARTIFACT_ID}', '${OP_MOVE}', 'zp-move-internal-expected-v1', 1, '${SIGNING_KEY_ID}',
         ${lit(ARTIFACT_PREIMAGE)}, '${ARTIFACT_SHA}', '${SIG}'
       );
       INSERT INTO node_events (
         seq, event_id, canonical_version, node_id, operation_id, wallet_id, event_type,
         data_text, data_sha256, preimage_text, preimage_sha256, signing_key_id, signature,
         previous_event_hash, event_hash, created_at
       ) VALUES (
         1, '${EVENT_ID}', 1, '${NODE_ID}', '${OP_MOVE}', '${WALLET_A}',
         'internal_move.landed', ${lit(EVENT_DATA)}, '${EVENT_DATA_SHA}',
         ${lit(EVENT_PREIMAGE)}, '${EVENT_PREIMAGE_SHA}', '${SIGNING_KEY_ID}', '${SIG}',
         NULL, '${HEX_B}', '2026-07-27T12:00:00Z'
       );
       INSERT INTO audit_log (
         id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
         details_text, details_sha256, created_at
       ) VALUES (
         '${AUDIT_ID}', '${NODE_ID}', 'SYSTEM', NULL, 'move.landed',
         '${OP_MOVE}', '${WALLET_A}', ${lit(AUDIT_DETAILS)}, '${AUDIT_SHA}',
         '2026-07-27T12:00:00Z'
       );`,
    );

    const insertLeg = (
      walletId: string,
      key: string,
      opId: string,
      role: string,
      proofId: string,
      text: string,
      sha: string,
      amount: string,
    ): void => {
      psqlMust(
        db!,
        `INSERT INTO wallet_settled_ledger (
           id, wallet_id, wallet_public_key, operation_id, attempt_no, operation_role,
           amount_zkz, settled_transaction_text, settled_transaction_sha256,
           landing_proof_id, landing_verdict, settled_at
         ) VALUES (
           gen_random_uuid(), '${walletId}', '${key}', '${opId}', 1, '${role}',
           '${amount}', ${lit(text)}, '${sha}',
           '${proofId}', 'LANDED_EXACT', '${SETTLED_AT}'
         );`,
      );
    };
    insertLeg(WALLET_A, KEY_A, OP_MOVE, "SOURCE", PROOF_MOVE, SETTLED_TEXT, SETTLED_SHA, "0.01000000");
    insertLeg(WALLET_B, KEY_B, OP_MOVE, "DESTINATION", PROOF_MOVE, SETTLED_TEXT, SETTLED_SHA, "0.01000000");
    insertLeg(
      WALLET_A,
      KEY_A,
      OP_RECEIVE,
      "RECEIVER",
      PROOF_RECEIVE,
      RECEIVE_TEXT,
      RECEIVE_SHA,
      "0.01000001",
    );
  }, 90_000);

  afterAll(() => {
    if (db !== null && reachable) {
      runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
    }
    if (reachable && drillsRun < EXPECTED_DRILLS) {
      throw new Error(`PG drills incomplete: ran ${drillsRun}/${EXPECTED_DRILLS}`);
    }
  });

  const skip = (): boolean => {
    if (!reachable || db === null) {
      if (PG_REQUIRED) throw new Error("PG_REQUIRED but suite did not initialise");
      return true;
    }
    return false;
  };

  const counts = (): Record<string, number> =>
    JSON.parse(psqlMust(db!, countSql).trim()) as Record<string, number>;

  it("1. exact-content columns survive insert/read; digests recomputed from READ-BACK bytes", () => {
    if (skip()) return;
    drillsRun += 1;

    const checks: Array<{ sql: string; expectHex: string; expectSha: string }> = [
      {
        sql: `SELECT encode(convert_to(settled_transaction_text,'UTF8'),'hex') || '|' ||
                     settled_transaction_sha256 || '|' || settled_transaction_text
                FROM wallet_settled_ledger
               WHERE operation_id='${OP_MOVE}' AND operation_role='SOURCE'`,
        expectHex: hexOf(SETTLED_TEXT),
        expectSha: SETTLED_SHA,
      },
      {
        sql: `SELECT encode(convert_to(completed_transaction_text,'UTF8'),'hex') || '|' ||
                     completed_transaction_sha256 || '|' || completed_transaction_text
                FROM operation_transactions WHERE operation_id='${OP_MOVE}'`,
        expectHex: hexOf(SETTLED_TEXT),
        expectSha: SETTLED_SHA,
      },
      {
        sql: `SELECT encode(convert_to(transfer_code_text,'UTF8'),'hex') || '|' ||
                     transfer_code_sha256 || '|' || transfer_code_text
                FROM external_send_partials WHERE operation_id='${OP_RECEIVE}'`,
        expectHex: hexOf(PARTIAL_TEXT),
        expectSha: PARTIAL_SHA,
      },
      {
        sql: `SELECT encode(convert_to(preimage_text,'UTF8'),'hex') || '|' ||
                     preimage_sha256 || '|' || preimage_text
                FROM operation_expected_artifacts WHERE id='${ARTIFACT_ID}'`,
        expectHex: hexOf(ARTIFACT_PREIMAGE),
        expectSha: ARTIFACT_SHA,
      },
      {
        sql: `SELECT encode(convert_to(preimage_text,'UTF8'),'hex') || '|' ||
                     preimage_sha256 || '|' || preimage_text
                FROM operation_approvals WHERE id='${APPROVAL_ID}'`,
        expectHex: hexOf(APPROVAL_PREIMAGE),
        expectSha: APPROVAL_SHA,
      },
      {
        sql: `SELECT encode(convert_to(details_text,'UTF8'),'hex') || '|' ||
                     details_sha256 || '|' || details_text
                FROM audit_log WHERE id='${AUDIT_ID}'`,
        expectHex: hexOf(AUDIT_DETAILS),
        expectSha: AUDIT_SHA,
      },
    ];

    for (const c of checks) {
      const row = psqlMust(db!, c.sql).trim();
      const [hex, storedSha, text] = row.split("|");
      expect(hex).toBe(c.expectHex);
      expect(text).toBeDefined();
      expect(sha256Hex(text!)).toBe(c.expectSha);
      expect(storedSha).toBe(c.expectSha);
      expect(storedSha).toBe(sha256Hex(text!));
    }

    const eventRow = psqlMust(
      db!,
      `SELECT encode(convert_to(data_text,'UTF8'),'hex') || '|' || data_sha256 || '|' ||
              data_text || '|' || encode(convert_to(preimage_text,'UTF8'),'hex') || '|' ||
              preimage_sha256 || '|' || preimage_text
         FROM node_events WHERE event_id='${EVENT_ID}'`,
    ).trim();
    const [dHex, dSha, dText, pHex, pSha, pText] = eventRow.split("|");
    expect(dHex).toBe(hexOf(EVENT_DATA));
    expect(sha256Hex(dText!)).toBe(dSha);
    expect(dSha).toBe(EVENT_DATA_SHA);
    expect(pHex).toBe(hexOf(EVENT_PREIMAGE));
    expect(sha256Hex(pText!)).toBe(pSha);
    expect(pSha).toBe(EVENT_PREIMAGE_SHA);
  });

  it("2. MOVE_INTERNAL produces exactly two ledger rows (SOURCE+DESTINATION) on one attempt body", () => {
    if (skip()) return;
    drillsRun += 1;

    expect(
      psqlMust(
        db!,
        `SELECT string_agg(operation_role, ',' ORDER BY operation_role)
           FROM wallet_settled_ledger WHERE operation_id='${OP_MOVE}'`,
      ).trim(),
    ).toBe("DESTINATION,SOURCE");

    expect(
      psqlMust(
        db!,
        `SELECT count(DISTINCT settled_transaction_sha256)
           FROM wallet_settled_ledger WHERE operation_id='${OP_MOVE}'`,
      ).trim(),
    ).toBe("1");

    expect(
      psqlMust(
        db!,
        `SELECT count(*) FROM operation_transactions WHERE operation_id='${OP_MOVE}'`,
      ).trim(),
    ).toBe("1");

    expect(
      psqlMust(
        db!,
        `SELECT count(*) FROM wallet_settled_ledger l
           JOIN operation_transactions t
             ON (t.operation_id, t.attempt_no) = (l.operation_id, l.attempt_no)
          WHERE l.operation_id='${OP_MOVE}'
            AND convert_to(l.settled_transaction_text,'UTF8')
                = convert_to(t.completed_transaction_text,'UTF8')`,
      ).trim(),
    ).toBe("2");
  });

  it("3. settlement replay never produces a second ledger row or mutates existing bytes", () => {
    if (skip()) return;
    drillsRun += 1;

    const before = psqlMust(
      db!,
      `SELECT count(*) || '|' ||
              string_agg(encode(convert_to(settled_transaction_text,'UTF8'),'hex'), ','
                         ORDER BY operation_role)
         FROM wallet_settled_ledger WHERE operation_id='${OP_MOVE}'`,
    ).trim();

    const dup = runPsql(
      db!,
      `INSERT INTO wallet_settled_ledger (
         id, wallet_id, wallet_public_key, operation_id, attempt_no, operation_role,
         amount_zkz, settled_transaction_text, settled_transaction_sha256,
         landing_proof_id, landing_verdict, settled_at
       ) VALUES (
         gen_random_uuid(), '${WALLET_A}', '${KEY_A}', '${OP_MOVE}', 1, 'SOURCE',
         '0.01000000', ${lit(SETTLED_TEXT)}, '${SETTLED_SHA}',
         '${PROOF_MOVE}', 'LANDED_EXACT', '${SETTLED_AT}'
       );`,
      true,
    );
    expect(dup.ok).toBe(false);
    expect(dup.stderr).toMatch(
      /23505|wallet_settled_ledger_wallet_signature_uniq|wallet_settled_ledger_one_row_per_role_uniq/,
    );

    const after = psqlMust(
      db!,
      `SELECT count(*) || '|' ||
              string_agg(encode(convert_to(settled_transaction_text,'UTF8'),'hex'), ','
                         ORDER BY operation_role)
         FROM wallet_settled_ledger WHERE operation_id='${OP_MOVE}'`,
    ).trim();
    expect(after).toBe(before);
  });

  it("4. verification-material transitions 409→200→410; 410 carries zero evidence bytes", async () => {
    if (skip()) return;
    drillsRun += 1;

    const terminalAtMs = Date.parse("2026-07-27T12:00:00.000Z");
    const untilMs = verificationMaterialAvailableUntilMs(terminalAtMs);
    expect(untilMs - terminalAtMs).toBe(DEFAULT_PROOF_ACCESS_WINDOW_MS);

    const colMs = Number(
      psqlMust(
        db!,
        `SELECT (extract(epoch FROM verification_material_available_until) * 1000)::bigint
           FROM operations WHERE id='${OP_MOVE}'`,
      ).trim(),
    );
    expect(colMs).toBe(untilMs);

    const material = {
      operation_type: "MOVE_INTERNAL",
      state: "INTERNAL_MOVE_LANDED",
      landed_attempt_no: 1,
      expected_artifact: { preimage: ARTIFACT_PREIMAGE },
      observation_evidence: [{ id: "obs-1" }],
      attempts: [{ attempt_no: 1, body: SETTLED_TEXT }],
      ancestor_proofs: [{ proof_id: PROOF_MOVE }],
    } as const;

    const sourceOf = (row: VerificationMaterialRow | null): VerificationMaterialSource => ({
      load: async (operationId, tenantId) =>
        operationId === OP_MOVE && tenantId === "tenant-a" ? row : null,
    });

    const get = async (row: VerificationMaterialRow | null, nowMs: number) =>
      handleGetVerificationMaterial(
        {
          requestId: randomUUID(),
          operationId: OP_MOVE,
          tenantId: "tenant-a",
          nowMs,
        },
        sourceOf(row),
      );

    const notReady = await get(
      {
        kind: "MOVE_INTERNAL",
        status: "CREATED",
        verificationMaterialAvailableUntilMs: untilMs,
        material,
      },
      terminalAtMs + 1_000,
    );
    expect(notReady.status).toBe(409);
    expect(JSON.parse(notReady.body).error.code).toBe("verification_material_not_ready");
    expect(notReady.body).not.toContain(SETTLED_TEXT);
    expect(notReady.body).not.toContain(ARTIFACT_PREIMAGE);
    expect(notReady.body).not.toContain("observation_evidence");

    const ok = await get(
      {
        kind: "MOVE_INTERNAL",
        status: "INTERNAL_MOVE_LANDED",
        verificationMaterialAvailableUntilMs: untilMs,
        material,
      },
      terminalAtMs + 1_000,
    );
    expect(ok.status).toBe(200);
    const okBody = JSON.parse(ok.body) as {
      operation_id: string;
      available_until: string;
      attempts: unknown;
    };
    expect(okBody.operation_id).toBe(OP_MOVE);
    expect(okBody.available_until).toBe(new Date(untilMs).toISOString());
    expect(okBody.attempts).toEqual(material.attempts);

    const expired = await get(
      {
        kind: "MOVE_INTERNAL",
        status: "INTERNAL_MOVE_LANDED",
        verificationMaterialAvailableUntilMs: untilMs,
        material,
      },
      untilMs,
    );
    expect(expired.status).toBe(410);
    const expiredParsed = JSON.parse(expired.body) as {
      error: { code: string };
      attempts?: unknown;
      observation_evidence?: unknown;
      expected_artifact?: unknown;
      ancestor_proofs?: unknown;
    };
    expect(expiredParsed.error.code).toBe("verification_material_expired");
    expect(expiredParsed.attempts).toBeUndefined();
    expect(expiredParsed.observation_evidence).toBeUndefined();
    expect(expiredParsed.expected_artifact).toBeUndefined();
    expect(expiredParsed.ancestor_proofs).toBeUndefined();
    expect(expired.body).not.toContain(SETTLED_TEXT);
    expect(expired.body).not.toContain(ARTIFACT_PREIMAGE);
    expect(expired.body).not.toContain(PROOF_MOVE);
    expect(psqlMust(db!, `SELECT count(*) FROM wallet_settled_ledger`).trim()).not.toBe("0");
    expect(
      psqlMust(
        db!,
        `SELECT count(*) FROM operation_transactions WHERE operation_id='${OP_MOVE}'`,
      ).trim(),
    ).toBe("1");
  });

  it("DB-TEST-20: retention jobs revoke proof access without deleting any permanent row", async () => {
    if (skip()) return;
    drillsRun += 1;

    const before = counts();
    const ledgerHexBefore = psqlMust(
      db!,
      `SELECT string_agg(encode(convert_to(settled_transaction_text,'UTF8'),'hex'), ','
              ORDER BY id::text)
         FROM wallet_settled_ledger`,
    ).trim();
    const windowBefore = psqlMust(
      db!,
      `SELECT verification_material_available_until::text FROM operations
        WHERE id='${OP_MOVE}'`,
    ).trim();

    const terminalAtMs = Date.parse("2026-07-27T12:00:00.000Z");
    const untilMs = verificationMaterialAvailableUntilMs(terminalAtMs);
    const material = {
      operation_type: "MOVE_INTERNAL",
      state: "INTERNAL_MOVE_LANDED",
      landed_attempt_no: 1,
      expected_artifact: null,
      observation_evidence: [],
      attempts: [],
      ancestor_proofs: [],
    } as const;
    const source: VerificationMaterialSource = {
      load: async () => ({
        kind: "MOVE_INTERNAL",
        status: "INTERNAL_MOVE_LANDED",
        verificationMaterialAvailableUntilMs: untilMs,
        material,
      }),
    };
    const expired = await handleGetVerificationMaterial(
      {
        requestId: randomUUID(),
        operationId: OP_MOVE,
        tenantId: "t",
        nowMs: untilMs + 1,
      },
      source,
    );
    expect(expired.status).toBe(410);

    const retentionCode = readFileSync(join(SRC_DIR, "data/retention.ts"), "utf8");
    expect(retentionSurfaceHits(retentionCode)).toEqual([]);
    const vmCode = readFileSync(join(SRC_DIR, "api/verification-material.ts"), "utf8");
    expect(
      retentionSurfaceHits(vmCode).filter((h) => h === "DELETE_FROM" || h === "TRUNCATE"),
    ).toEqual([]);

    expect(counts()).toEqual(before);
    expect(
      psqlMust(
        db!,
        `SELECT string_agg(encode(convert_to(settled_transaction_text,'UTF8'),'hex'), ','
                ORDER BY id::text)
           FROM wallet_settled_ledger`,
      ).trim(),
    ).toBe(ledgerHexBefore);
    expect(
      psqlMust(
        db!,
        `SELECT verification_material_available_until::text FROM operations
          WHERE id='${OP_MOVE}'`,
      ).trim(),
    ).toBe(windowBefore);
  });

  it("6. pg_dump/restore preserves every evidence row byte and the retention window", () => {
    if (skip()) return;
    drillsRun += 1;

    const beforeCounts = counts();
    const beforeLedger = psqlMust(
      db!,
      `SELECT string_agg(
         operation_id::text || ':' || operation_role || ':' ||
         encode(convert_to(settled_transaction_text,'UTF8'),'hex') || ':' ||
         settled_transaction_sha256, '|' ORDER BY operation_id::text, operation_role)
         FROM wallet_settled_ledger`,
    ).trim();
    const beforePartial = psqlMust(
      db!,
      `SELECT encode(convert_to(transfer_code_text,'UTF8'),'hex') || '|' || transfer_code_sha256
         FROM external_send_partials WHERE operation_id='${OP_RECEIVE}'`,
    ).trim();
    const beforeWindow = psqlMust(
      db!,
      `SELECT id::text || '|' ||
              coalesce(verification_material_available_until::text,'') || '|' ||
              coalesce(description,'') || '|' || coalesce(client_reference,'')
         FROM operations ORDER BY id::text`,
    ).trim();
    const beforeEvents = psqlMust(
      db!,
      `SELECT encode(convert_to(data_text,'UTF8'),'hex') || '|' || data_sha256
         FROM node_events ORDER BY seq`,
    ).trim();
    const beforeAudit = psqlMust(
      db!,
      `SELECT encode(convert_to(details_text,'UTF8'),'hex') || '|' || details_sha256
         FROM audit_log ORDER BY id::text`,
    ).trim();

    const dir = mkdtempSync(join(tmpdir(), "ledger-export-"));
    const dumpPath = join(dir, "evidence.dump");
    const restoreDb = `${db}_restore`;
    try {
      execFileSync(
        "pg_dump",
        ["-d", db!, "-Fc", "-f", dumpPath, "--no-owner", "--no-acl"],
        { encoding: "utf-8", timeout: 60_000, stdio: ["ignore", "pipe", "pipe"] },
      );
      psqlMust(MAINTENANCE_DB, `DROP DATABASE IF EXISTS "${restoreDb}"`);
      psqlMust(MAINTENANCE_DB, `CREATE DATABASE "${restoreDb}"`);
      execFileSync("pg_restore", ["-d", restoreDb, "--no-owner", "--no-acl", dumpPath], {
        encoding: "utf-8",
        timeout: 60_000,
        stdio: ["ignore", "pipe", "pipe"],
      });

      expect(JSON.parse(psqlMust(restoreDb, countSql).trim())).toEqual(beforeCounts);
      expect(
        psqlMust(
          restoreDb,
          `SELECT string_agg(
             operation_id::text || ':' || operation_role || ':' ||
             encode(convert_to(settled_transaction_text,'UTF8'),'hex') || ':' ||
             settled_transaction_sha256, '|' ORDER BY operation_id::text, operation_role)
             FROM wallet_settled_ledger`,
        ).trim(),
      ).toBe(beforeLedger);
      expect(
        psqlMust(
          restoreDb,
          `SELECT encode(convert_to(transfer_code_text,'UTF8'),'hex') || '|' || transfer_code_sha256
             FROM external_send_partials WHERE operation_id='${OP_RECEIVE}'`,
        ).trim(),
      ).toBe(beforePartial);
      expect(
        psqlMust(
          restoreDb,
          `SELECT id::text || '|' ||
                  coalesce(verification_material_available_until::text,'') || '|' ||
                  coalesce(description,'') || '|' || coalesce(client_reference,'')
             FROM operations ORDER BY id::text`,
        ).trim(),
      ).toBe(beforeWindow);
      expect(
        psqlMust(
          restoreDb,
          `SELECT encode(convert_to(data_text,'UTF8'),'hex') || '|' || data_sha256
             FROM node_events ORDER BY seq`,
        ).trim(),
      ).toBe(beforeEvents);
      expect(
        psqlMust(
          restoreDb,
          `SELECT encode(convert_to(details_text,'UTF8'),'hex') || '|' || details_sha256
             FROM audit_log ORDER BY id::text`,
        ).trim(),
      ).toBe(beforeAudit);

      const restoredText = psqlMust(
        restoreDb,
        `SELECT settled_transaction_text FROM wallet_settled_ledger
          WHERE operation_id='${OP_MOVE}' AND operation_role='SOURCE'`,
      ).trim();
      expect(sha256Hex(restoredText)).toBe(SETTLED_SHA);
    } finally {
      runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS "${restoreDb}" WITH (FORCE)`);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("7. UPDATE/DELETE rejected on evidence tables; corruption caught; redaction only advisory fields", () => {
    if (skip()) return;
    drillsRun += 1;

    const before = counts();

    const obsId = "a0000000-0000-4000-8000-000000000099";
    psqlMust(
      db!,
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship,
         semantic_fingerprint, state_changed, wallet_role, s_signature, p_signature, b_amount,
         inner_preimage_text, step_1_signature, step_2_signature,
         completed_transaction_text, completed_transaction_sha256
       ) VALUES (
         '${obsId}', '${OBSERVER_ID}', '${ENDPOINT_FP}', '${KEY_A}', 9001,
         now(), E'\\\\x01', '${INNER_SHA}', 'VERIFIED_HEAD', 'FIRST',
         '${INNER_SHA}', true, 'sender', '${SIG}', '', '5.5',
         'inner', '${SIG}', '${SIG}', 'body', '${INNER_SHA}'
       );`,
    );
    const badObs = "a0000000-0000-4000-8000-000000000098";
    const anomId = "a0000000-0000-4000-8000-000000000097";
    psqlMust(
      db!,
      `BEGIN;
       INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship
       ) VALUES (
         '${badObs}', '${OBSERVER_ID}', '${ENDPOINT_FP}', '${KEY_B}', 1,
         now(), E'\\\\x00', '${HEX_B}', 'TRANSPORT_ERROR', 'NOT_APPLICABLE'
       );
       INSERT INTO observation_anomalies (
         id, observation_id, observer_id, wallet_public_key, kind, details, detected_at
       ) VALUES (
         '${anomId}', '${badObs}', '${OBSERVER_ID}', '${KEY_B}',
         'TRANSPORT_ERROR', 'transport fail', now()
       );
       COMMIT;`,
    );

    const guarded: ReadonlyArray<{
      table: string;
      update: string;
      del: string;
      marker: string;
    }> = [
      {
        table: "wallet_settled_ledger",
        update: `UPDATE wallet_settled_ledger SET amount_zkz='0.02' WHERE operation_id='${OP_MOVE}'`,
        del: `DELETE FROM wallet_settled_ledger WHERE operation_id='${OP_MOVE}'`,
        marker: "WALLET_SETTLED_LEDGER_INSERT_ONLY",
      },
      {
        table: "gateway_observations",
        update: `UPDATE gateway_observations SET raw_response_sha256='${"f".repeat(64)}'`,
        del: `DELETE FROM gateway_observations`,
        marker: "append-only",
      },
      {
        table: "observation_anomalies",
        update: `UPDATE observation_anomalies SET details='tampered'`,
        del: `DELETE FROM observation_anomalies`,
        marker: "append-only",
      },
      {
        table: "node_events",
        update: `UPDATE node_events SET data_text='tampered' WHERE event_id='${EVENT_ID}'`,
        del: `DELETE FROM node_events WHERE event_id='${EVENT_ID}'`,
        marker: "append-only",
      },
      {
        table: "audit_log",
        update: `UPDATE audit_log SET details_text='tampered' WHERE id='${AUDIT_ID}'`,
        del: `DELETE FROM audit_log WHERE id='${AUDIT_ID}'`,
        marker: "append-only",
      },
    ];

    for (const g of guarded) {
      expect(Number(psqlMust(db!, `SELECT count(*) FROM ${g.table}`).trim())).toBeGreaterThan(0);
      const up = runPsql(db!, g.update, true);
      expect(up.ok, `${g.table} UPDATE must fail`).toBe(false);
      expect(up.stderr, `${g.table} UPDATE marker`).toMatch(
        new RegExp(g.marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"),
      );
      const del = runPsql(db!, g.del, true);
      expect(del.ok, `${g.table} DELETE must fail`).toBe(false);
      expect(del.stderr, `${g.table} DELETE marker`).toMatch(
        new RegExp(g.marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"),
      );
    }

    const trunc = runPsql(db!, "TRUNCATE wallet_settled_ledger", true);
    expect(trunc.ok).toBe(false);
    expect(trunc.stderr).toContain("WALLET_SETTLED_LEDGER_INSERT_ONLY");

    const corrupt = runPsql(
      db!,
      `INSERT INTO wallet_settled_ledger (
         id, wallet_id, wallet_public_key, operation_id, attempt_no, operation_role,
         amount_zkz, settled_transaction_text, settled_transaction_sha256,
         landing_proof_id, landing_verdict, settled_at
       ) VALUES (
         gen_random_uuid(), '${WALLET_A}', '${KEY_A}', '${OP_MOVE}', 1, 'SOURCE',
         '0.01000000', ${lit(SETTLED_TEXT)}, '${"0".repeat(64)}',
         '${PROOF_MOVE}', 'LANDED_EXACT', '${SETTLED_AT}'
       );`,
      true,
    );
    expect(corrupt.ok).toBe(false);
    expect(corrupt.stderr).toMatch(
      /WALLET_SETTLED_LEDGER_NOT_VERBATIM|23505|wallet_settled_ledger/,
    );

    const truncated = runPsql(
      db!,
      `INSERT INTO wallet_settled_ledger (
         id, wallet_id, wallet_public_key, operation_id, attempt_no, operation_role,
         amount_zkz, settled_transaction_text, settled_transaction_sha256,
         landing_proof_id, landing_verdict, settled_at
       ) VALUES (
         gen_random_uuid(), '${WALLET_B}', '${KEY_B}', '${OP_MOVE}', 1, 'DESTINATION',
         '0.01000000', '', '${SETTLED_SHA}',
         '${PROOF_MOVE}', 'LANDED_EXACT', '${SETTLED_AT}'
       );`,
      true,
    );
    expect(truncated.ok).toBe(false);

    // Broken FK: fresh SEND op + settled body so uniqueness cannot fire first.
    const opFk = "a0000000-0000-4000-8000-0000000000f1";
    const proofFk = "a0000000-0000-4000-8000-0000000000f2";
    const fkText = SETTLED_TEXT.replace('"0.01000000"', '"0.01000002"');
    const fkSha = sha256Hex(fkText);
    const orphanKey = `${"Z".repeat(43)}=`;
    psqlMust(
      db!,
      `INSERT INTO operations (id, kind, status, amount_zkz)
         VALUES ('${opFk}', 'SEND_EXTERNAL', 'EXTERNAL_SEND_LANDED', '0.01000002');
       INSERT INTO operation_wallets (operation_id, wallet_id, operation_role)
         VALUES ('${opFk}', '${WALLET_A}', 'SOURCE');
       INSERT INTO operation_transactions (
         operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
         step_1_signature, step_2_preimage_text, step_2_preimage_sha256, step_2_signature,
         completed_transaction_text, completed_transaction_sha256, settled_at, formed_at
       ) VALUES (
         '${opFk}', 1, 'SETTLED_BODY_PERSISTED', 'inner', '${INNER_SHA}',
         '${SIG}', 'step2', '${INNER_SHA}', '${SIG}',
         ${lit(fkText)}, '${fkSha}', '${SETTLED_AT}', now()
       );
       INSERT INTO operation_verifications (id, operation_id, landing_proof_id, verdict)
         VALUES (gen_random_uuid(), '${opFk}', '${proofFk}', 'VERIFIED');`,
    );
    const brokenFk = runPsql(
      db!,
      `INSERT INTO wallet_settled_ledger (
         id, wallet_id, wallet_public_key, operation_id, attempt_no, operation_role,
         amount_zkz, settled_transaction_text, settled_transaction_sha256,
         landing_proof_id, landing_verdict, settled_at
       ) VALUES (
         gen_random_uuid(), 'ffffffff-ffff-4fff-8fff-ffffffffffff', '${orphanKey}',
         '${opFk}', 1, 'SOURCE', '0.01000002', ${lit(fkText)}, '${fkSha}',
         '${proofFk}', 'LANDED_EXACT', '${SETTLED_AT}'
       );`,
      true,
    );
    expect(brokenFk.ok).toBe(false);
    expect(brokenFk.stderr).toMatch(/23503|foreign key/i);

    const rows = psqlMust(
      db!,
      `SELECT settled_transaction_text || E'\\t' || settled_transaction_sha256
         FROM wallet_settled_ledger`,
    )
      .trim()
      .split("\n")
      .filter(Boolean);
    for (const line of rows) {
      const tab = line.indexOf("\t");
      expect(sha256Hex(line.slice(0, tab))).toBe(line.slice(tab + 1));
    }
    const sample = rows[0]!;
    const tab = sample.indexOf("\t");
    const goodText = sample.slice(0, tab);
    const goodSha = sample.slice(tab + 1);
    expect(sha256Hex(goodText.slice(0, Math.max(0, goodText.length - 1)))).not.toBe(goodSha);

    const redact = runPsql(
      db!,
      `UPDATE operations
          SET description = 'REDACTED', client_reference = 'REDACTED'
        WHERE id='${OP_MOVE}'
        RETURNING description, client_reference, amount_zkz::text`,
    );
    expect(redact.ok, redact.stderr).toBe(true);
    expect(redact.stdout.trim().startsWith("REDACTED|REDACTED|")).toBe(true);
    expect(
      psqlMust(db!, `SELECT amount_zkz FROM operations WHERE id='${OP_MOVE}'`).trim(),
    ).toBe("0.01000000");

    const after = counts();
    expect(after.wallet_settled_ledger).toBe(before.wallet_settled_ledger);
    expect(after.operation_transactions).toBeGreaterThanOrEqual(before.operation_transactions);
    expect(after.external_send_partials).toBe(before.external_send_partials);
    expect(after.node_events).toBe(before.node_events);
    expect(after.audit_log).toBe(before.audit_log);
    expect(after.operation_expected_artifacts).toBe(before.operation_expected_artifacts);
    expect(after.operation_approvals).toBe(before.operation_approvals);
    expect(
      psqlMust(
        db!,
        `SELECT encode(convert_to(settled_transaction_text,'UTF8'),'hex')
           FROM wallet_settled_ledger
          WHERE operation_id='${OP_MOVE}' AND operation_role='SOURCE'`,
      ).trim(),
    ).toBe(hexOf(SETTLED_TEXT));

    const stillGuarded = runPsql(
      db!,
      `UPDATE node_events SET data_text='nope' WHERE event_id='${EVENT_ID}'`,
      true,
    );
    expect(stillGuarded.ok).toBe(false);
  });

  it("8. gateway_observations A,B,C,A via writer path yields four rows (final REGRESSION)", async () => {
    if (skip()) return;
    drillsRun += 1;

    const pk = `${"W".repeat(43)}=`;
    const key: ObservationStreamKey = { observerId: OBSERVER_ID, walletPublicKey: pk };

    class PsqlSession {
      readonly child: ChildProcessWithoutNullStreams;
      readonly pending: Array<{
        resolve: (line: string) => void;
        reject: (err: Error) => void;
      }> = [];
      buffer = "";
      closed = false;
      stderrBuf = "";

      constructor(database: string) {
        this.child = spawn(
          "psql",
          ["-d", database, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"],
          { stdio: ["pipe", "pipe", "pipe"] },
        );
        this.child.stdout.setEncoding("utf8");
        this.child.stderr.setEncoding("utf8");
        this.child.stdout.on("data", (chunk: string) => {
          this.buffer += chunk;
          let newline = this.buffer.indexOf("\n");
          while (newline !== -1) {
            const line = this.buffer.slice(0, newline);
            this.buffer = this.buffer.slice(newline + 1);
            const waiter = this.pending.shift();
            if (waiter) waiter.resolve(line);
            newline = this.buffer.indexOf("\n");
          }
        });
        this.child.stderr.on("data", (chunk: string) => {
          this.stderrBuf += chunk;
        });
        this.child.on("close", () => {
          this.closed = true;
          while (this.pending.length > 0) {
            this.pending.shift()!.reject(new Error(`psql session closed: ${this.stderrBuf}`));
          }
        });
      }

      async writeLine(payload: string): Promise<string> {
        if (this.closed) throw new Error("psql session already closed");
        this.stderrBuf = "";
        const line = await new Promise<string>((resolve, reject) => {
          this.pending.push({ resolve, reject });
          this.child.stdin.write(payload);
        });
        if (this.stderrBuf.trim()) throw new Error(this.stderrBuf.trim());
        return line.trim();
      }

      async exec(sql: string): Promise<void> {
        await this.writeLine(`${sql.replace(/;\s*$/, "")}; SELECT 'ok';\n`);
      }

      async selectJson(sql: string): Promise<string> {
        const wrapped = `SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json)::text FROM (${sql.replace(/;\s*$/, "")}) q`;
        return this.writeLine(`${wrapped};\n`);
      }

      kill(): void {
        try {
          this.child.stdin.end();
        } catch {
          /* ignore */
        }
        this.child.kill("SIGKILL");
      }
    }

    const session = new PsqlSession(db!);
    const sessionSql: SqlExecutor = {
      async query<R>(qtext: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
        let sql = qtext;
        for (let n = params.length; n >= 1; n -= 1) {
          sql = sql.replaceAll(`$${n}`, sqlLiteral(params[n - 1]));
        }
        if (!/^\s*(SELECT|WITH)\b/i.test(sql)) {
          await session.exec(sql);
          return { rows: [] };
        }
        const raw = await session.selectJson(sql);
        const rows = JSON.parse(raw === "" ? "[]" : raw) as R[];
        for (const row of rows as Array<Record<string, unknown>>) {
          if (typeof row.raw_response_bytes === "string") {
            const s = row.raw_response_bytes as string;
            if (s.startsWith("\\x")) row.raw_response_bytes = Buffer.from(s.slice(2), "hex");
          }
        }
        return { rows: Array.isArray(rows) ? rows : [] };
      },
    };

    try {
      const base = createSqlStreamWriterEffects({
        sql: sessionSql,
        project,
        takeAdvisoryLock: false,
        onAnomalyRequired: async ({ key: k, observationId, result, capture }) => {
          const kind =
            result.plan.kind === "APPEND" &&
            (result.plan.observation.relationship === "REGRESSION" ||
              result.plan.observation.relationship === "UNEXPLAINED_JUMP" ||
              result.plan.observation.relationship === "GENESIS_AFTER_HISTORY" ||
              result.plan.observation.relationship === "SIGNATURE_COLLISION")
              ? result.plan.observation.relationship
              : capture.parseResult;
          await sessionSql.query(
            `INSERT INTO observation_anomalies (
               id, observation_id, observer_id, wallet_public_key, kind, details, detected_at
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)`,
            [
              randomUUID(),
              observationId,
              k.observerId,
              k.walletPublicKey,
              kind,
              `anomaly:${kind}`,
              new Date(),
            ],
          );
        },
      });

      const effects = {
        async loadPrior(k: ObservationStreamKey) {
          await session.exec("BEGIN");
          try {
            return await base.loadPrior(k);
          } catch (err) {
            await session.exec("ROLLBACK").catch(() => undefined);
            throw err;
          }
        },
        async apply(
          k: ObservationStreamKey,
          result: Parameters<typeof base.apply>[1],
          capture: SequenceCapture,
        ) {
          try {
            await base.apply(k, result, capture);
            await session.exec("COMMIT");
          } catch (err) {
            await session.exec("ROLLBACK").catch(() => undefined);
            throw err;
          }
        },
      };

      const writer = createSerializedStreamWriter(effects);
      const r1 = await writer.capture(key, CAP_A);
      const r2 = await writer.capture(key, CAP_B);
      const r3 = await writer.capture(key, CAP_C);
      const r4 = await writer.capture(key, CAP_A_RET);

      expect([r1, r2, r3, r4].map((r) => r.plan.kind)).toEqual([
        "APPEND",
        "APPEND",
        "APPEND",
        "APPEND",
      ]);
      expect(
        [r1, r2, r3, r4].map((r) =>
          r.plan.kind === "APPEND" ? r.plan.observation.relationship : null,
        ),
      ).toEqual(["FIRST", "SUCCESSOR", "SUCCESSOR", "REGRESSION"]);

      expect(
        psqlMust(
          db!,
          `SELECT count(*) FROM gateway_observations
            WHERE observer_id='${OBSERVER_ID}' AND wallet_public_key='${pk}'`,
        ).trim(),
      ).toBe("4");

      expect(
        psqlMust(
          db!,
          `SELECT string_agg(relationship::text, ',' ORDER BY wallet_seq)
             FROM gateway_observations
            WHERE observer_id='${OBSERVER_ID}' AND wallet_public_key='${pk}'`,
        ).trim(),
      ).toBe("FIRST,SUCCESSOR,SUCCESSOR,REGRESSION");

      expect(
        psqlMust(
          db!,
          `SELECT count(*) FROM observation_anomalies a
             JOIN gateway_observations o ON o.id = a.observation_id
            WHERE o.observer_id='${OBSERVER_ID}' AND o.wallet_public_key='${pk}'
              AND a.kind='REGRESSION'`,
        ).trim(),
      ).toBe("1");

      const bodies = psqlMust(
        db!,
        `SELECT encode(raw_response_bytes,'hex') || '|' || raw_response_sha256
           FROM gateway_observations
          WHERE observer_id='${OBSERVER_ID}' AND wallet_public_key='${pk}'
          ORDER BY wallet_seq`,
      )
        .trim()
        .split("\n");
      expect(bodies).toHaveLength(4);
      for (const line of bodies) {
        const [hex, sha] = line.split("|");
        expect(createHash("sha256").update(Buffer.from(hex!, "hex")).digest("hex")).toBe(sha);
      }
      expect(bodies[0]!.split("|")[0]).toBe(bodies[3]!.split("|")[0]);
    } finally {
      session.kill();
    }
  });

  it("9. node-core retention/verification surface has zero DELETE against evidence tables", () => {
    drillsRun += 1;
    const files = [
      join(SRC_DIR, "data/retention.ts"),
      join(SRC_DIR, "api/verification-material.ts"),
      join(SRC_DIR, "observation/storage-budget.ts"),
    ];
    for (const file of files) {
      const src = readFileSync(file, "utf8");
      expect(retentionSurfaceHits(src).filter((h) => h !== "UPDATE"), file).toEqual([]);
    }
    const retentionTs = readFileSync(join(SRC_DIR, "data/retention.ts"), "utf8");
    expect(retentionTs).toMatch(/revokes? access/);
    expect(retentionTs).toMatch(/no purge|never delete|NO row is ever removed/i);
  });

  
  it("9b. plant: string-borne comment opener no longer hides DELETE FROM", () => {
    const plant =
      'const route = "/admin/v1/*";\n' +
      'await db.query("DELETE FROM wallet_settled_ledger");\n' +
      'const end = "*/";\n';
    expect(retentionSurfaceHits(plant)).toContain("DELETE_FROM");
    const stripped = legacyStripComments(plant);
    expect(/\bDELETE\s+FROM\b/i.test(stripped)).toBe(false);
  });

  it("10. per-wallet ledger export covers every settled leg with recomputed digests", () => {
    if (skip()) return;
    drillsRun += 1;

    const exportJson = psqlMust(
      db!,
      `SELECT coalesce(json_agg(section ORDER BY (section->>'wallet_public_key')), '[]'::json)::text
         FROM (
           SELECT json_build_object(
             'wallet_public_key', l.wallet_public_key,
             'rows', (
               SELECT coalesce(json_agg(row_to_json(r) ORDER BY r.settled_at, r.id::text), '[]'::json)
                 FROM (
                   SELECT id, operation_id, operation_role, amount_zkz,
                          settled_transaction_text, settled_transaction_sha256, settled_at
                     FROM wallet_settled_ledger l2
                    WHERE l2.wallet_public_key = l.wallet_public_key
                 ) r
             )
           ) AS section
             FROM (SELECT DISTINCT wallet_public_key FROM wallet_settled_ledger) l
         ) s`,
    ).trim();

    const sections = JSON.parse(exportJson) as Array<{
      wallet_public_key: string;
      rows: Array<{
        operation_id: string;
        operation_role: string;
        settled_transaction_text: string;
        settled_transaction_sha256: string;
      }>;
    }>;

    expect(sections.map((s) => s.wallet_public_key).sort()).toEqual([KEY_A, KEY_B].sort());

    const sectionA = sections.find((s) => s.wallet_public_key === KEY_A)!;
    const sectionB = sections.find((s) => s.wallet_public_key === KEY_B)!;
    expect(sectionA.rows.map((r) => r.operation_role).sort()).toEqual(["RECEIVER", "SOURCE"]);
    expect(sectionB.rows.map((r) => r.operation_role)).toEqual(["DESTINATION"]);

    for (const section of sections) {
      for (const row of section.rows) {
        expect(sha256Hex(row.settled_transaction_text)).toBe(row.settled_transaction_sha256);
        expect([SETTLED_TEXT, RECEIVE_TEXT]).toContain(row.settled_transaction_text);
      }
    }

    const exportedIds = sections.flatMap((s) =>
      s.rows.map((r) => `${r.operation_id}:${r.operation_role}`),
    );
    const dbIds = psqlMust(
      db!,
      `SELECT string_agg(operation_id::text || ':' || operation_role, ','
              ORDER BY operation_id::text, operation_role)
         FROM wallet_settled_ledger`,
    )
      .trim()
      .split(",");
    expect(exportedIds.sort()).toEqual(dbIds.sort());
  });
});