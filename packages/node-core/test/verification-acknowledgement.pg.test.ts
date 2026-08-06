// The acknowledgement + group-release layer against a real PostgreSQL.
//
// The acceptance criteria that are RUNTIME criteria live here, not in the unit suite:
// The constraints have to be the ones refusing, the group predicate has to read real
// `lease_group_operations` / `verification_ack_wallet_evidence` rows, and a conflicting replay
// has to leave the durable verdict and the wallet lease untouched.
//
// Governing rules: the acknowledgement + evidence tables (DDL owned by the acknowledgement
// slice; this slice reads and writes it), the lease group / membership tables, the two
// database test obligations, and the `lease_release_status` contract.
//
// Schema: the frozen .sql slices are contract text, each written to be applied ALONE by the
// schema phase (see migration-integrity.test.ts), so each redeclares the shared
// reference domains. `buildSchema` below concatenates the prerequisite slices and drops a
// repeated CREATE of an object already declared, then appends the two acknowledgement
// tables extracted BYTE-EXACT from verification-proofs.sql. The rest of that file — the
// forward references, the reporting_assert_completed_mutation correlation trigger (now gated
// by receive_arms; this test deliberately exercises only the acknowledgement tables
// themselves, not the correlation path), and the node_runtime REVOKEs — is deliberately NOT
// applied: the correlation trigger/proof path is tested by proof-access-verdict-history.pg.test.ts
// and the arm-sql-schema-pin.test.ts unit suite.
//
// Connectivity: TEST_DATABASE_URL (vitest.global-setup provisions one) or PG_REQUIRED
// fail-closed. Teardown drops only databases this file created (verification_ack_ prefix).

import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { splitSqlStatements } from "../src/leases/index.ts";
import {
  computeEvidenceSetSha256,
  createAcknowledgementService,
  createSqlAcknowledgementStore,
  evaluateGroupRelease,
  type AckSqlExecutor,
  type AckSqlQueryResult,
  type AckWalletEvidenceInput,
  type AcknowledgementInput,
} from "../src/verification/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

/* ─── schema assembly ─────────────────────────────────────────────── */

// Prerequisite slices in dependency sequence: reference domains, the nodes/implementers
// registries, wallets/destinations, operations, the observation ledger, the reporting
// nonce/idempotency tables, and the lease foundation.
const PREREQUISITE_SLICES = [
  "base-enums-domains.sql",
  "node-implementer-registry.sql",
  "custody-eligibility.sql",
  "operations.sql",
  "observation-ledger.sql",
  "reporting-persistence.sql",
  "lease-foundation.sql",
] as const;

/** Object identity of a CREATE statement, so a redeclaration across slices is dropped once. */
function declaredObject(statement: string): string | null {
  const flat = statement.replace(/\s+/g, " ").trim();
  const trigger =
    /^CREATE\s+(?:CONSTRAINT\s+)?TRIGGER\s+([A-Za-z_][A-Za-z0-9_]*)\b.*?\bON\s+([A-Za-z_][A-Za-z0-9_]*)/i.exec(
      flat,
    );
  if (trigger !== null) {
    return `TRIGGER ${trigger[1]!.toLowerCase()} ON ${trigger[2]!.toLowerCase()}`;
  }
  const created =
    /^CREATE\s+(?:UNIQUE\s+)?(TYPE|DOMAIN|FUNCTION|TABLE|ROLE|INDEX)\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)/i.exec(
      flat,
    );
  return created === null ? null : `${created[1]!.toUpperCase()} ${created[2]!.toLowerCase()}`;
}

/** Byte-exact extraction of one top-level block from a frozen slice. */
function extractBlock(sql: string, pattern: RegExp, label: string): string {
  const found = pattern.exec(sql);
  if (found === null) {
    throw new Error(`verification-proofs.sql: ${label} block not found`);
  }
  return found[0];
}

function buildSchema(): string {
  const seen = new Set<string>();
  const out: string[] = ["CREATE EXTENSION IF NOT EXISTS pgcrypto;"];

  const verificationProofs = readFileSync(resolve(schemaDir, "verification-proofs.sql"), "utf8");
  // The two enums the acknowledgement columns are typed against are declared by that slice.
  // Bounded by `[^;]*` rather than a line-anchored `^);$`: `reporting_request_class` is a
  // one-line CREATE TYPE, and a line-anchored close would run past it into the next block.
  for (const name of ["verification_verdict", "reporting_request_class"]) {
    const block = extractBlock(
      verificationProofs,
      new RegExp(`^CREATE TYPE ${name} AS ENUM \\([^;]*\\);`, "m"),
      name,
    );
    seen.add(declaredObject(block)!);
    out.push(block);
  }

  for (const file of PREREQUISITE_SLICES) {
    for (const statement of splitSqlStatements(readFileSync(resolve(schemaDir, file), "utf8"))) {
      const object = declaredObject(statement);
      if (object !== null) {
        if (seen.has(object)) continue;
        seen.add(object);
      }
      out.push(`${statement};`);
    }
  }

  for (const name of ["verification_acknowledgements", "verification_ack_wallet_evidence"]) {
    out.push(
      extractBlock(
        verificationProofs,
        new RegExp(`^CREATE TABLE ${name} \\([\\s\\S]*?^\\);$`, "m"),
        name,
      ),
    );
  }
  return out.join("\n");
}

/* ─── psql helpers ────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (url: string, sql: string, timeoutMs = 60_000): PsqlOutcome => {
  try {
    const stdout = execFileSync(
      "psql",
      [url, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] },
    );
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (url: string, sql: string): string => {
  const outcome = runPsql(url, sql);
  if (!outcome.ok) {
    throw new Error(`psql failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const applyFile = (url: string, sql: string): void => {
  try {
    execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-f", "-"], {
      input: sql,
      encoding: "utf-8",
      timeout: 120_000,
    });
  } catch (err) {
    throw new Error(`schema apply failed: ${((err as { stderr?: string }).stderr ?? "").trim()}`);
  }
};

const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1]!;
};

function sqlLiteral(value: unknown): string {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number") return String(value);
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (typeof value === "string") return `'${value.replace(/'/g, "''")}'`;
  throw new Error(`unsupported sql param type: ${typeof value}`);
}

function bindSql(text: string, params: readonly unknown[] = []): string {
  return text.replace(/\$(\d+)/g, (_m, n: string) => {
    const index = Number(n) - 1;
    if (index < 0 || index >= params.length) throw new Error(`missing sql param $${n}`);
    return sqlLiteral(params[index]);
  });
}

function pgEnv(url: string): NodeJS.ProcessEnv {
  const u = new URL(url);
  return {
    ...process.env,
    PGHOST: u.hostname,
    PGPORT: u.port === "" ? "5432" : u.port,
    PGUSER: decodeURIComponent(u.username),
    PGPASSWORD: decodeURIComponent(u.password),
    PGDATABASE: u.pathname.replace(/^\//, ""),
  };
}

const MARKER = "__SQL_END__";

/**
 * One `psql` OS process = one DB session, so an explicit BEGIN keeps intermediate writes and
 * FOR UPDATE locks visible until COMMIT. The service issues several statements per call and
 * must see its own acknowledgement when it reads the group back.
 */
class PsqlSession implements AckSqlExecutor {
  private child: ChildProcessWithoutNullStreams | null = null;
  private buffer = "";
  private readonly pending: Array<(payload: string) => void> = [];

  constructor(private readonly url: string) {}

  start(): void {
    if (this.child !== null) return;
    // No ON_ERROR_STOP: a mid-transaction failure must leave the session alive so the test can
    // ROLLBACK and still read the ERROR text.
    this.child = spawn("psql", ["-X", "-q", "-A", "-t", "-v", "VERBOSITY=verbose"], {
      env: pgEnv(this.url),
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    const absorb = (chunk: string): void => {
      this.buffer += chunk;
      let index = this.buffer.indexOf(`${MARKER}\n`);
      while (index !== -1) {
        const payload = this.buffer.slice(0, index);
        this.buffer = this.buffer.slice(index + MARKER.length + 1);
        this.pending.shift()?.(payload);
        index = this.buffer.indexOf(`${MARKER}\n`);
      }
    };
    this.child.stderr.on("data", (chunk: string) => {
      this.buffer += chunk;
    });
    this.child.stdout.on("data", absorb);
  }

  stop(): void {
    if (this.child === null) return;
    this.child.stdin.end();
    this.child.kill("SIGTERM");
    this.child = null;
  }

  private send(sql: string): Promise<string> {
    this.start();
    const child = this.child!;
    return new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(
        () => rejectPromise(new Error(`psql session timeout: ${sql.slice(0, 90)}`)),
        30_000,
      );
      this.pending.push((payload) => {
        clearTimeout(timer);
        if (/\bERROR:\s+/i.test(payload)) {
          const err = new Error(payload.trim());
          (err as { code?: string }).code = extractSqlstate(payload);
          rejectPromise(err);
          return;
        }
        resolvePromise(payload);
      });
      child.stdin.write(`${sql};\n\\echo ${MARKER}\n`);
    });
  }

  async begin(): Promise<void> {
    await this.send("BEGIN");
  }

  async commit(): Promise<void> {
    await this.send("COMMIT");
  }

  async rollback(): Promise<void> {
    try {
      await this.send("ROLLBACK");
    } catch {
      // already aborted
    }
  }

  async query<R>(text: string, params: readonly unknown[] = []): Promise<AckSqlQueryResult<R>> {
    const bound = bindSql(text, params).trim();
    if (/^(INSERT|UPDATE|DELETE)\b/i.test(bound)) {
      const wrapped = `WITH __m AS (${bound} RETURNING 1) SELECT count(*)::int AS __rc FROM __m`;
      const out = await this.send(wrapped);
      const lines = out
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
      return { rows: [] as R[], rowCount: Number(lines[lines.length - 1] ?? "0") };
    }
    const jsonSql = `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json)::text FROM (${bound}) t`;
    const out = await this.send(jsonSql);
    const lines = out
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    const rows = JSON.parse(lines[lines.length - 1] ?? "[]") as R[];
    return { rows, rowCount: rows.length };
  }
}

async function withTx<T>(url: string, body: (db: PsqlSession) => Promise<T>): Promise<T> {
  const session = new PsqlSession(url);
  session.start();
  try {
    await session.begin();
    const result = await body(session);
    await session.commit();
    return result;
  } catch (err) {
    await session.rollback();
    throw err;
  } finally {
    session.stop();
  }
}

/* ─── fixtures ────────────────────────────────────────────────────── */

const NODE = "b0000000-0000-4000-8000-0000000000aa";
const IMPLEMENTER = "b0000000-0000-4000-8000-0000000000bb";
const OBSERVER = "b0000000-0000-4000-8000-0000000000cc";
const KEY = "b0000000-0000-4000-8000-0000000000dd";
const SRC_WALLET = "a0000000-0000-4000-8000-000000000001";
const DST_WALLET = "a0000000-0000-4000-8000-000000000002";
const RCV_WALLET = "a0000000-0000-4000-8000-000000000003";
const DESTINATION = "a1000000-0000-4000-8000-000000000001";
const OBS_T0 = "f0000000-0000-4000-8000-000000000001";
const OBS_TERMINAL = "f0000000-0000-4000-8000-000000000002";

const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;
const hex = (seed: string): string => seed.repeat(64).slice(0, 64);
const signature = (seed: string): string => `${seed.repeat(86).slice(0, 86)}==`;

function seed(url: string): void {
  psqlMust(
    url,
    `
    INSERT INTO nodes (id, display_name, identity_public_key)
      VALUES ('${NODE}', 'verification-ack', '${pubkey("n1")}');
    INSERT INTO implementers (id, name) VALUES ('${IMPLEMENTER}', 'verification-ack-impl');
    INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
      VALUES ('${KEY}', '${NODE}', '${IMPLEMENTER}', '${pubkey("k1")}', now());
    INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
      VALUES ('${OBSERVER}', 'NODE', '${NODE}', '${hex("a")}', now());

    INSERT INTO wallets (id, node_id, public_key, key_origin, state)
      VALUES ('${SRC_WALLET}', '${NODE}', '${pubkey("w1")}', 'node_generated', 'PINNED'),
             ('${DST_WALLET}', '${NODE}', '${pubkey("w2")}', 'node_generated', 'PINNED'),
             ('${RCV_WALLET}', '${NODE}', '${pubkey("w3")}', 'node_generated', 'PINNED');
    INSERT INTO destinations (id, node_id, wallet_id) VALUES ('${DESTINATION}', '${NODE}', '${DST_WALLET}');

    -- VERIFIED_HEAD carries the full field set its CHECK constraints demand, so the
    -- evidence rows below point at observations shaped like real accepted ones.
    INSERT INTO gateway_observations (
      id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq, observed_at,
      raw_response_bytes, raw_response_sha256, parse_result, relationship,
      semantic_fingerprint, state_changed, wallet_role, s_signature, p_signature, b_amount,
      inner_preimage_text, step_1_signature, step_2_signature, completed_transaction_text,
      completed_transaction_sha256)
      VALUES ('${OBS_T0}', '${OBSERVER}', '${hex("a")}', '${pubkey("w1")}', 1, now(),
              '\\x00'::bytea, '${hex("b")}', 'VERIFIED_HEAD', 'FIRST',
              '${hex("b")}', false, 'receiver', '${signature("1")}', '', '0',
              '{"t0":1}', '${signature("2")}', '${signature("3")}', '{"tx":"t0"}', '${hex("b")}'),
             ('${OBS_TERMINAL}', '${OBSERVER}', '${hex("a")}', '${pubkey("w1")}', 2, now(),
              '\\x01'::bytea, '${hex("c")}', 'VERIFIED_HEAD', 'SUCCESSOR',
              '${hex("c")}', true, 'receiver', '${signature("4")}', '${signature("1")}', '1.5',
              '{"terminal":1}', '${signature("5")}', '${signature("6")}', '{"tx":"terminal"}',
              '${hex("c")}');
    `,
  );
}

/**
 * One test's own receive operation, its automatic child move, and the lease group both legs
 * belong to. Every identity is fresh, so the whole suite shares ONE database and ONE schema
 * apply: no test can see another's rows, and the `reporting_*` immutability triggers (which
 * forbid DELETE) never need to be worked around.
 */
interface OperationSet {
  readonly groupId: string;
  readonly receiveOp: string;
  readonly moveOp: string;
  readonly receiveTarget: string;
  readonly moveTarget: string;
}

let setCounter = 0;

function seedOperationSet(
  url: string,
  childDisposition: "NONE" | "PENDING" | "JOINED",
  options: { readonly joinChild?: boolean } = {},
): OperationSet {
  setCounter += 1;
  const suffix = String(setCounter).padStart(4, "0");
  const groupId = randomUUID();
  const receiveOp = randomUUID();
  const moveOp = randomUUID();
  const joinChild = options.joinChild ?? true;

  psqlMust(
    url,
    `
    INSERT INTO operations (
      id, node_id, implementer_id, kind, status, row_version, amount_zkz, receiver_wallet_id,
      after_landing, after_landing_destination_id, discriminator, anchor, idempotency_key,
      request_sha256, expiry_unix_time_secs, t0_observation_id)
      VALUES ('${receiveOp}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'RECEIVE_LANDED',
              7, '1.5', '${RCV_WALLET}', 'INTERNAL_MOVE', '${DESTINATION}', '${receiveOp}',
              'anchor${suffix}', 'verification-ack-receive-key-${suffix}', '${hex("d")}', '1900000000',
              '${OBS_T0}');
    INSERT INTO operations (
      id, node_id, implementer_id, kind, status, row_version, amount_zkz, source_wallet_id,
      destination_id, idempotency_key, request_sha256, spawned_from_operation_id)
      VALUES ('${moveOp}', '${NODE}', '${IMPLEMENTER}', 'MOVE_INTERNAL', 'INTERNAL_MOVE_LANDED',
              4, '1.5', '${SRC_WALLET}', '${DESTINATION}', 'verification-ack-move-key-${suffix}',
              '${hex("e")}', '${receiveOp}');

    INSERT INTO lease_groups (id, root_operation_id, created_at, child_disposition)
      VALUES ('${groupId}', '${receiveOp}', now(), '${childDisposition}');
    INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at)
      VALUES ('${groupId}', '${receiveOp}', now() - interval '2 minutes')
      ${
        joinChild
          ? `, ('${groupId}', '${moveOp}', now() - interval '1 minute')`
          : ""
      };
    INSERT INTO wallet_lease_memberships (
      id, lease_group_id, wallet_id, operation_id, lease_role, lease_epoch, acquired_at)
      VALUES ('${randomUUID()}', '${groupId}', '${RCV_WALLET}', '${receiveOp}',
              'RECEIVE_WINDOW', 1, now())
      ${
        joinChild
          ? `, ('${randomUUID()}', '${groupId}', '${SRC_WALLET}', '${moveOp}', 'MOVE_SOURCE', 1, now())`
          : ""
      };
    `,
  );

  return {
    groupId,
    receiveOp,
    moveOp,
    receiveTarget: `/v1/operations/${receiveOp}/verification-complete`,
    moveTarget: `/v1/operations/${moveOp}/verification-complete`,
  };
}

/** Row counts scoped to one test's own group, so a shared database stays readable. */
function groupCounts(
  url: string,
  set: OperationSet,
): {
  readonly acknowledgements: number;
  readonly evidenceRows: number;
  readonly openMemberships: number;
  readonly closedMemberships: number;
  readonly releasedGroups: number;
} {
  const [acknowledgements, evidenceRows, openMemberships, closedMemberships, releasedGroups] =
    psqlMust(
      url,
      `SELECT
         (SELECT count(*) FROM verification_acknowledgements
            WHERE operation_id IN ('${set.receiveOp}', '${set.moveOp}')) || '|' ||
         (SELECT count(*) FROM verification_ack_wallet_evidence e
            JOIN verification_acknowledgements a ON a.id = e.acknowledgement_id
            WHERE a.operation_id IN ('${set.receiveOp}', '${set.moveOp}')) || '|' ||
         (SELECT count(*) FROM wallet_lease_memberships
            WHERE lease_group_id = '${set.groupId}' AND released_at IS NULL) || '|' ||
         (SELECT count(*) FROM wallet_lease_memberships
            WHERE lease_group_id = '${set.groupId}' AND released_at IS NOT NULL) || '|' ||
         (SELECT count(*) FROM lease_groups
            WHERE id = '${set.groupId}' AND released_at IS NOT NULL)`,
    )
      .trim()
      .split("|")
      .map(Number);
  return {
    acknowledgements: acknowledgements!,
    evidenceRows: evidenceRows!,
    openMemberships: openMemberships!,
    closedMemberships: closedMemberships!,
    releasedGroups: releasedGroups!,
  };
}

const verdictOf = (url: string, operationId: string): string =>
  psqlMust(
    url,
    `SELECT verdict FROM verification_acknowledgements WHERE operation_id = '${operationId}'`,
  ).trim();

/**
 * The signed request evidence binds through `reporting_nonce_id`
 * `mutation_idempotency_id`. `child_record_id` names the acknowledgement id up front, which is
 * how the frozen deferred correlation is satisfied.
 */
function seedRequestEvidence(
  url: string,
  input: {
    readonly nonceId: string;
    readonly idempotencyId: string;
    readonly idempotencyKey: string;
    readonly childRecordId: string;
    readonly rawTarget: string;
    readonly bodySha256: string;
    readonly preimageText: string;
    readonly signature: string;
    /** Frozen response JSON. Defaults to `{}` placeholder (conservative non-RELEASED replay). */
    readonly responseBodyJson?: string;
  },
): void {
  const responseJson = input.responseBodyJson ?? "{}";
  // bytea via convert_to keeps the exact UTF-8 response body bytes the composition root freezes.
  psqlMust(
    url,
    `
    INSERT INTO reporting_request_nonces (
      id, node_id, implementer_id, nonce, purpose, route_id, request_class, reporting_key_id,
      lifecycle_epoch, nonce_burn_sequence, request_preimage_text, request_preimage_sha256,
      request_signature, method, raw_target, body_sha256, issued_at, expires_at, received_at,
      consumed_at, retention_class)
      VALUES ('${input.nonceId}', '${NODE}', '${IMPLEMENTER}', '${randomUUID()}',
              'zp-report-request-v1', 'verification_complete', 'MUTATION', '${KEY}',
              1, nextval('verification_ack_burn_seq'), '${input.preimageText.replace(/'/g, "''")}',
              '${hex("f")}', '${input.signature}', 'POST',
              '${input.rawTarget}', '${input.bodySha256}',
              now(), now() + interval '30 seconds', now(), now(), 'PERMANENT_MUTATION');
    INSERT INTO reporting_mutation_idempotency (
      id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id,
      child_record_id, method, raw_target, body_sha256, response_status, response_bytes,
      completed_at, created_at)
      VALUES ('${input.idempotencyId}', '${NODE}', '${IMPLEMENTER}', 'verification_complete',
              '${input.idempotencyKey}', '${input.nonceId}', '${input.childRecordId}', 'POST',
              '${input.rawTarget}', '${input.bodySha256}', 200,
              convert_to('${responseJson.replace(/'/g, "''")}', 'UTF8'), now(), now());
    `,
  );
}

const evidence = (
  role: string,
  walletId: string | null,
  key: string,
): AckWalletEvidenceInput => ({
  walletId,
  walletPublicKey: pubkey(key),
  role,
  t0: { observationId: OBS_T0 },
  terminal: { observationId: OBS_TERMINAL },
});

/* ─── suite ───────────────────────────────────────────────────────── */

const serverReachable = ((): boolean => {
  if (TEST_DATABASE_URL === "") return false;
  return runPsql(TEST_DATABASE_URL, "SELECT 1", 15_000).ok;
})();

if (!serverReachable && PG_REQUIRED) {
  throw new Error(
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unreachable — the real-PostgreSQL acknowledgement " +
      "criteria cannot run and must not silently skip.",
  );
}

describe.skipIf(!serverReachable)("acknowledgement + group release (real PG)", () => {
  // ONE database, ONE schema apply. Per-test identities keep the tests isolated without
  // deletes, which the `reporting_*` immutability triggers forbid anyway.
  const databaseName = `verification_ack_ack_${process.pid}`;
  let url = "";

  beforeAll(() => {
    psqlMust(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${databaseName}`);
    url = withDatabase(TEST_DATABASE_URL, databaseName);
    applyFile(url, buildSchema());
    // A private sequence supplies the frozen UNIQUE (node_id, nonce_burn_sequence) without the
    // test having to track a counter itself.
    psqlMust(url, "CREATE SEQUENCE verification_ack_burn_seq START 1");
    seed(url);
  }, 180_000);

  afterAll(() => {
    // Prefix-scoped: never touch a sibling lane's database on a shared server.
    runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
  });

  /** Bind the service to one session and one pre-chosen acknowledgement id. */
  const acknowledgeWith = (session: PsqlSession, acknowledgementId: string) =>
    createAcknowledgementService<AckSqlExecutor>({
      store: createSqlAcknowledgementStore(),
      newAcknowledgementId: () => acknowledgementId,
      nowIso: () => new Date().toISOString(),
    }).acknowledge.bind(null, session);

  interface LegRequest {
    readonly nonceId: string;
    readonly idempotencyId: string;
    readonly acknowledgementId: string;
  }

  /** Seed the signed-request evidence a leg's acknowledgement will bind to. */
  function prepareLeg(input: {
    readonly rawTarget: string;
    readonly bodySha256: string;
    readonly preimageText: string;
    readonly signature: string;
    readonly idempotencyKey?: string;
    /** When set, freezes these body bytes on the completed parent (production path). */
    readonly frozenResponseBody?: {
      readonly operation_id: string;
      readonly acknowledgement_id: string;
      readonly verdict: string;
      readonly lease_release_status: string;
      readonly acknowledged_at: string;
    };
  }): LegRequest {
    const leg: LegRequest = {
      nonceId: randomUUID(),
      idempotencyId: randomUUID(),
      acknowledgementId: randomUUID(),
    };
    const responseBodyJson =
      input.frozenResponseBody === undefined
        ? undefined
        : JSON.stringify({
            ...input.frozenResponseBody,
            acknowledgement_id: leg.acknowledgementId,
          });
    seedRequestEvidence(url, {
      nonceId: leg.nonceId,
      idempotencyId: leg.idempotencyId,
      idempotencyKey: input.idempotencyKey ?? `verification-ack-${randomUUID()}`,
      childRecordId: leg.acknowledgementId,
      rawTarget: input.rawTarget,
      bodySha256: input.bodySha256,
      preimageText: input.preimageText,
      signature: input.signature,
      responseBodyJson,
    });
    return leg;
  }

  /** The request for a receive leg. */
  const receiveRequest = (
    set: OperationSet,
    leg: LegRequest,
    over: Partial<AcknowledgementInput> = {},
  ): AcknowledgementInput => ({
    expectedRowVersion: 7,
    consumedCursor: 1051n,
    verdict: "VERIFIED",
    walletEvidence: [evidence("RECEIVER", RCV_WALLET, "w3")],
    nodeId: NODE,
    implementerId: IMPLEMENTER,
    rawTarget: set.receiveTarget,
    requestBodySha256: hex("1"),
    requestPreimageText: "receive-preimage",
    requestSignature: signature("S"),
    reportingNonceId: leg.nonceId,
    mutationIdempotencyId: leg.idempotencyId,
    ...over,
  });

  /** The request for the child move leg, with its full SOURCE+DESTINATION set. */
  const moveRequest = (
    set: OperationSet,
    leg: LegRequest,
    over: Partial<AcknowledgementInput> = {},
  ): AcknowledgementInput => ({
    expectedRowVersion: 4,
    consumedCursor: 1099n,
    verdict: "VERIFIED",
    walletEvidence: [
      evidence("SOURCE", SRC_WALLET, "w1"),
      evidence("DESTINATION", DST_WALLET, "w2"),
    ],
    nodeId: NODE,
    implementerId: IMPLEMENTER,
    rawTarget: set.moveTarget,
    requestBodySha256: hex("3"),
    requestPreimageText: "move-preimage",
    requestSignature: signature("T"),
    reportingNonceId: leg.nonceId,
    mutationIdempotencyId: leg.idempotencyId,
    ...over,
  });

  const acknowledgeLeg = async (
    operationId: string,
    leg: LegRequest,
    request: AcknowledgementInput,
  ) =>
    withTx(url, async (session) =>
      acknowledgeWith(session, leg.acknowledgementId)(operationId, request),
    );

  /* ── the frozen tables themselves ─────────────────────────────── */

  it("materializes the frozen tables with their real constraints", () => {
    const checks = psqlMust(
      url,
      `SELECT conname FROM pg_constraint
        WHERE conrelid = 'verification_acknowledgements'::regclass AND contype = 'c'
        ORDER BY conname`,
    );
    expect(checks).toContain("verification_acknowledgements_verdict_check");

    const uniques = psqlMust(
      url,
      `SELECT pg_get_constraintdef(oid) FROM pg_constraint
        WHERE conrelid = 'verification_acknowledgements'::regclass AND contype = 'u'`,
    );
    expect(uniques).toContain("UNIQUE (operation_id)");

    const evidenceKeys = psqlMust(
      url,
      `SELECT contype::text || ' ' || pg_get_constraintdef(oid) FROM pg_constraint
        WHERE conrelid = 'verification_ack_wallet_evidence'::regclass
          AND contype IN ('p', 'u') ORDER BY contype::text`,
    );
    expect(evidenceKeys).toContain("PRIMARY KEY (acknowledgement_id, evidence_role)");
    expect(evidenceKeys).toContain("UNIQUE (acknowledgement_id, wallet_public_key)");
  });

  // Byte-discipline indicator: the preimage and the digest inputs are text/sha256_hex columns,
  // never JSON — nothing on this path can be silently re-serialized (the byte-exact signing rule).
  it("uses no JSON or JSONB column anywhere on the acknowledgement evidence path", () => {
    const jsonColumns = psqlMust(
      url,
      `SELECT count(*)::int FROM information_schema.columns
        WHERE table_name IN ('verification_acknowledgements','verification_ack_wallet_evidence',
                             'reporting_request_nonces')
          AND data_type IN ('json','jsonb')`,
    ).trim();
    expect(jsonColumns).toBe("0");
  });

  it("refuses a PENDING verdict at the database, not only in the service", () => {
    const set = seedOperationSet(url, "JOINED");
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "pending-preimage",
      signature: signature("S"),
    });
    const outcome = runPsql(
      url,
      `INSERT INTO verification_acknowledgements (
         id, operation_id, node_id, implementer_id, raw_target, consumed_cursor, verdict,
         evidence_set_sha256, request_body_sha256, reporting_nonce_id, mutation_idempotency_id,
         acknowledged_at)
       VALUES ('${leg.acknowledgementId}', '${set.receiveOp}', '${NODE}', '${IMPLEMENTER}',
               '${set.receiveTarget}', 0, 'PENDING', '${hex("2")}', '${hex("1")}',
               '${leg.nonceId}', '${leg.idempotencyId}', now())`,
    );
    expect(outcome.ok).toBe(false);
    expect(extractSqlstate(outcome.stderr)).toBe("23514");
  });

  /* ── the group-release predicate over real rows ───────────────── */

  it("writes the acknowledgement and its evidence rows, and holds the group pending", async () => {
    const set = seedOperationSet(url, "JOINED");
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "receive-preimage",
      signature: signature("S"),
    });
    const outcome = await acknowledgeLeg(set.receiveOp, leg, receiveRequest(set, leg));

    // Requirement: only one of the two legs has acknowledged, so the shared
    // source-wallet membership must NOT be releasable yet.
    expect(outcome.body.lease_release_status).toBe("PINNED_GROUP_PENDING");
    expect(outcome.decision.reason).toBe("LEG_NOT_ACKNOWLEDGED");
    expect(outcome.decision.blockingOperationIds).toEqual([set.moveOp]);
    expect(outcome.releasableMemberships).toEqual([]);

    const counts = groupCounts(url, set);
    expect(counts.acknowledgements).toBe(1);
    expect(counts.evidenceRows).toBe(1);
    expect(counts.openMemberships).toBe(2);
    expect(counts.closedMemberships).toBe(0);

    expect(
      psqlMust(
        url,
        `SELECT e.evidence_role || '|' || e.wallet_public_key || '|' || e.wallet_id
           FROM verification_ack_wallet_evidence e
           WHERE e.acknowledgement_id = '${leg.acknowledgementId}'`,
      ).trim(),
    ).toBe(`RECEIVER|${pubkey("w3")}|${RCV_WALLET}`);
  });

  it("releases only after BOTH legs acknowledge with complete evidence", async () => {
    const set = seedOperationSet(url, "JOINED");

    const receiveLeg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "receive-preimage",
      signature: signature("S"),
    });
    const first = await acknowledgeLeg(set.receiveOp, receiveLeg, receiveRequest(set, receiveLeg));
    expect(first.body.lease_release_status).toBe("PINNED_GROUP_PENDING");

    const moveLeg = prepareLeg({
      rawTarget: set.moveTarget,
      bodySha256: hex("3"),
      preimageText: "move-preimage",
      signature: signature("T"),
    });
    const second = await acknowledgeLeg(set.moveOp, moveLeg, moveRequest(set, moveLeg));

    expect(second.body.lease_release_status).toBe("RELEASED");
    expect(second.decision.reason).toBe("ALL_LEGS_PROVEN");
    // The directive names the still-open memberships; consuming a minted terminal-positive
    // proof to actually close them is the caller's step (leases/releaseLease).
    expect(second.releasableMemberships.map((m) => m.walletId).sort()).toEqual(
      [RCV_WALLET, SRC_WALLET].sort(),
    );

    // This service released nothing itself — the one-in-flight-per-wallet rule keeps both wallets held.
    const counts = groupCounts(url, set);
    expect(counts.acknowledgements).toBe(2);
    expect(counts.evidenceRows).toBe(3);
    expect(counts.openMemberships).toBe(2);
    expect(counts.closedMemberships).toBe(0);
    expect(counts.releasedGroups).toBe(0);
  });

  it("refuses release while a declared child move has not joined (child_disposition PENDING)", async () => {
    const set = seedOperationSet(url, "PENDING", { joinChild: false });
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "receive-preimage",
      signature: signature("S"),
    });
    const outcome = await acknowledgeLeg(set.receiveOp, leg, receiveRequest(set, leg));

    expect(outcome.body.lease_release_status).toBe("PINNED_GROUP_PENDING");
    expect(outcome.decision.reason).toBe("CHILD_OPERATION_NOT_JOINED");
    expect(outcome.releasableMemberships).toEqual([]);
    expect(groupCounts(url, set).closedMemberships).toBe(0);
  });

  it("releases a HOLD group whose only leg is proven (child_disposition NONE)", async () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "receive-preimage",
      signature: signature("S"),
    });
    const outcome = await acknowledgeLeg(set.receiveOp, leg, receiveRequest(set, leg));
    expect(outcome.body.lease_release_status).toBe("RELEASED");
    expect(outcome.releasableMemberships.map((m) => m.walletId)).toEqual([RCV_WALLET]);
  });

  /* ── conflicting replay (data-model) ──────────────── */

  // Item 16, exact wording: "verification-complete conflicting replay fails and cannot
  // release the wallet."
  it("rejects a conflicting replay and cannot release the wallet", async () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "conflict-preimage",
      signature: signature("S"),
    });
    const first = await acknowledgeLeg(
      set.receiveOp,
      leg,
      receiveRequest(set, leg, { requestPreimageText: "conflict-preimage" }),
    );
    expect(first.body.verdict).toBe("VERIFIED");
    expect(verdictOf(url, set.receiveOp)).toBe("VERIFIED");

    // A fresh nonce AND a fresh Idempotency-Key: the reporting runtime's replay guard is keyed
    // on that header, so it cannot see this at all. The operation_id UNIQUE plus the
    // bound-field comparison is the only thing standing between this request and a release.
    const replayLeg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("4"),
      preimageText: "different-preimage",
      signature: signature("Z"),
    });
    await expect(
      acknowledgeLeg(
        set.receiveOp,
        replayLeg,
        receiveRequest(set, replayLeg, {
          verdict: "REJECTED",
          requestBodySha256: hex("4"),
          requestPreimageText: "different-preimage",
          requestSignature: signature("Z"),
        }),
      ),
    ).rejects.toMatchObject({ reason: "CONFLICTING_REPLAY" });

    // The durable verdict is untouched, no second row exists, and nothing was released.
    expect(verdictOf(url, set.receiveOp)).toBe("VERIFIED");
    const counts = groupCounts(url, set);
    expect(counts.acknowledgements).toBe(1);
    expect(counts.closedMemberships).toBe(0);
    expect(counts.releasedGroups).toBe(0);
  });

  it("rejects a conflicting replay that differs only in the signed preimage bytes", async () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "exact-preimage",
      signature: signature("S"),
    });
    await acknowledgeLeg(
      set.receiveOp,
      leg,
      receiveRequest(set, leg, { requestPreimageText: "exact-preimage" }),
    );

    // Same verdict, same cursor, same body digest — one trailing byte different on the signed
    // preimage. The frozen guarded uniqueness already forbids a SECOND completed idempotency
    // row for that identical (method, raw target, body digest) triple, so this presents a new
    // nonce carrying the different bytes against the same completed mutation — the shape a
    // re-signed request actually takes. Only the byte comparison can refuse it.
    const replayNonceId = randomUUID();
    psqlMust(
      url,
      `INSERT INTO reporting_request_nonces (
         id, node_id, implementer_id, nonce, purpose, route_id, request_class, reporting_key_id,
         lifecycle_epoch, nonce_burn_sequence, request_preimage_text, request_preimage_sha256,
         request_signature, method, raw_target, body_sha256, issued_at, expires_at, received_at,
         consumed_at, retention_class)
       VALUES ('${replayNonceId}', '${NODE}', '${IMPLEMENTER}', '${randomUUID()}',
               'zp-report-request-v1', 'verification_complete', 'MUTATION', '${KEY}',
               1, nextval('verification_ack_burn_seq'), 'exact-preimage ', '${hex("f")}',
               '${signature("S")}', 'POST', '${set.receiveTarget}', '${hex("1")}',
               now(), now() + interval '30 seconds', now(), now(), 'PERMANENT_MUTATION')`,
    );
    await expect(
      withTx(url, async (session) =>
        acknowledgeWith(session, randomUUID())(
          set.receiveOp,
          receiveRequest(set, leg, {
            requestPreimageText: "exact-preimage ",
            reportingNonceId: replayNonceId,
          }),
        ),
      ),
    ).rejects.toMatchObject({ reason: "CONFLICTING_REPLAY" });
    expect(groupCounts(url, set).acknowledgements).toBe(1);
  });

  it("replays an identical acknowledgement idempotently against the durable row", async () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const fixedAt = "2026-07-26T12:00:00.000Z";
    // Composition freezes response_bytes at commit; the parent row is immutable, so the test
    // seeds the expected body up front (HOLD single-leg → RELEASED) with a fixed clock.
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "replay-preimage",
      signature: signature("S"),
      frozenResponseBody: {
        operation_id: set.receiveOp,
        acknowledgement_id: "placeholder",
        verdict: "VERIFIED",
        lease_release_status: "RELEASED",
        acknowledged_at: fixedAt,
      },
    });
    const request = receiveRequest(set, leg, { requestPreimageText: "replay-preimage" });
    const first = await withTx(url, async (session) =>
      createAcknowledgementService<AckSqlExecutor>({
        store: createSqlAcknowledgementStore(),
        newAcknowledgementId: () => leg.acknowledgementId,
        nowIso: () => fixedAt,
      }).acknowledge(session, set.receiveOp, request),
    );
    expect(first.body.lease_release_status).toBe("RELEASED");

    // A different acknowledgement id is offered; the durable row must win, and the reply must
    // be byte-identical to the first (including frozen lease_release_status).
    const second = await withTx(url, async (session) =>
      acknowledgeWith(session, randomUUID())(set.receiveOp, request),
    );
    expect(second.idempotentReplay).toBe(true);
    expect(second.body.acknowledgement_id).toBe(first.body.acknowledgement_id);
    expect(second.body).toEqual(first.body);
    expect(groupCounts(url, set).acknowledgements).toBe(1);
  });

  // One-in-flight /: wrong-wallet RECEIVER evidence must not write and must not RELEASED.
  it("refuses wrong wallet_id evidence and never writes or releases", async () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "wrong-wallet-preimage",
      signature: signature("S"),
    });
    await expect(
      acknowledgeLeg(
        set.receiveOp,
        leg,
        receiveRequest(set, leg, {
          requestPreimageText: "wrong-wallet-preimage",
          walletEvidence: [evidence("RECEIVER", SRC_WALLET, "w1")],
        }),
      ),
    ).rejects.toMatchObject({ reason: "EVIDENCE_SET_INVALID" });
    expect(groupCounts(url, set).acknowledgements).toBe(0);
    expect(groupCounts(url, set).openMemberships).toBe(1);
    expect(groupCounts(url, set).closedMemberships).toBe(0);
  });

  it("refuses wrong wallet_public_key evidence and never writes or releases", async () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "wrong-pubkey-preimage",
      signature: signature("S"),
    });
    await expect(
      acknowledgeLeg(
        set.receiveOp,
        leg,
        receiveRequest(set, leg, {
          requestPreimageText: "wrong-pubkey-preimage",
          walletEvidence: [evidence("RECEIVER", RCV_WALLET, "w1")],
        }),
      ),
    ).rejects.toMatchObject({ reason: "EVIDENCE_SET_INVALID" });
    expect(groupCounts(url, set).acknowledgements).toBe(0);
  });

  // Freeze: first response PINNED_GROUP_PENDING stays frozen after sibling completes.
  // Parent response_bytes is immutable and seeded before the write (composition freezes at
  // commit). This case seeds a real frozen body with a fixed clock so first write + replay
  // share the same bytes; after the sibling releases the group, receive replay must NOT flip.
  it("freezes lease_release_status on matching replay after the sibling leg completes", async () => {
    const set = seedOperationSet(url, "JOINED");
    const fixedAt = "2026-07-26T12:00:00.000Z";
    const receiveLeg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "freeze-receive-preimage",
      signature: signature("S"),
      frozenResponseBody: {
        operation_id: set.receiveOp,
        acknowledgement_id: "placeholder",
        verdict: "VERIFIED",
        lease_release_status: "PINNED_GROUP_PENDING",
        acknowledged_at: fixedAt,
      },
    });
    const request = receiveRequest(set, receiveLeg, {
      requestPreimageText: "freeze-receive-preimage",
    });

    // Fixed clock so the first-write body matches the pre-seeded freeze bytes.
    const first = await withTx(url, async (session) =>
      createAcknowledgementService<AckSqlExecutor>({
        store: createSqlAcknowledgementStore(),
        newAcknowledgementId: () => receiveLeg.acknowledgementId,
        nowIso: () => fixedAt,
      }).acknowledge(session, set.receiveOp, request),
    );
    expect(first.body.lease_release_status).toBe("PINNED_GROUP_PENDING");
    expect(first.body.acknowledged_at).toBe(fixedAt);
    expect(first.releasableMemberships).toEqual([]);

    // Sibling completes out-of-band — a re-eval of the receive ack would flip to RELEASED.
    const moveLeg = prepareLeg({
      rawTarget: set.moveTarget,
      bodySha256: hex("3"),
      preimageText: "freeze-move-preimage",
      signature: signature("T"),
    });
    const moveOutcome = await acknowledgeLeg(
      set.moveOp,
      moveLeg,
      moveRequest(set, moveLeg, { requestPreimageText: "freeze-move-preimage" }),
    );
    expect(moveOutcome.body.lease_release_status).toBe("RELEASED");

    // Replay receive bytes: must return the frozen first response, not a fresh RELEASED.
    const second = await withTx(url, async (session) =>
      acknowledgeWith(session, randomUUID())(set.receiveOp, request),
    );
    expect(second.idempotentReplay).toBe(true);
    expect(second.body.lease_release_status).toBe("PINNED_GROUP_PENDING");
    expect(second.body).toEqual(first.body);
    expect(second.releasableMemberships).toEqual([]);
    // Memberships remain open — freeze must not mint a release the first response withheld.
    expect(groupCounts(url, set).openMemberships).toBe(2);
    expect(groupCounts(url, set).closedMemberships).toBe(0);
  });

  // "one reporting_request_nonce/idempotency key with a different request hash is a
  // conflict, never a replay success." Proven by the frozen guarded uniqueness itself.
  it("treats one idempotency key with a different body digest as a database conflict", () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const sharedKey = `verification-ack-guarded-${setCounter}`;
    prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "guarded-preimage",
      signature: signature("S"),
      idempotencyKey: sharedKey,
    });
    const secondNonce = randomUUID();
    seedRequestEvidence(url, {
      nonceId: secondNonce,
      idempotencyId: randomUUID(),
      idempotencyKey: `${sharedKey}-other`,
      childRecordId: randomUUID(),
      rawTarget: set.receiveTarget,
      bodySha256: hex("9"),
      preimageText: "guarded-preimage-2",
      signature: signature("S"),
    });
    const clash = runPsql(
      url,
      `INSERT INTO reporting_mutation_idempotency (
         id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id,
         child_record_id, method, raw_target, body_sha256, response_status, response_bytes,
         completed_at, created_at)
       VALUES ('${randomUUID()}', '${NODE}', '${IMPLEMENTER}', 'verification_complete',
               '${sharedKey}', '${secondNonce}', '${randomUUID()}', 'POST',
               '${set.receiveTarget}', '${hex("9")}', 200, '\\x7b7d'::bytea, now(), now())`,
    );
    expect(clash.ok).toBe(false);
    expect(extractSqlstate(clash.stderr)).toBe("23505");
  });

  /* ── verdicts that must never release ─────────────────────────── */

  // Requirement: "acknowledging REJECTED or INDETERMINATE never produces
  // lease_release_status: RELEASED."
  it.each(["REJECTED", "INDETERMINATE"] as const)(
    "never releases the wallet on a %s verdict, even when every sibling leg is proven",
    async (verdict) => {
      const set = seedOperationSet(url, "JOINED");

      // Prove the sibling move leg first, so this verdict is the ONLY thing between the group
      // and release. Without the clamp the group predicate would say RELEASED.
      const moveLeg = prepareLeg({
        rawTarget: set.moveTarget,
        bodySha256: hex("3"),
        preimageText: "move-preimage",
        signature: signature("T"),
      });
      await acknowledgeLeg(set.moveOp, moveLeg, moveRequest(set, moveLeg));

      const receiveLeg = prepareLeg({
        rawTarget: set.receiveTarget,
        bodySha256: hex("1"),
        preimageText: "receive-preimage",
        signature: signature("S"),
      });
      const outcome = await acknowledgeLeg(
        set.receiveOp,
        receiveLeg,
        receiveRequest(set, receiveLeg, { verdict }),
      );

      expect(outcome.body.verdict).toBe(verdict);
      expect(outcome.body.lease_release_status).toBe("PINNED_FOR_ATTENTION");
      expect(outcome.releasableMemberships).toEqual([]);
      expect(verdictOf(url, set.receiveOp)).toBe(verdict);

      const counts = groupCounts(url, set);
      expect(counts.closedMemberships).toBe(0);
      expect(counts.releasedGroups).toBe(0);
    },
  );

  it("pins a group for attention once any leg is REJECTED, even from the sibling's request", async () => {
    const set = seedOperationSet(url, "JOINED");
    const receiveLeg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "receive-preimage",
      signature: signature("S"),
    });
    await acknowledgeLeg(
      set.receiveOp,
      receiveLeg,
      receiveRequest(set, receiveLeg, { verdict: "REJECTED" }),
    );

    // The move leg is VERIFIED, but its own group carries a rejected sibling.
    const moveLeg = prepareLeg({
      rawTarget: set.moveTarget,
      bodySha256: hex("3"),
      preimageText: "move-preimage",
      signature: signature("T"),
    });
    const outcome = await acknowledgeLeg(set.moveOp, moveLeg, moveRequest(set, moveLeg));

    expect(outcome.body.verdict).toBe("VERIFIED");
    expect(outcome.body.lease_release_status).toBe("PINNED_FOR_ATTENTION");
    expect(outcome.decision.reason).toBe("LEG_VERDICT_NOT_VERIFIED");
    expect(outcome.decision.blockingOperationIds).toEqual([set.receiveOp]);
    expect(outcome.releasableMemberships).toEqual([]);
    expect(groupCounts(url, set).closedMemberships).toBe(0);
  });

  /* ── evidence role set (binding prose) ────────────────────── */

  it("refuses a move acknowledgement missing its DESTINATION evidence row, writing nothing", async () => {
    const set = seedOperationSet(url, "JOINED");
    const leg = prepareLeg({
      rawTarget: set.moveTarget,
      bodySha256: hex("3"),
      preimageText: "move-preimage",
      signature: signature("T"),
    });
    await expect(
      acknowledgeLeg(
        set.moveOp,
        leg,
        moveRequest(set, leg, { walletEvidence: [evidence("SOURCE", SRC_WALLET, "w1")] }),
      ),
    ).rejects.toMatchObject({ reason: "EVIDENCE_SET_INVALID" });

    const counts = groupCounts(url, set);
    expect(counts.acknowledgements).toBe(0);
    expect(counts.evidenceRows).toBe(0);
  });

  it("refuses a receive acknowledgement carrying a superset of its role set", async () => {
    const set = seedOperationSet(url, "JOINED");
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "receive-preimage",
      signature: signature("S"),
    });
    await expect(
      acknowledgeLeg(
        set.receiveOp,
        leg,
        receiveRequest(set, leg, {
          walletEvidence: [
            evidence("RECEIVER", RCV_WALLET, "w3"),
            evidence("SOURCE", SRC_WALLET, "w1"),
          ],
        }),
      ),
    ).rejects.toMatchObject({ reason: "EVIDENCE_SET_INVALID" });
    expect(groupCounts(url, set).acknowledgements).toBe(0);
  });

  it("lets the PRIMARY KEY, UNIQUE and role CHECK refuse malformed evidence rows", () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "evidence-preimage",
      signature: signature("S"),
    });
    psqlMust(
      url,
      `INSERT INTO verification_acknowledgements (
         id, operation_id, node_id, implementer_id, raw_target, consumed_cursor, verdict,
         evidence_set_sha256, request_body_sha256, reporting_nonce_id, mutation_idempotency_id,
         acknowledged_at)
       VALUES ('${leg.acknowledgementId}', '${set.receiveOp}', '${NODE}', '${IMPLEMENTER}',
               '${set.receiveTarget}', 1, 'VERIFIED', '${hex("2")}', '${hex("1")}',
               '${leg.nonceId}', '${leg.idempotencyId}', now());
       INSERT INTO verification_ack_wallet_evidence (
         acknowledgement_id, evidence_role, wallet_id, wallet_public_key,
         t0_observation_id, terminal_observation_id)
       VALUES ('${leg.acknowledgementId}', 'SOURCE', '${SRC_WALLET}', '${pubkey("w1")}',
               '${OBS_T0}', '${OBS_TERMINAL}')`,
    );

    const insertEvidence = (role: string, walletId: string, key: string): PsqlOutcome =>
      runPsql(
        url,
        `INSERT INTO verification_ack_wallet_evidence (
           acknowledgement_id, evidence_role, wallet_id, wallet_public_key,
           t0_observation_id, terminal_observation_id)
         VALUES ('${leg.acknowledgementId}', '${role}', '${walletId}', '${pubkey(key)}',
                 '${OBS_T0}', '${OBS_TERMINAL}')`,
      );

    const repeatedRole = insertEvidence("SOURCE", DST_WALLET, "w2");
    expect(repeatedRole.ok).toBe(false);
    expect(extractSqlstate(repeatedRole.stderr)).toBe("23505");

    const repeatedKey = insertEvidence("DESTINATION", SRC_WALLET, "w1");
    expect(repeatedKey.ok).toBe(false);
    expect(extractSqlstate(repeatedKey.stderr)).toBe("23505");

    // Admits no counterparty token: the closed set is SOURCE/RECEIVER/DESTINATION.
    const unknownRole = insertEvidence("COUNTERPARTY", DST_WALLET, "w2");
    expect(unknownRole.ok).toBe(false);
    expect(extractSqlstate(unknownRole.stderr)).toBe("23514");
  });

  it("lets operation_id UNIQUE refuse a second acknowledgement row for one operation", () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    // Distinct body digests, so the guarded fingerprint uniqueness is satisfied and
    // operation_id UNIQUE is the only constraint left to refuse the second row.
    const insertAck = (bodySha256: string): PsqlOutcome => {
      const leg = prepareLeg({
        rawTarget: set.receiveTarget,
        bodySha256,
        preimageText: "opunique-preimage",
        signature: signature("S"),
      });
      return runPsql(
        url,
        `INSERT INTO verification_acknowledgements (
           id, operation_id, node_id, implementer_id, raw_target, consumed_cursor, verdict,
           evidence_set_sha256, request_body_sha256, reporting_nonce_id, mutation_idempotency_id,
           acknowledged_at)
         VALUES ('${leg.acknowledgementId}', '${set.receiveOp}', '${NODE}', '${IMPLEMENTER}',
                 '${set.receiveTarget}', 1, 'VERIFIED', '${hex("2")}', '${bodySha256}',
                 '${leg.nonceId}', '${leg.idempotencyId}', now())`,
      );
    };
    expect(insertAck(hex("1")).ok).toBe(true);
    const second = insertAck(hex("5"));
    expect(second.ok).toBe(false);
    expect(extractSqlstate(second.stderr)).toBe("23505");
    expect(second.stderr).toContain("verification_acknowledgements_operation_id_key");
  });

  it("refuses a foreign reporting-credential tenant (composite operation FK)", async () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "receive-preimage",
      signature: signature("S"),
    });
    await expect(
      acknowledgeLeg(
        set.receiveOp,
        leg,
        receiveRequest(set, leg, { implementerId: "b0000000-0000-4000-8000-0000000000ee" }),
      ),
    ).rejects.toMatchObject({ reason: "TENANT_MISMATCH" });
    expect(groupCounts(url, set).acknowledgements).toBe(0);
  });

  it("refuses a stale expected_row_version against the durable operation", async () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "receive-preimage",
      signature: signature("S"),
    });
    await expect(
      acknowledgeLeg(set.receiveOp, leg, receiveRequest(set, leg, { expectedRowVersion: 3 })),
    ).rejects.toMatchObject({ reason: "OPERATION_VERSION_CONFLICT" });
    expect(groupCounts(url, set).acknowledgements).toBe(0);
  });

  /* ── byte discipline and read parity ─────────────────────────── */

  it("round-trips the exact signed preimage bytes and derives the same evidence digest", async () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    // Bytes that survive nothing but verbatim storage: quotes, braces, trailing space.
    const preimage = '{"purpose":"zp-report-request-v1","canonical_version":1,"x":"a\'b {} "}';
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: preimage,
      signature: signature("S"),
    });
    const request = receiveRequest(set, leg, { requestPreimageText: preimage });
    await acknowledgeLeg(set.receiveOp, leg, request);

    const stored = psqlMust(
      url,
      `SELECT a.evidence_set_sha256 || '#' || n.request_preimage_text
         FROM verification_acknowledgements a
         JOIN reporting_request_nonces n ON n.id = a.reporting_nonce_id
         WHERE a.operation_id = '${set.receiveOp}'`,
    ).trim();
    const separator = stored.indexOf("#");
    expect(stored.slice(0, separator)).toBe(computeEvidenceSetSha256(request.walletEvidence));
    expect(stored.slice(separator + 1)).toBe(preimage);

    // The identical request replays rather than conflicting, which holds only if the stored
    // bytes compare equal to the supplied ones.
    const replay = await withTx(url, async (session) =>
      acknowledgeWith(session, randomUUID())(set.receiveOp, request),
    );
    expect(replay.idempotentReplay).toBe(true);
  });

  it("reads a real two-leg group into the same facts the pure predicate judges", async () => {
    const set = seedOperationSet(url, "JOINED");
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "receive-preimage",
      signature: signature("S"),
    });
    await acknowledgeLeg(set.receiveOp, leg, receiveRequest(set, leg));

    const facts = await withTx(url, async (session) =>
      createSqlAcknowledgementStore().readGroupReleaseFacts(session, set.groupId),
    );
    expect(facts.childDisposition).toBe("JOINED");
    expect(facts.operations).toEqual([
      {
        operationId: set.receiveOp,
        kind: "RECEIVE_EXTERNAL",
        verdict: "VERIFIED",
        evidenceRoles: ["RECEIVER"],
        evidence: [
          {
            role: "RECEIVER",
            walletId: RCV_WALLET,
            walletPublicKey: pubkey("w3"),
          },
        ],
        expectedWallets: [
          {
            role: "RECEIVER",
            walletId: RCV_WALLET,
            walletPublicKey: pubkey("w3"),
          },
        ],
        completed: true,
      },
      {
        operationId: set.moveOp,
        kind: "MOVE_INTERNAL",
        verdict: null,
        evidenceRoles: [],
        evidence: [],
        expectedWallets: [
          {
            role: "SOURCE",
            walletId: SRC_WALLET,
            walletPublicKey: pubkey("w1"),
          },
          {
            role: "DESTINATION",
            walletId: DST_WALLET,
            walletPublicKey: pubkey("w2"),
          },
        ],
        completed: false,
      },
    ]);

    // The SQL read and the pure predicate agree, so the unit suite's cases bind the real path.
    expect(evaluateGroupRelease(facts).status).toBe("PINNED_GROUP_PENDING");
  });

  it("stamps the leg terminal in lease_group_operations, and a replay does not move the stamp", async () => {
    const set = seedOperationSet(url, "NONE", { joinChild: false });
    const leg = prepareLeg({
      rawTarget: set.receiveTarget,
      bodySha256: hex("1"),
      preimageText: "receive-preimage",
      signature: signature("S"),
    });
    const request = receiveRequest(set, leg);
    await acknowledgeLeg(set.receiveOp, leg, request);
    const stampedAt = psqlMust(
      url,
      `SELECT completed_at::text FROM lease_group_operations
        WHERE lease_group_id = '${set.groupId}' AND operation_id = '${set.receiveOp}'`,
    ).trim();
    expect(stampedAt).not.toBe("");

    await withTx(url, async (session) =>
      acknowledgeWith(session, randomUUID())(set.receiveOp, request),
    );
    expect(
      psqlMust(
        url,
        `SELECT completed_at::text FROM lease_group_operations
          WHERE lease_group_id = '${set.groupId}' AND operation_id = '${set.receiveOp}'`,
      ).trim(),
    ).toBe(stampedAt);
  });
});
