/**
 * operations.pg.test.ts
 *
 * Proves, against a REAL PostgreSQL database, that every table-level and
 * inline CHECK in the frozen `operations` contract, and the `operation_wallets` role
 * uniqueness, REJECTS ITS SPECIFIC VIOLATING INSERT — the review indicator. The
 * census and docs-artifact tests prove the DDL says what the doc says; only an executed
 * INSERT proves the database enforces it. A rejection is confirmed by SQLSTATE (23514
 * check_violation / 23505 unique_violation), never by string-matching an error message.
 *
 * FK-target stubs. operations REFERENCES nodes, implementers, wallets and destinations, and
 * no slice in this package creates them: nodes/implementers are registry, and the
 * spelling `wallets(id)` is the open reconciliation against the frozen custody
 * `wallets(wallet_id)` that operations.contract.ts inventories. This file therefore creates
 * minimal id-only stubs for the four targets before applying the contract unchanged. The
 * stubs exist so the CHECK matrix is reachable; nothing here asserts anything about them, and
 * migration-integrity.test.ts remains the record that operations.sql alone fails on nodes.
 *
 * No silent skip. An unreachable PostgreSQL is a hard failure: a green run that never reached
 * a database would be exactly the vacuous control this file exists to remove.
 */
import { execFile } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
// DB-TEST-05: every operation-kind/status/nullable-field invalid combination fails CHECK


import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { OPERATIONS_SCHEMA_FILE } from "../src/schema/operations.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const MAINTENANCE_DB = "postgres";
const SQLSTATE_CHECK_VIOLATION = "23514";
const SQLSTATE_UNIQUE_VIOLATION = "23505";

/** CREATE/DROP DATABASE budget. Generous because concurrent lanes share this server. */
const PROVISION_TIMEOUT_MS = 120_000;

// Own prefix, own database. Teardown drops ONLY the database this run created — a broader
// DROP takes out the concurrent lanes sharing this server.
const SCRATCH_DB = `operations_operations_${Date.now()}_${process.pid}`;

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * Server states that mean "come back in a moment", not "your SQL is wrong". Several lanes
 * share this PostgreSQL and connection-slot exhaustion otherwise arrives indistinguishable
 * from a broken schema. Nothing SQL-level is listed, so a real check_violation still fails on
 * the first attempt.
 */
const TRANSIENT_SERVER_STATE =
  /too many clients already|is being accessed by other users|the database system is (starting up|shutting down)/i;
const CAPACITY_ATTEMPTS = 6;
const CAPACITY_DELAY_MS = 3_000;

const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

/**
 * ASYNC on purpose: execFileSync would block the vitest worker's event loop for the whole of a
 * slow CREATE DATABASE, and the runner then raises `Timeout calling "onTaskUpdate"`, whose own
 * warning is "This might cause false positive tests".
 */
const spawnPsql = async (args: readonly string[], timeoutMs: number): Promise<PsqlOutcome> => {
  for (let attempt = 1; ; attempt += 1) {
    try {
      const { stdout } = await promisify(execFile)("psql", [...args], {
        encoding: "utf-8",
        timeout: timeoutMs,
      });
      return { ok: true, stdout, stderr: "" };
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; signal?: string; code?: string };
      // A timeout kill leaves stderr EMPTY, which would read like a DDL fault. Name it.
      const killed = e.signal === "SIGTERM" || e.code === "ETIMEDOUT";
      const stderr = killed
        ? `psql exceeded the ${timeoutMs}ms client timeout (killed, no server error). ${e.stderr ?? ""}`
        : (e.stderr ?? "");
      if (attempt < CAPACITY_ATTEMPTS && TRANSIENT_SERVER_STATE.test(stderr)) {
        await sleep(CAPACITY_DELAY_MS);
        continue;
      }
      return { ok: false, stdout: e.stdout ?? "", stderr };
    }
  }
};

const runPsql = async (db: string, sql: string, timeoutMs = 20_000): Promise<PsqlOutcome> =>
  spawnPsql(["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], timeoutMs);

const psqlMust = async (db: string, sql: string, timeoutMs?: number): Promise<string> => {
  const outcome = await runPsql(db, sql, timeoutMs);
  if (!outcome.ok) {
    throw new Error(`psql failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout.trim();
};

// ─── row construction ────────────────────────────────────────────────────────────────────
// Every case below is a full INSERT differing from a legal baseline in exactly the one column
// (or pair) whose CHECK it targets, so a rejection can only be that CHECK.

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const WALLET_A = "33333333-3333-4333-8333-333333333333";
const WALLET_B = "44444444-4444-4444-8444-444444444444";
const DESTINATION_ID = "55555555-5555-4555-8555-555555555555";
const OBSERVATION_ID = "66666666-6666-4666-8666-666666666666";
/** 43 base64url characters plus the `=` pad, per the data model padded_base64url_pubkey domain. */
const DESTINATION_ADDRESS = `${"A".repeat(43)}=`;
const DIGEST = "a".repeat(64);
/**
 * 16 visible-ASCII characters: the shortest key the reconciled grammar admits. Only the
 * four cases that deliberately probe UNIQUE (implementer_id, kind, idempotency_key) share it;
 * every other row derives a distinct key from its own id, so a rejection below can only be the
 * constraint that case targets and never an incidental idempotency collision.
 */
const IDEMPOTENCY_KEY = "k".repeat(16);

type Cell = string | null;
type Row = Record<string, Cell>;

/** uuid literal built from a case ordinal, so every row carries a distinct primary key. */
const opId = (n: number): string => `000000${String(n).padStart(2, "0")}-0000-4000-8000-000000000000`;

/** 32 visible-ASCII characters, unique per row: the id with its dashes removed. */
const keyFor = (id: string): string => id.replace(/-/g, "");

const baseRow = (id: string): Row => ({
  id,
  node_id: NODE_ID,
  implementer_id: IMPLEMENTER_ID,
  kind: "MOVE_INTERNAL",
  status: "CREATED",
  amount_zkz: "2.25",
  source_wallet_id: WALLET_A,
  destination_id: DESTINATION_ID,
  idempotency_key: keyFor(id),
  request_sha256: DIGEST,
});

/** A RECEIVE_EXTERNAL that has not been assigned a wallet yet: discriminator = id, anchor set. */
const receiveRow = (id: string): Row => ({
  id,
  node_id: NODE_ID,
  implementer_id: IMPLEMENTER_ID,
  kind: "RECEIVE_EXTERNAL",
  status: "CREATED",
  amount_zkz: "2.25",
  after_landing: "HOLD",
  discriminator: id,
  anchor: "anchor-0",
  idempotency_key: keyFor(id),
  request_sha256: DIGEST,
});

/** A RECEIVE_EXTERNAL past assignment: receiver wallet, expiry and T0 observation all present. */
const receiveReadyRow = (id: string): Row => ({
  ...receiveRow(id),
  status: "READY",
  receiver_wallet_id: WALLET_B,
  expiry_unix_time_secs: "1784883937",
  t0_observation_id: OBSERVATION_ID,
});

const sendRow = (id: string): Row => ({
  id,
  node_id: NODE_ID,
  implementer_id: IMPLEMENTER_ID,
  kind: "SEND_EXTERNAL",
  status: "CREATED",
  amount_zkz: "2.25",
  source_wallet_id: WALLET_A,
  destination_address: DESTINATION_ADDRESS,
  formation_state: "APPROVAL_PENDING",
  idempotency_key: keyFor(id),
  request_sha256: DIGEST,
});

/** Dollar-quoted: no value below contains `$z$`, so nothing needs escaping. */
const literal = (value: Cell): string => (value === null ? "NULL" : `$z$${value}$z$`);

const insert = (table: string, row: Row): string => {
  const columns = Object.keys(row);
  const values = columns.map((column) => literal(row[column] ?? null));
  return `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${values.join(", ")})`;
};

interface Case {
  /** What the insert violates, or "" when it is expected to be accepted. */
  readonly sqlstate: string;
  readonly statement: string;
}

let ordinal = 0;
const nextId = (): string => {
  ordinal += 1;
  return opId(ordinal);
};

const CASES: Readonly<Record<string, Case>> = {
  // ── legal baselines: one per public verb, so a rejection below is the override, not the shape
  MOVE_ACCEPTED: { sqlstate: "", statement: insert("operations", baseRow(nextId())) },
  RECEIVE_ACCEPTED: { sqlstate: "", statement: insert("operations", receiveRow(nextId())) },
  RECEIVE_READY_ACCEPTED: {
    sqlstate: "",
    statement: insert("operations", receiveReadyRow(nextId())),
  },
  SEND_ACCEPTED: { sqlstate: "", statement: insert("operations", sendRow(nextId())) },

  // ── amount: numeric positivity, not string `<> '0'`
  AMOUNT_ZERO: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), amount_zkz: "0" }),
  },
  AMOUNT_ZERO_ONE_DP: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), amount_zkz: "0.0" }),
  },
  AMOUNT_ZERO_TWO_DP: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), amount_zkz: "0.00" }),
  },
  AMOUNT_ZERO_32_DP: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...baseRow(nextId()),
      amount_zkz: `0.${"0".repeat(32)}`,
    }),
  },
  AMOUNT_AT_UPPER_BOUND: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), amount_zkz: "100000000" }),
  },
  AMOUNT_SMALLEST_POSITIVE_ACCEPTED: {
    sqlstate: "",
    statement: insert("operations", {
      ...baseRow(nextId()),
      amount_zkz: `0.${"0".repeat(31)}1`,
    }),
  },

  // ── CAS predicate
  ROW_VERSION_ZERO: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), row_version: "0" }),
  },

  // ── kind ↔ discriminator / anchor / expiry coupling
  MOVE_CARRYING_DISCRIMINATOR: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), discriminator: opId(90) }),
  },
  RECEIVE_MISSING_ANCHOR: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...receiveRow(nextId()), anchor: null }),
  },
  RECEIVE_DISCRIMINATOR_NOT_ID: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...receiveRow(nextId()), discriminator: opId(91) }),
  },
  RECEIVE_ANCHOR_OFF_GRAMMAR: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...receiveRow(nextId()), anchor: "not an anchor!" }),
  },

  // ── RECEIVE status ↔ receiver wallet / expiry / T0 triple
  RECEIVE_ASSIGNED_WITHOUT_EXPIRY: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...receiveReadyRow(nextId()),
      expiry_unix_time_secs: null,
    }),
  },
  RECEIVE_ASSIGNED_WITHOUT_T0: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...receiveReadyRow(nextId()), t0_observation_id: null }),
  },

  // ── the never-assigned receive expires in place. node-core step 5 and
  // operation flows expire a receive that outwaited RECEIVE_QUEUE_MAX_WAIT with no
  // wallet and no lease; the earlier arms made that row unrepresentable. Only EXPIRED
  // joined CREATED, and only in the walletless arm — the rest of the matrix must still reject.
  RECEIVE_EXPIRED_UNASSIGNED_ACCEPTED: {
    sqlstate: "",
    statement: insert("operations", { ...receiveRow(nextId()), status: "EXPIRED" }),
  },
  RECEIVE_EXPIRED_ASSIGNED_ACCEPTED: {
    sqlstate: "",
    statement: insert("operations", { ...receiveReadyRow(nextId()), status: "EXPIRED" }),
  },
  RECEIVE_EXPIRED_UNASSIGNED_CARRYING_EXPIRY: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...receiveRow(nextId()),
      status: "EXPIRED",
      expiry_unix_time_secs: "1784883937",
    }),
  },
  RECEIVE_EXPIRED_UNASSIGNED_CARRYING_T0: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...receiveRow(nextId()),
      status: "EXPIRED",
      t0_observation_id: OBSERVATION_ID,
    }),
  },
  RECEIVE_READY_WITHOUT_WALLET: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...receiveRow(nextId()), status: "READY" }),
  },
  RECEIVE_LANDED_WITHOUT_WALLET: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...receiveRow(nextId()), status: "RECEIVE_LANDED" }),
  },

  // ── expiry grammar (unix SECONDS as a bare digit string)
  EXPIRY_NOT_DIGITS: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...receiveReadyRow(nextId()),
      expiry_unix_time_secs: "17e9",
    }),
  },
  EXPIRY_NEGATIVE: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...receiveReadyRow(nextId()),
      expiry_unix_time_secs: "-1",
    }),
  },

  // ── per-kind column-presence triple
  MOVE_WITHOUT_SOURCE: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), source_wallet_id: null }),
  },
  SEND_CARRYING_DESTINATION_ID: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...sendRow(nextId()), destination_id: DESTINATION_ID }),
  },
  RECEIVE_CARRYING_SOURCE_WALLET: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...receiveRow(nextId()), source_wallet_id: WALLET_A }),
  },

  // ── after_landing coupling and its inline literal set
  AFTER_LANDING_MOVE_WITHOUT_DESTINATION: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...receiveRow(nextId()), after_landing: "INTERNAL_MOVE" }),
  },
  AFTER_LANDING_OFF_LITERAL_SET: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...receiveRow(nextId()), after_landing: "BURN" }),
  },

  // ── kind → allowed-status whitelist
  MOVE_IN_RECEIVE_STATUS: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), status: "READY" }),
  },
  RECEIVE_IN_SEND_STATUS: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...receiveRow(nextId()), status: "APPROVED" }),
  },

  // ── SEND_EXTERNAL ⇔ formation_state <> NOT_REQUIRED, and the formation/status lockstep
  MOVE_WITH_FORMATION_STATE: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...baseRow(nextId()),
      formation_state: "APPROVAL_PENDING",
    }),
  },
  SEND_WITHOUT_FORMATION_STATE: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...sendRow(nextId()), formation_state: "NOT_REQUIRED" }),
  },
  SEND_FORMATION_OFF_LOCKSTEP: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...sendRow(nextId()),
      formation_state: "PARTIAL_DELIVERED",
    }),
  },
  // AWAITING_REDEMPTION may sit at PARTIAL_PERSISTED (operation flows step 3) before
  // delivery advances formation to PARTIAL_DELIVERED. The draft CHECK rejected this pair.
  SEND_AWAITING_AT_PARTIAL_PERSISTED: {
    sqlstate: "",
    statement: insert("operations", {
      ...sendRow(nextId()),
      status: "AWAITING_REDEMPTION",
      formation_state: "PARTIAL_PERSISTED",
    }),
  },
  // EXTERNAL_SEND_LANDED still requires PARTIAL_DELIVERED — PARTIAL_PERSISTED is not enough.
  SEND_LANDED_AT_PARTIAL_PERSISTED: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...sendRow(nextId()),
      status: "EXTERNAL_SEND_LANDED",
      formation_state: "PARTIAL_PERSISTED",
    }),
  },

  // ── attention coupling
  ATTENTION_FLAG_WITHOUT_REASON: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), attention_required: "true" }),
  },
  ATTENTION_REASON_WITHOUT_FLAG: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), attention_reason: "stalled" }),
  },

  // ── terminal ordering
  TERMINAL_BEFORE_CREATED: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...baseRow(nextId()),
      created_at: "2026-07-24T00:00:00Z",
      terminal_at: "2026-07-23T00:00:00Z",
    }),
  },

  // ── idempotency-key grammar, reconciled to the API contract by
  IDEMPOTENCY_KEY_TOO_SHORT: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), idempotency_key: "k".repeat(15) }),
  },
  IDEMPOTENCY_KEY_TOO_LONG: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", { ...baseRow(nextId()), idempotency_key: "k".repeat(256) }),
  },
  IDEMPOTENCY_KEY_NON_VISIBLE_ASCII: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operations", {
      ...baseRow(nextId()),
      idempotency_key: `k${" ".repeat(1)}${"k".repeat(15)}`,
    }),
  },

  // ── UNIQUE (implementer_id, kind, idempotency_key): the idempotency backbone. The racer
  // loses regardless of whether its request digest matches (turns the former into a
  // replay and the latter into a 409 — both above this layer).
  IDEMPOTENCY_FIRST_CLAIM: {
    sqlstate: "",
    statement: insert("operations", {
      ...baseRow(nextId()),
      idempotency_key: IDEMPOTENCY_KEY,
    }),
  },
  IDEMPOTENCY_REPLAY_SAME_DIGEST: {
    sqlstate: SQLSTATE_UNIQUE_VIOLATION,
    statement: insert("operations", {
      ...baseRow(nextId()),
      idempotency_key: IDEMPOTENCY_KEY,
      source_wallet_id: WALLET_B,
    }),
  },
  IDEMPOTENCY_CONFLICT_OTHER_DIGEST: {
    sqlstate: SQLSTATE_UNIQUE_VIOLATION,
    statement: insert("operations", {
      ...baseRow(nextId()),
      idempotency_key: IDEMPOTENCY_KEY,
      request_sha256: "b".repeat(64),
    }),
  },
  IDEMPOTENCY_SCOPED_BY_KIND: {
    // Same implementer, same key, different kind — the scope is the triple, not the key.
    sqlstate: "",
    statement: insert("operations", {
      ...receiveRow(nextId()),
      idempotency_key: IDEMPOTENCY_KEY,
    }),
  },

  // ── operation_wallets: composite PK and one row per role
  ROLE_SOURCE_ACCEPTED: {
    sqlstate: "",
    statement: insert("operation_wallets", {
      operation_id: opId(1),
      wallet_id: WALLET_A,
      operation_role: "SOURCE",
    }),
  },
  ROLE_DESTINATION_ACCEPTED: {
    sqlstate: "",
    statement: insert("operation_wallets", {
      operation_id: opId(1),
      wallet_id: WALLET_B,
      operation_role: "DESTINATION",
    }),
  },
  ROLE_SECOND_SOURCE_REJECTED: {
    sqlstate: SQLSTATE_UNIQUE_VIOLATION,
    statement: insert("operation_wallets", {
      operation_id: opId(1),
      wallet_id: WALLET_B,
      operation_role: "SOURCE",
    }),
  },
  ROLE_DUPLICATE_PRIMARY_KEY: {
    sqlstate: SQLSTATE_UNIQUE_VIOLATION,
    statement: insert("operation_wallets", {
      operation_id: opId(1),
      wallet_id: WALLET_A,
      operation_role: "RECEIVER",
    }),
  },
  ROLE_OFF_LITERAL_SET: {
    sqlstate: SQLSTATE_CHECK_VIOLATION,
    statement: insert("operation_wallets", {
      operation_id: opId(1),
      wallet_id: WALLET_B,
      operation_role: "SENDER",
    }),
  },
};

/**
 * FK-target stubs, id-only. See the file header: the real registries are other slices, and the
 * `wallets(id)` spelling is the open reconciliation.
 */
const FK_STUBS = `
CREATE TABLE nodes (id uuid PRIMARY KEY);
CREATE TABLE implementers (id uuid PRIMARY KEY);
CREATE TABLE wallets (id uuid PRIMARY KEY);
CREATE TABLE destinations (id uuid PRIMARY KEY);
INSERT INTO nodes (id) VALUES ($z$${NODE_ID}$z$);
INSERT INTO implementers (id) VALUES ($z$${IMPLEMENTER_ID}$z$);
INSERT INTO wallets (id) VALUES ($z$${WALLET_A}$z$), ($z$${WALLET_B}$z$);
INSERT INTO destinations (id) VALUES ($z$${DESTINATION_ID}$z$);
`;

interface InsertOutcome {
  readonly ok: boolean;
  readonly sqlstate: string;
}

const outcomes = new Map<string, InsertOutcome>();

/**
 * Every case in ONE round trip, each in its own sub-transaction so a rejection rolls back only
 * that insert. Order is preserved, which the duplicate cases rely on: they must run after the
 * baseline row they collide with.
 */
const probeAllInserts = async (): Promise<void> => {
  const rows = Object.entries(CASES)
    // Outer tag differs from the `$z$` the statements themselves use — nesting the same tag
    // terminates the outer literal at the first inner one.
    .map(([name, { statement }], index) => `(${index}, $n$${name}$n$, $s$${statement}$s$)`)
    .join(",\n    ");
  const sql = `
CREATE TEMP TABLE insert_probe (name text, ok boolean, state text);
DO $probe$
DECLARE
  r record;
BEGIN
  FOR r IN SELECT * FROM (VALUES
    ${rows}
  ) AS t(seq, name, stmt) ORDER BY t.seq LOOP
    BEGIN
      EXECUTE r.stmt;
      INSERT INTO insert_probe VALUES (r.name, true, NULL);
    EXCEPTION WHEN others THEN
      INSERT INTO insert_probe VALUES (r.name, false, SQLSTATE);
    END;
  END LOOP;
END
$probe$;
SELECT name, ok, coalesce(state, '') FROM insert_probe;
`;
  const rendered = await psqlMust(SCRATCH_DB, sql, PROVISION_TIMEOUT_MS);
  for (const line of rendered.split("\n")) {
    if (line === "") continue;
    const [name, ok, state] = line.split("|");
    outcomes.set(name ?? "", { ok: ok === "t", sqlstate: state ?? "" });
  }
  const expected = Object.keys(CASES).length;
  if (outcomes.size !== expected) {
    throw new Error(
      `insert probe returned ${outcomes.size} outcomes, expected ${expected} — some case never ` +
        `executed, so an assertion below would read an absent result`,
    );
  }
};

/** Throws rather than defaulting: an unprobed case must fail, never quietly pass. */
const outcomeOf = (name: string): InsertOutcome => {
  const outcome = outcomes.get(name);
  if (outcome === undefined) {
    throw new Error(`${name} was never executed against the database`);
  }
  return outcome;
};

let defaultRowVersion = "";
let assertionsRun = 0;

beforeAll(async () => {
  const probe = await runPsql(MAINTENANCE_DB, "SELECT 1");
  if (!probe.ok) {
    throw new Error(
      `requires a real PostgreSQL server: maintenance database "${MAINTENANCE_DB}" is ` +
        `not usable, so the CHECK matrix was never executed. This is a hard failure, not a ` +
        `skip. psql said: ${probe.stderr.trim() || "unknown error"}`,
    );
  }
  // TEMPLATE template0: template1 accepts connections, so a concurrent lane holding one makes
  // PostgreSQL refuse with a message indistinguishable from a broken DDL.
  await psqlMust(
    MAINTENANCE_DB,
    `CREATE DATABASE ${SCRATCH_DB} TEMPLATE template0`,
    PROVISION_TIMEOUT_MS,
  );
  await psqlMust(SCRATCH_DB, FK_STUBS, PROVISION_TIMEOUT_MS);
  const applied = await spawnPsql(
    ["-d", SCRATCH_DB, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, OPERATIONS_SCHEMA_FILE)],
    PROVISION_TIMEOUT_MS,
  );
  if (!applied.ok) {
    throw new Error(
      `${OPERATIONS_SCHEMA_FILE} apply failed over the FK stubs: ${applied.stderr.trim() || "unknown error"}`,
    );
  }
  await probeAllInserts();
  defaultRowVersion = await psqlMust(
    SCRATCH_DB,
    `SELECT DISTINCT row_version::text FROM operations`,
  );
  // Explicit hook timeout: the 10s default turns CREATE DATABASE contention from concurrent
  // lanes into a red "N skipped" run that reads like a pass.
}, PROVISION_TIMEOUT_MS * 2);

afterAll(async () => {
  await runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${SCRATCH_DB}`, PROVISION_TIMEOUT_MS);
}, PROVISION_TIMEOUT_MS * 2);

describe("operations / operation_wallets against real PostgreSQL", () => {
  it("DB-TEST-05: every operation-kind/status/nullable-field invalid combination fails CHECK", () => {
    // beforeAll throws on a failed apply; reaching any assertion at all proves it applied.
    expect(outcomes.size).toBe(Object.keys(CASES).length);
  });

  it.each(Object.entries(CASES).filter(([, c]) => c.sqlstate === "").map(([name]) => name))(
    "accepts the legal row: %s",
    (name) => {
      const outcome = outcomeOf(name);
      assertionsRun += 1;
      expect(outcome.ok, `${name} was rejected with SQLSTATE ${outcome.sqlstate}`).toBe(true);
    },
  );

  it.each(Object.entries(CASES).filter(([, c]) => c.sqlstate !== "").map(([name]) => name))(
    "rejects the violating insert: %s",
    (name) => {
      const outcome = outcomeOf(name);
      assertionsRun += 1;
      expect(outcome.ok, `${name} was ACCEPTED — its constraint does not enforce`).toBe(false);
      expect(outcome.sqlstate, `${name} failed on the wrong constraint class`).toBe(
        CASES[name]?.sqlstate,
      );
    },
  );

  it("row_version starts at 1 on every accepted row (the CAS predicate's origin)", () => {
    assertionsRun += 1;
    expect(defaultRowVersion).toBe("1");
  });

  it("obligation guard: every case ran against the database", () => {
    // vitest reports a suite that never executed as a pass. This turns an undischarged
    // obligation into a red rather than a silent green.
    expect(assertionsRun).toBe(Object.keys(CASES).length + 1);
  });
});
