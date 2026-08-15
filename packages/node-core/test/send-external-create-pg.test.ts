/**
 * send-external-create-pg.test.ts
 *
 * Proves, against a REAL PostgreSQL database running the REAL frozen
 * DDL (src/schema/send-external-create.sql, applied after its prerequisite
 * custody-eligibility.sql), that the money-path invariants this slice exists to guarantee
 * are enforced BY THE DATABASE and cannot be satisfied by an in-memory fake:
 *
 *   1. The one-in-flight-per-wallet rule — a second UNSETTLED external send from the same source wallet is
 *      rejected with unique_violation (SQLSTATE 23505) on
 *      send_operations_one_unsettled_per_source_wallet. A terminal predecessor does NOT
 *      block a fresh send, proving the partial predicate is a real state test rather than a
 *      blanket uniqueness; a NEEDS_ATTENTION predecessor DOES block, proving NEEDS_ATTENTION
 *      is not treated as terminal. The predicate EXCLUDES the terminal pair rather than
 *      listing the non-terminal states, and that direction is drilled directly: extending the
 *      status vocabulary without touching the index still refuses the second send
 *      (fail-closed), where a positive allowlist would have admitted it.
 * 2. Idempotency — a second row carrying the same
 *      (implementer_id, http_method, route, idempotency_key) tuple is rejected with 23505 on
 *      send_operations_idempotency_scope.
 *   3. — a mathematically zero amount is rejected by send_operations_amount_positive
 *      with check_violation (23514), at rest, not merely by the application validator.
 *   4. Immutability (parent exit criterion) — updating source_wallet_id,
 *      destination_address, amount_zkz or references_operation_id raises
 *      SEND_IMMUTABLE_FIELD_REJECTED, while a legitimate status advance succeeds.
 * 5. the data model — exactly one artifact per operation (UNIQUE), insert-only
 *      (UPDATE and DELETE both raise SEND_ARTIFACT_INSERT_ONLY).
 * 6. step 3 atomicity — the store's create statement writes the operation row and its
 *      artifact together or not at all, and a one-in-flight-per-wallet rejection leaves neither.
 *
 * Load-bearing detail: the arbiter drills run the store's OWN statement text
 * (SqlSendCreateStore's STATEMENTS.INSERT_CREATED) through PostgreSQL PREPARE / EXECUTE, not
 * a hand-written mirror. PREPARE resolves `ON CONFLICT ON CONSTRAINT
 * send_operations_idempotency_scope` against the live catalog, so a renamed or missing
 * constraint fails here rather than silently degrading to a swallowed conflict. It also
 * proves the ON CONFLICT clause is narrowly targeted: it absorbs the idempotency constraint
 * and does NOT absorb the one-in-flight-per-wallet index, whose 23505 still propagates.
 *
 * Harness: this file provisions its OWN hermetic scratch database named for this suite
 * (nothing outside the send_external_create_send_create_ prefix is created or dropped — the server is
 * shared), applies the real DDL, runs the drills, and drops only that database. It is the
 * same shape as test/custody-eligibility-lease-pk.test.ts, deliberately: psql runs as a child
 * process, which keeps the in-process network-containment guard intact, and the
 * fail-closed guard at the bottom turns an undischarged obligation into a hard FAILURE
 * whenever PostgreSQL is reachable, so this can never silently skip itself into a no-op.
 *
 * PG_REQUIRED race guard: mirrors custody-eligibility-lease-pk.test.ts. scripts/verify-local.sh
 * exports PG_REQUIRED=1 to child processes ONLY after its own probe found Postgres reachable,
 * so PG_REQUIRED=1 with an unusable database is a race / broken gate and fails hard, never
 * skips.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { OPERATION_COLUMNS, STATEMENTS } from "../src/send/sql-store.js";
import { verificationModeFixtureSql } from "./verification-mode-fixture.js";

/* ─── constants ───────────────────────────────────────────────────── */

const MAINTENANCE_DB = "postgres";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_CHECK_VIOLATION = "23514";
const SQLSTATE_RAISE_EXCEPTION = "P0001";
const IDEMPOTENCY_CONSTRAINT = "send_operations_idempotency_scope";
const SOURCE_IN_FLIGHT_INDEX = "send_operations_one_unsettled_per_source_wallet";
const ARTIFACT_OPERATION_UNIQUE = "send_operation_expected_artifacts_operation_id_key";
const AMOUNT_CONSTRAINT = "send_operations_amount_positive";
const EXPECTED_DRILL_COUNT = 12;

/* ─── psql helpers (same shape as custody-eligibility-lease-pk.test.ts) ─── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) {
    args.push("-v", "VERBOSITY=verbose");
  }
  args.push("-qAt", "-c", sql);
  try {
    const stdout = execFileSync("psql", args, {
      encoding: "utf-8",
      timeout: 15_000,
      // The drills provoke intentional constraint violations; their psql ERROR output is
      // asserted on, not console noise.
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

// Setup/seed statements MUST succeed; a failure here is a real error and is thrown, never
// swallowed into a green run that tested nothing.
const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const applyDdl = (db: string, ddl: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      input: ddl,
      encoding: "utf-8",
      timeout: 30_000,
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(
      `send-external-create DDL apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`,
    );
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const extractConstraint = (stderr: string): string => {
  const m = /CONSTRAINT NAME:\s+(\S+)/.exec(stderr);
  return m === null ? "" : m[1];
};

/* ─── real frozen DDL, in prerequisite sequence ───────────────────── */

// custody-eligibility.sql declares wallets and destinations; send-external-create.sql
// foreign-keys into wallets. An FK needs its target relation to exist EARLIER in the
// sequence, so the arrangement below is the contract, not a convenience.
// Custody is prerequisite-bound (base enums/domains + nodes).
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

const CUSTODY_DDL = readSchema("custody-eligibility.sql");
const SEND_DDL = readSchema("send-external-create.sql");

/* ─── fixtures ────────────────────────────────────────────────────── */

const NODE_ID = "c1000000-0000-4000-8000-000000000001";
const IMPLEMENTER_ID = "c1000000-0000-4000-8000-000000000002";
const SIGNING_KEY_ID = "c1000000-0000-4000-8000-000000000003";

const SOURCE_WALLET = "d1000000-0000-4000-8000-000000000001";
const OTHER_WALLET = "d1000000-0000-4000-8000-000000000002";
const RECOVERY_ID = "d1000000-0000-4000-8000-000000000003";
const RECOVERY_ID_2 = "d1000000-0000-4000-8000-000000000004";

const SHA_A = "a".repeat(64);
const DESTINATION = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const OTHER_DESTINATION = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const PREIMAGE_TEXT = "zp-send-external-expected-v1\n{}";
const SIGNATURE = `${"A".repeat(86)}==`;

// public_key is padded_base64url_pubkey; export_sha256 is sha256_hex.
const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const seedNode = (): string =>
  `INSERT INTO nodes (id, display_name, identity_public_key) ` +
  `VALUES ('${NODE_ID}', 'send-external-create-send-create', '${pubkey("NODE")}') ON CONFLICT (id) DO NOTHING;`;

// A node-generated, recovery-verified, AVAILABLE wallet. Recovery is stamped by UPDATE
// because wallets.recovery_verification_id foreign-keys wallet_recovery_verifications, which
// itself references wallets — the verification row cannot exist before its wallet.
const seedVerifiedWallet = (walletId: string, recoveryId: string, publicKey: string): string =>
  `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
  `VALUES ('${walletId}', '${NODE_ID}', '${publicKey}', 'node_generated', 'AVAILABLE'); ` +
  `INSERT INTO wallet_recovery_verifications ` +
  `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
  `VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${SHA_A}', '${publicKey}', ` +
  `'${recoveryId}', now(), 'send-external-create-test'); ` +
  `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
  `WHERE id = '${walletId}';`;

/* ─── the store's OWN create statement, driven through PREPARE/EXECUTE ─── */

interface InsertArgs {
  readonly operationId: string;
  readonly artifactId: string;
  readonly idempotencyKey: string;
  readonly requestSha256?: string;
  readonly amountZkz?: string;
  readonly status?: string;
  readonly sourceWalletId?: string;
  readonly destinationAddress?: string;
  readonly referencesOperationId?: string | null;
}

const lit = (value: string | number | boolean | null): string => {
  if (value === null) return "NULL";
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return String(value);
  return `'${value}'`;
};

// PREPARE resolves ON CONFLICT ON CONSTRAINT against the live catalog, so a missing or
// renamed constraint fails the drill outright rather than degrading to a silently swallowed
// conflict. A prepared statement is session-scoped and each psql invocation is a fresh
// session, so the PREPARE ships with every EXECUTE.
const PREPARE_INSERT = `PREPARE send_create AS ${STATEMENTS.INSERT_CREATED};`;

// Argument list for STATEMENTS.INSERT_CREATED: OPERATION_COLUMNS sequence, then
// ARTIFACT_COLUMNS sequence minus operation_id, which the statement takes from the CTE.
const executeInsert = (args: InsertArgs): string =>
  `${PREPARE_INSERT} EXECUTE send_create(${[
    lit(args.operationId),
    lit(IMPLEMENTER_ID),
    lit(NODE_ID),
    lit("SEND_EXTERNAL"),
    lit(args.status ?? "CREATED"),
    lit(1),
    lit(false),
    lit("APPROVAL_PENDING"),
    lit("POST"),
    lit("/v1/external-sends"),
    lit(args.idempotencyKey),
    lit(args.requestSha256 ?? SHA_A),
    lit(args.sourceWalletId ?? SOURCE_WALLET),
    lit(args.destinationAddress ?? DESTINATION),
    lit(args.amountZkz ?? "2.25"),
    lit(args.referencesOperationId ?? null),
    lit(null),
    lit(null),
    lit(1700000000000),
    lit("INDEPENDENT"),
    lit(args.artifactId),
    lit("zp-send-external-expected-v1"),
    lit(1),
    lit(SIGNING_KEY_ID),
    lit(PREIMAGE_TEXT),
    lit(SHA_A),
    lit(SIGNATURE),
  ].join(", ")});`;

// The same operation row written with a plain INSERT, so the constraint — not ON CONFLICT DO
// NOTHING — is the thing observed rejecting the duplicate.
const rawOperationInsert = (args: InsertArgs): string =>
  `INSERT INTO send_operations (${OPERATION_COLUMNS.join(", ")}) VALUES (${[
    lit(args.operationId),
    lit(IMPLEMENTER_ID),
    lit(NODE_ID),
    lit("SEND_EXTERNAL"),
    lit(args.status ?? "CREATED"),
    lit(1),
    lit(false),
    lit("APPROVAL_PENDING"),
    lit("POST"),
    lit("/v1/external-sends"),
    lit(args.idempotencyKey),
    lit(args.requestSha256 ?? SHA_A),
    lit(args.sourceWalletId ?? SOURCE_WALLET),
    lit(args.destinationAddress ?? DESTINATION),
    lit(args.amountZkz ?? "2.25"),
    lit(args.referencesOperationId ?? null),
    lit(null),
    lit(null),
  ].join(", ")}, now(), 'INDEPENDENT');`;

const rawArtifactInsert = (artifactId: string, operationId: string): string =>
  `INSERT INTO send_operation_expected_artifacts ` +
  `(artifact_id, operation_id, purpose, canonical_version, signing_key_id, preimage_text, preimage_sha256, signature) ` +
  `VALUES ('${artifactId}', '${operationId}', 'zp-send-external-expected-v1', 1, '${SIGNING_KEY_ID}', ` +
  `'${PREIMAGE_TEXT}', '${SHA_A}', '${SIGNATURE}');`;

const countRows = (db: string, table: string, where: string): string =>
  runPsql(db, `SELECT count(*) FROM ${table} WHERE ${where};`).stdout.trim();

/* ─── suite ───────────────────────────────────────────────────────── */

const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

let assertionsRun = 0;

describeIfPg("external-send create — real frozen DDL against real PostgreSQL", () => {
  const scratchDb = `send_external_create_send_create_${Date.now()}_${process.pid}`;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    // prerequisite chain, then custody, then send-external (FK target must exist first).
    applyDdl(scratchDb, prerequisiteDdl);
    applyDdl(scratchDb, CUSTODY_DDL);
    applyDdl(scratchDb, SEND_DDL);
    applyDdl(scratchDb, verificationModeFixtureSql());
    psqlMust(scratchDb, seedNode());
    psqlMust(scratchDb, seedVerifiedWallet(SOURCE_WALLET, RECOVERY_ID, pubkey("SRC")));
    psqlMust(scratchDb, seedVerifiedWallet(OTHER_WALLET, RECOVERY_ID_2, pubkey("OTH")));
  });

  afterAll(() => {
    // Scoped teardown: only the database this suite created. The server is shared.
    psqlMust(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  it("the store's own INSERT_CREATED writes the operation and its one artifact atomically", () => {
    const outcome = runPsql(
      scratchDb,
      executeInsert({
        operationId: "e1000000-0000-4000-8000-000000000001",
        artifactId: "f1000000-0000-4000-8000-000000000001",
        idempotencyKey: "idem-key-send-drill-0001",
      }),
    );
    expect(outcome.ok, outcome.stderr).toBe(true);
    expect(outcome.stdout.trim()).toBe("e1000000-0000-4000-8000-000000000001");
    // The artifact's operation_id comes from the CTE, so it can only ever name the operation
    // this same statement inserted.
    expect(
      countRows(
        scratchDb,
        "send_operation_expected_artifacts",
        `operation_id = 'e1000000-0000-4000-8000-000000000001'`,
      ),
    ).toBe("1");
    assertionsRun += 1;
  });

  it("rejects a duplicate idempotency scope tuple with unique_violation (23505)", () => {
    const duplicate = runPsql(
      scratchDb,
      rawOperationInsert({
        operationId: "e1000000-0000-4000-8000-000000000002",
        artifactId: "f1000000-0000-4000-8000-000000000002",
        idempotencyKey: "idem-key-send-drill-0001",
        sourceWalletId: OTHER_WALLET,
      }),
      true,
    );
    expect(duplicate.ok, "a second row for one idempotency scope must be rejected").toBe(false);
    expect(extractSqlstate(duplicate.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(duplicate.stderr)).toBe(IDEMPOTENCY_CONSTRAINT);
    assertionsRun += 1;
  });

  it("the store's own statement absorbs the idempotency conflict and creates no second row", () => {
    const follower = runPsql(
      scratchDb,
      executeInsert({
        operationId: "e1000000-0000-4000-8000-000000000003",
        artifactId: "f1000000-0000-4000-8000-000000000003",
        idempotencyKey: "idem-key-send-drill-0001",
      }),
    );
    // ON CONFLICT DO NOTHING: the follower returns no row, so the store reports
    // IDEMPOTENCY_CONFLICT rather than creating a second operation — and because the artifact
    // insert selects FROM the empty CTE, no orphan artifact is written either.
    expect(follower.ok, follower.stderr).toBe(true);
    expect(follower.stdout.trim()).toBe("");
    expect(
      countRows(scratchDb, "send_operations", `idempotency_key = 'idem-key-send-drill-0001'`),
    ).toBe("1");
    expect(
      countRows(
        scratchDb,
        "send_operation_expected_artifacts",
        `artifact_id = 'f1000000-0000-4000-8000-000000000003'`,
      ),
    ).toBe("0");
    assertionsRun += 1;
  });

  it("The one-in-flight-per-wallet rule: a second unsettled send for one source wallet is rejected with 23505", () => {
    // Different idempotency key, so the scope constraint cannot be what rejects it — and the
    // store's own statement is used, proving its ON CONFLICT clause does NOT swallow this.
    const second = runPsql(
      scratchDb,
      executeInsert({
        operationId: "e1000000-0000-4000-8000-000000000004",
        artifactId: "f1000000-0000-4000-8000-000000000004",
        idempotencyKey: "idem-key-send-drill-0002",
      }),
      true,
    );
    expect(second.ok, "a second in-flight send for one wallet must be rejected").toBe(false);
    expect(extractSqlstate(second.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(second.stderr)).toBe(SOURCE_IN_FLIGHT_INDEX);
    // Nothing partial survives the rejection: no operation row and no artifact row.
    expect(
      countRows(scratchDb, "send_operations", `operation_id = 'e1000000-0000-4000-8000-000000000004'`),
    ).toBe("0");
    expect(
      countRows(
        scratchDb,
        "send_operation_expected_artifacts",
        `artifact_id = 'f1000000-0000-4000-8000-000000000004'`,
      ),
    ).toBe("0");
    assertionsRun += 1;
  });

  it("The one-in-flight-per-wallet rule: a NEEDS_ATTENTION predecessor still holds the source wallet", () => {
    // the state-event reference keeps the source lease held at NEEDS_ATTENTION, so it is
    // deliberately absent from the index's terminal exclusion list and still holds the wallet.
    psqlMust(
      scratchDb,
      `UPDATE send_operations SET status = 'NEEDS_ATTENTION' WHERE operation_id = 'e1000000-0000-4000-8000-000000000001';`,
    );
    const blocked = runPsql(
      scratchDb,
      executeInsert({
        operationId: "e1000000-0000-4000-8000-000000000005",
        artifactId: "f1000000-0000-4000-8000-000000000005",
        idempotencyKey: "idem-key-send-drill-0003",
      }),
      true,
    );
    expect(blocked.ok, "NEEDS_ATTENTION is not terminal and must keep holding the wallet").toBe(false);
    expect(extractSqlstate(blocked.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(blocked.stderr)).toBe(SOURCE_IN_FLIGHT_INDEX);
    assertionsRun += 1;
  });

  it("a TERMINAL predecessor does not block a fresh send for the same source wallet", () => {
    psqlMust(
      scratchDb,
      `UPDATE send_operations SET status = 'EXTERNAL_SEND_LANDED' WHERE operation_id = 'e1000000-0000-4000-8000-000000000001';`,
    );
    const fresh = runPsql(
      scratchDb,
      executeInsert({
        operationId: "e1000000-0000-4000-8000-000000000006",
        artifactId: "f1000000-0000-4000-8000-000000000006",
        idempotencyKey: "idem-key-send-drill-0004",
      }),
    );
    expect(fresh.ok, fresh.stderr).toBe(true);
    expect(fresh.stdout.trim()).toBe("e1000000-0000-4000-8000-000000000006");
    assertionsRun += 1;
  });

  it("a mathematically zero amount is rejected by the CHECK (23514)", () => {
    // '0.00' matches the canonical-decimal regex and is <> '0' as a string. Only NUMERIC
    // positivity rejects it, and it is rejected at rest, not merely by the app validator.
    const zero = runPsql(
      scratchDb,
      rawOperationInsert({
        operationId: "e1000000-0000-4000-8000-000000000011",
        artifactId: "f1000000-0000-4000-8000-000000000011",
        idempotencyKey: "idem-key-send-drill-0005",
        sourceWalletId: OTHER_WALLET,
        amountZkz: "0.00",
      }),
      true,
    );
    expect(zero.ok, "a mathematically zero amount_zkz must be rejected by the database").toBe(false);
    expect(extractSqlstate(zero.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    expect(extractConstraint(zero.stderr)).toBe(AMOUNT_CONSTRAINT);
    assertionsRun += 1;
  });

  it("an amount at or above 1e8 is rejected by the same CHECK (23514)", () => {
    const tooLarge = runPsql(
      scratchDb,
      rawOperationInsert({
        operationId: "e1000000-0000-4000-8000-000000000012",
        artifactId: "f1000000-0000-4000-8000-000000000012",
        idempotencyKey: "idem-key-send-drill-0006",
        sourceWalletId: OTHER_WALLET,
        amountZkz: "100000000",
      }),
      true,
    );
    expect(tooLarge.ok, "amount_zkz must be strictly below 1e8 at rest").toBe(false);
    expect(extractSqlstate(tooLarge.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    expect(extractConstraint(tooLarge.stderr)).toBe(AMOUNT_CONSTRAINT);
    assertionsRun += 1;
  });

  it("the four immutable economic fields cannot be rewritten after commit", () => {
    // Parent exit criterion, structurally: this is what makes
    // approval-tuple rebuild-and-compare check meaningful.
    const target = "e1000000-0000-4000-8000-000000000006";
    const mutations: readonly string[] = [
      `source_wallet_id = '${OTHER_WALLET}'`,
      `destination_address = '${OTHER_DESTINATION}'`,
      `amount_zkz = '9.99'`,
      `references_operation_id = 'e1000000-0000-4000-8000-000000000001'`,
    ];
    for (const set of mutations) {
      const rejected = runPsql(
        scratchDb,
        `UPDATE send_operations SET ${set} WHERE operation_id = '${target}';`,
        true,
      );
      expect(rejected.ok, `${set} must be rejected`).toBe(false);
      expect(extractSqlstate(rejected.stderr), set).toBe(SQLSTATE_RAISE_EXCEPTION);
      expect(rejected.stderr, set).toContain("SEND_IMMUTABLE_FIELD_REJECTED");
    }
    // The row is unchanged and a legitimate advance still works, so the guard is scoped to
    // the economic fields rather than freezing the row outright.
    expect(
      runPsql(scratchDb, `SELECT amount_zkz FROM send_operations WHERE operation_id = '${target}';`)
        .stdout.trim(),
    ).toBe("2.25");
    const advance = runPsql(
      scratchDb,
      `UPDATE send_operations SET status = 'APPROVED', formation_state = 'APPROVED_UNSIGNED', row_version = 2 WHERE operation_id = '${target}';`,
    );
    expect(advance.ok, advance.stderr).toBe(true);
    assertionsRun += 1;
  });

  it("an operation carries exactly one expected artifact", () => {
    const second = runPsql(
      scratchDb,
      rawArtifactInsert(
        "f1000000-0000-4000-8000-000000000021",
        "e1000000-0000-4000-8000-000000000006",
      ),
      true,
    );
    expect(second.ok, "a second artifact for one operation must be rejected").toBe(false);
    expect(extractSqlstate(second.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(second.stderr)).toBe(ARTIFACT_OPERATION_UNIQUE);
    assertionsRun += 1;
  });

  it("artifact rows are insert-only — UPDATE and DELETE both raise", () => {
    const target = "e1000000-0000-4000-8000-000000000006";
    for (const statement of [
      `UPDATE send_operation_expected_artifacts SET signature = '${"B".repeat(86)}==' WHERE operation_id = '${target}';`,
      `DELETE FROM send_operation_expected_artifacts WHERE operation_id = '${target}';`,
    ]) {
      const rejected = runPsql(scratchDb, statement, true);
      expect(rejected.ok, statement).toBe(false);
      expect(extractSqlstate(rejected.stderr), statement).toBe(SQLSTATE_RAISE_EXCEPTION);
      expect(rejected.stderr, statement).toContain("SEND_ARTIFACT_INSERT_ONLY");
    }
    expect(
      countRows(scratchDb, "send_operation_expected_artifacts", `operation_id = '${target}'`),
    ).toBe("1");
    assertionsRun += 1;
  });

  it("The one-in-flight-per-wallet rule is FAIL-CLOSED: a status added to the vocabulary still holds the wallet", () => {
    // The hazard a partial index invites: a predicate that lists non-terminal states positively
    // does not index a row outside the list, so that row holds nothing and the next send is
    // admitted. Simulated exactly — extend the frozen status vocabulary WITHOUT touching the
    // index — and the second send must still be refused.
    psqlMust(
      scratchDb,
      `ALTER TABLE send_operations DROP CONSTRAINT send_operations_status_check;
       ALTER TABLE send_operations ADD CONSTRAINT send_operations_status_check
         CHECK (status IN ('CREATED', 'APPROVED', 'AWAITING_REDEMPTION', 'EXTERNAL_SEND_LANDED', 'REJECTED', 'NEEDS_ATTENTION', 'HYPOTHETICAL_UNSETTLED'));`,
    );
    const held = runPsql(
      scratchDb,
      rawOperationInsert({
        operationId: "e1000000-0000-4000-8000-000000000031",
        artifactId: "f1000000-0000-4000-8000-000000000031",
        idempotencyKey: "idem-key-send-drill-0031",
        sourceWalletId: OTHER_WALLET,
        status: "HYPOTHETICAL_UNSETTLED",
      }),
    );
    expect(held.ok, held.stderr).toBe(true);
    const second = runPsql(
      scratchDb,
      executeInsert({
        operationId: "e1000000-0000-4000-8000-000000000032",
        artifactId: "f1000000-0000-4000-8000-000000000032",
        idempotencyKey: "idem-key-send-drill-0032",
        sourceWalletId: OTHER_WALLET,
      }),
      true,
    );
    expect(second.ok, "an unrecognised status must be treated as unsettled and block").toBe(false);
    expect(extractSqlstate(second.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(second.stderr)).toBe(SOURCE_IN_FLIGHT_INDEX);
    // Restore the frozen vocabulary so no later drill inherits the probe.
    psqlMust(
      scratchDb,
      `DELETE FROM send_operations WHERE operation_id = 'e1000000-0000-4000-8000-000000000031';
       ALTER TABLE send_operations DROP CONSTRAINT send_operations_status_check;
       ALTER TABLE send_operations ADD CONSTRAINT send_operations_status_check
         CHECK (status IN ('CREATED', 'APPROVED', 'AWAITING_REDEMPTION', 'EXTERNAL_SEND_LANDED', 'REJECTED', 'NEEDS_ATTENTION'));`,
    );
    assertionsRun += 1;
  });
});

/* ─── fail-closed obligation guard ────────────────────────────────────
 * Top-level (OUTSIDE the pg-gated describe) so it runs even when the suite is skipped, and
 * mirrors the guard in custody-eligibility-lease-pk.test.ts. Three cases, none of which can
 * silently pass having tested nothing:
 *   1. PG unusable AND PG_REQUIRED=1 → HARD FAILURE (race / broken gate, not absent Postgres).
 *   2. PG unusable AND PG_REQUIRED unset → Postgres is genuinely optional for a standalone
 *      run outside the canonical pipeline; verify-local.sh's own VERIFY_REQUIRE_PG step
 *      independently fails the whole run in that case.
 *   3. PG usable → the drills MUST have executed, else the obligation is undischarged
 *      and this fails hard. A green suite that never opened a connection is not evidence. */
it("obligation guard: real-PG create drills must execute (hard fail under PG_REQUIRED=1)", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        `PG_REQUIRED=1 but PostgreSQL maintenance database "${MAINTENANCE_DB}" is not usable: the ` +
          "real-PG one-in-flight-per-wallet, idempotency, immutability and artifact drills could not " +
          "run and the local verification lane must not silently skip them. The outer runner exports " +
          "PG_REQUIRED=1 only after seeing a reachable Postgres, so this is a race / broken gate, not " +
          "an absent Postgres — provision the maintenance database and re-run.",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the real-PG send-create drills did not run — undischarged obligation",
  ).toBe(EXPECTED_DRILL_COUNT);
});
