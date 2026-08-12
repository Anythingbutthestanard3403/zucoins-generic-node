/**
 * approval-stores-auto-policy.pg.test.ts
 *
 * Real-PostgreSQL drills for the AUTO_POLICY method arm on operation_approvals
 * (ZTR-1233). Applies the frozen greenfield DDL (base-enums-domains +
 * approval-stores) over minimal FK stubs, then asserts:
 *   - AUTO_POLICY inserts with NULL challenge/TOTP/device
 *   - AUTO_POLICY rejects any non-null factor column
 *   - TOTP_ONLY / TOTP_AND_DEVICE still require challenge_id + totp_timestep
 *   - two AUTO_POLICY rows coexist (no totp_timestep collision)
 *   - two TOTP rows sharing (node_id, totp_timestep) still collide (23505)
 *   - composite FK MATCH SIMPLE: NULL challenge_id inserts cleanly
 *   - external_send_sign_intents may reference an AUTO_POLICY approval id
 *
 * No silent skip when PG is reachable. PG_REQUIRED=1 hard-fails if not.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const MAINTENANCE_DB = "postgres";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_CHECK_VIOLATION = "23514";
const SQLSTATE_FK_VIOLATION = "23503";

const NODE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const HEX64 = "a".repeat(64);
const SIG88 = `${"A".repeat(86)}==`;
const PUBKEY = `${"B".repeat(43)}=`;

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) args.push("-v", "VERBOSITY=verbose");
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

const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql, true);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const applySql = (db: string, sql: string, label: string): void => {
  const outcome = runPsql(db, sql, true);
  if (!outcome.ok) {
    throw new Error(`${label} apply failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const applyFile = (db: string, file: string): void => {
  try {
    execFileSync(
      "psql",
      ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, file)],
      { encoding: "utf-8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;
const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const PURPOSE = "zp-send-external-approval-v1";

const insertOperation = (operationId: string): string =>
  `INSERT INTO operations (id) VALUES ('${operationId}');`;

const insertChallenge = (
  challengeId: string,
  operationId: string,
  status: "ISSUED" | "CONSUMED" = "CONSUMED",
): string =>
  `INSERT INTO approval_challenges (
     id, node_id, operation_id, status, purpose, canonical_version, nonce,
     preimage_text, preimage_sha256, issued_at, expires_at
   ) VALUES (
     '${challengeId}', '${NODE_ID}', '${operationId}', '${status}',
     '${PURPOSE}', 1, gen_random_uuid(),
     'preimage-${challengeId}', '${HEX64}',
     now(), now() + interval '5 minutes'
   );`;

const approvalCols =
  "id, node_id, operation_id, challenge_id, method, purpose, canonical_version, " +
  "preimage_text, preimage_sha256, device_key_id, device_signature, totp_timestep, consumed_at";

const insertApproval = (args: {
  id: string;
  operationId: string;
  method: string;
  challengeId: string | null;
  totpTimestep: string | null;
  deviceKeyId?: string | null;
  deviceSignature?: string | null;
}): string => {
  const challenge = args.challengeId === null ? "NULL" : `'${args.challengeId}'`;
  const totp = args.totpTimestep === null ? "NULL" : args.totpTimestep;
  const deviceKey =
    args.deviceKeyId === undefined || args.deviceKeyId === null
      ? "NULL"
      : `'${args.deviceKeyId}'`;
  const deviceSig =
    args.deviceSignature === undefined || args.deviceSignature === null
      ? "NULL"
      : `'${args.deviceSignature}'`;
  return (
    `INSERT INTO operation_approvals (${approvalCols}) VALUES (` +
    `'${args.id}', '${NODE_ID}', '${args.operationId}', ${challenge}, ` +
    `'${args.method}', '${PURPOSE}', 1, 'preimage-${args.id}', '${HEX64}', ` +
    `${deviceKey}, ${deviceSig}, ${totp}, now());`
  );
};

let assertionsRun = 0;
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

describeIfPg("approval-stores AUTO_POLICY real-PG drills (hermetic scratch DB)", () => {
  const scratchDb = `approval_auto_policy_${Date.now()}_${process.pid}`;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    // Minimal FK targets referenced by approval-stores + transaction-material.
    applySql(
      scratchDb,
      `
      CREATE TABLE nodes (id uuid PRIMARY KEY);
      CREATE TABLE operations (id uuid PRIMARY KEY);
      CREATE TABLE wallets (id uuid PRIMARY KEY);
      INSERT INTO nodes (id) VALUES ('${NODE_ID}');
      `,
      "stubs",
    );
    applyFile(scratchDb, "base-enums-domains.sql");
    applyFile(scratchDb, "approval-stores.sql");
    // Sign-intent table only (transaction-material also redeclares domains already present).
    applySql(
      scratchDb,
      `
      CREATE TABLE external_send_sign_intents (
        operation_id uuid PRIMARY KEY REFERENCES operations(id),
        approval_id uuid NOT NULL UNIQUE REFERENCES operation_approvals(id),
        source_wallet_id uuid NOT NULL REFERENCES wallets(id),
        source_t0_observation_id uuid NOT NULL,
        destination_t0_observation_id uuid NOT NULL,
        lease_group_id uuid NOT NULL,
        lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
        inner_preimage_text text NOT NULL,
        inner_sha256 sha256_hex NOT NULL,
        redemption_expiry_at timestamptz NOT NULL,
        prepared_at timestamptz NOT NULL,
        CHECK (octet_length(inner_preimage_text) > 0)
      );
      `,
      "sign-intents",
    );
  });

  afterAll(() => {
    runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  it("AUTO_POLICY inserts with NULL challenge, totp_timestep, and device factors", () => {
    const op = randomUUID();
    const ap = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    const r = runPsql(
      scratchDb,
      insertApproval({
        id: ap,
        operationId: op,
        method: "AUTO_POLICY",
        challengeId: null,
        totpTimestep: null,
      }),
      true,
    );
    expect(r.ok, r.stderr).toBe(true);
    assertionsRun += 1;
  });

  it("AUTO_POLICY rejects non-null challenge_id (23514)", () => {
    const op = randomUUID();
    const ch = randomUUID();
    const ap = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    psqlMust(scratchDb, insertChallenge(ch, op));
    const r = runPsql(
      scratchDb,
      insertApproval({
        id: ap,
        operationId: op,
        method: "AUTO_POLICY",
        challengeId: ch,
        totpTimestep: null,
      }),
      true,
    );
    expect(r.ok).toBe(false);
    expect(extractSqlstate(r.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("AUTO_POLICY rejects non-null totp_timestep (23514)", () => {
    const op = randomUUID();
    const ap = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    const r = runPsql(
      scratchDb,
      insertApproval({
        id: ap,
        operationId: op,
        method: "AUTO_POLICY",
        challengeId: null,
        totpTimestep: "42",
      }),
      true,
    );
    expect(r.ok).toBe(false);
    expect(extractSqlstate(r.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("AUTO_POLICY rejects non-null device factors (23514)", () => {
    const op = randomUUID();
    const ap = randomUUID();
    const dk = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    psqlMust(
      scratchDb,
      `INSERT INTO operator_device_keys (id, node_id, public_key, label, enrolled_at)
       VALUES ('${dk}', '${NODE_ID}', '${PUBKEY}', 'k', now());`,
    );
    const r = runPsql(
      scratchDb,
      insertApproval({
        id: ap,
        operationId: op,
        method: "AUTO_POLICY",
        challengeId: null,
        totpTimestep: null,
        deviceKeyId: dk,
        deviceSignature: SIG88,
      }),
      true,
    );
    expect(r.ok).toBe(false);
    expect(extractSqlstate(r.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("TOTP_ONLY with NULL challenge_id is rejected (23514)", () => {
    const op = randomUUID();
    const ap = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    const r = runPsql(
      scratchDb,
      insertApproval({
        id: ap,
        operationId: op,
        method: "TOTP_ONLY",
        challengeId: null,
        totpTimestep: "100",
      }),
      true,
    );
    expect(r.ok).toBe(false);
    expect(extractSqlstate(r.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("TOTP_ONLY with NULL totp_timestep is rejected (23514)", () => {
    const op = randomUUID();
    const ch = randomUUID();
    const ap = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    psqlMust(scratchDb, insertChallenge(ch, op));
    const r = runPsql(
      scratchDb,
      insertApproval({
        id: ap,
        operationId: op,
        method: "TOTP_ONLY",
        challengeId: ch,
        totpTimestep: null,
      }),
      true,
    );
    expect(r.ok).toBe(false);
    expect(extractSqlstate(r.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("TOTP_AND_DEVICE with NULL challenge_id is rejected (23514)", () => {
    const op = randomUUID();
    const ap = randomUUID();
    const dk = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    psqlMust(
      scratchDb,
      `INSERT INTO operator_device_keys (id, node_id, public_key, label, enrolled_at)
       VALUES ('${dk}', '${NODE_ID}', '${"C".repeat(43)}=', 'k2', now());`,
    );
    const r = runPsql(
      scratchDb,
      insertApproval({
        id: ap,
        operationId: op,
        method: "TOTP_AND_DEVICE",
        challengeId: null,
        totpTimestep: "200",
        deviceKeyId: dk,
        deviceSignature: SIG88,
      }),
      true,
    );
    expect(r.ok).toBe(false);
    expect(extractSqlstate(r.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("two AUTO_POLICY rows for different operations coexist (no timestep collision)", () => {
    const op1 = randomUUID();
    const op2 = randomUUID();
    const ap1 = randomUUID();
    const ap2 = randomUUID();
    psqlMust(scratchDb, insertOperation(op1) + insertOperation(op2));
    const r1 = runPsql(
      scratchDb,
      insertApproval({
        id: ap1,
        operationId: op1,
        method: "AUTO_POLICY",
        challengeId: null,
        totpTimestep: null,
      }),
      true,
    );
    const r2 = runPsql(
      scratchDb,
      insertApproval({
        id: ap2,
        operationId: op2,
        method: "AUTO_POLICY",
        challengeId: null,
        totpTimestep: null,
      }),
      true,
    );
    expect(r1.ok, r1.stderr).toBe(true);
    expect(r2.ok, r2.stderr).toBe(true);
    assertionsRun += 1;
  });

  it("two TOTP_ONLY rows sharing (node_id, totp_timestep) collide (23505)", () => {
    const op1 = randomUUID();
    const op2 = randomUUID();
    const ch1 = randomUUID();
    const ch2 = randomUUID();
    const ap1 = randomUUID();
    const ap2 = randomUUID();
    const step = "9001";
    psqlMust(scratchDb, insertOperation(op1) + insertOperation(op2));
    psqlMust(scratchDb, insertChallenge(ch1, op1) + insertChallenge(ch2, op2));
    const r1 = runPsql(
      scratchDb,
      insertApproval({
        id: ap1,
        operationId: op1,
        method: "TOTP_ONLY",
        challengeId: ch1,
        totpTimestep: step,
      }),
      true,
    );
    expect(r1.ok, r1.stderr).toBe(true);
    const r2 = runPsql(
      scratchDb,
      insertApproval({
        id: ap2,
        operationId: op2,
        method: "TOTP_ONLY",
        challengeId: ch2,
        totpTimestep: step,
      }),
      true,
    );
    expect(r2.ok).toBe(false);
    expect(extractSqlstate(r2.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    assertionsRun += 1;
  });

  it("TOTP_ONLY happy path still inserts when challenge + timestep present", () => {
    const op = randomUUID();
    const ch = randomUUID();
    const ap = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    psqlMust(scratchDb, insertChallenge(ch, op));
    const r = runPsql(
      scratchDb,
      insertApproval({
        id: ap,
        operationId: op,
        method: "TOTP_ONLY",
        challengeId: ch,
        totpTimestep: "4242",
      }),
      true,
    );
    expect(r.ok, r.stderr).toBe(true);
    assertionsRun += 1;
  });

  it("composite FK MATCH SIMPLE: AUTO_POLICY NULL challenge_id does not FK-fail", () => {
    // Covered by the successful AUTO_POLICY insert; assert FK still rejects a bad non-null id.
    const op = randomUUID();
    const ap = randomUUID();
    const missingChallenge = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    const r = runPsql(
      scratchDb,
      insertApproval({
        id: ap,
        operationId: op,
        method: "TOTP_ONLY",
        challengeId: missingChallenge,
        totpTimestep: "7777",
      }),
      true,
    );
    expect(r.ok).toBe(false);
    expect(extractSqlstate(r.stderr)).toBe(SQLSTATE_FK_VIOLATION);
    assertionsRun += 1;
  });

  it("sign-intent row may reference an AUTO_POLICY approval id", () => {
    const op = randomUUID();
    const ap = randomUUID();
    const wallet = randomUUID();
    const obs = randomUUID();
    const lease = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    psqlMust(
      scratchDb,
      insertApproval({
        id: ap,
        operationId: op,
        method: "AUTO_POLICY",
        challengeId: null,
        totpTimestep: null,
      }),
    );
    psqlMust(scratchDb, `INSERT INTO wallets (id) VALUES ('${wallet}');`);
    const r = runPsql(
      scratchDb,
      `INSERT INTO external_send_sign_intents (
         operation_id, approval_id, source_wallet_id,
         source_t0_observation_id, destination_t0_observation_id,
         lease_group_id, lease_epoch, inner_preimage_text, inner_sha256,
         redemption_expiry_at, prepared_at
       ) VALUES (
         '${op}', '${ap}', '${wallet}',
         '${obs}', '${obs}',
         '${lease}', 1, 'inner', '${HEX64}',
         now() + interval '1 hour', now()
       );`,
      true,
    );
    expect(r.ok, r.stderr).toBe(true);
    assertionsRun += 1;
  });

  it("purpose / preimage / consumed_at remain NOT NULL for AUTO_POLICY", () => {
    const op = randomUUID();
    const ap = randomUUID();
    psqlMust(scratchDb, insertOperation(op));
    const r = runPsql(
      scratchDb,
      `INSERT INTO operation_approvals (
         id, node_id, operation_id, method, purpose, canonical_version,
         preimage_text, preimage_sha256, consumed_at
       ) VALUES (
         '${ap}', '${NODE_ID}', '${op}', 'AUTO_POLICY', '${PURPOSE}', 1,
         NULL, '${HEX64}', now()
       );`,
      true,
    );
    expect(r.ok).toBe(false);
    // not_null_violation
    expect(extractSqlstate(r.stderr)).toBe("23502");
    assertionsRun += 1;
  });
});

describe("approval-stores AUTO_POLICY PG drill gate", () => {
  it("does not silently skip when PG_REQUIRED=1", () => {
    if (PG_REQUIRED && !PG_AVAILABLE) {
      throw new Error("PG_REQUIRED=1 but PostgreSQL is unreachable");
    }
    if (PG_AVAILABLE) {
      expect(assertionsRun).toBeGreaterThanOrEqual(12);
    }
  });
});
