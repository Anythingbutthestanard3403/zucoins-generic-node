/**
 * auto-approve-policy.pg.test.ts
 *
 * Real-PostgreSQL drills for ops.auto_approve_sends + commitAutoApproval (ZTR-1234):
 *   - window cap boundary (spend + amount == cap approves; one more falls through)
 *   - concurrent same-implementer multi-op commits cannot overshoot window cap
 *   - CAS miss atomicity (no orphan approval / audit row)
 *   - concurrent manual reject beats auto-approve cleanly
 *   - window query excludes TOTP-method approvals and older-than-window rows
 *   - audit row byte-shape (action, actor_kind, details_sha256)
 *
 * No silent skip when PG is reachable. PG_REQUIRED=1 hard-fails if not.
 * registerPgRequiredGuard is top-level *after* the live describe so beforeAll
 * can set schemaReady before the guard it runs (leadership.pg pattern).
 */
import { execFileSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  AUTO_APPROVE_APPLIED_ACTION,
  commitAutoApproval,
  queryWindowSpend,
  type AutoApproveRule,
} from "../src/send/auto-approve-policy.js";
import { DECISION_STATEMENTS } from "../src/send/decide.js";
import { OPERATION_COLUMNS } from "../src/send/sql-store.js";
import type { SqlExecutor, SqlTxFn } from "../src/send/sql-store.js";
import {
  bindSql,
  extractSqlstate,
  PsqlSessionExecutor,
  runPsql as runPsqlUrl,
  wrapModifyingCteAsJson,
} from "./psql-harness.js";
import { registerPgRequiredGuard } from "./pg-required-guard.js";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const MAINTENANCE_DB = "postgres";
const HEX64 = "a".repeat(64);
const SIG88 = `${"A".repeat(86)}==`;
const NODE_ID = "e1000000-0000-4000-8000-000000000001";
const IMPLEMENTER_ID = "e1000000-0000-4000-8000-000000000002";
const SIGNING_KEY_ID = "e1000000-0000-4000-8000-000000000003";
const DESTINATION = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const NODE_PUB = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const PURPOSE = "zp-send-external-approval-v1";

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
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): string => {
  const outcome = runPsql(db, sql, true);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const applyFile = (db: string, file: string, stripShaDomain = false): void => {
  let sql = readFileSync(resolve(schemaDir, file), "utf-8");
  if (stripShaDomain) {
    sql = sql.replace(/CREATE DOMAIN sha256_hex AS text[\s\S]*?;/g, "");
  }
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      input: sql,
      encoding: "utf-8",
      timeout: 60_000,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const applySql = (db: string, sql: string, label: string): void => {
  const outcome = runPsql(db, sql, true);
  if (!outcome.ok) {
    throw new Error(`${label} apply failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const lit = (value: unknown): string => {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return `'${String(value).replace(/'/g, "''")}'`;
};

/** Autocommit SqlExecutor over db name (one psql process per query). */
class AutocommitPsql implements SqlExecutor {
  constructor(private readonly db: string) {}

  async query<R>(text: string, params: readonly unknown[] = []): Promise<{ rows: R[] }> {
    const bound = bindSql(text, params);
    const trimmed = bound.trim();
    let sql: string;
    if (/^WITH\b/i.test(trimmed) && /\b(INSERT|UPDATE|DELETE)\b/i.test(trimmed)) {
      sql = wrapModifyingCteAsJson(trimmed);
    } else if (/\bRETURNING\b/i.test(trimmed) && /^(INSERT|UPDATE|DELETE)\b/i.test(trimmed)) {
      sql =
        `WITH __m AS (${trimmed}) ` +
        `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM __m t`;
    } else if (/^(SELECT|WITH)\b/i.test(trimmed)) {
      sql = `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (${trimmed}) t`;
    } else if (/^(INSERT|UPDATE|DELETE)\b/i.test(trimmed)) {
      // bare mutation
      const outcome = runPsql(this.db, trimmed, true);
      if (!outcome.ok) {
        const err = new Error(outcome.stderr.trim());
        (err as { code?: string }).code = extractSqlstate(outcome.stderr);
        throw err;
      }
      return { rows: [] as R[] };
    } else {
      const outcome = runPsql(this.db, trimmed, true);
      if (!outcome.ok) throw new Error(outcome.stderr.trim());
      return { rows: [] as R[] };
    }
    const outcome = runPsql(this.db, sql, true);
    if (!outcome.ok) {
      const err = new Error(outcome.stderr.trim());
      (err as { code?: string }).code = extractSqlstate(outcome.stderr);
      throw err;
    }
    const line = outcome.stdout.trim().split("\n").filter(Boolean).pop() ?? "[]";
    return { rows: JSON.parse(line) as R[] };
  }
}

function sessionWithTx(dbUrl: string): { withTx: SqlTxFn; stop: () => void } {
  // One long-lived session per TX body so FOR UPDATE locks hold across statements.
  return {
    withTx: async <T>(body: (tx: SqlExecutor) => Promise<T>): Promise<T> => {
      const session = new PsqlSessionExecutor(dbUrl);
      session.start();
      try {
        await session.begin();
        try {
          const result = await body(session);
          await session.commit();
          return result;
        } catch (err) {
          await session.rollback();
          throw err;
        }
      } finally {
        session.stop();
      }
    },
    stop: () => undefined,
  };
}

const scratchDb = `auto_approve_policy_${Date.now()}_${process.pid}`;
let dbUrl = "";
let schemaReady = false;
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

const RULE: AutoApproveRule = {
  rule_id: "zukaz-rewards",
  implementer_id: IMPLEMENTER_ID,
  per_send_max_zkz: "1",
  per_send_min_zkz: null,
  window_hours: 288,
  window_cap_zkz: "3",
  expires_at: null,
  enabled: true,
};

const seedNode = (): string =>
  `INSERT INTO nodes (id, display_name, identity_public_key) ` +
  `VALUES ('${NODE_ID}', 'auto-approve-pg', '${NODE_PUB}') ON CONFLICT (id) DO NOTHING;`;

/** Canonical padded base64url of 32 random bytes (unique per call). */
const freshWalletPubkey = (): string => {
  const unpadded = randomBytes(32).toString("base64url");
  const pad = (4 - (unpadded.length % 4)) % 4;
  return unpadded + "=".repeat(pad);
};

const seedWallet = (walletId: string): string => {
  const recoveryId = randomUUID();
  const pk = freshWalletPubkey();
  return (
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
    `VALUES ('${walletId}', '${NODE_ID}', '${pk}', 'node_generated', 'AVAILABLE'); ` +
    `INSERT INTO wallet_recovery_verifications ` +
    `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
    `VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${HEX64}', '${pk}', ` +
    `'${recoveryId}', now(), 'auto-approve-pg'); ` +
    `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
    `WHERE id = '${walletId}';`
  );
};

const insertCreatedSend = (
  operationId: string,
  sourceWalletId: string,
  amount: string,
  idemSuffix: string,
): string => {
  const cols = OPERATION_COLUMNS.join(", ");
  const vals = [
    lit(operationId),
    lit(IMPLEMENTER_ID),
    lit(NODE_ID),
    lit("SEND_EXTERNAL"),
    lit("CREATED"),
    lit(1),
    lit(false),
    lit("APPROVAL_PENDING"),
    lit("POST"),
    lit("/v1/external-sends"),
    lit(`aa-${idemSuffix}`),
    lit(HEX64),
    lit(sourceWalletId),
    lit(DESTINATION),
    lit(amount),
    lit(null),
    lit(null),
    lit(null),
  ].join(", ");
  return (
    `INSERT INTO operations (id) VALUES ('${operationId}'); ` +
    `INSERT INTO send_operations (${cols}) VALUES (${vals}, now()); ` +
    `INSERT INTO send_operation_expected_artifacts ` +
    `(artifact_id, operation_id, purpose, canonical_version, signing_key_id, preimage_text, preimage_sha256, signature) ` +
    `VALUES ('${randomUUID()}', '${operationId}', 'zp-send-external-expected-v1', 1, '${SIGNING_KEY_ID}', ` +
    `'preimage', '${HEX64}', '${SIG88}');`
  );
};

const insertAutoApprovalDirect = (
  approvalId: string,
  operationId: string,
  consumedAtSql: string,
): string =>
  `INSERT INTO operation_approvals (
     id, node_id, operation_id, challenge_id, method, purpose, canonical_version,
     preimage_text, preimage_sha256, device_key_id, device_signature, totp_timestep, consumed_at
   ) VALUES (
     '${approvalId}', '${NODE_ID}', '${operationId}', NULL, 'AUTO_POLICY', '${PURPOSE}', 1,
     'preimage-${approvalId}', '${HEX64}', NULL, NULL, NULL, ${consumedAtSql}
   );`;

const insertTotpApprovalDirect = (
  approvalId: string,
  operationId: string,
  challengeId: string,
  timestep: number,
): string =>
  `INSERT INTO approval_challenges (
     id, node_id, operation_id, status, purpose, canonical_version, nonce,
     preimage_text, preimage_sha256, issued_at, expires_at
   ) VALUES (
     '${challengeId}', '${NODE_ID}', '${operationId}', 'CONSUMED', '${PURPOSE}', 1,
     gen_random_uuid(), 'preimage-ch', '${HEX64}', now(), now() + interval '5 minutes'
   ); ` +
  `INSERT INTO operation_approvals (
     id, node_id, operation_id, challenge_id, method, purpose, canonical_version,
     preimage_text, preimage_sha256, device_key_id, device_signature, totp_timestep, consumed_at
   ) VALUES (
     '${approvalId}', '${NODE_ID}', '${operationId}', '${challengeId}', 'TOTP_ONLY', '${PURPOSE}', 1,
     'preimage-${approvalId}', '${HEX64}', NULL, NULL, ${timestep}, now()
   );`;

describeIfPg("auto-approve-policy real-PG drills", { timeout: 180_000 }, () => {
  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    // base + nodes extract
    const base = readFileSync(resolve(schemaDir, "base-enums-domains.sql"), "utf-8");
    const registry = readFileSync(resolve(schemaDir, "node-implementer-registry.sql"), "utf-8");
    const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
    if (nodes === null) throw new Error("nodes block missing");
    applySql(scratchDb, `${base}\n${nodes[0]}\n`, "base+nodes");
    applyFile(scratchDb, "custody-eligibility.sql");
    applyFile(scratchDb, "send-external-create.sql");
    // operations stub for approval + audit FKs (full operations.sql is heavy)
    applySql(
      scratchDb,
      `CREATE TABLE IF NOT EXISTS operations (id uuid PRIMARY KEY);`,
      "operations-stub",
    );
    applyFile(scratchDb, "approval-stores.sql");
    applyFile(scratchDb, "operational-stores.sql");
    applyFile(scratchDb, "audit-log.sql", true);
    psqlMust(scratchDb, seedNode());
    // local socket URL for PsqlSessionExecutor
    dbUrl = `postgresql:///${scratchDb}`;
    schemaReady = true;
  }, 90_000);

  afterAll(() => {
    runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  async function seedCreated(amount: string): Promise<{
    operationId: string;
    walletId: string;
  }> {
    const walletId = randomUUID();
    const operationId = randomUUID();
    psqlMust(scratchDb, seedWallet(walletId));
    psqlMust(scratchDb, insertCreatedSend(operationId, walletId, amount, operationId));
    return { operationId, walletId };
  }

  it("cap boundary: spend+amount == cap approves; one more falls through", async () => {
    const { withTx } = sessionWithTx(dbUrl);
    const sql = new AutocommitPsql(scratchDb);

    // Pre-seed two AUTO_POLICY approvals of amount 1 (window spend = 2, cap = 3).
    for (let i = 0; i < 2; i++) {
      const w = randomUUID();
      const op = randomUUID();
      psqlMust(scratchDb, seedWallet(w));
      psqlMust(scratchDb, insertCreatedSend(op, w, "1", `pre-${i}-${op}`));
      psqlMust(
        scratchDb,
        `UPDATE send_operations SET status = 'APPROVED', formation_state = 'APPROVED_UNSIGNED', row_version = 2 WHERE operation_id = '${op}';`,
      );
      psqlMust(scratchDb, insertAutoApprovalDirect(randomUUID(), op, "now()"));
    }

    const spendBefore = await queryWindowSpend(sql, IMPLEMENTER_ID, RULE.window_hours);
    expect(spendBefore).toBe("2");

    // Wall-clock nowMs: WINDOW_SPEND_SQL filters consumed_at against SQL now(), and
    // commitAutoApproval stamps consumed_at from nowMs. A frozen epoch (e.g. 2026-08-01)
    // lands outside the rolling window so prior AUTO_POLICY rows vanish from spend.
    const nowMs = () => Date.now();

    // Candidate amount 1 → projected 3 == cap → approve
    const { operationId: okOp } = await seedCreated("1");
    const ok = await commitAutoApproval(
      { operationId: okOp, rule: RULE },
      { sql, withTx, nowMs },
    );
    expect(ok.decision).toBe("approve");
    if (ok.decision !== "approve") return;
    expect(ok.windowSpendBefore).toBe("2");

    const statusOk = psqlMust(
      scratchDb,
      `SELECT status || '|' || formation_state FROM send_operations WHERE operation_id = '${okOp}';`,
    ).trim();
    expect(statusOk).toBe("APPROVED|APPROVED_UNSIGNED");

    // One more amount 1 → projected 4 > 3 → fall_through window_cap
    const { operationId: overOp } = await seedCreated("1");
    const over = await commitAutoApproval(
      { operationId: overOp, rule: RULE },
      { sql, withTx, nowMs },
    );
    expect(over).toEqual({ decision: "fall_through", reason: "window_cap" });
    const statusOver = psqlMust(
      scratchDb,
      `SELECT status FROM send_operations WHERE operation_id = '${overOp}';`,
    ).trim();
    expect(statusOver).toBe("CREATED");
    const orphan = psqlMust(
      scratchDb,
      `SELECT count(*) FROM operation_approvals WHERE operation_id = '${overOp}';`,
    ).trim();
    expect(orphan).toBe("0");
  });

  it("CAS miss rolls back approval + audit (atomicity)", async () => {
    const { operationId } = await seedCreated("1");
    // Same-session: lock, insert approval, then CAS against a stale expected version
    // after an in-TX row_version bump so the guard matches zero rows; ROLLBACK drops both.
    const session = new PsqlSessionExecutor(dbUrl);
    session.start();
    try {
      await session.begin();
      const locked = await session.query<{ row_version: string | number }>(
        "SELECT row_version FROM send_operations WHERE operation_id = $1 FOR UPDATE",
        [operationId],
      );
      expect(Number(locked.rows[0]?.row_version)).toBe(1);

      await session.query(
        "UPDATE send_operations SET row_version = row_version + 1 WHERE operation_id = $1",
        [operationId],
      );

      const approvalId = randomUUID();
      await session.query(
        `INSERT INTO operation_approvals (
           id, node_id, operation_id, challenge_id, challenge_status, method, purpose,
           canonical_version, preimage_text, preimage_sha256, device_key_id, device_signature,
           totp_timestep, consumed_at
         ) VALUES (
           $1, $2, $3, NULL, 'CONSUMED', 'AUTO_POLICY', $4,
           1, 'pre', $5, NULL, NULL, NULL, now()
         )`,
        [approvalId, NODE_ID, operationId, PURPOSE, HEX64],
      );
      const cas = await session.query(
        DECISION_STATEMENTS.APPROVE_CREATED,
        [operationId, 1],
      );
      expect(cas.rows).toHaveLength(0);
      await session.rollback();
    } finally {
      session.stop();
    }

    const apCount = psqlMust(
      scratchDb,
      `SELECT count(*) FROM operation_approvals WHERE operation_id = '${operationId}';`,
    ).trim();
    expect(apCount).toBe("0");
    const auditCount = psqlMust(
      scratchDb,
      `SELECT count(*) FROM audit_log WHERE operation_id = '${operationId}' AND action = '${AUTO_APPROVE_APPLIED_ACTION}';`,
    ).trim();
    expect(auditCount).toBe("0");
    const status = psqlMust(
      scratchDb,
      `SELECT status FROM send_operations WHERE operation_id = '${operationId}';`,
    ).trim();
    expect(status).toBe("CREATED");
  });

  it("commitAutoApproval itself returns cas_miss with no durable side effects", async () => {
    const sql = new AutocommitPsql(scratchDb);
    // Fresh implementer so prior cap-boundary spend does not short-circuit before CAS.
    const imp = "e2000000-0000-4000-8000-0000000000bb";
    const rule: AutoApproveRule = { ...RULE, implementer_id: imp, window_cap_zkz: "100" };
    const w = randomUUID();
    const operationId = randomUUID();
    psqlMust(scratchDb, seedWallet(w));
    const cols = OPERATION_COLUMNS.join(", ");
    const vals = [
      lit(operationId),
      lit(imp),
      lit(NODE_ID),
      lit("SEND_EXTERNAL"),
      lit("CREATED"),
      lit(1),
      lit(false),
      lit("APPROVAL_PENDING"),
      lit("POST"),
      lit("/v1/external-sends"),
      lit(`cas-${operationId}`),
      lit(HEX64),
      lit(w),
      lit(DESTINATION),
      lit("1"),
      lit(null),
      lit(null),
      lit(null),
    ].join(", ");
    psqlMust(
      scratchDb,
      `INSERT INTO operations (id) VALUES ('${operationId}'); ` +
        `INSERT INTO send_operations (${cols}) VALUES (${vals}, now()); ` +
        `INSERT INTO send_operation_expected_artifacts ` +
        `(artifact_id, operation_id, purpose, canonical_version, signing_key_id, preimage_text, preimage_sha256, signature) ` +
        `VALUES ('${randomUUID()}', '${operationId}', 'zp-send-external-expected-v1', 1, '${SIGNING_KEY_ID}', ` +
        `'preimage', '${HEX64}', '${SIG88}');`,
    );

    // Same-TX saboteur: after FOR UPDATE, bump row_version inside the holding
    // transaction so the subsequent CAS (expected = locked original version)
    // matches zero rows. An external connection cannot bump under FOR UPDATE
    // without blocking, so the bump must be same-session.
    let queryCount = 0;
    const sabotagedWithTx: SqlTxFn = async (body) => {
      const session = new PsqlSessionExecutor(dbUrl);
      session.start();
      try {
        await session.begin();
        const wrapped: SqlExecutor = {
          async query<R>(text: string, params: readonly unknown[] = []) {
            const result = await session.query<R>(text, params);
            queryCount += 1;
            if (text.includes("FOR UPDATE OF o")) {
              await session.query(
                "UPDATE send_operations SET row_version = row_version + 1 WHERE operation_id = $1",
                [operationId],
              );
            }
            return result;
          },
        };
        try {
          const out = await body(wrapped);
          await session.commit();
          return out;
        } catch (err) {
          await session.rollback();
          throw err;
        }
      } finally {
        session.stop();
      }
    };

    const result = await commitAutoApproval(
      { operationId, rule },
      {
        sql,
        withTx: sabotagedWithTx,
        nowMs: () => Date.now(),
      },
    );
    expect(result).toEqual({ decision: "fall_through", reason: "cas_miss" });
    expect(queryCount).toBeGreaterThan(0);

    const apCount = psqlMust(
      scratchDb,
      `SELECT count(*) FROM operation_approvals WHERE operation_id = '${operationId}';`,
    ).trim();
    expect(apCount).toBe("0");
    const auditCount = psqlMust(
      scratchDb,
      `SELECT count(*) FROM audit_log WHERE operation_id = '${operationId}';`,
    ).trim();
    expect(auditCount).toBe("0");
    const status = psqlMust(
      scratchDb,
      `SELECT status FROM send_operations WHERE operation_id = '${operationId}';`,
    ).trim();
    expect(status).toBe("CREATED");
  });

  it("concurrent manual reject beats auto-approve cleanly", async () => {
    const { withTx } = sessionWithTx(dbUrl);
    const sql = new AutocommitPsql(scratchDb);
    const { operationId } = await seedCreated("1");

    // Race: reject CAS vs auto-approve commit
    const rejectP = (async () => {
      // small delay so auto may start locking first sometimes
      await new Promise((r) => setTimeout(r, 5));
      const outcome = runPsql(
        scratchDb,
        bindSql(DECISION_STATEMENTS.REJECT_CREATED, [operationId, 1]),
        true,
      );
      return outcome;
    })();

    const autoP = commitAutoApproval(
      { operationId, rule: RULE },
      {
        sql,
        withTx,
        nowMs: () => Date.now(),
      },
    );

    const [rejectOutcome, autoResult] = await Promise.all([rejectP, autoP]);

    const final = psqlMust(
      scratchDb,
      `SELECT status FROM send_operations WHERE operation_id = '${operationId}';`,
    ).trim();
    expect(["REJECTED", "APPROVED"]).toContain(final);

    if (final === "REJECTED") {
      expect(rejectOutcome.ok).toBe(true);
      // auto either cas_miss or operation_not_created
      expect(autoResult.decision).toBe("fall_through");
      const ap = psqlMust(
        scratchDb,
        `SELECT count(*) FROM operation_approvals WHERE operation_id = '${operationId}';`,
      ).trim();
      expect(ap).toBe("0");
    } else {
      expect(autoResult.decision).toBe("approve");
      // reject should have matched zero rows (still ok exit from UPDATE)
    }
  });

  it("window query excludes TOTP approvals and older-than-window rows", async () => {
    const sql = new AutocommitPsql(scratchDb);
    // Isolate: use a fresh implementer id so prior drills don't pollute.
    const imp = "c1000000-0000-4000-8000-000000000099";
    const ruleHours = 24;

    // Old AUTO_POLICY (outside window)
    {
      const w = randomUUID();
      const op = randomUUID();
      psqlMust(scratchDb, seedWallet(w));
      // insert send with this implementer
      const cols = OPERATION_COLUMNS.join(", ");
      const vals = [
        lit(op),
        lit(imp),
        lit(NODE_ID),
        lit("SEND_EXTERNAL"),
        lit("APPROVED"),
        lit(2),
        lit(false),
        lit("APPROVED_UNSIGNED"),
        lit("POST"),
        lit("/v1/external-sends"),
        lit(`old-${op}`),
        lit(HEX64),
        lit(w),
        lit(DESTINATION),
        lit("5"),
        lit(null),
        lit(null),
        lit(null),
      ].join(", ");
      psqlMust(
        scratchDb,
        `INSERT INTO operations (id) VALUES ('${op}'); ` +
          `INSERT INTO send_operations (${cols}) VALUES (${vals}, now());`,
      );
      psqlMust(
        scratchDb,
        insertAutoApprovalDirect(randomUUID(), op, "now() - interval '48 hours'"),
      );
    }

    // Recent TOTP approval (same implementer) — must NOT count
    {
      const w = randomUUID();
      const op = randomUUID();
      const ch = randomUUID();
      psqlMust(scratchDb, seedWallet(w));
      const cols = OPERATION_COLUMNS.join(", ");
      const vals = [
        lit(op),
        lit(imp),
        lit(NODE_ID),
        lit("SEND_EXTERNAL"),
        lit("APPROVED"),
        lit(2),
        lit(false),
        lit("APPROVED_UNSIGNED"),
        lit("POST"),
        lit("/v1/external-sends"),
        lit(`totp-${op}`),
        lit(HEX64),
        lit(w),
        lit(DESTINATION),
        lit("7"),
        lit(null),
        lit(null),
        lit(null),
      ].join(", ");
      psqlMust(
        scratchDb,
        `INSERT INTO operations (id) VALUES ('${op}'); ` +
          `INSERT INTO send_operations (${cols}) VALUES (${vals}, now());`,
      );
      psqlMust(scratchDb, insertTotpApprovalDirect(randomUUID(), op, ch, 42_000 + Math.floor(Math.random() * 1000)));
    }

    // Recent AUTO_POLICY that should count
    {
      const w = randomUUID();
      const op = randomUUID();
      psqlMust(scratchDb, seedWallet(w));
      const cols = OPERATION_COLUMNS.join(", ");
      const vals = [
        lit(op),
        lit(imp),
        lit(NODE_ID),
        lit("SEND_EXTERNAL"),
        lit("APPROVED"),
        lit(2),
        lit(false),
        lit("APPROVED_UNSIGNED"),
        lit("POST"),
        lit("/v1/external-sends"),
        lit(`auto-${op}`),
        lit(HEX64),
        lit(w),
        lit(DESTINATION),
        lit("1.5"),
        lit(null),
        lit(null),
        lit(null),
      ].join(", ");
      psqlMust(
        scratchDb,
        `INSERT INTO operations (id) VALUES ('${op}'); ` +
          `INSERT INTO send_operations (${cols}) VALUES (${vals}, now());`,
      );
      psqlMust(scratchDb, insertAutoApprovalDirect(randomUUID(), op, "now()"));
    }

    const spend = await queryWindowSpend(sql, imp, ruleHours);
    expect(spend).toBe("1.5");
  });

  it("audit row byte-shape on successful auto-approve", async () => {
    const { withTx } = sessionWithTx(dbUrl);
    const sql = new AutocommitPsql(scratchDb);
    // Fresh implementer with empty window so cap is free
    const imp = "d1000000-0000-4000-8000-0000000000aa";
    const rule: AutoApproveRule = { ...RULE, implementer_id: imp, window_cap_zkz: "100" };
    const w = randomUUID();
    const op = randomUUID();
    psqlMust(scratchDb, seedWallet(w));
    const cols = OPERATION_COLUMNS.join(", ");
    const vals = [
      lit(op),
      lit(imp),
      lit(NODE_ID),
      lit("SEND_EXTERNAL"),
      lit("CREATED"),
      lit(1),
      lit(false),
      lit("APPROVAL_PENDING"),
      lit("POST"),
      lit("/v1/external-sends"),
      lit(`aud-${op}`),
      lit(HEX64),
      lit(w),
      lit(DESTINATION),
      lit("0.5"),
      lit(null),
      lit(null),
      lit(null),
    ].join(", ");
    psqlMust(
      scratchDb,
      `INSERT INTO operations (id) VALUES ('${op}'); ` +
        `INSERT INTO send_operations (${cols}) VALUES (${vals}, now()); ` +
        `INSERT INTO send_operation_expected_artifacts ` +
        `(artifact_id, operation_id, purpose, canonical_version, signing_key_id, preimage_text, preimage_sha256, signature) ` +
        `VALUES ('${randomUUID()}', '${op}', 'zp-send-external-expected-v1', 1, '${SIGNING_KEY_ID}', ` +
        `'preimage', '${HEX64}', '${SIG88}');`,
    );

    const result = await commitAutoApproval(
      { operationId: op, rule },
      { sql, withTx, nowMs: () => Date.now() },
    );
    expect(result.decision).toBe("approve");

    const row = psqlMust(
      scratchDb,
      `SELECT actor_kind || E'\\t' || actor_id || E'\\t' || action || E'\\t' || details_text || E'\\t' || details_sha256 ` +
        `FROM audit_log WHERE operation_id = '${op}' AND action = '${AUTO_APPROVE_APPLIED_ACTION}';`,
    ).trim();
    const [actorKind, actorId, action, detailsText, detailsSha] = row.split("\t");
    expect(actorKind).toBe("SYSTEM");
    expect(actorId).toBe("auto_policy:zukaz-rewards");
    expect(action).toBe(AUTO_APPROVE_APPLIED_ACTION);
    expect(detailsText).toBe(
      `rule_id=zukaz-rewards;implementer_id=${imp};amount_zkz=0.5;window_spend_before=0;window_cap_zkz=100`,
    );
    expect(detailsSha).toBe(
      createHash("sha256").update(detailsText!, "utf8").digest("hex"),
    );

    // Approval method arm
    const method = psqlMust(
      scratchDb,
      `SELECT method || '|' || (challenge_id IS NULL) || '|' || (totp_timestep IS NULL) ` +
        `FROM operation_approvals WHERE operation_id = '${op}';`,
    ).trim();
    expect(method === "AUTO_POLICY|t|t" || method === "AUTO_POLICY|true|true").toBe(true);
  });

  it("concurrent same-implementer commits cannot overshoot window cap", async () => {
    // Two distinct CREATED sends, each amount = cap = 1. Concurrent writers with
    // separate withTx sessions must not both AUTO_POLICY-approve (cap overshoot).
    const imp = "f1000000-0000-4000-8000-0000000000cc";
    const rule: AutoApproveRule = {
      ...RULE,
      implementer_id: imp,
      per_send_max_zkz: "1",
      window_cap_zkz: "1",
      window_hours: 288,
    };

    const seedOne = (amount: string): string => {
      const w = randomUUID();
      const op = randomUUID();
      const cols = OPERATION_COLUMNS.join(", ");
      const vals = [
        lit(op),
        lit(imp),
        lit(NODE_ID),
        lit("SEND_EXTERNAL"),
        lit("CREATED"),
        lit(1),
        lit(false),
        lit("APPROVAL_PENDING"),
        lit("POST"),
        lit("/v1/external-sends"),
        lit(`race-${op}`),
        lit(HEX64),
        lit(w),
        lit(DESTINATION),
        lit(amount),
        lit(null),
        lit(null),
        lit(null),
      ].join(", ");
      psqlMust(scratchDb, seedWallet(w));
      psqlMust(
        scratchDb,
        `INSERT INTO operations (id) VALUES ('${op}'); ` +
          `INSERT INTO send_operations (${cols}) VALUES (${vals}, now()); ` +
          `INSERT INTO send_operation_expected_artifacts ` +
          `(artifact_id, operation_id, purpose, canonical_version, signing_key_id, preimage_text, preimage_sha256, signature) ` +
          `VALUES ('${randomUUID()}', '${op}', 'zp-send-external-expected-v1', 1, '${SIGNING_KEY_ID}', ` +
          `'preimage', '${HEX64}', '${SIG88}');`,
      );
      return op;
    };

    const opA = seedOne("1");
    const opB = seedOne("1");

    const sql = new AutocommitPsql(scratchDb);
    // Two independent TX factories — not one shared client / queue.
    const sessionA = sessionWithTx(dbUrl);
    const sessionB = sessionWithTx(dbUrl);
    // Must match SQL now() used by WINDOW_SPEND_SQL (see cap-boundary comment).
    const nowMs = () => Date.now();

    const [resultA, resultB] = await Promise.all([
      commitAutoApproval(
        { operationId: opA, rule },
        { sql, withTx: sessionA.withTx, nowMs },
      ),
      commitAutoApproval(
        { operationId: opB, rule },
        { sql, withTx: sessionB.withTx, nowMs },
      ),
    ]);

    const decisions = [resultA.decision, resultB.decision].sort();
    expect(decisions).toEqual(["approve", "fall_through"]);
    const fall = resultA.decision === "fall_through" ? resultA : resultB;
    expect(fall).toEqual({ decision: "fall_through", reason: "window_cap" });

    const autoCount = psqlMust(
      scratchDb,
      `SELECT count(*) FROM operation_approvals a ` +
        `JOIN send_operations o ON o.operation_id = a.operation_id ` +
        `WHERE a.method = 'AUTO_POLICY' AND o.implementer_id = '${imp}' ` +
        `AND o.operation_id IN ('${opA}', '${opB}');`,
    ).trim();
    expect(autoCount).toBe("1");

    const spendSum = psqlMust(
      scratchDb,
      `SELECT COALESCE(SUM(o.amount_zkz::numeric), 0)::text FROM operation_approvals a ` +
        `JOIN send_operations o ON o.operation_id = a.operation_id ` +
        `WHERE a.method = 'AUTO_POLICY' AND o.implementer_id = '${imp}' ` +
        `AND o.operation_id IN ('${opA}', '${opB}');`,
    ).trim();
    expect(spendSum === "1" || spendSum === "1.0" || spendSum === "1.0000").toBe(true);

    const statuses = psqlMust(
      scratchDb,
      `SELECT operation_id || '=' || status FROM send_operations ` +
        `WHERE operation_id IN ('${opA}', '${opB}') ORDER BY operation_id;`,
    )
      .trim()
      .split("\n")
      .filter(Boolean);
    const statusMap = new Map(
      statuses.map((line) => {
        const [id, st] = line.split("=");
        return [id!, st!] as const;
      }),
    );
    expect(statusMap.get(opA) === "APPROVED" || statusMap.get(opA) === "CREATED").toBe(true);
    expect(statusMap.get(opB) === "APPROVED" || statusMap.get(opB) === "CREATED").toBe(true);
    const approvedN = [...statusMap.values()].filter((s) => s === "APPROVED").length;
    const createdN = [...statusMap.values()].filter((s) => s === "CREATED").length;
    expect(approvedN).toBe(1);
    expect(createdN).toBe(1);

    // No orphan approval without CAS (loser stays CREATED with zero approvals).
    for (const op of [opA, opB]) {
      if (statusMap.get(op) === "CREATED") {
        const orphans = psqlMust(
          scratchDb,
          `SELECT count(*) FROM operation_approvals WHERE operation_id = '${op}';`,
        ).trim();
        expect(orphans).toBe("0");
      }
    }
  });
});

// Guard after live describe so beforeAll sets schemaReady before this it runs.
registerPgRequiredGuard({
  name: "auto-approve-policy PG drills",
  databaseUrl: process.env.TEST_DATABASE_URL,
  isReady: () => schemaReady,
});

// Silence unused import when PG unavailable
void runPsqlUrl;
