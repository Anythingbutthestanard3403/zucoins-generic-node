// SEND_EXTERNAL step-1 signature advance vs lease release (One-in-flight money-path).
// Governing: signing custody; the data model; the one-in-flight-per-wallet and never-blind-retry rules.
//
// persistSendPartialSql makes the step-1 signature durable in a statement separate from the
// signUnderLease lease read. This suite plants a real wallet_active_leases row and proves a
// mid-sign release leaves no durable signature — the SEND half of the AttemptLeaseGuard.

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  persistSendPartialSql,
  persistSendSignIntentSql,
  type DurableSignIntent,
  type FormAndSignClaim,
  type FormAndSignHeldLease,
} from "../src/core/send-form-and-sign.ts";
import { advanceAttemptPhase } from "../src/core/transaction-material-store.ts";
import type { SqlQueryFn } from "../src/core/sql-query-fn.ts";
import {
  buildSendTransferCodeText,
  hashTransferCodeText,
} from "../src/protocol/send-transfer-code.ts";
import { TRANSACTION_MATERIAL_SCHEMA_FILE } from "../src/schema/transaction-material.contract.ts";
import {
  WALLET_INNER_PREIMAGE_SHA256,
  WALLET_INNER_PREIMAGE_TEXT,
  WALLET_STEP_1_SIGNATURE,
} from "./fixtures/splitchain-v2-byte-evidence.ts";
import { verificationModeFixtureSql } from "./verification-mode-fixture.js";

const here = dirname(fileURLToPath(import.meta.url));
const contractSql = readFileSync(
  resolve(here, "../src/schema", TRANSACTION_MATERIAL_SCHEMA_FILE),
  "utf8",
);

const SCHEMA = "send_form_and_sign_send_lease_guard";
const databaseUrl = process.env.TEST_DATABASE_URL;

const SOURCE_WALLET = "22222222-2222-4222-8222-222222222222";
const OWNER_INSTANCE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const LEASE_EPOCH = 7n;

const WALLET_ACTIVE_LEASES_DDL = `
CREATE TABLE wallet_active_leases (
  wallet_id uuid PRIMARY KEY,
  membership_id uuid NOT NULL UNIQUE,
  lease_group_id uuid NOT NULL,
  root_operation_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  lease_role text NOT NULL
    CHECK (lease_role IN (
      'RECEIVE_WINDOW',
      'MOVE_SOURCE',
      'MOVE_DESTINATION',
      'SEND_SOURCE',
      'RECONCILIATION'
    )),
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  acquired_at timestamptz NOT NULL,
  heartbeat_at timestamptz NOT NULL,
  owner_instance_id uuid NOT NULL,
  release_not_before timestamptz,
  UNIQUE (operation_id, wallet_id),
  UNIQUE (lease_group_id, wallet_id)
);
`;

// send_operations is only needed for the CAS after a successful partial — the lease-guard
// failure path never reaches it. Stub the minimum columns the CAS statement touches so a
// happy-path seed can exercise the full persistSendPartialSql sequence.
const SEND_OPERATIONS_DDL = `
CREATE TABLE send_operations (
  operation_id uuid PRIMARY KEY,
  status text NOT NULL,
  formation_state text NOT NULL,
  row_version integer NOT NULL DEFAULT 1
);
`;

const pgEnv = (): NodeJS.ProcessEnv => {
  const url = new URL(databaseUrl as string);
  return {
    ...process.env,
    PGHOST: url.hostname,
    PGPORT: url.port || "5432",
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: url.pathname.replace(/^\//, ""),
  };
};

interface PsqlResult {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

function psql(sql: string, values: readonly unknown[] = []): Promise<PsqlResult> {
  const args = ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"];
  values.forEach((value, index) => {
    if (value !== null && value !== undefined) {
      args.push("-v", `p${index + 1}=${String(value)}`);
    }
  });
  args.push("-f", "-");
  const bound = sql.replace(/\$(\d+)/g, (_match, position: string) => {
    const value = values[Number(position) - 1];
    return value === null || value === undefined ? "NULL" : `:'p${position}'`;
  });
  return new Promise((settle, fail) => {
    const child = spawn("psql", args, { env: pgEnv(), stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", fail);
    child.on("close", (code) => settle({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(`${sql.trimEnd().endsWith(";") ? bound : `${bound};`}\n`);
  });
}

async function psqlOk(sql: string, values: readonly unknown[] = []): Promise<string> {
  const result = await psql(sql, values);
  if (result.code !== 0) throw new Error(result.stderr.trim());
  return result.stdout;
}

const inSchema = (sql: string): string => `SET search_path TO ${SCHEMA};\n${sql}`;

const query: SqlQueryFn = async (text, values) => {
  const returnsRows = /^\s*(SELECT|WITH)\b/i.test(text) || /\bRETURNING\b/i.test(text);
  if (!returnsRows) {
    await psqlOk(inSchema(text), values);
    return [];
  }
  const wrapped = `WITH q AS (${text}) SELECT coalesce(json_agg(row_to_json(q)), '[]'::json) FROM q`;
  const stdout = await psqlOk(inSchema(wrapped), values);
  const line = stdout.trim().split("\n").filter(Boolean).at(-1) ?? "[]";
  return JSON.parse(line) as Record<string, unknown>[];
};

let reachable = false;

interface Seeded {
  readonly operationId: string;
  readonly approvalId: string;
  readonly intent: DurableSignIntent;
}

async function seedSignIntentReady(): Promise<Seeded> {
  const operationId = randomUUID();
  const approvalId = randomUUID();
  const leaseGroupId = randomUUID();
  const membershipId = randomUUID();

  await psqlOk(inSchema(`INSERT INTO operations (id) VALUES ($1::uuid)`), [operationId]);
  await psqlOk(inSchema(`INSERT INTO operation_approvals (id) VALUES ($1::uuid)`), [approvalId]);
  await psqlOk(
    inSchema(
      `INSERT INTO send_operations (operation_id, status, formation_state, row_version)
       VALUES ($1::uuid, 'APPROVED', 'APPROVED_UNSIGNED', 1)`,
    ),
    [operationId],
  );

  const claim: FormAndSignClaim = {
    operationId,
    status: "APPROVED",
    formationState: "APPROVED_UNSIGNED",
    rowVersion: 1,
    sourceWalletId: SOURCE_WALLET,
    sourcePubkey: "unused-for-sql-path",
    destinationAddress: "unused-for-sql-path",
    amountZkz: "1",
  };
  const held: FormAndSignHeldLease = {
    walletId: SOURCE_WALLET,
    membershipId,
    leaseGroupId,
    leaseEpoch: LEASE_EPOCH,
    operationId,
  };

  const persisted = await persistSendSignIntentSql(query, {
    claim,
    held,
    approvalId,
    sourceT0ObservationId: randomUUID(),
    destinationFormationObservationId: randomUUID(),
    constructed: {
      innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
      innerSha256: WALLET_INNER_PREIMAGE_SHA256,
      expiryUnixTimeSecs: "1718000300",
      redemptionExpiryAt: "2026-01-01T00:05:00.000Z",
      formationUnixTimeSecs: "1718000000",
      // capability is discarded after intent commit; not read by the SQL path under test
      capability: null as unknown as import("../src/protocol/send-inner.ts").ConstructedSendInner["capability"],
    },
    preparedAt: "2026-01-01T00:00:00.000Z",
  });
  if (!persisted.ok) {
    throw new Error(`sign intent seed failed: ${persisted.reason}: ${persisted.detail}`);
  }

  // Plant the SEND_SOURCE lease the guard will re-check.
  await psqlOk(
    inSchema(
      `INSERT INTO wallet_active_leases
         (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
          lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $4::uuid,
               'SEND_SOURCE', $5, now(), now(), $6::uuid)`,
    ),
    [SOURCE_WALLET, membershipId, leaseGroupId, operationId, LEASE_EPOCH.toString(), OWNER_INSTANCE],
  );

  return { operationId, approvalId, intent: persisted.intent };
}

const readAttempt = async (operationId: string): Promise<Record<string, unknown>> => {
  const rows = await query(
    `SELECT attempt_phase, step_1_signature FROM operation_transactions
      WHERE operation_id = $1 AND attempt_no = 1`,
    [operationId],
  );
  const row = rows[0];
  if (row === undefined) throw new Error(`no attempt for ${operationId}`);
  return row;
};

const countPartials = async (operationId: string): Promise<number> => {
  const rows = await query(
    `SELECT count(*)::int AS n FROM external_send_partials WHERE operation_id = $1`,
    [operationId],
  );
  return Number(rows[0]?.n ?? 0);
};

const countLeases = async (): Promise<number> => {
  const rows = await query(`SELECT count(*)::int AS n FROM wallet_active_leases`, []);
  return Number(rows[0]?.n ?? 0);
};

describe.skipIf(databaseUrl === undefined)(
  "SEND step-1 signature advance lease guard against live PostgreSQL",
  () => {
    beforeAll(async () => {
      await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
      await psqlOk(
        inSchema(
          `CREATE TABLE operations (id uuid PRIMARY KEY);
           CREATE TABLE operation_approvals (id uuid PRIMARY KEY);
           CREATE TABLE wallets (id uuid PRIMARY KEY);
           INSERT INTO wallets (id) VALUES ('${SOURCE_WALLET}');
           ${contractSql}
           ${WALLET_ACTIVE_LEASES_DDL}
           ${SEND_OPERATIONS_DDL}
           ${verificationModeFixtureSql()}`,
        ),
      );
      reachable = true;
    });

    afterAll(async () => {
      if (reachable) await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE;`);
    });

    afterEach(async () => {
      if (!reachable) return;
      await psqlOk(inSchema(`DELETE FROM external_send_partials`));
      await psqlOk(inSchema(`DELETE FROM external_send_sign_intents`));
      await psqlOk(inSchema(`DELETE FROM operation_transactions`));
      await psqlOk(inSchema(`DELETE FROM wallet_active_leases`));
      await psqlOk(inSchema(`DELETE FROM send_operations`));
      await psqlOk(inSchema(`DELETE FROM operation_approvals`));
      await psqlOk(inSchema(`DELETE FROM operations`));
    });

    it("happy path: held lease lets the step-1 signature and partial become durable", async () => {
      const { operationId, intent } = await seedSignIntentReady();
      const transferCodeText = buildSendTransferCodeText(
        intent.innerPreimageText,
        WALLET_STEP_1_SIGNATURE,
      );
      const transferCodeSha256 = hashTransferCodeText(transferCodeText);

      const result = await persistSendPartialSql(query, {
        intent,
        step1Signature: WALLET_STEP_1_SIGNATURE,
        transferCodeText,
        transferCodeSha256,
        persistedAt: "2026-01-01T00:00:05.000Z",
      });
      expect(result.ok).toBe(true);

      const row = await readAttempt(operationId);
      expect(row.attempt_phase).toBe("STEP1_SIGNATURE_PERSISTED");
      expect(row.step_1_signature).toBe(WALLET_STEP_1_SIGNATURE);
      expect(await countPartials(operationId)).toBe(1);
    });

    it("a release before the advance leaves no durable signature and no partial", async () => {
      const { operationId, intent } = await seedSignIntentReady();
      const transferCodeText = buildSendTransferCodeText(
        intent.innerPreimageText,
        WALLET_STEP_1_SIGNATURE,
      );
      const transferCodeSha256 = hashTransferCodeText(transferCodeText);

      // Release between sign and persist — the window under test.
      await psqlOk(inSchema(`DELETE FROM wallet_active_leases WHERE wallet_id = $1::uuid`), [
        SOURCE_WALLET,
      ]);

      const result = await persistSendPartialSql(query, {
        intent,
        step1Signature: WALLET_STEP_1_SIGNATURE,
        transferCodeText,
        transferCodeSha256,
        persistedAt: "2026-01-01T00:00:05.000Z",
      });
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("unreachable");
      expect(result.reason).toBe("partial_insert_rejected");
      expect(result.detail).toMatch(/did not advance to STEP1_SIGNATURE_PERSISTED/);

      const row = await readAttempt(operationId);
      expect(row.attempt_phase).toBe("INNER_PREIMAGE_PERSISTED");
      expect(row.step_1_signature).toBeNull();
      expect(await countPartials(operationId)).toBe(0);
      expect(await countLeases()).toBe(0);
    });

    it("behavioral: advance blocks on FOR SHARE while releaser holds FOR UPDATE, then matches 0", async () => {
      const { operationId } = await seedSignIntentReady();

      const hold = spawn(
        "psql",
        ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-f", "-"],
        { env: pgEnv(), stdio: ["pipe", "pipe", "pipe"] },
      );
      let holdOut = "";
      let holdErr = "";
      hold.stdout.setEncoding("utf8");
      hold.stderr.setEncoding("utf8");
      hold.stdout.on("data", (c: string) => {
        holdOut += c;
      });
      hold.stderr.on("data", (c: string) => {
        holdErr += c;
      });
      hold.stdin.write(
        `SET search_path TO ${SCHEMA};\n` +
          `BEGIN ISOLATION LEVEL SERIALIZABLE;\n` +
          `SELECT 1 FROM wallet_active_leases WHERE wallet_id = '${SOURCE_WALLET}' FOR UPDATE;\n`,
      );

      await new Promise<void>((resolve, reject) => {
        const start = Date.now();
        const tick = () => {
          if (holdOut.includes("1")) {
            resolve();
            return;
          }
          if (Date.now() - start > 5_000) {
            reject(new Error(`lock not acquired: out=${holdOut} err=${holdErr}`));
            return;
          }
          setTimeout(tick, 50);
        };
        tick();
      });

      const advanceStarted = Date.now();
      let advanceSettledAt = 0;
      const advancePromise = advanceAttemptPhase(
        query,
        operationId,
        "STEP1_SIGNATURE_PERSISTED",
        { step_1_signature: WALLET_STEP_1_SIGNATURE },
        {
          walletId: SOURCE_WALLET,
          operationId,
          leaseEpoch: LEASE_EPOCH,
        },
      ).then(
        () => {
          advanceSettledAt = Date.now();
          return "ok" as const;
        },
        (err: unknown) => {
          advanceSettledAt = Date.now();
          return err;
        },
      );

      await new Promise((r) => setTimeout(r, 400));
      expect(advanceSettledAt).toBe(0);

      hold.stdin.write(
        `DELETE FROM wallet_active_leases WHERE wallet_id = '${SOURCE_WALLET}';\nCOMMIT;\n`,
      );
      hold.stdin.end();
      await new Promise<void>((resolve) => hold.on("close", () => resolve()));

      const outcome = await advancePromise;
      expect(outcome).not.toBe("ok");
      expect(String(outcome)).toMatch(/did not advance to STEP1_SIGNATURE_PERSISTED/);
      expect(advanceSettledAt - advanceStarted).toBeGreaterThanOrEqual(350);

      const row = await readAttempt(operationId);
      expect(row.attempt_phase).toBe("INNER_PREIMAGE_PERSISTED");
      expect(row.step_1_signature).toBeNull();
      expect(await countLeases()).toBe(0);
    }, 20_000);
  },
);
