/**
 * Production writer for wallet_settled_ledger.
 *
 * Real PostgreSQL drills (psql child process; network guard intact):
 *   1. RECEIVE writes exactly one RECEIVER row; amount/sha match operation_transactions
 *   2. Re-running the writer is idempotent (no duplicate rows)
 *   3. MOVE writes SOURCE + DESTINATION against one settled body
 *   4. SEND writes SOURCE and promotes SETTLED_BODY_PERSISTED
 *   5. landing_verdict matches the input oracle
 */
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { recordWalletSettledLedger } from "../src/core/wallet-settled-ledger-writer.js";
import type { SqlQueryFn } from "../src/core/sql-query-fn.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "../src/schema");
const SCHEMA = "wallet_settled_ledger_wsl_writer";
const databaseUrl = process.env.TEST_DATABASE_URL;

const SIG = `${"S".repeat(86)}==`;
const INNER_SHA = "a".repeat(64);
const FP = "f".repeat(64);
const SETTLED_AT = "2026-07-27T04:05:06.000Z";
const pubkey = (letter: string): string => `${letter.repeat(43)}=`;
const KEY_R = pubkey("R");
const KEY_S = pubkey("S");
const KEY_D = pubkey("D");
const KEY_X = pubkey("X");

const SETTLED_TEXT =
  '{"transaction": {"unix_time_secs": "1784880000", "amount": "0.01000000"},' +
  '"step_1_signature": "' +
  SIG +
  '", "step_2_signature": "' +
  SIG +
  '"}';
const SETTLED_SHA = createHash("sha256").update(SETTLED_TEXT, "utf8").digest("hex");

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
  if (result.code !== 0) throw new Error(result.stderr.trim() || result.stdout.trim());
  return result.stdout;
}

const inSchema = (sql: string): string => `SET search_path TO ${SCHEMA}, public;\n${sql}`;

const query: SqlQueryFn = async (text, values) => {
  // Anything with a result set (SELECT / WITH / … RETURNING) is JSON-aggregated so the
  // writer can read rows. Bare INSERT/UPDATE/DELETE without RETURNING runs as-is.
  const trimmed = text.trimStart();
  const returnsRows =
    /^(SELECT|WITH)\b/i.test(trimmed) || /\bRETURNING\b/i.test(trimmed);
  if (!returnsRows) {
    await psqlOk(inSchema(text), values);
    return [];
  }
  const wrapped = `WITH q AS (${text}) SELECT coalesce(json_agg(row_to_json(q)), '[]'::json) FROM q`;
  const stdout = await psqlOk(inSchema(wrapped), values);
  const line = stdout.trim().split("\n").filter(Boolean).at(-1) ?? "[]";
  return JSON.parse(line) as Record<string, unknown>[];
};

const frozenTable = (file: string, table: string): string => {
  const sql = readFileSync(join(SCHEMA_DIR, file), "utf8");
  const block = new RegExp(`^CREATE TABLE ${table} \\([\\s\\S]*?^\\);$`, "m").exec(sql)?.[0];
  if (block === undefined) throw new Error(`${file}: CREATE TABLE ${table} missing`);
  return block;
};

const ledgerDdl = (): string =>
  readFileSync(join(SCHEMA_DIR, "wallet-settled-ledger.sql"), "utf8").replace(
    /^CREATE DOMAIN [\s\S]*?;$/gm,
    "",
  );

const landingProofDdl = (): string =>
  readFileSync(join(SCHEMA_DIR, "landing-proof-verifications.sql"), "utf8").replace(
    /^CREATE TYPE [\s\S]*?;$/gm,
    "",
  );

const OP_RECEIVE = randomUUID();
const OP_MOVE = randomUUID();
const OP_SEND = randomUUID();
const WALLET_R = randomUUID();
const WALLET_S = randomUUID();
const WALLET_Dst = randomUUID();
const WALLET_X = randomUUID();
const DEST_ID = randomUUID();
const NODE_ID = randomUUID();
const OBSERVER_ID = randomUUID();
const T0_R = randomUUID();
const TERM_R = randomUUID();
const T0_M_S = randomUUID();
const TERM_M = randomUUID();
const T0_X = randomUUID();
const TERM_X = randomUUID();

describe.skipIf(!databaseUrl)("wallet_settled_ledger writer (PG)", () => {
  beforeAll(async () => {
    await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
    await psqlOk(
      inSchema(readFileSync(join(SCHEMA_DIR, "base-enums-domains.sql"), "utf8")),
    );

    const prereq = `
      CREATE TABLE nodes (id uuid PRIMARY KEY);
      CREATE TABLE wallets (
        id uuid PRIMARY KEY,
        public_key padded_base64url_pubkey NOT NULL
      );
      CREATE TABLE destinations (
        id uuid PRIMARY KEY,
        wallet_id uuid NOT NULL REFERENCES wallets(id)
      );
      CREATE TABLE operations (
        id uuid PRIMARY KEY,
        kind operation_kind NOT NULL,
        amount_zkz zkz_amount_positive_text NOT NULL,
        source_wallet_id uuid REFERENCES wallets(id),
        receiver_wallet_id uuid REFERENCES wallets(id),
        destination_id uuid REFERENCES destinations(id)
      );
      ${frozenTable("operations.sql", "operation_wallets")}
      ${frozenTable("transaction-material.sql", "operation_transactions")}
      CREATE TABLE observers (
        id uuid PRIMARY KEY,
        domain observer_domain NOT NULL DEFAULT 'NODE',
        owner_id uuid NOT NULL,
        gateway_endpoint_fingerprint sha256_hex NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE TABLE gateway_observations (
        id uuid PRIMARY KEY,
        observer_id uuid NOT NULL REFERENCES observers(id),
        wallet_public_key padded_base64url_pubkey NOT NULL DEFAULT '${KEY_R}'
      );
    `;
    await psqlOk(inSchema(prereq));
    await psqlOk(inSchema(landingProofDdl()));
    await psqlOk(inSchema(ledgerDdl()));

    await psqlOk(inSchema(`INSERT INTO nodes (id) VALUES ('${NODE_ID}'::uuid)`));
    await psqlOk(
      inSchema(
        `INSERT INTO wallets (id, public_key) VALUES
           ('${WALLET_R}'::uuid, '${KEY_R}'),
           ('${WALLET_S}'::uuid, '${KEY_S}'),
           ('${WALLET_Dst}'::uuid, '${KEY_D}'),
           ('${WALLET_X}'::uuid, '${KEY_X}')`,
      ),
    );
    await psqlOk(
      inSchema(
        `INSERT INTO destinations (id, wallet_id) VALUES ('${DEST_ID}'::uuid, '${WALLET_Dst}'::uuid)`,
      ),
    );
    await psqlOk(
      inSchema(
        `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
         VALUES ('${OBSERVER_ID}'::uuid, 'NODE', '${NODE_ID}'::uuid, '${FP}', now())`,
      ),
    );

    for (const [id, key] of [
      [T0_R, KEY_R],
      [TERM_R, KEY_R],
      [T0_M_S, KEY_S],
      [TERM_M, KEY_S],
      [T0_X, KEY_X],
      [TERM_X, KEY_X],
    ] as const) {
      await psqlOk(
        inSchema(
          `INSERT INTO gateway_observations (id, observer_id, wallet_public_key)
           VALUES ('${id}'::uuid, '${OBSERVER_ID}'::uuid, '${key}')`,
        ),
      );
    }

    const seedAttempt = async (
      opId: string,
      phase: "STEP2_SIGNATURE_PERSISTED" | "SETTLED_BODY_PERSISTED",
    ) => {
      const settledAt = phase === "SETTLED_BODY_PERSISTED" ? `'${SETTLED_AT}'::timestamptz` : "NULL";
      // Escape single quotes in SETTLED_TEXT for literal embed.
      const textLit = SETTLED_TEXT.replaceAll("'", "''");
      await psqlOk(
        inSchema(
          `INSERT INTO operation_transactions (
             operation_id, attempt_no, attempt_phase,
             inner_preimage_text, inner_sha256, step_1_signature,
             step_2_preimage_text, step_2_preimage_sha256,
             step_2_signature, completed_transaction_text, completed_transaction_sha256,
             settled_at, formed_at
           ) VALUES (
             '${opId}'::uuid, 1, '${phase}',
             'inner', '${INNER_SHA}', '${SIG}',
             'step2', '${INNER_SHA}',
             '${SIG}', '${textLit}', '${SETTLED_SHA}',
             ${settledAt}, now()
           )`,
        ),
      );
    };

    await psqlOk(
      inSchema(
        `INSERT INTO operations (id, kind, amount_zkz, receiver_wallet_id)
         VALUES ('${OP_RECEIVE}'::uuid, 'RECEIVE_EXTERNAL', '0.01000000', '${WALLET_R}'::uuid);
         INSERT INTO operation_wallets (operation_id, wallet_id, operation_role)
         VALUES ('${OP_RECEIVE}'::uuid, '${WALLET_R}'::uuid, 'RECEIVER');`,
      ),
    );
    await seedAttempt(OP_RECEIVE, "SETTLED_BODY_PERSISTED");

    await psqlOk(
      inSchema(
        `INSERT INTO operations (id, kind, amount_zkz, source_wallet_id, destination_id)
         VALUES ('${OP_MOVE}'::uuid, 'MOVE_INTERNAL', '0.01000000', '${WALLET_S}'::uuid, '${DEST_ID}'::uuid)`,
      ),
    );
    await seedAttempt(OP_MOVE, "STEP2_SIGNATURE_PERSISTED");

    await psqlOk(
      inSchema(
        `INSERT INTO operations (id, kind, amount_zkz, source_wallet_id)
         VALUES ('${OP_SEND}'::uuid, 'SEND_EXTERNAL', '0.01000000', '${WALLET_X}'::uuid)`,
      ),
    );
    await seedAttempt(OP_SEND, "STEP2_SIGNATURE_PERSISTED");
  }, 60_000);

  afterAll(async () => {
    if (!databaseUrl) return;
    await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
  });

  it("RECEIVE writes one RECEIVER row matching operation_transactions amount/sha/verdict", async () => {
    const result = await recordWalletSettledLedger(query, {
      operationId: OP_RECEIVE,
      landingVerdict: "LANDED_EXACT",
      pathDepth: 0,
      t0ObservationId: T0_R,
      terminalObservationId: TERM_R,
      requiredPathCount: 1,
      verifiedAtIso: SETTLED_AT,
    });
    expect(result.ledgerRolesWritten).toEqual(["RECEIVER"]);
    expect(result.reusedExistingProof).toBe(false);

    const rows = await query(
      `SELECT operation_role, amount_zkz, settled_transaction_sha256,
              settled_transaction_text, landing_verdict, wallet_id::text AS wallet_id
         FROM wallet_settled_ledger WHERE operation_id = $1::uuid`,
      [OP_RECEIVE],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.operation_role).toBe("RECEIVER");
    expect(rows[0]!.wallet_id).toBe(WALLET_R);
    expect(rows[0]!.amount_zkz).toBe("0.01000000");
    expect(rows[0]!.settled_transaction_sha256).toBe(SETTLED_SHA);
    expect(rows[0]!.settled_transaction_text).toBe(SETTLED_TEXT);
    expect(rows[0]!.landing_verdict).toBe("LANDED_EXACT");

    const match = await query(
      `SELECT (l.settled_transaction_sha256 = t.completed_transaction_sha256
           AND convert_to(l.settled_transaction_text,'UTF8')
               = convert_to(t.completed_transaction_text,'UTF8')
           AND l.settled_at IS NOT DISTINCT FROM t.settled_at) AS ok
         FROM wallet_settled_ledger l
         JOIN operation_transactions t
           ON t.operation_id = l.operation_id AND t.attempt_no = l.attempt_no
        WHERE l.operation_id = $1::uuid`,
      [OP_RECEIVE],
    );
    expect(match[0]!.ok).toBe(true);
  });

  it("RECEIVE writer is idempotent under replay", async () => {
    const before = await query(
      `SELECT count(*)::int AS n FROM wallet_settled_ledger WHERE operation_id = $1::uuid`,
      [OP_RECEIVE],
    );
    expect(before[0]!.n).toBe(1);

    const result = await recordWalletSettledLedger(query, {
      operationId: OP_RECEIVE,
      landingVerdict: "LANDED_EXACT",
      pathDepth: 0,
      t0ObservationId: T0_R,
      terminalObservationId: TERM_R,
      requiredPathCount: 1,
      verifiedAtIso: SETTLED_AT,
    });
    expect(result.reusedExistingProof).toBe(true);

    const after = await query(
      `SELECT count(*)::int AS n FROM wallet_settled_ledger WHERE operation_id = $1::uuid`,
      [OP_RECEIVE],
    );
    expect(after[0]!.n).toBe(1);

    const proofs = await query(
      `SELECT count(*)::int AS n FROM operation_landing_proofs WHERE operation_id = $1::uuid`,
      [OP_RECEIVE],
    );
    expect(proofs[0]!.n).toBe(1);
  });

  it("MOVE writes SOURCE+DESTINATION; SEND writes SOURCE; both promote SETTLED_BODY_PERSISTED", async () => {
    await recordWalletSettledLedger(query, {
      operationId: OP_MOVE,
      landingVerdict: "LANDED_EXACT",
      pathDepth: 0,
      t0ObservationId: T0_M_S,
      terminalObservationId: TERM_M,
      requiredPathCount: 2,
      verifiedAtIso: SETTLED_AT,
    });
    const moveRows = await query(
      `SELECT operation_role FROM wallet_settled_ledger
        WHERE operation_id = $1::uuid ORDER BY operation_role`,
      [OP_MOVE],
    );
    expect(moveRows.map((r) => r.operation_role)).toEqual(["DESTINATION", "SOURCE"]);
    const moveSha = await query(
      `SELECT count(DISTINCT settled_transaction_sha256)::int AS n
         FROM wallet_settled_ledger WHERE operation_id = $1::uuid`,
      [OP_MOVE],
    );
    expect(moveSha[0]!.n).toBe(1);
    const movePhase = await query(
      `SELECT attempt_phase FROM operation_transactions WHERE operation_id = $1::uuid`,
      [OP_MOVE],
    );
    expect(movePhase[0]!.attempt_phase).toBe("SETTLED_BODY_PERSISTED");

    await recordWalletSettledLedger(query, {
      operationId: OP_SEND,
      landingVerdict: "LANDED_COMPLETE_PATH",
      pathDepth: 2,
      t0ObservationId: T0_X,
      terminalObservationId: TERM_X,
      requiredPathCount: 1,
      verifiedAtIso: SETTLED_AT,
    });
    const sendRows = await query(
      `SELECT operation_role, landing_verdict, wallet_id::text AS wallet_id
         FROM wallet_settled_ledger WHERE operation_id = $1::uuid`,
      [OP_SEND],
    );
    expect(sendRows).toHaveLength(1);
    expect(sendRows[0]!.operation_role).toBe("SOURCE");
    expect(sendRows[0]!.wallet_id).toBe(WALLET_X);
    expect(sendRows[0]!.landing_verdict).toBe("LANDED_COMPLETE_PATH");
  });
});
