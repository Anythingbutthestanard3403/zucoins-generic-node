// Real-PostgreSQL proof for connector-reserve-wallets.sql (ZTR-1324 / GN-101).
//
// Engine-only properties:
//   1. setReserveWallets binds a default plus a secondary, funding pin follows the default,
//      and list() returns both public_key and display_label.
//   2. A pre-existing funding_wallet_id backfills one is_default junction row.
//   3. A second is_default row for the same connector hits SQLSTATE 23505.
//   4. A RETIRED wallet or a wallet on another node is refused and writes nothing.
//
// psql runs as a child process so the in-process network guard stays intact.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { SqlImplementerRegistry } from "../src/implementer/sql-store.ts";
import type { ImplementerSqlExecutor } from "../src/implementer/sql-store.ts";
import { CONNECTOR_RESERVE_WALLETS_SCHEMA_FILE } from "../src/schema/connector-reserve-wallets.contract.ts";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sliceSql = readFileSync(
  resolve(here, "../src/schema", CONNECTOR_RESERVE_WALLETS_SCHEMA_FILE),
  "utf8",
);

const SCHEMA = "ztr1324_reserve";
const BACKFILL_SCHEMA = "ztr1324_reserve_backfill";

const NODE = "11111111-1111-4111-8111-111111111111";
const NODE_OTHER = "22222222-2222-4222-8222-222222222222";
const ACTOR = "operator-ztr-1324";

const IMPL = "33333333-3333-4333-8333-333333333331";
const IMPL_REFUSE = "33333333-3333-4333-8333-333333333332";
const IMPL_FUNDING = "33333333-3333-4333-8333-333333333333";
const IMPL_UNIQUE = "33333333-3333-4333-8333-333333333334";
const IMPL_BACKFILL = "33333333-3333-4333-8333-333333333335";

const W1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const W2 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2";
const W_RETIRED = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3";
const W_OTHER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4";
const W_FUNDING = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5";
const W_UNIQUE_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6";
const W_UNIQUE_B = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa7";
const W_BACKFILL = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa8";
const W_RECEIVE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9";
const W_SEND = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab";
const W_PENDING = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaac";
const IMPL_INELIGIBLE = "33333333-3333-4333-8333-333333333336";

const PUB_1 = "pub-reserve-w1";
const PUB_2 = "pub-reserve-w2";

const STUBS = `
CREATE TABLE nodes (
  id uuid PRIMARY KEY
);
CREATE TABLE wallets (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes (id),
  public_key text NOT NULL,
  state text NOT NULL DEFAULT 'ACTIVE',
  retired_at timestamptz NULL,
  allow_internal_move boolean NOT NULL DEFAULT true,
  money_mode text NOT NULL DEFAULT 'INTERNAL_ONLY'
);
CREATE TABLE destinations (
  id uuid PRIMARY KEY,
  wallet_id uuid NOT NULL REFERENCES wallets (id) ON DELETE CASCADE,
  state text NOT NULL
);
CREATE TABLE implementers (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz NULL,
  funding_wallet_id uuid NULL REFERENCES wallets (id)
);
CREATE TABLE audit_log (
  id uuid PRIMARY KEY,
  node_id uuid,
  actor_kind text,
  actor_id text,
  action text,
  operation_id uuid,
  wallet_id uuid,
  details_text text,
  details_sha256 text,
  created_at timestamptz
);
`;

const databaseUrl = process.env.TEST_DATABASE_URL;
let ready = false;

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

const scalar = (schema: string, query: string): string =>
  psql(["-t", "-A", "-c", `SET search_path TO ${schema}`, "-c", query]).stdout.trim();

const execSql = (schema: string, statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${schema}`, "-c", statement]);

const applySlice = (schema: string): void => {
  const applied = execSql(schema, sliceSql);
  if (applied.status !== 0) {
    throw new Error(`slice apply failed on ${schema}: ${applied.stderr}`);
  }
};

const literal = (value: unknown): string => {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "NULL";
  if (Array.isArray(value)) {
    if (value.length === 0) return "ARRAY[]::uuid[]";
    const items = value.map((item) => `'${String(item).replaceAll("'", "''")}'`);
    return `ARRAY[${items.join(",")}]::uuid[]`;
  }
  return `'${String(value).replaceAll("'", "''")}'`;
};

const bind = (text: string, params: readonly unknown[]): string => {
  let sql = text;
  for (let i = params.length; i >= 1; i -= 1) {
    sql = sql.replaceAll(`$${i}`, literal(params[i - 1]));
  }
  return sql;
};

function executorFor(schema: string): ImplementerSqlExecutor {
  return {
    async query<R extends Record<string, unknown>>(text: string, params?: readonly unknown[]) {
      const bound = bind(text, params ?? []).trim().replace(/;+\s*$/, "");
      // A data-modifying WITH must stay top-level. CREATE TABLE AS accepts that form
      // only when the primary statement is SELECT. A primary INSERT/UPDATE/DELETE is
      // folded into one more CTE so the outer statement is a SELECT.
      const dataModifying =
        /^\s*WITH\b/i.test(bound) && /\b(UPDATE|INSERT|DELETE)\b/i.test(bound);
      const writeSplit = /\)\s*(INSERT|UPDATE|DELETE)\b/i.exec(bound);
      const returning = /\bRETURNING\s+(.+)$/i.exec(bound);
      let wrapped: string;
      if (
        dataModifying &&
        writeSplit !== null &&
        returning !== null &&
        writeSplit.index < returning.index
      ) {
        const withHead = bound.slice(0, writeSplit.index + 1);
        const tail = bound.slice(writeSplit.index + 1, returning.index).trim();
        const cols = returning[1].trim();
        wrapped =
          `${withHead}, __result AS (${tail} RETURNING ${cols}) ` +
          `SELECT coalesce(json_agg(row_to_json(t)), '[]'::json)::text FROM __result t`;
      } else if (dataModifying) {
        wrapped =
          `BEGIN; CREATE TEMP TABLE _q_scratch ON COMMIT DROP AS ${bound}; ` +
          `SELECT coalesce(json_agg(row_to_json(_q_scratch)), '[]'::json)::text FROM _q_scratch; COMMIT;`;
      } else {
        wrapped = `WITH q AS (${bound}) SELECT coalesce(json_agg(row_to_json(q)), '[]'::json)::text FROM q`;
      }
      const result = psql([
        "-t",
        "-A",
        "-c",
        `SET search_path TO ${schema}`,
        "-c",
        wrapped,
      ]);
      if (result.status !== 0) {
        throw new Error(`psql query failed: ${result.stderr}\n${bound.slice(0, 500)}`);
      }
      const line = result.stdout
        .split("\n")
        .map((row) => row.trim())
        .filter((row) => row.length > 0)
        .at(-1) ?? "[]";
      const parsed = JSON.parse(line) as R[];
      return { rows: parsed };
    },
  };
}

const insertWallet = (
  schema: string,
  id: string,
  nodeId: string,
  publicKey: string,
  extras = "",
  opts: { readonly moneyMode?: string; readonly destinationState?: string | null } = {},
): void => {
  const mode = opts.moneyMode ?? "INTERNAL_ONLY";
  const inserted = execSql(
    schema,
    `INSERT INTO wallets (id, node_id, public_key, money_mode${extras.length > 0 ? ", state, retired_at" : ""})
     VALUES ('${id}', '${nodeId}', '${publicKey}', '${mode}'${extras})`,
  );
  if (inserted.status !== 0) throw new Error(inserted.stderr);
  if (opts.destinationState === null) return;
  const destinationState = opts.destinationState ?? "BLESSED";
  const destinationId = `d${id.slice(1)}`;
  const destination = execSql(
    schema,
    `INSERT INTO destinations (id, wallet_id, state)
     VALUES ('${destinationId}', '${id}', '${destinationState}')`,
  );
  if (destination.status !== 0) throw new Error(destination.stderr);
};

const insertImplementer = (schema: string, id: string, name: string, funding: string | null): void => {
  const fundingSql = funding === null ? "NULL" : `'${funding}'`;
  const inserted = execSql(
    schema,
    `INSERT INTO implementers (id, name, funding_wallet_id) VALUES ('${id}', '${name}', ${fundingSql})`,
  );
  if (inserted.status !== 0) throw new Error(inserted.stderr);
};

describe("implementer reserve wallets PG drills (ZTR-1324)", () => {
  const registry = new SqlImplementerRegistry(executorFor(SCHEMA));

  beforeAll(() => {
    if (!databaseUrl) return;
    const probe = psql(["-c", "SELECT 1"]);
    if (probe.status !== 0) return;
    const created = psql([
      "-c",
      `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`,
    ]);
    if (created.status !== 0) throw new Error(created.stderr);
    const stubs = execSql(SCHEMA, STUBS);
    if (stubs.status !== 0) throw new Error(stubs.stderr);
    applySlice(SCHEMA);
    const seeded = execSql(
      SCHEMA,
      `INSERT INTO nodes (id) VALUES ('${NODE}'), ('${NODE_OTHER}');`,
    );
    if (seeded.status !== 0) throw new Error(seeded.stderr);
    ready = true;
  });

  afterAll(() => {
    if (!ready) return;
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
    psql(["-c", `DROP SCHEMA IF EXISTS ${BACKFILL_SCHEMA} CASCADE`]);
  });

  registerPgRequiredGuard({
    name: "implementer-reserve-wallets.pg",
    databaseUrl,
    isReady: () => ready,
  });

  it("binds a default and a secondary and list() returns labels and public keys", async () => {
    if (!ready) return;
    insertWallet(SCHEMA, W1, NODE, PUB_1);
    insertWallet(SCHEMA, W2, NODE, PUB_2);
    insertImplementer(SCHEMA, IMPL, "connector-main", null);
    execSql(SCHEMA, `UPDATE wallets SET display_label = 'Main Reserve' WHERE id = '${W1}'`);
    execSql(SCHEMA, `UPDATE wallets SET display_label = 'Secondary' WHERE id = '${W2}'`);

    const bound = await registry.setReserveWallets({
      nodeId: NODE,
      implementerId: IMPL,
      walletIds: [W1, W2],
      defaultWalletId: W1,
      actorId: ACTOR,
    });
    expect(bound.ok).toBe(true);
    if (!bound.ok) return;
    expect(bound.implementer.funding_wallet_id).toBe(W1);
    expect(bound.implementer.reserve_wallets).toEqual([
      {
        wallet_id: W1,
        public_key: PUB_1,
        display_label: "Main Reserve",
        is_default: true,
      },
      {
        wallet_id: W2,
        public_key: PUB_2,
        display_label: "Secondary",
        is_default: false,
      },
    ]);

    const listed = await registry.list();
    const row = listed.find((item) => item.id === IMPL);
    expect(row?.funding_wallet_id).toBe(W1);
    expect(row?.reserve_wallets).toEqual(bound.implementer.reserve_wallets);

    const audits = scalar(
      SCHEMA,
      `SELECT count(*) FROM audit_log
        WHERE action = 'implementer.reserve_wallets_changed'
          AND actor_kind = 'OPERATOR_SESSION'
          AND actor_id = '${ACTOR}'`,
    );
    expect(audits).toBe("1");

    const removed = execSql(SCHEMA, `DELETE FROM wallets WHERE id = '${W1}'`);
    expect(removed.status).not.toBe(0);
    expect(removed.stderr).toMatch(/restrict|foreign key/i);
  });

  it("backfills funding_wallet_id into one default junction row", () => {
    if (!ready) return;
    const created = psql([
      "-c",
      `DROP SCHEMA IF EXISTS ${BACKFILL_SCHEMA} CASCADE; CREATE SCHEMA ${BACKFILL_SCHEMA};`,
    ]);
    if (created.status !== 0) throw new Error(created.stderr);
    const stubs = execSql(BACKFILL_SCHEMA, STUBS);
    if (stubs.status !== 0) throw new Error(stubs.stderr);
    const seeded = execSql(
      BACKFILL_SCHEMA,
      `INSERT INTO nodes (id) VALUES ('${NODE}');
       INSERT INTO wallets (id, node_id, public_key) VALUES ('${W_BACKFILL}', '${NODE}', 'pub-backfill');
       INSERT INTO implementers (id, name, funding_wallet_id)
       VALUES ('${IMPL_BACKFILL}', 'connector-backfill', '${W_BACKFILL}');`,
    );
    if (seeded.status !== 0) throw new Error(seeded.stderr);
    applySlice(BACKFILL_SCHEMA);
    applySlice(BACKFILL_SCHEMA);
    const rows = scalar(
      BACKFILL_SCHEMA,
      `SELECT implementer_id::text || '|' || wallet_id::text || '|' || is_default::text
         FROM implementer_reserve_wallets
        WHERE implementer_id = '${IMPL_BACKFILL}'`,
    );
    expect(rows).toBe(`${IMPL_BACKFILL}|${W_BACKFILL}|true`);
    const funding = scalar(
      BACKFILL_SCHEMA,
      `SELECT funding_wallet_id::text FROM implementers WHERE id = '${IMPL_BACKFILL}'`,
    );
    expect(funding).toBe(W_BACKFILL);
  });

  it("rejects a second default row with SQLSTATE 23505", () => {
    if (!ready) return;
    insertWallet(SCHEMA, W_UNIQUE_A, NODE, "pub-unique-a");
    insertWallet(SCHEMA, W_UNIQUE_B, NODE, "pub-unique-b");
    insertImplementer(SCHEMA, IMPL_UNIQUE, "connector-unique", null);
    const first = execSql(
      SCHEMA,
      `INSERT INTO implementer_reserve_wallets (implementer_id, wallet_id, is_default)
       VALUES ('${IMPL_UNIQUE}', '${W_UNIQUE_A}', true)`,
    );
    expect(first.status).toBe(0);
    const second = psql([
      "-v",
      "VERBOSITY=verbose",
      "-c",
      `SET search_path TO ${SCHEMA}`,
      "-c",
      `INSERT INTO implementer_reserve_wallets (implementer_id, wallet_id, is_default)
       VALUES ('${IMPL_UNIQUE}', '${W_UNIQUE_B}', true)`,
    ]);
    expect(second.status).not.toBe(0);
    expect(second.stderr).toMatch(/23505/);
    const count = scalar(
      SCHEMA,
      `SELECT count(*) FROM implementer_reserve_wallets WHERE implementer_id = '${IMPL_UNIQUE}'`,
    );
    expect(count).toBe("1");
  });

  it("refuses a retired wallet and a wallet on another node without writing", async () => {
    if (!ready) return;
    insertWallet(SCHEMA, W_RETIRED, NODE, "pub-retired", ", 'RETIRED', now()");
    insertWallet(SCHEMA, W_OTHER, NODE_OTHER, "pub-other");
    insertImplementer(SCHEMA, IMPL_REFUSE, "connector-refuse", null);

    const retired = await registry.setReserveWallets({
      nodeId: NODE,
      implementerId: IMPL_REFUSE,
      walletIds: [W_RETIRED],
      defaultWalletId: W_RETIRED,
      actorId: ACTOR,
    });
    expect(retired).toEqual({ ok: false, reason: "wallet_retired" });

    const other = await registry.setReserveWallets({
      nodeId: NODE,
      implementerId: IMPL_REFUSE,
      walletIds: [W_OTHER],
      defaultWalletId: W_OTHER,
      actorId: ACTOR,
    });
    expect(other).toEqual({ ok: false, reason: "wallet_not_found" });

    const junction = scalar(
      SCHEMA,
      `SELECT count(*) FROM implementer_reserve_wallets WHERE implementer_id = '${IMPL_REFUSE}'`,
    );
    const funding = scalar(
      SCHEMA,
      `SELECT funding_wallet_id IS NULL FROM implementers WHERE id = '${IMPL_REFUSE}'`,
    );
    const audits = scalar(
      SCHEMA,
      `SELECT count(*) FROM audit_log WHERE action = 'implementer.reserve_wallets_changed' AND node_id = '${NODE}' AND details_text LIKE '%${IMPL_REFUSE}%'`,
    );
    expect(junction).toBe("0");
    expect(funding).toBe("t");
    expect(audits).toBe("0");
  });

  it("setFundingWallet keeps the junction aligned with the funding pin", async () => {
    if (!ready) return;
    insertWallet(SCHEMA, W_FUNDING, NODE, "pub-funding");
    insertImplementer(SCHEMA, IMPL_FUNDING, "connector-funding", null);
    const attached = await registry.setFundingWallet({
      nodeId: NODE,
      implementerId: IMPL_FUNDING,
      mode: "WALLET_ID",
      walletId: W_FUNDING,
      actorId: ACTOR,
    });
    expect(attached.ok).toBe(true);
    if (!attached.ok) return;
    expect(attached.implementer.funding_wallet_id).toBe(W_FUNDING);
    expect(attached.implementer.reserve_wallets).toEqual([
      {
        wallet_id: W_FUNDING,
        public_key: "pub-funding",
        display_label: null,
        is_default: true,
      },
    ]);
    const cleared = await registry.setFundingWallet({
      nodeId: NODE,
      implementerId: IMPL_FUNDING,
      mode: "DEFAULT",
      actorId: ACTOR,
    });
    expect(cleared.ok).toBe(true);
    if (!cleared.ok) return;
    expect(cleared.implementer.funding_wallet_id).toBeNull();
    expect(cleared.implementer.reserve_wallets).toEqual([]);
    const junction = scalar(
      SCHEMA,
      `SELECT count(*) FROM implementer_reserve_wallets WHERE implementer_id = '${IMPL_FUNDING}'`,
    );
    expect(junction).toBe("0");
  });

  it("refuses a worker wallet and a wallet without a BLESSED destination", async () => {
    if (!ready) return;
    insertWallet(SCHEMA, W_RECEIVE, NODE, "pub-receive", "", {
      moneyMode: "RECEIVE_ONLY",
    });
    insertWallet(SCHEMA, W_SEND, NODE, "pub-send", "", { moneyMode: "SEND_ONLY" });
    insertWallet(SCHEMA, W_PENDING, NODE, "pub-pending", "", {
      moneyMode: "FULL",
      destinationState: "PENDING",
    });
    insertImplementer(SCHEMA, IMPL_INELIGIBLE, "connector-ineligible", null);

    const receiveOnly = await registry.setReserveWallets({
      nodeId: NODE,
      implementerId: IMPL_INELIGIBLE,
      walletIds: [W_RECEIVE],
      defaultWalletId: W_RECEIVE,
      actorId: ACTOR,
    });
    expect(receiveOnly).toEqual({ ok: false, reason: "wallet_ineligible" });

    const sendOnly = await registry.setReserveWallets({
      nodeId: NODE,
      implementerId: IMPL_INELIGIBLE,
      walletIds: [W_SEND],
      defaultWalletId: W_SEND,
      actorId: ACTOR,
    });
    expect(sendOnly).toEqual({ ok: false, reason: "wallet_ineligible" });

    const pending = await registry.setReserveWallets({
      nodeId: NODE,
      implementerId: IMPL_INELIGIBLE,
      walletIds: [W_PENDING],
      defaultWalletId: W_PENDING,
      actorId: ACTOR,
    });
    expect(pending).toEqual({ ok: false, reason: "wallet_ineligible" });

    const junction = scalar(
      SCHEMA,
      `SELECT count(*) FROM implementer_reserve_wallets WHERE implementer_id = '${IMPL_INELIGIBLE}'`,
    );
    expect(junction).toBe("0");
  });
});
