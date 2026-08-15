// ZTR-1273 — real-PostgreSQL acceptance drills for the epic scenario matrix.
// Complements money-capability-acceptance.matrix.test.ts (composition) and
// assign-and-topup.pg.test.ts / wallet-money-capability-gates.pg.test.ts.
//
// Proves load-bearing SQL cells against live PG:
//   S1 selection path (empty worker + funded hub)
//   S2 funded worker preference
//   S3 INTERNAL_ONLY never worker
//   S4 RECEIVE_ONLY never worker
//   S5 no hub liquidity
//   S6 second hub covers
//   S9 SEND_ONLY excluded from receive pool
//   S10 INTERNAL_ONLY admits MOVE_SOURCE + MOVE_DESTINATION leases

import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  SELECT_SEND_WORKER_SQL,
  SELECT_TOPUP_HUB_SQL,
} from "../src/assign-and-topup.js";
import { registerPgRequiredGuard } from "./pg-required-guard.js";
import { verificationModeFixtureSql } from "./verification-mode-fixture.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

const scratchDb = `money_accept_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;
let seq = 0;

const NODE_ID = "a0000000-0000-4000-8000-0000000000aa";

const uuid = (n: number): string => {
  const hex = n.toString(16).padStart(12, "0");
  return `d0000000-0000-4000-8000-${hex}`;
};

const pub = (n: number): string => {
  const ch = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"[n % 64]!;
  return `${ch.repeat(43)}=`;
};

const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

const adminPsql = (url: string, sql: string): void => {
  execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
    encoding: "utf-8",
    timeout: 60_000,
  });
};

const runPsql = (sql: string, timeoutMs = 20_000): Promise<PsqlOutcome> =>
  new Promise((resolve) => {
    execFile(
      "psql",
      [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: timeoutMs },
      (err, stdout, stderr) => {
        resolve({ ok: !err, stdout: stdout ?? "", stderr: stderr ?? (err ? String(err) : "") });
      },
    );
  });

const must = async (sql: string): Promise<string> => {
  const outcome = await runPsql(sql);
  if (!outcome.ok) {
    throw new Error(`psql failed:\n${outcome.stderr}\n${outcome.stdout}`);
  }
  return outcome.stdout.trim();
};

const bindWorkerSql = (nodeId: string, amount: string): string =>
  SELECT_SEND_WORKER_SQL.replace(/\$1::uuid/g, `'${nodeId}'::uuid`)
    .replace(/\$2::numeric/g, `${amount}::numeric`)
    .replace(/\$2/g, `'${amount}'`);

const bindHubSql = (nodeId: string, amount: string): string =>
  SELECT_TOPUP_HUB_SQL.replace(/\$1::uuid/g, `'${nodeId}'::uuid`)
    .replace(/\$2::numeric/g, `${amount}::numeric`)
    .replace(/\$2/g, `'${amount}'`);

const buildSchemaDdl = (): string => {
  const base = readSchema("base-enums-domains.sql");
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) throw new Error("nodes block missing");
  const implementers = /^CREATE TABLE implementers \([\s\S]*?^\);$/m.exec(registry);
  const custody = readSchema("custody-eligibility.sql");
  const cap = readSchema("wallet-money-capability.sql");
  const slimObs = `
CREATE TABLE IF NOT EXISTS gateway_observations (
  id uuid PRIMARY KEY,
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key text NOT NULL,
  wallet_seq bigint NOT NULL CHECK (wallet_seq > 0),
  observed_at timestamptz NOT NULL DEFAULT now(),
  b_amount text
);
CREATE INDEX IF NOT EXISTS gateway_observations_wallet_id_idx
  ON gateway_observations (wallet_id);
`;
  const sendOps = `
CREATE TABLE send_operations (
  operation_id uuid PRIMARY KEY,
  implementer_id uuid NOT NULL,
  node_id uuid NOT NULL,
  kind text NOT NULL DEFAULT 'SEND_EXTERNAL',
  status text NOT NULL,
  row_version integer NOT NULL DEFAULT 1,
  attention_required boolean NOT NULL DEFAULT false,
  formation_state text NOT NULL DEFAULT 'APPROVAL_PENDING',
  http_method text NOT NULL DEFAULT 'POST',
  route text NOT NULL DEFAULT '/v1/external-sends',
  idempotency_key text NOT NULL,
  request_sha256 text NOT NULL DEFAULT '',
  source_wallet_id uuid NOT NULL REFERENCES wallets(id),
  destination_address text NOT NULL DEFAULT '',
  amount_zkz text NOT NULL DEFAULT '1',
  references_operation_id uuid,
  client_reference text,
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  response_status integer,
  response_body text
);
CREATE UNIQUE INDEX send_operations_one_unsettled_per_source_wallet
  ON send_operations (source_wallet_id)
  WHERE status NOT IN ('EXTERNAL_SEND_LANDED', 'REJECTED');
`;
  return [
    base,
    nodes[0],
    implementers?.[0] ?? "",
    custody,
    cap,
    slimObs,
    sendOps,
    verificationModeFixtureSql(),
  ].join("\n");
};

type Mode = "RECEIVE_ONLY" | "SEND_ONLY" | "INTERNAL_ONLY" | "FULL";

const MODE_FLAGS: Record<Mode, { recv: boolean; send: boolean; move: boolean }> = {
  RECEIVE_ONLY: { recv: true, send: false, move: true },
  SEND_ONLY: { recv: false, send: true, move: true },
  INTERNAL_ONLY: { recv: false, send: false, move: true },
  FULL: { recv: true, send: true, move: true },
};

const seedWallet = async (
  mode: Mode,
  opts: { balance?: string | null; nodeId?: string } = {},
): Promise<string> => {
  seq += 1;
  const walletId = uuid(seq);
  const publicKey = pub(seq);
  const f = MODE_FLAGS[mode];
  const nodeId = opts.nodeId ?? NODE_ID;
  await must(
    `INSERT INTO wallets (
       id, node_id, public_key, key_origin, state,
       allow_external_receive, allow_external_send, allow_internal_move, money_mode
     ) VALUES (
       '${walletId}', '${nodeId}', '${publicKey}', 'node_generated', 'AVAILABLE',
       ${f.recv}, ${f.send}, ${f.move}, '${mode}'
     )`,
  );
  seq += 1;
  const verificationId = uuid(seq);
  const exportSha = `${"cd".repeat(30)}${String(seq).padStart(4, "0")}`;
  await must(
    `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `VALUES ('${verificationId}', '${walletId}', 'AUDITED_EXPORT', ` +
      `'${exportSha}', '${publicKey}', '${verificationId}', now(), 'money-accept');`,
  );
  await must(
    `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${verificationId}' ` +
      `WHERE id = '${walletId}'`,
  );
  if (opts.balance !== undefined && opts.balance !== null) {
    seq += 1;
    const obsId = uuid(seq);
    await must(
      `INSERT INTO gateway_observations (id, wallet_id, wallet_public_key, wallet_seq, b_amount)
       VALUES ('${obsId}', '${walletId}', '${publicKey}', 1, '${opts.balance}')`,
    );
  }
  return walletId;
};

registerPgRequiredGuard({
  name: "money-capability-acceptance.pg",
  databaseUrl: TEST_DATABASE_URL,
  isReady: () => schemaReady,
});

beforeAll(() => {
  if (!TEST_DATABASE_URL) return;
  adminPsql(TEST_DATABASE_URL, `CREATE DATABASE ${scratchDb}`);
  scratchDbUrl = withDatabase(TEST_DATABASE_URL, scratchDb);
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: buildSchemaDdl(),
    encoding: "utf-8",
    timeout: 90_000,
  });
  execFileSync(
    "psql",
    [
      scratchDbUrl,
      "-v",
      "ON_ERROR_STOP=1",
      "-qAt",
      "-c",
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${NODE_ID}', 'money-accept', '${pub(0)}') ON CONFLICT (id) DO NOTHING;`,
    ],
    { encoding: "utf-8", timeout: 15_000 },
  );
  schemaReady = true;
});

afterAll(() => {
  if (!TEST_DATABASE_URL || !scratchDbUrl) return;
  try {
    adminPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  } catch {
    /* best-effort */
  }
});

describe.skipIf(!TEST_DATABASE_URL)("ZTR-1273 money-capability acceptance (real PG)", () => {
  it("S1 selection: empty SEND_ONLY worker + funded INTERNAL_ONLY hub both visible to frozen SQL", async () => {
    const node = "a0000000-0000-4000-8000-0000000000b1";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${node}', 's1', '${pub(11)}') ON CONFLICT (id) DO NOTHING`,
    );
    const worker = await seedWallet("SEND_ONLY", { balance: null, nodeId: node });
    const hub = await seedWallet("INTERNAL_ONLY", { balance: "100", nodeId: node });

    const workerPick = await must(`BEGIN; ${bindWorkerSql(node, "10")}; ROLLBACK;`);
    expect(workerPick).toContain(worker);
    expect(workerPick).not.toContain(hub);

    const hubPick = await must(`BEGIN; ${bindHubSql(node, "10")}; ROLLBACK;`);
    expect(hubPick).toContain(hub);
    expect(hubPick).not.toContain(worker);
  });

  it("S2: funded SEND_ONLY preferred; hub never selected as worker", async () => {
    const node = "a0000000-0000-4000-8000-0000000000b2";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${node}', 's2', '${pub(12)}') ON CONFLICT (id) DO NOTHING`,
    );
    const funded = await seedWallet("SEND_ONLY", { balance: "50", nodeId: node });
    const empty = await seedWallet("SEND_ONLY", { balance: null, nodeId: node });
    const hub = await seedWallet("INTERNAL_ONLY", { balance: "100", nodeId: node });
    const picked = await must(`BEGIN; ${bindWorkerSql(node, "10")}; ROLLBACK;`);
    expect(picked).toContain(funded);
    expect(picked).not.toContain(empty);
    expect(picked).not.toContain(hub);
  });

  it("S3: only INTERNAL_ONLY → worker select empty", async () => {
    const node = "a0000000-0000-4000-8000-0000000000b3";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${node}', 's3', '${pub(13)}') ON CONFLICT (id) DO NOTHING`,
    );
    const hub = await seedWallet("INTERNAL_ONLY", { balance: "100", nodeId: node });
    const out = await must(
      `BEGIN; SELECT coalesce((SELECT wallet_id FROM (${bindWorkerSql(node, "1")}) q), 'NONE'); ROLLBACK;`,
    );
    expect(out).toContain("NONE");
    expect(out).not.toContain(hub);
  });

  it("S4: only RECEIVE_ONLY → worker select empty", async () => {
    const node = "a0000000-0000-4000-8000-0000000000b4";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${node}', 's4', '${pub(14)}') ON CONFLICT (id) DO NOTHING`,
    );
    const recv = await seedWallet("RECEIVE_ONLY", { balance: "100", nodeId: node });
    const out = await must(
      `BEGIN; SELECT coalesce((SELECT wallet_id FROM (${bindWorkerSql(node, "1")}) q), 'NONE'); ROLLBACK;`,
    );
    expect(out).toContain("NONE");
    expect(out).not.toContain(recv);
  });

  it("S5: underfunded worker + empty hubs → hub select empty", async () => {
    const node = "a0000000-0000-4000-8000-0000000000b5";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${node}', 's5', '${pub(15)}') ON CONFLICT (id) DO NOTHING`,
    );
    await seedWallet("SEND_ONLY", { balance: "1", nodeId: node });
    await seedWallet("INTERNAL_ONLY", { balance: null, nodeId: node });
    const out = await must(
      `BEGIN; SELECT coalesce((SELECT wallet_id FROM (${bindHubSql(node, "10")}) q), 'NONE'); ROLLBACK;`,
    );
    expect(out).toContain("NONE");
  });

  it("S6: two hubs; only second covers shortfall", async () => {
    const node = "a0000000-0000-4000-8000-0000000000b6";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${node}', 's6', '${pub(16)}') ON CONFLICT (id) DO NOTHING`,
    );
    const low = await seedWallet("INTERNAL_ONLY", { balance: "5", nodeId: node });
    const high = await seedWallet("INTERNAL_ONLY", { balance: "100", nodeId: node });
    const picked = await must(`BEGIN; ${bindHubSql(node, "50")}; ROLLBACK;`);
    expect(picked).toContain(high);
    expect(picked).not.toContain(low);
  });

  it("S9: SEND_ONLY excluded from receive-pool capability filter", async () => {
    const node = "a0000000-0000-4000-8000-0000000000b9";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${node}', 's9', '${pub(19)}') ON CONFLICT (id) DO NOTHING`,
    );
    const sendOnly = await seedWallet("SEND_ONLY", { nodeId: node });
    const recvOnly = await seedWallet("RECEIVE_ONLY", { nodeId: node });
    const rows = await must(
      `SELECT id::text FROM wallets w
        WHERE w.node_id = '${node}'
          AND w.allow_external_receive IS TRUE
        ORDER BY id`,
    );
    expect(rows).toContain(recvOnly);
    expect(rows).not.toContain(sendOnly);
  });

  it("S10: INTERNAL_ONLY admits both MOVE parties at capability flags", async () => {
    const node = "a0000000-0000-4000-8000-0000000000ba";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${node}', 's10', '${pub(20)}') ON CONFLICT (id) DO NOTHING`,
    );
    const a = await seedWallet("INTERNAL_ONLY", { nodeId: node });
    const b = await seedWallet("INTERNAL_ONLY", { nodeId: node });
    const rows = await must(
      `SELECT id::text FROM wallets w
        WHERE w.id IN ('${a}', '${b}')
          AND w.allow_internal_move IS TRUE
          AND w.allow_external_send IS FALSE
          AND w.money_mode = 'INTERNAL_ONLY'
        ORDER BY id`,
    );
    expect(rows).toContain(a);
    expect(rows).toContain(b);
  });
});
