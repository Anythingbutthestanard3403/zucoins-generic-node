// Real-PostgreSQL drills for send assign + multi-hub top-up selection SQL (ZTR-1270).
//
// Proves against live PG:
// 1. Funded send-capable worker preferred over underfunded
// 2. INTERNAL_ONLY never selected as send worker
// 3. Multi-hub: second hub (id ASC) when first cannot cover shortfall
// 4. Busy hub / no funds → empty hub pick (deterministic)
// 5. Top-up readiness: park until MOVE INTERNAL_MOVE_LANDED; linkage queryable
// 6. SKIP LOCKED on worker select (frozen literal)
//
// Schema: base + nodes/wallets/destinations/leases + observation ledger +
// send_operations + operations (minimal) + wallet-money-capability columns.
import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  SELECT_BLESSED_DESTINATION_FOR_WALLET_SQL,
  SELECT_FUNDING_WALLET_FOR_TOPUP_SQL,
  SELECT_SEND_BY_TOPUP_MOVE_SQL,
  SELECT_SEND_TOPUP_READY_SQL,
  SELECT_SEND_WORKER_SQL,
  SELECT_TOPUP_HUB_SQL,
} from "../src/assign-and-topup.js";
import { registerPgRequiredGuard } from "./pg-required-guard.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

const scratchDb = `assign_topup_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;
let seq = 0;

const NODE_ID = "a0000000-0000-4000-8000-0000000000aa";
const IMPLEMENTER_ID = "b0000000-0000-4000-8000-0000000000bb";

const uuid = (n: number): string => {
  const hex = n.toString(16).padStart(12, "0");
  return `c0000000-0000-4000-8000-${hex}`;
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

// Minimal DDL: custody wallets + destinations + leases + observations + send_ops + operations.
const buildSchemaDdl = (): string => {
  const base = readSchema("base-enums-domains.sql");
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) throw new Error("nodes block missing");
  const implementers = /^CREATE TABLE implementers \([\s\S]*?^\);$/m.exec(registry);
  const custody = readSchema("custody-eligibility.sql");
  const cap = readSchema("wallet-money-capability.sql");
  // Observation ledger needs observer registry fragments — use a slim observations table
  // matching the columns selection SQL reads (wallet_id, b_amount, observed_at, wallet_seq).
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
  // send_operations minimal shape for unsettled index + references linkage.
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
  // operations for MOVE rows + top-up readiness join.
  const ops = `
CREATE TABLE IF NOT EXISTS operations (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  kind operation_kind NOT NULL,
  status operation_status NOT NULL,
  amount_zkz text,
  source_wallet_id uuid,
  destination_id uuid,
  receiver_wallet_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
`;
  return [
    base,
    nodes[0],
    implementers?.[0] ?? "",
    custody,
    cap,
    slimObs,
    sendOps,
    ops,
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
  opts: {
    blessed?: boolean;
    workerSink?: boolean;
    recoveryVerified?: boolean;
    balance?: string | null;
    nodeId?: string;
  } = {},
): Promise<{ walletId: string; destinationId: string | null }> => {
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
  if (opts.recoveryVerified !== false) {
    seq += 1;
    const verificationId = uuid(seq);
    const exportSha = `${"ab".repeat(30)}${String(seq).padStart(4, "0")}`;
    await must(
      `INSERT INTO wallet_recovery_verifications ` +
        `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
        `VALUES ('${verificationId}', '${walletId}', 'AUDITED_EXPORT', ` +
        `'${exportSha}', '${publicKey}', '${verificationId}', now(), 'assign-topup');`,
    );
    await must(
      `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${verificationId}' ` +
        `WHERE id = '${walletId}'`,
    );
  }

  if (opts.balance !== undefined && opts.balance !== null) {
    seq += 1;
    const obsId = uuid(seq);
    await must(
      `INSERT INTO gateway_observations (id, wallet_id, wallet_public_key, wallet_seq, b_amount)
       VALUES ('${obsId}', '${walletId}', '${publicKey}', 1, '${opts.balance}')`,
    );
  }

  let destinationId: string | null = null;
  if (opts.workerSink === true) {
    seq += 1;
    destinationId = uuid(seq);
    await must(
      `INSERT INTO destinations (id, node_id, wallet_id, label, state, created_at) ` +
        `VALUES ('${destinationId}', '${nodeId}', '${walletId}', ` +
        `'send-worker-${walletId.slice(0, 8)}', 'WORKER', now())`,
    );
  } else if (opts.blessed === true) {
    seq += 1;
    destinationId = uuid(seq);
    seq += 1;
    const deviceKeyId = uuid(seq);
    seq += 1;
    const artifactId = uuid(seq);
    await must(
      `INSERT INTO destinations ` +
        `(id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
        `VALUES ('${destinationId}', '${nodeId}', '${walletId}', 'BLESSED', now(), ` +
        `'${deviceKeyId}', '${artifactId}')`,
    );
  }
  return { walletId, destinationId };
};

/** Mark hub busy without full lease ceremony — AVAILABLE is an eligibility conjunct. */
const pinBusy = async (walletId: string): Promise<void> => {
  await must(`UPDATE wallets SET state = 'PINNED' WHERE id = '${walletId}'`);
};

registerPgRequiredGuard({
  name: "assign-and-topup.pg",
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
  // Own committed TXs: ADD VALUE cannot be used until the adding transaction commits.
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: readSchema("destination-state-worker.sql"),
    encoding: "utf-8",
    timeout: 15_000,
  });
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: readSchema("destination-worker-sink.sql"),
    encoding: "utf-8",
    timeout: 15_000,
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
         ('${NODE_ID}', 'assign-topup', '${pub(0)}') ON CONFLICT (id) DO NOTHING;
       INSERT INTO implementers (id, name)
         VALUES ('${IMPLEMENTER_ID}', 'assign-topup-impl')
         ON CONFLICT (id) DO NOTHING;`,
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

describe.skipIf(!TEST_DATABASE_URL)("send assign + multi-hub top-up (real PG)", () => {
  it("frozen worker SQL carries SKIP LOCKED + allow_external_send", () => {
    expect(SELECT_SEND_WORKER_SQL).toContain("FOR UPDATE OF w SKIP LOCKED");
    expect(SELECT_SEND_WORKER_SQL).toContain("allow_external_send IS TRUE");
    expect(SELECT_SEND_WORKER_SQL).not.toContain("recovery_verified_at");
  });

  it("recovery-unverified SEND_ONLY + WORKER sink is still selected", async () => {
    const nodeC = "a0000000-0000-4000-8000-0000000000c1";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${nodeC}', 'worker-sink', '${pub(91)}') ON CONFLICT (id) DO NOTHING`,
    );
    const unverified = await seedWallet("SEND_ONLY", {
      workerSink: true,
      recoveryVerified: false,
      balance: "10",
      nodeId: nodeC,
    });
    const dest = await must(
      SELECT_BLESSED_DESTINATION_FOR_WALLET_SQL.replace(
        /\$1::uuid/g,
        `'${unverified.walletId}'::uuid`,
      ),
    );
    expect(dest).toContain(unverified.destinationId);
    const picked = await must(
      `BEGIN;
       ${SELECT_SEND_WORKER_SQL.replace(/\$1::uuid/g, `'${nodeC}'::uuid`).replace(/\$2::numeric/g, `2::numeric`).replace(/\$2/g, `'2'`)};
       ROLLBACK;`,
    );
    expect(picked).toContain(unverified.walletId);
  });

  it("funded send-capable worker preferred; skips MOVE need", async () => {
    const funded = await seedWallet("SEND_ONLY", { blessed: true, balance: "10" });
    const empty = await seedWallet("SEND_ONLY", { blessed: true, balance: null });
    // Prefer funded when amount=2
    const picked = await must(
      `BEGIN;
       ${SELECT_SEND_WORKER_SQL.replace(/\$1::uuid/g, `'${NODE_ID}'::uuid`).replace(/\$2::numeric/g, `2::numeric`).replace(/\$2/g, `'2'`)};
       ROLLBACK;`,
    );
    // psql -qAt may return just wallet_id|balance
    expect(picked).toContain(funded.walletId);
    expect(picked).not.toContain(empty.walletId);
  });

  it("INTERNAL_ONLY never selected as send worker (PG negative)", async () => {
    const hub = await seedWallet("INTERNAL_ONLY", { balance: "100" });
    // Only hub exists — worker select must return empty
    const out = await must(
      `BEGIN;
       SELECT coalesce(
         (SELECT wallet_id FROM (${SELECT_SEND_WORKER_SQL}) q),
         'NONE'
       );
       ROLLBACK;`.replace(/\$1::uuid/g, `'${NODE_ID}'::uuid`).replace(/\$2::numeric/g, `1::numeric`).replace(/\$2/g, `'1'`),
    );
    // May still pick prior SEND_ONLY wallets from earlier tests — assert hub id never chosen
    expect(out).not.toContain(hub.walletId);
  });

  it("multi-hub: second hub by id ASC when first lacks coverage", async () => {
    const nodeB = "a0000000-0000-4000-8000-0000000000b1";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${nodeB}', 'multi-hub', '${pub(90)}') ON CONFLICT (id) DO NOTHING`,
    );
    const amount = "50";
    const hubLow = await seedWallet("INTERNAL_ONLY", { balance: "5", nodeId: nodeB });
    const hubHigh = await seedWallet("INTERNAL_ONLY", { balance: "100", nodeId: nodeB });
    const sql = SELECT_TOPUP_HUB_SQL.replace(/\$1::uuid/g, `'${nodeB}'::uuid`)
      .replace(/\$2::numeric/g, `${amount}::numeric`)
      .replace(/\$2/g, `'${amount}'`);
    const picked = await must(`BEGIN; ${sql}; ROLLBACK;`);
    expect(picked).toContain(hubHigh.walletId);
    expect(picked).not.toContain(hubLow.walletId);

    seq += 1;
    const obsId = uuid(seq);
    await must(
      `INSERT INTO gateway_observations (id, wallet_id, wallet_public_key, wallet_seq, b_amount)
       SELECT '${obsId}', '${hubLow.walletId}', public_key, 2, '100'
         FROM wallets WHERE id = '${hubLow.walletId}'`,
    );
    const picked2 = await must(`BEGIN; ${sql}; ROLLBACK;`);
    expect(picked2).toContain(hubLow.walletId);
  });

  it("busy hub skipped via active lease; no silent wrong wallet", async () => {
    const nodeC = "a0000000-0000-4000-8000-0000000000c1";
    await must(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${nodeC}', 'busy-hub', '${pub(91)}') ON CONFLICT (id) DO NOTHING`,
    );
    const hubA = await seedWallet("INTERNAL_ONLY", { balance: "20", nodeId: nodeC });
    const hubB = await seedWallet("INTERNAL_ONLY", { balance: "20", nodeId: nodeC });
    await pinBusy(hubA.walletId);
    const sql = SELECT_TOPUP_HUB_SQL.replace(/\$1::uuid/g, `'${nodeC}'::uuid`)
      .replace(/\$2::numeric/g, `10::numeric`)
      .replace(/\$2/g, `'10'`);
    const picked = await must(`BEGIN; ${sql}; ROLLBACK;`);
    expect(picked).not.toContain(hubA.walletId);
    expect(picked).toContain(hubB.walletId);
  });

  it("no hub liquidity → empty pick", async () => {
    const sql = SELECT_TOPUP_HUB_SQL.replace(/\$1::uuid/g, `'${NODE_ID}'::uuid`)
      .replace(/\$2::numeric/g, `99999999::numeric`)
      .replace(/\$2/g, `'99999999'`);
    const picked = await must(
      `BEGIN; SELECT coalesce((SELECT wallet_id FROM (${sql}) q), 'NONE'); ROLLBACK;`,
    );
    expect(picked).toContain("NONE");
  });

  it("ZTR-1289: funding wallet lock returns observed balance + flags", async () => {
    const w = await seedWallet("INTERNAL_ONLY", { balance: "42" });
    const sql = SELECT_FUNDING_WALLET_FOR_TOPUP_SQL.replace(
      /\$1::uuid/g,
      `'${w.walletId}'::uuid`,
    ).replace(/\$2::uuid/g, `'${NODE_ID}'::uuid`);
    const row = await must(`BEGIN; ${sql}; ROLLBACK;`);
    expect(row).toContain(w.walletId);
    expect(row).toContain("42");
  });

  it("ZTR-1289: dry/unobserved funding wallet still locks (caller fails closed)", async () => {
    const w = await seedWallet("INTERNAL_ONLY", { balance: null });
    const sql = SELECT_FUNDING_WALLET_FOR_TOPUP_SQL.replace(
      /\$1::uuid/g,
      `'${w.walletId}'::uuid`,
    ).replace(/\$2::uuid/g, `'${NODE_ID}'::uuid`);
    // Row returns; observed_balance_zkz is empty — evaluateFundingWalletForTopUp fails closed.
    const row = await must(
      `BEGIN; SELECT wallet_id, coalesce(observed_balance_zkz, 'NULL') FROM (${sql}) q; ROLLBACK;`,
    );
    expect(row).toContain(w.walletId);
    expect(row).toContain("NULL");
  });

  it("blessed destination lookup for worker", async () => {
    const w = await seedWallet("SEND_ONLY", { blessed: true, balance: "0" });
    const sql = SELECT_BLESSED_DESTINATION_FOR_WALLET_SQL.replace(
      /\$1::uuid/g,
      `'${w.walletId}'::uuid`,
    );
    const dest = await must(sql);
    expect(dest).toBe(w.destinationId);
  });

  it("top-up readiness + durable linkage queryable", async () => {
    const worker = await seedWallet("SEND_ONLY", { blessed: true, balance: "0" });
    seq += 1;
    const moveId = uuid(seq);
    seq += 1;
    const sendId = uuid(seq);

    await must(
      `INSERT INTO operations (id, node_id, implementer_id, kind, status, amount_zkz, source_wallet_id)
       VALUES ('${moveId}', '${NODE_ID}', '${IMPLEMENTER_ID}',
               'MOVE_INTERNAL', 'CREATED', '2', NULL)`,
    );
    await must(
      `INSERT INTO send_operations (
         operation_id, implementer_id, node_id, status, formation_state,
         idempotency_key, source_wallet_id, amount_zkz, references_operation_id
       ) VALUES (
         '${sendId}', '${IMPLEMENTER_ID}', '${NODE_ID}', 'CREATED', 'APPROVAL_PENDING',
         'idem-topup-link-0001', '${worker.walletId}', '2', '${moveId}'
       )`,
    );

    // Not ready while MOVE CREATED
    const notReady = await must(
      SELECT_SEND_TOPUP_READY_SQL.replace(/\$1::uuid/g, `'${sendId}'::uuid`),
    );
    expect(notReady).toBe("");

    await must(
      `UPDATE operations SET status = 'INTERNAL_MOVE_LANDED' WHERE id = '${moveId}'`,
    );
    const ready = await must(
      SELECT_SEND_TOPUP_READY_SQL.replace(/\$1::uuid/g, `'${sendId}'::uuid`),
    );
    expect(ready).toContain(sendId);

    const link = await must(
      SELECT_SEND_BY_TOPUP_MOVE_SQL.replace(/\$1::uuid/g, `'${moveId}'::uuid`),
    );
    expect(link).toContain(sendId);
    expect(link).toContain(moveId);
    expect(link).toContain(worker.walletId);
  });

  it("funded path has no references_operation_id requirement", async () => {
    const worker = await seedWallet("SEND_ONLY", { balance: "5" });
    seq += 1;
    const sendId = uuid(seq);
    await must(
      `INSERT INTO send_operations (
         operation_id, implementer_id, node_id, status, formation_state,
         idempotency_key, source_wallet_id, amount_zkz, references_operation_id
       ) VALUES (
         '${sendId}', '${IMPLEMENTER_ID}', '${NODE_ID}', 'CREATED', 'APPROVAL_PENDING',
         'idem-funded-path-0001', '${worker.walletId}', '2', NULL
       )`,
    );
    const ready = await must(
      SELECT_SEND_TOPUP_READY_SQL.replace(/\$1::uuid/g, `'${sendId}'::uuid`),
    );
    expect(ready).toContain(sendId);
  });
});
