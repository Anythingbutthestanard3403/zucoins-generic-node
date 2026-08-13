// Real-PostgreSQL proof: money-capability lease claim matrix (ZTR-1268).
//
// Four presets × RECEIVE_WINDOW / SEND_SOURCE / MOVE_SOURCE / MOVE_DESTINATION.
// Schema path mirrors custody-claim-boundary: base + nodes + custody-eligibility
// + wallet-money-capability columns + lease-guard overlay (CREATE OR REPLACE).
import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  buildLeaseClaimInsertSql,
  type LeaseClaimInsertInput,
} from "../src/core/custody-claim.js";
import { registerPgRequiredGuard } from "./pg-required-guard.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const SQLSTATE_RAISE_EXCEPTION = "P0001";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

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

const schemaDdl = `${prerequisiteDdl}${readSchema("custody-eligibility.sql")}\n${readSchema("wallet-money-capability.sql")}\n${readSchema("wallet-money-capability-lease-guard.sql")}\n`;

const scratchDb = `wallet_money_gates_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;
let seq = 0;

const NODE_ID = "a0000000-0000-4000-8000-0000000000aa";

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

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1]!;
};

const mustReject = async (sql: string, literal: string): Promise<void> => {
  const outcome = await runPsql(sql);
  expect(outcome.ok, `expected reject ${literal}`).toBe(false);
  expect(extractSqlstate(outcome.stderr)).toBe(SQLSTATE_RAISE_EXCEPTION);
  expect(outcome.stderr).toContain(literal);
};

const nextFence = (walletId: string): Omit<LeaseClaimInsertInput, "leaseRole"> => {
  seq += 1;
  const base = 0x1000 + seq * 10;
  return {
    walletId,
    membershipId: uuid(base + 1),
    leaseGroupId: uuid(base + 2),
    rootOperationId: uuid(base + 3),
    operationId: uuid(base + 4),
    leaseEpoch: 1,
    ownerInstanceId: uuid(base + 5),
  };
};

const leaseInsertSql = (
  walletId: string,
  leaseRole: LeaseClaimInsertInput["leaseRole"],
): string => buildLeaseClaimInsertSql({ ...nextFence(walletId), leaseRole });

type Mode = "RECEIVE_ONLY" | "SEND_ONLY" | "INTERNAL_ONLY" | "FULL";

const MODE_FLAGS: Record<Mode, { recv: boolean; send: boolean; move: boolean }> = {
  RECEIVE_ONLY: { recv: true, send: false, move: true },
  SEND_ONLY: { recv: false, send: true, move: true },
  INTERNAL_ONLY: { recv: false, send: false, move: true },
  FULL: { recv: true, send: true, move: true },
};

const seedWallet = async (
  mode: Mode,
  opts: { blessed?: boolean } = {},
): Promise<string> => {
  seq += 1;
  const walletId = uuid(seq);
  const publicKey = pub(seq);
  const f = MODE_FLAGS[mode];
  // recovery_verified_at and recovery_verification_id must be set together
  // (wallets_recovery_fields_together); verification row must exist first for the FK.
  await must(
    `INSERT INTO wallets (
       id, node_id, public_key, key_origin, state,
       allow_external_receive, allow_external_send, allow_internal_move, money_mode
     ) VALUES (
       '${walletId}', '${NODE_ID}', '${publicKey}', 'node_generated', 'AVAILABLE',
       ${f.recv}, ${f.send}, ${f.move}, '${mode}'
     )`,
  );
  seq += 1;
  const verificationId = uuid(seq);
  const exportSha = `${"ab".repeat(30)}${String(seq).padStart(4, "0")}`;
  await must(
    `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `VALUES ('${verificationId}', '${walletId}', 'AUDITED_EXPORT', ` +
      `'${exportSha}', '${publicKey}', '${verificationId}', now(), 'money-cap-gates');`,
  );
  await must(
    `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${verificationId}' ` +
      `WHERE id = '${walletId}'`,
  );
  if (opts.blessed === true) {
    seq += 1;
    const destId = uuid(seq);
    seq += 1;
    const deviceKeyId = uuid(seq);
    seq += 1;
    const artifactId = uuid(seq);
    await must(
      `INSERT INTO destinations ` +
        `(id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
        `VALUES ('${destId}', '${NODE_ID}', '${walletId}', 'BLESSED', now(), ` +
        `'${deviceKeyId}', '${artifactId}')`,
    );
  }
  return walletId;
};

beforeAll(() => {
  if (!TEST_DATABASE_URL) return;
  adminPsql(TEST_DATABASE_URL, `CREATE DATABASE ${scratchDb}`);
  scratchDbUrl = withDatabase(TEST_DATABASE_URL, scratchDb);
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: schemaDdl,
    encoding: "utf-8",
    timeout: 60_000,
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
         ('${NODE_ID}', 'money-cap-gates', '${pub(0)}') ON CONFLICT (id) DO NOTHING;`,
    ],
    { encoding: "utf-8", timeout: 15_000 },
  );
  schemaReady = true;
}, 90_000);

afterAll(() => {
  if (!schemaReady) return;
  try {
    adminPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  } catch {
    /* best-effort */
  }
});

registerPgRequiredGuard({
  name: "wallet-money-capability-gates.pg",
  databaseUrl: TEST_DATABASE_URL,
  isReady: () => schemaReady,
});

describe("wallet money capability lease matrix PG (ZTR-1268)", () => {
  const modes = Object.keys(MODE_FLAGS) as Mode[];

  it("overlay function body carries capability exception codes", async () => {
    if (!schemaReady) return;
    const body = await must(
      `SELECT pg_get_functiondef('custody_reject_ineligible_lease'::regproc)`,
    );
    expect(body).toContain("CUSTODY_LEASE_RECEIVE_CAPABILITY_REJECTED");
    expect(body).toContain("CUSTODY_LEASE_SEND_CAPABILITY_REJECTED");
    expect(body).toContain("CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED");
  });

  describe("RECEIVE_WINDOW × presets", () => {
    for (const mode of modes) {
      const ok = MODE_FLAGS[mode].recv;
      it(`${mode}: RECEIVE_WINDOW ${ok ? "admits" : "rejects"}`, async () => {
        if (!schemaReady) return;
        const walletId = await seedWallet(mode);
        const sql = leaseInsertSql(walletId, "RECEIVE_WINDOW");
        if (ok) {
          await must(sql);
        } else {
          await mustReject(sql, "CUSTODY_LEASE_RECEIVE_CAPABILITY_REJECTED");
        }
      });
    }
  });

  describe("SEND_SOURCE × presets", () => {
    for (const mode of modes) {
      const ok = MODE_FLAGS[mode].send;
      it(`${mode}: SEND_SOURCE ${ok ? "admits" : "rejects"}`, async () => {
        if (!schemaReady) return;
        const walletId = await seedWallet(mode);
        const sql = leaseInsertSql(walletId, "SEND_SOURCE");
        if (ok) {
          await must(sql);
        } else {
          await mustReject(sql, "CUSTODY_LEASE_SEND_CAPABILITY_REJECTED");
        }
      });
    }
  });

  describe("MOVE_SOURCE × presets", () => {
    for (const mode of modes) {
      const ok = MODE_FLAGS[mode].move;
      it(`${mode}: MOVE_SOURCE ${ok ? "admits" : "rejects"}`, async () => {
        if (!schemaReady) return;
        const walletId = await seedWallet(mode);
        const sql = leaseInsertSql(walletId, "MOVE_SOURCE");
        if (ok) {
          await must(sql);
        } else {
          await mustReject(sql, "CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED");
        }
      });
    }
  });

  describe("MOVE_DESTINATION × presets (blessed sink)", () => {
    for (const mode of modes) {
      const ok = MODE_FLAGS[mode].move;
      it(`${mode}: MOVE_DESTINATION ${ok ? "admits" : "rejects"}`, async () => {
        if (!schemaReady) return;
        const walletId = await seedWallet(mode, { blessed: true });
        const sql = leaseInsertSql(walletId, "MOVE_DESTINATION");
        if (ok) {
          await must(sql);
        } else {
          await mustReject(sql, "CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED");
        }
      });
    }
  });

  it("receive-pool SELECT excludes allow_external_receive=false wallets", async () => {
    if (!schemaReady) return;
    const fullId = await seedWallet("FULL");
    const sendOnlyId = await seedWallet("SEND_ONLY");
    const rows = await must(
      `SELECT id::text FROM wallets w
        WHERE w.id IN ('${fullId}', '${sendOnlyId}')
          AND w.key_origin = 'node_generated'
          AND w.recovery_verified_at IS NOT NULL
          AND w.state = 'AVAILABLE'
          AND w.allow_external_receive IS TRUE
        ORDER BY id`,
    );
    expect(rows).toContain(fullId);
    expect(rows).not.toContain(sendOnlyId);
  });
});
