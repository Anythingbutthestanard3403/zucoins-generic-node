// Follow-up — real multi-process DB lock-contention proofs.
//
// Governing:
//     ("Run real database concurrency tests, not only mocked unit tests";
//      "Exactly one contender may reach signing")
//     (signer lease capability; source/destination move lease races cannot deadlock
//      or partially acquire)
//     (second active lease fails including cross-operation-kind races;
//      two-wallet acquisition is all-or-nothing and sorted)
//   packages/node-core/src/schema/custody-eligibility.contract.ts
//     (wallet_active_leases PK invariant)
//
// Gap closed by this suite (relative to pg-concurrency.test.ts and the
// in-memory lifecycle fuzzer):
//   - True multi-process contenders (separate `psql` OS processes) racing long
//     multi-statement transactions with deliberate mid-tx sleeps so lock order
//     interleaves — not merely concurrent single-statement INSERT races.
//   - Cross-kind same-source race (MOVE_SOURCE vs SEND_SOURCE) under that model.
//   - Two-wallet MOVE pair: sorted acquisition is deadlock-free and all-or-nothing;
//     a mid-pair failure rolls back to zero partial holds.
//   - Adversarial destination-only locking shown insufficient (source remains free).
//   - End-to-end "exactly one reaches signing": lease acquire + formation_state CAS.
//
// Schema under test for leases is the REAL frozen DDL (custody-eligibility.sql)
// loaded via the tokenizer — no hand-rolled mirror. The `operations` table used
// only for the signing-CAS drill is the same documented self-owned minimal surface
// as pg-concurrency.test.ts (no frozen operations.sql yet).
//
// Connectivity: TEST_DATABASE_URL is auto-provisioned by vitest.global-setup.ts
// when run through the ROOT vitest project. Direct
// `vitest run --root packages/node-core` bypasses global-setup and skips.

import { execFile, execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { tokenizeCustodySql } from "./custody-eligibility-sql-statements.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

/* ─── psql helpers ────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
  /** Wall-clock ms for the child process — used to bound deadlock waits. */
  readonly elapsedMs: number;
}

// VERBOSITY=verbose is unconditional so SQLSTATE appears in stderr as
// `ERROR:  <sqlstate>:` (default verbosity omits the code).
const runPsql = (url: string, sql: string, timeoutMs = 20_000): Promise<PsqlOutcome> =>
  new Promise((resolve) => {
    const started = Date.now();
    execFile(
      "psql",
      [url, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: timeoutMs },
      (err, stdout, stderr) => {
        resolve({
          ok: !err,
          stdout: stdout ?? "",
          stderr: stderr ?? (err ? String(err) : ""),
          elapsedMs: Date.now() - started,
        });
      },
    );
  });

const psqlMust = async (url: string, sql: string): Promise<string> => {
  const outcome = await runPsql(url, sql);
  if (!outcome.ok) {
    throw new Error(`psql failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_DEADLOCK = "40P01";

/* ─── operations DDL — self-owned; no frozen schema file yet ─── */

const OPERATIONS_DDL = `
CREATE TABLE operations (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  kind text NOT NULL,
  status text NOT NULL DEFAULT 'CREATED',
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  source_wallet_id uuid REFERENCES wallets(id),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 255),
  request_sha256 text NOT NULL,
  formation_state text NOT NULL DEFAULT 'NOT_REQUIRED',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (implementer_id, kind, idempotency_key)
);
`;

/* ─── load real DDL via the tokenizer (no hand-rolled mirror) ─────── */

// custody-eligibility.sql is prerequisite-bound (base enums/domains + nodes).
const prerequisiteDdl = ((): string => {
  const base = readFileSync(
    new URL("../src/schema/base-enums-domains.sql", import.meta.url),
    "utf-8",
  );
  const registry = readFileSync(
    new URL("../src/schema/node-implementer-registry.sql", import.meta.url),
    "utf-8",
  );
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  return `${base}\n${nodes[0]}\n`;
})();

const custodyDdlSource = readFileSync(
  new URL("../src/schema/custody-eligibility.sql", import.meta.url),
  "utf-8",
);
const custodyDdl = tokenizeCustodySql(custodyDdlSource)
  .map((statement) => statement.raw)
  .join("\n");

/* ─── lifecycle ───────────────────────────────────────────────────── */

const scratchDb = `wallet_lease_lock_lockcontention_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;
/** Counts real multi-process drills that ran assertions (fail-closed guard). */
let drillsRun = 0;
const EXPECTED_DRILL_COUNT = 6;

beforeAll(async () => {
  if (!TEST_DATABASE_URL) return;
  await psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${scratchDb}`);
  scratchDbUrl = withDatabase(TEST_DATABASE_URL, scratchDb);
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: `${prerequisiteDdl}${custodyDdl}`,
    encoding: "utf-8",
    timeout: 30_000,
  });
  await psqlMust(scratchDbUrl, OPERATIONS_DDL);
  schemaReady = true;
}, 30_000);

afterAll(async () => {
  if (!schemaReady) return;
  await runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
});

/* ─── fixtures ────────────────────────────────────────────────────── */

const NODE_ID = "b0000000-0000-4000-8000-000000000002";
const IMPLEMENTER_ID = "c0000000-0000-4000-8000-000000000003";
const FAKE_SHA = "a".repeat(64);

// wallet_id order matters: LO < HI so sorted acquisition is unambiguous.
const WALLET_LO = "a0000000-0000-4000-8000-000000000010";
const WALLET_HI = "a0000000-0000-4000-8000-000000000020";
const WALLET_SOLO = "a0000000-0000-4000-8000-000000000030";
const WALLET_DEST = "a0000000-0000-4000-8000-000000000040";

// public_key carries padded_base64url_pubkey again — seeds must be 44-char padded base64url.
const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const seedNode = (): string =>
  `INSERT INTO nodes (id, display_name, identity_public_key) ` +
  `VALUES ('${NODE_ID}', 'wallet-lease-lock-lockcontention', '${pubkey("NODE")}') ON CONFLICT (id) DO NOTHING;`;

const seedWallet = (walletId: string, publicKey: string): string =>
  `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
  `VALUES ('${walletId}', '${NODE_ID}', '${publicKey}', 'node_generated', 'AVAILABLE') ` +
  `ON CONFLICT (id) DO NOTHING;`;

/** Fencing columns are NOT NULL — each insert carries unique identifiers so the wallet_id PK remains the sole rejector of a duplicate lease. */
const leaseInsert = (walletId: string, role: string, extra = ""): string =>
  `INSERT INTO wallet_active_leases (wallet_id, membership_id, lease_group_id, ` +
  `root_operation_id, operation_id, lease_role, lease_epoch, acquired_at, heartbeat_at, ` +
  `owner_instance_id) VALUES ('${walletId}', '${randomUUID()}', '${randomUUID()}', ` +
  `'${randomUUID()}', '${randomUUID()}', '${role}', 1, now(), now(), '${randomUUID()}')${extra}`;

/** Bless + recovery-verify a wallet so MOVE_DESTINATION passes the eligibility trigger. */
const seedBlessedDestination = (walletId: string, publicKey: string): string => {
  const recoveryId = randomUUID();
  const destinationId = randomUUID();
  const deviceKeyId = randomUUID();
  const artifactId = randomUUID();
  const auditEventId = randomUUID();
  return [
    seedWallet(walletId, publicKey),
    `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${FAKE_SHA}', '${publicKey}', ` +
      `'${auditEventId}', now(), 'wallet-lease-lock-test');`,
    `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
      `WHERE id = '${walletId}';`,
    `INSERT INTO destinations ` +
      `(id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
      `VALUES ('${destinationId}', '${NODE_ID}', '${walletId}', 'BLESSED', now(), '${deviceKeyId}', '${artifactId}');`,
  ].join(" ");
};

const clearLeases = (...walletIds: string[]): string =>
  `DELETE FROM wallet_active_leases WHERE wallet_id IN (${walletIds
    .map((id) => `'${id}'`)
    .join(", ")});`;

const countLeases = async (...walletIds: string[]): Promise<number> => {
  const out = await psqlMust(
    scratchDbUrl,
    `SELECT count(*)::int FROM wallet_active_leases WHERE wallet_id IN (${walletIds
      .map((id) => `'${id}'`)
      .join(", ")});`,
  );
  return Number(out.trim());
};

const leaseRows = async (
  ...walletIds: string[]
): Promise<ReadonlyArray<{ wallet_id: string; lease_role: string }>> => {
  const out = await psqlMust(
    scratchDbUrl,
    `SELECT coalesce(json_agg(row_to_json(t) ORDER BY wallet_id), '[]'::json) FROM (` +
      `SELECT wallet_id::text, lease_role FROM wallet_active_leases ` +
      `WHERE wallet_id IN (${walletIds.map((id) => `'${id}'`).join(", ")})` +
      `) t;`,
  );
  return JSON.parse(out.trim() || "[]") as Array<{ wallet_id: string; lease_role: string }>;
};

/* ─── suite ───────────────────────────────────────────────────────── */

describe.skipIf(!TEST_DATABASE_URL)(
  "multi-process wallet_active_leases lock contention",
  { timeout: 90_000 },
  () => {
    beforeAll(async () => {
      await psqlMust(
        scratchDbUrl,
        [
          seedNode(),
          seedWallet(WALLET_LO, pubkey("LO")),
          seedWallet(WALLET_HI, pubkey("HI")),
          seedWallet(WALLET_SOLO, pubkey("SOLO")),
          seedBlessedDestination(WALLET_DEST, pubkey("DEST")),
        ].join(" "),
      );
    });

    it("multi-process MOVE_SOURCE vs SEND_SOURCE on same source: exactly one holder", async () => {
      await psqlMust(scratchDbUrl, clearLeases(WALLET_SOLO));

      // Each contender is a separate OS process (psql). Mid-tx sleep forces real
      // lock interleaving rather than one finishing before the other starts.
      const moveWorker = runPsql(
        scratchDbUrl,
        `BEGIN; ` +
          `${leaseInsert(WALLET_SOLO, "MOVE_SOURCE", "; ")}` +
          `SELECT pg_sleep(0.25); ` +
          `COMMIT; ` +
          `SELECT 'move-won';`,
      );
      const sendWorker = runPsql(
        scratchDbUrl,
        `BEGIN; ` +
          `SELECT pg_sleep(0.05); ` +
          `${leaseInsert(WALLET_SOLO, "SEND_SOURCE", "; ")}` +
          `COMMIT; ` +
          `SELECT 'send-won';`,
      );

      const [move, send] = await Promise.all([moveWorker, sendWorker]);
      const winners = [move, send].filter((r) => r.ok);
      const losers = [move, send].filter((r) => !r.ok);

      expect(winners, "exactly one cross-kind contender may hold the lease").toHaveLength(1);
      expect(losers).toHaveLength(1);
      expect(extractSqlstate(losers[0]!.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      expect(await countLeases(WALLET_SOLO)).toBe(1);

      const rows = await leaseRows(WALLET_SOLO);
      expect(rows).toHaveLength(1);
      expect(["MOVE_SOURCE", "SEND_SOURCE"]).toContain(rows[0]!.lease_role);
      drillsRun += 1;
    });

    it("multi-process two SEND_SOURCE workers on same source: exactly one holder", async () => {
      await psqlMust(scratchDbUrl, clearLeases(WALLET_SOLO));

      const N = 4;
      const results = await Promise.all(
        Array.from({ length: N }, (_, i) =>
          runPsql(
            scratchDbUrl,
            `BEGIN; ` +
              `SELECT pg_sleep(${(0.02 * i).toFixed(3)}); ` +
              `${leaseInsert(WALLET_SOLO, "SEND_SOURCE", ` RETURNING 'worker-${i}'`)}; ` +
              `COMMIT;`,
          ),
        ),
      );

      const winners = results.filter((r) => r.ok && r.stdout.includes(`worker-`));
      const losers = results.filter((r) => !r.ok);
      expect(winners).toHaveLength(1);
      expect(losers).toHaveLength(N - 1);
      for (const loser of losers) {
        expect(extractSqlstate(loser.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      }
      expect(await countLeases(WALLET_SOLO)).toBe(1);
      drillsRun += 1;
    });

    it("sorted two-wallet MOVE acquire: exactly one full pair, no partial, no deadlock", async () => {
      await psqlMust(scratchDbUrl, clearLeases(WALLET_LO, WALLET_DEST));

      // Both workers sort by wallet_id ascending (LO then DEST) — the mandated
      // protocol. Opposite operation intents still cannot deadlock under this order.
      // Worker A is MOVE (MOVE_SOURCE on LO, MOVE_DESTINATION on DEST).
      // Worker B is a competing MOVE that wants the same pair (second approval).
      const acquireSorted = (tag: string, staggerSec: number) =>
        runPsql(
          scratchDbUrl,
          `BEGIN; ` +
            `SELECT pg_sleep(${staggerSec.toFixed(3)}); ` +
            // wallet_id order: LO < DEST
            `${leaseInsert(WALLET_LO, "MOVE_SOURCE", "; ")}` +
            `SELECT pg_sleep(0.2); ` +
            `${leaseInsert(WALLET_DEST, "MOVE_DESTINATION", "; ")}` +
            `COMMIT; ` +
            `SELECT '${tag}';`,
          25_000,
        );

      const [a, b] = await Promise.all([
        acquireSorted("move-a", 0),
        acquireSorted("move-b", 0.05),
      ]);

      const outcomes = [a, b];
      const winners = outcomes.filter((r) => r.ok);
      const losers = outcomes.filter((r) => !r.ok);

      expect(winners, "exactly one sorted MOVE contender acquires the pair").toHaveLength(1);
      expect(losers).toHaveLength(1);
      // Loser is unique_violation on the first contended wallet — never a partial hold
      // and never a deadlock under sorted acquisition.
      expect(extractSqlstate(losers[0]!.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      expect(extractSqlstate(losers[0]!.stderr)).not.toBe(SQLSTATE_DEADLOCK);

      const rows = await leaseRows(WALLET_LO, WALLET_DEST);
      expect(rows).toHaveLength(2);
      expect(rows.find((r) => r.wallet_id === WALLET_LO)?.lease_role).toBe("MOVE_SOURCE");
      expect(rows.find((r) => r.wallet_id === WALLET_DEST)?.lease_role).toBe("MOVE_DESTINATION");
      // No third partial row, no orphan from the loser.
      expect(await countLeases(WALLET_LO, WALLET_DEST)).toBe(2);
      drillsRun += 1;
    });

    it("mid-pair failure rolls back: no partial acquire survives", async () => {
      await psqlMust(scratchDbUrl, clearLeases(WALLET_LO, WALLET_DEST));

      // Pre-hold DEST so the second INSERT of a sorted pair fails.
      await psqlMust(
        scratchDbUrl,
        `${leaseInsert(WALLET_DEST, "MOVE_DESTINATION", ";")}`,
      );

      const partialAttempt = await runPsql(
        scratchDbUrl,
        `BEGIN; ` +
          `${leaseInsert(WALLET_LO, "MOVE_SOURCE", "; ")}` +
          `${leaseInsert(WALLET_DEST, "MOVE_DESTINATION", "; ")}` +
          `COMMIT; ` +
          `SELECT 'should-not-reach';`,
      );

      expect(partialAttempt.ok).toBe(false);
      expect(extractSqlstate(partialAttempt.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);

      // Source insert must have rolled back with the failed transaction — only the
      // pre-held destination lease remains. Partial acquire is forbidden.
      const rows = await leaseRows(WALLET_LO, WALLET_DEST);
      expect(rows).toHaveLength(1);
      expect(rows[0]!.wallet_id).toBe(WALLET_DEST);
      expect(await countLeases(WALLET_LO)).toBe(0);
      drillsRun += 1;
    });

    it("adversarial — destination-only locking is insufficient (source stays free)", async () => {
      await psqlMust(scratchDbUrl, clearLeases(WALLET_LO, WALLET_DEST, WALLET_SOLO));

      // Contender A "locks" only the destination (the insufficient strategy).
      const destOnly = await runPsql(
        scratchDbUrl,
        `${leaseInsert(WALLET_DEST, "MOVE_DESTINATION", " RETURNING 'dest-only';")}`,
      );
      expect(destOnly.ok).toBe(true);

      // Contender B races a SEND_EXTERNAL on the intended MOVE source — succeeds,
      // proving destination-only locking does not serialise the money path.
      const sourceTaken = await runPsql(
        scratchDbUrl,
        `${leaseInsert(WALLET_LO, "SEND_SOURCE", " RETURNING 'source-stolen';")}`,
      );
      expect(sourceTaken.ok).toBe(true);
      expect(sourceTaken.stdout).toContain("source-stolen");

      // Both leases coexist on different wallets: destination-only failed to protect
      // the source. A correct MOVE must acquire BOTH, sorted, in one transaction.
      const rows = await leaseRows(WALLET_LO, WALLET_DEST);
      expect(rows).toHaveLength(2);
      expect(rows.find((r) => r.wallet_id === WALLET_LO)?.lease_role).toBe("SEND_SOURCE");
      expect(rows.find((r) => r.wallet_id === WALLET_DEST)?.lease_role).toBe("MOVE_DESTINATION");
      drillsRun += 1;
    });

    it("multi-process lease+CAS: exactly one contender reaches signing", async () => {
      await psqlMust(scratchDbUrl, clearLeases(WALLET_SOLO));

      const opId = randomUUID();
      await psqlMust(
        scratchDbUrl,
        `INSERT INTO operations (id, node_id, implementer_id, kind, status, row_version, ` +
          `source_wallet_id, idempotency_key, request_sha256, formation_state) ` +
          `VALUES ('${opId}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'SEND_EXTERNAL', 'APPROVED', 1, ` +
          `'${WALLET_SOLO}', 'sign-race-${opId}', '${FAKE_SHA}', 'APPROVED_UNSIGNED');`,
      );

      // Full critical section: take the wallet lease, then CAS formation_state to
      // SIGNING_CLAIMED. Only one multi-process contender may complete both steps.
      const tryReachSigning = (workerId: number) =>
        runPsql(
          scratchDbUrl,
          `BEGIN; ` +
            `SELECT pg_sleep(${(0.03 * workerId).toFixed(3)}); ` +
            `${leaseInsert(WALLET_SOLO, "SEND_SOURCE", "; ")}` +
            `UPDATE operations SET formation_state = 'SIGNING_CLAIMED', ` +
            `row_version = row_version + 1, updated_at = now() ` +
            `WHERE id = '${opId}' AND formation_state = 'APPROVED_UNSIGNED' AND row_version = 1 ` +
            `RETURNING 'signed-by-${workerId}'; ` +
            `COMMIT;`,
        );

      const N = 5;
      const results = await Promise.all(
        Array.from({ length: N }, (_, i) => tryReachSigning(i)),
      );

      const winners = results.filter((r) => r.ok && r.stdout.includes("signed-by-"));
      const losers = results.filter((r) => !r.ok);
      expect(winners, "exactly one contender reaches signing").toHaveLength(1);
      expect(losers.length).toBeGreaterThanOrEqual(N - 1);

      for (const loser of losers) {
        // Lease PK is the first gate; a loser never advances formation_state.
        expect(extractSqlstate(loser.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      }

      const formation = await psqlMust(
        scratchDbUrl,
        `SELECT formation_state || ':' || row_version::text FROM operations WHERE id = '${opId}';`,
      );
      expect(formation.trim()).toBe("SIGNING_CLAIMED:2");
      expect(await countLeases(WALLET_SOLO)).toBe(1);
      drillsRun += 1;
    });
  },
);

/* ─── fail-closed obligation guard ────────────────────────────────────
 * Top-level so it runs even when the suite is skipIf'd. Mirrors
 * custody-eligibility-lease-pk.test.ts / migration-integrity.test.ts:
 * PG_REQUIRED=1 + no URL or zero drills = hard failure, never silent green. */
it("guard: multi-process lease contention drills must execute under PG_REQUIRED=1", () => {
  if (!TEST_DATABASE_URL) {
    if (PG_REQUIRED) {
      throw new Error(
        "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts " +
          "provisions it when Postgres is reachable. The multi-process wallet lease " +
          "contention suite cannot silently skip.",
      );
    }
    return;
  }
  if (!schemaReady && PG_REQUIRED) {
    throw new Error(
      "PG_REQUIRED=1 but the scratch schema never became ready — " +
        "multi-process lease contention drills did not run.",
    );
  }
  if (schemaReady) {
    expect(
      drillsRun,
      "PostgreSQL was reachable but multi-process lease contention drills did not all run",
    ).toBe(EXPECTED_DRILL_COUNT);
  }
});
