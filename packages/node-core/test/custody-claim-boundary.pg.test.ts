// Real-PostgreSQL proofs for the custody claim boundary.
//
// Two mandatory adversarial inputs (addendum), plus the recovery-
// unverified sink exclusion (mandatory security test 6) and one-in-flight PK independence
// (the one-in-flight-per-wallet rule must remain alongside the eligibility trigger, never replaced by it).
//
// Governing:
// the data model predicates 2–4, (one active lease PK), tests 1–2
// the custody rules tests 5–6
//
// Schema under test is the REAL frozen DDL (custody-eligibility.sql), loaded via the
// tokenizer on the prerequisite chain (base-enums-domains + nodes) — no hand-rolled
// mirror. Connectivity: TEST_DATABASE_URL from vitest.global-setup.ts under the
// root vitest project.
import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  buildLeaseClaimInsertSql,
  claimWalletLease,
  precheckAutomaticSink,
  precheckDestinationCreate,
  precheckLeaseClaim,
  type LeaseClaimInsertInput,
} from "../src/core/custody-claim.js";
import { tokenizeCustodySql } from "./custody-eligibility-sql-statements.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

const SQLSTATE_RAISE_EXCEPTION = "P0001";
const SQLSTATE_UNIQUE_VIOLATION = "23505";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

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
    throw new Error(`psql failed for [${sql}]: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout.trim();
};

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const mustReject = async (sql: string, sqlstate: string, literal?: string): Promise<string> => {
  const outcome = await runPsql(sql);
  expect(outcome.ok, `expected rejection but the statement succeeded: ${sql}`).toBe(false);
  expect(extractSqlstate(outcome.stderr), `SQLSTATE for: ${sql}\n${outcome.stderr}`).toBe(sqlstate);
  if (literal !== undefined) {
    expect(outcome.stderr, `error literal for: ${sql}`).toContain(literal);
  }
  return outcome.stderr;
};

const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

// Custody is prerequisite-bound (base enums/domains + nodes), not greenfield-alone.
const prerequisiteDdl = ((): string => {
  const base = readSchema("base-enums-domains.sql");
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  return `${base}\n${nodes[0]}\n`;
})();

const custodyDdl = tokenizeCustodySql(readSchema("custody-eligibility.sql"))
  .map((statement) => statement.raw)
  .join("\n");

const schemaDdl = `${prerequisiteDdl}${custodyDdl}`;

const scratchDb = `custody_claim_boundary_claim_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;

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

const NODE_ID = "b0000000-0000-4000-8000-000000000001";
const EXPORT_SHA = "b".repeat(64);

beforeAll(() => {
  if (!TEST_DATABASE_URL) return;
  adminPsql(TEST_DATABASE_URL, `CREATE DATABASE ${scratchDb}`);
  scratchDbUrl = withDatabase(TEST_DATABASE_URL, scratchDb);
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: schemaDdl,
    encoding: "utf-8",
    timeout: 60_000,
  });
  // Tenant root for wallet FKs (wallets.node_id REFERENCES nodes(id)).
  execFileSync(
    "psql",
    [
      scratchDbUrl,
      "-v",
      "ON_ERROR_STOP=1",
      "-qAt",
      "-c",
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${NODE_ID}', 'custody-claim-boundary-claim', '${"N".repeat(43)}=') ON CONFLICT (id) DO NOTHING;`,
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
    /* best-effort teardown */
  }
});

let seq = 0;

const nextIds = (): { walletId: string; publicKey: string } => {
  seq += 1;
  const suffix = String(seq).padStart(12, "0");
  return {
    walletId: `a0000000-0000-4000-8000-${suffix}`,
    publicKey: `${"B".repeat(43 - suffix.length)}${suffix}=`,
  };
};

const uuid = (n: number): string => `c0000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

/** Fresh fencing ids for one lease INSERT (no FK to membership tables on custody DDL). */
const nextLeaseFence = (
  walletId: string,
): Omit<LeaseClaimInsertInput, "leaseRole" | "acquiredAtIso" | "heartbeatAtIso"> => {
  seq += 1;
  const base = seq * 10;
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
): string => buildLeaseClaimInsertSql({ ...nextLeaseFence(walletId), leaseRole });

const seedWallet = async (
  origin: "node_generated" | "imported" = "node_generated",
): Promise<{ walletId: string; publicKey: string }> => {
  const ids = nextIds();
  await must(
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) VALUES ` +
      `('${ids.walletId}', '${NODE_ID}', '${ids.publicKey}', '${origin}', 'AVAILABLE');`,
  );
  return ids;
};

const seedVerification = async (walletId: string, publicKey: string): Promise<string> => {
  seq += 1;
  const verificationId = uuid(seq);
  const exportSha = `${EXPORT_SHA.slice(0, 60)}${String(seq).padStart(4, "0")}`;
  await must(
    `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `VALUES ('${verificationId}', '${walletId}', 'AUDITED_EXPORT', ` +
      `'${exportSha}', '${publicKey}', '${verificationId}', now(), 'custody-claim-boundary-claim-test');`,
  );
  await must(
    `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${verificationId}' ` +
      `WHERE id = '${walletId}';`,
  );
  return verificationId;
};

const seedBlessedDestination = async (walletId: string): Promise<void> => {
  seq += 1;
  await must(
    `INSERT INTO destinations ` +
      `(id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
      `VALUES ('${uuid(seq)}', '${NODE_ID}', '${walletId}', 'BLESSED', now(), '${uuid(900)}', '${uuid(901)}');`,
  );
};

/**
 * Plant a BLESSED destination against an imported wallet by briefly disabling the
 * destination-origin trigger. This is the only way to construct adversarial #1's
 * "otherwise fully sink-eligible imported wallet" — the structural destination guard
 * (data-model rule 2) correctly forbids it in normal operation, but the claim-boundary origin
 * conjunct must still reject even if that guard were bypassed.
 */
const plantBlessedDestinationBypassingOriginGuard = async (walletId: string): Promise<void> => {
  seq += 1;
  await must(`ALTER TABLE destinations DISABLE TRIGGER destinations_custody_insert_guard;`);
  try {
    await must(
      `INSERT INTO destinations ` +
        `(id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
        `VALUES ('${uuid(seq)}', '${NODE_ID}', '${walletId}', 'BLESSED', now(), '${uuid(900)}', '${uuid(901)}');`,
    );
  } finally {
    await must(`ALTER TABLE destinations ENABLE TRIGGER destinations_custody_insert_guard;`);
  }
};

const sinkFacts = (overrides: Record<string, unknown> = {}) => ({
  keyOrigin: "node_generated",
  destinationState: "BLESSED",
  recoveryVerifiedAt: "2026-07-26T00:00:00.000Z",
  walletState: "AVAILABLE",
  ...overrides,
});

describe.skipIf(!TEST_DATABASE_URL)(
  "claim-boundary adversarial tests against real PostgreSQL",
  { timeout: 120_000 },
  () => {
    it("#1 origin-only rejection — fully sink-eligible imported wallet fails purely on key_origin", async () => {
      // Every other automatic-sink dimension is satisfied: recovery-verified, BLESSED
      // destination (planted via temporary trigger disable), AVAILABLE. Rejection must be
      // CUSTODY_LEASE_ORIGIN_REJECTED — not destination/recovery/state.
      const { walletId, publicKey } = await seedWallet("imported");
      await seedVerification(walletId, publicKey);
      await plantBlessedDestinationBypassingOriginGuard(walletId);

      // Service precheck also fails purely on origin (typed denial).
      const pre = precheckLeaseClaim(sinkFacts({ keyOrigin: "imported" }), "MOVE_DESTINATION");
      expect(pre).toEqual({ ok: false, denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED" });

      // Claim INSERT is rejected by the claim-boundary trigger for the origin conjunct.
      const stderr = await mustReject(
        leaseInsertSql(walletId, "MOVE_DESTINATION"),
        SQLSTATE_RAISE_EXCEPTION,
        "CUSTODY_LEASE_ORIGIN_REJECTED",
      );
      // Not a disguised unblessed/unverified failure:
      expect(stderr).not.toContain("CUSTODY_LEASE_DESTINATION_NOT_BLESSED");
      expect(stderr).not.toContain("CUSTODY_LEASE_RECOVERY_UNVERIFIED");
      expect(stderr).not.toContain("CUSTODY_LEASE_WALLET_STATE_REJECTED");
      expect(
        await must(`SELECT count(*)::int FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
      ).toBe("0");
    });

    it("#2 non-monotonic TOCTOU — quarantine between precheck and claim re-rejects at claim boundary", async () => {
      const { walletId, publicKey } = await seedWallet("node_generated");
      await seedVerification(walletId, publicKey);
      await seedBlessedDestination(walletId);

      // Precheck against live facts succeeds.
      const pre = precheckAutomaticSink(sinkFacts());
      expect(pre).toEqual({ eligible: true, denialReason: null });
      expect(precheckLeaseClaim(sinkFacts(), "MOVE_DESTINATION").ok).toBe(true);

      // Flip eligibility in the precheck→claim window (non-monotonic dimension).
      await must(
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'toctou adversarial' ` +
          `WHERE id = '${walletId}';`,
      );

      // Claim boundary (BEFORE INSERT trigger), not the precheck snapshot, is authoritative.
      const decision = await claimWalletLease(
        sinkFacts(), // stale precheck facts still look eligible
        "MOVE_DESTINATION",
        async (sql) => {
          const outcome = await runPsql(sql);
          if (!outcome.ok) {
            throw new Error(outcome.stderr);
          }
        },
        nextLeaseFence(walletId),
      );
      // Service saw the claim-boundary literal and mapped it — precheck was NOT the rejector.
      expect(decision).toEqual({
        ok: false,
        denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE",
      });
      expect(
        await must(`SELECT count(*)::int FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
      ).toBe("0");
    });

    it("mandatory security test 6 — recovery-unverified blessed destination is never auto-selected (lease)", async () => {
      const { walletId } = await seedWallet("node_generated");
      // Blessed but NO recovery stamp.
      await seedBlessedDestination(walletId);
      expect(
        precheckAutomaticSink(sinkFacts({ recoveryVerifiedAt: null })).eligible,
      ).toBe(false);

      await mustReject(
        leaseInsertSql(walletId, "MOVE_DESTINATION"),
        SQLSTATE_RAISE_EXCEPTION,
        "CUSTODY_LEASE_RECOVERY_UNVERIFIED",
      );
    });

    it("golden test 5 — imported destination insert fails at DB and service boundaries independently", async () => {
      const { walletId } = await seedWallet("imported");
      // Service boundary:
      expect(precheckDestinationCreate({ keyOrigin: "imported" }).ok).toBe(false);
      // Database boundary (structural trigger — independent of service):
      seq += 1;
      await mustReject(
        `INSERT INTO destinations ` +
          `(id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
          `VALUES ('${uuid(seq)}', '${NODE_ID}', '${walletId}', 'BLESSED', now(), '${uuid(900)}', '${uuid(901)}');`,
        SQLSTATE_RAISE_EXCEPTION,
        "CUSTODY_DESTINATION_ORIGIN_REJECTED",
      );
    });

    it("the one-in-flight-per-wallet rule PK exclusivity is independent of the eligibility trigger", async () => {
      const { walletId, publicKey } = await seedWallet("node_generated");
      await seedVerification(walletId, publicKey);
      await seedBlessedDestination(walletId);
      await must(leaseInsertSql(walletId, "MOVE_DESTINATION"));
      // Second insert: PK unique_violation (23505), not an eligibility RAISE.
      await mustReject(
        leaseInsertSql(walletId, "SEND_SOURCE"),
        SQLSTATE_UNIQUE_VIOLATION,
      );
    });

    it("eligible node-generated sink claim succeeds end-to-end via claimWalletLease", async () => {
      const { walletId, publicKey } = await seedWallet("node_generated");
      await seedVerification(walletId, publicKey);
      await seedBlessedDestination(walletId);
      const decision = await claimWalletLease(
        sinkFacts(),
        "MOVE_DESTINATION",
        async (sql) => {
          await must(sql);
        },
        nextLeaseFence(walletId),
      );
      expect(decision).toEqual({ ok: true, denialReason: null });
      expect(
        await must(`SELECT lease_role FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
      ).toBe("MOVE_DESTINATION");
    });
  },
);

it("guard: claim-boundary drills must execute under PG_REQUIRED=1", () => {
  if (PG_REQUIRED && !TEST_DATABASE_URL) {
    throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unset — harness is broken");
  }
  if (PG_REQUIRED && TEST_DATABASE_URL && !schemaReady) {
    throw new Error("PG_REQUIRED=1 but custody schema failed to apply");
  }
  expect(true).toBe(true);
});
