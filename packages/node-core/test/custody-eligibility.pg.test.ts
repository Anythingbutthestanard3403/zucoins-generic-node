// Behavioural proof of the frozen custody schema against a REAL
// PostgreSQL. The DDL is EXECUTED, never pattern-matched: every expectation below is the
// observed accept/reject behaviour of a live constraint or trigger, and a rejection is
// confirmed by SQLSTATE (23514 check_violation, 23503 foreign_key_violation,
// 23505 unique_violation, P0001 raise_exception) plus the trigger's own error literal —
// never by string-matching an incidental message.
//
// Rules under proof: the wallet-custody and destination CHECK / immutability / recovery
// rules; "an imported wallet cannot become a destination"; custody classification and the
// imported-wallet launch rule; custody vs automatic-sink conjuncts; the import/drain joint
// deferral ('imported' is an inert enum reservation); the recovery gate (no column DEFAULT
// on recovery_verified_at); and the wallets(id) spelling — the composite PK spelling is
// retired, and this suite proves the live catalog rather than the retired name.
//
// Gap this closes: `custody-eligibility.sql` was already censused statically
// (custody-eligibility.census.test.ts, custody-eligibility-sql-statements.test.ts) and its
// greenfield APPLY was characterized (migration-integrity.test.ts), but no suite had ever
// driven its CHECKs both ways, tripped the immutability trigger, or proven the
// imported-origin destination guard from the DATABASE side. A static census proves the file
// says the right words; only this file proves the database enforces them.
// Apply is prerequisite-bound (base-enums-domains + nodes) — not greenfield-alone.
//
// Deliberately NOT covered here: the MOVE_DESTINATION lease-eligibility trigger
// (wallet-lease-lock-contention.pg.test.ts, pg-concurrency.test.ts) and the service-boundary
// predicates.
//
// Connectivity: TEST_DATABASE_URL is auto-provisioned by vitest.global-setup.ts
// when run through the ROOT vitest project. Under PG_REQUIRED=1 an unreachable server is a
// broken harness, not "no Postgres here" — the fail-closed guard at the bottom of this file
// turns a silent skip into a failure.
import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { tokenizeCustodySql } from "./custody-eligibility-sql-statements.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";

const SQLSTATE_CHECK_VIOLATION = "23514";
const SQLSTATE_FOREIGN_KEY_VIOLATION = "23503";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_RAISE_EXCEPTION = "P0001";

/* ─── psql helpers ────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

// VERBOSITY=verbose is unconditional so SQLSTATE appears in stderr as
// `ERROR:  <sqlstate>:` (default verbosity omits the code).
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

/** Runs SQL that must succeed; returns trimmed stdout. */
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

/**
 * Runs SQL that must be REJECTED by the database, and asserts on the SQLSTATE (plus, for
 * plpgsql RAISE, the exact error literal the frozen trigger names). A rejection asserted only
 * by "it failed" would pass on a typo, so both legs are required.
 */
const mustReject = async (sql: string, sqlstate: string, literal?: string): Promise<void> => {
  const outcome = await runPsql(sql);
  expect(outcome.ok, `expected rejection but the statement succeeded: ${sql}`).toBe(false);
  expect(extractSqlstate(outcome.stderr), `SQLSTATE for: ${sql}\n${outcome.stderr}`).toBe(sqlstate);
  if (literal !== undefined) {
    expect(outcome.stderr, `error literal for: ${sql}`).toContain(literal);
  }
};

/* ─── real frozen DDL (no hand-rolled mirror), prereq sequence ─ */

const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

// custody-eligibility.sql is prerequisite-bound: base domains/enums + nodes first.
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

/* ─── lifecycle ───────────────────────────────────────────────────── */

// Own prefix, own database. Teardown drops ONLY the database this run created — several
// lanes share this server and a broader DROP takes their data with it.
const scratchDb = `custody_eligibility_custody_${Date.now()}_${process.pid}`;
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

beforeAll(() => {
  if (!TEST_DATABASE_URL) return;
  adminPsql(TEST_DATABASE_URL, `CREATE DATABASE ${scratchDb}`);
  scratchDbUrl = withDatabase(TEST_DATABASE_URL, scratchDb);
  // The apply itself is the first assertion: prereqs + the frozen custody contract must load
  // in one transaction, or nothing below runs.
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: schemaDdl,
    encoding: "utf-8",
    timeout: 60_000,
  });
  // Tenant roots for wallet FKs (wallets.node_id REFERENCES nodes(id)).
  execFileSync(
    "psql",
    [
      scratchDbUrl,
      "-v",
      "ON_ERROR_STOP=1",
      "-qAt",
      "-c",
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${NODE_ID}', 'custody-eligibility-a', '${"N".repeat(43)}=') ON CONFLICT (id) DO NOTHING;
       INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${OTHER_NODE_ID}', 'custody-eligibility-b', '${"O".repeat(43)}=') ON CONFLICT (id) DO NOTHING;`,
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
    /* teardown is best-effort; a leaked scratch database must never fail the suite */
  }
});

/* ─── fixtures ────────────────────────────────────────────────────── */

const NODE_ID = "b0000000-0000-4000-8000-000000000001";
const OTHER_NODE_ID = "b0000000-0000-4000-8000-000000000002";
const EXPORT_SHA = "a".repeat(64);

let seq = 0;
/** Fresh uuid + public key per fixture so no test can pass on another test's row. */
const nextIds = (): { walletId: string; publicKey: string } => {
  seq += 1;
  const suffix = String(seq).padStart(12, "0");
  return {
    walletId: `a0000000-0000-4000-8000-${suffix}`,
    // padded_base64url_pubkey shape (43 base64url chars + '='), valid under the bare-text
    // column on main and under the domain if this column is ever re-derived to it.
    publicKey: `${"A".repeat(43 - suffix.length)}${suffix}=`,
  };
};

const uuid = (n: number): string => `c0000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

/**
 * Seeds one wallet. Column names follow the canon data-model spelling (`wallets.id`).
 */
const seedWallet = async (
  origin: "node_generated" | "imported" = "node_generated",
  nodeId: string = NODE_ID,
): Promise<{ walletId: string; publicKey: string }> => {
  const ids = nextIds();
  await must(
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) VALUES ` +
      `('${ids.walletId}', '${nodeId}', '${ids.publicKey}', '${origin}', 'AVAILABLE');`,
  );
  return ids;
};

/** Seeds an AUDITED_EXPORT recovery-evidence row for a wallet; returns its id. */
const seedVerification = async (walletId: string, publicKey: string): Promise<string> => {
  seq += 1;
  const verificationId = uuid(seq);
  await must(
    `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `VALUES ('${verificationId}', '${walletId}', 'AUDITED_EXPORT', '${EXPORT_SHA}', '${publicKey}', ` +
      `'${verificationId}', now(), 'custody-eligibility-test');`,
  );
  return verificationId;
};

const blessedDestinationInsert = (
  walletId: string,
  nodeId: string = NODE_ID,
): string => {
  seq += 1;
  return (
    `INSERT INTO destinations ` +
    `(id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
    `VALUES ('${uuid(seq)}', '${nodeId}', '${walletId}', 'BLESSED', now(), '${uuid(900)}', '${uuid(901)}');`
  );
};

/* ─── suite ───────────────────────────────────────────────────────── */

describe.skipIf(!TEST_DATABASE_URL)(
  "frozen custody schema behaviour against real PostgreSQL",
  { timeout: 120_000 },
  () => {
    describe("live schema shape", () => {
      it("wallets is keyed on id — the canon data-model spelling, read from the live catalog", async () => {
        const pk = await must(
          `SELECT a.attname FROM pg_index i ` +
            `JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey) ` +
            `WHERE i.indrelid = 'wallets'::regclass AND i.indisprimary;`,
        );
        expect(pk).toBe("id");
      });

      it("recovery_verified_at and recovery_verification_id carry NO column DEFAULT", async () => {
        const defaults = await must(
          `SELECT column_name || '=' || coalesce(column_default, 'NULL') ` +
            `FROM information_schema.columns WHERE table_name = 'wallets' ` +
            `AND column_name IN ('recovery_verified_at', 'recovery_verification_id', 'state') ` +
            `ORDER BY column_name;`,
        );
        expect(defaults.split("\n")).toEqual([
          "recovery_verification_id=NULL",
          "recovery_verified_at=NULL",
          // Non-vacuity: the same query DOES observe a default where one exists, so the two
          // NULLs above are an absent default and not an inert query.
          "state='AVAILABLE'::wallet_state",
        ]);
      });

      it("wallet_key_origin reserves 'imported' and nothing else (forward-compat only)", async () => {
        const labels = await must(
          `SELECT e.enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid ` +
            `WHERE t.typname = 'wallet_key_origin' ORDER BY e.enumsortorder;`,
        );
        expect(labels.split("\n")).toEqual(["node_generated", "imported"]);
      });
    });

    describe("wallets CHECK constraints — proven both ways", () => {
      it("QUARANTINED without a quarantine_reason is rejected; with one it is accepted", async () => {
        const { walletId } = await seedWallet();
        await mustReject(
          `UPDATE wallets SET state = 'QUARANTINED' WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
          "wallets_quarantine_reason_iff",
        );
        await must(
          `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'indeterminate head' ` +
            `WHERE id = '${walletId}';`,
        );
      });

      it("a quarantine_reason on a non-QUARANTINED wallet is rejected (the CHECK is an iff)", async () => {
        const { walletId } = await seedWallet();
        await mustReject(
          `UPDATE wallets SET quarantine_reason = 'reason without the state' WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
          "wallets_quarantine_reason_iff",
        );
      });

      it("RETIRED without retired_at is rejected; with it accepted; retired_at alone is rejected", async () => {
        const { walletId } = await seedWallet();
        await mustReject(
          `UPDATE wallets SET state = 'RETIRED' WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
          "wallets_retired_at_iff",
        );
        await mustReject(
          `UPDATE wallets SET retired_at = now() WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
          "wallets_retired_at_iff",
        );
        await must(
          `UPDATE wallets SET state = 'RETIRED', retired_at = now() WHERE id = '${walletId}';`,
        );
      });
    });

    describe("wallets immutability trigger (data-model rule 1)", () => {
      it("rejects an UPDATE of key_origin", async () => {
        const { walletId } = await seedWallet();
        await mustReject(
          `UPDATE wallets SET key_origin = 'imported' WHERE id = '${walletId}';`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_IMMUTABLE_FIELD_REJECTED",
        );
      });

      it("rejects an UPDATE of node_id", async () => {
        const { walletId } = await seedWallet();
        await mustReject(
          `UPDATE wallets SET node_id = '${OTHER_NODE_ID}' WHERE id = '${walletId}';`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_IMMUTABLE_FIELD_REJECTED",
        );
      });

      it("rejects an UPDATE of public_key", async () => {
        const { walletId } = await seedWallet();
        const replacement = nextIds().publicKey;
        await mustReject(
          `UPDATE wallets SET public_key = '${replacement}' WHERE id = '${walletId}';`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_IMMUTABLE_FIELD_REJECTED",
        );
      });

      it("still permits a legal lifecycle UPDATE — the guard is field-scoped, not a blanket freeze", async () => {
        const { walletId } = await seedWallet();
        await must(`UPDATE wallets SET state = 'PINNED' WHERE id = '${walletId}';`);
        expect(await must(`SELECT state FROM wallets WHERE id = '${walletId}';`)).toBe(
          "PINNED",
        );
      });
    });

    describe("destinations insert guard (data-model rule 2, data-model test 1, custody)", () => {
      it("rejects a destination for an imported-origin wallet — the database-bypass path", async () => {
        // The only 'imported' write in this package, and it exists solely to be refused a
        // destination. no route, seed, or importer creates one; a *.test.ts fixture is
        // outside the launch-deferral absence census's content classes by design.
        const { walletId } = await seedWallet("imported");
        await mustReject(
          blessedDestinationInsert(walletId),
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_DESTINATION_ORIGIN_REJECTED",
        );
        expect(
          await must(`SELECT count(*)::int FROM destinations WHERE wallet_id = '${walletId}';`),
        ).toBe("0");
      });

      it("rejects a destination whose node_id differs from its wallet's (tenant isolation)", async () => {
        const { walletId } = await seedWallet();
        await mustReject(
          blessedDestinationInsert(walletId, OTHER_NODE_ID),
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_TENANT_MISMATCH_REJECTED",
        );
      });

      it("accepts a fully blessed destination for a node-generated wallet", async () => {
        const { walletId } = await seedWallet();
        await must(blessedDestinationInsert(walletId));
      });

      it("rejects a second destination for the same wallet (one destination per wallet)", async () => {
        const { walletId } = await seedWallet();
        await must(blessedDestinationInsert(walletId));
        await mustReject(blessedDestinationInsert(walletId), SQLSTATE_UNIQUE_VIOLATION);
      });
    });

    describe("destinations CHECK constraints — proven both ways", () => {
      it("BLESSED without blessed_at is rejected", async () => {
        const { walletId } = await seedWallet();
        seq += 1;
        await mustReject(
          `INSERT INTO destinations (id, node_id, wallet_id, state) ` +
            `VALUES ('${uuid(seq)}', '${NODE_ID}', '${walletId}', 'BLESSED');`,
          SQLSTATE_CHECK_VIOLATION,
          "destinations_blessed_iff",
        );
      });

      it("PENDING with a blessed_at is rejected (the CHECK is an iff)", async () => {
        const { walletId } = await seedWallet();
        seq += 1;
        await mustReject(
          `INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at, ` +
            `blessed_by_device_key_id, blessing_artifact_id) ` +
            `VALUES ('${uuid(seq)}', '${NODE_ID}', '${walletId}', 'PENDING', now(), '${uuid(900)}', '${uuid(901)}');`,
          SQLSTATE_CHECK_VIOLATION,
          "destinations_blessed_iff",
        );
      });

      it("a blessing without both the device key and the artifact is rejected (data-model rule 6)", async () => {
        const { walletId } = await seedWallet();
        seq += 1;
        await mustReject(
          `INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at, ` +
            `blessed_by_device_key_id) ` +
            `VALUES ('${uuid(seq)}', '${NODE_ID}', '${walletId}', 'BLESSED', now(), '${uuid(900)}');`,
          SQLSTATE_CHECK_VIOLATION,
          "destinations_blessing_requires_device_artifact",
        );
      });

      it("RETIRED without retired_at is rejected; with it accepted", async () => {
        const { walletId } = await seedWallet();
        await must(blessedDestinationInsert(walletId));
        await mustReject(
          `UPDATE destinations SET state = 'RETIRED' WHERE wallet_id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
          "destinations_retired_at_iff",
        );
        await must(
          `UPDATE destinations SET state = 'RETIRED', retired_at = now() WHERE wallet_id = '${walletId}';`,
        );
      });
    });

    describe("recovery evidence (data-model rule 5)", () => {
      it("rejects recovery_verified_at without recovery_verification_id, and the reverse", async () => {
        const { walletId, publicKey } = await seedWallet();
        const verificationId = await seedVerification(walletId, publicKey);
        await mustReject(
          `UPDATE wallets SET recovery_verified_at = now() WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
          "wallets_recovery_fields_together",
        );
        await mustReject(
          `UPDATE wallets SET recovery_verification_id = '${verificationId}' WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
          "wallets_recovery_fields_together",
        );
        await must(
          `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${verificationId}' ` +
            `WHERE id = '${walletId}';`,
        );
      });

      it("rejects a recovery_verification_id with no evidence row behind it", async () => {
        const { walletId } = await seedWallet();
        await mustReject(
          `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${uuid(999)}' ` +
            `WHERE id = '${walletId}';`,
          SQLSTATE_FOREIGN_KEY_VIOLATION,
          "wallets_recovery_verification_fk",
        );
      });

      it("never lets a verified wallet be cleared or re-pointed", async () => {
        const { walletId, publicKey } = await seedWallet();
        const verificationId = await seedVerification(walletId, publicKey);
        await must(
          `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${verificationId}' ` +
            `WHERE id = '${walletId}';`,
        );
        await mustReject(
          `UPDATE wallets SET recovery_verified_at = NULL, recovery_verification_id = NULL ` +
            `WHERE id = '${walletId}';`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_RECOVERY_NEVER_CLEARED",
        );
        const other = await seedWallet();
        const otherVerification = await seedVerification(other.walletId, other.publicKey);
        await mustReject(
          `UPDATE wallets SET recovery_verification_id = '${otherVerification}' ` +
            `WHERE id = '${walletId}';`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_RECOVERY_NEVER_CLEARED",
        );
      });

      it("accepts only method = 'AUDITED_EXPORT'", async () => {
        const { walletId, publicKey } = await seedWallet();
        seq += 1;
        await mustReject(
          `INSERT INTO wallet_recovery_verifications ` +
            `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
            `VALUES ('${uuid(seq)}', '${walletId}', 'SELF_ATTESTED', '${EXPORT_SHA}', '${publicKey}', ` +
            `'${uuid(seq)}', now(), 'custody-eligibility-test');`,
          SQLSTATE_CHECK_VIOLATION,
          "wallet_recovery_verifications_method_check",
        );
      });

      it("rejects a duplicate (wallet_id, export_sha256) evidence row", async () => {
        const { walletId, publicKey } = await seedWallet();
        await seedVerification(walletId, publicKey);
        await mustReject(
          `INSERT INTO wallet_recovery_verifications ` +
            `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
            `VALUES ('${uuid(998)}', '${walletId}', 'AUDITED_EXPORT', '${EXPORT_SHA}', '${publicKey}', ` +
            `'${uuid(998)}', now(), 'custody-eligibility-test');`,
          SQLSTATE_UNIQUE_VIOLATION,
        );
      });

      it("rejects evidence for a wallet that does not exist", async () => {
        // public_key must satisfy padded_base64url_pubkey so the FK (not the domain) rejects.
        const orphanKey = `${"X".repeat(43)}=`;
        await mustReject(
          `INSERT INTO wallet_recovery_verifications ` +
            `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
            `VALUES ('${uuid(997)}', '${uuid(996)}', 'AUDITED_EXPORT', '${EXPORT_SHA}', '${orphanKey}', ` +
            `'${uuid(997)}', now(), 'custody-eligibility-test');`,
          SQLSTATE_FOREIGN_KEY_VIOLATION,
        );
      });
    });
  },
);

/* ─── fail-closed harness guard (pattern) ─────────────────────
 * Top-level, OUTSIDE the gated describe, so it runs even when that block skips itself. Under
 * PG_REQUIRED=1 an unassigned TEST_DATABASE_URL or a schema that never applied is a BROKEN
 * HARNESS, never "no Postgres here" — otherwise this suite reports green having proven
 * nothing, which is exactly the vacuous control it exists to remove. */
it("custody behaviour must execute under PG_REQUIRED=1 (no silent skip)", () => {
  if (process.env.PG_REQUIRED !== "1") return;
  expect(
    TEST_DATABASE_URL,
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts provisioned no test database, so the live block skipped",
  ).not.toBe("");
  expect(
    schemaReady,
    "PG_REQUIRED=1 but the frozen custody DDL never applied — every assertion below it was skipped, not proven",
  ).toBe(true);
});
