/**
 * custody-eligibility-lease-pk.test.ts
 *
 * SCHEMA_EXECUTION_OBLIGATIONS #9 (C-02). Proves, against a REAL PostgreSQL
 * database, that the frozen custody-eligibility DDL structurally enforces:
 *   - The one-in-flight-per-wallet rule backstop: wallet_active_leases.wallet_id PRIMARY KEY rejects a second
 *     active lease for the same wallet with unique_violation (SQLSTATE 23505).
 *   - lease_role vocabulary: an out-of-vocabulary lease_role is rejected fail-closed by the
 *     BEFORE INSERT unknown-role raise (CUSTODY_LEASE_ROLE_UNKNOWN / P0001; the inline CHECK is
 *     23512, which is not an assigned SQLSTATE).
 *
 * Home rationale : the frozen contract declares this package carries NO database
 * harness (custody-eligibility.contract.ts, SCHEMA_EXECUTION_OBLIGATIONS preamble), and no
 * real-PG execution harness exists in the tree. Rather than skip the obligation, this test
 * provisions its OWN hermetic scratch database, applies the real DDL (loaded via the tokenizer
 * — no hand-rolled mirror), runs the two negative drills, and tears the database down. It is
 * discovered and executed by packages/node-core's own `vitest run` (default include over
 * test/**). The fail-closed guard at the bottom turns an undischarged obligation into a hard
 * FAILURE whenever PostgreSQL is reachable, so it can never be silently skipped where a
 * database is present.
 *
 * Connectivity: pg_isready alone is insufficient — it proves the server accepts connections
 * but NOT that a usable database exists (psql with no -d targets a database named after the
 * OS user, which is typically absent → FATAL). The gate therefore probes the actual
 * maintenance database this test depends on. psql runs at verbose verbosity so the
 * machine-readable `ERROR:  <sqlstate>:` and `CONSTRAINT NAME:` lines are emitted and asserted.
 *
 * PG_REQUIRED race guard (mirrors apps/node/src/auth/test-support.ts): this suite does
 * NOT, and structurally CANNOT, reimplement scripts/verify-local.sh's own Postgres reachability
 * gate. The defense is two independent layers, and the load-bearing one for this file is (b):
 *   (a) verify-local.sh's OWN `VERIFY_REQUIRE_PG` (default ON) runs a hard `pg_isready -q` step and
 *       fails the WHOLE local-verify run if Postgres was never reachable at all. That variable is a
 *       script-LOCAL shell var (assigned without `export`), so it is invisible to this child vitest
 *       process — this test neither sees it nor needs to; layer (a) already closes the
 *       "no Postgres → silent green" hole at the outer-runner level. (Its NAME also existing in
 *       verify-local.sh is a coincidence, not a wiring: nothing arms it for this suite.)
 *   (b) This suite's OWN guard (below) keys off `PG_REQUIRED`, the SAME convention every PG-gated
 *       suite in the repo already uses (apps/node/src/auth/test-support.ts). verify-local.sh
 *       `export`s `PG_REQUIRED=1` to child processes ONLY when its own probe found Postgres
 *       reachable, so within this process `PG_REQUIRED=1` means "the outer runner confirmed PG was
 *       up," never "PG is optional." If it is set but this suite's own stricter `pgUsable()` probe
 *       then finds Postgres NOT usable, that is a race / broken gate (not an absent Postgres) and is
 *       a HARD FAILURE — never a silent skip. This is the only env var the real pipeline actually
 *       exports to us, so it is the only one this suite gates on.
 *
 * Seed vocabulary: the PK-drill lease roles are drawn from the canonical LEASE_ROLES enum — the
 * same source of truth the DDL's lease_role CHECK is bound to by lease-role-parity.test.ts — so a
 * future vocabulary rename cannot silently re-break setup the way the literal 'RECEIVE' did after
 * reconciled the enum to RECEIVE_WINDOW/MOVE_DESTINATION/RECONCILIATION.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LEASE_ROLES } from "../../generic-node-contracts/src/wallet-state/leases.ts";
import { tokenizeCustodySql } from "./custody-eligibility-sql-statements.js";

/* ─── constants ───────────────────────────────────────────────────── */

const MAINTENANCE_DB = "postgres";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const PK_CONSTRAINT = "wallet_active_leases_pkey";
const EXPECTED_DRILL_COUNT = 2;

/* ─── psql helpers ────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) {
    args.push("-v", "VERBOSITY=verbose");
  }
  args.push("-qAt", "-c", sql);
  try {
    const stdout = execFileSync("psql", args, {
      encoding: "utf-8",
      timeout: 15_000,
      // Capture stderr into the thrown error rather than forwarding it to the terminal:
      // the drills provoke intentional constraint violations, and their psql ERROR output
      // is asserted on, not noise for the console.
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

// Setup/seed statements MUST succeed. A failure here is a real error and is surfaced
// (thrown), never swallowed — that swallowing was the original harness's core defect.
const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

// Apply the whole frozen DDL in a single transaction, streamed via stdin.
const applyDdl = (db: string, ddl: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      input: ddl,
      encoding: "utf-8",
      timeout: 30_000,
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`custody DDL apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

// Probe the ACTUAL maintenance database this test depends on (see file header): a passing
// probe is the precondition under which the drills MUST run and the guard MUST fire.
const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

/* ─── verbose-psql extraction ─────────────────────────────────────── */

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const extractConstraint = (stderr: string): string => {
  const m = /CONSTRAINT NAME:\s+(\S+)/.exec(stderr);
  return m === null ? "" : m[1];
};

/* ─── load real DDL via the tokenizer (no hand-rolled mirror) ─────── */

const ddlSource = readFileSync(
  new URL("../src/schema/custody-eligibility.sql", import.meta.url),
  "utf-8",
);
const ddlToApply = tokenizeCustodySql(ddlSource)
  .map((statement) => statement.raw)
  .join("\n");

// custody-eligibility.sql conforms to the data-model canon and is therefore
// prerequisite-bound — it references the data-model reference domains, the enumerations, and
// `nodes`. Both prerequisites are read from the real frozen contracts, never hand-mirrored:
// base-enums-domains.sql whole, and node-implementer-registry.sql's `nodes` block only. That
// slice re-declares padded_base64url_pubkey, which base-enums-domains.sql has already created,
// so applying it whole would abort on a duplicate type — reconciling that overlap across all
// nine slices is scope, not this test's.
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

/* ─── fixtures ────────────────────────────────────────────────────── */

const WALLET_A = "a0000000-0000-4000-8000-000000000001";
const NODE_A = "b0000000-0000-4000-8000-000000000002";
const WALLET_B = "a0000000-0000-4000-8000-000000000003";
const NODE_B = "b0000000-0000-4000-8000-000000000004";

// public_key columns carry the padded_base64url_pubkey domain again, so seeds must be
// real 44-char padded base64url — the old 'pk-a' literals now fail the domain CHECK, which is
// exactly the ii schema-level guarantee restored here.
const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const seedNode = (nodeId: string, identityKey: string): string =>
  `INSERT INTO nodes (id, display_name, identity_public_key) ` +
  `VALUES ('${nodeId}', 'custody-eligibility-${nodeId.slice(0, 8)}', '${identityKey}');`;

const seedWallet = (walletId: string, nodeId: string, publicKey: string): string =>
  `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
  `VALUES ('${walletId}', '${nodeId}', '${publicKey}', 'node_generated', 'AVAILABLE');`;

// data-model lease fencing columns are NOT NULL, so every drill insert carries a full lease row.
// membership_id is UNIQUE and (operation_id, wallet_id) / (lease_group_id, wallet_id) are too,
// so each call gets its own identifiers — leaving the wallet_id PRIMARY KEY as the sole
// possible rejector of a duplicate lease, which is what the first drill asserts.
let leaseSeq = 0;
const insertLease = (walletId: string, leaseRole: string): string => {
  leaseSeq += 1;
  const uuid = (tag: number): string =>
    `c0000000-0000-4000-8000-${String(leaseSeq * 100 + tag).padStart(12, "0")}`;
  return (
    `INSERT INTO wallet_active_leases (wallet_id, membership_id, lease_group_id, ` +
    `root_operation_id, operation_id, lease_role, lease_epoch, acquired_at, heartbeat_at, ` +
    `owner_instance_id) VALUES ('${walletId}', '${uuid(1)}', '${uuid(2)}', '${uuid(3)}', ` +
    `'${uuid(4)}', '${leaseRole}', 1, now(), now(), '${uuid(5)}');`
  );
};

// Two distinct valid, trigger-safe lease roles for the PK drill, taken from the canonical
// LEASE_ROLES enum (the DDL CHECK is bound to this same enum by lease-role-parity.test.ts).
// MOVE_DESTINATION and RECEIVE_WINDOW are excluded: their eligibility triggers require recovery
// verification (and MOVE_DESTINATION also needs a blessed destination), so they would reject
// the insert for a reason OTHER than the wallet_id PRIMARY KEY. Origin-only roles pass the
// trigger, leaving the PK as the sole possible rejector of the duplicate.
const TRIGGER_SAFE_ROLES: readonly string[] = LEASE_ROLES.filter(
  (role) => role !== "MOVE_DESTINATION" && role !== "RECEIVE_WINDOW",
);
const FIRST_LEASE_ROLE = TRIGGER_SAFE_ROLES[0] ?? "SEND_SOURCE";
const DUPLICATE_LEASE_ROLE = TRIGGER_SAFE_ROLES[1] ?? FIRST_LEASE_ROLE;

/* ─── suite ───────────────────────────────────────────────────────── */

// PG_REQUIRED=1 is exported by scripts/verify-local.sh ONLY when its own pg_isready probe found
// Postgres reachable — the same signal apps/node/src/auth/test-support.ts keys off. It means "the
// outer runner confirmed PG was up," NOT "PG is optional": if it is set but this suite's own
// pgUsable() probe disagrees, that is a race / broken gate and the guard below fails hard. It is
// the only PG env var the real pipeline exports to this process, so it is the only one we gate on.
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

let assertionsRun = 0;

describeIfPg("custody-eligibility lease PK & CHECK (real frozen DDL, hermetic scratch DB)", () => {
  const scratchDb = `custody_eligibility_lease_pk_${Date.now()}_${process.pid}`;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    applyDdl(scratchDb, prerequisiteDdl);
    applyDdl(scratchDb, ddlToApply);
  });

  afterAll(() => {
    psqlMust(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  it("rejects a second active lease for one wallet with unique_violation (23505)", () => {
    psqlMust(scratchDb, seedNode(NODE_A, pubkey("NODEA")));
    psqlMust(scratchDb, seedWallet(WALLET_A, NODE_A, pubkey("WALLETA")));
    psqlMust(scratchDb, insertLease(WALLET_A, FIRST_LEASE_ROLE));

    // A second lease for the SAME wallet_id (different valid role) must be rejected by the PK,
    // not by the CHECK or the eligibility trigger.
    const duplicate = runPsql(scratchDb, insertLease(WALLET_A, DUPLICATE_LEASE_ROLE), true);

    expect(duplicate.ok, "second active lease for the same wallet must be rejected").toBe(false);
    expect(extractSqlstate(duplicate.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(duplicate.stderr)).toBe(PK_CONSTRAINT);
    assertionsRun += 1;
  });

  it("rejects an out-of-vocabulary lease_role fail-closed (BEFORE INSERT unknown-role raise)", () => {
    psqlMust(scratchDb, seedNode(NODE_B, pubkey("NODEB")));
    psqlMust(scratchDb, seedWallet(WALLET_B, NODE_B, pubkey("WALLETB")));

    const invalid = runPsql(scratchDb, insertLease(WALLET_B, "INVALID_ROLE"), true);

    expect(invalid.ok, "out-of-vocabulary lease_role must be rejected").toBe(false);
    // BEFORE INSERT fires before CHECK, so CUSTODY_LEASE_ROLE_UNKNOWN (P0001) is the
    // observed rejector. The inline CHECK remains as a second line of defence.
    expect(extractSqlstate(invalid.stderr)).toBe("P0001");
    expect(invalid.stderr).toContain("CUSTODY_LEASE_ROLE_UNKNOWN");
    assertionsRun += 1;
  });
});

/* ─── fail-closed obligation guard ────────────────────────────────────
 * Top-level (OUTSIDE the pg-gated describe) so it runs even when the suite is skipped. Mirrors the
 * PG_REQUIRED race guard in apps/node/src/auth/test-support.ts. Three cases, none of which can
 * silently pass having tested nothing:
 *   1. PG unusable AND PG_REQUIRED=1 → HARD FAILURE. The outer verify-local.sh runner confirmed
 *      Postgres was reachable (the only way PG_REQUIRED=1 is exported to us) and forbade any
 *      PG-gated suite from skipping; this suite's own probe now disagreeing is a race / broken gate,
 *      never "no Postgres", so the obligation fails loudly instead of skipping.
 *   2. PG unusable AND PG_REQUIRED unset → Postgres is genuinely optional for a standalone run
 *      outside the canonical pipeline; graceful no-op. Making "no Postgres at all" fail is NOT this
 *      test's job and it cannot do it (PG_REQUIRED is never exported in that case): verify-local.sh's
 *      own default-ON VERIFY_REQUIRE_PG / pg_isready step independently fails the whole run then —
 *      see the file header, layer (a).
 *   3. PG usable → the two real-PG drills MUST have executed their assertions, else the
 *      obligation went undischarged and this fails hard. */
it("obligation guard: real-PG lease drills must execute (hard fail under PG_REQUIRED=1)", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        `PG_REQUIRED=1 but PostgreSQL maintenance database "${MAINTENANCE_DB}" is not usable: the ` +
          "the real-PG lease PK backstop could not run and the local " +
          "verification lane must not silently skip it. The outer runner exports PG_REQUIRED=1 only " +
          "after seeing a reachable Postgres, so this is a race / broken gate, not an absent " +
          "Postgres — provision the maintenance database and re-run (or run without PG_REQUIRED to " +
          "make Postgres optional).",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the real-PG lease drills did not run — the lease PK backstop is undischarged",
  ).toBe(EXPECTED_DRILL_COUNT);
});
