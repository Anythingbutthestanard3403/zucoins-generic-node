// real-PostgreSQL wallet lifecycle state-machine proofs.
//
// Verification slice of schema and claim-boundary
// predicates already land; this suite proves the lifecycle
// assembled from them holds under structural bypass, service-boundary calls, and
// concurrency. remediation also closes the structural
// gap: custody_reject_ineligible_lease state allowlist applies to every
// non-RECONCILIATION lease role (not only MOVE_DESTINATION).
//
// Governing rules: the wallet/destination enums and CHECK constraints (immutability,
// recovery, destination-origin), the one-active-lease primary key, the
// internal_custody / automatic_sink_eligible pair, the imported launch rule, and the
// rejection of quarantined/retired wallets at lease acquisition.
//
// Schema under test is the REAL frozen DDL (custody-eligibility.sql), loaded via
// the tokenizer on the prerequisite chain (base-enums-domains + nodes) — no hand-rolled
// mirror. Connectivity: TEST_DATABASE_URL from
// vitest.global-setup.ts under the root vitest project. Under
// PG_REQUIRED=1 an unreachable server is a broken harness, not a silent skip.
//
// Scope notes (ticket gotchas, implementer judgment):
//   (a) "restored" = PINNED→AVAILABLE lease-release, not un-quarantine/un-retire.
//       QUARANTINE_WALLETS is one-directional.
//   (b) "wrong-tenant" = node_id mismatch → CUSTODY_TENANT_MISMATCH_REJECTED
//       (no tenant_id column on wallets; scoping is implementer-credential based).
//   (c) open: do NOT assert PINNED-implies-leased; assert wallet_active_leases
//       row presence as the source of truth for "leased".
import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  buildLeaseClaimInsertSql,
  claimWalletLease,
  precheckAutomaticSink,
  precheckDestinationCreate,
  precheckInternalCustody,
  precheckLeaseClaim,
  type LeaseClaimInsertInput,
} from "../src/core/custody-claim.js";
import {
  AUTOMATIC_SINK_CONJUNCTS,
  WALLET_STATES,
  type WalletState,
} from "../../generic-node-contracts/src/custody/predicates.contract.ts";
import { verifyAutomaticSinkEligibility } from "../../generic-node-contracts/src/custody/predicate-verifier.ts";
import { tokenizeCustodySql } from "./custody-eligibility-sql-statements.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

const SQLSTATE_CHECK_VIOLATION = "23514";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_RAISE_EXCEPTION = "P0001";

/* ─── transition matrix (custody CHECKs / pool policy + lease effects) ─ */

/**
 * Structural transitions the live CHECK + mutation guard permit as UPDATEs.
 * QUARANTINED→AVAILABLE is legal at the column layer (pool-policy permits it)
 * but no production recovery-action lifts quarantine (gotcha a) — we still
 * prove the DB would accept the row shape if a future path wrote it, and that
 * QUARANTINED/RETIRED cannot acquire leases regardless.
 */
const STRUCTURAL_WALLET_TRANSITIONS: ReadonlyMap<WalletState, readonly WalletState[]> = new Map([
  ["AVAILABLE", ["PINNED", "QUARANTINED", "RETIRED"]],
  ["PINNED", ["AVAILABLE", "QUARANTINED", "RETIRED"]],
  ["QUARANTINED", ["RETIRED", "AVAILABLE"]],
  ["RETIRED", []],
]);

const SINK_ALLOWED = new Set<string>(AUTOMATIC_SINK_CONJUNCTS.allowedWalletStates);

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

const NODE_ID = "b0000000-0000-4000-8000-000000000001";
const OTHER_NODE_ID = "b0000000-0000-4000-8000-000000000002";
const EXPORT_SHA = "c".repeat(64);
let seq = 0;

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

const scratchDb = `wallet_lifecycle_lifecycle_${Date.now()}_${process.pid}`;
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
         ('${NODE_ID}', 'wallet-lifecycle-a', '${"N".repeat(43)}=') ON CONFLICT (id) DO NOTHING;
       INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${OTHER_NODE_ID}', 'wallet-lifecycle-b', '${"O".repeat(43)}=') ON CONFLICT (id) DO NOTHING;`,
    ],
    { encoding: "utf-8", timeout: 15_000 },
  );
  schemaReady = true;
}, 90_000);

afterAll(() => {
  if (!schemaReady) return;
  try {
    // Terminate backends first so DROP does not wait on idle psql children.
    adminPsql(
      TEST_DATABASE_URL,
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity ` +
        `WHERE datname = '${scratchDb}' AND pid <> pg_backend_pid();`,
    );
    adminPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  } catch {
    /* best-effort teardown — never fail the suite on a leaked scratch DB */
  }
}, 60_000);


const nextIds = (): { walletId: string; publicKey: string } => {
  seq += 1;
  const suffix = String(seq).padStart(12, "0");
  return {
    walletId: `a0000000-0000-4000-8000-${suffix}`,
    publicKey: `${"C".repeat(43 - suffix.length)}${suffix}=`,
  };
};

const uuid = (n: number): string => `c0000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

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

const seedVerification = async (walletId: string, publicKey: string): Promise<string> => {
  seq += 1;
  const verificationId = uuid(seq);
  const exportSha = `${EXPORT_SHA.slice(0, 60)}${String(seq).padStart(4, "0")}`;
  await must(
    `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `VALUES ('${verificationId}', '${walletId}', 'AUDITED_EXPORT', ` +
      `'${exportSha}', '${publicKey}', '${verificationId}', now(), 'wallet-lifecycle-lifecycle');`,
  );
  await must(
    `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${verificationId}' ` +
      `WHERE id = '${walletId}';`,
  );
  return verificationId;
};

const seedBlessedDestination = async (walletId: string, nodeId: string = NODE_ID): Promise<string> => {
  seq += 1;
  const destinationId = uuid(seq);
  await must(
    `INSERT INTO destinations ` +
      `(id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
      `VALUES ('${destinationId}', '${nodeId}', '${walletId}', 'BLESSED', now(), '${uuid(900)}', '${uuid(901)}');`,
  );
  return destinationId;
};

const seedPendingDestination = async (walletId: string, nodeId: string = NODE_ID): Promise<string> => {
  seq += 1;
  const destinationId = uuid(seq);
  await must(
    `INSERT INTO destinations (id, node_id, wallet_id, state) ` +
      `VALUES ('${destinationId}', '${nodeId}', '${walletId}', 'PENDING');`,
  );
  return destinationId;
};

/** Bypass origin trigger so #1 can plant a fully-else-eligible imported sink. */
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

const setWalletState = async (walletId: string, state: WalletState): Promise<void> => {
  if (state === "QUARANTINED") {
    await must(
      `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'lifecycle-test', retired_at = NULL ` +
        `WHERE id = '${walletId}';`,
    );
    return;
  }
  if (state === "RETIRED") {
    await must(
      `UPDATE wallets SET state = 'RETIRED', retired_at = now(), quarantine_reason = NULL ` +
        `WHERE id = '${walletId}';`,
    );
    return;
  }
  // AVAILABLE / PINNED — clear co-invariant fields.
  await must(
    `UPDATE wallets SET state = '${state}', quarantine_reason = NULL, retired_at = NULL ` +
      `WHERE id = '${walletId}';`,
  );
};

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

const insertLease = (
  walletId: string,
  role: LeaseClaimInsertInput["leaseRole"] = "RECEIVE_WINDOW",
): string => buildLeaseClaimInsertSql({ ...nextLeaseFence(walletId), leaseRole: role });

const sinkFacts = (overrides: Record<string, unknown> = {}) => ({
  keyOrigin: "node_generated",
  destinationState: "BLESSED",
  recoveryVerifiedAt: "2026-07-26T00:00:00.000Z",
  walletState: "AVAILABLE",
  ...overrides,
});

/**
 * Derive CustodyPredicateFacts from the seeded wallet/destination rows (break D-A).
 * Matrix sink assertions must not re-author the same literals the cell already put
 * into sinkFacts — they must round-trip what Postgres actually stores.
 */
const loadSinkFactsFromDb = async (walletId: string) => {
  // One row: wallet columns + LEFT JOIN destinations (0 or 1 expected under lifecycle).
  const raw = await must(
    `SELECT w.key_origin, w.state, ` +
      `w.recovery_verified_at IS NOT NULL AS recovery_set, ` +
      `to_char(w.recovery_verified_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS recovery_iso, ` +
      `d.state AS destination_state ` +
      `FROM wallets w ` +
      `LEFT JOIN destinations d ON d.wallet_id = w.id ` +
      `WHERE w.id = '${walletId}' ` +
      `LIMIT 1;`,
  );
  const parts = raw.split("|");
  if (parts.length < 5) {
    throw new Error(`loadSinkFactsFromDb: unexpected row shape for ${walletId}: ${raw}`);
  }
  const [keyOrigin, walletState, recoverySet, recoveryIso, destinationState] = parts;
  return {
    keyOrigin,
    walletState,
    recoveryVerifiedAt: recoverySet === "t" ? recoveryIso : null,
    destinationState: destinationState === "" ? "PENDING" : destinationState,
  };
};

const executeInsertViaPsql = async (sql: string): Promise<void> => {
  const outcome = await runPsql(sql);
  if (!outcome.ok) throw new Error(outcome.stderr);
};

/* ─── matrix cells for the review-indicator checklist ─────────────── */

type MatrixCell = {
  readonly name: string;
  readonly origin: "node_generated" | "imported";
  readonly blessed: boolean;
  readonly recoveryVerified: boolean;
  readonly walletState: WalletState;
  readonly expectSink: boolean;
  readonly expectLease: "ok" | "origin" | "destination" | "recovery" | "state";
};

const MATRIX: readonly MatrixCell[] = [
  {
    name: "generated+blessed+verified+AVAILABLE",
    origin: "node_generated",
    blessed: true,
    recoveryVerified: true,
    walletState: "AVAILABLE",
    expectSink: true,
    expectLease: "ok",
  },
  {
    name: "generated+blessed+verified+PINNED",
    origin: "node_generated",
    blessed: true,
    recoveryVerified: true,
    walletState: "PINNED",
    expectSink: true,
    expectLease: "ok",
  },
  {
    name: "generated+blessed+verified+QUARANTINED",
    origin: "node_generated",
    blessed: true,
    recoveryVerified: true,
    walletState: "QUARANTINED",
    expectSink: false,
    expectLease: "state",
  },
  {
    name: "generated+blessed+verified+RETIRED",
    origin: "node_generated",
    blessed: true,
    recoveryVerified: true,
    walletState: "RETIRED",
    expectSink: false,
    expectLease: "state",
  },
  {
    name: "generated+unblessed+verified+AVAILABLE",
    origin: "node_generated",
    blessed: false,
    recoveryVerified: true,
    walletState: "AVAILABLE",
    expectSink: false,
    expectLease: "destination",
  },
  {
    name: "generated+blessed+unverified+AVAILABLE",
    origin: "node_generated",
    blessed: true,
    recoveryVerified: false,
    walletState: "AVAILABLE",
    expectSink: false,
    expectLease: "recovery",
  },
  {
    name: "imported+blessed+verified+AVAILABLE (origin-only)",
    origin: "imported",
    blessed: true,
    recoveryVerified: true,
    walletState: "AVAILABLE",
    expectSink: false,
    expectLease: "origin",
  },
];

const leaseRejectLiteral = (kind: MatrixCell["expectLease"]): string | null => {
  switch (kind) {
    case "ok":
      return null;
    case "origin":
      return "CUSTODY_LEASE_ORIGIN_REJECTED";
    case "destination":
      return "CUSTODY_LEASE_DESTINATION_NOT_BLESSED";
    case "recovery":
      return "CUSTODY_LEASE_RECOVERY_UNVERIFIED";
    case "state":
      return "CUSTODY_LEASE_WALLET_STATE_REJECTED";
  }
};

/* ─── suite ───────────────────────────────────────────────────────── */

describe.skipIf(!TEST_DATABASE_URL)(
  "wallet lifecycle transitions against real PostgreSQL",
  { timeout: 180_000 },
  () => {
    describe("table-driven lifecycle matrix (criterion 1)", () => {
      it.each(MATRIX)("$name", async (cell) => {
        const { walletId, publicKey } = await seedWallet(cell.origin);
        if (cell.recoveryVerified) {
          await seedVerification(walletId, publicKey);
        }
        if (cell.blessed) {
          if (cell.origin === "imported") {
            await plantBlessedDestinationBypassingOriginGuard(walletId);
          } else {
            await seedBlessedDestination(walletId);
          }
        } else if (cell.origin === "node_generated") {
          await seedPendingDestination(walletId);
        }
        await setWalletState(walletId, cell.walletState);

        // Sink leg against real Postgres: facts come from SELECT of seeded rows
        // (opposed-break defect A — not hand-built sinkFacts mirroring the cell).
        const facts = await loadSinkFactsFromDb(walletId);
        expect(facts.keyOrigin, `DB key_origin for ${cell.name}`).toBe(cell.origin);
        expect(facts.walletState, `DB wallet state for ${cell.name}`).toBe(cell.walletState);
        if (cell.blessed) {
          expect(facts.destinationState).toBe("BLESSED");
        } else if (cell.origin === "node_generated") {
          expect(facts.destinationState).toBe("PENDING");
        }
        if (cell.recoveryVerified) {
          expect(facts.recoveryVerifiedAt).not.toBeNull();
        } else {
          expect(facts.recoveryVerifiedAt).toBeNull();
        }

        // Service-boundary automatic-sink predicate driven by DB-read facts.
        const sink = verifyAutomaticSinkEligibility(facts);
        expect(sink.eligible, `sink eligibility for ${cell.name}`).toBe(cell.expectSink);
        expect(precheckAutomaticSink(facts).eligible).toBe(cell.expectSink);

        // Structural MOVE_DESTINATION claim (sink lease role).
        // RECEIVE_WINDOW / sources for QUARANTINED|RETIRED are proven under indicator 7.
        const literal = leaseRejectLiteral(cell.expectLease);
        if (literal === null) {
          await must(insertLease(walletId, "MOVE_DESTINATION"));
          expect(
            await must(`SELECT count(*)::int FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
          ).toBe("1");
          // Cleanup so subsequent cells stay independent on PK.
          await must(`DELETE FROM wallet_active_leases WHERE wallet_id = '${walletId}';`);
        } else {
          await mustReject(insertLease(walletId, "MOVE_DESTINATION"), SQLSTATE_RAISE_EXCEPTION, literal);
          expect(
            await must(`SELECT count(*)::int FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
          ).toBe("0");
        }
      });
    });

    describe("wallet state transitions + co-invariants (criteria 2)", () => {
      it("AVAILABLE → PINNED → AVAILABLE (lease acquire / release = 'restored')", async () => {
        const { walletId } = await seedWallet();
        await setWalletState(walletId, "PINNED");
        expect(await must(`SELECT state FROM wallets WHERE id = '${walletId}';`)).toBe("PINNED");
        // "Restored": PINNED→AVAILABLE after lease release (gotcha a).
        await setWalletState(walletId, "AVAILABLE");
        expect(await must(`SELECT state FROM wallets WHERE id = '${walletId}';`)).toBe("AVAILABLE");
      });

      it("AVAILABLE → QUARANTINED requires quarantine_reason (iff CHECK both ways)", async () => {
        const { walletId } = await seedWallet();
        await mustReject(
          `UPDATE wallets SET state = 'QUARANTINED' WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
        );
        await must(
          `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'probe-fail' ` +
            `WHERE id = '${walletId}';`,
        );
        await mustReject(
          `UPDATE wallets SET quarantine_reason = NULL WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
        );
        // reason on a non-QUARANTINED state is also rejected
        await setWalletState(walletId, "AVAILABLE");
        await mustReject(
          `UPDATE wallets SET quarantine_reason = 'stray' WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
        );
      });

      it("AVAILABLE → RETIRED requires retired_at (iff CHECK both ways); RETIRED is terminal for escape", async () => {
        const { walletId } = await seedWallet();
        await mustReject(
          `UPDATE wallets SET state = 'RETIRED' WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
        );
        await setWalletState(walletId, "RETIRED");
        expect(await must(`SELECT state FROM wallets WHERE id = '${walletId}';`)).toBe("RETIRED");
        // No production un-retire; co-invariant still binds: clearing retired_at alone fails.
        await mustReject(
          `UPDATE wallets SET retired_at = NULL WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
        );
      });

      it("PINNED → QUARANTINED and PINNED → RETIRED succeed with co-invariant fields", async () => {
        const { walletId: w1 } = await seedWallet();
        await setWalletState(w1, "PINNED");
        await setWalletState(w1, "QUARANTINED");
        expect(await must(`SELECT state FROM wallets WHERE id = '${w1}';`)).toBe("QUARANTINED");

        const { walletId: w2 } = await seedWallet();
        await setWalletState(w2, "PINNED");
        await setWalletState(w2, "RETIRED");
        expect(await must(`SELECT state FROM wallets WHERE id = '${w2}';`)).toBe("RETIRED");
      });

      it("QUARANTINED → RETIRED succeeds; destination RETIRED iff retired_at", async () => {
        const { walletId } = await seedWallet();
        await setWalletState(walletId, "QUARANTINED");
        await setWalletState(walletId, "RETIRED");
        expect(await must(`SELECT state FROM wallets WHERE id = '${walletId}';`)).toBe("RETIRED");

        const { walletId: dw } = await seedWallet();
        const destId = await seedBlessedDestination(dw);
        await mustReject(
          `UPDATE destinations SET state = 'RETIRED' WHERE id = '${destId}';`,
          SQLSTATE_CHECK_VIOLATION,
        );
        await must(
          `UPDATE destinations SET state = 'RETIRED', retired_at = now() WHERE id = '${destId}';`,
        );
        expect(await must(`SELECT state FROM destinations WHERE id = '${destId}';`)).toBe(
          "RETIRED",
        );
      });

      it("STRUCTURAL_WALLET_TRANSITIONS pairs are writable under CHECKs (not an FSM)", async () => {
        // Named after the allow-map only — CHECKs are co-invariants, not a transition
        // graph (opposed-break defect C). Illegal / unlisted pairs are not asserted here.
        for (const [from, tos] of STRUCTURAL_WALLET_TRANSITIONS) {
          for (const to of tos) {
            const { walletId } = await seedWallet();
            if (from !== "AVAILABLE") await setWalletState(walletId, from);
            await setWalletState(walletId, to);
            expect(await must(`SELECT state FROM wallets WHERE id = '${walletId}';`)).toBe(to);
          }
        }
      });

      it("known gap: RETIRED→AVAILABLE structural escape succeeds (no transition FSM trigger)", async () => {
        // CHECKs only enforce (state='RETIRED') iff (retired_at IS NOT NULL). Clearing
        // both fields is accepted at the DB layer. Ticket gotcha (a): no production
        // un-retire path; lease eligibility + service layer own terminal semantics.
        const { walletId } = await seedWallet();
        await setWalletState(walletId, "RETIRED");
        expect(
          await must(
            `SELECT (state = 'RETIRED') = (retired_at IS NOT NULL) FROM wallets WHERE id = '${walletId}';`,
          ),
        ).toBe("t");
        // Escape: both fields cleared together — succeeds (documents the non-FSM gap).
        await must(
          `UPDATE wallets SET state = 'AVAILABLE', retired_at = NULL, quarantine_reason = NULL ` +
            `WHERE id = '${walletId}';`,
        );
        expect(await must(`SELECT state FROM wallets WHERE id = '${walletId}';`)).toBe(
          "AVAILABLE",
        );
        expect(
          await must(`SELECT retired_at IS NULL FROM wallets WHERE id = '${walletId}';`),
        ).toBe("t");
        // Half-escape still blocked by the iff CHECK.
        await setWalletState(walletId, "RETIRED");
        await mustReject(
          `UPDATE wallets SET state = 'AVAILABLE' WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
        );
      });
    });

    describe("immutable wallet fields (criterion 3)", () => {
      it("rejects UPDATE of key_origin, node_id, and public_key", async () => {
        const { walletId, publicKey } = await seedWallet();
        await mustReject(
          `UPDATE wallets SET key_origin = 'imported' WHERE id = '${walletId}';`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_IMMUTABLE_FIELD_REJECTED",
        );
        await mustReject(
          `UPDATE wallets SET node_id = '${OTHER_NODE_ID}' WHERE id = '${walletId}';`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_IMMUTABLE_FIELD_REJECTED",
        );
        const tampered = publicKey.replace(/^C/, "D");
        await mustReject(
          `UPDATE wallets SET public_key = '${tampered}' WHERE id = '${walletId}';`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_IMMUTABLE_FIELD_REJECTED",
        );
        // Lifecycle UPDATE still works — guard is field-scoped.
        await setWalletState(walletId, "PINNED");
        expect(await must(`SELECT state FROM wallets WHERE id = '${walletId}';`)).toBe("PINNED");
      });
    });

    describe("recovery fields monotonic (criterion 4)", () => {
      it("set-together or not at all; never cleared once set", async () => {
        const { walletId, publicKey } = await seedWallet();
        await mustReject(
          `UPDATE wallets SET recovery_verified_at = now() WHERE id = '${walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
        );
        seq += 1;
        const verificationId = uuid(seq);
        // dangling FK rejected before we can pair incorrectly
        await mustReject(
          `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${verificationId}' ` +
            `WHERE id = '${walletId}';`,
          "23503",
        );
        await seedVerification(walletId, publicKey);
        await mustReject(
          `UPDATE wallets SET recovery_verified_at = NULL, recovery_verification_id = NULL ` +
            `WHERE id = '${walletId}';`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_RECOVERY_NEVER_CLEARED",
        );
        seq += 1;
        const otherId = uuid(seq);
        await mustReject(
          `UPDATE wallets SET recovery_verification_id = '${otherId}' WHERE id = '${walletId}';`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_RECOVERY_NEVER_CLEARED",
        );
      });
    });

    describe("mandatory negatives (criterion 5)", () => {
      it("#1 — fully sink-eligible imported wallet fails purely on key_origin", async () => {
        const { walletId, publicKey } = await seedWallet("imported");
        await seedVerification(walletId, publicKey);
        await plantBlessedDestinationBypassingOriginGuard(walletId);
        await setWalletState(walletId, "AVAILABLE");

        const facts = sinkFacts({ keyOrigin: "imported" });
        // Service: origin alone.
        expect(precheckInternalCustody(facts)).toEqual({
          eligible: false,
          denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED",
        });
        expect(precheckLeaseClaim(facts, "MOVE_DESTINATION")).toEqual({
          ok: false,
          denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED",
        });
        // Structural: origin conjunct, not a disguised unblessed/unverified/state fail.
        const stderr = await mustReject(
          insertLease(walletId, "MOVE_DESTINATION"),
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_LEASE_ORIGIN_REJECTED",
        );
        expect(stderr).not.toContain("CUSTODY_LEASE_DESTINATION_NOT_BLESSED");
        expect(stderr).not.toContain("CUSTODY_LEASE_RECOVERY_UNVERIFIED");
        expect(stderr).not.toContain("CUSTODY_LEASE_WALLET_STATE_REJECTED");
      });

      it("#2 — quarantine flip in precheck→claim window re-rejects at claim boundary", async () => {
        const { walletId, publicKey } = await seedWallet();
        await seedVerification(walletId, publicKey);
        await seedBlessedDestination(walletId);

        expect(precheckAutomaticSink(sinkFacts()).eligible).toBe(true);
        expect(precheckLeaseClaim(sinkFacts(), "MOVE_DESTINATION").ok).toBe(true);

        await setWalletState(walletId, "QUARANTINED");

        const decision = await claimWalletLease(
          sinkFacts(), // stale snapshot still looks eligible
          "MOVE_DESTINATION",
          executeInsertViaPsql,
          nextLeaseFence(walletId),
        );
        expect(decision).toEqual({
          ok: false,
          denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE",
        });
        expect(
          await must(`SELECT count(*)::int FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
        ).toBe("0");
      });
    });

    describe("imported destination forbidden (criterion 6)", () => {
      it("no destinations row for imported origin — DB + service independently", async () => {
        const { walletId } = await seedWallet("imported");
        expect(precheckDestinationCreate({ keyOrigin: "imported" }).ok).toBe(false);
        seq += 1;
        await mustReject(
          `INSERT INTO destinations ` +
            `(id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
            `VALUES ('${uuid(seq)}', '${NODE_ID}', '${walletId}', 'BLESSED', now(), '${uuid(900)}', '${uuid(901)}');`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_DESTINATION_ORIGIN_REJECTED",
        );
        expect(
          await must(`SELECT count(*)::int FROM destinations WHERE wallet_id = '${walletId}';`),
        ).toBe("0");
      });
    });

    describe("QUARANTINED/RETIRED cannot acquire leases (criterion 7)", () => {
      /**
       * Non-exempt signing roles under acquisition rule 3. RECONCILIATION is the
       * recovery-lane exemption and is asserted separately as ADMITTED.
       */
      const NON_EXEMPT_LEASE_ROLES = [
        "RECEIVE_WINDOW",
        "MOVE_SOURCE",
        "SEND_SOURCE",
        "MOVE_DESTINATION",
      ] as const;

      it.each(
        (["QUARANTINED", "RETIRED"] as const).flatMap((state) =>
          NON_EXEMPT_LEASE_ROLES.map((role) => ({ state, role })),
        ),
      )(
        "$state wallet is rejected for $role with CUSTODY_LEASE_WALLET_STATE_REJECTED",
        async ({ state, role }) => {
          const { walletId, publicKey } = await seedWallet();
          await seedVerification(walletId, publicKey);
          // MOVE_DESTINATION also needs a blessed dest so the state reject fires first /
          // independently of destination/recovery conjuncts.
          if (role === "MOVE_DESTINATION") {
            await seedBlessedDestination(walletId);
          }
          await setWalletState(walletId, state);
          await mustReject(
            insertLease(walletId, role),
            SQLSTATE_RAISE_EXCEPTION,
            "CUSTODY_LEASE_WALLET_STATE_REJECTED",
          );
          expect(
            await must(`SELECT count(*)::int FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
          ).toBe("0");
        },
      );

      it.each(["QUARANTINED", "RETIRED"] as const)(
        "RECONCILIATION recovery-lane exemption admits %s",
        async (state) => {
          const { walletId } = await seedWallet();
          await setWalletState(walletId, state);
          await must(insertLease(walletId, "RECONCILIATION"));
          expect(
            await must(
              `SELECT lease_role FROM wallet_active_leases WHERE wallet_id = '${walletId}';`,
            ),
          ).toBe("RECONCILIATION");
          await must(`DELETE FROM wallet_active_leases WHERE wallet_id = '${walletId}';`);
        },
      );

      it("sink allowlist parity — AUTOMATIC_SINK_CONJUNCTS.allowedWalletStates is the sole admit set", () => {
        for (const state of WALLET_STATES) {
          const admitted = SINK_ALLOWED.has(state);
          const decision = verifyAutomaticSinkEligibility(
            sinkFacts({ walletState: state }),
          );
          expect(decision.eligible, `state ${state}`).toBe(admitted);
        }
      });
    });

    describe("wrong-tenant / cross-implementer isolation (criterion 8)", () => {
      it("destination insert with mismatched node_id is rejected (no existence leak path)", async () => {
        const { walletId } = await seedWallet("node_generated", NODE_ID);
        seq += 1;
        await mustReject(
          `INSERT INTO destinations (id, node_id, wallet_id, state) ` +
            `VALUES ('${uuid(seq)}', '${OTHER_NODE_ID}', '${walletId}', 'PENDING');`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_TENANT_MISMATCH_REJECTED",
        );
        expect(
          await must(`SELECT count(*)::int FROM destinations WHERE wallet_id = '${walletId}';`),
        ).toBe("0");
      });
    });

    describe("lease concurrency + one-in-flight (the one-in-flight-per-wallet rule)", () => {
      it("second concurrent lease on the same wallet is PK-rejected (23505), not eligibility", async () => {
        const { walletId, publicKey } = await seedWallet();
        await seedVerification(walletId, publicKey);
        await seedBlessedDestination(walletId);
        await must(insertLease(walletId, "RECEIVE_WINDOW"));
        await mustReject(insertLease(walletId, "SEND_SOURCE"), SQLSTATE_UNIQUE_VIOLATION);
        // Source of truth for "leased" is the row (gotcha c — not PINNED state).
        expect(
          await must(`SELECT lease_role FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
        ).toBe("RECEIVE_WINDOW");
        // PINNED column is independent of the lease row under open.
        expect(await must(`SELECT state FROM wallets WHERE id = '${walletId}';`)).toBe(
          "AVAILABLE",
        );
      });

      it("20-racer claim: exactly one MOVE_DESTINATION holder", async () => {
        const { walletId, publicKey } = await seedWallet();
        await seedVerification(walletId, publicKey);
        await seedBlessedDestination(walletId);

        const racers = Array.from({ length: 20 }, () => runPsql(insertLease(walletId, "MOVE_DESTINATION")));
        const results = await Promise.all(racers);
        const wins = results.filter((r) => r.ok).length;
        const pkLosses = results.filter(
          (r) => !r.ok && extractSqlstate(r.stderr) === SQLSTATE_UNIQUE_VIOLATION,
        ).length;
        expect(wins).toBe(1);
        expect(pkLosses).toBe(19);
        expect(
          await must(`SELECT count(*)::int FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
        ).toBe("1");
      });

      it("eligible node-generated sink claim succeeds end-to-end via claimWalletLease", async () => {
        const { walletId, publicKey } = await seedWallet();
        await seedVerification(walletId, publicKey);
        await seedBlessedDestination(walletId);
        const decision = await claimWalletLease(
          sinkFacts(),
          "MOVE_DESTINATION",
          executeInsertViaPsql,
          nextLeaseFence(walletId),
        );
        expect(decision).toEqual({ ok: true, denialReason: null });
      });

      it("lease release leaves no row — 'restored' path does not require un-quarantine", async () => {
        const { walletId, publicKey } = await seedWallet();
        await seedVerification(walletId, publicKey);
        await seedBlessedDestination(walletId);
        await must(insertLease(walletId, "RECEIVE_WINDOW"));
        await setWalletState(walletId, "PINNED");
        await must(`DELETE FROM wallet_active_leases WHERE wallet_id = '${walletId}';`);
        await setWalletState(walletId, "AVAILABLE");
        expect(
          await must(`SELECT count(*)::int FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
        ).toBe("0");
        expect(await must(`SELECT state FROM wallets WHERE id = '${walletId}';`)).toBe(
          "AVAILABLE",
        );
      });
    });

    describe("destination blessing co-invariants", () => {
      it("BLESSED requires blessed_at + device key + artifact; PENDING cannot carry blessed_at", async () => {
        const { walletId } = await seedWallet();
        seq += 1;
        await mustReject(
          `INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at) ` +
            `VALUES ('${uuid(seq)}', '${NODE_ID}', '${walletId}', 'BLESSED', now());`,
          SQLSTATE_CHECK_VIOLATION,
        );
        const destId = await seedPendingDestination(walletId);
        await mustReject(
          `UPDATE destinations SET blessed_at = now() WHERE id = '${destId}';`,
          SQLSTATE_CHECK_VIOLATION,
        );
        await must(
          `UPDATE destinations SET state = 'BLESSED', blessed_at = now(), ` +
            `blessed_by_device_key_id = '${uuid(910)}', blessing_artifact_id = '${uuid(911)}' ` +
            `WHERE id = '${destId}';`,
        );
        expect(await must(`SELECT state FROM destinations WHERE id = '${destId}';`)).toBe(
          "BLESSED",
        );
      });
    });
  },
);

it("guard: lifecycle drills must execute under PG_REQUIRED=1", () => {
  if (PG_REQUIRED && !TEST_DATABASE_URL) {
    throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unset — harness is broken");
  }
  if (PG_REQUIRED && TEST_DATABASE_URL && !schemaReady) {
    throw new Error("PG_REQUIRED=1 but custody schema failed to apply");
  }
  expect(true).toBe(true);
});
