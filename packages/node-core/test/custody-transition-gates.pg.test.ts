// Destination and custody TRANSITION gates, raced against a real
// PostgreSQL by separate OS processes.
//
// Governing:
// the API contract ("both predicates are
// rechecked at execution time"), ("retirement prevents new selection immediately …
// never rewrites an existing signed operation"), (cross-tenant collapses to
//     not_found, never a 403 that confirms existence)
// the custody rules (custody
// classification), (imported-wallet launch rule), (a NEEDS_ATTENTION lease remains
//     held or the wallet is quarantined until human-gated resolution)
// the data model (wallets/destinations
// CHECKs + triggers), (wallet_active_leases fencing)
// the test plan ("Run real database
//     concurrency tests, not only mocked unit tests")
//   the FOR UPDATE on the lease guard
//
// What makes this suite different from its siblings:
//   - custody-eligibility.pg.test.ts proves each CHECK/trigger in ISOLATION, one statement at
//     a time. It cannot observe a transition racing a read.
//   - wallet-lease-lock-contention.pg.test.ts races two lease ACQUISITIONS against each other.
//     It does not race a lease acquisition against a custody TRANSITION.
//   This file closes exactly that gap: every drill below has one process mutating custody
//   state inside an open transaction while a second process, in its own OS process, tries to
//   claim the wallet. The claimant blocks on the row lock the frozen trigger takes
//   (`SELECT … FOR UPDATE`,(2)) and is then judged against the state that actually
//   committed — which is the whole reason that lock exists.
//
// The DDL is EXECUTED, never pattern-matched, and every rejection is asserted by SQLSTATE plus
// the frozen trigger's own error literal. A rejection asserted only by "it failed" would pass
// on a typo.
//
// Each concurrency drill also asserts the loser BLOCKED (its wall clock covers the winner's
// in-transaction sleep). Without that, two statements that merely happened to run in order
// would read as a race, which is the "passes by construction" failure this suite exists to
// avoid.
//
// Connectivity: TEST_DATABASE_URL is auto-provisioned by vitest.global-setup.ts when
// run through the ROOT vitest project. Under PG_REQUIRED=1 an unreachable server is a broken
// harness, not "no Postgres here" — the fail-closed guard at the bottom turns a silent skip
// into a failure.

import { execFile, execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

import { verifyAutomaticSinkEligibility } from "@zucoins/generic-node-contracts/custody";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  createDestinationService,
  type DestinationRecord,
  type DestinationStore,
  type DestinationWalletFacts,
  type NewDestination,
} from "../src/api/destination.js";
import type { Uuid, WalletPublicKey } from "../src/protocol/scalars.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";

const SQLSTATE_CHECK_VIOLATION = "23514";
const SQLSTATE_RAISE_EXCEPTION = "P0001";

/* ─── psql helpers ────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
  /** Wall-clock ms for the child process — used to prove a contender actually blocked. */
  readonly elapsedMs: number;
}

// VERBOSITY=verbose is unconditional so SQLSTATE appears in stderr as `ERROR:  <sqlstate>:`
// (default verbosity omits the code).
const runPsql = (sql: string, timeoutMs = 30_000): Promise<PsqlOutcome> =>
  new Promise((resolve) => {
    const started = Date.now();
    execFile(
      "psql",
      [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
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

/** Asserts the database REFUSED the statement, by SQLSTATE and by the frozen error literal. */
const mustReject = async (sql: string, sqlstate: string, literal?: string): Promise<void> => {
  const outcome = await runPsql(sql);
  expect(outcome.ok, `expected rejection but the statement succeeded: ${sql}`).toBe(false);
  expect(extractSqlstate(outcome.stderr), `SQLSTATE for: ${sql}\n${outcome.stderr}`).toBe(sqlstate);
  if (literal !== undefined) {
    expect(outcome.stderr, `error literal for: ${sql}`).toContain(literal);
  }
};

/* ─── real frozen DDL — composed, never mirrored ──────────────────── */

const schemaDir = new URL("../src/schema/", import.meta.url);
const readSchema = (file: string): string => readFileSync(new URL(file, schemaDir), "utf-8");

// Every frozen slice re-declares the domains and enums it consumes so it can be applied
// standalone (see the self-containment note at the head of each file). Applying them in
// sequence therefore duplicates whatever base-enums-domains.sql already owns, so the composed
// apply drops exactly those redeclarations and nothing else. Table and trigger text is used
// verbatim: this suite tests the shipped schema, not a mirror of it.
const composeDdl = (): string => {
  const base = readSchema("base-enums-domains.sql");
  const owned = new Set([...base.matchAll(/CREATE (?:DOMAIN|TYPE)\s+(\w+)/g)].map((m) => m[1]));
  const dropOwnedTypes = (sql: string): string => {
    let out = "";
    let cursor = 0;
    for (const m of sql.matchAll(/CREATE (?:DOMAIN|TYPE)\s+(\w+)[\s\S]*?;\n/g)) {
      if (!owned.has(m[1])) continue;
      out += sql.slice(cursor, m.index);
      cursor = m.index + m[0].length;
    }
    return out + sql.slice(cursor);
  };
  const slices = [
    "node-implementer-registry.sql",
    "custody-eligibility.sql",
    "signing-key-registry.sql",
    "operations.sql",
    "expected-artifacts.sql",
  ].map((file) => dropOwnedTypes(readSchema(file)));
  return [base, ...slices].join("\n");
};

/* ─── lifecycle ───────────────────────────────────────────────────── */

// Own prefix, own database. Teardown drops ONLY the database this run created — several lanes
// share this server and a broader DROP takes their data with it.
const scratchDb = `custody_transition_transitions_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;
/** Counts drills that raced two real OS processes; the fail-closed guard checks it. */
let concurrentDrills = 0;
const EXPECTED_CONCURRENT_DRILLS = 7;

const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

const adminPsql = (sql: string): void => {
  execFileSync("psql", [TEST_DATABASE_URL, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
    encoding: "utf-8",
    timeout: 60_000,
  });
};

/* ─── fixtures ────────────────────────────────────────────────────── */

const NODE_A = "b0000000-0000-4000-8000-000000000323";
const NODE_B = "b0000000-0000-4000-8000-000000000324";
const IMPLEMENTER_A = "c0000000-0000-4000-8000-000000000323";
const SIGNING_KEY_ID = "d0000000-0000-4000-8000-000000000323";
const EXPORT_SHA = "a".repeat(64);
const PREIMAGE_SHA = "b".repeat(64);
const REQUEST_SHA = "c".repeat(64);
// padded_base64url_signature: 86 base64url chars + '=='.
const ARTIFACT_SIGNATURE = `${"S".repeat(86)}==`;

let seq = 0;
const pubkey = (): string => {
  seq += 1;
  const suffix = String(seq).padStart(12, "0");
  return `${"A".repeat(43 - suffix.length)}${suffix}=`;
};

const LEASE_ROLES = [
  "RECEIVE_WINDOW",
  "MOVE_SOURCE",
  "MOVE_DESTINATION",
  "SEND_SOURCE",
  "RECONCILIATION",
] as const;

/** data-model fencing columns are NOT NULL; fresh identifiers keep the wallet_id PK the sole bar. */
const leaseInsert = (walletId: string, role: string, tail = ";"): string =>
  `INSERT INTO wallet_active_leases (wallet_id, membership_id, lease_group_id, ` +
  `root_operation_id, operation_id, lease_role, lease_epoch, acquired_at, heartbeat_at, ` +
  `owner_instance_id) VALUES ('${walletId}', '${randomUUID()}', '${randomUUID()}', ` +
  `'${randomUUID()}', '${randomUUID()}', '${role}', 1, now(), now(), '${randomUUID()}')${tail}`;

interface Wallet {
  readonly walletId: string;
  readonly publicKey: string;
  readonly destinationId: string;
  readonly verificationId: string;
}

/**
 * Seeds one wallet plus (optionally) its recovery evidence and its destination row.
 * Returns the identifiers so a drill can mutate exactly the row it owns — no drill shares a
 * wallet with another, so none can pass on another's state.
 */
const seedWallet = async (opts: {
  readonly origin?: "node_generated" | "imported";
  readonly nodeId?: string;
  readonly recoveryVerified?: boolean;
  readonly destination?: "none" | "PENDING" | "BLESSED";
} = {}): Promise<Wallet> => {
  const origin = opts.origin ?? "node_generated";
  const nodeId = opts.nodeId ?? NODE_A;
  const wallet: Wallet = {
    walletId: randomUUID(),
    publicKey: pubkey(),
    destinationId: randomUUID(),
    verificationId: randomUUID(),
  };
  const statements = [
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) VALUES ` +
      `('${wallet.walletId}', '${nodeId}', '${wallet.publicKey}', '${origin}', 'AVAILABLE');`,
    // Evidence is always seeded; whether it is STAMPED onto the wallet is the gate.
    `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `VALUES ('${wallet.verificationId}', '${wallet.walletId}', 'AUDITED_EXPORT', '${EXPORT_SHA}', ` +
      `'${wallet.publicKey}', '${randomUUID()}', now(), 'custody-transition-test');`,
  ];
  if (opts.recoveryVerified === true) {
    statements.push(
      `UPDATE wallets SET recovery_verified_at = now(), ` +
        `recovery_verification_id = '${wallet.verificationId}' WHERE id = '${wallet.walletId}';`,
    );
  }
  const destination = opts.destination ?? "none";
  if (destination === "PENDING") {
    statements.push(
      `INSERT INTO destinations (id, node_id, wallet_id, state) VALUES ` +
        `('${wallet.destinationId}', '${nodeId}', '${wallet.walletId}', 'PENDING');`,
    );
  } else if (destination === "BLESSED") {
    statements.push(
      `INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at, ` +
        `blessed_by_device_key_id, blessing_artifact_id) VALUES ` +
        `('${wallet.destinationId}', '${nodeId}', '${wallet.walletId}', 'BLESSED', now(), ` +
        `'${randomUUID()}', '${randomUUID()}');`,
    );
  }
  await must(statements.join(" "));
  return wallet;
};

const blessStatement = (wallet: Wallet): string =>
  `UPDATE destinations SET state = 'BLESSED', blessed_at = now(), ` +
  `blessed_by_device_key_id = '${randomUUID()}', blessing_artifact_id = '${randomUUID()}' ` +
  `WHERE id = '${wallet.destinationId}';`;

const quarantineStatement = (wallet: Wallet, reason: string): string =>
  `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = '${reason}' ` +
  `WHERE id = '${wallet.walletId}';`;

const verifyRecoveryStatement = (wallet: Wallet): string =>
  `UPDATE wallets SET recovery_verified_at = now(), ` +
  `recovery_verification_id = '${wallet.verificationId}' WHERE id = '${wallet.walletId}';`;

const leaseCount = async (walletId: string): Promise<number> =>
  Number(await must(`SELECT count(*)::int FROM wallet_active_leases WHERE wallet_id = '${walletId}';`));

/** The exact bytes of a row, so "unchanged" is byte-exact and not a field spot-check. */
const rowBytes = async (table: string, where: string): Promise<string> =>
  must(
    `SELECT coalesce(json_agg(row_to_json(t) ORDER BY t), '[]'::json)::text FROM ` +
      `(SELECT * FROM ${table} WHERE ${where}) t;`,
  );

/**
 * The authoritative facts the frozen contract verifier judges, read back from the database.
 * Every drill compares the verifier's verdict to what the database actually did, so the
 * runtime gate and `packages/generic-node-contracts` cannot silently diverge under race.
 */
const readFacts = async (
  wallet: Wallet,
): Promise<{ keyOrigin: string; destinationState: string | null; recoveryVerifiedAt: string | null; walletState: string }> => {
  const raw = await must(
    `SELECT json_build_object(` +
      `'keyOrigin', w.key_origin, 'walletState', w.state, ` +
      `'recoveryVerifiedAt', to_char(w.recovery_verified_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), ` +
      `'destinationState', d.state)::text ` +
      `FROM wallets w LEFT JOIN destinations d ON d.wallet_id = w.id WHERE w.id = '${wallet.walletId}';`,
  );
  return JSON.parse(raw) as {
    keyOrigin: string;
    destinationState: string | null;
    recoveryVerifiedAt: string | null;
    walletState: string;
  };
};

/** Asserts the frozen predicate verifier reaches the same verdict the database enforced. */
const expectContractAgrees = async (wallet: Wallet, dbAccepted: boolean): Promise<void> => {
  const facts = await readFacts(wallet);
  const decision = verifyAutomaticSinkEligibility(facts);
  expect(
    decision.eligible,
    `frozen automatic_sink_eligible disagreed with the database for ${JSON.stringify(facts)}`,
  ).toBe(dbAccepted);
};

/**
 * Real-PG DestinationStore for scenario 6. Tenant isolation is enforced by the production
 * DestinationService (nodeId on every call) against rows that actually live in Postgres —
 * not by a hand-written `WHERE node_id = B` identity filter in the assertion itself.
 */
const mapDestination = (row: Record<string, unknown>): DestinationRecord => ({
  destinationId: String(row.id) as Uuid,
  nodeId: String(row.node_id) as Uuid,
  walletId: String(row.wallet_id) as Uuid,
  walletPublicKey: String(row.wallet_public_key) as WalletPublicKey,
  state: row.state as DestinationRecord["state"],
  label: String(row.label ?? ""),
  blessedAt: row.blessed_at === null || row.blessed_at === undefined ? null : String(row.blessed_at),
  blessedByDeviceKeyId:
    row.blessed_by_device_key_id === null || row.blessed_by_device_key_id === undefined
      ? null
      : (String(row.blessed_by_device_key_id) as Uuid),
  blessingArtifactId:
    row.blessing_artifact_id === null || row.blessing_artifact_id === undefined
      ? null
      : (String(row.blessing_artifact_id) as Uuid),
  retiredAt: row.retired_at === null || row.retired_at === undefined ? null : String(row.retired_at),
  createdAt: String(row.created_at),
});

const loadDestinationRow = async (destinationId: string): Promise<DestinationRecord | null> => {
  const raw = await must(
    `SELECT coalesce((SELECT row_to_json(x) FROM (` +
      `SELECT d.id, d.node_id, d.wallet_id, w.public_key AS wallet_public_key, d.state, ` +
      `''::text AS label, d.blessed_at, d.blessed_by_device_key_id, d.blessing_artifact_id, ` +
      `d.retired_at, d.created_at FROM destinations d JOIN wallets w ON w.id = d.wallet_id ` +
      `WHERE d.id = '${destinationId}') x), 'null'::json)::text;`,
  );
  if (raw === "null") return null;
  return mapDestination(JSON.parse(raw) as Record<string, unknown>);
};

const createPgDestinationStore = (): DestinationStore => ({
  findById: (destinationId) => loadDestinationRow(destinationId),
  async findByIdempotencyKey() {
    return null;
  },
  async insert(record: NewDestination) {
    await must(
      `INSERT INTO destinations (id, node_id, wallet_id, state, created_at) VALUES (` +
        `'${record.destinationId}', '${record.nodeId}', '${record.walletId}', 'PENDING', ` +
        `'${record.createdAt}');`,
    );
    return {
      ...record,
      state: "PENDING",
      blessedAt: null,
      blessedByDeviceKeyId: null,
      blessingArtifactId: null,
      retiredAt: null,
    };
  },
  async walletKeyOrigin(walletId) {
    const raw = await must(
      `SELECT coalesce((SELECT key_origin FROM wallets WHERE id = '${walletId}'), '')`,
    );
    if (raw === "") return null;
    return raw as "node_generated" | "imported";
  },
  async walletFacts(walletId): Promise<DestinationWalletFacts | null> {
    const raw = await must(
      `SELECT coalesce((SELECT row_to_json(x) FROM (` +
        `SELECT key_origin, state, ` +
        `to_char(recovery_verified_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') ` +
        `AS recovery_verified_at FROM wallets WHERE id = '${walletId}') x), 'null'::json)::text;`,
    );
    if (raw === "null") return null;
    const row = JSON.parse(raw) as {
      key_origin: string;
      state: string;
      recovery_verified_at: string | null;
    };
    return {
      keyOrigin: row.key_origin as DestinationWalletFacts["keyOrigin"],
      walletState: row.state as DestinationWalletFacts["walletState"],
      recoveryVerifiedAt: row.recovery_verified_at,
    };
  },
  async bless(destinationId, patch) {
    const raw = await must(
      `WITH u AS (` +
        `UPDATE destinations SET state = 'BLESSED', blessed_at = '${patch.blessedAt}', ` +
        `blessed_by_device_key_id = '${patch.blessedByDeviceKeyId}', ` +
        `blessing_artifact_id = '${patch.blessingArtifactId}' ` +
        `WHERE id = '${destinationId}' AND state = 'PENDING' RETURNING id` +
        `) SELECT count(*)::int FROM u;`,
    );
    if (raw === "0") return null;
    return loadDestinationRow(destinationId);
  },
  async retire(destinationId, retiredAt) {
    await must(
      `UPDATE destinations SET state = 'RETIRED', retired_at = '${retiredAt}' ` +
        `WHERE id = '${destinationId}';`,
    );
    const row = await loadDestinationRow(destinationId);
    if (row === null) throw new Error(`retire missed ${destinationId}`);
    return row;
  },
  async list(nodeId, filter) {
    const stateClause =
      filter.state === undefined ? "" : ` AND d.state = '${filter.state}'`;
    const afterClause =
      filter.after === undefined ? "" : ` AND d.id > '${filter.after}'`;
    const limit = filter.limit ?? 20;
    const raw = await must(
      `SELECT coalesce(json_agg(row_to_json(x) ORDER BY x.id), '[]'::json)::text FROM (` +
        `SELECT d.id, d.node_id, d.wallet_id, w.public_key AS wallet_public_key, d.state, ` +
        `''::text AS label, d.blessed_at, d.blessed_by_device_key_id, d.blessing_artifact_id, ` +
        `d.retired_at, d.created_at FROM destinations d JOIN wallets w ON w.id = d.wallet_id ` +
        `WHERE d.node_id = '${nodeId}'${stateClause}${afterClause} ` +
        `ORDER BY d.id LIMIT ${limit + 1}) x;`,
    );
    const rows = (JSON.parse(raw) as Record<string, unknown>[]).map(mapDestination);
    const items = rows.slice(0, limit);
    const nextAfter =
      rows.length > limit ? (items[items.length - 1]?.destinationId ?? null) : null;
    return { items, nextAfter };
  },
});

/** Production DestinationService bound to the live scratch database. */
const destinationServiceForScratch = () =>
  createDestinationService({
    store: createPgDestinationStore(),
    keyGenerator: {
      async generate() {
        throw new Error("scenario 6 never mints wallets through the service");
      },
    },
    blessingAuthorizer: {
      async authorize() {
        throw new Error("scenario 6 never blesses through the service");
      },
    },
    clock: { now: () => new Date().toISOString() },
    ids: { destinationId: () => randomUUID() as Uuid },
  });

/**
 * Production-shaped claim path: a tenant may only lease a MOVE_DESTINATION wallet that
 * DestinationService considers selectable (get returns a move_eligible row for that tenant).
 * Bypassing get() is exactly the attack scenario 6 exists to close at the service boundary.
 */
const selectAndClaimMoveDestination = async (
  nodeId: string,
  destinationId: string,
): Promise<{ readonly ok: true } | { readonly ok: false; readonly reason: "not_selectable" }> => {
  const service = destinationServiceForScratch();
  const item = await service.get(nodeId as Uuid, destinationId as Uuid);
  if (item === null || !item.move_eligible) {
    return { ok: false, reason: "not_selectable" };
  }
  const outcome = await runPsql(leaseInsert(item.walletId, "MOVE_DESTINATION"));
  if (!outcome.ok) {
    throw new Error(`eligible claim rejected: ${outcome.stderr}`);
  }
  return { ok: true };
};

beforeAll(() => {
  if (!TEST_DATABASE_URL) return;
  adminPsql(`CREATE DATABASE ${scratchDb}`);
  scratchDbUrl = withDatabase(TEST_DATABASE_URL, scratchDb);
  // The apply is the first assertion: the composed frozen contract must load in one
  // transaction, or nothing below runs.
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: composeDdl(),
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
         ('${NODE_A}', 'custody-transition-a', '${"N".repeat(43)}='),
         ('${NODE_B}', 'custody-transition-b', '${"O".repeat(43)}=');
       INSERT INTO implementers (id, name) VALUES ('${IMPLEMENTER_A}', 'custody-transition-impl');
       INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
         VALUES ('${SIGNING_KEY_ID}', '${NODE_A}', 'NODE_IDENTITY', '${"K".repeat(43)}=',
                 '${randomUUID()}', now());`,
    ],
    { encoding: "utf-8", timeout: 20_000 },
  );
  schemaReady = true;
}, 90_000);

// Explicit budget: several lanes share this server, and a saturated one makes DROP DATABASE
// slower than vitest's 30s hook default — which reddens the whole FILE on teardown alone.
afterAll(() => {
  if (!schemaReady) return;
  try {
    adminPsql(`DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  } catch {
    /* teardown is best-effort; a leaked scratch database must never fail the suite */
  }
}, 90_000);

/* ─── suite ───────────────────────────────────────────────────────── */

describe.skipIf(!TEST_DATABASE_URL)(
  "custody transition gates under real concurrency",
  { timeout: 180_000 },
  () => {
    /* 1. Bless vs concurrent move-selection ───────────────────────── */

    describe("scenario 1 — blessing races a MOVE_INTERNAL destination selection", () => {
      it("a selection that raced an ABANDONED blessing is rejected, not admitted", async () => {
        const wallet = await seedWallet({ recoveryVerified: true, destination: "PENDING" });

        // Blesser holds the destinations row lock for 600ms, then abandons the ceremony.
        const blesser = runPsql(
          `BEGIN; ${blessStatement(wallet)} SELECT pg_sleep(0.6); ROLLBACK; SELECT 'abandoned';`,
        );
        // Selector starts 150ms in, so its lease insert is already inside the blesser's
        // window. The frozen trigger's `SELECT … FROM destinations … FOR UPDATE` blocks it.
        const selector = runPsql(
          `SELECT pg_sleep(0.15); BEGIN; ${leaseInsert(wallet.walletId, "MOVE_DESTINATION")} COMMIT;`,
        );
        const [blessOutcome, selectOutcome] = await Promise.all([blesser, selector]);

        expect(blessOutcome.ok).toBe(true);
        expect(selectOutcome.ok, "the move must not land against an unblessed destination").toBe(false);
        expect(extractSqlstate(selectOutcome.stderr)).toBe(SQLSTATE_RAISE_EXCEPTION);
        expect(selectOutcome.stderr).toContain("CUSTODY_LEASE_DESTINATION_NOT_BLESSED");
        // Proof this was a real race: the selector's wall clock covers the blesser's
        // in-transaction sleep, so it blocked on the lock rather than simply running after.
        expect(selectOutcome.elapsedMs).toBeGreaterThanOrEqual(600);
        expect(await leaseCount(wallet.walletId)).toBe(0);
        expect((await must(`SELECT state FROM destinations WHERE id = '${wallet.destinationId}';`))).toBe(
          "PENDING",
        );
        await expectContractAgrees(wallet, false);
        concurrentDrills += 1;
      });

      it("the same selection succeeds once the blessing commits — the gate is state, not timing", async () => {
        const wallet = await seedWallet({ recoveryVerified: true, destination: "PENDING" });
        const blesser = runPsql(
          `BEGIN; ${blessStatement(wallet)} SELECT pg_sleep(0.4); COMMIT; SELECT 'blessed';`,
        );
        const selector = runPsql(
          `SELECT pg_sleep(0.1); BEGIN; ${leaseInsert(wallet.walletId, "MOVE_DESTINATION")} COMMIT;`,
        );
        const [blessOutcome, selectOutcome] = await Promise.all([blesser, selector]);

        expect(blessOutcome.ok).toBe(true);
        expect(selectOutcome.ok, selectOutcome.stderr).toBe(true);
        expect(selectOutcome.elapsedMs).toBeGreaterThanOrEqual(400);
        expect(await leaseCount(wallet.walletId)).toBe(1);
        await expectContractAgrees(wallet, true);
        concurrentDrills += 1;
      });
    });

    /* 2. Recovery verification vs automatic-sink selection ────────── */

    describe("scenario 2 — recovery verification races automatic-sink selection", () => {
      it("a sink selection that raced an ABANDONED verification is rejected", async () => {
        const wallet = await seedWallet({ destination: "BLESSED" });
        const verifier = runPsql(
          `BEGIN; ${verifyRecoveryStatement(wallet)} SELECT pg_sleep(0.6); ROLLBACK; SELECT 'abandoned';`,
        );
        const selector = runPsql(
          `SELECT pg_sleep(0.15); BEGIN; ${leaseInsert(wallet.walletId, "MOVE_DESTINATION")} COMMIT;`,
        );
        const [verifyOutcome, selectOutcome] = await Promise.all([verifier, selector]);

        expect(verifyOutcome.ok).toBe(true);
        expect(selectOutcome.ok).toBe(false);
        expect(extractSqlstate(selectOutcome.stderr)).toBe(SQLSTATE_RAISE_EXCEPTION);
        expect(selectOutcome.stderr).toContain("CUSTODY_LEASE_RECOVERY_UNVERIFIED");
        expect(selectOutcome.elapsedMs).toBeGreaterThanOrEqual(600);
        expect(await leaseCount(wallet.walletId)).toBe(0);
        expect(
          await must(`SELECT coalesce(recovery_verified_at::text, 'NULL') FROM wallets WHERE id = '${wallet.walletId}';`),
        ).toBe("NULL");
        await expectContractAgrees(wallet, false);
        concurrentDrills += 1;
      });

      it("the two recovery columns cannot be set one at a time — the pairing is atomic", async () => {
        // data-model rule 5. This is what makes the race above winnable-or-losable but never
        // half-applied: no interleaving can leave a timestamp without its evidence pointer.
        const wallet = await seedWallet({ destination: "BLESSED" });
        await mustReject(
          `UPDATE wallets SET recovery_verified_at = now() WHERE id = '${wallet.walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
          "wallets_recovery_fields_together",
        );
        await mustReject(
          `UPDATE wallets SET recovery_verification_id = '${wallet.verificationId}' WHERE id = '${wallet.walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
          "wallets_recovery_fields_together",
        );
        await must(verifyRecoveryStatement(wallet));
        await expectContractAgrees(wallet, true);
      });
    });

    /* 3. Quarantine vs an active lease ───────────────────────────── */

    describe("scenario 3 — quarantine and an active lease", () => {
      it("quarantining a leased wallet leaves the lease held, byte-identical", async () => {
        const wallet = await seedWallet({ recoveryVerified: true, destination: "BLESSED" });
        await must(leaseInsert(wallet.walletId, "MOVE_DESTINATION"));
        const before = await rowBytes("wallet_active_leases", `wallet_id = '${wallet.walletId}'`);

        await must(quarantineStatement(wallet, "needs attention: ambiguous submit"));

        // "A NEEDS_ATTENTION lease remains held or the wallet is quarantined until
        // human-gated resolution" — held, not force-released, and not silently rewritten.
        expect(await rowBytes("wallet_active_leases", `wallet_id = '${wallet.walletId}'`)).toBe(before);
        expect(await leaseCount(wallet.walletId)).toBe(1);
        await expectContractAgrees(wallet, false);

        // Once the operator resolves and the lease is released, the wallet is no longer
        // claimable — the quarantine is a real gate, not a label.
        await must(`DELETE FROM wallet_active_leases WHERE wallet_id = '${wallet.walletId}';`);
        await mustReject(
          leaseInsert(wallet.walletId, "MOVE_DESTINATION"),
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_LEASE_WALLET_STATE_REJECTED",
        );
      });

      it("a claim that raced an in-flight quarantine is rejected once it commits", async () => {
        const wallet = await seedWallet({ recoveryVerified: true, destination: "BLESSED" });
        // (2) exists for exactly this: the lease guard locks the wallet row, so a
        // claimant cannot read pre-quarantine state and commit against it.
        const quarantiner = runPsql(
          `BEGIN; ${quarantineStatement(wallet, "operator hold")} SELECT pg_sleep(0.6); COMMIT; SELECT 'held';`,
        );
        const claimant = runPsql(
          `SELECT pg_sleep(0.15); BEGIN; ${leaseInsert(wallet.walletId, "MOVE_DESTINATION")} COMMIT;`,
        );
        const [quarantineOutcome, claimOutcome] = await Promise.all([quarantiner, claimant]);

        expect(quarantineOutcome.ok).toBe(true);
        expect(claimOutcome.ok).toBe(false);
        expect(extractSqlstate(claimOutcome.stderr)).toBe(SQLSTATE_RAISE_EXCEPTION);
        expect(claimOutcome.stderr).toContain("CUSTODY_LEASE_WALLET_STATE_REJECTED");
        expect(claimOutcome.elapsedMs).toBeGreaterThanOrEqual(600);
        expect(await leaseCount(wallet.walletId)).toBe(0);
        await expectContractAgrees(wallet, false);
        concurrentDrills += 1;
      });

      it("a quarantine without a reason is refused outright (wallets_quarantine_reason_iff)", async () => {
        const wallet = await seedWallet({ recoveryVerified: true, destination: "BLESSED" });
        await mustReject(
          `UPDATE wallets SET state = 'QUARANTINED' WHERE id = '${wallet.walletId}';`,
          SQLSTATE_CHECK_VIOLATION,
          "wallets_quarantine_reason_iff",
        );
        expect(await must(`SELECT state FROM wallets WHERE id = '${wallet.walletId}';`)).toBe("AVAILABLE");
      });
    });

    /* 4. Retire vs an in-flight operation ────────────────────────── */

    describe("scenario 4 — retirement and an in-flight signed operation", () => {
      it("retirement leaves the lease and the signed artifact byte-identical", async () => {
        const source = await seedWallet({ recoveryVerified: true, destination: "BLESSED" });
        const sink = await seedWallet({ recoveryVerified: true, destination: "BLESSED" });
        const operationId = randomUUID();

        await must(
          `INSERT INTO operations (id, node_id, implementer_id, kind, status, amount_zkz, ` +
            `source_wallet_id, destination_id, idempotency_key, request_sha256) VALUES ` +
            `('${operationId}', '${NODE_A}', '${IMPLEMENTER_A}', 'MOVE_INTERNAL', 'CREATED', ` +
            `'0.01', '${source.walletId}', '${sink.destinationId}', 'custody-transition-move-idem-0001', ` +
            `'${REQUEST_SHA}');` +
            `INSERT INTO operation_expected_artifacts (id, operation_id, purpose, canonical_version, ` +
            `signing_key_id, preimage_text, preimage_sha256, signature) VALUES ` +
            `('${randomUUID()}', '${operationId}', 'zp-move-internal-expected-v1', 1, ` +
            `'${SIGNING_KEY_ID}', '{"exact":"preimage"}', '${PREIMAGE_SHA}', '${ARTIFACT_SIGNATURE}');` +
            leaseInsert(sink.walletId, "MOVE_DESTINATION") +
            leaseInsert(source.walletId, "MOVE_SOURCE"),
        );

        const artifactBefore = await rowBytes(
          "operation_expected_artifacts",
          `operation_id = '${operationId}'`,
        );
        const operationBefore = await rowBytes("operations", `id = '${operationId}'`);
        const leasesBefore = await rowBytes(
          "wallet_active_leases",
          `wallet_id IN ('${source.walletId}', '${sink.walletId}')`,
        );

        await must(
          `UPDATE destinations SET state = 'RETIRED', retired_at = now() WHERE id = '${sink.destinationId}';`,
        );

        // The byte-exact signing rule applied to the custody-administration surface: retirement never
        // rewrites, re-derives, or orphans an already-signed operation.
        expect(
          await rowBytes("operation_expected_artifacts", `operation_id = '${operationId}'`),
          "retirement rewrote a signed expected artifact",
        ).toBe(artifactBefore);
        expect(await rowBytes("operations", `id = '${operationId}'`)).toBe(operationBefore);
        expect(
          await rowBytes(
            "wallet_active_leases",
            `wallet_id IN ('${source.walletId}', '${sink.walletId}')`,
          ),
          "retirement released or altered a lease",
        ).toBe(leasesBefore);

        // Forward-looking only: new selection is barred from this moment on.
        await must(`DELETE FROM wallet_active_leases WHERE wallet_id = '${sink.walletId}';`);
        await mustReject(
          leaseInsert(sink.walletId, "MOVE_DESTINATION"),
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_LEASE_DESTINATION_NOT_BLESSED",
        );
        await expectContractAgrees(sink, false);
      });

      it("nothing cascades off destinations — no trigger and no CASCADE reaches an operation", async () => {
        // The byte-equality above is an observation of one run; this is the structural reason
        // it holds. A future ON DELETE/UPDATE CASCADE or an AFTER UPDATE trigger on
        // destinations would be the mechanism by which retirement could touch signed rows.
        // The one trigger destinations carries is the BEFORE INSERT origin/tenant guard. A
        // trigger that fired on UPDATE is the only shape that could react to a retirement.
        const triggers = await must(
          `SELECT coalesce(string_agg(tgname || ' => ' || pg_get_triggerdef(oid), E'\\n' ORDER BY tgname), '') ` +
            `FROM pg_trigger WHERE tgrelid = 'destinations'::regclass AND NOT tgisinternal;`,
        );
        expect(triggers.split("\n").map((line) => line.split(" => ")[0])).toEqual([
          "destinations_custody_insert_guard",
        ]);
        expect(triggers).toContain("BEFORE INSERT ON public.destinations");
        expect(triggers).not.toContain("UPDATE");
        expect(triggers).not.toContain("DELETE");
        const cascades = await must(
          `SELECT coalesce(string_agg(conname || ':' || confupdtype::text || confdeltype::text, ','), '') ` +
            `FROM pg_constraint WHERE confrelid = 'destinations'::regclass AND contype = 'f' ` +
            `AND (confupdtype <> 'a' OR confdeltype <> 'a');`,
        );
        expect(cascades, "a foreign key to destinations carries a non-NO ACTION rule").toBe("");
        // Non-vacuity: the same query DOES see the foreign keys that exist.
        expect(
          Number(
            await must(
              `SELECT count(*)::int FROM pg_constraint WHERE confrelid = 'destinations'::regclass AND contype = 'f';`,
            ),
          ),
        ).toBeGreaterThan(0);
      });

      it("a claim that raced an ABANDONED retirement is admitted once the lock releases", async () => {
        // Symmetric to scenario 1's abandon path, but for retire: an operator who opens a
        // retirement and rolls back must not permanently bar a concurrent selector. The
        // claimant blocks on destinations FOR UPDATE, then sees BLESSED and lands.
        const wallet = await seedWallet({ recoveryVerified: true, destination: "BLESSED" });
        const retirer = runPsql(
          `BEGIN; UPDATE destinations SET state = 'RETIRED', retired_at = now() ` +
            `WHERE id = '${wallet.destinationId}'; SELECT pg_sleep(0.6); ROLLBACK; SELECT 'abandoned';`,
        );
        const selector = runPsql(
          `SELECT pg_sleep(0.15); BEGIN; ${leaseInsert(wallet.walletId, "MOVE_DESTINATION")} COMMIT;`,
        );
        const [retireOutcome, selectOutcome] = await Promise.all([retirer, selector]);

        expect(retireOutcome.ok).toBe(true);
        expect(selectOutcome.ok, selectOutcome.stderr).toBe(true);
        expect(selectOutcome.elapsedMs).toBeGreaterThanOrEqual(600);
        expect(await leaseCount(wallet.walletId)).toBe(1);
        expect(await must(`SELECT state FROM destinations WHERE id = '${wallet.destinationId}';`)).toBe(
          "BLESSED",
        );
        await expectContractAgrees(wallet, true);
        concurrentDrills += 1;
      });

      it("a claim that raced a COMMITTED retirement is rejected against post-commit state", async () => {
        // Checklist: race retire with move selection. The trigger's destinations FOR UPDATE
        // serializes the claim behind the retirement; once RETIRED commits the claim is judged
        // against that state and raises CUSTODY_LEASE_DESTINATION_NOT_BLESSED.
        const wallet = await seedWallet({ recoveryVerified: true, destination: "BLESSED" });
        const retirer = runPsql(
          `BEGIN; UPDATE destinations SET state = 'RETIRED', retired_at = now() ` +
            `WHERE id = '${wallet.destinationId}'; SELECT pg_sleep(0.6); COMMIT; SELECT 'retired';`,
        );
        const selector = runPsql(
          `SELECT pg_sleep(0.15); BEGIN; ${leaseInsert(wallet.walletId, "MOVE_DESTINATION")} COMMIT;`,
        );
        const [retireOutcome, selectOutcome] = await Promise.all([retirer, selector]);

        expect(retireOutcome.ok).toBe(true);
        expect(selectOutcome.ok, "move must not land against a retired destination").toBe(false);
        expect(extractSqlstate(selectOutcome.stderr)).toBe(SQLSTATE_RAISE_EXCEPTION);
        expect(selectOutcome.stderr).toContain("CUSTODY_LEASE_DESTINATION_NOT_BLESSED");
        expect(selectOutcome.elapsedMs).toBeGreaterThanOrEqual(600);
        expect(await leaseCount(wallet.walletId)).toBe(0);
        expect(await must(`SELECT state FROM destinations WHERE id = '${wallet.destinationId}';`)).toBe(
          "RETIRED",
        );
        await expectContractAgrees(wallet, false);
        concurrentDrills += 1;
      });
    });

    /* 5. Imported-wallet rejection ───────────────────────────────── */

    describe("scenario 5 — imported wallets are structurally excluded", () => {
      it("cannot become a destination even by a direct database write", async () => {
        const imported = await seedWallet({ origin: "imported" });
        await mustReject(
          `INSERT INTO destinations (id, node_id, wallet_id, state) VALUES ` +
            `('${imported.destinationId}', '${NODE_A}', '${imported.walletId}', 'PENDING');`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_DESTINATION_ORIGIN_REJECTED",
        );
        expect(
          await must(`SELECT count(*)::int FROM destinations WHERE wallet_id = '${imported.walletId}';`),
        ).toBe("0");
      });

      it("carries no lease role at all — the origin conjunct holds at every claim boundary", async () => {
        const imported = await seedWallet({ origin: "imported" });
        for (const role of LEASE_ROLES) {
          await mustReject(
            leaseInsert(imported.walletId, role),
            SQLSTATE_RAISE_EXCEPTION,
            "CUSTODY_LEASE_ORIGIN_REJECTED",
          );
        }
        expect(await leaseCount(imported.walletId)).toBe(0);
      });

      it("stays rejected while a legitimate blessing commits alongside it", async () => {
        const imported = await seedWallet({ origin: "imported" });
        const legitimate = await seedWallet({ recoveryVerified: true, destination: "PENDING" });

        const blesser = runPsql(
          `BEGIN; ${blessStatement(legitimate)} SELECT pg_sleep(0.4); COMMIT; SELECT 'blessed';`,
        );
        const smuggler = runPsql(
          `SELECT pg_sleep(0.1); INSERT INTO destinations (id, node_id, wallet_id, state) VALUES ` +
            `('${imported.destinationId}', '${NODE_A}', '${imported.walletId}', 'PENDING');`,
        );
        const [blessOutcome, smuggleOutcome] = await Promise.all([blesser, smuggler]);

        expect(blessOutcome.ok, blessOutcome.stderr).toBe(true);
        expect(smuggleOutcome.ok).toBe(false);
        expect(smuggleOutcome.stderr).toContain("CUSTODY_DESTINATION_ORIGIN_REJECTED");
        expect(await must(`SELECT state FROM destinations WHERE id = '${legitimate.destinationId}';`)).toBe(
          "BLESSED",
        );
        await expectContractAgrees(legitimate, true);
        await expectContractAgrees(imported, false);
        concurrentDrills += 1;
      });
    });

    /* 6. Wrong-tenant rejection ──────────────────────────────────── */

    describe("scenario 6 — cross-tenant access", () => {
      it("cannot register a destination for another tenant's wallet", async () => {
        const wallet = await seedWallet({ nodeId: NODE_A });
        await mustReject(
          `INSERT INTO destinations (id, node_id, wallet_id, state) VALUES ` +
            `('${wallet.destinationId}', '${NODE_B}', '${wallet.walletId}', 'PENDING');`,
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_TENANT_MISMATCH_REJECTED",
        );
      });

      it("is never visible, selectable, or retirable through DestinationService for the other tenant", async () => {
        // Tenant isolation for destinations is owned by DestinationService (nodeId on every
        // call), not by a raw SQL filter in the assertion. The store underneath reads real
        // Postgres rows; the service is what collapses cross-tenant to not_found / empty.
        const wallet = await seedWallet({
          nodeId: NODE_A,
          recoveryVerified: true,
          destination: "BLESSED",
        });
        // A wallet owned by B so list(NODE_B) is non-empty for the wrong reason if scoping
        // ever widened — and so owner non-vacuity has a positive control on the same service.
        const bOwn = await seedWallet({
          nodeId: NODE_B,
          recoveryVerified: true,
          destination: "BLESSED",
        });
        const service = destinationServiceForScratch();
        const absentId = randomUUID() as Uuid;

        // Visible: get for B of A's id is identical to get of a random absent id (both null).
        const crossGet = await service.get(NODE_B as Uuid, wallet.destinationId as Uuid);
        const absentGet = await service.get(NODE_B as Uuid, absentId);
        expect(crossGet).toBeNull();
        expect(absentGet).toBeNull();
        expect(crossGet).toEqual(absentGet);

        // Selectable: B's list never surfaces A's destination, even when A is move_eligible.
        // Non-vacuity: the same service marks it move_eligible for its real owner, and B's own
        // destination does appear in B's list.
        const ownerView = await service.get(NODE_A as Uuid, wallet.destinationId as Uuid);
        expect(ownerView).not.toBeNull();
        expect(ownerView?.move_eligible).toBe(true);
        expect(ownerView?.walletId).toBe(wallet.walletId);

        const bList = await service.list(NODE_B as Uuid, {});
        expect(bList.items.map((item) => item.destinationId)).not.toContain(wallet.destinationId);
        expect(bList.items.map((item) => item.destinationId)).toContain(bOwn.destinationId);
        expect(bList.items.every((item) => item.nodeId === NODE_B)).toBe(true);

        // Selectable at the claim boundary the suite owns: production-shaped select-then-claim.
        // B cannot obtain a MOVE_DESTINATION lease on A's wallet through that path; A can.
        const bClaim = await selectAndClaimMoveDestination(NODE_B, wallet.destinationId);
        expect(bClaim).toEqual({ ok: false, reason: "not_selectable" });
        expect(await leaseCount(wallet.walletId)).toBe(0);

        const aClaim = await selectAndClaimMoveDestination(NODE_A, wallet.destinationId);
        expect(aClaim).toEqual({ ok: true });
        expect(await leaseCount(wallet.walletId)).toBe(1);
        await must(`DELETE FROM wallet_active_leases WHERE wallet_id = '${wallet.walletId}';`);

        // Unretirable: retire authenticated for B collapses to not_found (same as absent id)
        // and leaves the row BLESSED. Owner can still retire afterwards.
        const crossRetire = await service.retire({
          nodeId: NODE_B as Uuid,
          destinationId: wallet.destinationId as Uuid,
        });
        const absentRetire = await service.retire({
          nodeId: NODE_B as Uuid,
          destinationId: absentId,
        });
        expect(crossRetire).toEqual({ status: "not_found", destinationId: wallet.destinationId });
        expect(absentRetire).toEqual({ status: "not_found", destinationId: absentId });
        expect(await must(`SELECT state FROM destinations WHERE id = '${wallet.destinationId}';`)).toBe(
          "BLESSED",
        );

        const ownerRetire = await service.retire({
          nodeId: NODE_A as Uuid,
          destinationId: wallet.destinationId as Uuid,
        });
        expect(ownerRetire.status).toBe("retired");
        expect(await must(`SELECT state FROM destinations WHERE id = '${wallet.destinationId}';`)).toBe(
          "RETIRED",
        );
      });
    });

    /* 7. Unrecoverable target rejected at execution time ──────────── */

    describe("scenario 7 — eligibility is rechecked at execution time", () => {
      it("a stale 'eligible' read does not survive a quarantine committed in between", async () => {
        const wallet = await seedWallet({ recoveryVerified: true, destination: "BLESSED" });

        // The selector's earlier read — genuinely eligible at the time it was taken.
        const staleFacts = await readFacts(wallet);
        expect(verifyAutomaticSinkEligibility(staleFacts).eligible).toBe(true);

        await must(quarantineStatement(wallet, "quarantined after the eligibility read"));

        // Execution time: the claim is judged against current state, not the stale read.
        await mustReject(
          leaseInsert(wallet.walletId, "MOVE_DESTINATION"),
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_LEASE_WALLET_STATE_REJECTED",
        );
        expect(await leaseCount(wallet.walletId)).toBe(0);
        await expectContractAgrees(wallet, false);
      });

      it("a blessed but never recovery-verified wallet is refused at claim time", async () => {
        // custody allows blessing before recovery export for administrative staging, so a
        // selector that checks only `state='BLESSED'` sees a usable destination. The recovery
        // conjunct is what refuses it, and it is enforced where the claim actually happens.
        const wallet = await seedWallet({ destination: "BLESSED" });
        expect(await must(`SELECT state FROM destinations WHERE id = '${wallet.destinationId}';`)).toBe(
          "BLESSED",
        );
        await mustReject(
          leaseInsert(wallet.walletId, "MOVE_DESTINATION"),
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_LEASE_RECOVERY_UNVERIFIED",
        );
        await expectContractAgrees(wallet, false);
      });

      it("a retired destination refuses a claim even though its wallet is otherwise perfect", async () => {
        const wallet = await seedWallet({ recoveryVerified: true, destination: "BLESSED" });
        await must(
          `UPDATE destinations SET state = 'RETIRED', retired_at = now() WHERE id = '${wallet.destinationId}';`,
        );
        expect(await must(`SELECT state FROM wallets WHERE id = '${wallet.walletId}';`)).toBe("AVAILABLE");
        await mustReject(
          leaseInsert(wallet.walletId, "MOVE_DESTINATION"),
          SQLSTATE_RAISE_EXCEPTION,
          "CUSTODY_LEASE_DESTINATION_NOT_BLESSED",
        );
        await expectContractAgrees(wallet, false);
      });
    });
  },
);

/* ─── fail-closed harness guard (pattern) ─────────────────────
 * Top-level, OUTSIDE the gated describe, so it runs even when that block skips itself. Under
 * PG_REQUIRED=1 an unassigned TEST_DATABASE_URL, a schema that never applied, or a run where
 * the concurrency drills never executed is a BROKEN HARNESS — never "no Postgres here".
 * Without this a green report here would prove nothing, which is exactly the vacuous control
 * this suite exists to remove. */
it("custody transition gates must execute under PG_REQUIRED=1 (no silent skip)", () => {
  if (process.env.PG_REQUIRED !== "1") return;
  expect(
    TEST_DATABASE_URL,
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts provisioned no test database, so the live block skipped",
  ).not.toBe("");
  expect(
    schemaReady,
    "PG_REQUIRED=1 but the composed frozen DDL never applied — every assertion below it was skipped, not proven",
  ).toBe(true);
  expect(
    concurrentDrills,
    "PG_REQUIRED=1 but the two-process race drills did not all run — a suite that never raced anything cannot have proven a transition gate",
  ).toBe(EXPECTED_CONCURRENT_DRILLS);
});
