// Real-PostgreSQL concurrency suite. Proves, against a live database, that the
// frozen schema structurally enforces:
//   - CAS: row_version-guarded UPDATE lets exactly one concurrent writer win.
//   - The one-in-flight-per-wallet rule: wallet_active_leases PK rejects a second lease for the same wallet.
//   - Idempotency: UNIQUE (implementer_id, kind, idempotency_key) rejects duplicate operations.
//   - Lease acquisition: concurrent INSERT ... ON CONFLICT yields exactly one holder.
//   - The never-blind-retry rule : operation_transactions admits no second transaction attempt —
// mandatory database test 10, the half of it that lives in this table.
//     The submit_decisions / gateway_submit_attempts half is proven, against the same frozen
//     contract text, by test/submit-decision-claim-store.pg.test.ts.
//
// wallets / wallet_active_leases are the REAL frozen DDL (src/schema/custody-eligibility.sql),
// loaded via the tokenizer — no hand-rolled mirror — and applied into a hermetic scratch
// database; operation_transactions is likewise the verbatim block of
// src/schema/transaction-material.sql, sliced out by the shared parser. Only that one table of
// that file is applied: its siblings reference operation_approvals and `wallets(id)`, and this
// database's frozen wallets is keyed `id` — the documented cross-document
// reconciliation gap, not something to paper over with a retyped mirror.
// `operations` has no frozen schema file yet: transaction-material.contract.ts
// references operations(id) only as a forward FK target for external_send_sign_intents /
// external_send_partials, and no operations.sql exists under src/schema/. The CAS and
// idempotency blocks below therefore run against a minimal self-owned operations table scoped
// to exactly the two invariants proven here (row_version CAS, idempotency UNIQUE) — a
// documented gap pending that table landing, not a substitute for real frozen DDL.
//
// Connectivity: TEST_DATABASE_URL is auto-provisioned by vitest.global-setup.ts when
// run through the ROOT vitest project. `vitest run --root packages/node-core` does not go
// through global-setup and silently skips this suite.
import { execFile, execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { tokenizeCustodySql } from "./custody-eligibility-sql-statements.js";
import { parseTables, tableByName } from "./transaction-material-sql-parser.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";

// set true only when the suite beforeAll has seeded successfully. A throwing
// beforeAll makes vitest report this suite's tests as SKIPPED, not failed, so without the
// fail-closed guard at the bottom of this file a broken harness reads as "no Postgres here".
let seedReady = false;

/* ─── psql helpers ────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

// VERBOSITY=verbose is unconditional: every caller in this file goes through this one helper,
// and the machine-readable `ERROR:  <sqlstate>:` line it emits is what the SQLSTATE assertions
// below actually need — the default verbosity never puts the code in stderr at all.
const runPsql = (url: string, sql: string): Promise<PsqlOutcome> =>
  new Promise((resolve) => {
    execFile(
      "psql",
      [url, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: 15_000 },
      (err, stdout, stderr) => {
        if (err) {
          resolve({ ok: false, stdout: stdout ?? "", stderr: stderr ?? String(err) });
        } else {
          resolve({ ok: true, stdout, stderr });
        }
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

/* ─── operations DDL — self-owned; no frozen schema file exists yet (see header) ─── */

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

const custodyDdlSource = readFileSync(
  new URL("../src/schema/custody-eligibility.sql", import.meta.url),
  "utf-8",
);
const custodyDdl = tokenizeCustodySql(custodyDdlSource)
  .map((statement) => statement.raw)
  .join("\n");

// custody-eligibility.sql conforms to the data model and is therefore
// prerequisite-bound — it references the reference domains, the enumerations, and
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

// operation_transactions — the frozen block itself. The two reference scalar
// domains its columns are typed on (sha256_hex, padded_base64url_signature) are already
// created by prerequisiteDdl's base-enums-domains.sql, so re-issuing material's CREATE DOMAIN
// statements would abort with "type already exists". Only the table block is applied.
const materialDdlSource = readFileSync(
  new URL("../src/schema/transaction-material.sql", import.meta.url),
  "utf-8",
);
const operationTransactionsDdl = tableByName(
  parseTables(materialDdlSource),
  "operation_transactions",
).raw;

/* ─── lifecycle ───────────────────────────────────────────────────── */

const scratchDb = `pg_concurrency_pgconcurrency_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;

beforeAll(async () => {
  if (!TEST_DATABASE_URL) return;
  // TEMPLATE template0, not the implicit template1: the Postgres instance is shared between
  // concurrent lanes, and any lane holding a session on template1 fails every other lane's
  // CREATE DATABASE with 55006 ("source database is being accessed by other users"). template0
  // admits no connections, so it cannot be contended. This suite creates all its own objects,
  // so a pristine template is also the more hermetic choice.
  await psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${scratchDb} TEMPLATE template0`);
  scratchDbUrl = withDatabase(TEST_DATABASE_URL, scratchDb);
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: `${prerequisiteDdl}\n${custodyDdl}`,
    encoding: "utf-8",
    timeout: 30_000,
  });
  await psqlMust(scratchDbUrl, OPERATIONS_DDL);
  await psqlMust(scratchDbUrl, operationTransactionsDdl);
  schemaReady = true;
}, 30_000);

afterAll(async () => {
  if (!schemaReady) return;
  await runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
});

/* ─── fixtures ────────────────────────────────────────────────────── */

const WALLET_ID = "a0000000-0000-4000-8000-000000000001";
const NODE_ID = "b0000000-0000-4000-8000-000000000002";
const IMPLEMENTER_ID = "c0000000-0000-4000-8000-000000000003";
const FAKE_SHA = "a".repeat(64);

// public_key columns carry the padded_base64url_pubkey domain again, so every seed must
// be real 44-char padded base64url — 'test-pub-key' now fails the domain CHECK, which is exactly
// the schema-level guarantee this suite pins. wallets.node_id FKs nodes(id), so
// the tenant row has to exist first.
const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const seedNode = () =>
  `INSERT INTO nodes (id, display_name, identity_public_key) ` +
  `VALUES ('${NODE_ID}', 'pg-concurrency-concurrency', '${pubkey("NODE")}') ON CONFLICT (id) DO NOTHING;`;

// RECEIVE_WINDOW branch requires recovery_verified_at + state=AVAILABLE at lease insert.
// Seed recovery on the primary wallet so the concurrent-lease role array (which includes
// RECEIVE_WINDOW) can exercise the PK race rather than the recovery rejector.
const seedWallet = () => {
  const recoveryId = "d0000000-0000-4000-8000-0000000000aa";
  const pk = pubkey("WALLETA");
  return (
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
    `VALUES ('${WALLET_ID}', '${NODE_ID}', '${pk}', 'node_generated', 'AVAILABLE') ` +
    `ON CONFLICT (id) DO NOTHING; ` +
    `INSERT INTO wallet_recovery_verifications ` +
    `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
    `VALUES ('${recoveryId}', '${WALLET_ID}', 'AUDITED_EXPORT', '${"a".repeat(64)}', '${pk}', ` +
    `'${"e".repeat(8)}-0000-4000-8000-0000000000bb', now(), 'pg-concurrency-concurrency') ` +
    `ON CONFLICT DO NOTHING; ` +
    `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
    `WHERE id = '${WALLET_ID}' AND recovery_verified_at IS NULL;`
  );
};

// the data model's lease fencing columns are NOT NULL, and membership_id / (operation_id, wallet_id) /
// (lease_group_id, wallet_id) are UNIQUE, so every racer carries its own identifiers. That
// leaves the wallet_id PRIMARY KEY as the sole possible rejector of a duplicate lease — which
// is the one-in-flight-per-wallet property these drills actually assert.
const leaseInsert = (walletId: string, role: string, tail = ";"): string =>
  `INSERT INTO wallet_active_leases (wallet_id, membership_id, lease_group_id, ` +
  `root_operation_id, operation_id, lease_role, lease_epoch, acquired_at, heartbeat_at, ` +
  `owner_instance_id) VALUES ('${walletId}', '${randomUUID()}', '${randomUUID()}', ` +
  `'${randomUUID()}', '${randomUUID()}', '${role}', 1, now(), now(), '${randomUUID()}') ${tail}`;

/* ─── suite ───────────────────────────────────────────────────────── */

describe.skipIf(!TEST_DATABASE_URL)(
  "real-PostgreSQL concurrency proofs",
  { timeout: 60_000 },
  () => {
    beforeAll(async () => {
      await psqlMust(scratchDbUrl, `${seedNode()} ${seedWallet()}`);
      seedReady = true;
    });

    describe("CAS (compare-and-swap) under concurrent access", () => {
      it("exactly one of N concurrent row_version-guarded UPDATEs succeeds", async () => {
        const opId = randomUUID();
        await psqlMust(
          scratchDbUrl,
          `INSERT INTO operations (id, node_id, implementer_id, kind, status, row_version, idempotency_key, request_sha256) ` +
            `VALUES ('${opId}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'SEND_EXTERNAL', 'APPROVED', 1, 'cas-${opId}', '${FAKE_SHA}');`,
        );

        const N = 8;
        const casUpdate = (workerId: number) =>
          runPsql(
            scratchDbUrl,
            `UPDATE operations SET row_version = row_version + 1, formation_state = 'SIGNING_CLAIMED', ` +
              `updated_at = now() ` +
              `WHERE id = '${opId}' AND row_version = 1 ` +
              `RETURNING 'worker-${workerId}';`,
          );

        const results = await Promise.all(
          Array.from({ length: N }, (_, i) => casUpdate(i)),
        );

        const winners = results.filter((r) => r.ok && r.stdout.trim().length > 0);
        expect(winners).toHaveLength(1);

        const finalVersion = await psqlMust(
          scratchDbUrl,
          `SELECT row_version FROM operations WHERE id = '${opId}';`,
        );
        expect(finalVersion.trim()).toBe("2");
      });

      it("a stale-read CAS (row_version already advanced) affects zero rows", async () => {
        const opId = randomUUID();
        await psqlMust(
          scratchDbUrl,
          `INSERT INTO operations (id, node_id, implementer_id, kind, status, row_version, idempotency_key, request_sha256) ` +
            `VALUES ('${opId}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'MOVE_INTERNAL', 'APPROVED', 5, 'stale-${opId}', '${FAKE_SHA}');`,
        );

        const outcome = await runPsql(
          scratchDbUrl,
          `UPDATE operations SET row_version = 6, formation_state = 'SIGNING_CLAIMED' ` +
            `WHERE id = '${opId}' AND row_version = 1;`,
        );
        expect(outcome.ok).toBe(true);
        expect(outcome.stdout.trim()).toBe("");
      });
    });

    describe("one-in-flight-per-wallet (the one-in-flight-per-wallet rule) under race conditions", () => {
      it("concurrent lease INSERTs for the same wallet yield exactly one holder", async () => {
        await psqlMust(
          scratchDbUrl,
          `DELETE FROM wallet_active_leases WHERE wallet_id = '${WALLET_ID}';`,
        );

        const N = 6;
        const roles = ["SEND_SOURCE", "MOVE_SOURCE", "RECONCILIATION", "RECEIVE_WINDOW", "SEND_SOURCE", "MOVE_SOURCE"];
        const raceLease = (i: number) => runPsql(scratchDbUrl, leaseInsert(WALLET_ID, roles[i]));

        const results = await Promise.all(
          Array.from({ length: N }, (_, i) => raceLease(i)),
        );

        const successes = results.filter((r) => r.ok);
        const failures = results.filter((r) => !r.ok);
        expect(successes).toHaveLength(1);
        expect(failures).toHaveLength(N - 1);
        for (const f of failures) {
          expect(f.stderr).toContain("23505");
        }

        const count = await psqlMust(
          scratchDbUrl,
          `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${WALLET_ID}';`,
        );
        expect(count.trim()).toBe("1");
      });

      it("different wallets can hold leases concurrently (no false contention)", async () => {
        const walletB = "a0000000-0000-4000-8000-000000000099";
        await psqlMust(
          scratchDbUrl,
          `INSERT INTO wallets (id, node_id, public_key, key_origin) VALUES ('${walletB}', '${NODE_ID}', '${pubkey("WALLETB")}', 'node_generated') ON CONFLICT DO NOTHING; ` +
            `DELETE FROM wallet_active_leases WHERE wallet_id IN ('${WALLET_ID}', '${walletB}');`,
        );

        const [r1, r2] = await Promise.all([
          runPsql(scratchDbUrl, leaseInsert(WALLET_ID, "SEND_SOURCE")),
          runPsql(scratchDbUrl, leaseInsert(walletB, "MOVE_SOURCE")),
        ]);

        expect(r1.ok).toBe(true);
        expect(r2.ok).toBe(true);
      });
    });

    describe("idempotency under concurrent duplicate requests", () => {
      it("concurrent INSERTs with the same idempotency key yield exactly one row", async () => {
        const idempotencyKey = `idem-${randomUUID()}`;
        const N = 5;

        const insertOp = (i: number) =>
          runPsql(
            scratchDbUrl,
            `INSERT INTO operations (id, node_id, implementer_id, kind, idempotency_key, request_sha256) ` +
              `VALUES ('${randomUUID()}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'SEND_EXTERNAL', '${idempotencyKey}', '${FAKE_SHA}') ` +
              `RETURNING 'worker-${i}';`,
          );

        const results = await Promise.all(
          Array.from({ length: N }, (_, i) => insertOp(i)),
        );

        const successes = results.filter((r) => r.ok && r.stdout.trim().length > 0);
        const failures = results.filter((r) => !r.ok);
        expect(successes).toHaveLength(1);
        expect(failures).toHaveLength(N - 1);
        for (const f of failures) {
          expect(f.stderr).toContain("23505");
        }
      });

      it("different idempotency keys for the same implementer+kind succeed independently", async () => {
        const [r1, r2] = await Promise.all([
          runPsql(
            scratchDbUrl,
            `INSERT INTO operations (id, node_id, implementer_id, kind, idempotency_key, request_sha256) ` +
              `VALUES ('${randomUUID()}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'SEND_EXTERNAL', 'key-a-${randomUUID()}', '${FAKE_SHA}');`,
          ),
          runPsql(
            scratchDbUrl,
            `INSERT INTO operations (id, node_id, implementer_id, kind, idempotency_key, request_sha256) ` +
              `VALUES ('${randomUUID()}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'SEND_EXTERNAL', 'key-b-${randomUUID()}', '${FAKE_SHA}');`,
          ),
        ]);
        expect(r1.ok).toBe(true);
        expect(r2.ok).toBe(true);
      });
    });

    describe("lease acquisition conflicts (INSERT ON CONFLICT)", () => {
      it("INSERT ... ON CONFLICT DO NOTHING yields exactly one acquirer across N racers", async () => {
        await psqlMust(
          scratchDbUrl,
          `DELETE FROM wallet_active_leases WHERE wallet_id = '${WALLET_ID}';`,
        );

        const N = 10;
        const tryAcquire = (i: number) =>
          runPsql(
            scratchDbUrl,
            leaseInsert(
              WALLET_ID,
              "SEND_SOURCE",
              `ON CONFLICT (wallet_id) DO NOTHING RETURNING 'acquired-by-${i}';`,
            ),
          );

        const results = await Promise.all(
          Array.from({ length: N }, (_, i) => tryAcquire(i)),
        );

        const acquired = results.filter((r) => r.ok && r.stdout.trim().length > 0);
        const noConflict = results.filter((r) => r.ok && r.stdout.trim() === "");
        expect(acquired).toHaveLength(1);
        expect(noConflict).toHaveLength(N - 1);

        const holder = await psqlMust(
          scratchDbUrl,
          `SELECT lease_role FROM wallet_active_leases WHERE wallet_id = '${WALLET_ID}';`,
        );
        expect(holder.trim()).toBe("SEND_SOURCE");
      });

      it("a released lease allows a subsequent acquirer to succeed", async () => {
        await psqlMust(
          scratchDbUrl,
          `DELETE FROM wallet_active_leases WHERE wallet_id = '${WALLET_ID}';`,
        );

        const first = await runPsql(
          scratchDbUrl,
          leaseInsert(
            WALLET_ID,
            "RECONCILIATION",
            "ON CONFLICT (wallet_id) DO NOTHING RETURNING 'first';",
          ),
        );
        expect(first.stdout.trim()).toBe("first");

        await psqlMust(
          scratchDbUrl,
          `DELETE FROM wallet_active_leases WHERE wallet_id = '${WALLET_ID}';`,
        );

        const second = await runPsql(
          scratchDbUrl,
          leaseInsert(
            WALLET_ID,
            "SEND_SOURCE",
            "ON CONFLICT (wallet_id) DO NOTHING RETURNING 'second';",
          ),
        );
        expect(second.stdout.trim()).toBe("second");
      });
    });

    // mandatory database test 10, quoted: "a second transaction attempt, submit decision, or
    // submit call for one operation fails; no positive non-landing/rebuild literal or table
    // exists." These run against the database with no application layer in the path at all —
    // the INSERTs go straight to psql, so what rejects them is the frozen DDL and nothing else.
    describe("no second transaction attempt (the never-blind-retry rule) — operation_transactions", () => {
      const seedOperation = async (): Promise<string> => {
        const opId = randomUUID();
        await psqlMust(
          scratchDbUrl,
          `INSERT INTO operations (id, node_id, implementer_id, kind, idempotency_key, request_sha256) ` +
            `VALUES ('${opId}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'MOVE_INTERNAL', 'attempt-${opId}', '${FAKE_SHA}');`,
        );
        return opId;
      };

      const insertAttempt = (opId: string, attemptNo: number) =>
        runPsql(
          scratchDbUrl,
          `INSERT INTO operation_transactions ` +
            `(operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256, formed_at) ` +
            `VALUES ('${opId}', ${attemptNo}, 'INNER_PREIMAGE_PERSISTED', 'inner-preimage', '${FAKE_SHA}', now());`,
        );

      it("applies the frozen transaction-material.sql block verbatim, not a mirror", async () => {
        const applied = await psqlMust(
          scratchDbUrl,
          `SELECT count(*) FROM pg_tables WHERE tablename = 'operation_transactions';`,
        );
        expect(applied.trim()).toBe("1");
        expect(operationTransactionsDdl).toContain("CHECK (attempt_no = 1)");
        expect(operationTransactionsDdl).toContain("PRIMARY KEY (operation_id, attempt_no)");
      });

      it("rejects attempt_no = 2 at the CHECK constraint — a rebuild has nowhere to be recorded", async () => {
        const opId = await seedOperation();
        expect((await insertAttempt(opId, 1)).ok).toBe(true);

        const second = await insertAttempt(opId, 2);

        expect(second.ok).toBe(false);
        expect(second.stderr).toContain("23514");
        expect(second.stderr).toContain("attempt_no");
      });

      it("rejects a repeat of attempt 1 at the primary key", async () => {
        const opId = await seedOperation();
        expect((await insertAttempt(opId, 1)).ok).toBe(true);

        const repeat = await insertAttempt(opId, 1);

        expect(repeat.ok).toBe(false);
        expect(repeat.stderr).toContain("23505");
      });

      it("under N concurrent writers exactly one attempt row survives", async () => {
        const opId = await seedOperation();
        const N = 8;

        const results = await Promise.all(Array.from({ length: N }, () => insertAttempt(opId, 1)));

        expect(results.filter((r) => r.ok)).toHaveLength(1);
        const rows = await psqlMust(
          scratchDbUrl,
          `SELECT count(*) FROM operation_transactions WHERE operation_id = '${opId}';`,
        );
        expect(rows.trim()).toBe("1");
      });

      it("every attempt_no other than 1 is refused, so no rebuild ladder exists", async () => {
        const opId = await seedOperation();

        for (const attemptNo of [0, 2, 3, 99]) {
          const outcome = await insertAttempt(opId, attemptNo);
          expect(outcome.ok).toBe(false);
          expect(outcome.stderr).toContain("23514");
        }
      });
    });
  },
);

/* ─── fail-closed harness guard (pattern) ────────────
 * Top-level and OUTSIDE the gated describe, so it runs even when that block
 * skips itself. Under PG_REQUIRED=1 an unprovisioned TEST_DATABASE_URL or a
 * beforeAll that threw is a BROKEN HARNESS, not "no Postgres here" — vitest
 * reports a throwing beforeAll as `skipped`, so these 13 one-in-flight-per-wallet
 * concurrency proofs would otherwise report green while asserting nothing. */
it("concurrency proofs must actually run under PG_REQUIRED=1 (no silent skip)", () => {
  if (process.env.PG_REQUIRED !== "1") return;
  expect(
    TEST_DATABASE_URL,
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unset — vitest.global-setup.ts provisioned no test database, so the live block skipped itself",
  ).not.toBe("");
  expect(
    seedReady,
    "PG_REQUIRED=1 but the suite beforeAll never completed — seedNode()/seedWallet() threw, so all concurrency proofs skipped without asserting anything",
  ).toBe(true);
});
