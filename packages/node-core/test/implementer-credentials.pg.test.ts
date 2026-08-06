// real-PostgreSQL proof for implementer-credentials.sql and the frozen
// CREDENTIAL_STATEMENTS.
//
// fingerprint); (no authorization oracle — not exercised here, this file is the
// management/storage path).
//
// Why this file exists. Two properties of this slice are only true of the ENGINE and cannot be
// established by any in-process test:
//
//   1. The table's CHECK constraints. Every one of them — the scope closure, the composite
//      status arms, the fingerprint/prefix regexes and `expires_at > issued_at` — was
//      unexercised by any test in this package. migration-integrity.test.ts registers this file
//      as `{ applies: false, missingRelation: "implementers" }`, which correctly asserts that
//      applied ALONE it fails on its FK target; it therefore never reaches a constraint. Here
//      the prerequisite is supplied first, so the real file applies and the constraints run.
//   2. Rollback of a mutation whose coupled audit insert fails. An in-process SqlExecutor fake
//      has no transaction, so "nothing was committed" over its own state holds by construction
//      of the fake. Only PostgreSQL can show the mutation being undone. The structural half of
//      the argument (one statement per mutation, audit insert selecting FROM the mutation's CTE)
//      lives in credential-lifecycle.test.ts; the runtime half is here.
//
// psql runs as a child process (node:child_process), keeping the in-process
// network-containment guard (setup-network-guard.ts) intact — the pattern established by
// node-implementer-registry.pg.test.ts and migration-integrity.test.ts. node-core depends on no
// database driver, so the production statements are exercised through PREPARE/EXECUTE over their
// exact frozen text rather than through SqlCredentialStore.
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { CREDENTIAL_STATEMENTS } from "../src/credential/sql-store.ts";
import { IMPLEMENTER_CREDENTIAL_SCHEMA_FILE } from "../src/schema/implementer-credentials.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", IMPLEMENTER_CREDENTIAL_SCHEMA_FILE);

const IMPL = "00000000-0000-0000-0000-0000000000a1";
const NODE = "00000000-0000-0000-0000-0000000000b1";
const ORIGINAL = "00000000-0000-0000-0000-0000000000c1";
const REPLACEMENT = "00000000-0000-0000-0000-0000000000c2";
const AUDIT_TAKEN = "00000000-0000-0000-0000-0000000000d1";
const AUDIT_FRESH = "00000000-0000-0000-0000-0000000000d2";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const PREFIX_A = "ik_AAAAAAAA";
const PREFIX_B = "ik_BBBBBBBB";
const DIGEST = "c".repeat(64);

// The two prerequisites this slice references and does not create. `implementers` is the FK
// target owned by node-implementer-registry.sql; audit_log is data-model, transcribed here without
// its out-of-slice FKs (nodes / operations / wallets) and without its append-only UPDATE/DELETE
// triggers, neither of which the INSERT path under test touches. What IS kept verbatim is the
// part the rollback proof depends on: `id uuid NOT NULL UNIQUE` and the sha256_hex domain on
// details_sha256, so the audit insert fails for a real reason rather than an injected one.
const PREREQUISITES = `
CREATE TABLE implementers (id uuid PRIMARY KEY);
CREATE DOMAIN sha256_hex AS text CHECK (VALUE ~ '^[0-9a-f]{64}$');
CREATE TABLE audit_log (
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id uuid NOT NULL UNIQUE,
  node_id uuid NOT NULL,
  actor_kind text NOT NULL CHECK (actor_kind IN
    ('SYSTEM','OPERATOR_SESSION','ACTION_KEY','DEVICE_KEY','IMPLEMENTER')),
  actor_id text,
  action text NOT NULL,
  operation_id uuid,
  wallet_id uuid,
  details_text text NOT NULL,
  details_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (id, node_id)
);
`;

// Parameter types for CREDENTIAL_STATEMENTS.ROTATE, in the order SqlCredentialStore.rotate()
// passes them: $1,$2 = target id + tenant; $3..$16 = credentialParams(replacement); $17,$18 =
// rotatedAt + graceUntil; $19..$26 = auditParams. Declared explicitly so PREPARE never has to
// infer a type and the test fails on behaviour rather than on inference.
const ROTATE_PARAM_TYPES = [
  "uuid", "uuid",
  "uuid", "uuid", "text", "text", "text[]", "implementer_credential_status",
  "integer", "timestamptz", "timestamptz", "timestamptz", "uuid", "uuid",
  "timestamptz", "timestamptz",
  "timestamptz", "timestamptz",
  "uuid", "uuid", "text", "text", "text", "text", "sha256_hex", "timestamptz",
].join(", ");

const databaseUrl = process.env.TEST_DATABASE_URL;

const pgEnv = (): Record<string, string> => {
  const url = new URL(databaseUrl as string);
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  env.PGHOST = url.hostname;
  env.PGPORT = url.port || "5432";
  env.PGUSER = decodeURIComponent(url.username);
  env.PGPASSWORD = decodeURIComponent(url.password);
  env.PGDATABASE = url.pathname.replace(/^\//, "");
  return env;
};

interface PsqlResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

const psql = (args: readonly string[]): PsqlResult => {
  try {
    const stdout = execFileSync("psql", ["-v", "ON_ERROR_STOP=1", "-q", ...args], {
      env: pgEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout: stdout.toString(), stderr: "" };
  } catch (error) {
    const err = error as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      status: err.status ?? 1,
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? String(error),
    };
  }
};

const SCHEMA = "implementer_credentials_implementer_credentials";
let reachable = false;

const run = (statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${SCHEMA}`, "-c", statement]);

const scalar = (query: string): string =>
  psql(["-t", "-A", "-c", `SET search_path TO ${SCHEMA}`, "-c", query]).stdout.trim();

// PREPARE is session-scoped, so the prepare and the execute must share one psql invocation.
// The statement text is the frozen production string, byte for byte.
const executeRotate = (args: readonly string[]): PsqlResult =>
  psql([
    "-c",
    `SET search_path TO ${SCHEMA}`,
    "-c",
    `PREPARE rot (${ROTATE_PARAM_TYPES}) AS ${CREDENTIAL_STATEMENTS.ROTATE}`,
    "-c",
    `EXECUTE rot (${args.join(", ")})`,
  ]);

/** A live ACTIVE credential to rotate, plus the audit id that is already taken. */
const seedRotationFixture = (expiresAt: string | null): void => {
  run(`DELETE FROM audit_log`);
  run(`UPDATE implementer_credentials SET rotated_to_id = NULL`);
  run(`DELETE FROM implementer_credentials`);
  run(
    `INSERT INTO implementer_credentials
       (id, implementer_id, public_prefix, credential_hash, scopes, status, key_version,
        issued_at, expires_at, revoked_at, rotated_from_id, rotated_to_id, rotated_at,
        rotation_grace_until)
     VALUES ('${ORIGINAL}', '${IMPL}', '${PREFIX_A}', '${HASH_A}',
             ARRAY['receive:read']::text[], 'ACTIVE', 1,
             '2026-07-01T00:00:00Z', ${expiresAt === null ? "NULL" : `'${expiresAt}'`},
             NULL, NULL, NULL, NULL, NULL)`,
  );
  run(
    `INSERT INTO audit_log
       (id, node_id, actor_kind, actor_id, action, details_text, details_sha256, created_at)
     VALUES ('${AUDIT_TAKEN}', '${NODE}', 'IMPLEMENTER', '${IMPL}', 'SEEDED',
             '{}', '${DIGEST}', '2026-07-01T00:00:00Z')`,
  );
};

/** EXECUTE arguments for a rotation of ORIGINAL, mirroring the service's own construction. */
const rotateArgs = (options: {
  readonly auditId: string;
  readonly replacementIssuedAt: string;
  readonly replacementExpiresAt: string | null;
}): string[] => [
  `'${ORIGINAL}'`,
  `'${IMPL}'`,
  `'${REPLACEMENT}'`,
  `'${IMPL}'`,
  `'${PREFIX_B}'`,
  `'${HASH_B}'`,
  `ARRAY['receive:read']::text[]`,
  `'ACTIVE'`,
  `2`,
  `'${options.replacementIssuedAt}'`,
  options.replacementExpiresAt === null ? "NULL" : `'${options.replacementExpiresAt}'`,
  `NULL`,
  `'${ORIGINAL}'`,
  `NULL`,
  `NULL`,
  `NULL`,
  `'${options.replacementIssuedAt}'`,
  `'2026-08-02T00:01:00Z'`,
  `'${options.auditId}'`,
  `'${NODE}'`,
  `'IMPLEMENTER'`,
  `'${IMPL}'`,
  `'IMPLEMENTER_CREDENTIAL_ROTATED'`,
  `'{}'`,
  `'${DIGEST}'`,
  `'${options.replacementIssuedAt}'`,
];

describe.skipIf(databaseUrl === undefined)(
  "implementer_credentials against a live PostgreSQL",
  () => {
    beforeAll(() => {
      reachable = psql(["-c", "SELECT 1"]).status === 0;
      if (!reachable) return;
      psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
      const applied = psql([
        "-c",
        `CREATE SCHEMA ${SCHEMA}`,
        "-c",
        `SET search_path TO ${SCHEMA}`,
        "-c",
        PREREQUISITES,
        "-f",
        sqlPath,
      ]);
      expect(applied.stderr, "greenfield apply over prerequisites should be clean").toBe("");
      expect(applied.status, "greenfield apply over prerequisites should succeed").toBe(0);
      run(`INSERT INTO implementers (id) VALUES ('${IMPL}')`);
    });

    afterAll(() => {
      if (!reachable) return;
      psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
    });

    it("materializes the enum with exactly the three writable statuses", (ctx) => {
      if (!reachable) ctx.skip();
      // Scoped to this suite's namespace: pg_type.typname is unique per schema, not per
      // database, and migration-integrity.test.ts applies this same file into its own throwaway
      // schema (the CREATE TYPE lands before its CREATE TABLE fails on the missing FK target),
      // so an unscoped lookup sees both copies' labels interleaved.
      expect(
        scalar(
          `SELECT string_agg(enumlabel, ',' ORDER BY enumsortorder)
             FROM pg_enum e
             JOIN pg_type t ON t.oid = e.enumtypid
             JOIN pg_namespace n ON n.oid = t.typnamespace
            WHERE t.typname = 'implementer_credential_status'
              AND n.nspname = '${SCHEMA}'`,
        ),
      ).toBe("ACTIVE,GRACE,REVOKED");
    });

    it("rejects the retired EXPIRED status as an unknown enum label", (ctx) => {
      if (!reachable) ctx.skip();
      const result = run(`SELECT 'EXPIRED'::implementer_credential_status`);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toMatch(/invalid input value for enum/i);
    });

    // The constraint the rotate guard exists to keep the service away from. Proving it
    // fires is what makes the guard a fix rather than a claim.
    it("check: expires_at at or before issued_at is rejected", (ctx) => {
      if (!reachable) ctx.skip();
      for (const [issued, expires] of [
        ["2026-08-02T00:00:00Z", "2026-08-01T00:00:00Z"],
        ["2026-08-02T00:00:00Z", "2026-08-02T00:00:00Z"],
      ]) {
        const result = run(
          `INSERT INTO implementer_credentials
             (id, implementer_id, public_prefix, credential_hash, scopes, status, key_version,
              issued_at, expires_at, revoked_at, rotated_from_id, rotated_to_id, rotated_at,
              rotation_grace_until)
           VALUES ('00000000-0000-0000-0000-0000000000e1', '${IMPL}', '${PREFIX_A}',
                   '${"1".repeat(64)}', ARRAY['receive:read']::text[], 'ACTIVE', 1,
                   '${issued}', '${expires}', NULL, NULL, NULL, NULL, NULL)`,
        );
        expect(result.status, `${issued}/${expires} must be rejected`).not.toBe(0);
        expect(result.stderr).toMatch(/check constraint/i);
      }
    });

    it("check: the scope closure rejects a free-text scope and an empty set", (ctx) => {
      if (!reachable) ctx.skip();
      for (const scopes of [`ARRAY['admin:all']::text[]`, `ARRAY[]::text[]`]) {
        const result = run(
          `INSERT INTO implementer_credentials
             (id, implementer_id, public_prefix, credential_hash, scopes, status, key_version,
              issued_at, expires_at, revoked_at, rotated_from_id, rotated_to_id, rotated_at,
              rotation_grace_until)
           VALUES ('00000000-0000-0000-0000-0000000000e2', '${IMPL}', '${PREFIX_A}',
                   '${"2".repeat(64)}', ${scopes}, 'ACTIVE', 1,
                   '2026-07-01T00:00:00Z', NULL, NULL, NULL, NULL, NULL, NULL)`,
        );
        expect(result.status, `${scopes} must be rejected`).not.toBe(0);
        expect(result.stderr).toMatch(/check constraint/i);
      }
    });

    it("check: the composite status arms reject every inconsistent lifecycle row", (ctx) => {
      if (!reachable) ctx.skip();
      const inconsistent: ReadonlyArray<readonly [string, string]> = [
        // ACTIVE must have no revoked_at.
        ["ACTIVE", `'2026-07-02T00:00:00Z', NULL, NULL, NULL, NULL`],
        // GRACE must carry rotated_to_id and rotation_grace_until = revoked_at.
        ["GRACE", `'2026-07-02T00:00:00Z', NULL, NULL, NULL, NULL`],
        // REVOKED must have a revoked_at.
        ["REVOKED", `NULL, NULL, NULL, NULL, NULL`],
      ];
      for (const [status, tail] of inconsistent) {
        const result = run(
          `INSERT INTO implementer_credentials
             (id, implementer_id, public_prefix, credential_hash, scopes, status, key_version,
              issued_at, expires_at, revoked_at, rotated_from_id, rotated_to_id, rotated_at,
              rotation_grace_until)
           VALUES ('00000000-0000-0000-0000-0000000000e3', '${IMPL}', '${PREFIX_A}',
                   '${"3".repeat(64)}', ARRAY['receive:read']::text[], '${status}', 1,
                   '2026-07-01T00:00:00Z', NULL, ${tail})`,
        );
        expect(result.status, `inconsistent ${status} row must be rejected`).not.toBe(0);
        expect(result.stderr).toMatch(/check constraint/i);
      }
    });

    it("check: a malformed fingerprint or public prefix is rejected", (ctx) => {
      if (!reachable) ctx.skip();
      for (const [prefix, hash] of [
        [PREFIX_A, "NOTHEX".padEnd(64, "z")],
        ["ik_short", HASH_A],
        ["xx_AAAAAAAA", HASH_A],
      ]) {
        const result = run(
          `INSERT INTO implementer_credentials
             (id, implementer_id, public_prefix, credential_hash, scopes, status, key_version,
              issued_at, expires_at, revoked_at, rotated_from_id, rotated_to_id, rotated_at,
              rotation_grace_until)
           VALUES ('00000000-0000-0000-0000-0000000000e4', '${IMPL}', '${prefix}', '${hash}',
                   ARRAY['receive:read']::text[], 'ACTIVE', 1,
                   '2026-07-01T00:00:00Z', NULL, NULL, NULL, NULL, NULL, NULL)`,
        );
        expect(result.status, `${prefix}/${hash} must be rejected`).not.toBe(0);
        expect(result.stderr).toMatch(/check constraint/i);
      }
    });

    // ---- the rollback proof -------------------------------------------------------------
    //
    // The negative runs FIRST so its "nothing changed" assertion cannot be satisfied by a state
    // the positive left behind, and the positive then proves the same statement does commit when
    // the audit insert succeeds — so the negative failed for the audit reason and not because
    // the statement never works.

    it("a failing audit insert rolls the whole ROTATE back", (ctx) => {
      if (!reachable) ctx.skip();
      seedRotationFixture(null);

      // Real failure, not an injected one: audit_log.id is UNIQUE and AUDIT_TAKEN is already
      // present, so the `audited` CTE raises a unique violation.
      const result = executeRotate(
        rotateArgs({
          auditId: AUDIT_TAKEN,
          replacementIssuedAt: "2026-08-02T00:00:00Z",
          replacementExpiresAt: null,
        }),
      );
      expect(result.status, "the duplicate audit id must abort the statement").not.toBe(0);
      expect(result.stderr).toMatch(/duplicate key|unique/i);

      // The retirement went back with it: one row, still ACTIVE, no rotation metadata, and no
      // replacement. This is the assertion an in-process fake cannot make.
      expect(scalar(`SELECT count(*) FROM implementer_credentials`)).toBe("1");
      expect(
        scalar(
          `SELECT status || '|' || coalesce(rotated_to_id::text, '-') || '|' ||
                  coalesce(rotated_at::text, '-') || '|' || coalesce(revoked_at::text, '-')
             FROM implementer_credentials WHERE id = '${ORIGINAL}'`,
        ),
      ).toBe("ACTIVE|-|-|-");
      expect(
        scalar(
          `SELECT count(*) FROM audit_log WHERE action = 'IMPLEMENTER_CREDENTIAL_ROTATED'`,
        ),
      ).toBe("0");
    });

    it("the same ROTATE commits mutation and audit together when the audit insert succeeds", (ctx) => {
      if (!reachable) ctx.skip();
      seedRotationFixture(null);

      const result = executeRotate(
        rotateArgs({
          auditId: AUDIT_FRESH,
          replacementIssuedAt: "2026-08-02T00:00:00Z",
          replacementExpiresAt: null,
        }),
      );
      expect(result.stderr).toBe("");
      expect(result.status).toBe(0);
      expect(result.stdout).toContain(REPLACEMENT);

      expect(
        scalar(
          `SELECT status FROM implementer_credentials WHERE id = '${ORIGINAL}'`,
        ),
      ).toBe("GRACE");
      expect(
        scalar(
          `SELECT status || '|' || key_version || '|' || rotated_from_id
             FROM implementer_credentials WHERE id = '${REPLACEMENT}'`,
        ),
      ).toBe(`ACTIVE|2|${ORIGINAL}`);
      expect(
        scalar(
          `SELECT count(*) FROM audit_log WHERE action = 'IMPLEMENTER_CREDENTIAL_ROTATED'`,
        ),
      ).toBe("1");
    });

    // The D1 blast radius, at the engine. This is the row rotate() built BEFORE the guard: a
    // fresh issued_at against the parent's already-past absolute expires_at. The CHECK rejects
    // it, and because ROTATE is one statement the retirement is rolled back too — leaving the
    // credential ACTIVE and permanently un-rotatable. The service-level guard (types.ts
    // rotate()) is what keeps this statement from ever being issued.
    it("the un-rotatable trap: an inherited past expiry aborts ROTATE and rolls the retirement back", (ctx) => {
      if (!reachable) ctx.skip();
      seedRotationFixture("2026-08-01T00:00:00Z");

      const result = executeRotate(
        rotateArgs({
          auditId: AUDIT_FRESH,
          replacementIssuedAt: "2026-08-02T00:00:00Z",
          replacementExpiresAt: "2026-08-01T00:00:00Z",
        }),
      );
      expect(result.status).not.toBe(0);
      expect(result.stderr).toMatch(/check constraint/i);
      expect(scalar(`SELECT count(*) FROM implementer_credentials`)).toBe("1");
      expect(
        scalar(`SELECT status FROM implementer_credentials WHERE id = '${ORIGINAL}'`),
      ).toBe("ACTIVE");
    });
  },
);

/* ─── fail-closed harness guard ─────────────────────────────
 * Same contract as migration-integrity.test.ts's guard: top-level so it runs even when the gated
 * describe skips, and under PG_REQUIRED=1 an unassigned TEST_DATABASE_URL or an unreachable
 * server is a broken harness rather than an absent Postgres. Both the constraint coverage and
 * the rollback proof above are real-PostgreSQL properties; a skipped run proves neither. */
it("implementer_credentials constraints and ROTATE rollback must run against real PostgreSQL under PG_REQUIRED=1", () => {
  if (process.env.PG_REQUIRED !== "1") return;
  expect(
    databaseUrl,
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts provisioned no test database, so the live block skipped",
  ).toBeDefined();
  expect(
    reachable,
    "PG_REQUIRED=1 but the live block never reached the server — the schema CHECKs and the ROTATE rollback went undischarged",
  ).toBe(true);
});
