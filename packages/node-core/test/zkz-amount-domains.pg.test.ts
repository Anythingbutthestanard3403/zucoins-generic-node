/**
 * zkz-amount-domains.pg.test.ts
 *
 * Proves, against a REAL PostgreSQL database, that the node-core schema contracts
 * carry the amount domains and no longer carry the superseded `zkz_amount_text`.
 *
 * Governing rules: the canonical ZKZ amount contract — two CHECK domains,
 * `zkz_balance_text` and `zkz_amount_positive_text`, replace the unbounded draft domain —
 * plus the reference scalar checks, the raw observation ledger, and the role-to-domain map
 * in src/schema/CONVENTIONS.md.
 *
 * Why executed, not regex-matched: the defect closes is a MISSING RUNTIME REJECTION.
 * The retired regex `^(0|[1-9][0-9]*)(\.[0-9]{1,32})?$` capped decimal places only, so an
 * at-rest amount at or above the 10^8 bound was accepted by the engine; in v1 `NUMERIC(40,32)`
 * physically WAS the bound. A text scan proving the new domain NAME appears would
 * pass just as happily against a domain whose predicate never fires. Every assertion below is
 * an INSERT the live engine accepts or rejects, over the real .sql files applied verbatim.
 *
 * Domain selection is not this test's choice — it is frozen upstream. Both `b_amount` columns
 * hold a role-relative absolute BALANCE (the SplitChain `b` field), so both take
 * `zkz_balance_text`: "0" is legal for a swept payer, a genesis wallet, and a landed payer
 * partial. The strictly-positive domain would reject that legal "0" and drop signed evidence
 * (the byte-exact signing rule). See generic-node-contracts/src/observation/scalars.contract.ts
 * "CANONICAL OVERRIDE " and that package's CONTRACT.md "Canonical reconciliations".
 *
 * Harness mirrors observation-anomaly-indexes.pg.test.ts: psql as a child process (keeping the
 * in-process network-containment guard intact) against a hermetic per-run scratch
 * database. The fail-closed guard at the bottom turns an undischarged obligation into a hard
 * FAILURE whenever PG_REQUIRED=1 — verify-local.sh exports that only after its own pg_isready
 * probe succeeded, so under it an unreachable server is a BROKEN HARNESS, never "no Postgres
 * here", and this file can never report green having executed nothing.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ZKZ_AMOUNT_CHECK_DOMAINS } from "@zucoins/generic-node-contracts/amounts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const MAINTENANCE_DB = "postgres";
const SQLSTATE_CHECK_VIOLATION = "23514";
const OBSERVER_ID = "77677767-0000-4000-8000-000000000001";

// The three files that declared or used the retired domain. base-enums-domains.sql is the
// database-wide foundation; the other two re-declare their slice's domains so each applies
// greenfield alone (the characterization migration-integrity.test.ts pins).
const AMOUNT_BEARING_SCHEMA_FILES = [
  "base-enums-domains.sql",
  "observation-ledger.sql",
  "proof-body-store.sql",
] as const;

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
      timeout: 20_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

// One scratch DATABASE, three scratch SCHEMAS inside it. Three separate databases would be the
// obvious shape, but CREATE/DROP DATABASE serialises repo-wide and stalls for minutes when
// sibling verification lanes run concurrently; schemas give the same isolation (each slice gets
// its own copy of the domains it declares) for one database round trip. `public` stays on the
// search_path so the pgcrypto digest() that base-enums-domains.sql's
// reporting_logical_fingerprint calls resolves wherever CREATE EXTENSION put it.
const inSchema = (schema: string, sql: string): string =>
  `SET search_path TO ${schema}, public; ${sql}`;

const applyFile = (db: string, schema: string, file: string): void => {
  try {
    execFileSync(
      "psql",
      [
        "-d",
        db,
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        `CREATE SCHEMA ${schema}`,
        "-c",
        `SET search_path TO ${schema}, public`,
        "-f",
        resolve(schemaDir, file),
      ],
      { encoding: "utf-8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

// The live CHECK predicate the engine installed for a domain, scoped to one scratch schema so a
// same-named domain in a sibling schema cannot answer for it.
const liveDomainCheck = (db: string, schema: string, domain: string): string =>
  runPsql(
    db,
    `SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_type t ON t.oid = c.contypid ` +
      `JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = '${schema}' ` +
      `AND t.typname = '${domain}';`,
  ).stdout.trim();

const columnDomain = (db: string, schema: string, table: string, column: string): string =>
  runPsql(
    db,
    `SELECT domain_name FROM information_schema.columns WHERE table_schema = '${schema}' ` +
      `AND table_name = '${table}' AND column_name = '${column}';`,
  ).stdout.trim();

/* ─── SQL fixtures ─── */

const PK = "repeat('A',43)||'='"; // padded_base64url_pubkey
const SIG = "repeat('A',86)||'=='"; // padded_base64url_signature
const HEX = "repeat('a',64)"; // sha256_hex

// A VERIFIED_HEAD gateway_observations row carrying `amount` as its b_amount. Every other 04
// head CHECK is satisfied, so the ONLY thing that can reject the row is the amount domain.
const headObservation = (id: string, seq: number, amount: string): string =>
  `INSERT INTO gateway_observations (id,observer_id,endpoint_fingerprint,wallet_public_key,` +
  `wallet_seq,observed_at,http_status,raw_response_bytes,raw_response_sha256,parse_result,` +
  `relationship,semantic_fingerprint,state_changed,wallet_role,s_signature,p_signature,b_amount,` +
  `inner_preimage_text,step_1_signature,step_2_signature,completed_transaction_text,` +
  `completed_transaction_sha256) VALUES ('${id}','${OBSERVER_ID}',${HEX},${PK},${seq},now(),200,` +
  `'\\x00',${HEX},'VERIFIED_HEAD','SUCCESSOR',${HEX},true,'sender',${SIG},${SIG},'${amount}',` +
  `'inner',${SIG},${SIG},'body',${HEX});`;

// A proof_channel_candidate_bodies row carrying `amount` as its b_amount, all other CHECKs met.
const candidateBody = (index: number, amount: string): string =>
  `INSERT INTO proof_channel_candidate_bodies (path_proof_id,path_index,source_kind,` +
  `completed_transaction_text,completed_transaction_sha256,completed_transaction_octets,` +
  `wallet_role,s_signature,p_signature,b_amount,inner_preimage_text,inner_sha256,` +
  `step_1_signature,step_2_signature,verification_manifest_text,verification_manifest_sha256,` +
  `raw_bytes_sha256,tenant_id,operation_id,idempotency_key,persisted_at) VALUES (` +
  `'${OBSERVER_ID}',${index},'PROOF_CHANNEL','body',${HEX},4,'sender',${SIG},${SIG},'${amount}',` +
  `'inner',${HEX},${SIG},${SIG},'manifest',${HEX},${HEX},'t','o','k${index}',now());`;

// The bound is EXCLUSIVE at 10^8, so the greatest legal value is 99999999. + 32 nines.
const GREATEST_LEGAL = `99999999.${"9".repeat(32)}`;

// Mathematically-zero strings that match the shared regex and are `<> '0'` as strings. These
// are exactly the bypass the register note amended the positive domain to close, so
// each must be rejected by NUMERIC positivity, not merely by a string comparison.
const ZERO_FORMS = ["0", "0.0", "0.00", `0.${"0".repeat(32)}`] as const;

let assertionsRun = 0;
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

describeIfPg("ZKZ amount domains — real-PG enforcement", () => {
  const db = `zkz_amount_domains_domains_${Date.now()}_${process.pid}`;
  const BASE = "base";
  const LEDGER = "ledger";
  const BODIES = "bodies";

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${db}`);

    applyFile(db, BASE, "base-enums-domains.sql");

    // The frozen custody wallets(wallet_id) vs gateway_observations wallets(id) mismatch is a
    // documented The durable-schema slice reconciliation gap (migration-integrity.test.ts), so a minimal stub is the
    // correct isolation for this slice — same posture as observation-anomaly-indexes.pg.test.ts.
    psqlMust(db, `CREATE SCHEMA ${LEDGER}; CREATE TABLE ${LEDGER}.wallets (id uuid PRIMARY KEY);`);
    try {
      execFileSync(
        "psql",
        [
          "-d",
          db,
          "-v",
          "ON_ERROR_STOP=1",
          "-c",
          `SET search_path TO ${LEDGER}, public`,
          "-f",
          resolve(schemaDir, "observation-ledger.sql"),
        ],
        { encoding: "utf-8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] },
      );
    } catch (err) {
      const e = err as { stderr?: string };
      throw new Error(`observation-ledger.sql apply failed: ${(e.stderr ?? "").trim()}`);
    }
    psqlMust(
      db,
      inSchema(
        LEDGER,
        `INSERT INTO observers (id,domain,owner_id,gateway_endpoint_fingerprint,created_at) ` +
          `VALUES ('${OBSERVER_ID}','NODE',gen_random_uuid(),${HEX},now());`,
      ),
    );

    applyFile(db, BODIES, "proof-body-store.sql");
  });

  afterAll(() => {
    psqlMust(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
  });

  it("(a) the base contract materializes both domains and no zkz_amount_text", () => {
    const domains = runPsql(
      db,
      `SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace ` +
        `WHERE t.typtype='d' AND n.nspname='${BASE}' ORDER BY t.typname;`,
    );
    expect(domains.ok, domains.stderr).toBe(true);
    // The five reference scalar domains: the base four, with the single zkz_amount_text
    // replaced by two. The exact-set assertion is what makes a re-added retired domain
    // a failure rather than an unnoticed sixth entry.
    expect(domains.stdout.trim().split("\n").filter(Boolean)).toEqual([
      "padded_base64url_pubkey",
      "padded_base64url_signature",
      "sha256_hex",
      "zkz_amount_positive_text",
      "zkz_balance_text",
    ]);
    assertionsRun += 1;
  });

  it("(b) each domain's CHECK is the frozen generic-node-contracts predicate, byte-for-byte", () => {
    // Binds the schema contract to frozen predicate rather than to a copy of the regex
    // written here: if manifest.ts and the .sql ever diverge, this reddens. Compared against the
    // .sql SOURCE bytes, not pg_get_constraintdef — the catalogue re-renders a predicate with
    // its own casts (`'...'::text`, `(0)::numeric`), so a catalogue string is the engine's
    // paraphrase and can never carry a byte-exactness claim.
    const baseSql = readFileSync(resolve(schemaDir, "base-enums-domains.sql"), "utf8");
    expect(baseSql).toContain(
      `CREATE DOMAIN zkz_balance_text AS text\n  CHECK (${ZKZ_AMOUNT_CHECK_DOMAINS.zkz_balance_text});`,
    );
    expect(baseSql).toContain(
      `CREATE DOMAIN zkz_amount_positive_text AS text\n  CHECK (${ZKZ_AMOUNT_CHECK_DOMAINS.zkz_amount_positive_text});`,
    );

    // And the predicate the ENGINE actually installed carries both clauses — a domain created
    // with the regex but without NUMERIC positivity would satisfy the name check above nowhere
    // near as cheaply as it would slip past a name-only scan.
    const positive = liveDomainCheck(db, BASE, "zkz_amount_positive_text");
    expect(positive).toContain("(VALUE)::numeric > (0)::numeric");
    expect(positive).toContain("[1-9][0-9]{0,7}");
    expect(liveDomainCheck(db, BASE, "zkz_balance_text")).toContain("[1-9][0-9]{0,7}");
    assertionsRun += 1;
  });

  it("(c) zkz_balance_text admits '0' and the greatest legal value, and enforces the 10^8 bound", () => {
    for (const legal of ["0", "0.0", "1", "5.5", GREATEST_LEGAL]) {
      const ok = runPsql(db, inSchema(BASE, `SELECT '${legal}'::zkz_balance_text;`));
      expect(ok.ok, `zkz_balance_text must admit ${legal}: ${ok.stderr}`).toBe(true);
    }
    // The bound breach the retired unbounded domain accepted at rest. This is the whole point
    // of '100000000' matches the OLD regex and must now be rejected by the engine.
    for (const illegal of ["100000000", "100000000.5", "999999999", "-1", "1e3", "01"]) {
      const bad = runPsql(db, inSchema(BASE, `SELECT '${illegal}'::zkz_balance_text;`), true);
      expect(bad.ok, `zkz_balance_text must reject ${illegal}`).toBe(false);
      expect(extractSqlstate(bad.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    }
    assertionsRun += 1;
  });

  it("(d) zkz_amount_positive_text rejects every mathematically-zero form (NUMERIC positivity)", () => {
    for (const zero of ZERO_FORMS) {
      const bad = runPsql(db, inSchema(BASE, `SELECT '${zero}'::zkz_amount_positive_text;`), true);
      expect(bad.ok, `zkz_amount_positive_text must reject the zero form '${zero}'`).toBe(false);
      expect(extractSqlstate(bad.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
      // Proves it is numeric positivity doing the work: every one of these is `<> '0'` as a
      // string, so a string-comparison predicate would have let it through.
      if (zero !== "0") {
        expect(runPsql(db, inSchema(BASE, `SELECT ('${zero}' <> '0');`)).stdout.trim()).toBe("t");
      }
    }
    // Smallest strictly-positive 32-dp value (one unit in the last place at the 32-dp floor).
    // 33+ fractional digits fail the shared grammar and are not a positivity-domain concern.
    const smallestPositive = `0.${"0".repeat(31)}1`;
    for (const legal of [smallestPositive, "1", GREATEST_LEGAL]) {
      const ok = runPsql(db, inSchema(BASE, `SELECT '${legal}'::zkz_amount_positive_text;`));
      expect(ok.ok, `zkz_amount_positive_text must admit ${legal}: ${ok.stderr}`).toBe(true);
    }
    expect(runPsql(db, inSchema(BASE, `SELECT '100000000'::zkz_amount_positive_text;`)).ok).toBe(false);
    assertionsRun += 1;
  });

  it("(e) gateway_observations.b_amount is typed zkz_balance_text and enforces it on INSERT", () => {
    expect(columnDomain(db, LEDGER, "gateway_observations", "b_amount")).toBe("zkz_balance_text");

    // A swept payer's post-transfer balance is legitimately "0" — it must still land.
    const zero = runPsql(db, inSchema(LEDGER, headObservation("77677767-0000-4000-8000-00000000000a", 1, "0")));
    expect(zero.ok, `a legal "0" balance observation must persist: ${zero.stderr}`).toBe(true);

    const max = runPsql(
      db,
      inSchema(LEDGER, headObservation("77677767-0000-4000-8000-00000000000b", 2, GREATEST_LEGAL)),
    );
    expect(max.ok, max.stderr).toBe(true);

    const over = runPsql(
      db,
      inSchema(LEDGER, headObservation("77677767-0000-4000-8000-00000000000c", 3, "100000000")),
      true,
    );
    expect(over.ok, "an out-of-bound observed balance must be rejected at rest").toBe(false);
    expect(extractSqlstate(over.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("(f) proof_channel_candidate_bodies.b_amount is typed zkz_balance_text and enforces it", () => {
    expect(columnDomain(db, BODIES, "proof_channel_candidate_bodies", "b_amount")).toBe(
      "zkz_balance_text",
    );

    // A landed payer partial is legitimately "0"; rejecting it would refuse a byte-faithful
    // candidate body at INSERT and drop signed evidence (the byte-exact signing rule).
    const zero = runPsql(db, inSchema(BODIES, candidateBody(0, "0")));
    expect(zero.ok, `a legal "0" candidate body must persist: ${zero.stderr}`).toBe(true);

    const max = runPsql(db, inSchema(BODIES, candidateBody(1, GREATEST_LEGAL)));
    expect(max.ok, max.stderr).toBe(true);

    const over = runPsql(db, inSchema(BODIES, candidateBody(2, "100000000")), true);
    expect(over.ok, "an out-of-bound candidate b_amount must be rejected at rest").toBe(false);
    expect(extractSqlstate(over.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("(g) the retired zkz_amount_text domain is created by no schema contract", () => {
    expect(
      runPsql(
        db,
        "SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace " +
          `WHERE n.nspname IN ('${BASE}','${LEDGER}','${BODIES}') AND t.typname='zkz_amount_text';`,
      ).stdout.trim(),
      "no applied contract may carry the superseded domain",
    ).toBe("0");
    // Source-text backstop across every amount-bearing contract: a live database only proves
    // the files it executed, and a re-added declaration in a file this test does not apply
    // would otherwise pass unnoticed. Run against comment-stripped DDL — header comments
    // deliberately name the retired domain when explaining the supersession,
    // and that prose must not trip the absence guard (same posture as proof-body-store.census).
    for (const file of AMOUNT_BEARING_SCHEMA_FILES) {
      const executable = readFileSync(resolve(schemaDir, file), "utf8")
        .split("\n")
        .filter((line) => !/^\s*--/.test(line))
        .join("\n");
      expect(executable, file).not.toContain("zkz_amount_text");
    }
    assertionsRun += 1;
  });
});

const EXPECTED_ASSERTIONS = 7;

it("obligation guard: the real-PG domain drills must execute (hard fail under PG_REQUIRED=1)", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        `PG_REQUIRED=1 but PostgreSQL maintenance database "${MAINTENANCE_DB}" is not usable: the ` +
          "The amount-domain enforcement drills could not run and the local " +
          "verification lane must not silently skip them.",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the amount-domain drills did not all run",
  ).toBe(EXPECTED_ASSERTIONS);
});
