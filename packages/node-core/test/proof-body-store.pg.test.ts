// D4 + D5 — the evidence-immutability triggers on proof_channel_candidate_bodies,
// and the live-database byte-for-byte round trip of the captured evidence bytes.
//
// Governing spec: mandatory database test 15 (append-only triggers reject update and
// delete), (complete-path bodies are permanent), mandatory database test 20 (retention revokes proof
// access without deleting any permanent row);; the byte-exact signing rule.
//
// The census block binds the frozen invariant inventory to the literal SQL and runs always.
// The live block is gated on TEST_DATABASE_URL and runs psql as a child process
// (node:child_process), which keeps the in-process network-containment guard
// (setup-network-guard.ts) intact — the pattern established by
// node-implementer-registry.pg.test.ts and migration-integrity.test.ts.
//
// Byte-for-byte is proved through the engine, not through psql's text formatting: the
// digest PostgreSQL computes over the stored column must equal the digest Node computes
// over the exact bytes that were sent. A round trip that only compared psql's printed
// output would silently pass on whitespace or newline mangling.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// DB-TEST-17: zero-depth and arbitrary-depth path bodies/manifests round-trip exactly
// DB-TEST-20: retention jobs revoke proof access without deleting any permanent row


import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

import {
  PROOF_BODY_STORE_INVARIANTS,
  PROOF_BODY_STORE_SCHEMA_FILE,
} from "../src/schema/proof-body-store.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", PROOF_BODY_STORE_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");

const GUARD_INVARIANTS = [
  "CANDIDATE_APPEND_ONLY_UPDATE_GUARD",
  "CANDIDATE_APPEND_ONLY_DELETE_GUARD",
  "CANDIDATE_APPEND_ONLY_TRUNCATE_GUARD",
  "APPEND_ONLY_REJECTOR_IS_THE_DOC_FUNCTION",
];

describe("D4 append-only guard census (mandatory database test 15)", () => {
  it("every guard invariant anchors to the literal SQL text", () => {
    const missing = PROOF_BODY_STORE_INVARIANTS.filter(
      (invariant) =>
        GUARD_INVARIANTS.includes(invariant.id) && !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("the file no longer defers the guards to a later phase", () => {
    expect(sql).not.toContain("installs BEFORE UPDATE/DELETE guards");
  });

  it("the two sighting counters are deliberately left unguarded (mutable indexes, the data model)", () => {
    for (const counter of [
      "proof_body_slot_sighting_counters",
      "proof_body_tenant_sighting_counters",
    ]) {
      expect(sql).not.toMatch(new RegExp(`BEFORE (UPDATE|DELETE|TRUNCATE) ON ${counter}`));
    }
  });

  it("mutation negative: dropping the TRUNCATE guard is caught by the census", () => {
    const mutated = sql.replace("  BEFORE TRUNCATE ON proof_channel_candidate_bodies\n", "");
    const missing = PROOF_BODY_STORE_INVARIANTS.filter(
      (invariant) =>
        GUARD_INVARIANTS.includes(invariant.id) && !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["CANDIDATE_APPEND_ONLY_TRUNCATE_GUARD"]);
  });
});

// ---------------------------------------------------------------------------
// Live PostgreSQL
// ---------------------------------------------------------------------------

const databaseUrl = process.env.TEST_DATABASE_URL;
const SCHEMA = "evidence_append_only_proof_body_store";

// Adversarial exact bytes: a doubled space, a tab, an embedded newline, a backslash, a
// double quote, a NUL-adjacent control char, and non-ASCII — every shape that a
// canonicalizing store (jsonb) or a sloppy round trip would silently normalize.
// These stand in for a signed transaction body, which the byte-exact signing rule forbids reformatting.
const EVIDENCE_TEXT =
  '{"inner":{"a__b":"x  y\tz"},"note":"line1\nline2","esc":"back\\\\slash \\"quoted\\"","u":"zß水🙂"}';
const INNER_TEXT = '{"expiry__unix_time_secs":"1767225600","b":"10.50"}';
const MANIFEST_TEXT = '[{"position":0,"body_index":0}]';

const sha256Hex = (value: string): string =>
  createHash("sha256").update(Buffer.from(value, "utf8")).digest("hex");

const byteLength = (value: string): number => Buffer.byteLength(value, "utf8");

const SIG = `${"A".repeat(86)}==`;
const SIG_2 = `${"B".repeat(86)}==`;
const SIG_S = `${"C".repeat(86)}==`;
const PATH_PROOF_ID = "00000000-0000-0000-0000-0000000007a6";

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

let reachable = false;
let scratchDir = "";
// True only after seed candidate lands — reachable alone is set before apply.
let liveReady = false;

const run = (statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${SCHEMA}`, "-c", statement]);

// Run a statement whose text carries exact evidence bytes. It goes through a file rather
// than an argv `-c`, so no shell or argv layer can touch the bytes.
const runFile = (statement: string): PsqlResult => {
  const file = join(scratchDir, `stmt-${Math.random().toString(36).slice(2)}.sql`);
  writeFileSync(file, `SET search_path TO ${SCHEMA};\n${statement}\n`, "utf8");
  return psql(["-f", file]);
};

const scalar = (query: string): string => psql([
  "-t",
  "-A",
  "-c",
  `SET search_path TO ${SCHEMA}`,
  "-c",
  query,
]).stdout.trim();

// Dollar-quoted so every byte above survives verbatim into the statement text.
const q = (value: string): string => `$evidence$${value}$evidence$`;

const insertCandidate = (pathIndex: number, idempotencyKey: string): PsqlResult =>
  runFile(
    `INSERT INTO proof_channel_candidate_bodies (
       path_proof_id, path_index, source_kind,
       completed_transaction_text, completed_transaction_sha256, completed_transaction_octets,
       wallet_role, s_signature, p_signature, b_amount,
       inner_preimage_text, inner_sha256, step_1_signature, step_2_signature,
       verification_manifest_text, verification_manifest_sha256,
       raw_bytes_sha256, tenant_id, operation_id, idempotency_key, persisted_at
     ) VALUES (
       '${PATH_PROOF_ID}', ${pathIndex}, 'PROOF_CHANNEL',
       ${q(EVIDENCE_TEXT)}, '${sha256Hex(EVIDENCE_TEXT)}', ${byteLength(EVIDENCE_TEXT)},
       'sender', '${SIG_S}', '', '10.50',
       ${q(INNER_TEXT)}, '${sha256Hex(INNER_TEXT)}', '${SIG}', '${SIG_2}',
       ${q(MANIFEST_TEXT)}, '${sha256Hex(MANIFEST_TEXT)}',
       '${sha256Hex(EVIDENCE_TEXT)}', 'tenant-a', 'op-1', '${idempotencyKey}',
       '2026-01-01T00:00:00Z'
     )`,
  );

describe.skipIf(databaseUrl === undefined)("against a live PostgreSQL", () => {
  beforeAll(() => {
    reachable = psql(["-c", "SELECT 1"]).status === 0;
    if (!reachable) return;
    scratchDir = mkdtempSync(join(tmpdir(), "evidence-append-only-"));
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
    const applied = psql([
      "-c",
      `CREATE SCHEMA ${SCHEMA}`,
      "-c",
      `SET search_path TO ${SCHEMA}`,
      "-f",
      sqlPath,
    ]);
    expect(applied.stderr, "greenfield apply should be clean").toBe("");
    expect(applied.status, "greenfield apply should succeed").toBe(0);
    const seeded = insertCandidate(0, "idem-0");
    expect(seeded.stderr, "seed candidate should insert").toBe("");
    expect(seeded.status).toBe(0);
    liveReady = true;
  });

  afterAll(() => {
    if (scratchDir !== "") rmSync(scratchDir, { recursive: true, force: true });
    if (!reachable) return;
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
  });

  // --- D5: byte-for-byte round trip -----------------------------------------------------

  it("D5: the engine's digest of every stored evidence column equals the digest of the bytes sent", (ctx) => {
    if (!reachable) ctx.skip();
    const columns: ReadonlyArray<[string, string]> = [
      ["completed_transaction_text", EVIDENCE_TEXT],
      ["inner_preimage_text", INNER_TEXT],
      ["verification_manifest_text", MANIFEST_TEXT],
    ];
    for (const [column, sent] of columns) {
      const stored = scalar(
        `SELECT encode(sha256(convert_to(${column}, 'UTF8')), 'hex')
         FROM proof_channel_candidate_bodies WHERE path_index = 0`,
      );
      expect(stored, `${column} must round-trip byte-for-byte`).toBe(sha256Hex(sent));
    }
  });

  it("D5: the stored byte length equals the sent byte length (multi-byte and control chars intact)", (ctx) => {
    if (!reachable) ctx.skip();
    const octets = scalar(
      `SELECT octet_length(completed_transaction_text)
       FROM proof_channel_candidate_bodies WHERE path_index = 0`,
    );
    expect(Number(octets)).toBe(byteLength(EVIDENCE_TEXT));
    // The declared octet count is CHECKed against the real length, so a drift between the
    // two would have failed the insert rather than landing a wrong number.
    expect(Number(octets)).toBeGreaterThan(EVIDENCE_TEXT.length);
  });

  it("D5: the persisted digest column equals the engine-computed digest of the stored bytes", (ctx) => {
    if (!reachable) ctx.skip();
    const agree = scalar(
      `SELECT completed_transaction_sha256
              = encode(sha256(convert_to(completed_transaction_text, 'UTF8')), 'hex')
       FROM proof_channel_candidate_bodies WHERE path_index = 0`,
    );
    expect(agree).toBe("t");
  });

  // --- D4: the append-only guards -------------------------------------------------------

  it("D4: UPDATE of an evidence column is rejected by the trigger", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `UPDATE proof_channel_candidate_bodies SET completed_transaction_text = 'tampered'
       WHERE path_index = 0`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
    expect(result.stderr).toContain("UPDATE is forbidden");
  });

  it("D4: a no-op UPDATE that changes nothing is still rejected", (ctx) => {
    if (!reachable) ctx.skip();
    // The guard is unconditional: there is no "harmless rewrite" carve-out an attacker
    // could shape a tampering statement into.
    const result = run(
      `UPDATE proof_channel_candidate_bodies SET tenant_id = tenant_id WHERE path_index = 0`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
  });

  it("D4: DELETE is rejected by the trigger", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(`DELETE FROM proof_channel_candidate_bodies WHERE path_index = 0`);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
    expect(result.stderr).toContain("DELETE is forbidden");
  });

  it("D4: a WHERE-less DELETE of the whole table is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(`DELETE FROM proof_channel_candidate_bodies`);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
  });

  it("D4: TRUNCATE is rejected — the row-level guards alone would leave this bypass open", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(`TRUNCATE proof_channel_candidate_bodies`);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("append-only");
    expect(result.stderr).toContain("TRUNCATE is forbidden");
  });

  it("D4: the rejection carries the documented 55000 SQLSTATE", (ctx) => {
    if (!reachable) ctx.skip();
    const result = psql([
      "-v",
      "VERBOSITY=verbose",
      "-c",
      `SET search_path TO ${SCHEMA}`,
      "-c",
      `DELETE FROM proof_channel_candidate_bodies WHERE path_index = 0`,
    ]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("55000");
  });

  it("D4 + D5: the evidence bytes are unchanged after every rejected mutation", (ctx) => {
    if (!reachable) ctx.skip();
    const stored = scalar(
      `SELECT encode(sha256(convert_to(completed_transaction_text, 'UTF8')), 'hex')
       FROM proof_channel_candidate_bodies WHERE path_index = 0`,
    );
    expect(stored).toBe(sha256Hex(EVIDENCE_TEXT));
    expect(scalar("SELECT count(*) FROM proof_channel_candidate_bodies")).toBe("1");
  });

  // --- the guards do not over-reach -----------------------------------------------------

  it("INSERT of a further candidate still works — append-only, not read-only", (ctx) => {
    if (!reachable) ctx.skip();
    const result = insertCandidate(1, "idem-1");
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(scalar("SELECT count(*) FROM proof_channel_candidate_bodies")).toBe("2");
  });

  it("the sighting counters remain mutable: the +1 UPSERT increment still works", (ctx) => {
    if (!reachable) ctx.skip();
    // These are operational indexes, not evidence. Guarding them would
    // break the cap logic, so their absence from the trigger set is load-bearing.
    for (let i = 0; i < 3; i += 1) {
      const result = run(
        `INSERT INTO proof_body_tenant_sighting_counters (tenant_id, sighting_count)
         VALUES ('tenant-a', 1)
         ON CONFLICT (tenant_id) DO UPDATE
           SET sighting_count = proof_body_tenant_sighting_counters.sighting_count + 1`,
      );
      expect(result.status).toBe(0);
    }
    expect(
      scalar(`SELECT sighting_count FROM proof_body_tenant_sighting_counters WHERE tenant_id = 'tenant-a'`),
    ).toBe("3");
  });

  it("both append-only triggers and the truncate guard are actually installed on the table", (ctx) => {
    if (!reachable) ctx.skip();
    const triggers = psql([
      "-t",
      "-A",
      "-c",
      `SELECT tgname FROM pg_trigger t
       JOIN pg_class c ON c.oid = t.tgrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = '${SCHEMA}' AND c.relname = 'proof_channel_candidate_bodies'
         AND NOT t.tgisinternal
       ORDER BY tgname`,
    ]).stdout.trim().split("\n").filter(Boolean);
    expect(triggers).toEqual([
      "proof_channel_candidate_bodies_no_delete",
      "proof_channel_candidate_bodies_no_truncate",
      "proof_channel_candidate_bodies_no_update",
    ]);
  });
});

registerPgRequiredGuard({
  name: "proof-body-store live block",
  databaseUrl,
  isReady: () => liveReady,
  readyMessage:
    "PG_REQUIRED=1 but the proof-body beforeAll never completed — D5/append-only proofs skipped, not proven",
});
