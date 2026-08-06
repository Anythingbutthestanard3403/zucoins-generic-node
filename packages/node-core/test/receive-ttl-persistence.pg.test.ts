// real-PostgreSQL proof of the RECEIVE_EXTERNAL TTL persistence semantics
// (expiry semantics (5)/(6)). The DDL under test is not restated here: the `expiry_unix_time_secs` column
// line and both table-level CHECK expressions that constrain it are sliced VERBATIM out of
// `the data model` and applied to a probe table, so
// a doc edit that drops the CHECK breaks this file rather than sliding past it. The
// `operations` table is not frozen in packages/node-core/src/schema yet, so a probe table with
// text stand-ins for the two enums is the honest apparatus — every extracted CHECK compares only
// against string literals, so text behaves identically to the enums.
//
// psql runs as a child process (node:child_process), keeping the in-process
// network-containment guard intact — exactly as signing-key-registry.pg.test.ts does.
//
// Governing spec: the data model (`operations.expiry_unix_time_secs`) and
// (`receive_codes`), operation flows. Canonical.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

import { clampReceiveTtlSecs, deriveExpiryUnixTimeSecs } from "../src/protocol/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const dataModelPath = resolve(here, "data-model.fixture.md");
const dataModel = readFileSync(dataModelPath, "utf8");

// ---- slice the operations DDL out of the doc ------------------------------------------
const OPS_HEADER = "CREATE TABLE operations (";
const opsStart = dataModel.indexOf(`\n${OPS_HEADER}`);
const opsEnd = dataModel.indexOf("\n);", opsStart);
const opsDdl = opsStart === -1 || opsEnd === -1 ? "" : dataModel.slice(opsStart + 1, opsEnd);

const expiryColumnLine =
  opsDdl
    .split("\n")
    .map((line) => line.trim())
    .find((line) => line.startsWith("expiry_unix_time_secs ")) ?? "";

// Every balanced `CHECK (...)` in the sliced DDL.
const allChecks = ((): readonly string[] => {
  const found: string[] = [];
  let cursor = 0;
  for (;;) {
    const start = opsDdl.indexOf("CHECK (", cursor);
    if (start === -1) return found;
    let depth = 0;
    let i = start + "CHECK ".length;
    for (; i < opsDdl.length; i += 1) {
      if (opsDdl[i] === "(") depth += 1;
      else if (opsDdl[i] === ")") {
        depth -= 1;
        if (depth === 0) {
          i += 1;
          break;
        }
      }
    }
    found.push(opsDdl.slice(start, i));
    cursor = i;
  }
})();

// The column-level format CHECK travels with the column line; the table-level ones are the
// queued-vs-formed state constraints this file exercises.
const COLUMN_FORMAT_CHECK = "CHECK (expiry_unix_time_secs ~ '^[0-9]+$')";
const expiryStateChecks = allChecks.filter(
  (check) => check.includes("expiry_unix_time_secs") && check !== COLUMN_FORMAT_CHECK,
);

describe("the data model operations census — expiry_unix_time_secs", () => {
  it("slices the operations DDL out of the doc", () => {
    expect(opsDdl.startsWith(OPS_HEADER), "the data model CREATE TABLE operations must be locatable").toBe(
      true,
    );
  });

  it("declares expiry_unix_time_secs as nullable text with the digits CHECK", () => {
    // The column previously lacked the format CHECK its receive_codes twin
    // already carried, so a millisecond or fractional rendering could land in `operations`.
    expect(expiryColumnLine).toBe(`expiry_unix_time_secs text ${COLUMN_FORMAT_CHECK},`);
    // Nullable is load-bearing: a queued (202) receive holds NULL for its whole CREATED life.
    expect(expiryColumnLine).not.toContain("NOT NULL");
  });

  it("matches the receive_codes twin's format CHECK", () => {
    const receiveCodes = dataModel.slice(dataModel.indexOf("CREATE TABLE receive_codes ("));
    expect(receiveCodes).toContain(`expiry_unix_time_secs text NOT NULL ${COLUMN_FORMAT_CHECK}`);
  });

  it("constrains the column with exactly the two queued-vs-formed state CHECKs", () => {
    expect(expiryStateChecks).toHaveLength(2);
  });

  it("persists no requested duration anywhere on operations", () => {
    // The requested `expires_in_seconds` is never stored — only the derived absolute expiry.
    expect(opsDdl).not.toMatch(/expires_in_seconds|requested_ttl|ttl_secs|ttl_ms|expiry_ms\b/);
  });

  it("introduces no outbox, delivery, or push table for queued receives", () => {
    // Scope strictly to the data model operations + receive_* tables (not the whole data model).
    // push_subscriptions is an unrelated node channel and must not trip this gate.
    const sliceTable = (name: string): string => {
      const start = dataModel.indexOf(`CREATE TABLE ${name} (`);
      if (start < 0) return "";
      const end = dataModel.indexOf("\n);", start);
      return end < 0 ? "" : dataModel.slice(start, end + 3);
    };
    const receiveSurface = [
      opsDdl,
      sliceTable("receive_codes"),
      sliceTable("receive_arms"),
      sliceTable("receive_release_proofs"),
    ].join("\n");
    const tableNames = [...receiveSurface.matchAll(/^CREATE TABLE (\w+) \(/gm)].map((m) => m[1]);
    expect(tableNames.filter((name) => /outbox|delivery|deliveries|push|webhook/.test(name))).toEqual(
      [],
    );
  });
});

// ---- live PostgreSQL --------------------------------------------------------------------
const databaseUrl = process.env.TEST_DATABASE_URL;
const SCHEMA = "receive_ttl_receive_ttl";
const PROBE = "operations_expiry_probe";
// The mutant drops ONLY the format CHECK, proving that CHECK — not some other constraint — is
// what rejects a non-digit rendering.
const MUTANT = "operations_expiry_probe_no_format_check";

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
// True only after probe tables apply — reachable is set before apply.
let liveReady = false;

const run = (statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${SCHEMA}`, "-c", statement]);

// Probe table carrying the extracted column line and CHECKs. `kind`/`status` stand in for the
// enums as text: the extracted CHECKs only compare them to string literals.
const probeTable = (name: string, expiryColumn: string): string => `
CREATE TABLE ${name} (
  id uuid PRIMARY KEY,
  kind text NOT NULL,
  status text NOT NULL,
  receiver_wallet_id uuid,
  discriminator uuid,
  anchor text,
  ${expiryColumn}
  t0_observation_id uuid,
  ${expiryStateChecks.join(",\n  ")}
)`;

const ID = "11111111-1111-4111-8111-111111111111";
const WALLET = "22222222-2222-4222-8222-222222222222";
const T0 = "33333333-3333-4333-8333-333333333333";

const sqlValue = (value: string | null): string => (value === null ? "NULL" : `'${value}'`);

// A queued (202) receive: CREATED, no pool wallet assigned yet, no observation.
const insertQueued = (table: string, expiry: string | null, id = ID): PsqlResult =>
  run(
    `INSERT INTO ${table} (id, kind, status, receiver_wallet_id, discriminator, anchor,
       expiry_unix_time_secs, t0_observation_id)
     VALUES ('${id}', 'RECEIVE_EXTERNAL', 'CREATED', NULL, '${id}', 'receive-ttl-anchor',
       ${sqlValue(expiry)}, NULL)`,
  );

// A formed receive: pool wallet assigned, t0 observed, code signed.
const insertFormed = (table: string, expiry: string | null, id = ID): PsqlResult =>
  run(
    `INSERT INTO ${table} (id, kind, status, receiver_wallet_id, discriminator, anchor,
       expiry_unix_time_secs, t0_observation_id)
     VALUES ('${id}', 'RECEIVE_EXTERNAL', 'AWAITING_PAYMENT', '${WALLET}', '${id}',
       'receive-ttl-anchor', ${sqlValue(expiry)}, '${T0}')`,
  );

// 2026-07-25T00:00:00Z, the shipped default policy, and the expiry that pair derives.
const NOW_MS = 1_784_937_600_000;
const TTL_BOUNDS = { defaultSecs: 300, minSecs: 60, maxSecs: 3600 };
const DERIVED = deriveExpiryUnixTimeSecs(NOW_MS, clampReceiveTtlSecs(undefined, TTL_BOUNDS));

describe.skipIf(databaseUrl === undefined)(
  "expiry_unix_time_secs against a live PostgreSQL",
  () => {
    beforeAll(() => {
      // No silent no-op: TEST_DATABASE_URL set but unreachable FAILS the whole block loudly
      // instead of letting every case ctx.skip() itself into a green tick.
      const probe = psql(["-c", "SELECT 1"]);
      if (probe.status !== 0) {
        throw new Error(`TEST_DATABASE_URL is set but PostgreSQL is unreachable: ${probe.stderr}`);
      }
      reachable = true;
      psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
      const applied = psql([
        "-c",
        `CREATE SCHEMA ${SCHEMA}`,
        "-c",
        `SET search_path TO ${SCHEMA}`,
        "-c",
        probeTable(PROBE, expiryColumnLine),
        "-c",
        // Mutant: the format CHECK stripped, everything else identical.
        probeTable(MUTANT, expiryColumnLine.replace(` ${COLUMN_FORMAT_CHECK}`, "")),
      ]);
      expect(applied.stderr, "extracted the data model DDL must apply cleanly").toBe("");
      expect(applied.status).toBe(0);
      liveReady = true;
    });

    afterAll(() => {
      if (!reachable) return;
      psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
    });

    it("accepts the derived absolute expiry on a formed receive", (ctx) => {
      if (!reachable) ctx.skip();
      const inserted = insertFormed(PROBE, DERIVED);
      expect(inserted.stderr).toBe("");
      expect(inserted.status).toBe(0);
      const read = psql([
        "-t",
        "-A",
        "-c",
        `SET search_path TO ${SCHEMA}`,
        "-c",
        `SELECT expiry_unix_time_secs FROM ${PROBE} WHERE id = '${ID}'`,
      ]);
      // Round-trips byte-identically: text in, text out, no numeric reformat (the byte-exact signing rule).
      expect(read.stdout.trim()).toBe(DERIVED);
      run(`DELETE FROM ${PROBE}`);
    });

    it("accepts NULL while the receive is queued", (ctx) => {
      if (!reachable) ctx.skip();
      const inserted = insertQueued(PROBE, null);
      expect(inserted.stderr).toBe("");
      expect(inserted.status).toBe(0);
      run(`DELETE FROM ${PROBE}`);
    });

    it("REJECTS an expiry while the receive is still queued", (ctx) => {
      if (!reachable) ctx.skip();
      // An expiry computed at admission would hand the payer a part-expired code, so the
      // queued row cannot carry one at all — the DB enforces it, not just the flow narrative.
      const inserted = insertQueued(PROBE, DERIVED);
      expect(inserted.status).not.toBe(0);
      expect(inserted.stderr).toMatch(/violates check constraint/);
    });

    it("REJECTS a formed receive with no expiry", (ctx) => {
      if (!reachable) ctx.skip();
      const inserted = insertFormed(PROBE, null);
      expect(inserted.status).not.toBe(0);
      expect(inserted.stderr).toMatch(/violates check constraint/);
    });

    it("REJECTS every non-digit rendering of the expiry", (ctx) => {
      if (!reachable) ctx.skip();
      for (const bad of [
        "1784937900.5", // fractional seconds
        "-1784937900", // signed
        "", // empty
        " 1784937900", // leading space
        "1784937900 ", // trailing space
        "1_784_937_900", // separators
        "1.7849379e9", // exponent
        "0x6a3f", // hex
      ]) {
        const inserted = insertFormed(PROBE, bad);
        expect(inserted.status, `expiry=${JSON.stringify(bad)} must be rejected`).not.toBe(0);
        expect(inserted.stderr, `expiry=${JSON.stringify(bad)}`).toMatch(
          /violates check constraint/,
        );
      }
    });

    it("mutation negative: without the format CHECK the bad renderings land", (ctx) => {
      if (!reachable) ctx.skip();
      // Proves the format CHECK is what rejects them above — not the state CHECKs, not the
      // column type. Remove `~ '^[0-9]+$'` from the data model and this table is what you get.
      const inserted = insertFormed(MUTANT, "1784937900.5");
      expect(inserted.stderr).toBe("");
      expect(inserted.status).toBe(0);
      run(`DELETE FROM ${MUTANT}`);
    });

    it("cannot catch a millisecond rendering — the code-side guard must", (ctx) => {
      if (!reachable) ctx.skip();
      // '1784937900000' is all digits, so the CHECK accepts it. This is exactly why
      // deriveExpiryUnixTimeSecs refuses a seconds-valued clock and why nothing else may
      // write this column.
      const inserted = insertFormed(PROBE, String(NOW_MS + 300_000));
      expect(inserted.status).toBe(0);
      run(`DELETE FROM ${PROBE}`);
      expect(() => deriveExpiryUnixTimeSecs(NOW_MS / 1000, 300)).toThrow(/MILLISECONDS/);
    });
  },
);

registerPgRequiredGuard({
  name: "receive-ttl-persistence live block",
  databaseUrl,
  isReady: () => liveReady,
  readyMessage:
    "PG_REQUIRED=1 but the receive-ttl beforeAll never completed — expiry_unix_time_secs proofs skipped, not proven",
});
