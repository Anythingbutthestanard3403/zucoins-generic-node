/**
 * base-enums-domains.pg.test.ts
 *
 * Proves, against a REAL PostgreSQL database, that the greenfield base
 * foundation DDL (base-enums-domains.sql) actually applies from empty and that the two
 * ZKZ amount CHECK domains it declares enforce the canonical amount contract AT REST:
 *   - `zkz_balance_text`  — 0 <= amount < 1e8; "0" is LEGAL (swept payer, genesis, landed
 *     payer partial are legitimately "0" byte authority — the byte-exact signing rule).
 *   - `zkz_amount_positive_text` — 0 < amount < 1e8, positivity by NUMERIC cast. This is the
 *     clause the whole domain split exists for: '0', '0.0', '0.00' and '0.' + 32 zeros all
 *     satisfy the shared regex, and all but the first are `<> '0'` AS STRINGS, so a string
 *     positivity test lets a mathematically-zero operation amount through. Only
 *     `VALUE::numeric > 0` rejects them.
 *
 * The DDL is EXECUTED, never pattern-matched: every expectation below is the observed
 * accept/reject behaviour of a live `::domain` cast, and a rejection is confirmed by SQLSTATE
 * 23514 (check_violation), not by string-matching an error message.
 *
 * Expected behaviour is derived from the FROZEN upstream contract in
 * @zucoins/generic-node-contracts/amounts (`AMOUNT_BOUNDARY_VECTORS`, `ZKZ_AMOUNT_CHECK_DOMAINS`,
 * `ZKZ_CHECK_DOMAIN_BY_ROLE`, `amountsContract`) — never from a predicate re-declared in this
 * file, which would only prove the file agrees with itself. `DB_DOMAIN_EXPECTATIONS` is
 * asserted to cover the frozen vector matrix exactly, so a vector added upstream fails here
 * until its at-rest behaviour is authored.
 *
 * Note the deliberate layer gap: the DB domains are the grammar + bound + positivity boundary,
 * NOT the canonical-form boundary. '2.50' is `amount_not_canonical` to the application
 * validator and is legal to the domain. Canonicalisation is enforced above the database.
 *
 * No silent skip. Unlike the PG_REQUIRED-gated drills in this directory, an unreachable
 * PostgreSQL is a hard FAILURE here: the base foundation is the one artifact every other
 * schema contract depends on, and the root harness provisions a live server for the
 * whole run before any worker forks. A green "0 failed" from a suite that never reached a
 * database would be exactly the vacuous control this suite exists to remove.
 */
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  AMOUNT_BOUNDARY_VECTORS,
  AMOUNT_REJECTION_REASONS,
  FOREIGN_NO_REJECT,
  ZKZ_AMOUNT_CHECK_DOMAINS,
  ZKZ_CHECK_DOMAIN_BY_ROLE,
  amountsContract,
  type AmountBoundaryVector,
} from "@zucoins/generic-node-contracts/amounts";

import { BASE_ENUMS_DOMAINS_SCHEMA_FILE } from "../src/schema/base-enums-domains.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const baseSql = readFileSync(resolve(schemaDir, BASE_ENUMS_DOMAINS_SCHEMA_FILE), "utf-8");

const MAINTENANCE_DB = "postgres";
const SQLSTATE_CHECK_VIOLATION = "23514";

/** CREATE/DROP DATABASE budget. Generous because concurrent lanes share this server. */
const PROVISION_TIMEOUT_MS = 120_000;

// Own prefix, own database. Teardown drops ONLY the database this run created — a broader
// DROP takes out the concurrent lanes sharing this server.
const SCRATCH_DB = `base_enums_domains_base_domains_${Date.now()}_${process.pid}`;

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * Server states that mean "come back in a moment", not "your SQL is wrong". Several lanes share
 * this PostgreSQL, and connection-slot exhaustion arrives as a psql failure that is otherwise
 * indistinguishable from a broken schema. Nothing SQL-level is listed here, so a real
 * check_violation or syntax error still fails on the first attempt.
 */
const TRANSIENT_SERVER_STATE =
  /too many clients already|is being accessed by other users|the database system is (starting up|shutting down)/i;
const CAPACITY_ATTEMPTS = 6;
const CAPACITY_DELAY_MS = 3_000;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The one place every psql invocation in this file goes through, so the capacity retry covers
 * provisioning, DDL apply and probing alike rather than whichever call happened to be unlucky.
 *
 * ASYNC on purpose, not for style. Provisioning a scratch database on a server several lanes
 * share is slow — a measured CREATE at 11s and a DROP at ~78s — and `execFileSync` blocks the
 * vitest worker's event loop for the whole of it, so the worker cannot answer the runner's RPC
 * and vitest raises `Timeout calling "onTaskUpdate"` as an unhandled error. Its own warning for
 * that is "This might cause false positive tests", which is not a thing a money-path control
 * may report. Awaiting the child keeps the loop free while PostgreSQL takes its time.
 */
const spawnPsql = async (args: readonly string[], timeoutMs: number): Promise<PsqlOutcome> => {
  for (let attempt = 1; ; attempt += 1) {
    try {
      const { stdout } = await promisify(execFile)("psql", [...args], {
        encoding: "utf-8",
        timeout: timeoutMs,
      });
      return { ok: true, stdout, stderr: "" };
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; signal?: string; code?: string };
      // A timeout kill leaves stderr EMPTY, which would otherwise surface as "unknown error" and
      // read like a DDL fault. Name it, so lane contention is never mistaken for a schema defect.
      const killed = e.signal === "SIGTERM" || e.code === "ETIMEDOUT";
      const stderr = killed
        ? `psql exceeded the ${timeoutMs}ms client timeout (killed, no server error). ${e.stderr ?? ""}`
        : (e.stderr ?? "");
      if (attempt < CAPACITY_ATTEMPTS && TRANSIENT_SERVER_STATE.test(stderr)) {
        await sleep(CAPACITY_DELAY_MS);
        continue;
      }
      return { ok: false, stdout: e.stdout ?? "", stderr };
    }
  }
};

const runPsql = async (db: string, sql: string, timeoutMs = 20_000): Promise<PsqlOutcome> =>
  spawnPsql(["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], timeoutMs);

const psqlMust = async (db: string, sql: string, timeoutMs?: number): Promise<string> => {
  const outcome = await runPsql(db, sql, timeoutMs);
  if (!outcome.ok) {
    throw new Error(`psql failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout.trim();
};

const applyFile = async (db: string, file: string): Promise<void> => {
  const outcome = await spawnPsql(
    ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, file)],
    PROVISION_TIMEOUT_MS,
  );
  if (!outcome.ok) {
    throw new Error(`${file} apply failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

type DomainName = keyof typeof ZKZ_AMOUNT_CHECK_DOMAINS;
const BALANCE: DomainName = "zkz_balance_text";
const POSITIVE: DomainName = "zkz_amount_positive_text";

const R = AMOUNT_REJECTION_REASONS;
const SMALLEST = `0.${"0".repeat(31)}1`;
const GREATEST = amountsContract.greatestLegalValue;

/**
 * At-rest behaviour of each frozen boundary vector, per domain. Authored deliberately rather
 * than computed from a regex re-implemented here — a JS regex asserting a Postgres regex
 * agrees with it proves nothing about the database. The two derivation cross-checks below bind
 * every mechanical row back to the frozen matrix, leaving only the genuinely layer-divergent
 * `amount_not_canonical` rows as hand-authored judgements.
 */
const DB_DOMAIN_EXPECTATIONS: Readonly<Record<string, { balance: boolean; operation: boolean }>> = {
  "0": { balance: true, operation: false },
  [SMALLEST]: { balance: true, operation: true },
  [GREATEST]: { balance: true, operation: true },
  "99999999": { balance: true, operation: true },
  "2.5": { balance: true, operation: true },
  "100000000": { balance: false, operation: false },
  "100000001": { balance: false, operation: false },
  "100000000.1": { balance: false, operation: false },
  "1e5": { balance: false, operation: false },
  "01": { balance: false, operation: false },
  "00.1": { balance: false, operation: false },
  "1.": { balance: false, operation: false },
  "-1": { balance: false, operation: false },
  "-0": { balance: false, operation: false },
  [`0.${"1".repeat(33)}`]: { balance: false, operation: false },
  // Layer divergence: non-canonical to the validator, legal grammar to the domain.
  "2.50": { balance: true, operation: true },
  // Non-canonical AND mathematically zero — the numeric-positivity clause is what rejects it.
  "0.0": { balance: true, operation: false },
};

/**
 * The numeric-positivity bypass set. These are NOT in the frozen boundary matrix (the
 * application validator rejects them earlier, on canonical form), so the database is the only
 * layer where their at-rest behaviour is observable. Every one of them matches the shared
 * regex and is `<> '0'` as a string — a string positivity test would admit all of them.
 */
const ZERO_BYPASS_VECTORS: readonly string[] = ["0.0", "0.00", `0.${"0".repeat(32)}`];

let assertionsRun = 0;
const EXPECTED_ASSERTIONS =
  Object.keys(DB_DOMAIN_EXPECTATIONS).length * 2 + ZERO_BYPASS_VECTORS.length * 2;

interface CastOutcome {
  readonly ok: boolean;
  /** The value as the database handed it back, for an accepted cast. */
  readonly returned: string;
  /** The SQLSTATE the server raised for a rejected cast; "" when accepted. */
  readonly sqlstate: string;
}

/** Every value whose at-rest behaviour is asserted below, cast against both domains. */
const PROBE_VALUES: readonly string[] = [
  ...new Set([
    ...Object.keys(DB_DOMAIN_EXPECTATIONS),
    ...ZERO_BYPASS_VECTORS,
    amountsContract.upperBoundExclusive,
    GREATEST,
  ]),
];

const castResults = new Map<string, CastOutcome>();
const probeKey = (domain: string, value: string): string => `${domain} ${value}`;

/**
 * Executes every (domain, value) pair as a live `::domain` cast in ONE psql round-trip. Each
 * cast still happens in the database and a rejection still reports the server's own SQLSTATE —
 * the plpgsql handler captures it instead of it being scraped out of psql's stderr.
 *
 * Batched rather than one psql per pair because ~40 sequential execFileSync calls block the
 * vitest worker's event loop long enough to starve its RPC channel, which surfaced as
 * `Timeout calling "onTaskUpdate"` — an unhandled error whose own vitest warning is "This might
 * cause false positive tests". A control that reports a possible false positive is not a
 * control, and raising the RPC timeout would have hidden the symptom rather than the cause.
 *
 * The temp table is dropped with the psql session, so nothing is added to the database whose
 * type inventory the tests below assert over.
 */
const probeAllCasts = async (): Promise<void> => {
  const rows = PROBE_VALUES.flatMap((value) =>
    [BALANCE, POSITIVE].map(
      // Dollar-quoted: no vector value needs escaping and none of them contains `$zkz$`.
      (domain) => `($zkz$${domain}$zkz$, $zkz$${value}$zkz$)`,
    ),
  ).join(",\n    ");
  const sql = `
CREATE TEMP TABLE cast_probe (dom text, val text, ok boolean, returned text, state text);
DO $probe$
DECLARE
  r record;
  v text;
BEGIN
  FOR r IN SELECT * FROM (VALUES
    ${rows}
  ) AS t(dom, val) LOOP
    BEGIN
      EXECUTE format('SELECT %L::%I::text', r.val, r.dom) INTO v;
      INSERT INTO cast_probe VALUES (r.dom, r.val, true, v, NULL);
    EXCEPTION WHEN others THEN
      INSERT INTO cast_probe VALUES (r.dom, r.val, false, NULL, SQLSTATE);
    END;
  END LOOP;
END
$probe$;
SELECT dom, val, ok, coalesce(returned, ''), coalesce(state, '') FROM cast_probe;
`;
  const rendered = await psqlMust(SCRATCH_DB, sql, PROVISION_TIMEOUT_MS);
  for (const line of rendered.split("\n")) {
    if (line === "") {
      continue;
    }
    const [dom, val, ok, returned, state] = line.split("|");
    castResults.set(probeKey(dom ?? "", val ?? ""), {
      ok: ok === "t",
      returned: returned ?? "",
      sqlstate: state ?? "",
    });
  }
  const expected = PROBE_VALUES.length * 2;
  if (castResults.size !== expected) {
    throw new Error(
      `cast probe returned ${castResults.size} outcomes, expected ${expected} — the batch did ` +
        `not execute every pair, so some assertion below would read an absent result`,
    );
  }
};

/** Throws rather than returning a default: an unprobed pair must fail, never quietly pass. */
const castOutcome = (domain: DomainName, value: string): CastOutcome => {
  const outcome = castResults.get(probeKey(domain, value));
  if (outcome === undefined) {
    throw new Error(`${domain} / ${value} was never cast against the database`);
  }
  return outcome;
};

beforeAll(async () => {
  const probe = await runPsql(MAINTENANCE_DB, "SELECT 1");
  if (!probe.ok) {
    throw new Error(
      `This suite requires a real PostgreSQL server: maintenance database "${MAINTENANCE_DB}" is ` +
        `not usable, so the base foundation DDL was never executed. This is a hard failure, ` +
        `not a skip. psql said: ${probe.stderr.trim() || "unknown error"}`,
    );
  }
  // CREATE DATABASE waits on a checkpoint, so it is the call that stalls when other lanes are
  // hammering this server. Its client timeout must stay well under the hook timeout below, or
  // the hook aborts first and vitest renders the whole file as "N skipped" — green-looking.
  //
  // TEMPLATE template0, not the default template1: template1 accepts connections, so any other
  // lane holding one makes PostgreSQL refuse with `source database "template1" is being accessed
  // by other users` — which arrives here as a provisioning failure indistinguishable from a
  // broken DDL. template0 has datallowconn = false, so it can never be busy. The DDL below
  // creates the one extension it needs, so nothing is inherited from template1 anyway.
  await psqlMust(
    MAINTENANCE_DB,
    `CREATE DATABASE ${SCRATCH_DB} TEMPLATE template0`,
    PROVISION_TIMEOUT_MS,
  );
  await applyFile(SCRATCH_DB, BASE_ENUMS_DOMAINS_SCHEMA_FILE);
  await probeAllCasts();
  // Explicit hook timeout: the 10s default turns CREATE DATABASE contention from concurrent
  // lanes into a red "N skipped" run that reads like a pass.
}, PROVISION_TIMEOUT_MS * 2);

afterAll(async () => {
  await runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${SCRATCH_DB}`, PROVISION_TIMEOUT_MS);
}, PROVISION_TIMEOUT_MS * 2);

describe("base foundation against real PostgreSQL", () => {
  it("the frozen manifest predicates appear verbatim in the shipped DDL", () => {
    // Binds the executed artifact to the upstream freeze. Execution alone would pass with a
    // predicate that behaves the same today but has drifted from the app-layer enforcer.
    for (const [domain, predicate] of Object.entries(ZKZ_AMOUNT_CHECK_DOMAINS)) {
      expect(baseSql, `${domain} predicate drifted from ZKZ_AMOUNT_CHECK_DOMAINS`).toContain(
        `CREATE DOMAIN ${domain} AS text\n  CHECK (${predicate});`,
      );
    }
  });

  it("the retired unbounded zkz_amount_text domain is not declared", async () => {
    // retires it. CONVENTIONS.md: it MUST NOT be attached to a new column.
    expect(baseSql).not.toContain("CREATE DOMAIN zkz_amount_text AS text");
    const declared = await psqlMust(
      SCRATCH_DB,
      "SELECT typname FROM pg_type WHERE typtype = 'd' AND typname LIKE 'zkz%' ORDER BY typname",
    );
    expect(declared.split("\n").filter((s) => s !== "")).toEqual([POSITIVE, BALANCE].sort());
  });

  it("every domain the frozen role map names exists in the database", async () => {
    // Coverage against the full target class: a role added upstream with a third domain fails
    // here rather than silently landing a column typed on a domain the DDL never creates.
    // FOREIGN_NO_REJECT is a posture, not a domain — a foreign signed amount is stored as
    // evidence and flagged as an anomaly, never rejected at INSERT (addendum clause 2,
    // the byte-exact signing rule), so the DDL must NOT create a type of that name.
    const named = new Set<string>(Object.values(ZKZ_CHECK_DOMAIN_BY_ROLE));
    expect(named.has(FOREIGN_NO_REJECT), "sentinel missing from the frozen role map").toBe(true);
    named.delete(FOREIGN_NO_REJECT);
    expect([...named].sort()).toEqual([POSITIVE, BALANCE].sort());

    const probed = [...named, FOREIGN_NO_REJECT];
    const values = probed.map((d) => `($zkz$${d}$zkz$)`).join(", ");
    const rendered = await psqlMust(
      SCRATCH_DB,
      `SELECT n.name FROM (VALUES ${values}) AS n(name)
       JOIN pg_type t ON t.typname = n.name AND t.typtype = 'd'`,
    );
    const present = new Set(rendered.split("\n").filter((s) => s !== ""));
    for (const domain of probed) {
      expect(
        present.has(domain),
        `role map entry ${domain}: unexpected domain presence`,
      ).toBe(domain !== FOREIGN_NO_REJECT);
    }
  });

  it("the at-rest expectation table covers the frozen boundary matrix exactly", () => {
    const frozen = AMOUNT_BOUNDARY_VECTORS.map((v) => v.input).sort();
    expect(Object.keys(DB_DOMAIN_EXPECTATIONS).sort()).toEqual(frozen);
  });

  it("the at-rest expectations agree with the frozen matrix wherever the layers agree", () => {
    const frozen: readonly AmountBoundaryVector[] = AMOUNT_BOUNDARY_VECTORS;
    for (const v of frozen) {
      const db = DB_DOMAIN_EXPECTATIONS[v.input];
      if (db === undefined) {
        throw new Error(`frozen vector ${v.input} has no at-rest expectation`);
      }
      if (v.balance.ok) {
        expect(db.balance, `${v.kind}: legal balance must be storable`).toBe(true);
      } else if (v.balance.reason === R.grammar || v.balance.reason === R.outOfRange) {
        expect(db.balance, `${v.kind}: grammar/range rejects are carried by the domain`).toBe(false);
      }
      if (v.operation.ok) {
        expect(db.operation, `${v.kind}: legal operation amount must be storable`).toBe(true);
      } else if (v.operation.reason === R.grammar || v.operation.reason === R.outOfRange) {
        expect(db.operation, `${v.kind}: grammar/range rejects are carried by the domain`).toBe(
          false,
        );
      } else if (v.operation.reason === R.notPositive) {
        expect(db.operation, `${v.kind}: non-positive must not reach an operation column`).toBe(
          false,
        );
      }
    }
  });

  it.each(Object.entries(DB_DOMAIN_EXPECTATIONS))(
    "%s casts as the frozen contract requires in both domains",
    (value, expected) => {
      for (const [domain, shouldAccept] of [
        [BALANCE, expected.balance],
        [POSITIVE, expected.operation],
      ] as const) {
        const outcome = castOutcome(domain, value);
        assertionsRun += 1;
        if (shouldAccept) {
          expect(
            outcome.ok,
            `${domain} rejected legal ${value} with SQLSTATE ${outcome.sqlstate}`,
          ).toBe(true);
          expect(outcome.returned).toBe(value);
        } else {
          expect(outcome.ok, `${domain} accepted illegal ${value}`).toBe(false);
          expect(outcome.sqlstate, `${domain}/${value} wrong SQLSTATE`).toBe(
            SQLSTATE_CHECK_VIOLATION,
          );
        }
      }
    },
  );

  it.each(ZERO_BYPASS_VECTORS)(
    "numeric-positivity: %s is a legal balance and never an operation amount",
    (value) => {
      const balance = castOutcome(BALANCE, value);
      assertionsRun += 1;
      expect(balance.ok, `zkz_balance_text rejected legal zero form ${value}`).toBe(true);

      const positive = castOutcome(POSITIVE, value);
      assertionsRun += 1;
      expect(
        positive.ok,
        `zkz_amount_positive_text admitted mathematically-zero ${value} — string positivity ` +
          `(VALUE <> '0') regressed over numeric positivity (VALUE::numeric > 0)`,
      ).toBe(false);
      expect(positive.sqlstate).toBe(SQLSTATE_CHECK_VIOLATION);
    },
  );

  it("the canonical bound is exclusive at rest", () => {
    expect(castOutcome(BALANCE, amountsContract.upperBoundExclusive).ok).toBe(false);
    expect(castOutcome(BALANCE, GREATEST).ok).toBe(true);
  });

  it("obligation guard: every real-PG domain cast ran", () => {
    // vitest reports a suite that never executed as a pass. This turns an undischarged
    // obligation into a failure.
    expect(
      assertionsRun,
      "PostgreSQL was reachable but the real-PG domain casts did not all run",
    ).toBe(EXPECTED_ASSERTIONS);
  });
});
