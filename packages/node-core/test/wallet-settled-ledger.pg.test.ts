/**
 * wallet-settled-ledger.pg.test.ts
 *
 * Real PostgreSQL drills for the canonical per-wallet settled ledger:
 *   1. RECEIVE_EXTERNAL lands exactly one row and the settled bytes round-trip byte-for-byte
 *   2. MOVE_INTERNAL lands exactly two rows (SOURCE + DESTINATION) against one settled body
 *   3. Duplicate (wallet_public_key, settled_transaction_sha256) rejected by PostgreSQL
 *   4. A re-serialized copy of the settled bytes is rejected (the byte-exact signing rule)
 *   5. An unsettled attempt is rejected
 *   6. An operation with no VERIFIED landing verification is rejected
 *   7. A wallet that is not a recorded participant is rejected by the operation_wallets FK
 *   8. UPDATE, DELETE and TRUNCATE all raise WALLET_SETTLED_LEDGER_INSERT_ONLY
 *   9. A swapped operation_role on a real MOVE participant is rejected
 *  10. A wallet_public_key that is not wallets.public_key for wallet_id is rejected
 *
 * Composition: base-enums-domains.sql supplies the domains and enums, the frozen
 * operation_wallets / operation_transactions CREATE TABLE blocks are lifted verbatim out of
 * their owning contracts so the ledger's foreign keys bind the real shapes, and the ledger
 * contract is applied with its three re-declared domains stripped (they are already present
 * from base-enums, and the census test proves the stripped text is byte-identical to it).
 * Harness mirrors test/send-external-landing-pg.test.ts.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "../src/schema");
const MAINTENANCE_DB = "postgres";
const DB_PREFIX = "wallet_settled_ledger_settled_ledger_";
const EXPECTED_DRILL_COUNT = 10;

const WALLET_A = "b0000000-0000-4000-8000-000000000001";
const WALLET_B = "b0000000-0000-4000-8000-000000000002";
const WALLET_C = "b0000000-0000-4000-8000-000000000003";
const WALLET_D = "b0000000-0000-4000-8000-000000000004";
const OP_RECEIVE = "b0000000-0000-4000-8000-000000000010";
const OP_MOVE = "b0000000-0000-4000-8000-000000000011";
const OP_UNSETTLED = "b0000000-0000-4000-8000-000000000012";
const OP_UNVERIFIED = "b0000000-0000-4000-8000-000000000013";
const OP_ZERO = "b0000000-0000-4000-8000-000000000014";
const PROOF_RECEIVE = "b0000000-0000-4000-8000-000000000020";
const PROOF_MOVE = "b0000000-0000-4000-8000-000000000021";
const PROOF_UNSETTLED = "b0000000-0000-4000-8000-000000000022";
const PROOF_UNVERIFIED = "b0000000-0000-4000-8000-000000000023";
const PROOF_ZERO = "b0000000-0000-4000-8000-000000000024";

const pubkey = (letter: string): string => `${letter.repeat(43)}=`;
const KEY_A = pubkey("A");
const KEY_B = pubkey("B");
const KEY_C = pubkey("C");
const KEY_D = pubkey("D");
const SIG = `${"S".repeat(86)}==`;
const INNER_SHA = "a".repeat(64);
const SETTLED_AT = "2026-07-27 04:05:06+00";

/**
 * A settled SplitChain transaction body, stored and re-read verbatim. The awkward key order
 * and the single space after each colon are exactly what a JSON.parse/JSON.stringify
 * round-trip would silently rewrite, so this literal is the byte-exactness fixture.
 */
const SETTLED_TEXT =
  '{"transaction": {"unix_time_secs": "1784880000", "amount": "0.01000000"},' +
  '"step_1_signature": "' +
  SIG +
  '", "step_2_signature": "' +
  SIG +
  '"}';
const SETTLED_SHA = createHash("sha256").update(SETTLED_TEXT, "utf8").digest("hex");

/** Same JSON value, different bytes: keys reordered and whitespace dropped. */
const RESERIALIZED_TEXT = JSON.stringify(JSON.parse(SETTLED_TEXT));

/** A second distinct settled body, so the zero-amount drill trips only on the domain. */
const ZERO_OP_TEXT = SETTLED_TEXT.replace('"0.01000000"', '"0.02000000"');
const ZERO_OP_SHA = createHash("sha256").update(ZERO_OP_TEXT, "utf8").digest("hex");

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string): PsqlOutcome => {
  try {
    const stdout = execFileSync(
      "psql",
      ["-d", db, "-v", "ON_ERROR_STOP=1", "--set=VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: 15_000, stdio: ["ignore", "pipe", "pipe"] },
    );
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const applyDdl = (db: string, sql: string, label: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-c", sql], {
      encoding: "utf-8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`DDL apply ${label} failed: ${(e.stderr ?? "").trim() || "unknown"}`);
  }
};

const probePostgres = (): boolean => {
  try {
    execFileSync("psql", ["-d", MAINTENANCE_DB, "-c", "SELECT 1"], {
      encoding: "utf-8",
      timeout: 5_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return true;
  } catch {
    return false;
  }
};

const lit = (value: string): string => `'${value.replaceAll("'", "''")}'`;

/** Lifts one frozen `CREATE TABLE <name> ( ... );` block out of its owning contract. */
const frozenTable = (file: string, table: string): string => {
  const sql = readFileSync(join(SCHEMA_DIR, file), "utf8");
  const block = new RegExp(`^CREATE TABLE ${table} \\([\\s\\S]*?^\\);$`, "m").exec(sql)?.[0];
  if (block === undefined) {
    throw new Error(`${file}: CREATE TABLE ${table} block not found`);
  }
  return block;
};

/** The ledger contract minus its three re-declared domains (already created above). */
const ledgerDdl = (): string =>
  readFileSync(join(SCHEMA_DIR, "wallet-settled-ledger.sql"), "utf8").replace(
    /^CREATE DOMAIN [\s\S]*?;$/gm,
    "",
  );

const seedOperation = (
  db: string,
  operationId: string,
  kind: string,
  participants: readonly (readonly [string, string])[],
): void => {
  psqlMust(
    db,
    `INSERT INTO operations (id, kind) VALUES ('${operationId}', '${kind}');` +
      participants
        .map(
          ([walletId, role]) =>
            ` INSERT INTO operation_wallets (operation_id, wallet_id, operation_role)` +
            ` VALUES ('${operationId}', '${walletId}', '${role}');`,
        )
        .join(""),
  );
};

/**
 * Attempt row. `settled` picks between the terminal SETTLED_BODY_PERSISTED phase (which
 * that table's own CHECKs require to carry the completed body, its digest and settled_at) and
 * the phase one step short of it (which requires all three to be NULL).
 */
const seedAttempt = (
  db: string,
  operationId: string,
  settled: boolean,
  text: string = SETTLED_TEXT,
): void => {
  // step_2_signature, completed_transaction_text, completed_transaction_sha256, settled_at.
  const settledColumns = settled
    ? `'${SIG}', ${lit(text)}, '${createHash("sha256").update(text, "utf8").digest("hex")}', '${SETTLED_AT}'`
    : "NULL, NULL, NULL, NULL";
  psqlMust(
    db,
    `INSERT INTO operation_transactions (operation_id, attempt_no, attempt_phase,` +
      ` inner_preimage_text, inner_sha256, step_1_signature, step_2_preimage_text,` +
      ` step_2_preimage_sha256, step_2_signature, completed_transaction_text,` +
      ` completed_transaction_sha256, settled_at, formed_at) VALUES ('${operationId}', 1,` +
      ` '${settled ? "SETTLED_BODY_PERSISTED" : "STEP2_PREIMAGE_PERSISTED"}',` +
      ` 'inner', '${INNER_SHA}', '${SIG}', 'step2', '${INNER_SHA}', ${settledColumns}, now());`,
  );
};

const seedVerification = (
  db: string,
  operationId: string,
  proofId: string,
  verdict: string,
): void => {
  psqlMust(
    db,
    `INSERT INTO operation_verifications (id, operation_id, landing_proof_id, verdict)` +
      ` VALUES (gen_random_uuid(), '${operationId}', '${proofId}', '${verdict}');`,
  );
};

const insertLedgerRow = (
  db: string,
  args: {
    readonly walletId: string;
    readonly walletKey: string;
    readonly operationId: string;
    readonly role: string;
    readonly proofId: string;
    readonly amount?: string;
    readonly text?: string;
    readonly sha256?: string;
    readonly settledAt?: string;
  },
): PsqlOutcome =>
  runPsql(
    db,
    `INSERT INTO wallet_settled_ledger (id, wallet_id, wallet_public_key, operation_id,` +
      ` attempt_no, operation_role, amount_zkz, settled_transaction_text,` +
      ` settled_transaction_sha256, landing_proof_id, landing_verdict, settled_at)` +
      ` VALUES (gen_random_uuid(), '${args.walletId}', '${args.walletKey}',` +
      ` '${args.operationId}', 1, '${args.role}', '${args.amount ?? "0.01000000"}',` +
      ` ${lit(args.text ?? SETTLED_TEXT)}, '${args.sha256 ?? SETTLED_SHA}',` +
      ` '${args.proofId}', 'LANDED_EXACT', '${args.settledAt ?? SETTLED_AT}');`,
  );

describe("canonical per-wallet settled ledger PG drills", () => {
  let db: string | null = null;
  let reachable = false;
  let drillsRun = 0;

  beforeAll(() => {
    reachable = probePostgres();
    if (!reachable) {
      if (process.env.PG_REQUIRED === "1") {
        throw new Error("PG_REQUIRED=1 but Postgres is unreachable");
      }
      return;
    }
    db = `${DB_PREFIX}${Date.now()}`;
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE "${db}"`);
    applyDdl(db, readFileSync(join(SCHEMA_DIR, "base-enums-domains.sql"), "utf8"), "base-enums");
    // Prerequisite relations. wallets / operations / operation_verifications are reduced to
    // the columns this slice binds (their full frozen shapes drag in the nodes, implementers,
    // observers and gateway_observations closures, which prove nothing about this ledger);
    // operation_wallets and operation_transactions are the ledger's own foreign-key targets,
    // so those two are the frozen blocks verbatim.
    applyDdl(
      db,
      `CREATE TABLE wallets (id uuid PRIMARY KEY, public_key padded_base64url_pubkey NOT NULL);
       CREATE TABLE operations (id uuid PRIMARY KEY, kind operation_kind NOT NULL);
       ${frozenTable("operations.sql", "operation_wallets")}
       ${frozenTable("transaction-material.sql", "operation_transactions")}
       CREATE TABLE operation_verifications (
         id uuid PRIMARY KEY,
         operation_id uuid NOT NULL REFERENCES operations(id),
         landing_proof_id uuid,
         verdict verification_verdict NOT NULL
       );`,
      "prerequisites",
    );
    applyDdl(db, ledgerDdl(), "wallet-settled-ledger.sql");

    psqlMust(
      db,
      `INSERT INTO wallets (id, public_key) VALUES ('${WALLET_A}', '${KEY_A}'),` +
        ` ('${WALLET_B}', '${KEY_B}'), ('${WALLET_C}', '${KEY_C}'),` +
        ` ('${WALLET_D}', '${KEY_D}');`,
    );
    seedOperation(db, OP_RECEIVE, "RECEIVE_EXTERNAL", [[WALLET_A, "RECEIVER"]]);
    seedOperation(db, OP_MOVE, "MOVE_INTERNAL", [
      [WALLET_B, "SOURCE"],
      [WALLET_C, "DESTINATION"],
    ]);
    seedOperation(db, OP_UNSETTLED, "MOVE_INTERNAL", [[WALLET_B, "SOURCE"]]);
    seedOperation(db, OP_UNVERIFIED, "MOVE_INTERNAL", [[WALLET_C, "SOURCE"]]);
    seedOperation(db, OP_ZERO, "SEND_EXTERNAL", [[WALLET_A, "SOURCE"]]);
    seedAttempt(db, OP_RECEIVE, true);
    seedAttempt(db, OP_MOVE, true);
    seedAttempt(db, OP_UNSETTLED, false);
    seedAttempt(db, OP_UNVERIFIED, true);
    seedAttempt(db, OP_ZERO, true, ZERO_OP_TEXT);
    seedVerification(db, OP_RECEIVE, PROOF_RECEIVE, "VERIFIED");
    seedVerification(db, OP_MOVE, PROOF_MOVE, "VERIFIED");
    seedVerification(db, OP_UNSETTLED, PROOF_UNSETTLED, "VERIFIED");
    seedVerification(db, OP_ZERO, PROOF_ZERO, "VERIFIED");
    // Landing verification exists but has NOT accepted the operation.
    seedVerification(db, OP_UNVERIFIED, PROOF_UNVERIFIED, "INDETERMINATE");
  });

  afterAll(() => {
    if (db !== null && reachable) {
      runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
    }
    if (reachable && drillsRun < EXPECTED_DRILL_COUNT) {
      throw new Error(
        `wallet-settled-ledger PG drills incomplete: ran ${drillsRun}/${EXPECTED_DRILL_COUNT}`,
      );
    }
  });

  const skip = (): boolean => {
    if (!reachable || db === null) {
      if (process.env.PG_REQUIRED === "1") {
        throw new Error("PG_REQUIRED but suite did not initialise");
      }
      return true;
    }
    return false;
  };

  it("1. RECEIVE_EXTERNAL lands exactly one row and the settled bytes round-trip verbatim", () => {
    if (skip()) return;
    drillsRun += 1;
    const inserted = insertLedgerRow(db!, {
      walletId: WALLET_A,
      walletKey: KEY_A,
      operationId: OP_RECEIVE,
      role: "RECEIVER",
      proofId: PROOF_RECEIVE,
    });
    expect(inserted.ok, inserted.stderr).toBe(true);

    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM wallet_settled_ledger WHERE operation_id='${OP_RECEIVE}'`,
      ).stdout.trim(),
    ).toBe("1");

    // C-10 byte round-trip: the stored bytes, the fixture bytes, and the body's bytes are
    // one and the same string of octets — hex-compared so no collation or client encoding can
    // launder a difference.
    const readBack = runPsql(
      db!,
      `SELECT encode(convert_to(settled_transaction_text, 'UTF8'), 'hex') || '|' ||` +
        ` settled_transaction_sha256 FROM wallet_settled_ledger` +
        ` WHERE operation_id='${OP_RECEIVE}'`,
    );
    expect(readBack.stdout.trim()).toBe(
      `${Buffer.from(SETTLED_TEXT, "utf8").toString("hex")}|${SETTLED_SHA}`,
    );

    const matchesBody = runPsql(
      db!,
      `SELECT convert_to(l.settled_transaction_text, 'UTF8')` +
        ` = convert_to(t.completed_transaction_text, 'UTF8')` +
        ` AND l.settled_transaction_sha256 = t.completed_transaction_sha256` +
        ` FROM wallet_settled_ledger l JOIN operation_transactions t` +
        ` ON (t.operation_id, t.attempt_no) = (l.operation_id, l.attempt_no)` +
        ` WHERE l.operation_id='${OP_RECEIVE}'`,
    );
    expect(matchesBody.stdout.trim()).toBe("t");

    // And the digest is the digest OF those bytes, not an independently supplied one.
    expect(
      runPsql(
        db!,
        `SELECT encode(sha256(convert_to(settled_transaction_text, 'UTF8')), 'hex')` +
          ` = settled_transaction_sha256 FROM wallet_settled_ledger` +
          ` WHERE operation_id='${OP_RECEIVE}'`,
      ).stdout.trim(),
    ).toBe("t");
  });

  it("2. MOVE_INTERNAL lands exactly two rows — SOURCE and DESTINATION — on one settled body", () => {
    if (skip()) return;
    drillsRun += 1;
    for (const [walletId, walletKey, role] of [
      [WALLET_B, KEY_B, "SOURCE"],
      [WALLET_C, KEY_C, "DESTINATION"],
    ] as const) {
      const outcome = insertLedgerRow(db!, {
        walletId,
        walletKey,
        operationId: OP_MOVE,
        role,
        proofId: PROOF_MOVE,
      });
      expect(outcome.ok, outcome.stderr).toBe(true);
    }
    expect(
      runPsql(
        db!,
        `SELECT string_agg(operation_role, ',' ORDER BY operation_role)` +
          ` FROM wallet_settled_ledger WHERE operation_id='${OP_MOVE}'`,
      ).stdout.trim(),
    ).toBe("DESTINATION,SOURCE");
    // One settled body, two wallet rows — the reason this table is not operation_transactions.
    expect(
      runPsql(
        db!,
        `SELECT count(DISTINCT settled_transaction_sha256) FROM wallet_settled_ledger` +
          ` WHERE operation_id='${OP_MOVE}'`,
      ).stdout.trim(),
    ).toBe("1");
  });

  it("3. the same settled bytes cannot be recorded twice against one wallet", () => {
    if (skip()) return;
    drillsRun += 1;
    // Correct role (RECEIVER) so the identity gate cannot fire first — uniqueness alone must
    // reject the second insert of the same (wallet_public_key, settled_transaction_sha256).
    const duplicate = insertLedgerRow(db!, {
      walletId: WALLET_A,
      walletKey: KEY_A,
      operationId: OP_RECEIVE,
      role: "RECEIVER",
      proofId: PROOF_RECEIVE,
    });
    expect(duplicate.ok).toBe(false);
    expect(duplicate.stderr).toContain("ERROR:  23505:");
    expect(duplicate.stderr).toContain(
      "CONSTRAINT NAME:  wallet_settled_ledger_wallet_signature_uniq",
    );
  });

  it("4. a re-serialized copy of the settled bytes is rejected (the byte-exact signing rule)", () => {
    if (skip()) return;
    drillsRun += 1;
    // Same JSON value, different octets. Nothing about the value changed; only the bytes did.
    // OP_UNVERIFIED's SOURCE (WALLET_C) is a real participant with no ledger row yet, so the
    // identity gate cannot fire first and the reserialize path is the only rejection.
    expect(RESERIALIZED_TEXT).not.toBe(SETTLED_TEXT);
    expect(JSON.parse(RESERIALIZED_TEXT)).toEqual(JSON.parse(SETTLED_TEXT));
    const rejected = insertLedgerRow(db!, {
      walletId: WALLET_C,
      walletKey: KEY_C,
      operationId: OP_UNVERIFIED,
      role: "SOURCE",
      proofId: PROOF_UNVERIFIED,
      text: RESERIALIZED_TEXT,
      sha256: createHash("sha256").update(RESERIALIZED_TEXT, "utf8").digest("hex"),
    });
    expect(rejected.ok).toBe(false);
    expect(rejected.stderr).toContain("WALLET_SETTLED_LEDGER_NOT_VERBATIM");
  });

  it("5. an attempt short of SETTLED_BODY_PERSISTED produces no ledger row", () => {
    if (skip()) return;
    drillsRun += 1;
    const rejected = insertLedgerRow(db!, {
      walletId: WALLET_B,
      walletKey: KEY_B,
      operationId: OP_UNSETTLED,
      role: "SOURCE",
      proofId: PROOF_UNSETTLED,
    });
    expect(rejected.ok).toBe(false);
    expect(rejected.stderr).toContain("WALLET_SETTLED_LEDGER_NOT_SETTLED");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM wallet_settled_ledger WHERE operation_id='${OP_UNSETTLED}'`,
      ).stdout.trim(),
    ).toBe("0");
  });

  it("6. a settled operation with no accepted landing verification produces no ledger row", () => {
    if (skip()) return;
    drillsRun += 1;
    const rejected = insertLedgerRow(db!, {
      walletId: WALLET_C,
      walletKey: KEY_C,
      operationId: OP_UNVERIFIED,
      role: "SOURCE",
      proofId: PROOF_UNVERIFIED,
    });
    expect(rejected.ok).toBe(false);
    expect(rejected.stderr).toContain("WALLET_SETTLED_LEDGER_NOT_LANDED");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM wallet_settled_ledger WHERE operation_id='${OP_UNVERIFIED}'`,
      ).stdout.trim(),
    ).toBe("0");
  });

  it("7. a non-participant and a zero amount are rejected; the SEND_EXTERNAL leg lands one row", () => {
    if (skip()) return;
    drillsRun += 1;
    // WALLET_D is a real wallet with no operation_wallets row anywhere, so nothing else in
    // the statement can fail first.
    const notAParticipant = insertLedgerRow(db!, {
      walletId: WALLET_D,
      walletKey: KEY_D,
      operationId: OP_RECEIVE,
      role: "SOURCE",
      proofId: PROOF_RECEIVE,
    });
    expect(notAParticipant.ok).toBe(false);
    expect(notAParticipant.stderr).toContain("ERROR:  23503:");
    expect(notAParticipant.stderr).toContain("operation_wallets");

    // '0.00' passes the shared grammar and is <> '0' as a string. Only VALUE::numeric
    // > 0 rejects it, which is why the positive domain and not zkz_balance_text is attached.
    // OP_ZERO is settled, verified and otherwise conflict-free, so the amount is the only
    // thing that can fail here.
    const zeroAmount = insertLedgerRow(db!, {
      walletId: WALLET_A,
      walletKey: KEY_A,
      operationId: OP_ZERO,
      role: "SOURCE",
      proofId: PROOF_ZERO,
      amount: "0.00",
      text: ZERO_OP_TEXT,
      sha256: ZERO_OP_SHA,
    });
    expect(zeroAmount.ok).toBe(false);
    expect(zeroAmount.stderr).toContain("zkz_amount_positive_text");

    // The same row with a positive amount lands, which proves the rejection above was the
    // domain and not some other property of the fixture.
    const positiveAmount = insertLedgerRow(db!, {
      walletId: WALLET_A,
      walletKey: KEY_A,
      operationId: OP_ZERO,
      role: "SOURCE",
      proofId: PROOF_ZERO,
      amount: "0.02000000",
      text: ZERO_OP_TEXT,
      sha256: ZERO_OP_SHA,
    });
    expect(positiveAmount.ok, positiveAmount.stderr).toBe(true);

    // OP_ZERO is a SEND_EXTERNAL whose only participant is its SOURCE, so that landed leg is
    // the other half of the obligation drill 2 states: single-leg kinds record exactly one
    // row, a two-leg MOVE_INTERNAL exactly two. Asserted on the role as well as the count so
    // a stray RECEIVER leg could not satisfy it.
    expect(
      runPsql(
        db!,
        `SELECT string_agg(operation_role, ',' ORDER BY operation_role)` +
          ` FROM wallet_settled_ledger WHERE operation_id='${OP_ZERO}'`,
      ).stdout.trim(),
    ).toBe("SOURCE");
  });

  it("8. UPDATE, DELETE and TRUNCATE all raise WALLET_SETTLED_LEDGER_INSERT_ONLY", () => {
    if (skip()) return;
    drillsRun += 1;
    for (const statement of [
      `UPDATE wallet_settled_ledger SET amount_zkz = '0.02' WHERE operation_id='${OP_RECEIVE}'`,
      `DELETE FROM wallet_settled_ledger WHERE operation_id='${OP_RECEIVE}'`,
      `TRUNCATE wallet_settled_ledger`,
    ]) {
      const rejected = runPsql(db!, statement);
      expect(rejected.ok, statement).toBe(false);
      expect(rejected.stderr, statement).toContain("WALLET_SETTLED_LEDGER_INSERT_ONLY");
    }
    // C-10: the bytes are still there afterwards.
    expect(
      runPsql(db!, "SELECT count(*) FROM wallet_settled_ledger").stdout.trim(),
    ).toBe("4");
  });

  it("9. a swapped operation_role on a real MOVE participant is rejected", () => {
    if (skip()) return;
    drillsRun += 1;
    // Fresh MOVE + distinct settled body so (wallet_public_key, settled_sha) uniqueness from
    // drill 2 cannot fire first. Participants: B=SOURCE, C=DESTINATION.
    const opSwap = "b0000000-0000-4000-8000-000000000015";
    const proofSwap = "b0000000-0000-4000-8000-000000000025";
    const swapText = SETTLED_TEXT.replace('"0.01000000"', '"0.03000000"');
    const swapSha = createHash("sha256").update(swapText, "utf8").digest("hex");
    seedOperation(db!, opSwap, "MOVE_INTERNAL", [
      [WALLET_B, "SOURCE"],
      [WALLET_C, "DESTINATION"],
    ]);
    seedAttempt(db!, opSwap, true, swapText);
    seedVerification(db!, opSwap, proofSwap, "VERIFIED");

    const sourceAsDest = insertLedgerRow(db!, {
      walletId: WALLET_B,
      walletKey: KEY_B,
      operationId: opSwap,
      role: "DESTINATION",
      proofId: proofSwap,
      text: swapText,
      sha256: swapSha,
    });
    expect(sourceAsDest.ok).toBe(false);
    expect(sourceAsDest.stderr).toContain("WALLET_SETTLED_LEDGER_ROLE_MISMATCH");

    const destAsSource = insertLedgerRow(db!, {
      walletId: WALLET_C,
      walletKey: KEY_C,
      operationId: opSwap,
      role: "SOURCE",
      proofId: proofSwap,
      text: swapText,
      sha256: swapSha,
    });
    expect(destAsSource.ok).toBe(false);
    expect(destAsSource.stderr).toContain("WALLET_SETTLED_LEDGER_ROLE_MISMATCH");

    // Correct roles still land — proves the gate is the role binding, not the fixture.
    for (const [walletId, walletKey, role] of [
      [WALLET_B, KEY_B, "SOURCE"],
      [WALLET_C, KEY_C, "DESTINATION"],
    ] as const) {
      const ok = insertLedgerRow(db!, {
        walletId,
        walletKey,
        operationId: opSwap,
        role,
        proofId: proofSwap,
        text: swapText,
        sha256: swapSha,
      });
      expect(ok.ok, ok.stderr).toBe(true);
    }
    expect(
      runPsql(
        db!,
        `SELECT string_agg(operation_role, ',' ORDER BY operation_role)` +
          ` FROM wallet_settled_ledger WHERE operation_id='${opSwap}'`,
      ).stdout.trim(),
    ).toBe("DESTINATION,SOURCE");
  });

  it("10. a wallet_public_key that is not wallets.public_key for wallet_id is rejected", () => {
    if (skip()) return;
    drillsRun += 1;
    // Fresh RECEIVE + distinct settled body so uniqueness against OP_RECEIVE cannot fire
    // first. WALLET_A's real key is KEY_A; KEY_B is a different wallet's pubkey.
    const opPk = "b0000000-0000-4000-8000-000000000016";
    const proofPk = "b0000000-0000-4000-8000-000000000026";
    const pkText = SETTLED_TEXT.replace('"0.01000000"', '"0.04000000"');
    const pkSha = createHash("sha256").update(pkText, "utf8").digest("hex");
    seedOperation(db!, opPk, "RECEIVE_EXTERNAL", [[WALLET_A, "RECEIVER"]]);
    seedAttempt(db!, opPk, true, pkText);
    seedVerification(db!, opPk, proofPk, "VERIFIED");

    const wrongKey = insertLedgerRow(db!, {
      walletId: WALLET_A,
      walletKey: KEY_B,
      operationId: opPk,
      role: "RECEIVER",
      proofId: proofPk,
      text: pkText,
      sha256: pkSha,
    });
    expect(wrongKey.ok).toBe(false);
    expect(wrongKey.stderr).toContain("WALLET_SETTLED_LEDGER_PUBKEY_MISMATCH");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM wallet_settled_ledger WHERE operation_id='${opPk}'`,
      ).stdout.trim(),
    ).toBe("0");

    const rightKey = insertLedgerRow(db!, {
      walletId: WALLET_A,
      walletKey: KEY_A,
      operationId: opPk,
      role: "RECEIVER",
      proofId: proofPk,
      text: pkText,
      sha256: pkSha,
    });
    expect(rightKey.ok, rightKey.stderr).toBe(true);
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM wallet_settled_ledger WHERE operation_id='${opPk}'`,
      ).stdout.trim(),
    ).toBe("1");
  });
});
