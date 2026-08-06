// statement-surface proofs for the data model stores.
//
// the data model freezes no trigger DDL and transaction-material.contract.ts assigns BEFORE UPDATE/DELETE
// guard installation to the schema-apply schema phase, so until those triggers exist the three mutability
// regimes are properties of THIS module's statement set. That makes the statement set itself the
// thing worth asserting: not "the store behaved correctly in one scenario" but "no reachable call
// can emit a statement that writes a byte column twice". Every expectation below is derived from
// TRANSACTION_MATERIAL_MUTABILITY_REGIMES and from the real transaction-material.sql bytes, never
// from a hand-copied column list — so widening a regime without widening the guard is a red test.
//
// The behavioural half drives the stores through a recording fake to prove the emitted SQL and
// the bound values; the real-PostgreSQL verdicts are in transaction-material-store.pg.test.ts.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  PARTIAL_UPDATABLE_COLUMNS,
  PHASE_ADDITIONS,
  TRANSACTION_MATERIAL_STATEMENTS,
  advanceAttemptPhase,
  insertPartial,
  insertSignIntent,
  insertTransactionAttempt,
  readTransactionMaterialFacts,
  recordPartialDelivery,
  type AdvancePhase,
} from "../src/core/transaction-material-store.ts";
import type { SqlQueryFn } from "../src/core/sql-query-fn.ts";
import { ATTEMPT_PHASE_LADDER } from "../src/core/execution-phase.ts";
import {
  TRANSACTION_MATERIAL_MUTABILITY_REGIMES,
  TRANSACTION_MATERIAL_SCHEMA_FILE,
} from "../src/schema/transaction-material.contract.ts";
import { parseTables, tableByName } from "./transaction-material-sql-parser.ts";
import {
  WALLET_INNER_PREIMAGE_SHA256,
  WALLET_INNER_PREIMAGE_TEXT,
  WALLET_SETTLED_TRANSACTION_SHA256,
  WALLET_SETTLED_TRANSACTION_TEXT,
  WALLET_STEP_1_SIGNATURE,
  WALLET_STEP_2_PREIMAGE_SHA256,
  WALLET_STEP_2_PREIMAGE_TEXT,
  WALLET_STEP_2_SIGNATURE,
} from "./fixtures/splitchain-v2-byte-evidence.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(resolve(here, "../src/schema", TRANSACTION_MATERIAL_SCHEMA_FILE), "utf8");
const tables = parseTables(sql);
const attempts = tableByName(tables, "operation_transactions");
const partials = tableByName(tables, "external_send_partials");

const regimeFor = (table: string) => {
  const regime = TRANSACTION_MATERIAL_MUTABILITY_REGIMES.find((entry) => entry.table === table);
  if (regime === undefined) throw new Error(`no frozen regime for ${table}`);
  return regime;
};

const OPERATION = "11111111-1111-4111-8111-111111111111";
/** The receiver wallet whose lease a guarded advance re-checks. */
const LEASED_WALLET = "33333333-3333-4333-8333-333333333333";

interface Recorded {
  readonly text: string;
  readonly values: readonly unknown[];
}

// Records every statement and returns `rows` for each call in turn, so a store that emits an
// unexpected extra statement runs out of canned rows rather than passing quietly.
const recorder = (
  rows: readonly (readonly Record<string, unknown>[])[] = [[{}]],
): { readonly calls: Recorded[]; readonly query: SqlQueryFn } => {
  const calls: Recorded[] = [];
  const query: SqlQueryFn = async (text, values) => {
    calls.push({ text, values });
    return rows[calls.length - 1] ?? [];
  };
  return { calls, query };
};

const statementsOf = (): string[] => Object.values(TRANSACTION_MATERIAL_STATEMENTS);

describe("the statement surface enforces the three mutability regimes", () => {
  it("external_send_sign_intents is insert-only: no statement UPDATEs or DELETEs it", () => {
    expect(regimeFor("external_send_sign_intents").updatableColumns).toEqual([]);
    for (const statement of statementsOf()) {
      if (!statement.includes("external_send_sign_intents")) continue;
      expect(statement.trimStart().startsWith("INSERT INTO"), statement).toBe(true);
      expect(statement).not.toMatch(/\b(UPDATE|DELETE)\b/);
    }
    // And the store module exposes no function that could carry one.
    expect(
      Object.keys(TRANSACTION_MATERIAL_STATEMENTS).filter((name) => /SIGN_INTENT/.test(name)),
    ).toEqual(["SIGN_INTENT_INSERT"]);
  });

  it("no statement DELETEs from any of the three tables", () => {
    for (const statement of statementsOf()) {
      expect(statement, statement).not.toMatch(/\bDELETE\b/);
    }
  });

  it("the partial store's only UPDATE touches exactly the frozen updatable columns", () => {
    const regime = regimeFor("external_send_partials");
    expect([...PARTIAL_UPDATABLE_COLUMNS].sort()).toEqual([...regime.updatableColumns].sort());

    const update = TRANSACTION_MATERIAL_STATEMENTS.PARTIAL_DELIVERY_UPDATE;
    const setClause = update.slice(update.indexOf("SET"), update.indexOf("WHERE"));
    const assigned = [...setClause.matchAll(/(?:SET|,)\s+(\w+)\s*=/g)].map((match) => match[1]!);
    expect(assigned.sort()).toEqual([...regime.updatableColumns].sort());

    // Every remaining column of the real table is a byte/identity column, and none is assignable.
    const frozen = partials.columns
      .map((column) => column.name)
      .filter((name) => !regime.updatableColumns.includes(name));
    expect(frozen).toEqual([
      "operation_id",
      "approval_id",
      "inner_sha256",
      "step_1_signature",
      "transfer_code_text",
      "transfer_code_sha256",
      "persisted_at",
    ]);
    for (const column of frozen) {
      expect(assigned, `${column} must never be assignable post-insert`).not.toContain(column);
    }
  });

  it("the one-way phase additions are a total, disjoint cover of operation_transactions' updatable set", () => {
    const regime = regimeFor("operation_transactions");
    const covered = Object.values(PHASE_ADDITIONS).flatMap((columns) => [...columns]);
    expect(covered.sort()).toEqual([...regime.updatableColumns].sort());
    // Disjoint: no column is filled by two different phases (that would be an overwrite path).
    expect(new Set(covered).size).toBe(covered.length);
    // And the updatable set is exactly the nullable set of the real table.
    const nullable = attempts.columns.filter((column) => !column.nullable).map((c) => c.name);
    expect(nullable).toEqual(["operation_id", "attempt_no", "attempt_phase", "inner_preimage_text", "inner_sha256", "formed_at"]);
  });

  it("every advance phase is a real ladder phase, and the ladder's first phase is an insert not an advance", () => {
    const advancePhases = Object.keys(PHASE_ADDITIONS) as AdvancePhase[];
    expect(advancePhases).toEqual([...ATTEMPT_PHASE_LADDER].slice(1));
    expect(advancePhases).not.toContain(ATTEMPT_PHASE_LADDER[0]);
  });
});

describe("emitted statements and bound values", () => {
  it("insertSignIntent binds all eleven columns verbatim, with no re-serialization", async () => {
    const { calls, query } = recorder();
    await insertSignIntent(query, {
      operationId: OPERATION,
      approvalId: "22222222-2222-4222-8222-222222222222",
      sourceWalletId: "33333333-3333-4333-8333-333333333333",
      sourceT0ObservationId: "44444444-4444-4444-8444-444444444444",
      destinationT0ObservationId: "55555555-5555-4555-8555-555555555555",
      leaseGroupId: "66666666-6666-4666-8666-666666666666",
      leaseEpoch: 7,
      innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
      innerSha256: WALLET_INNER_PREIMAGE_SHA256,
      redemptionExpiryAt: "2026-07-26T00:05:00.000Z",
      preparedAt: "2026-07-26T00:00:00.000Z",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.values).toHaveLength(11);
    // The preimage crosses the seam byte-identical — the byte-exact signing rule.
    expect(calls[0]!.values[7]).toBe(WALLET_INNER_PREIMAGE_TEXT);
    expect(calls[0]!.values[8]).toBe(WALLET_INNER_PREIMAGE_SHA256);
  });

  it("insertTransactionAttempt pins attempt_no to 1 and picks the phase from the payer signature", async () => {
    const move = recorder();
    const movePhase = await insertTransactionAttempt(move.query, {
      operationId: OPERATION,
      innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
      innerSha256: WALLET_INNER_PREIMAGE_SHA256,
      formedAt: "2026-07-26T00:00:01.000Z",
    });
    expect(movePhase).toBe("INNER_PREIMAGE_PERSISTED");
    expect(move.calls[0]!.text).toContain("VALUES ($1, 1, $2, $3, $4, $5, $6::timestamptz)");
    expect(move.calls[0]!.values[1]).toBe("INNER_PREIMAGE_PERSISTED");
    expect(move.calls[0]!.values[4]).toBeNull();

    const receive = recorder();
    const receivePhase = await insertTransactionAttempt(receive.query, {
      operationId: OPERATION,
      innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
      innerSha256: WALLET_INNER_PREIMAGE_SHA256,
      formedAt: "2026-07-26T00:00:01.000Z",
      payerStep1Signature: WALLET_STEP_1_SIGNATURE,
    });
    expect(receivePhase).toBe("STEP1_SIGNATURE_PERSISTED");
    expect(receive.calls[0]!.values[1]).toBe("STEP1_SIGNATURE_PERSISTED");
    expect(receive.calls[0]!.values[4]).toBe(WALLET_STEP_1_SIGNATURE);
  });

  it("each advance requires the prior phase AND that its target columns are still NULL", async () => {
    const ladder: Array<{ phase: AdvancePhase; values: Record<string, string>; prior: string }> = [
      {
        phase: "STEP1_SIGNATURE_PERSISTED",
        prior: "INNER_PREIMAGE_PERSISTED",
        values: { step_1_signature: WALLET_STEP_1_SIGNATURE },
      },
      {
        phase: "STEP2_PREIMAGE_PERSISTED",
        prior: "STEP1_SIGNATURE_PERSISTED",
        values: {
          step_2_preimage_text: WALLET_STEP_2_PREIMAGE_TEXT,
          step_2_preimage_sha256: WALLET_STEP_2_PREIMAGE_SHA256,
        },
      },
      {
        phase: "STEP2_SIGNATURE_PERSISTED",
        prior: "STEP2_PREIMAGE_PERSISTED",
        values: {
          step_2_signature: WALLET_STEP_2_SIGNATURE,
          completed_transaction_text: WALLET_SETTLED_TRANSACTION_TEXT,
          completed_transaction_sha256: WALLET_SETTLED_TRANSACTION_SHA256,
        },
      },
      {
        phase: "SETTLED_BODY_PERSISTED",
        prior: "STEP2_SIGNATURE_PERSISTED",
        values: { settled_at: "2026-07-26T00:00:09.000Z" },
      },
    ];

    for (const step of ladder) {
      const { calls, query } = recorder([[{ attempt_phase: step.phase }]]);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- one call per ladder entry; the per-phase value maps are proven by PHASE_ADDITIONS above.
      await advanceAttemptPhase(query, OPERATION, step.phase as any, step.values as any);
      const emitted = calls[0]!;
      expect(emitted.text, step.phase).toContain(`attempt_phase = '${step.phase}'`);
      expect(emitted.text, step.phase).toContain("attempt_no = 1");
      expect(emitted.values[1], step.phase).toBe(step.prior);
      for (const column of PHASE_ADDITIONS[step.phase]) {
        expect(emitted.text, `${step.phase}/${column}`).toContain(`${column} IS NULL`);
        expect(emitted.text, `${step.phase}/${column}`).toContain(`${column} = $`);
        expect(emitted.values, `${step.phase}/${column}`).toContain(step.values[column]);
      }
      // settled_at is the only timestamptz addition and must be cast.
      if (step.phase === "SETTLED_BODY_PERSISTED") {
        expect(emitted.text).toContain("settled_at = $3::timestamptz");
      }
    }
  });

  it("an advance that matches no row throws instead of retrying or overwriting", async () => {
    const { query } = recorder([[]]);
    await expect(
      advanceAttemptPhase(query, OPERATION, "STEP1_SIGNATURE_PERSISTED", {
        step_1_signature: WALLET_STEP_1_SIGNATURE,
      }),
    ).rejects.toThrow(/did not advance to STEP1_SIGNATURE_PERSISTED/);
  });

  // FOR SHARE is the whole mechanism: a plain EXISTS reads the pre-release snapshot
  // under READ COMMITTED and admits exactly the write the guard exists to refuse, so a refactor
  // that keeps the EXISTS and drops the lock would look correct and protect nothing.
  it("a guarded advance locks the lease row it checks and binds the capability tuple", async () => {
    const { calls, query } = recorder([[{ attempt_phase: "STEP2_SIGNATURE_PERSISTED" }]]);
    await advanceAttemptPhase(
      query,
      OPERATION,
      "STEP2_SIGNATURE_PERSISTED",
      {
        step_2_signature: WALLET_STEP_2_SIGNATURE,
        completed_transaction_text: WALLET_SETTLED_TRANSACTION_TEXT,
        completed_transaction_sha256: WALLET_SETTLED_TRANSACTION_SHA256,
      },
      { walletId: LEASED_WALLET, operationId: OPERATION, leaseEpoch: 7n },
    );
    const emitted = calls[0]!;
    expect(emitted.text).toContain("FROM wallet_active_leases");
    expect(emitted.text).toContain("FOR SHARE");
    expect(emitted.text).toContain("AND EXISTS (SELECT 1 FROM held_lease)");
    // The tuple binds after the three added columns, and the epoch crosses as text: a bigint has
    // no wire form of its own.
    expect(emitted.values.slice(5)).toEqual([LEASED_WALLET, OPERATION, "7"]);
  });

  it("an unguarded advance takes no lease lock — a preimage rung signs nothing", async () => {
    const { calls, query } = recorder([[{ attempt_phase: "STEP1_SIGNATURE_PERSISTED" }]]);
    await advanceAttemptPhase(query, OPERATION, "STEP1_SIGNATURE_PERSISTED", {
      step_1_signature: WALLET_STEP_1_SIGNATURE,
    });
    expect(calls[0]!.text).not.toContain("wallet_active_leases");
    expect(calls[0]!.text).not.toContain("FOR SHARE");
  });

  it("insertPartial binds the transfer-code bytes verbatim", async () => {
    const { calls, query } = recorder();
    await insertPartial(query, {
      operationId: OPERATION,
      approvalId: "22222222-2222-4222-8222-222222222222",
      innerSha256: WALLET_INNER_PREIMAGE_SHA256,
      step1Signature: WALLET_STEP_1_SIGNATURE,
      transferCodeText: WALLET_STEP_2_PREIMAGE_TEXT,
      transferCodeSha256: WALLET_STEP_2_PREIMAGE_SHA256,
      persistedAt: "2026-07-26T00:00:05.000Z",
    });
    expect(calls[0]!.values[4]).toBe(WALLET_STEP_2_PREIMAGE_TEXT);
    expect(calls[0]!.values[3]).toBe(WALLET_STEP_1_SIGNATURE);
  });

  it("recordPartialDelivery on a missing partial throws — delivery before commit is forbidden", async () => {
    const { query } = recorder([[]]);
    await expect(recordPartialDelivery(query, OPERATION, "2026-07-26T00:00:06.000Z")).rejects.toThrow(
      /delivery is forbidden until the partial row commits/,
    );
  });

  it("readTransactionMaterialFacts is one statement over exactly the three tables", async () => {
    const { calls, query } = recorder([
      [
        {
          attempt_phase: "STEP1_SIGNATURE_PERSISTED",
          sign_intent_persisted: true,
          partial_persisted: false,
          partial_first_delivered: false,
        },
      ],
    ]);
    const facts = await readTransactionMaterialFacts(query, OPERATION);
    expect(calls).toHaveLength(1);
    expect(facts).toEqual({
      attemptPhase: "STEP1_SIGNATURE_PERSISTED",
      signIntentPersisted: true,
      partialPersisted: false,
      partialFirstDelivered: false,
    });
    const text = calls[0]!.text;
    for (const table of [
      "operation_transactions",
      "external_send_sign_intents",
      "external_send_partials",
    ]) {
      expect(text, table).toContain(table);
    }
    // A read, and only a read: no execution_phase column is selected or written anywhere.
    expect(text).not.toMatch(/\b(INSERT|UPDATE|DELETE)\b/);
    expect(sql).not.toContain("execution_phase");
    expect(text).not.toContain("execution_phase");
  });

  it("a missing attempt row reads back as a null phase, not as a thrown error", async () => {
    const { query } = recorder([
      [
        {
          attempt_phase: null,
          sign_intent_persisted: false,
          partial_persisted: false,
          partial_first_delivered: false,
        },
      ],
    ]);
    expect((await readTransactionMaterialFacts(query, OPERATION)).attemptPhase).toBeNull();
  });
});
