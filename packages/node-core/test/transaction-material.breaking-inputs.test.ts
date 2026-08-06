// breaking-input proofs: feeds the ACTUAL breaking inputs against the
// constraint model parsed from the real transaction-material.sql bytes — duplicate keys,
// out-of-ladder phases, both CHECK polarities across the full 5x7 NULL matrix, bad bounds,
// bad domain formats — plus the racing-insert interleavings whose exactly-one-committer
// verdicts are derived from the parsed uniqueness surfaces. Offline stand-in for the live
// the mandatory database tests negatives; those remain schema-apply execution obligations (see the contract module).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { TRANSACTION_MATERIAL_SCHEMA_FILE } from "../src/schema/transaction-material.contract.ts";
import { FORMATION_TRANSITIONS } from "../../generic-node-contracts/src/approval/sign-intent.contract.ts";
import {
  parseAttemptPhaseLiterals,
  parseDomains,
  parsePhaseChecks,
  parseTables,
  phaseCheckExpectsNull,
  tableByName,
} from "./transaction-material-sql-parser.ts";
import {
  keySetsFor,
  simulateInsert,
  validateRowAgainstTable,
  type RowValues,
} from "./transaction-material-model.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(resolve(here, "../src/schema", TRANSACTION_MATERIAL_SCHEMA_FILE), "utf8");

const tables = parseTables(sql);
const domains = parseDomains(sql);
const signIntents = tableByName(tables, "external_send_sign_intents");
const attempts = tableByName(tables, "operation_transactions");
const partials = tableByName(tables, "external_send_partials");
const phaseChecks = parsePhaseChecks(attempts);
const phaseLiterals = parseAttemptPhaseLiterals(attempts);

const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const VALID_SIGNATURE = `${"A".repeat(86)}==`;

const NON_NULL_BY_COLUMN: Readonly<Record<string, string>> = {
  step_1_signature: VALID_SIGNATURE,
  step_2_preimage_text: "step-2-preimage",
  step_2_preimage_sha256: SHA_B,
  step_2_signature: VALID_SIGNATURE,
  completed_transaction_text: "completed-transaction",
  completed_transaction_sha256: SHA_B,
  settled_at: "2026-07-20T01:00:00.000Z",
};

const signIntentRow = (overrides: Partial<RowValues> = {}): RowValues => ({
  operation_id: "op-1",
  approval_id: "approval-1",
  source_wallet_id: "wallet-1",
  source_t0_observation_id: "observation-source-1",
  destination_t0_observation_id: "observation-destination-1",
  lease_group_id: "lease-group-1",
  lease_epoch: 7,
  inner_preimage_text: "inner-preimage",
  inner_sha256: SHA_A,
  redemption_expiry_at: "2026-07-20T00:05:00.000Z",
  prepared_at: "2026-07-20T00:00:00.000Z",
  ...overrides,
});

/** A valid attempt row at `phase`: every checked column set per the parsed biconditionals. */
const attemptRowAt = (phase: string, overrides: Partial<RowValues> = {}): RowValues => {
  const row: Record<string, string | number | null> = {
    operation_id: "op-1",
    attempt_no: 1,
    attempt_phase: phase,
    inner_preimage_text: "inner-preimage",
    inner_sha256: SHA_A,
    formed_at: "2026-07-20T00:00:00.000Z",
  };
  for (const check of phaseChecks) {
    row[check.column] = phaseCheckExpectsNull(check, phase) ? null : NON_NULL_BY_COLUMN[check.column] ?? "x";
  }
  return { ...row, ...overrides };
};

const partialRow = (overrides: Partial<RowValues> = {}): RowValues => ({
  operation_id: "op-1",
  approval_id: "approval-1",
  inner_sha256: SHA_A,
  step_1_signature: VALID_SIGNATURE,
  transfer_code_text: "transfer-code",
  transfer_code_sha256: SHA_B,
  persisted_at: "2026-07-20T00:00:00.000Z",
  first_delivered_at: null,
  last_redelivered_at: null,
  redelivery_count: 0,
  ...overrides,
});

describe("breaking inputs over the parsed model", () => {
  it("accepts a valid row factory baseline for all three tables", () => {
    expect(validateRowAgainstTable(signIntents, domains, signIntentRow())).toEqual([]);
    expect(validateRowAgainstTable(partials, domains, partialRow())).toEqual([]);
  });

  it("accepts a valid attempt insert at EVERY phase — including an initial insert at STEP1_SIGNATURE_PERSISTED (RECEIVE allowance, 04:769-770)", () => {
    for (const phase of phaseLiterals) {
      const violations = validateRowAgainstTable(attempts, domains, attemptRowAt(phase));
      expect(violations, `phase ${phase} must accept its valid row`).toEqual([]);
    }
  });

  it("rejects all 35 cells of the phase NULL matrix when flipped (both polarities per CHECK)", () => {
    const cells = phaseLiterals.flatMap((phase) =>
      phaseChecks.map((check) => ({ phase, check })),
    );
    expect(cells).toHaveLength(35);
    for (const { phase, check } of cells) {
      const row: Record<string, string | number | null> = { ...attemptRowAt(phase) };
      row[check.column] =
        row[check.column] === null ? NON_NULL_BY_COLUMN[check.column] ?? "x" : null;
      const violations = validateRowAgainstTable(attempts, domains, row);
      expect(
        violations,
        `flipped ${check.column} at ${phase} must violate its biconditional CHECK`,
      ).toContain(`PHASE:${check.column}`);
    }
    // Polarity coverage: every one of the seven CHECKs is fed a value-before-its-phase input
    // AND an absent-at-its-phase input somewhere in the matrix — >= 14 directed negatives.
    for (const check of phaseChecks) {
      const nullExpected = phaseLiterals.filter((phase) => phaseCheckExpectsNull(check, phase));
      const valueExpected = phaseLiterals.filter((phase) => !phaseCheckExpectsNull(check, phase));
      expect(nullExpected.length, `${check.column}: no phase feeds the too-early polarity`).toBeGreaterThan(0);
      expect(valueExpected.length, `${check.column}: no phase feeds the too-late polarity`).toBeGreaterThan(0);
    }
  });

  it("rejects a duplicate (operation_id, attempt_no = 1) on the composite primary key", () => {
    const first = attemptRowAt("INNER_PREIMAGE_PERSISTED");
    const duplicate = attemptRowAt("STEP1_SIGNATURE_PERSISTED");
    const verdict = simulateInsert([first], duplicate, attempts, domains);
    expect(verdict.committed).toBe(false);
    expect(verdict.rejectedByKey).toEqual({ kind: "PRIMARY KEY", columns: ["operation_id", "attempt_no"] });
  });

  it("rejects attempt_no = 2 on the column CHECK even when the primary key does not fire", () => {
    const first = attemptRowAt("INNER_PREIMAGE_PERSISTED");
    const secondAttempt = attemptRowAt("INNER_PREIMAGE_PERSISTED", {
      operation_id: "op-2",
      attempt_no: 2,
    });
    const verdict = simulateInsert([first], secondAttempt, attempts, domains);
    expect(verdict.committed).toBe(false);
    expect(verdict.rejectedByKey).toBeNull();
    expect(verdict.violations).toContain("CHECK:attempt_no");
  });

  it("rejects a bogus sixth attempt_phase literal", () => {
    const row = attemptRowAt("SETTLED_BODY_PERSISTED", { attempt_phase: "FINALIZED" });
    const violations = validateRowAgainstTable(attempts, domains, row);
    expect(violations).toContain("PHASE_LITERAL:attempt_phase");
  });

  it.each([0, -1])("rejects lease_epoch = %i on the sign-intent CHECK", (leaseEpoch) => {
    const violations = validateRowAgainstTable(signIntents, domains, signIntentRow({ lease_epoch: leaseEpoch }));
    expect(violations).toContain("CHECK:lease_epoch");
  });

  it("accepts the smallest positive lease_epoch", () => {
    expect(validateRowAgainstTable(signIntents, domains, signIntentRow({ lease_epoch: 1 }))).toEqual([]);
  });

  it("rejects an empty inner_preimage_text on the octet-length CHECK", () => {
    const violations = validateRowAgainstTable(signIntents, domains, signIntentRow({ inner_preimage_text: "" }));
    expect(violations).toContain("OCTET:inner_preimage_text");
  });

  it("rejects redelivery_count = -1 and accepts the default 0", () => {
    expect(
      validateRowAgainstTable(partials, domains, partialRow({ redelivery_count: -1 })),
    ).toContain("CHECK:redelivery_count");
    expect(validateRowAgainstTable(partials, domains, partialRow({ redelivery_count: 0 }))).toEqual([]);
  });

  it("rejects malformed sha256_hex values (wrong length, wrong alphabet)", () => {
    expect(
      validateRowAgainstTable(signIntents, domains, signIntentRow({ inner_sha256: "a".repeat(63) })),
    ).toContain("DOMAIN:inner_sha256");
    expect(
      validateRowAgainstTable(signIntents, domains, signIntentRow({ inner_sha256: "A".repeat(64) })),
    ).toContain("DOMAIN:inner_sha256");
  });

  it("rejects malformed padded_base64url_signature values (missing pad, bad alphabet, NULL on the partial)", () => {
    expect(
      validateRowAgainstTable(partials, domains, partialRow({ step_1_signature: "A".repeat(86) })),
    ).toContain("DOMAIN:step_1_signature");
    expect(
      validateRowAgainstTable(partials, domains, partialRow({ step_1_signature: `${"+".repeat(86)}==` })),
    ).toContain("DOMAIN:step_1_signature");
    expect(
      validateRowAgainstTable(partials, domains, partialRow({ step_1_signature: null })),
    ).toContain("NOT NULL:step_1_signature");
  });
});

describe("concurrency structural proof (derived from parsed uniqueness surfaces)", () => {
  it("cites the application-layer compare-and-swap guard frozen in signing custody", () => {
    expect(FORMATION_TRANSITIONS[0]?.guard).toBe(
      "persist_sign_intent_before_signer_then_compare_and_swap",
    );
  });

  it("race: two workers inserting a sign intent for the same operation — exactly one commits, on the primary key", () => {
    const workerA = signIntentRow({ approval_id: "approval-A" });
    const workerB = signIntentRow({ approval_id: "approval-B" });
    for (const [first, second] of [
      [workerA, workerB],
      [workerB, workerA],
    ]) {
      const firstVerdict = simulateInsert([], first, signIntents, domains);
      const secondVerdict = simulateInsert([first], second, signIntents, domains);
      expect(firstVerdict.committed).toBe(true);
      expect(secondVerdict.committed).toBe(false);
      expect(secondVerdict.rejectedByKey?.kind).toBe("PRIMARY KEY");
    }
  });

  it("race: the same approval_id under two DIFFERENT operations — exactly one commits, on the approval UNIQUE of BOTH tables (schema-apply obligation 6)", () => {
    for (const [table, row] of [
      [signIntents, signIntentRow],
      [partials, partialRow],
    ] as const) {
      const workerA = row({ operation_id: "op-A", approval_id: "approval-shared" });
      const workerB = row({ operation_id: "op-B", approval_id: "approval-shared" });
      for (const [first, second] of [
        [workerA, workerB],
        [workerB, workerA],
      ]) {
        const firstVerdict = simulateInsert([], first, table, domains);
        const secondVerdict = simulateInsert([first], second, table, domains);
        expect(firstVerdict.committed).toBe(true);
        expect(secondVerdict.committed).toBe(false);
        // The rejection must come from the approval UNIQUE, not the primary key — feeding the
        // duplicate under different operation_ids is what keeps this proof non-vacuous.
        expect(secondVerdict.rejectedByKey).toEqual({ kind: "UNIQUE", columns: ["approval_id"] });
      }
    }
  });

  it("race: two workers persisting the partial for one send — exactly one commits, on the primary key", () => {
    const workerA = partialRow({ transfer_code_sha256: SHA_A });
    const workerB = partialRow({ transfer_code_sha256: SHA_B });
    for (const [first, second] of [
      [workerA, workerB],
      [workerB, workerA],
    ]) {
      const firstVerdict = simulateInsert([], first, partials, domains);
      const secondVerdict = simulateInsert([first], second, partials, domains);
      expect(firstVerdict.committed).toBe(true);
      expect(secondVerdict.committed).toBe(false);
      expect(secondVerdict.rejectedByKey?.kind).toBe("PRIMARY KEY");
    }
  });

  it("a replacement under a NEW approval still fails on operation_id — expiry forces a new operation", () => {
    for (const [table, existing, replacement, freshOperation] of [
      [
        signIntents,
        signIntentRow(),
        signIntentRow({ approval_id: "approval-fresh" }),
        signIntentRow({ operation_id: "op-new", approval_id: "approval-fresh" }),
      ],
      [
        partials,
        partialRow(),
        partialRow({ approval_id: "approval-fresh" }),
        partialRow({ operation_id: "op-new", approval_id: "approval-fresh" }),
      ],
    ] as const) {
      const replacementVerdict = simulateInsert([existing], replacement, table, domains);
      expect(replacementVerdict.committed).toBe(false);
      expect(replacementVerdict.rejectedByKey?.kind).toBe("PRIMARY KEY");
      const freshVerdict = simulateInsert([existing], freshOperation, table, domains);
      expect(freshVerdict.committed).toBe(true);
    }
  });

  it("scope: the parsed surfaces are per-operation and per-approval only — never per-wallet", () => {
    // Per-wallet exclusion is the lease layer's job (wallet_active_leases in
    // custody-eligibility.sql; the test plan structural proof), NOT this contract's. This
    // contract must not overclaim it: no uniqueness surface here may span source_wallet_id.
    for (const keySet of keySetsFor(signIntents)) {
      expect(keySet.columns).not.toContain("source_wallet_id");
    }
    expect(keySetsFor(signIntents).map((keySet) => keySet.columns)).toEqual([
      ["operation_id"],
      ["approval_id"],
    ]);
  });
});
