import { describe, it, expect } from "vitest";
import { enforceAmountField } from "./enforcement.js";
import { AMOUNT_FIELD_ROLES, type AmountFieldRole } from "./field-roles.js";
import { AMOUNT_REJECTION_REASONS } from "./manifest.js";

const roles = Object.keys(AMOUNT_FIELD_ROLES) as AmountFieldRole[];
const operationRoles = roles.filter((r) => AMOUNT_FIELD_ROLES[r].layer === "operation");
const balanceRoles = roles.filter((r) => AMOUNT_FIELD_ROLES[r].layer === "balance");
const foreignRoles = roles.filter((r) => AMOUNT_FIELD_ROLES[r].authorship === "foreign");

const NINES_32 = "9".repeat(32);
const GREATEST = `99999999.${NINES_32}`;

describe("enforceAmountField — one typed rejection contract", () => {
  it("every node rejection has the same shape { kind:'rejected', role, layer, reason, value }", () => {
    expect(enforceAmountField("operation_amount_zkz", "0")).toEqual({
      kind: "rejected",
      role: "operation_amount_zkz",
      layer: "operation",
      reason: AMOUNT_REJECTION_REASONS.notPositive,
      value: "0",
    });
    expect(enforceAmountField("node_head_amount", "1e5")).toEqual({
      kind: "rejected",
      role: "node_head_amount",
      layer: "balance",
      reason: AMOUNT_REJECTION_REASONS.grammar,
      value: "1e5",
    });
  });
  it("accepts a canonical positive amount for every node role", () => {
    for (const role of [...operationRoles, ...balanceRoles]) {
      expect(enforceAmountField(role, "2.5")).toEqual({ kind: "accepted", role, canonical: "2.5" });
    }
  });
});

describe("enforceAmountField — layer split (zero)", () => {
  it("zero is REJECTED for every operation role (consistently, not-positive)", () => {
    for (const role of operationRoles) {
      const result = enforceAmountField(role, "0");
      expect(result.kind).toBe("rejected");
      if (result.kind === "rejected") {
        expect(result.reason).toBe(AMOUNT_REJECTION_REASONS.notPositive);
      }
    }
  });
  it("zero is ACCEPTED for every balance role (swept-payer / genesis '0')", () => {
    for (const role of balanceRoles) {
      expect(enforceAmountField(role, "0")).toEqual({ kind: "accepted", role, canonical: "0" });
    }
  });
});

describe("enforceAmountField — boundary conditions rejected consistently (all node roles)", () => {
  const nodeRoles = [...operationRoles, ...balanceRoles];
  const rejectedBoundaries: Array<[string, string, string]> = [
    ["100000000", AMOUNT_REJECTION_REASONS.grammar, "exact upper bound"],
    ["100000000.1", AMOUNT_REJECTION_REASONS.grammar, "overflow"],
    ["100000001", AMOUNT_REJECTION_REASONS.grammar, "overflow integer"],
    ["1e5", AMOUNT_REJECTION_REASONS.grammar, "exponent notation"],
    [`0.${"1".repeat(33)}`, AMOUNT_REJECTION_REASONS.grammar, "excess precision (33 dp)"],
    ["2.50", AMOUNT_REJECTION_REASONS.nonCanonical, "non-canonical trailing zero"],
    ["-1", AMOUNT_REJECTION_REASONS.grammar, "negative"],
  ];
  for (const [value, reason, why] of rejectedBoundaries) {
    it(`${JSON.stringify(value)} (${why}) rejected with ${reason} for every node role`, () => {
      for (const role of nodeRoles) {
        const result = enforceAmountField(role, value);
        expect(result.kind).toBe("rejected");
        if (result.kind === "rejected") expect(result.reason).toBe(reason);
      }
    });
  }
  it("the greatest representable value below the bound succeeds for every node role", () => {
    for (const role of nodeRoles) {
      expect(enforceAmountField(role, GREATEST)).toEqual({
        kind: "accepted",
        role,
        canonical: GREATEST,
      });
    }
  });
});

describe("enforceAmountField — foreign roles inspect, never reject (the byte-exact signing rule)", () => {
  it("returns foreign bytes verbatim and never canonicalizes or rejects", () => {
    for (const role of foreignRoles) {
      const wellFormed = enforceAmountField(role, "2.50");
      expect(wellFormed).toEqual({
        kind: "foreign",
        role,
        bytes: "2.50",
        wellFormed: true,
        anomaly: null,
      });
      const malformed = enforceAmountField(role, "1e5");
      expect(malformed.kind).toBe("foreign");
      if (malformed.kind === "foreign") {
        expect(malformed.bytes).toBe("1e5");
        expect(malformed.wellFormed).toBe(false);
        expect(malformed.anomaly).toBe("foreign_amount_grammar_violation");
      }
    }
  });
  it("does not apply operation positivity to a foreign zero", () => {
    for (const role of foreignRoles) {
      const result = enforceAmountField(role, "0");
      expect(result.kind).toBe("foreign");
      if (result.kind === "foreign") expect(result.wellFormed).toBe(true);
    }
  });
});
