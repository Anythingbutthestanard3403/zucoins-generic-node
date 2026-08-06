// Two-human dual control vs single-operator.

import { describe, expect, it } from "vitest";

import {
  DUAL_CONTROL_COPY,
  enforceDualControlOperators,
  InMemoryDualControlPolicy,
  parseDualControlMode,
} from "./dual-control-policy.js";
import { InMemoryApprovalChallengeIssuerStore } from "./challenge-issuer-store.js";

describe("dual-control policy modes", () => {
  it("defaults unknown/empty to single_operator", () => {
    expect(parseDualControlMode(undefined)).toBe("single_operator");
    expect(parseDualControlMode("")).toBe("single_operator");
    expect(parseDualControlMode("two_human")).toBe("two_human");
  });

  it("exposes plain-language copy for both modes", () => {
    expect(DUAL_CONTROL_COPY.single_operator.short).toMatch(/Single/i);
    expect(DUAL_CONTROL_COPY.two_human.short).toMatch(/Two-human/i);
    expect(DUAL_CONTROL_COPY.two_human.long).toMatch(/different admin operator/i);
  });
});

describe("enforceDualControlOperators", () => {
  it("single_operator allows same operator both sides", () => {
    const r = enforceDualControlOperators("single_operator", "op-1", "op-1");
    expect(r.ok).toBe(true);
  });

  it("two_human rejects same operator both sides", () => {
    const r = enforceDualControlOperators("two_human", "op-1", "op-1");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("same_operator_both_sides");
      expect(r.detail).toMatch(/different admin operator/i);
    }
  });

  it("two_human allows distinct operators", () => {
    const r = enforceDualControlOperators("two_human", "op-1", "op-2");
    expect(r.ok).toBe(true);
  });

  it("two_human fails closed when challenge issuer missing", () => {
    const r = enforceDualControlOperators("two_human", null, "op-2");
    expect(r.ok).toBe(false);
  });
});

describe("InMemoryDualControlPolicy + issuer store", () => {
  it("policy port switches modes", () => {
    const p = new InMemoryDualControlPolicy("single_operator");
    expect(p.getMode()).toBe("single_operator");
    p.setMode("two_human");
    expect(p.getMode()).toBe("two_human");
  });

  it("issuer store records and clears", () => {
    const s = new InMemoryApprovalChallengeIssuerStore();
    s.recordIssuer("op-id", "ch-1", "admin-a");
    expect(s.findIssuer("op-id")).toBe("admin-a");
    s.clear("op-id");
    expect(s.findIssuer("op-id")).toBeNull();
  });
});
