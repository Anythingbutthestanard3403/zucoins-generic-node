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
  it("resolves only the exact mode literals", () => {
    expect(parseDualControlMode("two_human")).toBe("two_human");
    expect(parseDualControlMode("single_operator")).toBe("single_operator");
  });

  // The fail-open regression this guards: every one of these once resolved to
  // single_operator, so an operator who typed the setting slightly wrong got no
  // dual control and no error (ZTR-1148).
  it.each(["two-human", "TWO_HUMAN", " two_human", "two_human ", "", "TWO-HUMAN", "yes"])(
    "never resolves a present-but-unrecognised value (%j) to a mode",
    (raw) => {
      expect(parseDualControlMode(raw)).toBe("invalid");
    },
  );

  // Deliberate and distinct from the above: doc 01 §4.2 makes node policy OPTIONAL,
  // so absence is "this deployment configured no policy", not a malformed value.
  // It is documented in .env.example, defaulted in the frozen schema, and readable
  // at GET /admin/v1/dual-control-policy — the three things the fail-open bug lacked.
  it("treats an absent setting as the documented no-policy default", () => {
    expect(parseDualControlMode(undefined)).toBe("single_operator");
    expect(parseDualControlMode(null)).toBe("single_operator");
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
