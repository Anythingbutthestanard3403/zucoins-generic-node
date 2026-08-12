import { describe, expect, it } from "vitest";
import { parseAutoApprovePolicyStructure, type AutoApproveRule } from "@zucoins/node-core";
import { mergeRuleIntoAutoApprovePolicy } from "../src/admin-router.js";

const rule = (id: string): AutoApproveRule => ({
  rule_id: `r-${id}`,
  implementer_id: id,
  per_send_max_zkz: "1",
  per_send_min_zkz: null,
  window_hours: 24,
  window_cap_zkz: "10",
  expires_at: null,
  enabled: true,
});

describe("mergeRuleIntoAutoApprovePolicy (ZTR-1258)", () => {
  it("defaults brand-new absent document to enabled:true", () => {
    const m = mergeRuleIntoAutoApprovePolicy(
      { status: "disabled", disabledReason: "absent" },
      rule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
    );
    expect(m.ok).toBe(true);
    if (!m.ok) return;
    const p = parseAutoApprovePolicyStructure(m.documentJson);
    expect(p.ok).toBe(true);
    if (p.ok) expect(p.enabled).toBe(true);
  });

  it("keeps parked enabled:false when merging a rule", () => {
    const m = mergeRuleIntoAutoApprovePolicy(
      { status: "disabled", disabledReason: "off", rules: [] },
      rule("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
    );
    expect(m.ok).toBe(true);
    if (!m.ok) return;
    const p = parseAutoApprovePolicyStructure(m.documentJson);
    expect(p.ok).toBe(true);
    if (p.ok) {
      expect(p.enabled).toBe(false);
      expect(p.rules).toHaveLength(1);
    }
  });

  it("keeps enabled:true when document is already on", () => {
    const m = mergeRuleIntoAutoApprovePolicy(
      { status: "enabled", rules: [] },
      rule("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
    );
    expect(m.ok).toBe(true);
    if (!m.ok) return;
    const p = parseAutoApprovePolicyStructure(m.documentJson);
    expect(p.ok && p.enabled).toBe(true);
  });
});
