import { describe, expect, it } from "vitest";

import { parseProposedIntegrationRule } from "./proposed-rule.js";

describe("parseProposedIntegrationRule", () => {
  it("accepts a minimal valid rule", () => {
    const r = parseProposedIntegrationRule({
      per_send_max_zkz: "0.001",
      window_hours: 24,
      window_cap_zkz: "1",
    });
    expect(r).not.toBeNull();
    expect(r?.per_send_max_zkz).toBe("0.001");
    expect(r?.per_send_min_zkz).toBeNull();
  });

  it("rejects implementer_id (must be absent at proposal)", () => {
    expect(
      parseProposedIntegrationRule({
        implementer_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        per_send_max_zkz: "1",
        window_hours: 1,
        window_cap_zkz: "1",
      }),
    ).toBeNull();
  });

  it("rejects unknown fields and bad windows", () => {
    expect(
      parseProposedIntegrationRule({
        per_send_max_zkz: "1",
        window_hours: 0,
        window_cap_zkz: "1",
      }),
    ).toBeNull();
    expect(
      parseProposedIntegrationRule({
        per_send_max_zkz: "1",
        window_hours: 1,
        window_cap_zkz: "1",
        enabled: true,
      }),
    ).toBeNull();
  });
});
