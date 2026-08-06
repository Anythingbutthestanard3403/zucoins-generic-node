import { describe, expect, it } from "vitest";

import { THREAT_MATRIX } from "./threat-model.contract.ts";
import { assessThreat, isThreatMitigated } from "./threat-verifier.ts";

describe("each vault control catches its threat (the vault threat-model freeze)", () => {
  it.each(THREAT_MATRIX)("$id: the frozen control catches it -> $caught_outcome", (threat) => {
    expect(assessThreat(threat.id, true)).toBe(threat.caught_outcome);
    expect(isThreatMitigated(threat.id)).toBe(true);
  });
});

describe("disabling a control lets the threat through (the vault threat-model freeze negative path)", () => {
  it.each(THREAT_MATRIX)("$id: control disabled -> NOT_CAUGHT", (threat) => {
    expect(assessThreat(threat.id, false)).toBe("NOT_CAUGHT");
  });

  it("every threat has both a caught outcome and a control-disabled miss", () => {
    for (const threat of THREAT_MATRIX) {
      expect(assessThreat(threat.id, true)).not.toBe("NOT_CAUGHT");
      expect(assessThreat(threat.id, false)).toBe("NOT_CAUGHT");
    }
  });

  it("cross-store collision: the distinct HKDF label catches it; a shared label lets it through", () => {
    expect(assessThreat("CROSS_STORE_KEY_DERIVATION_COLLISION", true)).toBe("DISTINCT_DERIVED_KEY");
    expect(assessThreat("CROSS_STORE_KEY_DERIVATION_COLLISION", false)).toBe("NOT_CAUGHT");
  });
});
