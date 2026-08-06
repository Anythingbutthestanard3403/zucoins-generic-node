import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import { THREAT_MATRIX, D9_11_GUARDS } from "./threat-model.contract.ts";
import { assessThreat } from "./threat-verifier.ts";

describe("vault threat matrix is frozen (the vault threat-model freeze; the vault-storage decision)", () => {
  it("threat ids in frozen sequence", () => {
    assertFieldOrder(
      THREAT_MATRIX.map((threat) => threat.id),
      [
        "SUBSTITUTION_CROSS_WALLET",
        "SUBSTITUTION_CROSS_VERSION",
        "SUBSTITUTION_CROSS_ORIGIN",
        "KEY_SMUGGLE_ORIGIN_FLIP",
        "AAD_STRIP_REORDER",
        "STORED_AAD_DOWNGRADE",
        "NONCE_REUSE",
        "TRUNCATED_CIPHERTEXT",
        "ROTATION_CRASH_WINDOW",
        "RESTORE_WITH_STALE_VAULT",
        "SIGNING_DURING_ROTATION",
        "KEY_DISCLOSURE_LOGS_DUMPS",
        "STALE_PROCESS_HOLDS_KEY",
        "CROSS_STORE_KEY_DERIVATION_COLLISION",
      ],
    );
  });

  it("every threat maps its control to a named the vault model freeze/.2 contract and a caught outcome", () => {
    for (const threat of THREAT_MATRIX) {
      expect(threat.control_source.length).toBeGreaterThan(0);
      expect(threat.caught_outcome.length).toBeGreaterThan(0);
      expect(assessThreat(threat.id, true)).toBe(threat.caught_outcome);
    }
  });

  it("five-guard census: every the vault-storage rule guard mitigates at least one threat (completeness)", () => {
    const guardsCovered = new Set(THREAT_MATRIX.map((threat) => threat.guard));
    for (const guard of D9_11_GUARDS) {
      expect(guardsCovered.has(guard)).toBe(true);
    }
  });

  it("every threat belongs to the vault-storage rule guard or the open-integrity control", () => {
    const allowed = new Set<string>([...D9_11_GUARDS, "OPEN_INTEGRITY"]);
    for (const threat of THREAT_MATRIX) {
      expect(allowed.has(threat.guard)).toBe(true);
    }
  });
});
