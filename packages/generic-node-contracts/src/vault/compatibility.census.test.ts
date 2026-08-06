import { describe, expect, it } from "vitest";

import {
  CARRIED_FORWARD_INVARIANTS,
  KEY_VERSION_SEMANTICS,
  SEALED_STORE_CENSUS,
  ZEROIZATION,
  DEFERRED_SUBCONTRACTS,
} from "./compatibility.contract.ts";
import { verifySealedStore } from "./vault-verifier.ts";

describe("compatibility and carried-forward invariants are frozen (the vault model freeze; the vault-storage rule)", () => {
  it("the model-independent vault invariants model-independent invariants are carried forward, the key-custody rule included", () => {
    expect(CARRIED_FORWARD_INVARIANTS).toContain("PLATFORM_ZERO_KEY_CUSTODY");
    expect(CARRIED_FORWARD_INVARIANTS).toContain("AES-256-GCM");
    expect(CARRIED_FORWARD_INVARIANTS).toContain("ZEROED_AFTER_USE");
  });

  it("the vault key_version semantics rule landmine: v2 key_version semantics are the inverse of v1 (negative)", () => {
    expect(KEY_VERSION_SEMANTICS.v1).toBe("APPEND_COUNTER_NEVER_BUMPS_ON_MASTER_ROTATION");
    expect(KEY_VERSION_SEMANTICS.v2).toBe("PER_ROW_EPOCH_BUMPS_ON_ROTATION");
    expect(KEY_VERSION_SEMANTICS.v2).not.toBe(KEY_VERSION_SEMANTICS.v1);
  });

  it("every VAULT_MASTER_KEY-sealed store is per-store HKDF with a fresh nonce — no shortcut", () => {
    expect(SEALED_STORE_CENSUS.length).toBeGreaterThanOrEqual(4);
    for (const entry of SEALED_STORE_CENSUS) {
      expect(verifySealedStore(entry)).toEqual([]);
    }
    const stores = SEALED_STORE_CENSUS.map((entry) => entry.store);
    expect(stores).toContain("WALLET_KEYS");
    expect(stores).toContain("TOTP_D8119");
  });

  it("concrete zeroization discipline is frozen (no soft where-permitted)", () => {
    expect(ZEROIZATION.buffer_type).toBe("LIBSODIUM_SECURE_UINT8ARRAY");
    expect(ZEROIZATION.never_js_string).toBe(true);
    expect(ZEROIZATION.wipe).toBe("SODIUM_MEMZERO_POST_SIGN");
    expect(ZEROIZATION.core_dumps).toBe("DISABLED");
  });

  it("byte/schema/runtime subcontracts are explicitly disowned to .2/.3", () => {
    expect(DEFERRED_SUBCONTRACTS["vault.2"]).toContain("exact 6-field AAD byte serialization");
    expect(DEFERRED_SUBCONTRACTS["vault.2"]).toContain("exact HKDF info-string encoding");
    expect(DEFERRED_SUBCONTRACTS["vault.3"].join(" ")).toContain("threat matrices");
  });
});
