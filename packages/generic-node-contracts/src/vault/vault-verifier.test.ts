import { describe, expect, it } from "vitest";

import { REQUIRED_VAULT_MODEL, REJECTED_DRAFT_DESCRIPTOR } from "./storage.contract.ts";
import {
  verifyVaultModelDescriptor,
  isConformantVaultModel,
  verifySealedStore,
} from "./vault-verifier.ts";

describe("verifyVaultModelDescriptor accepts the hardened model, rejects the draft (the vault model freeze)", () => {
  it("the vault-storage rule hardened model conforms", () => {
    expect(verifyVaultModelDescriptor(REQUIRED_VAULT_MODEL)).toEqual([]);
    expect(isConformantVaultModel(REQUIRED_VAULT_MODEL)).toBe(true);
  });

  it("the rejected draft yields exactly the four hardening violations (negative path)", () => {
    const violations = verifyVaultModelDescriptor(REJECTED_DRAFT_DESCRIPTOR);
    expect([...violations].sort()).toEqual(
      [
        "KEY_DERIVATION_NOT_PER_WALLET_HKDF",
        "NONCE_NOT_FRESH_PER_SEAL",
        "AAD_NOT_RECONSTRUCTED",
        "ROTATION_NOT_CRASH_SAFE",
      ].sort(),
    );
    expect(isConformantVaultModel(REJECTED_DRAFT_DESCRIPTOR)).toBe(false);
  });

  it("a single-blob grain and a permitted hybrid are each caught", () => {
    expect(
      verifyVaultModelDescriptor({ ...REQUIRED_VAULT_MODEL, grain: "SINGLE_VAULT_ROW" }),
    ).toContain("GRAIN_NOT_PER_WALLET");
    expect(
      verifyVaultModelDescriptor({ ...REQUIRED_VAULT_MODEL, hybridPermitted: true }),
    ).toContain("HYBRID_FORBIDDEN");
  });
});

describe("verifySealedStore rejects shared-key / reused-nonce shortcuts (the vault model freeze)", () => {
  it("a per-store HKDF + fresh-nonce store conforms", () => {
    expect(
      verifySealedStore({ store: "X", derivation: "PER_STORE_HKDF", nonce: "FRESH_PER_SEAL" }),
    ).toEqual([]);
  });

  it("a shared-key shortcut is flagged (negative path)", () => {
    expect(
      verifySealedStore({ store: "X", derivation: "SHARED_MASTER_KEY", nonce: "FRESH_PER_SEAL" }),
    ).toContain("SHARED_KEY_SHORTCUT");
  });

  it("a reused-nonce shortcut is flagged (negative path)", () => {
    expect(
      verifySealedStore({ store: "X", derivation: "PER_STORE_HKDF", nonce: "RANDOM_SHARED" }),
    ).toContain("NONCE_SHORTCUT");
  });
});
