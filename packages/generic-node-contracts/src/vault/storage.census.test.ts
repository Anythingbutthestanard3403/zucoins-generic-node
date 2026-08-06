import { describe, expect, it } from "vitest";

import {
  VAULT_STORAGE_GRAIN,
  VAULT_TABLE_NAME,
  VAULT_PRIMARY_KEY,
  VAULT_VERSION_COLUMN,
  STORAGE_RESOLUTION,
  ENVELOPE_STRUCTURE,
  REQUIRED_VAULT_MODEL,
  REJECTED_DRAFT_DESCRIPTOR,
} from "./storage.contract.ts";

describe("vault storage grain and naming are frozen (the vault model freeze; the vault-storage rule / the frozen rule)", () => {
  it("v2 grain and the frozen rule frozen names", () => {
    expect(VAULT_STORAGE_GRAIN).toBe("PER_WALLET_ENVELOPE_ROW");
    expect(VAULT_TABLE_NAME).toBe("vault");
    expect(VAULT_PRIMARY_KEY).toBe("wallet_id");
    expect(VAULT_VERSION_COLUMN).toBe("key_version");
  });

  it("the single-vault vs per-wallet resolution has no hybrid ambiguity", () => {
    expect(STORAGE_RESOLUTION).toEqual({
      v2_grain: "PER_WALLET_ENVELOPE_ROW",
      v1_grain: "SINGLE_VAULT_ROW",
      hybrid_permitted: false,
      migration_shim: false,
      v1_v2_disjoint: true,
    });
  });

  it("the envelope logical structure freezes sizes, uniqueness, and no stored AAD column", () => {
    expect(ENVELOPE_STRUCTURE.cipher).toBe("AES-256-GCM");
    expect(ENVELOPE_STRUCTURE.nonce_bits).toBe(96);
    expect(ENVELOPE_STRUCTURE.tag_bits).toBe(128);
    expect(ENVELOPE_STRUCTURE.structural_unique).toEqual(["key_version", "nonce"]);
    expect(ENVELOPE_STRUCTURE.stored_aad_column).toBe(false);
  });

  it("the required model is the vault-storage rule hardened shape", () => {
    expect(REQUIRED_VAULT_MODEL).toEqual({
      grain: "PER_WALLET_ENVELOPE_ROW",
      hybridPermitted: false,
      keyDerivation: "PER_WALLET_HKDF",
      nonceSource: "CSPRNG_FRESH_PER_SEAL",
      aadSource: "RECONSTRUCTED_AT_OPEN",
      rotation: "CRASH_SAFE_RESUMABLE_KEY_RING",
    });
  });

  it("the rejected draft deviates from the required model (negative fixture)", () => {
    expect(REJECTED_DRAFT_DESCRIPTOR.keyDerivation).toBe("NAKED_MASTER_KEY");
    expect(REJECTED_DRAFT_DESCRIPTOR.nonceSource).toBe("RANDOM_SHARED");
    expect(REJECTED_DRAFT_DESCRIPTOR.aadSource).toBe("STORED_COLUMN");
    expect(REJECTED_DRAFT_DESCRIPTOR.table).toBe("wallet_secrets");
    expect(REJECTED_DRAFT_DESCRIPTOR.keyDerivation).not.toBe(REQUIRED_VAULT_MODEL.keyDerivation);
  });
});
