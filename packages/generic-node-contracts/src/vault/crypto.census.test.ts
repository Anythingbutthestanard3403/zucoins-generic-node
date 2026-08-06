import { describe, expect, it } from "vitest";

import { KEY_DERIVATION, KEY_ISOLATION } from "./crypto.contract.ts";

describe("key-hierarchy algorithm + parameter contract is frozen (the vault model freeze; the vault-storage rule guard 1)", () => {
  it("PBKDF2 root parameters — 600k once at boot", () => {
    expect(KEY_DERIVATION.root.algorithm).toBe("PBKDF2-SHA256");
    expect(KEY_DERIVATION.root.iterations).toBe(600000);
    expect(KEY_DERIVATION.root.applies).toBe("ONCE_AT_BOOT");
    expect(KEY_DERIVATION.root.source_env_name).toBe("VAULT_MASTER_KEY");
  });

  it("per-wallet HKDF binds node_id, wallet_id, key_version; exact info encoding deferred", () => {
    expect(KEY_DERIVATION.wallet_dek.algorithm).toBe("HKDF-SHA256");
    expect(KEY_DERIVATION.wallet_dek.info_binds).toEqual(["node_id", "wallet_id", "key_version"]);
    expect(KEY_DERIVATION.wallet_dek.exact_info_encoding_owner).toBe("vault.2");
  });

  it("AES-256-GCM seal with a fresh 96-bit CSPRNG nonce over the 64-byte Ed25519 secret", () => {
    expect(KEY_DERIVATION.seal.algorithm).toBe("AES-256-GCM");
    expect(KEY_DERIVATION.seal.nonce_bits).toBe(96);
    expect(KEY_DERIVATION.seal.nonce_source).toBe("CSPRNG_FRESH_PER_SEAL");
    expect(KEY_DERIVATION.seal.tag_bits).toBe(128);
    expect(KEY_DERIVATION.seal.sealed_material).toBe("ED25519_SECRET_64_BYTES");
  });

  it("per-wallet DEK isolation and the structural nonce-reuse guard", () => {
    expect(KEY_ISOLATION.per_wallet_dek).toBe(true);
    expect(KEY_ISOLATION.cross_wallet_nonce_collision_harmless).toBe(true);
    expect(KEY_ISOLATION.structural_nonce_reuse_guard).toBe("UNIQUE(key_version, nonce)");
  });

  it("freezes no real key material — only identifiers and numeric parameters (negative)", () => {
    const serialized = JSON.stringify(KEY_DERIVATION);
    expect(serialized).not.toMatch(/[0-9a-f]{64}/); // no 32-byte hex key/secret value
    expect(KEY_DERIVATION.root).not.toHaveProperty("salt");
    expect(KEY_DERIVATION.root).not.toHaveProperty("root_bytes");
  });
});
