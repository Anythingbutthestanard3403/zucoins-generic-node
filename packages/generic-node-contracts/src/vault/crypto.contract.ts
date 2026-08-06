/**
 * SOURCE: the vault-storage decision guard 1 (per-wallet key derivation), carried-forward model-independent vault invariants
 * (600k anchor, AES-256-GCM), the TOTP sealed-store rule / the sealed-store rule pattern (HKDF domain-separated key).
 *
 * The key-hierarchy ALGORITHM and PARAMETER contract only — identifiers and numeric parameters
 * as frozen data. the vault model freeze freezes NO real key material and NO exact byte encoding: the PBKDF2
 * salt/root bytes and the HKDF info-string encoding are the vault schema freeze's byte subcontract, listed in
 * compatibility.contract.ts DEFERRED_SUBCONTRACTS. `source_env_name` is a frozen NAME string,
 * never read.
 */

export const KEY_DERIVATION = {
  root: {
    algorithm: "PBKDF2-SHA256",
    iterations: 600000,
    applies: "ONCE_AT_BOOT",
    source_env_name: "VAULT_MASTER_KEY",
    output: "ROOT",
  },
  wallet_dek: {
    algorithm: "HKDF-SHA256",
    input: "ROOT",
    info_binds: ["node_id", "wallet_id", "key_version"],
    output: "DEK_WALLET",
    exact_info_encoding_owner: "vault.2",
  },
  seal: {
    algorithm: "AES-256-GCM",
    nonce_bits: 96,
    nonce_source: "CSPRNG_FRESH_PER_SEAL",
    tag_bits: 128,
    sealed_material: "ED25519_SECRET_64_BYTES",
  },
} as const;

/**
 * The per-key blast-radius isolation the per-wallet DEK restores versus the rejected shared-key
 * draft: distinct DEK per wallet makes a nonce collision across wallets harmless, and the
 * structural constraint turns a same-key nonce-reuse bug into a write abort, never a silent GCM
 * catastrophe.
 */
export const KEY_ISOLATION = {
  per_wallet_dek: true,
  cross_wallet_nonce_collision_harmless: true,
  structural_nonce_reuse_guard: "UNIQUE(key_version, nonce)",
} as const;
