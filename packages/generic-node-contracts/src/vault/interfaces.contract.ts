/**
 * SOURCE: the signing-custody signer boundary + the vault-storage decision
 * guards 2/4/5. the vault schema freeze freezes the sealing / signer API SIGNATURE contracts, the leadership
 * rules, and the zeroization interface. Types are compile-checked contracts; the frozen data
 * consts are census-frozen. No implementation, no key access.
 */

export interface WalletSigningCapability {
  readonly walletId: string;
  readonly operationId: string;
  readonly leaseEpoch: bigint;
  readonly purpose: "SPLITCHAIN_STEP_1" | "SPLITCHAIN_STEP_2";
  readonly preimageText: string;
  readonly expectedPreimageSha256: string;
}

export interface WalletSecretEnvelope {
  readonly walletId: string;
  readonly keyVersion: number;
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly authTag: Uint8Array;
  readonly ciphertextSha256: string;
}

export interface SecureBuffer {
  readonly bytes: Uint8Array;
  wipe(): void;
}

export const SEALING_API = {
  seal: {
    name: "sealWalletSecret",
    inputs: ["node_id", "wallet_id", "key_version", "public_key", "key_origin", "ed25519_secret"],
    output: "vault_envelope_row",
    derives_dek_via: "HKDF_PER_WALLET",
    binds_aad: true,
  },
  open: {
    name: "openWalletSecret",
    inputs: ["vault_row", "authoritative_wallet_fields"],
    output: "ed25519_secret_in_secure_buffer",
    reconstructs_aad_from: "AUTHORITATIVE_FIELDS_NEVER_STORED_COLUMN",
    substitution_check: "DERIVE_PUBKEY_ASSERT_EQ_WALLETS_PUBLIC_KEY",
  },
} as const;

export const SIGNER_BOUNDARY = {
  capability_fields: [
    "walletId",
    "operationId",
    "leaseEpoch",
    "purpose",
    "preimageText",
    "expectedPreimageSha256",
  ],
  purposes: ["SPLITCHAIN_STEP_1", "SPLITCHAIN_STEP_2"],
  rereads_lease_before_decrypt: true,
  no_vault_row_lock: true,
  returns_only_signature_and_digest: true,
  never_returns_or_logs_private_key: true,
} as const;

export const LEADERSHIP_RULES = {
  mutations_single_writer: true,
  rotation_is_sole_all_envelope_writer: true,
  wallet_ordering_authority: "C-02_UNIVERSAL_LEASE",
  no_hybrid_fallback: true,
} as const;

export const ZEROIZATION_INTERFACE = {
  buffer: "SECURE_UINT8ARRAY",
  never_js_string: true,
  lifecycle: ["ALLOCATE", "DECRYPT_INTO", "SIGN", "WIPE"],
  wipe: "SODIUM_MEMZERO_MANDATORY_POST_SIGN",
} as const;
