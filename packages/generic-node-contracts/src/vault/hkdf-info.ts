/**
 * SOURCE: the vault-storage decision guard 1 + the AAD/HKDF encoding decision
 * (2026-07-19). The decision AMENDED the HKDF info encoding: it
 * MUST carry its own domain label. Under a shared root, the label is the ONLY separation stopping
 * two sealed stores deriving the SAME AES key (a vault-scoped UNIQUE(key_version,nonce) cannot
 * catch a cross-store nonce collision -> GCM catastrophe). Amended form:
 * zp-wallet-dek-v1\n<node_id>\n<wallet_id>\n<key_version> (4 LF-joined fields)
 *
 * STATUS: FROZEN (the amended form is operative). Byte contract (the byte-exact signing rule
 * 3) — never reformat.
 */

/** The wallet-DEK HKDF domain label — globally unique across sealed stores. */
export const HKDF_DEK_LABEL = "zp-wallet-dek-v1" as const;

export const HKDF_INFO_ENCODING = {
  status: "FROZEN",
  decision: "AAD/HKDF encoding decision 2026-07-19 (amended)",
  method: "NEWLINE_JOINED_UTF8",
  domain_prefixed: true,
  domain: "zp-wallet-dek-v1",
  field_sequence: ["domain", "node_id", "wallet_id", "key_version"],
} as const;

/** HKDF-SHA256 parameters (decision-pinned). Salt is never per-row; IKM is the PBKDF2 root. */
export const HKDF_PARAMS = {
  algorithm: "HKDF-SHA256",
  output_length_bytes: 32,
  salt: "EMPTY",
  salt_per_row: false,
  ikm: "ROOT",
} as const;

/**
 * Cross-store separation requirement. Each VAULT_MASTER_KEY-sealed store derives under a globally
 * unique HKDF label; sibling stores' labels are their own sub-freezes and are deliberately NOT
 * frozen here.
 */
export const CROSS_STORE_LABEL_SEPARATION = {
  requirement: "GLOBALLY_UNIQUE_HKDF_LABEL_PER_STORE",
  this_store_label: "zp-wallet-dek-v1",
  sibling_store_labels_owned_elsewhere: true,
  rationale:
    "under a shared root the label is the only thing stopping two stores deriving the same AES key",
} as const;

export interface WalletDekInfoInputs {
  readonly nodeId: string;
  readonly walletId: string;
  readonly keyVersion: string;
}

/** Construct the exact UTF-8 HKDF info text. Deterministic string assembly; not a crypto op. */
export const buildWalletDekInfo = (inputs: WalletDekInfoInputs): string =>
  [HKDF_DEK_LABEL, inputs.nodeId, inputs.walletId, inputs.keyVersion].join("\n");

/** Frozen golden with synthetic, obviously-fake inputs; `info_sha256` pins the exact bytes. */
export const HKDF_INFO_GOLDEN = {
  inputs: {
    nodeId: "11111111-1111-4111-8111-111111111111",
    walletId: "22222222-2222-4222-8222-222222222222",
    keyVersion: "1",
  },
  info_text:
    "zp-wallet-dek-v1\n11111111-1111-4111-8111-111111111111\n22222222-2222-4222-8222-222222222222\n1",
  info_sha256: "ee42fe8ff3a40e33625244d9331a90e153e7198867ac0fc7c922e93917a8c431",
} as const;
