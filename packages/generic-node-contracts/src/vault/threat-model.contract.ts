/**
 * SOURCE: the signing-custody vault and threat-model contract; the vault-storage decision (the five guards)
 * + the dual-run addendum failure modes. the vault threat-model freeze freezes the vault threat model: each threat
 * class, its mitigating control mapped to the vault model freeze/.2 contract, the guard it belongs to, and
 * the detection outcome. threat-verifier.ts proves each control catches its threat by reading the
 * actual frozen contract values, so weakening a control fails these tests.
 */

export interface ThreatEntry {
  readonly id: string;
  readonly guard: string;
  readonly family: string;
  readonly control: string;
  readonly control_source: readonly string[];
  readonly caught_outcome: string;
}

export const THREAT_MATRIX = [
  {
    id: "SUBSTITUTION_CROSS_WALLET",
    guard: "GUARD_2",
    family: "SUBSTITUTION",
    control: "AAD binds wallet_id; decrypt-derive-pubkey-match backstop",
    control_source: ["AAD_BINDING", "SUBSTITUTION_CONTROL"],
    caught_outcome: "AAD_MISMATCH",
  },
  {
    id: "SUBSTITUTION_CROSS_VERSION",
    guard: "GUARD_2",
    family: "SUBSTITUTION",
    control: "AAD binds key_version (per-row epoch)",
    control_source: ["AAD_BINDING"],
    caught_outcome: "AAD_MISMATCH",
  },
  {
    id: "SUBSTITUTION_CROSS_ORIGIN",
    guard: "GUARD_2",
    family: "SUBSTITUTION",
    control: "AAD binds key_origin",
    control_source: ["AAD_BINDING"],
    caught_outcome: "AAD_MISMATCH",
  },
  {
    id: "KEY_SMUGGLE_ORIGIN_FLIP",
    guard: "GUARD_2",
    family: "SUBSTITUTION",
    control: "AAD binds key_origin; imported->node_generated flip fails decrypt",
    control_source: ["AAD_BINDING", "SUBSTITUTION_CONTROL"],
    caught_outcome: "AAD_MISMATCH",
  },
  {
    id: "AAD_STRIP_REORDER",
    guard: "GUARD_2",
    family: "SUBSTITUTION",
    control: "AAD reconstructed at open in the frozen field sequence, never from a stored column",
    control_source: ["AAD_BINDING", "AAD_FULL_FIELD_SEQUENCE"],
    caught_outcome: "AAD_MISMATCH",
  },
  {
    id: "STORED_AAD_DOWNGRADE",
    guard: "GUARD_2",
    family: "AAD_PROVENANCE",
    control: "no aad_text column; open reconstructs from authoritative fields only",
    control_source: ["ENVELOPE_STRUCTURE", "SEALING_API"],
    caught_outcome: "RECONSTRUCT_ONLY",
  },
  {
    id: "NONCE_REUSE",
    guard: "GUARD_1",
    family: "NONCE",
    control: "structural UNIQUE(key_version, nonce) plus per-wallet DEK isolation",
    control_source: ["KEY_ISOLATION", "VAULT_CONSTRAINTS"],
    caught_outcome: "WRITE_ABORT",
  },
  {
    id: "TRUNCATED_CIPHERTEXT",
    guard: "OPEN_INTEGRITY",
    family: "OPEN_INTEGRITY",
    control: "octet-length check plus AES-256-GCM tag verification",
    control_source: ["VAULT_CONSTRAINTS", "VAULT_OPEN_FAILURE_CODES"],
    caught_outcome: "LENGTH_OR_TAG_FAILURE",
  },
  {
    id: "ROTATION_CRASH_WINDOW",
    guard: "GUARD_3",
    family: "ROTATION",
    control: "old key retained until committed marker; failed row aborts without advancing writer",
    control_source: ["ROTATION_INVARIANTS"],
    caught_outcome: "RESUME_BEFORE_DECOMMISSION",
  },
  {
    id: "RESTORE_WITH_STALE_VAULT",
    guard: "GUARD_3",
    family: "ROTATION",
    control: "old key retained until marker; boot key-ring reads mixed key_version",
    control_source: ["ROTATION_INVARIANTS"],
    caught_outcome: "MIXED_VERSION_RESUME",
  },
  {
    id: "SIGNING_DURING_ROTATION",
    guard: "GUARD_4",
    family: "CONCURRENCY",
    control: "signing holds no vault row lock; rotation quiesces signing under the lease",
    control_source: ["SIGNING_CONCURRENCY"],
    caught_outcome: "SIGNING_QUIESCED",
  },
  {
    id: "KEY_DISCLOSURE_LOGS_DUMPS",
    guard: "GUARD_5",
    family: "MEMORY_HYGIENE",
    control: "keys never logged; core dumps disabled",
    control_source: ["ZEROIZATION", "SIGNER_BOUNDARY"],
    caught_outcome: "WIPED_NEVER_LOGGED",
  },
  {
    id: "STALE_PROCESS_HOLDS_KEY",
    guard: "GUARD_5",
    family: "MEMORY_HYGIENE",
    control: "secure buffer wiped with sodium_memzero immediately after signing",
    control_source: ["ZEROIZATION", "ZEROIZATION_INTERFACE"],
    caught_outcome: "WIPED_POST_SIGN",
  },
  {
    id: "CROSS_STORE_KEY_DERIVATION_COLLISION",
    guard: "GUARD_1",
    family: "KEY_DERIVATION",
    control: "distinct globally-unique HKDF domain label per sealed store",
    control_source: ["HKDF_INFO_ENCODING", "CROSS_STORE_LABEL_SEPARATION"],
    caught_outcome: "DISTINCT_DERIVED_KEY",
  },
] as const satisfies readonly ThreatEntry[];

export type ThreatId = (typeof THREAT_MATRIX)[number]["id"];

/** The vault-storage rule five guards; the census asserts every guard mitigates at least one threat.*/
export const D9_11_GUARDS = ["GUARD_1", "GUARD_2", "GUARD_3", "GUARD_4", "GUARD_5"] as const;
