/**
 * SOURCE: the vault-storage decision (carried-forward model-independent vault invariants; the dual-run addendum's
 * census + the vault key_version semantics rule landmine), the vault key_version semantics rule (v1 key_version semantics), the secure-buffer rule (secure buffer), the TOTP sealed-store rule
 * the sealed-store rule (other sealed stores).
 */

/** the model-independent vault invariants model-independent invariants carried forward unchanged into v2 (the vault-storage rule).*/
export const CARRIED_FORWARD_INVARIANTS = [
  "AES-256-GCM",
  "ENV_MASTER_KEY",
  "PLAINTEXT_KEY_MATERIAL_IN_MEMORY_ONLY",
  "ZEROED_AFTER_USE",
  "SINGLE_WRITER_FOR_MUTATIONS",
  "PLATFORM_ZERO_KEY_CUSTODY",
] as const;

/**
 * the vault key_version semantics rule landmine. v1's `key_version` is an append counter that must NOT bump on master-key
 * rotation. v2 has no shared blob or append counter: `key_version` is the per-row epoch and
 * rotation DOES bump it per row. The two semantics are inverses; tests assert the inverse so v1
 * behaviour is never imported.
 */
export const KEY_VERSION_SEMANTICS = {
  v1: "APPEND_COUNTER_NEVER_BUMPS_ON_MASTER_ROTATION",
  v2: "PER_ROW_EPOCH_BUMPS_ON_ROTATION",
} as const;

export interface SealedStoreEntry {
  readonly store: string;
  readonly derivation: string;
  readonly nonce: string;
}

/**
 * The dual-run addendum scopes the five guards to EVERY store sealed under the env master key.
 * This census asserts none is left on a shared-key or reused-nonce shortcut. Concrete per-store
 * schemas are owned by their own concerns; this is the architecture-level completeness claim.
 */
export const SEALED_STORE_CENSUS = [
  { store: "WALLET_KEYS", derivation: "PER_WALLET_HKDF", nonce: "FRESH_PER_SEAL" },
  { store: "NODE_SIGNING_AND_EVENT_KEYS", derivation: "PER_STORE_HKDF", nonce: "FRESH_PER_SEAL" },
  { store: "TOTP_D8119", derivation: "PER_STORE_HKDF", nonce: "FRESH_PER_SEAL" },
  { store: "WEBHOOK_SECRET_D826", derivation: "PER_STORE_HKDF", nonce: "FRESH_PER_SEAL" },
] as const satisfies readonly SealedStoreEntry[];

/** Concrete zeroization discipline (the vault-storage rule guard 5; the secure-buffer rule) — no soft "where the runtime permits".*/
export const ZEROIZATION = {
  buffer_type: "LIBSODIUM_SECURE_UINT8ARRAY",
  never_js_string: true,
  wipe: "SODIUM_MEMZERO_POST_SIGN",
  core_dumps: "DISABLED",
  keys_logged: false,
} as const;

/**
 * The honest boundary the custody dual-run synthesis fixed: the vault model freeze freezes the architecture
 * only and explicitly disowns these byte / schema / runtime subcontracts, so no reader mistakes
 * this ADR for cryptographic byte completeness.
 */
export const DEFERRED_SUBCONTRACTS = {
  "vault.2": [
    "exact PBKDF2 salt and root byte derivation",
    "exact HKDF info-string encoding",
    "exact 6-field AAD byte serialization",
    "active key_version selection",
    "concrete vault column schema, types, and CHECK constraints",
    "sealing and signer API signatures and failure codes",
  ],
  "vault.3": [
    "rotation journal and cutover format",
    "backup behaviour during mixed-version rotation",
    "threat matrices: row substitution, nonce reuse, wrong AAD or key, truncated ciphertext, concurrent rotation, crash recovery, stale process, logs, dumps, and restore",
  ],
} as const;
