/**
 * The sealed-store registry: the key inventory, the vault AAD/DEK construction, rotation,
 * the closed backup-coverage set and its exclusions, `node_signing_keys`, `vault`, and the
 * wallet-vault model,
 * sealed-store rewrap census; sealed-store census.
 *
 * Static inventory of every VAULT_MASTER_KEY-sealed store the v2 generic node holds (or
 * will hold). Companion exclusions for reporting / webhook live in
 * sealed-store-exclusions.contract.ts.
 *
 * Operational rewrap primitives for stores with live seal-write runtime live in
 * `src/vault/rewrap.ts`. Stores whose seal-write runtime does not yet exist are registered
 * here with `rewrapStatus: "DEFERRED_NO_SEAL_RUNTIME"` (sealed-store rewrap census) so the census still pins
 * their identity; a future seal site fails the structural grep until registered + rewrap
 * lands.
 */

/** Closed set of v2 generic-node sealed-store ids. */
export type SealedStoreId =
  | "WALLET_VAULT"
  | "NODE_SIGNING_KEYS"
  | "PUSH_RECEIVER_SECRETS"
  | "TOTP_SECRET"
  | "SESSION_SECRETS";

export type HkdfLabelState = "FROZEN" | "DEFERRED";
export type TableState = "FROZEN" | "DEFERRED";
/**
 * `EXCLUDED_REGENERABLE` (EXCLUDED_REGENERABLE sealed-store class) records a store whose rows the node can re-mint from nothing
 * after a restore, so backup carries no obligation to hold them. It is NOT an amendment to
 * sealed-store backup coverage(2)'s closed EXCLUDED list: sealed-store backup coverage(2) mandates whole-table coverage for every
 * node-owned table in the data model, and `push_subscriptions` appears
 * nowhere in that document — it is a new table introduced by..1020 with DDL at
 * `packages/node-core/src/schema/push-subscriptions.sql`. `COVERAGE_TABLES` (41) and
 * `BACKUP_COVERAGE_TABLES` (43) were therefore never wrong to omit it, and recording a table
 * outside the mandated set changes no coverage — so no new format literal and no goldens.
 */
export type BackupCoverage =
  | "COVERED"
  | "EXCLUDED_AUTH_FACTOR"
  | "EXCLUDED_ROOT_KEY"
  | "EXCLUDED_REGENERABLE";

export type SealedStoreAccessPattern =
  | "SIGNER_BOUNDARY_READ_ONLY"
  | "SIGNER_BOUNDARY_SEAL_AND_READ"
  | "RECEIVER_BOUNDARY_SEAL_AND_READ"
  | "AUTH_FACTOR_SEAL_AND_VERIFY"
  | "AUTH_EPHEMERAL_SEAL_AND_VERIFY";

/** Whether a production `rewrap` primitive is executable today. */
export type RewrapStatus =
  | "IMPLEMENTED"
  | "DEFERRED_NO_SEAL_RUNTIME";

export interface SealedStoreEncryption {
  readonly cipher: "AES-256-GCM";
  /** Globally-unique HKDF info domain label, or null when deferred/direct-root. */
  readonly hkdfLabel: string | null;
  readonly hkdfLabelState: HkdfLabelState;
  /**
   * Descriptive AAD template. For WALLET_VAULT this uses real LF (0x0A) joiners matching
   * never the two-char literal backslash-n.
   */
  readonly aad: string;
}

export interface SealedStoreStorage {
  /** Every sealed store is database-resident by definition; the root key is not a store. */
  readonly databaseResident: true;
  /** Concrete table name when FROZEN by 04-data-model / a sub-freeze; null when DEFERRED. */
  readonly table: string | null;
  readonly tableState: TableState;
  readonly grain: string;
}

export interface SealedStoreDescriptor {
  readonly id: SealedStoreId;
  /** Logical coverage / inventory name (may differ from a deferred table). */
  readonly name: string;
  readonly purpose: string;
  readonly encryption: SealedStoreEncryption;
  readonly storage: SealedStoreStorage;
  readonly accessPattern: SealedStoreAccessPattern;
  readonly backupCoverage: BackupCoverage;
  /** Prose description of rotation treatment; executable rewrap is separate (rewrap.ts). */
  readonly rotationTreatment: string;
  readonly rewrapStatus: RewrapStatus;
  /**
   * Module path (repo-root relative) of the PRODUCTION seal site when one exists.
   * Drill-only reproductions are listed in REGISTERED_SEAL_SITES with kind DRILL.
   */
  readonly productionSealSite: string | null;
}

/**
 * Root key material seals stores; it is never itself a sealed store. Modelled here so the
 * census and backup coverage set stay complete without inventing a database row for it.
 */
export interface RootKeyMaterialDescriptor {
  readonly id: "VAULT_MASTER_KEY";
  readonly purpose: string;
  readonly derivation: {
    readonly kdf: "PBKDF2-SHA256";
    readonly iterations: number;
    readonly output: "ROOT";
  };
  readonly storage: { readonly databaseResident: false };
  readonly backupCoverage: "EXCLUDED_ROOT_KEY";
  readonly rotationTreatment: string;
}

export const ROOT_KEY_MATERIAL: RootKeyMaterialDescriptor = {
  id: "VAULT_MASTER_KEY",
  purpose:
    "operator-held 256-bit master; PBKDF2-SHA256-600k derives the process-lifetime " +
    "root = PBKDF2-SHA256-600k(master key), used in process memory only and zeroed after use",
  derivation: { kdf: "PBKDF2-SHA256", iterations: 600_000, output: "ROOT" },
  storage: { databaseResident: false },
  backupCoverage: "EXCLUDED_ROOT_KEY",
  rotationTreatment:
    "operator-supplied; rotation derives a fresh root from the new master key and re-wraps " +
    "every sealed store — the master key itself is never re-wrapped, archived, or persisted",
};

export const SEALED_STORES: readonly SealedStoreDescriptor[] = [
  {
    id: "WALLET_VAULT",
    name: "vault",
    purpose:
      "Ed25519 wallet secret (64 bytes) for SplitChain step 1 / step 2 signing; the public key " +
      "is held in `wallets`, the secret only here as a per-wallet AES-256-GCM envelope",
    encryption: {
      cipher: "AES-256-GCM",
      hkdfLabel: "zp-wallet-dek-v1",
      hkdfLabelState: "FROZEN",
      // real single LF (0x0A) between fields — never the two-char literal \n.
      aad: "zp-wallet-secret-v1\n<node_id>\n<wallet_id>\n<key_version>\n<public_key>\n<key_origin>",
    },
    storage: {
      databaseResident: true,
      table: "vault",
      tableState: "FROZEN",
      grain: "PER_WALLET_ENVELOPE_ROW",
    },
    accessPattern: "SIGNER_BOUNDARY_READ_ONLY",
    backupCoverage: "COVERED",
    rotationTreatment:
      "value-preserving master-key rewrap: open under old root, reseal under new root at the " +
      "SAME key_version with a fresh nonce; AAD source columns never touched; " +
      "N>1 wallet rows iterated — not a singleton",
    rewrapStatus: "IMPLEMENTED",
    productionSealSite: "packages/node-core/src/vault/envelope.ts",
  },
  {
    id: "NODE_SIGNING_KEYS",
    name: "node_signing_key_sealed_store",
    purpose:
      "node identity and event-signing Ed25519 private seeds (32 bytes); the public rows live in " +
      "`node_signing_keys`, each addressed by its `vault_secret_ref` sealed ciphertext",
    encryption: {
      cipher: "AES-256-GCM",
      // Frozen wallet-vault AAD and HKDF-info cross-store domain-separation register.
      hkdfLabel: "zp-node-signing-dek-v1",
      hkdfLabelState: "FROZEN",
      // Real single LF (0x0A) joiners — never the two-char literal \n (wallet-vault AAD and HKDF-info).
      aad: "zp-node-signing-secret-v1\n<node_id>\n<purpose>\n<public_key>\n<key_version>",
    },
    storage: {
      databaseResident: true,
      table: "node_signing_key_sealed_store",
      tableState: "FROZEN",
      grain: "PER_KEY_ENVELOPE_ROW",
    },
    accessPattern: "SIGNER_BOUNDARY_SEAL_AND_READ",
    backupCoverage: "COVERED",
    rotationTreatment:
      "value-preserving master-key rewrap: open under old root, reseal under new root at the " +
      "SAME key_version with a fresh nonce; AAD source columns never touched; " +
      "N≥0 per-key rows iterated",
    rewrapStatus: "IMPLEMENTED",
    productionSealSite: "packages/node-core/src/signing-keys/sealed-store.ts",
  },
  {
    id: "PUSH_RECEIVER_SECRETS",
    name: "push_subscriptions",
    purpose:
      "per-wallet Web Push receive ECDH private key and RFC 8291 auth secret; public receive material is stored separately",
    encryption: {
      cipher: "AES-256-GCM",
      // (i)'s cross-store domain-separation register. Info is the
      // label LF-joined with <node_id> and <wallet_id>; key_version is DB tracking only and
      // is deliberately absent, because rotation trial-decrypts across the key ring rather
      // than selecting an info string by epoch (push/rewrap.ts openWithPushKeyRing).
      hkdfLabel: "zp-push-receiver-dek-v1",
      hkdfLabelState: "FROZEN",
      aad: "zp-push-seal-v1|<node_id>|<wallet_id>|<purpose>",
    },
    storage: {
      databaseResident: true,
      table: "push_subscriptions",
      tableState: "FROZEN",
      grain: "PER_WALLET_MATERIAL_ENVELOPE_ROW",
    },
    accessPattern: "RECEIVER_BOUNDARY_SEAL_AND_READ",
    // EXCLUDED_REGENERABLE sealed-store class. Nothing in the row is externally issued and unrecoverable: endpoint_id is
    // node-generated, the endpoint URL is rebuilt from PUBLIC_BASE_URL, the public ECDH half
    // comes from the freshly minted keypair, and the gateway is told the new material at
    // subscribe time via a wallet-signed id-proof. A restore without the table leaves the row
    // absent, `ensureRow` mints fresh material and `subscribeRow` re-registers it; until then
    // requireActiveSubscription refuses external operations, so the loss is
    // bounded and fails closed.
    backupCoverage: "EXCLUDED_REGENERABLE",
    rotationTreatment:
      "value-preserving master-key rewrap through the old/new key ring: open with the canonical node+wallet+purpose AAD and reseal under the new root; key_version remains DB tracking only; both material rows are censused and committed transactionally",
    rewrapStatus: "IMPLEMENTED",
    productionSealSite: "packages/node-core/src/push/seal.ts",
  },
  {
    id: "TOTP_SECRET",
    name: "totp_secret",
    purpose:
      "RFC 6238 TOTP shared secret gating fresh authentication of guarded money mutations; the " +
      "code is never stored or logged, only the sealed secret at rest",
    encryption: {
      cipher: "AES-256-GCM",
      // domain-separation registry.
      hkdfLabel: "zupayments/totp-secret/v1",
      hkdfLabelState: "FROZEN",
      aad: "admin-row id as GCM AAD; binds the sealed secret to its admin_users row",
    },
    storage: {
      databaseResident: true,
      // Operator surface residency is admin_operators (reporting-prefix journal; not money pack).
      table: "admin_operators",
      tableState: "FROZEN",
      grain: "PER_OPERATOR_ENVELOPE_ROW",
    },
    accessPattern: "AUTH_FACTOR_SEAL_AND_VERIFY",
    // Auth factor: restore without envelopes forces re-enrol; do not ship secrets in backup.
    backupCoverage: "EXCLUDED_AUTH_FACTOR",
    rotationTreatment:
      "value-preserving master-key rewrap through the old/new key ring: open with the " +
      "admin-row-id AAD and reseal under the new root (totp/rewrap.ts)",
    rewrapStatus: "IMPLEMENTED",
    productionSealSite: "packages/node-core/src/totp/seal.ts",
  },
  {
    id: "SESSION_SECRETS",
    name: "session_secrets",
    purpose:
      "session / authentication-ephemeral secret material; encrypted at rest and never held in " +
      "plaintext in the node database (the trust-domain split excludes it)",
    encryption: {
      cipher: "AES-256-GCM",
      hkdfLabel: null,
      hkdfLabelState: "DEFERRED",
      aad: "DEFERRED — no committed session-secret sub-freeze (an excluded auth factor only)",
    },
    storage: {
      databaseResident: true,
      table: null,
      tableState: "DEFERRED",
      grain: "PER_SESSION_ENVELOPE_ROW",
    },
    accessPattern: "AUTH_EPHEMERAL_SEAL_AND_VERIFY",
    backupCoverage: "EXCLUDED_AUTH_FACTOR",
    rotationTreatment:
      "rewrapped or re-issued on re-authentication once seal-write runtime exists",
    rewrapStatus: "DEFERRED_NO_SEAL_RUNTIME",
    productionSealSite: null,
  },
] as const;

const SEALED_STORE_BY_ID: ReadonlyMap<SealedStoreId, SealedStoreDescriptor> = new Map(
  SEALED_STORES.map((store) => [store.id, store]),
);

export function sealedStore(id: SealedStoreId): SealedStoreDescriptor | undefined {
  return SEALED_STORE_BY_ID.get(id);
}

export const SEALED_STORE_IDS: readonly SealedStoreId[] = SEALED_STORES.map((store) => store.id);

export const SEALED_STORE_REGISTRY_SOURCE =
  "signing-custody: key inventory, vault AAD/DEK, rotation, and backup coverage" as const;

// ─── Seal-site register (structural census surface) ──────────────────────────

export type SealSiteKind = "PRODUCTION" | "DRILL";

export interface RegisteredSealSite {
  /** Path from repo root of a module that produces/opens an AES-256-GCM custody envelope. */
  readonly path: string;
  readonly store: SealedStoreId;
  readonly kind: SealSiteKind;
  readonly note: string;
}

/**
 * Every packages/** module that calls createCipheriv/createDecipheriv for custody envelopes.
 * The census greps the tree and asserts equality with this set (both directions).
 *
 * Scope: packages/** only. apps/node and apps/platform own independent censuses over
 * different store sets (the v1 product path; the platform holds no private keys).
 */
export const REGISTERED_SEAL_SITES: readonly RegisteredSealSite[] = [
  {
    path: "packages/node-core/src/vault/envelope.ts",
    store: "WALLET_VAULT",
    kind: "PRODUCTION",
    note:
      "production wallet-vault seal/open (sealWalletSecret / openWalletSecret). " +
      "DEK via HKDF zp-wallet-dek-v1; 6-field AAD reconstructed at open.",
  },
  {
    path: "packages/node-core/src/signing-keys/sealed-store.ts",
    store: "NODE_SIGNING_KEYS",
    kind: "PRODUCTION",
    note:
      "production NODE_SIGNING_KEYS seal/open (sealNodeSigningSeed / openNodeSigningSeed). " +
      "DEK via HKDF zp-node-signing-dek-v1; 5-field AAD reconstructed at open from registry.",
  },
  {
    path: "packages/node-core/src/push/seal.ts",
    store: "PUSH_RECEIVER_SECRETS",
    kind: "PRODUCTION",
    // Single entry for this path: registered it under WALLET_VAULT while
    // it keyed on the raw vault root. schema discipline gives it its own HKDF label, so the site belongs
    // to PUSH_RECEIVER_SECRETS alone — two entries for one path would both double-count the
    // seal-site census and attribute one site to two stores in the very register wallet-vault AAD and HKDF-info(i)
    // exists to keep separate.
    note:
      "production PUSH_RECEIVER_SECRETS seal/open (createPushSecretSealer), the " +
      "canonical per-wallet Web Push ECDH/auth site used by the live push path. DEK via HKDF " +
      "zp-push-receiver-dek-v1, under the shared-root HKDF label rule; 3-field AAD (node|wallet|purpose). " +
      "Distinct from sealWalletSecret because push secrets are 32-byte P-256 ECDH scalars and " +
      "16-byte RFC 8291 auth secrets, not 64-byte Ed25519.",
  },
  {
    path: "packages/generic-node-contracts/src/recovery-drill/envelope.ts",
    store: "WALLET_VAULT",
    kind: "DRILL",
    note:
      "destroy-restore drill: seals/opens the SAME WALLET_VAULT bytes (deriveWalletDek, " +
      "6-field AAD); new_ciphertext_class_introduced === false — rewraps in lockstep with production.",
  },
  {
    path: "packages/node-core/src/totp/seal.ts",
    store: "TOTP_SECRET",
    kind: "PRODUCTION",
    note:
      "production TOTP_SECRET seal/open (sealTotpSecret / openTotpSecret). " +
      "DEK via HKDF zupayments/totp-secret/v1; AAD is the admin_operators row id reconstructed at open.",
  },
] as const;

export const REGISTERED_SEAL_SITE_PATHS: readonly string[] = REGISTERED_SEAL_SITES.map(
  (s) => s.path,
);

/**
 * Pure comparator for the seal-site SOURCE census.
 * - unregistered: in source but NOT registered — rotation would orphan (must fail).
 * - stale: registered but no longer in source — dead registration to prune.
 * Passes iff both empty.
 */
export function sealSiteCensus(
  found: readonly string[],
  registered: readonly string[] = REGISTERED_SEAL_SITE_PATHS,
): { readonly unregistered: readonly string[]; readonly stale: readonly string[] } {
  const registeredSet = new Set(registered);
  const foundSet = new Set(found);
  return {
    unregistered: [...found].filter((p) => !registeredSet.has(p)).sort(),
    stale: [...registered].filter((p) => !foundSet.has(p)).sort(),
  };
}
