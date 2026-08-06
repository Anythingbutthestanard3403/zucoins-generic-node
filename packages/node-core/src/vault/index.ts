// Encrypted wallet-key storage (per-wallet AES-256-GCM envelope; frozen). Custody
// boundary: this module seals/opens wallet secret keys on the self-hosted node and never logs
// or persists key material. `sha256Hex` is intentionally not re-exported here — the package
// barrel pins that name to the gateway export to avoid a star-export ambiguity.

export {
  AAD_GOLDEN,
  HKDF_INFO_GOLDEN,
  WALLET_DEK_HKDF_LABEL,
  WALLET_SECRET_AAD_DOMAIN,
  buildWalletDekInfo,
  buildWalletSecretAad,
  toBase64UrlPadded,
  type WalletDekInfoFields,
  type WalletSecretAadFields,
} from "./serialization.js";

export {
  AUTH_TAG_LENGTH_BYTES,
  DEK_LENGTH_BYTES,
  ED25519_SECRET_KEY_BYTES,
  ED25519_SEED_BYTES,
  NONCE_LENGTH_BYTES,
  ROOT_KDF_HASH,
  ROOT_KDF_ITERATIONS,
  SUPPORTED_ENVELOPE_VERSION,
  VaultOpenError,
  VaultSealError,
  deriveEd25519PublicKeyBase64Url,
  deriveRootKey,
  gcmCrypto,
  keyMaterialHygiene,
  openWalletSecret,
  sealWalletSecret,
  type KeyMaterialWipeRole,
  type SecureBuffer,
  type SealedEnvelope,
  type VaultOpenFailureCode,
  type WalletIdentity,
} from "./envelope.js";

export {
  EncryptedWalletKeyStore,
  InMemoryVaultAccessAuditLog,
  InMemoryVaultStore,
  VaultRecordNotFoundError,
  type EncryptedWalletKeyStoreDeps,
  type VaultAccessAuditEntry,
  type VaultAccessAuditLog,
  type VaultAccessOutcome,
  type VaultRecord,
  type VaultStore,
} from "./store.js";

// The `vault` table itself lives in src/schema/vault.sql (the frozen schema contract set),
// not in a TypeScript string — so it is covered by the column-type lint, the greenfield
// migration-integrity characterization, and a real-PostgreSQL execution test.
// `SqlExecutor`/`SqlQueryResult` are deliberately not re-exported: proof-body already pins
// those names in the package barrel (same reason as `sha256Hex` above).
export { STATEMENTS as VAULT_STATEMENTS, VAULT_COLUMNS, VaultSqlStore } from "./sql-store.js";

// per-store master-key rewrap primitives (wallet vault today;
// sibling stores deferred until seal-write runtime exists — sealed-store rewrap census).
export {
  rewrapWalletVaultStore,
  type SealedStoreRewrapResult,
  type WalletVaultRewrapInput,
  type WalletVaultRewrapRow,
} from "./rewrap.js";

// atomic multi-store master-key rotation orchestrator.
export {
  MASTER_KEY_ROTATION_PHASES,
  InMemoryMasterKeyRotationJournal,
  type MasterKeyRotationJournal,
  type MasterKeyRotationJournalRecord,
  type MasterKeyRotationPhase,
} from "./rotation-journal.js";
export {
  KeyRingOpenError,
  buildKeyRing,
  openWithKeyRing,
  orderEntriesForOpen,
  writerRoot,
  type KeyRingEntry,
  type VaultKeyRing,
} from "./key-ring.js";
export {
  ACQUIRE_ROTATION_SESSION_LOCK_SQL,
  ACQUIRE_ROTATION_XACT_LOCK_SQL,
  RELEASE_ROTATION_SESSION_LOCK_SQL,
  MASTER_KEY_ROTATION_ADVISORY_LOCK_ID,
  InMemoryRotationUnitOfWork,
  MasterKeyRotationError,
  ProcessLocalMasterKeyRotationInterlock,
  createSqlRotationUnitOfWork,
  rotateMasterKey,
  type MasterKeyRotationInput,
  type MasterKeyRotationInterlock,
  type MasterKeyRotationResult,
  type NodeSigningKeyRotationCensus,
  type NodeSigningKeyRotationRow,
  type PushSecretRotationCensus,
  type PushSecretRotationRow,
  type RegisteredSealedStore,
  type RegisteredStoreRewrapStatus,
  type RotationLogger,
  type RotationSqlClient,
  type RotationSqlTransactionFactory,
  type RotationUnitOfWork,
  type StoreRotationReport,
  type WalletVaultRotationCensus,
} from "./master-key-rotation.js";
// sortWalletIdsAscending stays module-private (leases barrel already exports the canonical name).
