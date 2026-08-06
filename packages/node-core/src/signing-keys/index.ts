// public barrel for the signing-key registry + sealed store.
// Schema: signing-key-registry.sql + node-signing-key-sealed-store.sql.
// PUBLIC registry reads never select vault_secret_ref or sealed ciphertext.
// Seal/open + ensure are the only sanctioned writers of private seed material.

export {
  NODE_SIGNING_KEY_COLUMNS,
  NODE_SIGNING_KEY_PURPOSES,
  REPORTING_KEY_COLUMNS,
  STATEMENTS,
  SigningKeyRegistry,
  UnknownSigningKeyPurposeError,
  assertExactPurpose,
  type NodeSigningKeyPurpose,
  type NodeSigningKeyRow,
  type ReportingKeyRow,
  type SqlExecutor,
  type SqlQueryResult,
} from "./registry-store.js";

export {
  NODE_SIGNING_DEK_HKDF_LABEL,
  NODE_SIGNING_SECRET_AAD_DOMAIN,
  buildNodeSigningDekInfo,
  buildNodeSigningSecretAad,
  generateEd25519Seed,
  openNodeSigningSeed,
  publicKeyFromEd25519Seed,
  sealNodeSigningSeed,
  type NodeSigningKeyIdentity,
  type NodeSigningKeySealedEnvelope,
} from "./sealed-store.js";

export {
  NODE_SIGNING_KEY_ENSURE_LOCK_CLASS,
  ensureActiveNodeSigningKey,
  type EnsureActiveNodeSigningKeyInput,
  type NodeIdentityArtifactSigner,
} from "./ensure.js";

export {
  rewrapNodeSigningKeyStore,
  type NodeSigningKeyRewrapInput,
  type NodeSigningKeyRewrapRow,
  type SealedStoreRewrapResult as NodeSigningKeySealedStoreRewrapResult,
} from "./rewrap.js";
