// proof-body intake envelope barrel.
//
// The frozen byte-contract surface for caller-supplied candidate bodies: types, the frozen
// Zod schema, and the capture-before-parse intake function. Supplied bodies are untrusted
// evidence (landing-path oracle), never authoritative chain state.
export {
  PROOF_BODY_SOURCE_KIND,
  PROOF_BODY_WALLET_ROLES,
  type AuthenticatedRequestIdentity,
  type ExpectedIdentityBinding,
  type ProofBodyAccepted,
  type ProofBodyIntakeRequest,
  type ProofBodyIntakeResult,
  type ProofBodyRejected,
  type ProofBodyRejectionCode,
  type ProofBodyRejectionReason,
  type ProofBodySourceKind,
  type ProofBodyTransportMetadata,
  type ProofBodyWalletRole,
  type ValidatedProofBody,
  PROOF_BODY_REJECTION_CODES,
  PROOF_BODY_REJECTION_REASONS,
} from "./types.js";

export {
  PROOF_BODY_FIELDS,
  proofBodySchema,
  type ProofBodyField,
} from "./schema.js";

export { intakeProofBody, MAX_PROOF_BODY_BYTES } from "./intake.js";

export {
  MAX_BODIES_PER_OPERATION,
  MAX_BODIES_PER_ROLE,
  MAX_BODIES_PER_TENANT,
  MAX_PATH_DEPTH,
  MAX_SIGHTINGS_PER_BODY,
  MAX_SIGHTINGS_PER_TENANT,
  MAX_TOTAL_BYTES_PER_TENANT,
  PERSIST_REJECTION_REASONS,
  persistProofBody,
  type PersistProofBodyRequest,
  type PersistProofBodyResult,
  type PersistRejectionReason,
  type ProofBodySighting,
  type ProofBodyStore,
  type TransactionalProofBodyStore,
  type StoredProofBody,
} from "./persist.js";

export {
  CANDIDATE_COLUMNS,
  SqlProofBodyStore,
  STATEMENTS as PROOF_BODY_STORE_STATEMENTS,
  type SqlExecutor,
  type SqlQueryResult,
  type SqlTransactionRunner,
} from "./sql-store.js";
