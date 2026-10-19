export {
  assertScope,
  BEARER_KEY_PREFIX,
  CredentialError,
  CredentialService,
  CredentialAuthError,
  generateRawKey,
  hashCredential,
  IMPLEMENTER_SCOPES,
  PUBLIC_PREFIX_LENGTH,
  validateScopes,
  type CreateCredentialResult,
  type CredentialAuditAction,
  type CredentialAuditEntry,
  type CredentialStatus,
  type CredentialStore,
  type ImplementerScope,
  type StoredCredential,
  type ValidatedCredential,
} from "./types.js";

export {
  CONNECTOR_SCOPES,
  DEFAULT_CONNECTOR_SCOPES,
  credentialScopesForConnectorScopes,
  isConnectorScope,
  type ConnectorScope,
} from "./connector-scopes.js";

export {
  CREDENTIAL_COLUMNS,
  CREDENTIAL_STATEMENTS,
  SqlCredentialStore,
} from "./sql-store.js";
