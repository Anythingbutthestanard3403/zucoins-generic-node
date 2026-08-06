export const IMPLEMENTER_CREDENTIAL_SCHEMA_FILE =
  "implementer-credentials.sql" as const;

export const IMPLEMENTER_CREDENTIAL_TABLE = "implementer_credentials" as const;

export const IMPLEMENTER_CREDENTIAL_COLUMNS = [
  "id",
  "implementer_id",
  "public_prefix",
  "credential_hash",
  "scopes",
  "status",
  "key_version",
  "issued_at",
  "expires_at",
  "revoked_at",
  "rotated_from_id",
  "rotated_to_id",
  "rotated_at",
  "rotation_grace_until",
] as const;

// Exactly the states a mutation writes; there is no stored EXPIRED (see the .sql header).
export const IMPLEMENTER_CREDENTIAL_STATUSES = [
  "ACTIVE",
  "GRACE",
  "REVOKED",
] as const;

export const IMPLEMENTER_CREDENTIAL_AUDIT_ACTIONS = [
  "IMPLEMENTER_CREDENTIAL_ISSUED",
  "IMPLEMENTER_CREDENTIAL_ROTATED",
  "IMPLEMENTER_CREDENTIAL_REVOKED",
] as const;
