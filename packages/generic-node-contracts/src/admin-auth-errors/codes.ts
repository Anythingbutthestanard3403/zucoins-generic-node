// OPERATOR_SESSION admin-auth error taxonomy (ZTR-1196).
// Parallel to API_ERROR_CODES — do not widen the public /v1 table.
// Codes are the wire strings admin routes already emit (including device
// rejection codes lowercased at the router boundary).

export interface AdminErrorCodeEntry {
  readonly code: string;
  readonly http: number;
}

/**
 * Frozen admin error codes. HTTP values are the *typical* status paired with
 * each code on the current surface; a given handler may still choose a
 * different status for the same code (e.g. challenge_expired as 409).
 * The census freezes membership, not the (code, status) pair matrix.
 */
export const ADMIN_ERROR_CODES = [
  // Shared with /v1 where meaning matches (reuse, do not fork).
  { code: "not_found", http: 404 },
  { code: "unknown_field", http: 400 },
  { code: "invalid_scalar", http: 400 },
  { code: "invalid_idempotency_key", http: 400 },
  { code: "idempotency_conflict", http: 409 },
  { code: "operation_not_armable", http: 409 },
  { code: "rate_limited", http: 429 },
  { code: "service_unavailable", http: 503 },

  // Session / auth factors (OPERATOR_SESSION surface).
  { code: "invalid_credentials", http: 401 },
  { code: "totp_required", http: 401 },
  { code: "totp_invalid", http: 401 },
  { code: "password_change_required", http: 403 },
  { code: "origin_forbidden", http: 403 },
  { code: "csrf_required", http: 403 },
  { code: "csrf_invalid", http: 401 },
  { code: "csrf_origin", http: 403 },
  { code: "csrf_token", http: 401 },

  // Generic admin request failures.
  { code: "validation_error", http: 400 },
  { code: "invalid_request", http: 400 },
  { code: "conflict", http: 409 },
  { code: "internal_error", http: 500 },
  { code: "mutation_failed", http: 500 },
  { code: "idempotency_unavailable", http: 503 },

  // Approvals / money mutations.
  { code: "approval_rejected", http: 401 },
  { code: "same_operator_both_sides", http: 401 },
  { code: "operation_version_conflict", http: 409 },
  // Alias retained only if any internal path still emits the old name — prefer version_conflict on wire (ZTR-1170).
  { code: "operation_conflict", http: 409 },
  { code: "authorizer_unknown", http: 404 },
  { code: "signature_invalid", http: 400 },
  { code: "challenge_unknown", http: 404 },

  // Reporting credentials.
  { code: "reporting_key_already_active", http: 409 },
  { code: "reporting_key_not_current", http: 409 },

  // Setup / vault / recovery ceremony.
  { code: "ceremony_in_flight", http: 409 },
  { code: "ceremony_not_accepted", http: 409 },
  { code: "ceremony_blocked", http: 409 },
  { code: "vault_master_unavailable", http: 422 },
  { code: "already_generated", http: 409 },
  { code: "already_sealed", http: 409 },
  { code: "not_pending", http: 409 },
  { code: "backup_kek_collision", http: 409 },
  { code: "configured_env", http: 409 },
  { code: "weak_recovery_secret", http: 400 },
  { code: "weak_secret", http: 400 },
  { code: "legacy_pack_v1", http: 400 },
  { code: "prove_failed", http: 400 },
  { code: "invalid_passcode", http: 400 },
  { code: "invalid_format", http: 400 },
  { code: "decrypt_failed", http: 400 },
  { code: "invalid_payload", http: 400 },
  { code: "master_key_too_short", http: 400 },

  // Lab receive (non-production) blocked codes.
  { code: "lab_amount_exceeds_cap", http: 400 },
  { code: "lab_amount_invalid", http: 400 },
  { code: "lab_gates_blocked", http: 422 },
  { code: "lab_implementer_missing", http: 503 },
  { code: "lab_not_ready", http: 503 },
  { code: "lab_arm_failed", http: 422 },
  { code: "lab_reporting_seed_invalid", http: 400 },
  { code: "lab_create_failed", http: 500 },

  // Device enrolment / blessing / revocation / break-glass (wire = lowercased internal codes).
  { code: "invalid_purpose", http: 400 },
  { code: "purpose_prefix_mismatch", http: 400 },
  { code: "non_canonical_preimage", http: 400 },
  { code: "invalid_json", http: 400 },
  { code: "invalid_utf8", http: 400 },
  { code: "invalid_field", http: 400 },
  { code: "invalid_canonical_version", http: 400 },
  { code: "invalid_public_key", http: 400 },
  { code: "duplicate_key", http: 409 },
  { code: "label_empty", http: 400 },
  { code: "label_too_long_scalars", http: 400 },
  { code: "label_too_long_bytes", http: 400 },
  { code: "label_malformed_utf8", http: 400 },
  { code: "label_control_chars", http: 400 },
  { code: "label_surrogates", http: 400 },
  { code: "label_noncharacters", http: 400 },
  { code: "label_line_separators", http: 400 },
  { code: "label_bom", http: 400 },
  { code: "label_bidi_controls", http: 400 },
  { code: "label_leading_trailing_space", http: 400 },
  { code: "label_disallowed", http: 400 },
  { code: "window_too_long", http: 400 },
  { code: "window_non_positive", http: 400 },
  { code: "enrolment_expired", http: 409 },
  { code: "authorizer_revoked", http: 401 },
  { code: "authorizer_key_id_mismatch", http: 400 },
  { code: "pop_invalid", http: 400 },
  { code: "challenge_not_issued", http: 409 },
  { code: "challenge_expired", http: 409 },
  { code: "challenge_mismatch", http: 400 },
  { code: "challenge_not_bound", http: 409 },
  { code: "break_glass_unsupported", http: 400 },
  { code: "break_glass_authority_unknown", http: 404 },
  { code: "break_glass_authority_revoked", http: 401 },
  { code: "break_glass_key_id_mismatch", http: 400 },
  { code: "digest_mismatch", http: 400 },
  { code: "host_attestation_required", http: 400 },
  { code: "invalid_label", http: 400 },
  { code: "duplicate_authority", http: 409 },
  { code: "authority_unknown", http: 404 },
  { code: "authority_revoked", http: 401 },
  { code: "authority_id_mismatch", http: 400 },
  { code: "ceremony_expired", http: 409 },
  { code: "target_unknown", http: 404 },
  { code: "store_failure", http: 503 },
  { code: "unknown_device", http: 404 },
  { code: "device_revoked", http: 401 },
  { code: "not_authorized", http: 401 },
] as const satisfies readonly AdminErrorCodeEntry[];

export type AdminErrorCode = (typeof ADMIN_ERROR_CODES)[number]["code"];

export const ADMIN_ERROR_CODE_SET: ReadonlySet<string> = new Set(
  ADMIN_ERROR_CODES.map((e) => e.code),
);

export function isAdminErrorCode(code: string): code is AdminErrorCode {
  return ADMIN_ERROR_CODE_SET.has(code);
}
