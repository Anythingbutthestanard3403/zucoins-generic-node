// Device enrollment types — operator_device_keys registry and the
// zp-device-enrol-v1 ceremony (A.4.3 / A.1.1). Challenge shape mirrors
// approval_challenges (status enum, unique nonce, issued/expires, single-consume).

export interface EnrolledDeviceKey {
  readonly id: string;
  readonly nodeId: string;
  readonly publicKey: string;
  readonly label: string;
  readonly enrolledAt: string;
  readonly revokedAt: string | null;
}

/** Wire payload fields of zp-device-enrol-v1 (A.4.3 insertion sequence). */
export interface DeviceEnrolmentTuple {
  readonly purpose: "zp-device-enrol-v1";
  readonly canonical_version: 1;
  readonly node_id: string;
  readonly new_device_key_id: string;
  readonly new_device_public_key: string;
  readonly label: string;
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
}

export type EnrollmentChallengeStatus = "ISSUED" | "CONSUMED" | "SUPERSEDED" | "EXPIRED";

/** Node-origin enrollment challenge (mirrors approval_challenges shape). */
export interface EnrollmentChallenge {
  readonly id: string;
  readonly nodeId: string;
  readonly status: EnrollmentChallengeStatus;
  readonly purpose: "zp-device-enrol-v1";
  readonly canonicalVersion: 1;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly supersededBy: string | null;
}

export type DeviceEnrolmentResult =
  | { readonly ok: true; readonly deviceKey: EnrolledDeviceKey }
  | { readonly ok: false; readonly code: DeviceEnrolmentRejectionCode; readonly detail: string };

export type DeviceEnrolmentRejectionCode =
  | "INVALID_PURPOSE"
  | "PURPOSE_PREFIX_MISMATCH"
  | "NON_CANONICAL_PREIMAGE"
  | "INVALID_JSON"
  | "INVALID_UTF8"
  | "INVALID_FIELD"
  | "INVALID_CANONICAL_VERSION"
  | "INVALID_PUBLIC_KEY"
  | "DUPLICATE_KEY"
  | "LABEL_EMPTY"
  | "LABEL_TOO_LONG_SCALARS"
  | "LABEL_TOO_LONG_BYTES"
  | "LABEL_MALFORMED_UTF8"
  | "LABEL_CONTROL_CHARS"
  | "LABEL_SURROGATES"
  | "LABEL_NONCHARACTERS"
  | "LABEL_LINE_SEPARATORS"
  | "LABEL_BOM"
  | "LABEL_BIDI_CONTROLS"
  | "LABEL_LEADING_TRAILING_SPACE"
  | "LABEL_DISALLOWED"
  | "WINDOW_TOO_LONG"
  | "WINDOW_NON_POSITIVE"
  | "SIGNATURE_INVALID"
  | "ENROLMENT_EXPIRED"
  | "AUTHORIZER_UNKNOWN"
  | "AUTHORIZER_REVOKED"
  | "AUTHORIZER_KEY_ID_MISMATCH"
  | "POP_INVALID"
  | "CHALLENGE_UNKNOWN"
  | "CHALLENGE_NOT_ISSUED"
  | "CHALLENGE_EXPIRED"
  | "CHALLENGE_MISMATCH"
  /** @deprecated implemented break-glass; retained for wire stability. */
  | "BREAK_GLASS_UNSUPPORTED"
  | "BREAK_GLASS_AUTHORITY_UNKNOWN"
  | "BREAK_GLASS_AUTHORITY_REVOKED"
  | "BREAK_GLASS_KEY_ID_MISMATCH"
  | "DIGEST_MISMATCH";

/** Ratified offline break-glass public key (A.4.3 alternative authorizer). */
export interface BreakGlassAuthority {
  readonly id: string;
  readonly nodeId: string;
  readonly publicKey: string;
  readonly label: string;
  readonly ratifiedAt: string;
  readonly revokedAt: string | null;
}

export type BreakGlassRatifyResult =
  | { readonly ok: true; readonly authority: BreakGlassAuthority }
  | {
      readonly ok: false;
      readonly code:
        | "HOST_ATTESTATION_REQUIRED"
        | "INVALID_PUBLIC_KEY"
        | "INVALID_LABEL"
        | "DUPLICATE_AUTHORITY";
      readonly detail: string;
    };

export type BreakGlassTotpResetResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code:
        | "AUTHORITY_UNKNOWN"
        | "AUTHORITY_REVOKED"
        | "AUTHORITY_ID_MISMATCH"
        | "CEREMONY_EXPIRED"
        | "SIGNATURE_INVALID";
      readonly detail: string;
    };

export type BreakGlassAuditOutcome = "RATIFIED" | "TOTP_RESET" | "REJECTED";

export interface BreakGlassAuditEntry {
  readonly outcome: BreakGlassAuditOutcome;
  readonly action: "RATIFY" | "TOTP_RESET";
  readonly code: string;
  readonly nodeId: string | null;
  readonly authorityId: string | null;
  readonly publicKey: string | null;
  readonly detail: string;
  readonly at: string;
}

export type DeviceRevocationResult =
  | {
      readonly ok: true;
      readonly deviceKey: EnrolledDeviceKey;
      readonly invalidatedEnrollmentChallenges: number;
      readonly alreadyRevoked: boolean;
    }
  | {
      readonly ok: false;
      readonly code:
        | "TARGET_UNKNOWN"
        | "AUTHORIZER_UNKNOWN"
        | "AUTHORIZER_REVOKED"
        | "AUTHORIZER_KEY_ID_MISMATCH"
        | "STORE_FAILURE";
      readonly detail: string;
    };

export type DeviceRevocationAuditOutcome = "REVOKED" | "REJECTED";

export interface DeviceRevocationAuditEntry {
  readonly outcome: DeviceRevocationAuditOutcome;
  readonly code: string;
  readonly nodeId: string;
  readonly targetDeviceKeyId: string;
  readonly authorizingKeyId: string | null;
  readonly invalidatedEnrollmentChallenges: number;
  readonly detail: string;
  readonly at: string;
}

/**
 * Custody fields that device lifecycle MUST NOT mutate.
 * Exported so reviewers and threat tests can assert structural isolation.
 */
export const DEVICE_LIFECYCLE_FORBIDDEN_CUSTODY_FIELDS = [
  "key_origin",
  "recovery_verified_at",
  "destinations.state",
  "destination_state",
  "BLESSED",
] as const;

export type DeviceSignatureVerificationResult =
  | { readonly ok: true; readonly deviceKey: EnrolledDeviceKey }
  | { readonly ok: false; readonly code: DeviceSignatureRejectionCode; readonly detail: string };

export type DeviceSignatureRejectionCode =
  | "UNKNOWN_DEVICE"
  | "DEVICE_REVOKED"
  | "SIGNATURE_INVALID"
  | "INVALID_PUBLIC_KEY";

export type EnrollmentAuditOutcome = "ENROLLED" | "REJECTED";

/** Public audit record — never carries private key material. */
export interface EnrollmentAuditEntry {
  readonly outcome: EnrollmentAuditOutcome;
  readonly code: DeviceEnrolmentRejectionCode | "OK";
  readonly nodeId: string | null;
  readonly challengeId: string | null;
  readonly challengeNonce: string | null;
  readonly authorizingKeyId: string | null;
  readonly authorizingPublicKey: string | null;
  readonly newDeviceKeyId: string | null;
  readonly newDevicePublicKey: string | null;
  readonly detail: string;
  readonly at: string;
}
