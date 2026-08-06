/**
 * durable reporting-persistence facts and pure decision helpers.
 * Contract-only: no database, network, key material, or live action.
 */

export const NONCE_UNIQUENESS_FIELDS = ["node_id", "implementer_id", "nonce"] as const;
export const NONCE_SCOPE_EXCLUDED_FIELDS = [
  "purpose",
  "route_id",
  "request_class",
  "reporting_key_id",
  "new_reporting_key_id",
  "bootstrap_evidence_id",
] as const;
export const REPORTING_NONCE_PURPOSES = [
  "zp-reporting-register-v1",
  "zp-report-request-v1",
] as const;
export type ReportingNoncePurpose = (typeof REPORTING_NONCE_PURPOSES)[number];

export const REPORTING_NONCE_FIELDS = [
  "id",
  "node_id",
  "implementer_id",
  "nonce",
  "purpose",
  "route_id",
  "request_class",
  "reporting_key_id",
  "new_reporting_key_id",
  "bootstrap_evidence_id",
  "lifecycle_epoch",
  "nonce_burn_sequence",
  "request_preimage_text",
  "request_preimage_sha256",
  "request_signature",
  "method",
  "raw_target",
  "body_sha256",
  "logical_fingerprint",
  "issued_at",
  "expires_at",
  "received_at",
  "consumed_at",
  "retention_class",
] as const;

export const REPORTING_KEY_ID_NULLABILITY = {
  nullableOnlyFor: "FIRST_KEY_BOOTSTRAP",
  requiredFor: ["EXISTING_KEY_ANCHORED_ROTATION", "SIGNED_REQUEST"],
} as const;

export const REPORTING_SIGNED_WINDOW_MS = {
  "zp-report-request-v1": 60_000,
  "zp-reporting-register-v1": 300_000,
} as const satisfies Readonly<Record<ReportingNoncePurpose, number>>;

export const PRE_BURN_CHECKS = [
  "bounded_shape",
  "signed_time_window",
  "bounded_size",
  "bounded_rate",
  "tenant_and_key_binding",
  "lifecycle_eligibility",
  "signature",
] as const;

export const BURN_TRANSACTION_STEPS = [
  "begin_short_transaction",
  "lock_shared_lifecycle_head",
  "recheck_lifecycle_epoch_key_and_auth_hold",
  "insert_shared_nonce_evidence",
  "commit_burn",
] as const;

export const POST_BURN_STAGES = [
  "completed_idempotency_lookup_and_fingerprint_check",
  "protected_lookup_if_no_completed_result",
  "guarded_handler",
] as const;

export const MUTATION_IDEMPOTENCY_UNIQUENESS_FIELDS = [
  "node_id",
  "implementer_id",
  "route_id",
  "idempotency_key",
] as const;

export const LOGICAL_FINGERPRINT_FIELDS = ["method", "raw_target", "body_sha256"] as const;
export const LOGICAL_FINGERPRINT_EXCLUDED_FIELDS = [
  "nonce",
  "reporting_key_id",
  "lifecycle_epoch",
  "issued_at",
  "expires_at",
  "received_at",
  "idempotency_key",
] as const;

export const FINGERPRINT_GUARDED_ROUTE_IDS = [
  "operation_armed",
  "verification_complete",
] as const;

// The guarded-route duplicate index is over the actual signed request triple
// (method, raw_target, body_sha256), NOT the derived `logical_fingerprint`, so a caller can never
// present a hash that bypasses it. This mirrors the SQL partial UNIQUE INDEX
// `reporting_mutation_guarded_fingerprint_uq` in 04-data-model.md exactly.
export const GUARDED_FINGERPRINT_UNIQUENESS_FIELDS = [
  "node_id",
  "implementer_id",
  "route_id",
  "method",
  "raw_target",
  "body_sha256",
] as const;

export const GUARDED_FINGERPRINT_PARTIAL_UNIQUENESS = {
  fields: GUARDED_FINGERPRINT_UNIQUENESS_FIELDS,
  whereRouteIdIn: FINGERPRINT_GUARDED_ROUTE_IDS,
} as const;

export const REPORTING_LIFECYCLE_HEAD_FIELDS = [
  "node_id",
  "implementer_id",
  "epoch",
  "current_key_id",
  "prior_key_id",
  "overlap_expires_at",
  "auth_hold",
  "lifecycle_event_id",
  "updated_at",
] as const;

export const REPORTING_LIFECYCLE_EVENT_FIELDS = [
  "id",
  "node_id",
  "implementer_id",
  "epoch",
  "event_type",
  "current_key_id",
  "prior_key_id",
  "overlap_expires_at",
  "auth_hold",
  "successor_registered_at",
  "nonce_evidence_id",
  "nonce_purpose",
  "enrolment_evidence_id",
  "public_evidence_text",
  "public_evidence_sha256",
  "previous_event_hash",
  "event_hash",
  "committed_at",
] as const;

export const REPORTING_LIFECYCLE_EVENT_UNIQUENESS_FIELDS = [
  "node_id",
  "implementer_id",
  "epoch",
] as const;

export const REPORTING_KEY_STATES = ["PENDING", "ACTIVE", "RETIRED", "REVOKED"] as const;
export type ReportingKeyState = (typeof REPORTING_KEY_STATES)[number];

export const REPORTING_LIFECYCLE_EVENT_TYPES = [
  "FIRST_KEY_ACTIVATED",
  "KEY_ROTATED",
  "PRIOR_KEY_RETIRED",
  "KEY_REVOKED",
  "AUTH_HOLD_SET",
  "AUTH_HOLD_RELEASED",
] as const;
export type ReportingLifecycleEventType = (typeof REPORTING_LIFECYCLE_EVENT_TYPES)[number];

export const LEGAL_LIFECYCLE_KEY_TRANSITIONS = [
  { eventType: "FIRST_KEY_ACTIVATED", from: "PENDING", to: "ACTIVE" },
  { eventType: "KEY_ROTATED", from: "PENDING", to: "ACTIVE" },
  { eventType: "PRIOR_KEY_RETIRED", from: "ACTIVE", to: "RETIRED" },
  { eventType: "KEY_REVOKED", from: "ACTIVE", to: "REVOKED" },
] as const;

export const REPORTING_KEY_IDENTITY_ALLOWED_FIELDS = [
  "id",
  "node_id",
  "implementer_id",
  "public_key",
  "registered_at",
] as const;

export const REPORTING_KEY_IDENTITY_FORBIDDEN_FIELDS = [
  "private_key",
  "private_key_bytes",
  "seed",
  "secret",
  "vault_ref",
  "vault_secret_ref",
] as const;

export const REPORTING_KEY_OVERLAP_MS = 24 * 60 * 60 * 1_000;

export const REGISTRATION_EVIDENCE_MODES = [
  "FIRST_KEY_BOOTSTRAP",
  "EXISTING_KEY_ANCHORED_ROTATION",
] as const;
export type RegistrationEvidenceMode = (typeof REGISTRATION_EVIDENCE_MODES)[number];

export const REGISTRATION_EVIDENCE_FIELDS = [
  "id",
  "node_id",
  "implementer_id",
  "new_reporting_key_id",
  "supersedes_key_id",
  "authorizing_key_id",
  "bootstrap_evidence_id",
  "nonce_evidence_id",
  "registration_purpose",
  "proof_of_possession_preimage_text",
  "proof_of_possession_preimage_sha256",
  "proof_of_possession_signature",
  "authorizing_preimage_text",
  "authorizing_preimage_sha256",
  "authorizing_signature",
  "issued_at",
  "expires_at",
  "created_at",
] as const;

export const IDEMPOTENCY_KEY_CONTRACT = {
  minLength: 16,
  maxLength: 255,
  minCodePoint: 0x21,
  maxCodePoint: 0x7e,
} as const;

export const MUTATION_IDEMPOTENCY_FIELDS = [
  "id",
  "node_id",
  "implementer_id",
  "route_id",
  "idempotency_key",
  "reporting_nonce_id",
  "child_record_id",
  "method",
  "raw_target",
  "body_sha256",
  "logical_fingerprint",
  "response_status",
  "response_bytes",
  "completed_at",
  "created_at",
] as const;

export const MUTATION_IDEMPOTENCY_PERSISTENCE = {
  durablePendingRowsAllowed: false,
  requiredCompletionFields: ["response_status", "response_bytes", "completed_at"],
  mutationAndCompletedResultAtomic: true,
  completedParentRequiresMatchingChild: true,
} as const;

export const MUTATION_EVIDENCE_BINDING_FIELDS = [
  "reporting_nonce_id",
  "mutation_idempotency_id",
  "child_record_id",
  "method",
  "raw_target",
  "body_sha256",
  "logical_fingerprint",
] as const;

export const MUTATION_ROUTE_RETENTION = "PERMANENT" as const;

export const MUTATION_EVIDENCE_IMMUTABILITY = {
  nonceEvidenceAppendOnly: true,
  nonceEvidenceImmutable: true,
  idempotencyEvidenceAppendOnly: true,
  idempotencyEvidenceImmutable: true,
  responseEvidenceImmutable: true,
} as const;

export const LIFECYCLE_EVENT_HASH_CHAIN = {
  eventsAppendOnly: true,
  eventBytesImmutable: true,
  predecessorHashRequiredAfterFirstEvent: true,
  predecessorHashMustEqualPriorEventHash: true,
} as const;

export const REPORTING_RETENTION = {
  readNonceBurn: "NO_PRUNE_UNTIL_SAFETY_SOURCE_AND_MARGIN_FROZEN",
  mutationNonceBurn: "PERMANENT",
  mutationIdempotency: "PERMANENT",
  lifecycleEvidence: "PERMANENT",
} as const;

export const RESTORE_POLICY = {
  regressionResult: "HARD_HOLD_REPORTING_AUTH",
  missingSafetySourceResult: "HARD_HOLD_REPORTING_AUTH",
  automaticHoldRelease: false,
  releaseRequires: [
    "external_lifecycle_epoch_verified_exact_equal",
    "external_nonce_burn_high_water_verified_exact_equal",
    "trusted_event_hash_equal",
    "next_event_previous_hash_continuous",
  ],
  equalLocalMarkersReleaseHold: false,
} as const;

export interface NonceClaim {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly nonce: string;
  readonly purpose: ReportingNoncePurpose;
  readonly routeId: string;
  readonly reportingKeyId: string | null;
  readonly newReportingKeyId: string | null;
  readonly registrationEvidenceMode: RegistrationEvidenceMode | null;
}

export type NonceClaimOutcome = "CLAIMED" | "REJECT_REPLAY";

export interface NonceClaimResult {
  readonly outcome: NonceClaimOutcome;
  readonly claims: readonly NonceClaim[];
}

export function nonceClaimHasValidKeySemantics(claim: NonceClaim): boolean {
  if (claim.purpose === "zp-report-request-v1") {
    return claim.reportingKeyId !== null &&
      claim.newReportingKeyId === null &&
      claim.registrationEvidenceMode === null;
  }
  if (claim.registrationEvidenceMode === "FIRST_KEY_BOOTSTRAP") {
    return claim.reportingKeyId === null && claim.newReportingKeyId !== null;
  }
  if (claim.registrationEvidenceMode === "EXISTING_KEY_ANCHORED_ROTATION") {
    return claim.reportingKeyId !== null &&
      claim.newReportingKeyId !== null &&
      claim.reportingKeyId !== claim.newReportingKeyId;
  }
  return false;
}

export function reportingSignedWindowIsValid(
  purpose: ReportingNoncePurpose,
  issuedAtMs: number,
  expiresAtMs: number,
): boolean {
  const duration = expiresAtMs - issuedAtMs;
  return duration > 0 && duration <= REPORTING_SIGNED_WINDOW_MS[purpose];
}

/** The `reporting_request_class` domain. Frozen as values, not a bare type alias, so the
 *  schema census can compare it against the doc's `CREATE TYPE … AS ENUM` block. */
export const REPORTING_REQUEST_CLASSES = ["READ", "MUTATION"] as const;
export type ReportingRouteClass = (typeof REPORTING_REQUEST_CLASSES)[number];

export function nonceRetentionForRoute(routeClass: ReportingRouteClass): string {
  return routeClass === "MUTATION"
    ? MUTATION_ROUTE_RETENTION
    : REPORTING_RETENTION.readNonceBurn;
}

export function claimSharedNonce(
  claims: readonly NonceClaim[],
  candidate: NonceClaim,
): NonceClaimResult {
  const exists = claims.some(
    (claim) =>
      claim.nodeId === candidate.nodeId &&
      claim.implementerId === candidate.implementerId &&
      claim.nonce === candidate.nonce,
  );
  if (exists) return { outcome: "REJECT_REPLAY", claims };
  return { outcome: "CLAIMED", claims: [...claims, candidate] };
}

export type DownstreamResult =
  | "SUCCESS"
  | "PROTECTED_404"
  | "STATE_409"
  | "HANDLER_500"
  | "HANDLER_FAILURE"
  | "HANDLER_CRASH";

export type BurnDecisionOutcome =
  | "REJECT_INVALID_AUTH"
  | "REJECT_LIFECYCLE_RECHECK"
  | "REJECT_NONCE_REPLAY"
  | "CONTINUE_AFTER_BURN";

export interface BurnDecision {
  readonly outcome: BurnDecisionOutcome;
  readonly burnInserted: boolean;
  readonly burnRetained: boolean;
}

export function decideReportingBurn(input: {
  readonly allPreBurnChecksPass: boolean;
  readonly lifecycleRecheckPasses: boolean;
  readonly nonceAlreadyClaimed: boolean;
  readonly downstreamResult: DownstreamResult;
}): BurnDecision {
  if (!input.allPreBurnChecksPass) {
    return { outcome: "REJECT_INVALID_AUTH", burnInserted: false, burnRetained: false };
  }
  if (!input.lifecycleRecheckPasses) {
    return { outcome: "REJECT_LIFECYCLE_RECHECK", burnInserted: false, burnRetained: false };
  }
  if (input.nonceAlreadyClaimed) {
    return { outcome: "REJECT_NONCE_REPLAY", burnInserted: false, burnRetained: true };
  }
  return { outcome: "CONTINUE_AFTER_BURN", burnInserted: true, burnRetained: true };
}

export type LifecycleCommitOutcome =
  | "COMMITTED"
  | "STALE_HEAD"
  | "INVALID_EPOCH"
  | "INVALID_EVENT"
  | "KEY_STATE_MISMATCH"
  | "TERMINAL_KEY_REACTIVATION"
  | "PRIOR_SLOT_OCCUPIED"
  | "EVENT_HASH_CHAIN_MISMATCH"
  | "HEAD_PROJECTION_MISMATCH";

export interface LifecycleHead {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly epoch: bigint;
  readonly currentKeyId: string | null;
  readonly priorKeyId: string | null;
  readonly overlapExpiresAtMs: number | null;
  readonly authHold: boolean;
  readonly lifecycleEventId: string | null;
  readonly updatedAtMs: number;
}

export interface AuthoritativeKeyState {
  readonly keyId: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly state: ReportingKeyState;
}

export interface LifecycleEvent {
  readonly id: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly epoch: bigint;
  readonly eventType: ReportingLifecycleEventType;
  readonly subjectKeyId: string | null;
  readonly subjectSlot: "CURRENT" | "PRIOR" | null;
  readonly previousEventHash: string | null;
  readonly eventHash: string;
  readonly committedAtMs: number;
  readonly projectedHead: LifecycleHead;
}

export interface LifecycleKeyTransition {
  readonly keyId: string;
  readonly fromState: ReportingKeyState;
  readonly toState: ReportingKeyState;
}

export interface LifecycleCommitResult {
  readonly outcome: LifecycleCommitOutcome;
  readonly committedHead: LifecycleHead | null;
  readonly committedTransition: LifecycleKeyTransition | null;
}

export function commitLifecycleHead(input: {
  readonly currentHead: LifecycleHead;
  readonly expectedEpoch: bigint;
  readonly currentEventHash: string | null;
  readonly keyStates: readonly AuthoritativeKeyState[];
  readonly event: LifecycleEvent;
}): LifecycleCommitResult {
  const { currentHead, event } = input;
  const reject = (outcome: Exclude<LifecycleCommitOutcome, "COMMITTED">): LifecycleCommitResult => ({
    outcome,
    committedHead: null,
    committedTransition: null,
  });
  if (currentHead.epoch < 0n || input.expectedEpoch < 0n || event.epoch <= 0n) {
    return reject("INVALID_EPOCH");
  }
  if (currentHead.epoch !== input.expectedEpoch) {
    return reject("STALE_HEAD");
  }
  if (event.nodeId !== currentHead.nodeId ||
    event.implementerId !== currentHead.implementerId ||
    event.epoch !== currentHead.epoch + 1n ||
    event.id.length === 0 ||
    event.eventHash.length === 0 ||
    !Number.isFinite(event.committedAtMs)) {
    return reject("INVALID_EVENT");
  }
  const isCanonicalPreBootstrapHead = currentHead.epoch === 0n &&
    currentHead.currentKeyId === null &&
    currentHead.priorKeyId === null &&
    currentHead.overlapExpiresAtMs === null &&
    currentHead.authHold &&
    currentHead.lifecycleEventId === null;
  if (currentHead.epoch === 0n ? !isCanonicalPreBootstrapHead || input.currentEventHash !== null
    : currentHead.lifecycleEventId === null || input.currentEventHash === null ||
      input.currentEventHash.length === 0) {
    return reject("INVALID_EVENT");
  }
  if (event.previousEventHash !== input.currentEventHash) {
    return reject("EVENT_HASH_CHAIN_MISMATCH");
  }

  const authoritativeState = (keyId: string): ReportingKeyState | null => {
    const matches = input.keyStates.filter((key) => key.keyId === keyId);
    if (matches.length !== 1) return null;
    const [key] = matches;
    return key.nodeId === currentHead.nodeId && key.implementerId === currentHead.implementerId
      ? key.state
      : null;
  };

  const currentState = currentHead.currentKeyId === null
    ? null
    : authoritativeState(currentHead.currentKeyId);
  const priorState = currentHead.priorKeyId === null
    ? null
    : authoritativeState(currentHead.priorKeyId);
  if ((currentHead.currentKeyId !== null && currentState !== "ACTIVE") ||
    (currentHead.priorKeyId !== null && priorState !== "ACTIVE")) {
    return reject("KEY_STATE_MISMATCH");
  }

  let expectedHead: LifecycleHead | null = null;
  let committedTransition: LifecycleKeyTransition | null = null;
  if (event.eventType === "FIRST_KEY_ACTIVATED" || event.eventType === "KEY_ROTATED") {
    if (event.subjectKeyId === null || event.subjectSlot !== "CURRENT") {
      return reject("INVALID_EVENT");
    }
    const subjectState = authoritativeState(event.subjectKeyId);
    if (subjectState === "RETIRED" || subjectState === "REVOKED") {
      return reject("TERMINAL_KEY_REACTIVATION");
    }
    if (subjectState !== "PENDING") return reject("KEY_STATE_MISMATCH");
    committedTransition = { keyId: event.subjectKeyId, fromState: "PENDING", toState: "ACTIVE" };
    if (event.eventType === "FIRST_KEY_ACTIVATED") {
      if (!isCanonicalPreBootstrapHead) return reject("INVALID_EVENT");
      expectedHead = {
        ...currentHead,
        epoch: event.epoch,
        currentKeyId: event.subjectKeyId,
        authHold: false,
        lifecycleEventId: event.id,
      };
    } else {
      if (currentHead.epoch === 0n || currentHead.currentKeyId === null || currentState !== "ACTIVE" ||
        event.subjectKeyId === currentHead.currentKeyId) {
        return reject("KEY_STATE_MISMATCH");
      }
      if (currentHead.priorKeyId !== null) return reject("PRIOR_SLOT_OCCUPIED");
      expectedHead = {
        ...currentHead,
        epoch: event.epoch,
        currentKeyId: event.subjectKeyId,
        priorKeyId: currentHead.currentKeyId,
        overlapExpiresAtMs: event.committedAtMs + REPORTING_KEY_OVERLAP_MS,
        lifecycleEventId: event.id,
      };
    }
  } else if (event.eventType === "PRIOR_KEY_RETIRED") {
    if (event.subjectKeyId === null || event.subjectSlot !== "PRIOR" ||
      event.subjectKeyId !== currentHead.priorKeyId || priorState !== "ACTIVE") {
      return reject("INVALID_EVENT");
    }
    committedTransition = { keyId: event.subjectKeyId, fromState: "ACTIVE", toState: "RETIRED" };
    expectedHead = {
      ...currentHead,
      epoch: event.epoch,
      priorKeyId: null,
      overlapExpiresAtMs: null,
      lifecycleEventId: event.id,
    };
  } else if (event.eventType === "KEY_REVOKED") {
    if (event.subjectKeyId === null || event.subjectSlot === null) return reject("INVALID_EVENT");
    if (event.subjectSlot === "CURRENT") {
      if (event.subjectKeyId !== currentHead.currentKeyId || currentState !== "ACTIVE") {
        return reject("INVALID_EVENT");
      }
      if (currentHead.priorKeyId !== null) return reject("PRIOR_SLOT_OCCUPIED");
      expectedHead = {
        ...currentHead,
        epoch: event.epoch,
        currentKeyId: null,
        authHold: true,
        lifecycleEventId: event.id,
      };
    } else {
      if (event.subjectKeyId !== currentHead.priorKeyId || priorState !== "ACTIVE") {
        return reject("INVALID_EVENT");
      }
      expectedHead = {
        ...currentHead,
        epoch: event.epoch,
        priorKeyId: null,
        overlapExpiresAtMs: null,
        lifecycleEventId: event.id,
      };
    }
    committedTransition = { keyId: event.subjectKeyId, fromState: "ACTIVE", toState: "REVOKED" };
  } else {
    if (event.subjectKeyId !== null || event.subjectSlot !== null) return reject("INVALID_EVENT");
    if (event.eventType === "AUTH_HOLD_SET") {
      if (currentHead.authHold) return reject("INVALID_EVENT");
      expectedHead = {
        ...currentHead,
        epoch: event.epoch,
        authHold: true,
        lifecycleEventId: event.id,
      };
    } else {
      if (!currentHead.authHold || currentHead.currentKeyId === null) return reject("INVALID_EVENT");
      expectedHead = {
        ...currentHead,
        epoch: event.epoch,
        authHold: false,
        lifecycleEventId: event.id,
      };
    }
  }

  expectedHead = { ...expectedHead, updatedAtMs: event.committedAtMs };
  const projectionMatches = Object.entries(expectedHead).every(
    ([field, value]) => event.projectedHead[field as keyof LifecycleHead] === value,
  );
  if (!projectionMatches) return reject("HEAD_PROJECTION_MISMATCH");
  return { outcome: "COMMITTED", committedHead: expectedHead, committedTransition };
}

export type ReportingKeyEligibilityState = "ACTIVE" | "RETIRED" | "REVOKED";

export function priorKeyEligible(input: {
  readonly isPriorSlot: boolean;
  readonly keyState: ReportingKeyEligibilityState;
  readonly revokedAtMs: number | null;
  readonly successorCommittedAtMs: number;
  readonly storedOverlapExpiresAtMs: number;
  readonly receivedAtMs: number;
}): boolean {
  const exactExpiry = input.successorCommittedAtMs + REPORTING_KEY_OVERLAP_MS;
  return input.isPriorSlot &&
    input.keyState === "ACTIVE" &&
    input.revokedAtMs === null &&
    input.storedOverlapExpiresAtMs === exactExpiry &&
    input.receivedAtMs >= input.successorCommittedAtMs &&
    input.receivedAtMs < exactExpiry;
}

export type RegistrationEvidenceOutcome =
  | "ACCEPT_FIRST_KEY_BOOTSTRAP"
  | "ACCEPT_EXISTING_KEY_ROTATION"
  | "REJECT_BOOTSTRAP_EVIDENCE"
  | "REJECT_ROTATION_ANCHOR"
  | "REJECT_PROOF_OF_POSSESSION";

export function evaluateRegistrationEvidence(input: {
  readonly mode: RegistrationEvidenceMode;
  readonly onboardingCredentialValid: boolean;
  readonly implementerIdFromAuthenticatedCaller: boolean;
  readonly nodeOriginOperatorApproval: boolean;
  readonly existingKeyAnchorValid: boolean;
  readonly proofOfPossessionValid: boolean;
}): RegistrationEvidenceOutcome {
  if (!input.proofOfPossessionValid) return "REJECT_PROOF_OF_POSSESSION";
  if (input.mode === "FIRST_KEY_BOOTSTRAP") {
    return input.onboardingCredentialValid &&
      input.implementerIdFromAuthenticatedCaller &&
      input.nodeOriginOperatorApproval
      ? "ACCEPT_FIRST_KEY_BOOTSTRAP"
      : "REJECT_BOOTSTRAP_EVIDENCE";
  }
  return input.existingKeyAnchorValid
    ? "ACCEPT_EXISTING_KEY_ROTATION"
    : "REJECT_ROTATION_ANCHOR";
}

export interface DurableRegistrationNonceEvidence {
  readonly id: string;
  readonly purpose: ReportingNoncePurpose;
  readonly reportingKeyId: string | null;
  readonly newReportingKeyId: string | null;
  readonly bootstrapEvidenceId: string | null;
  readonly requestPreimageText: string;
  readonly requestPreimageSha256: string;
  readonly requestSignature: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface DurableEnrolmentEvidence {
  readonly nonceEvidenceId: string;
  readonly registrationPurpose: ReportingNoncePurpose;
  readonly newReportingKeyId: string;
  readonly supersedesKeyId: string | null;
  readonly authorizingKeyId: string | null;
  readonly bootstrapEvidenceId: string | null;
  readonly proofOfPossessionPreimageText: string;
  readonly proofOfPossessionPreimageSha256: string;
  readonly proofOfPossessionSignature: string;
  readonly authorizingPreimageText: string | null;
  readonly authorizingPreimageSha256: string | null;
  readonly authorizingSignature: string | null;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface BootstrapEvidenceProjection {
  readonly id: string;
  readonly newReportingKeyId: string;
}

export interface RotationAuthorizerEvidence {
  readonly keyId: string;
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly signature: string;
}

export interface RegistrationCrossBinding {
  readonly mode: RegistrationEvidenceMode;
  readonly nonce: DurableRegistrationNonceEvidence;
  readonly enrolment: DurableEnrolmentEvidence;
  readonly bootstrapEvidence: BootstrapEvidenceProjection | null;
  readonly rotationAuthorizer: RotationAuthorizerEvidence | null;
  readonly proofOfPossessionVerified: boolean;
  readonly authorizingSignatureVerified: boolean;
}

export type RegistrationCrossBindingOutcome =
  | "ACCEPT_BOOTSTRAP_CROSS_BINDING"
  | "ACCEPT_ROTATION_CROSS_BINDING"
  | "REJECT_REGISTER_BINDING"
  | "REJECT_BOOTSTRAP_CROSS_BINDING"
  | "REJECT_ROTATION_CROSS_BINDING";

const nonEmpty = (value: string | null): value is string => value !== null && value.length > 0;

export function evaluateRegistrationCrossBinding(
  input: RegistrationCrossBinding,
): RegistrationCrossBindingOutcome {
  const { nonce, enrolment } = input;
  const registerBindingValid =
    nonce.purpose === "zp-reporting-register-v1" &&
    enrolment.registrationPurpose === "zp-reporting-register-v1" &&
    nonce.id === enrolment.nonceEvidenceId &&
    nonce.newReportingKeyId !== null &&
    nonce.newReportingKeyId === enrolment.newReportingKeyId &&
    nonce.requestPreimageText === enrolment.proofOfPossessionPreimageText &&
    nonce.requestPreimageSha256 === enrolment.proofOfPossessionPreimageSha256 &&
    nonce.requestSignature === enrolment.proofOfPossessionSignature &&
    nonce.issuedAt === enrolment.issuedAt &&
    nonce.expiresAt === enrolment.expiresAt &&
    nonEmpty(nonce.requestPreimageText) &&
    nonEmpty(nonce.requestPreimageSha256) &&
    nonEmpty(nonce.requestSignature) &&
    nonEmpty(nonce.issuedAt) &&
    nonEmpty(nonce.expiresAt) &&
    input.proofOfPossessionVerified;
  if (!registerBindingValid) return "REJECT_REGISTER_BINDING";

  if (input.mode === "FIRST_KEY_BOOTSTRAP") {
    return nonce.reportingKeyId === null &&
      nonEmpty(nonce.bootstrapEvidenceId) &&
      enrolment.supersedesKeyId === null &&
      enrolment.authorizingKeyId === null &&
      enrolment.bootstrapEvidenceId === nonce.bootstrapEvidenceId &&
      input.bootstrapEvidence !== null &&
      input.bootstrapEvidence.id === nonce.bootstrapEvidenceId &&
      input.bootstrapEvidence.newReportingKeyId === nonce.newReportingKeyId &&
      enrolment.authorizingPreimageText === null &&
      enrolment.authorizingPreimageSha256 === null &&
      enrolment.authorizingSignature === null &&
      input.rotationAuthorizer === null
      ? "ACCEPT_BOOTSTRAP_CROSS_BINDING"
      : "REJECT_BOOTSTRAP_CROSS_BINDING";
  }

  return nonce.bootstrapEvidenceId === null &&
    enrolment.bootstrapEvidenceId === null &&
    input.bootstrapEvidence === null &&
    nonEmpty(nonce.reportingKeyId) &&
    nonce.reportingKeyId === enrolment.supersedesKeyId &&
    nonce.reportingKeyId === enrolment.authorizingKeyId &&
    nonce.reportingKeyId !== nonce.newReportingKeyId &&
    input.rotationAuthorizer !== null &&
    input.rotationAuthorizer.keyId === nonce.reportingKeyId &&
    input.rotationAuthorizer.preimageText === enrolment.authorizingPreimageText &&
    input.rotationAuthorizer.preimageSha256 === enrolment.authorizingPreimageSha256 &&
    input.rotationAuthorizer.signature === enrolment.authorizingSignature &&
    nonEmpty(enrolment.authorizingPreimageText) &&
    nonEmpty(enrolment.authorizingPreimageSha256) &&
    nonEmpty(enrolment.authorizingSignature) &&
    input.authorizingSignatureVerified
    ? "ACCEPT_ROTATION_CROSS_BINDING"
    : "REJECT_ROTATION_CROSS_BINDING";
}

export interface LogicalFingerprintInput {
  readonly method: string;
  readonly rawTarget: string;
  readonly bodySha256: string;
  readonly nonce: string;
  readonly reportingKeyId: string;
  readonly lifecycleEpoch: bigint;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly idempotencyKey: string;
}

export function sameLogicalFingerprint(
  left: LogicalFingerprintInput,
  right: LogicalFingerprintInput,
): boolean {
  return left.method === right.method &&
    left.rawTarget === right.rawTarget &&
    left.bodySha256 === right.bodySha256;
}

export interface PersistedExactResponse {
  readonly status: number;
  readonly bytes: readonly number[];
  readonly completedAt: string;
}

export function persistExactResponse(
  status: number,
  responseBytes: Uint8Array,
  completedAt: string,
  crashBeforeAtomicCommit: boolean,
): PersistedExactResponse | null {
  if (crashBeforeAtomicCommit) return null;
  if (!Number.isInteger(status) || status < 100 || status > 599 || completedAt.length === 0) return null;
  const bytes = Object.freeze(Array.from(responseBytes));
  return Object.freeze({ status, bytes, completedAt });
}

export function replayExactResponse(original: PersistedExactResponse): Uint8Array {
  return new Uint8Array(original.bytes);
}

export type MutationAtomicityOutcome =
  | "COMMIT_COMPLETED_PAIR"
  | "NO_PERSISTENCE"
  | "REJECT_DURABLE_PENDING"
  | "REJECT_ORPHAN_COMPLETED_PARENT"
  | "REJECT_ORPHAN_CHILD";

export function decideMutationAtomicity(input: {
  readonly parentState: "NONE" | "PENDING" | "COMPLETED";
  readonly matchingChildExists: boolean;
}): MutationAtomicityOutcome {
  if (input.parentState === "PENDING") return "REJECT_DURABLE_PENDING";
  if (input.parentState === "COMPLETED") {
    return input.matchingChildExists
      ? "COMMIT_COMPLETED_PAIR"
      : "REJECT_ORPHAN_COMPLETED_PARENT";
  }
  return input.matchingChildExists ? "REJECT_ORPHAN_CHILD" : "NO_PERSISTENCE";
}

export interface MutationBindingProjection {
  readonly reportingNonceId: string;
  readonly idempotencyId: string;
  readonly childRecordId: string;
  readonly method: string;
  readonly rawTarget: string;
  readonly bodySha256: string;
  readonly logicalFingerprint: string;
}

export function mutationEvidenceBindingsMatch(
  nonce: MutationBindingProjection,
  idempotency: MutationBindingProjection,
  child: MutationBindingProjection,
): boolean {
  const fields: readonly (keyof MutationBindingProjection)[] = [
    "reportingNonceId",
    "idempotencyId",
    "childRecordId",
    "method",
    "rawTarget",
    "bodySha256",
    "logicalFingerprint",
  ];
  return fields.every((field) =>
    nonce[field].length > 0 &&
    nonce[field] === idempotency[field] &&
    idempotency[field] === child[field]);
}

export interface RestoreMarkers {
  readonly lifecycleEpoch: bigint;
  readonly nonceBurnHighWater: bigint;
}

export interface ExternalRestoreAuthority {
  readonly markers: RestoreMarkers;
  readonly lifecycleEpochVerified: boolean;
  readonly nonceBurnHighWaterVerified: boolean;
  readonly trustedEventHash: string;
}

export interface RestoredReportingState {
  readonly markers: RestoreMarkers;
  readonly eventHash: string;
  readonly nextEventPreviousHash: string;
}

export function restoreRequiresAuthHold(
  restored: RestoredReportingState,
  external: ExternalRestoreAuthority | null,
): boolean {
  if (external === null) return true;
  if (!external.lifecycleEpochVerified || !external.nonceBurnHighWaterVerified) return true;
  if (!nonEmpty(external.trustedEventHash) || !nonEmpty(restored.eventHash) ||
    !nonEmpty(restored.nextEventPreviousHash)) return true;
  return restored.markers.lifecycleEpoch !== external.markers.lifecycleEpoch ||
    restored.markers.nonceBurnHighWater !== external.markers.nonceBurnHighWater ||
    restored.eventHash !== external.trustedEventHash ||
    restored.nextEventPreviousHash !== restored.eventHash;
}

export function reportingAdmissionAllowed(input: {
  readonly nodeRestoreHold: boolean;
  readonly lifecycleHeadAuthHold: boolean;
}): boolean {
  return !input.nodeRestoreHold && !input.lifecycleHeadAuthHold;
}

export function reportingKeyIdentityIsPublicOnly(fields: readonly string[]): boolean {
  if (fields.length !== REPORTING_KEY_IDENTITY_ALLOWED_FIELDS.length) return false;
  const allowed = new Set<string>(REPORTING_KEY_IDENTITY_ALLOWED_FIELDS);
  return new Set(fields).size === fields.length && fields.every((field) => allowed.has(field));
}

export function idempotencyKeyIsValid(value: string): boolean {
  if (value.length < IDEMPOTENCY_KEY_CONTRACT.minLength ||
    value.length > IDEMPOTENCY_KEY_CONTRACT.maxLength) return false;
  return [...value].every((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined &&
      codePoint >= IDEMPOTENCY_KEY_CONTRACT.minCodePoint &&
      codePoint <= IDEMPOTENCY_KEY_CONTRACT.maxCodePoint;
  });
}

export interface GuardedFingerprintClaim {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly routeId: (typeof FINGERPRINT_GUARDED_ROUTE_IDS)[number];
  readonly method: string;
  readonly rawTarget: string;
  readonly bodySha256: string;
  readonly logicalFingerprint: string;
  readonly idempotencyKey: string;
}

export function guardedFingerprintAlreadyClaimed(
  claims: readonly GuardedFingerprintClaim[],
  candidate: GuardedFingerprintClaim,
): boolean {
  return claims.some((claim) =>
    claim.nodeId === candidate.nodeId &&
    claim.implementerId === candidate.implementerId &&
    claim.routeId === candidate.routeId &&
    claim.method === candidate.method &&
    claim.rawTarget === candidate.rawTarget &&
    claim.bodySha256 === candidate.bodySha256);
}

export interface CompletedIdempotencyResult {
  readonly fingerprint: LogicalFingerprintInput;
  readonly response: PersistedExactResponse;
}

export type PostBurnOutcome =
  | "REPLAY_EXACT_RESPONSE"
  | "CONFLICTING_FINGERPRINT"
  | "PROTECTED_NOT_FOUND"
  | "RUN_HANDLER";

export interface PostBurnDecision {
  readonly outcome: PostBurnOutcome;
  readonly protectedLookupPerformed: boolean;
  readonly response: PersistedExactResponse | null;
}

export function decidePostBurn(input: {
  readonly completed: CompletedIdempotencyResult | null;
  readonly requestFingerprint: LogicalFingerprintInput;
  readonly protectedObjectExists: boolean;
}): PostBurnDecision {
  if (input.completed !== null) {
    return sameLogicalFingerprint(input.completed.fingerprint, input.requestFingerprint)
      ? {
          outcome: "REPLAY_EXACT_RESPONSE",
          protectedLookupPerformed: false,
          response: input.completed.response,
        }
      : {
          outcome: "CONFLICTING_FINGERPRINT",
          protectedLookupPerformed: false,
          response: null,
        };
  }
  if (!input.protectedObjectExists) {
    return { outcome: "PROTECTED_NOT_FOUND", protectedLookupPerformed: true, response: null };
  }
  return { outcome: "RUN_HANDLER", protectedLookupPerformed: true, response: null };
}
