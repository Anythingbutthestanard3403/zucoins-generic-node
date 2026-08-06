import { describe, expect, it } from "vitest";

import golden from "./gen/reporting-persistence.json" with { type: "json" };
import {
  buildReportingPersistenceManifest,
  reportingPersistenceConcernManifest,
} from "./manifest.js";

const manifest = buildReportingPersistenceManifest();

describe("reporting-persistence manifest freeze", () => {
  it("freezes the concern identity, authorities, and complete contract slices", () => {
    expect(reportingPersistenceConcernManifest).toEqual({
      concern: "reporting-persistence",
      ticket: "reporting-persistence",
      frozen: [
        "SHARED_NONCE_LEDGER",
        "PRE_HANDLER_BURN_TRANSACTION",
        "REPORTING_LIFECYCLE_PERSISTENCE",
        "MUTATION_IDEMPOTENCY",
        "RESTORE_AND_RETENTION",
        "PUBLIC_KEY_ONLY_IDENTITY",
      ],
    });
    expect(manifest.governing.decisions).toEqual(["reporting-channel", "reporting-key-enrolment"]);
    expect(() => JSON.stringify(manifest)).not.toThrow();
  });

  it("freezes the one shared nonce scope and immutable exact evidence", () => {
    expect(manifest.nonceLedger.purposes).toEqual([
      "zp-reporting-register-v1", "zp-report-request-v1",
    ]);
    expect(manifest.nonceLedger.uniqueBy).toEqual(["node_id", "implementer_id", "nonce"]);
    expect(manifest.nonceLedger.scopeExcludes).toEqual([
      "purpose", "route_id", "request_class", "reporting_key_id", "new_reporting_key_id",
      "bootstrap_evidence_id",
    ]);
    expect(manifest.nonceLedger.fields).toEqual([
      "id", "node_id", "implementer_id", "nonce", "purpose", "route_id",
      "request_class", "reporting_key_id", "new_reporting_key_id", "bootstrap_evidence_id",
      "lifecycle_epoch", "nonce_burn_sequence", "request_preimage_text",
      "request_preimage_sha256", "request_signature", "method", "raw_target", "body_sha256",
      "logical_fingerprint", "issued_at", "expires_at", "received_at", "consumed_at",
      "retention_class",
    ]);
    expect(manifest.nonceLedger.allFieldsImmutable).toBe(true);
    expect(manifest.nonceLedger.reportingKeyIdNullability).toEqual({
      nullableOnlyFor: "FIRST_KEY_BOOTSTRAP",
      requiredFor: ["EXISTING_KEY_ANCHORED_ROTATION", "SIGNED_REQUEST"],
    });
    expect(manifest.nonceLedger.signedWindowMs).toEqual({
      "zp-report-request-v1": 60_000,
      "zp-reporting-register-v1": 300_000,
    });
    expect(manifest.nonceLedger.registerRequiresNewReportingKeyId).toBe(true);
    expect(manifest.nonceLedger.rawTargetRule).toBe(
      "OPAQUE_EXACT_SIGNED_BYTES_NEVER_NORMALIZE_OR_RECONSTRUCT",
    );
    expect(manifest.nonceLedger.invalidAuthBurnsNothing).toBe(true);
    expect(manifest.nonceLedger.authenticatedFailureRetainsBurn).toEqual([
      404, 409, 500, "handler_failure", "handler_crash",
    ]);
  });

  it("commits the short burn before any protected lookup or handler work", () => {
    expect(manifest.requestPipeline.preBurnChecks).toEqual([
      "bounded_shape", "signed_time_window", "bounded_size", "bounded_rate",
      "tenant_and_key_binding", "lifecycle_eligibility", "signature",
    ]);
    expect(manifest.requestPipeline.burnTransaction).toEqual([
      "begin_short_transaction", "lock_shared_lifecycle_head",
      "recheck_lifecycle_epoch_key_and_auth_hold", "insert_shared_nonce_evidence",
      "commit_burn",
    ]);
    expect(manifest.requestPipeline.postBurnStages).toEqual([
      "completed_idempotency_lookup_and_fingerprint_check",
      "protected_lookup_if_no_completed_result",
      "guarded_handler",
    ]);
    expect(manifest.requestPipeline.shortTransactionEndsBeforeProtectedLookup).toBe(true);
    expect(manifest.requestPipeline.completedIdempotencyPrecedesProtectedLookup).toBe(true);
    expect(manifest.requestPipeline.changedFingerprintConflictsBeforeProtectedLookup).toBe(true);
  });

  it("freezes one lifecycle head, append-only epoch events, terminal states, and strict overlap", () => {
    expect(manifest.lifecycle.identityFields).toEqual([
      "id", "node_id", "implementer_id", "public_key", "registered_at",
    ]);
    expect(manifest.lifecycle.oneHeadBy).toEqual(["node_id", "implementer_id"]);
    expect(manifest.lifecycle.headFields).toEqual([
      "node_id", "implementer_id", "epoch", "current_key_id", "prior_key_id",
      "overlap_expires_at", "auth_hold", "lifecycle_event_id", "updated_at",
    ]);
    expect(manifest.lifecycle.eventFields).toEqual([
      "id", "node_id", "implementer_id", "epoch", "event_type", "current_key_id",
      "prior_key_id", "overlap_expires_at", "auth_hold", "successor_registered_at",
      "nonce_evidence_id", "nonce_purpose", "enrolment_evidence_id", "public_evidence_text",
      "public_evidence_sha256", "previous_event_hash", "event_hash", "committed_at",
    ]);
    expect(manifest.lifecycle.canonicalPreBootstrapHead).toEqual({
      epoch: 0,
      currentKeyId: null,
      priorKeyId: null,
      overlapExpiresAt: null,
      authHold: true,
      lifecycleEventId: null,
    });
    expect(manifest.lifecycle.positiveEventEpoch).toBe(true);
    expect(manifest.lifecycle.eventUniqueBy).toEqual(["node_id", "implementer_id", "epoch"]);
    expect(manifest.lifecycle.keyStates).toEqual(["PENDING", "ACTIVE", "RETIRED", "REVOKED"]);
    expect(manifest.lifecycle.eventTypes).toEqual([
      "FIRST_KEY_ACTIVATED", "KEY_ROTATED", "PRIOR_KEY_RETIRED", "KEY_REVOKED",
      "AUTH_HOLD_SET", "AUTH_HOLD_RELEASED",
    ]);
    expect(manifest.lifecycle.legalKeyTransitions).toEqual([
      { eventType: "FIRST_KEY_ACTIVATED", from: "PENDING", to: "ACTIVE" },
      { eventType: "KEY_ROTATED", from: "PENDING", to: "ACTIVE" },
      { eventType: "PRIOR_KEY_RETIRED", from: "ACTIVE", to: "RETIRED" },
      { eventType: "KEY_REVOKED", from: "ACTIVE", to: "REVOKED" },
    ]);
    expect(manifest.lifecycle.transitionsUseSameHeadLock).toEqual([
      "FIRST_KEY_ACTIVATED", "KEY_ROTATED", "PRIOR_KEY_RETIRED", "KEY_REVOKED",
      "AUTH_HOLD_SET", "AUTH_HOLD_RELEASED",
    ]);
    expect(manifest.lifecycle.firstHeadLockCommitWins).toBe(true);
    expect(manifest.lifecycle.lifecycleEventIsAuthoritative).toBe(true);
    expect(manifest.lifecycle.headProjectionMustEqualCitedEvent).toBe(true);
    expect(manifest.lifecycle.terminalKeysReactivate).toBe(false);
    expect(manifest.lifecycle.occupiedPriorMustBeExplicitlyRetiredOrRevokedBeforeRotation).toBe(true);
    expect(manifest.lifecycle.eventsAppendOnly).toBe(true);
    expect(manifest.lifecycle.identitiesImmutable).toBe(true);
    expect(manifest.lifecycle.overlapWindowMs).toBe(86_400_000);
    expect(manifest.lifecycle.overlapInterval).toBe(
      "SUCCESSOR_COMMIT_INCLUSIVE_TO_EXPIRY_EXCLUSIVE",
    );
    expect(manifest.lifecycle.overlapExpiryDerivedFromSuccessorCommit).toBe(true);
    expect(manifest.lifecycle.storedOverlapExpiryMustEqualDerivedExpiry).toBe(true);
    expect(manifest.lifecycle.registrationEvidenceModes).toEqual([
      "FIRST_KEY_BOOTSTRAP", "EXISTING_KEY_ANCHORED_ROTATION",
    ]);
    expect(manifest.lifecycle.firstBootstrapEvidence).toBe(
      "AUTHENTICATED_CALLER_PLUS_NODE_APPROVAL_PLUS_PROOF_OF_POSSESSION",
    );
    expect(manifest.lifecycle.rotationEvidence).toBe(
      "EXISTING_KEY_ANCHOR_PLUS_PROOF_OF_POSSESSION",
    );
    expect(manifest.lifecycle.registrationEvidenceFields).toEqual([
      "id", "node_id", "implementer_id", "new_reporting_key_id", "supersedes_key_id",
      "authorizing_key_id", "bootstrap_evidence_id", "nonce_evidence_id",
      "registration_purpose", "proof_of_possession_preimage_text",
      "proof_of_possession_preimage_sha256", "proof_of_possession_signature",
      "authorizing_preimage_text", "authorizing_preimage_sha256", "authorizing_signature",
      "issued_at", "expires_at", "created_at",
    ]);
    expect(manifest.lifecycle.registrationCrossBinding).toEqual({
      exactNonceEvidenceFields: [
        "request_preimage_text", "request_preimage_sha256", "request_signature",
        "issued_at", "expires_at", "new_reporting_key_id",
      ],
      enrolmentMustExactlyMatchNonceEvidence: true,
      bootstrapEvidenceIdMustMatchCitedEvidence: true,
      bootstrapEvidenceNewKeyMustMatchRegisterPreimage: true,
      rotationAuthorizingKeyMatchesLedgerKey: true,
      rotationAuthorizingPreimageDigestAndSignatureMustExactlyMatch: true,
    });
    expect(manifest.lifecycle.eventHashChain).toEqual({
      eventsAppendOnly: true,
      eventBytesImmutable: true,
      predecessorHashRequiredAfterFirstEvent: true,
      predecessorHashMustEqualPriorEventHash: true,
    });
  });

  it("separates mutation idempotency and freezes exact response replay plus arm/ack guard", () => {
    expect(manifest.mutationIdempotency.fields).toEqual([
      "id", "node_id", "implementer_id", "route_id", "idempotency_key",
      "reporting_nonce_id", "child_record_id", "method", "raw_target", "body_sha256",
      "logical_fingerprint", "response_status", "response_bytes", "completed_at", "created_at",
    ]);
    expect(manifest.mutationIdempotency.uniqueBy).toEqual([
      "node_id", "implementer_id", "route_id", "idempotency_key",
    ]);
    expect(manifest.mutationIdempotency.logicalFingerprintFields).toEqual([
      "method", "raw_target", "body_sha256",
    ]);
    expect(manifest.mutationIdempotency.logicalFingerprintExcludes).toEqual([
      "nonce", "reporting_key_id", "lifecycle_epoch", "issued_at", "expires_at",
      "received_at", "idempotency_key",
    ]);
    expect(manifest.mutationIdempotency.bodyDigestComparedOutsideKeyUniqueness).toBe(true);
    expect(manifest.mutationIdempotency.exactStatusAndResponseBytesCommitAtomicallyWithMutation).toBe(true);
    expect(manifest.mutationIdempotency.exactResponseBytesReplayAcrossKeyRotation).toBe(true);
    expect(manifest.mutationIdempotency.fingerprintGuardedRouteIds).toEqual([
      "operation_armed", "verification_complete",
    ]);
    expect(manifest.mutationIdempotency.guardedFingerprintPartialUnique).toEqual({
      fields: ["node_id", "implementer_id", "route_id", "method", "raw_target", "body_sha256"],
      whereRouteIdIn: ["operation_armed", "verification_complete"],
    });
    expect(manifest.mutationIdempotency.fingerprintGuardDefeatsChangedUnsignedIdempotencyHeader).toBe(true);
    expect(manifest.mutationIdempotency.guardedDuplicateAuthorityFields).toEqual([
      "method", "raw_target", "body_sha256",
    ]);
    expect(manifest.mutationIdempotency.logicalFingerprintDerivedAuditOnly).toBe(true);
    expect(manifest.mutationIdempotency.idempotencyKey).toEqual({
      minLength: 16,
      maxLength: 255,
      minCodePoint: 0x21,
      maxCodePoint: 0x7e,
    });
    expect(manifest.mutationIdempotency.durablePendingRowsAllowed).toBe(false);
    expect(manifest.mutationIdempotency.requiredCompletionFields).toEqual([
      "response_status", "response_bytes", "completed_at",
    ]);
    expect(manifest.mutationIdempotency.mutationAndCompletedResultAtomic).toBe(true);
    expect(manifest.mutationIdempotency.completedParentRequiresMatchingChild).toBe(true);
    expect(manifest.mutationIdempotency.evidenceBindingFields).toEqual([
      "reporting_nonce_id", "mutation_idempotency_id", "child_record_id", "method",
      "raw_target", "body_sha256", "logical_fingerprint",
    ]);
    expect(manifest.mutationIdempotency.nonceIdempotencyAndChildEvidenceMustMatch).toBe(true);
    expect(manifest.mutationIdempotency.routeRetention).toBe("PERMANENT");
    expect(manifest.mutationIdempotency.immutability).toEqual({
      nonceEvidenceAppendOnly: true,
      nonceEvidenceImmutable: true,
      idempotencyEvidenceAppendOnly: true,
      idempotencyEvidenceImmutable: true,
      responseEvidenceImmutable: true,
    });
    expect(manifest.mutationIdempotency.exactResponsePersistence).toEqual({
      statusRange: [100, 599],
      statusRequired: true,
      bodyRequired: true,
      completionTimestampRequired: true,
      bytesImmutableCopy: true,
      mutationAndResultCrashAtomic: true,
      replayReturnsFreshByteCopy: true,
    });
  });

  it("freezes restore hard-hold, no-prune posture, permanence, and public-key-only custody", () => {
    expect(manifest.recovery.backupIncludesAllEvidence).toBe(true);
    expect(manifest.recovery.regressionMarkers).toEqual([
      "lifecycle_epoch", "nonce_burn_high_water",
    ]);
    expect(manifest.recovery.restorePolicy).toEqual({
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
    });
    expect(manifest.recovery.restoreAdmissionRequiresBothHoldsClear).toEqual([
      "node_restore_hold", "lifecycle_head_auth_hold",
    ]);
    expect(manifest.recovery.retention).toEqual({
      readNonceBurn: "NO_PRUNE_UNTIL_SAFETY_SOURCE_AND_MARGIN_FROZEN",
      mutationNonceBurn: "PERMANENT",
      mutationIdempotency: "PERMANENT",
      lifecycleEvidence: "PERMANENT",
    });
    expect(manifest.custody.allowedIdentityFields).toEqual([
      "id", "node_id", "implementer_id", "public_key", "registered_at",
    ]);
    expect(manifest.custody.nodeStoresReportingPublicKeyOnly).toBe(true);
    expect(manifest.custody.exactFieldSetRequired).toBe(true);
    expect(manifest.custody.unknownFieldsRejected).toBe(true);
    expect(manifest.custody.forbiddenIdentityFields).toEqual([
      "private_key", "private_key_bytes", "seed", "secret", "vault_ref", "vault_secret_ref",
    ]);
  });

  it("freezes the contract-only exclusions", () => {
    expect(manifest.scopeExclusions).toEqual([
      "physical_application_migration", "legacy_push_reporting_tables",
      "frozen_v1_path_changes", "private_key_storage", "live_action",
    ]);
  });
});

describe("reporting-persistence gen golden freeze (drift-audit backstop)", () => {
  it("buildReportingPersistenceManifest matches the committed gen snapshot", () => {
    expect(JSON.parse(JSON.stringify(buildReportingPersistenceManifest()))).toEqual(golden);
  });
});
