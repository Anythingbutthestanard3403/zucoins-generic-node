import { describe, expect, it } from "vitest";

import {
  BURN_TRANSACTION_STEPS,
  FINGERPRINT_GUARDED_ROUTE_IDS,
  GUARDED_FINGERPRINT_PARTIAL_UNIQUENESS,
  GUARDED_FINGERPRINT_UNIQUENESS_FIELDS,
  IDEMPOTENCY_KEY_CONTRACT,
  LEGAL_LIFECYCLE_KEY_TRANSITIONS,
  LIFECYCLE_EVENT_HASH_CHAIN,
  LOGICAL_FINGERPRINT_EXCLUDED_FIELDS,
  LOGICAL_FINGERPRINT_FIELDS,
  MUTATION_EVIDENCE_BINDING_FIELDS,
  MUTATION_EVIDENCE_IMMUTABILITY,
  MUTATION_IDEMPOTENCY_UNIQUENESS_FIELDS,
  MUTATION_IDEMPOTENCY_FIELDS,
  MUTATION_IDEMPOTENCY_PERSISTENCE,
  MUTATION_ROUTE_RETENTION,
  NONCE_SCOPE_EXCLUDED_FIELDS,
  NONCE_UNIQUENESS_FIELDS,
  POST_BURN_STAGES,
  PRE_BURN_CHECKS,
  REGISTRATION_EVIDENCE_MODES,
  REGISTRATION_EVIDENCE_FIELDS,
  REPORTING_KEY_IDENTITY_ALLOWED_FIELDS,
  REPORTING_KEY_IDENTITY_FORBIDDEN_FIELDS,
  REPORTING_KEY_ID_NULLABILITY,
  REPORTING_KEY_OVERLAP_MS,
  REPORTING_KEY_STATES,
  REPORTING_LIFECYCLE_EVENT_TYPES,
  REPORTING_LIFECYCLE_EVENT_FIELDS,
  REPORTING_LIFECYCLE_EVENT_UNIQUENESS_FIELDS,
  REPORTING_LIFECYCLE_HEAD_FIELDS,
  REPORTING_NONCE_FIELDS,
  REPORTING_NONCE_PURPOSES,
  REPORTING_SIGNED_WINDOW_MS,
  REPORTING_RETENTION,
  RESTORE_POLICY,
  claimSharedNonce,
  commitLifecycleHead,
  decidePostBurn,
  decideReportingBurn,
  decideMutationAtomicity,
  evaluateRegistrationCrossBinding,
  evaluateRegistrationEvidence,
  guardedFingerprintAlreadyClaimed,
  idempotencyKeyIsValid,
  mutationEvidenceBindingsMatch,
  nonceClaimHasValidKeySemantics,
  nonceRetentionForRoute,
  persistExactResponse,
  priorKeyEligible,
  replayExactResponse,
  reportingAdmissionAllowed,
  reportingKeyIdentityIsPublicOnly,
  reportingSignedWindowIsValid,
  restoreRequiresAuthHold,
  sameLogicalFingerprint,
  type DownstreamResult,
  type LogicalFingerprintInput,
  type LifecycleEvent,
  type LifecycleHead,
  type MutationBindingProjection,
  type NonceClaim,
  type RegistrationCrossBinding,
} from "./decisions.js";

const CLAIM: NonceClaim = {
  nodeId: "node-a",
  implementerId: "impl-a",
  nonce: "nonce-a",
  purpose: "zp-report-request-v1",
  routeId: "events",
  reportingKeyId: "key-a",
  newReportingKeyId: null,
  registrationEvidenceMode: null,
};

const FINGERPRINT: LogicalFingerprintInput = {
  method: "POST",
  rawTarget: "/v1/operations/id/verification-complete?cursor=%2F",
  bodySha256: "a".repeat(64),
  nonce: "nonce-a",
  reportingKeyId: "key-a",
  lifecycleEpoch: 1n,
  issuedAt: "2026-07-19T00:00:00.000Z",
  expiresAt: "2026-07-19T00:01:00.000Z",
  idempotencyKey: "idem-a",
};

describe("shared durable nonce ledger", () => {
  it("freezes the cross-purpose schema, projections, and node+implementer+nonce uniqueness", () => {
    expect(NONCE_UNIQUENESS_FIELDS).toEqual(["node_id", "implementer_id", "nonce"]);
    expect(NONCE_SCOPE_EXCLUDED_FIELDS).toEqual([
      "purpose", "route_id", "request_class", "reporting_key_id", "new_reporting_key_id",
      "bootstrap_evidence_id",
    ]);
    expect(REPORTING_NONCE_PURPOSES).toEqual([
      "zp-reporting-register-v1",
      "zp-report-request-v1",
    ]);
    expect(REPORTING_NONCE_FIELDS).toEqual([
      "id", "node_id", "implementer_id", "nonce", "purpose", "route_id",
      "request_class", "reporting_key_id", "new_reporting_key_id", "bootstrap_evidence_id",
      "lifecycle_epoch", "nonce_burn_sequence", "request_preimage_text",
      "request_preimage_sha256", "request_signature", "method", "raw_target", "body_sha256",
      "logical_fingerprint", "issued_at", "expires_at", "received_at", "consumed_at",
      "retention_class",
    ]);
    expect(REPORTING_KEY_ID_NULLABILITY).toEqual({
      nullableOnlyFor: "FIRST_KEY_BOOTSTRAP",
      requiredFor: ["EXISTING_KEY_ANCHORED_ROTATION", "SIGNED_REQUEST"],
    });
  });

  it("allows one concurrent claimant and rejects the cross-route, cross-key contender", () => {
    const first = claimSharedNonce([], CLAIM);
    expect(first.outcome).toBe("CLAIMED");

    const second = claimSharedNonce(first.claims, {
      ...CLAIM,
      routeId: "state_snapshot",
      reportingKeyId: "key-b",
    });
    expect(second.outcome).toBe("REJECT_REPLAY");
    expect(second.claims).toHaveLength(1);
    expect(second.claims[0]).toBe(CLAIM);
  });

  it("rejects the same nonce when register/bootstrap and request purposes race", () => {
    const bootstrap: NonceClaim = {
      ...CLAIM,
      purpose: "zp-reporting-register-v1",
      routeId: "reporting_key_register_bootstrap",
      reportingKeyId: null,
      newReportingKeyId: "key-new",
      registrationEvidenceMode: "FIRST_KEY_BOOTSTRAP",
    };
    expect(nonceClaimHasValidKeySemantics(bootstrap)).toBe(true);
    const first = claimSharedNonce([], bootstrap);
    const request = claimSharedNonce(first.claims, CLAIM);
    expect(request.outcome).toBe("REJECT_REPLAY");
    expect(request.claims).toHaveLength(1);
  });

  it("allows a null reporting key only for first-key bootstrap evidence", () => {
    const bootstrap: NonceClaim = {
      ...CLAIM,
      purpose: "zp-reporting-register-v1",
      reportingKeyId: null,
      newReportingKeyId: "key-new",
      registrationEvidenceMode: "FIRST_KEY_BOOTSTRAP",
    };
    expect(nonceClaimHasValidKeySemantics(bootstrap)).toBe(true);
    expect(nonceClaimHasValidKeySemantics({ ...bootstrap, purpose: "zp-report-request-v1" })).toBe(false);
    expect(nonceClaimHasValidKeySemantics({
      ...bootstrap,
      registrationEvidenceMode: "EXISTING_KEY_ANCHORED_ROTATION",
    })).toBe(false);
    expect(nonceClaimHasValidKeySemantics({
      ...bootstrap,
      reportingKeyId: "key-a",
      newReportingKeyId: "key-new",
      registrationEvidenceMode: "EXISTING_KEY_ANCHORED_ROTATION",
    })).toBe(true);
  });

  it("enforces the 60-second request and 300-second register windows", () => {
    expect(REPORTING_SIGNED_WINDOW_MS).toEqual({
      "zp-report-request-v1": 60_000,
      "zp-reporting-register-v1": 300_000,
    });
    expect(reportingSignedWindowIsValid("zp-report-request-v1", 0, 60_000)).toBe(true);
    expect(reportingSignedWindowIsValid("zp-report-request-v1", 0, 60_001)).toBe(false);
    expect(reportingSignedWindowIsValid("zp-reporting-register-v1", 0, 300_000)).toBe(true);
    expect(reportingSignedWindowIsValid("zp-reporting-register-v1", 0, 300_001)).toBe(false);
    expect(reportingSignedWindowIsValid("zp-report-request-v1", 1, 1)).toBe(false);
  });

  it("derives permanent retention for every mutation route", () => {
    expect(MUTATION_ROUTE_RETENTION).toBe("PERMANENT");
    expect(nonceRetentionForRoute("MUTATION")).toBe("PERMANENT");
    expect(nonceRetentionForRoute("READ")).toBe(
      "NO_PRUNE_UNTIL_SAFETY_SOURCE_AND_MARGIN_FROZEN",
    );
  });
});

describe("auth-before-burn transaction split", () => {
  it("freezes all validation before the short burn transaction and all protected work after it", () => {
    expect(PRE_BURN_CHECKS).toEqual([
      "bounded_shape",
      "signed_time_window",
      "bounded_size",
      "bounded_rate",
      "tenant_and_key_binding",
      "lifecycle_eligibility",
      "signature",
    ]);
    expect(BURN_TRANSACTION_STEPS).toEqual([
      "begin_short_transaction",
      "lock_shared_lifecycle_head",
      "recheck_lifecycle_epoch_key_and_auth_hold",
      "insert_shared_nonce_evidence",
      "commit_burn",
    ]);
    expect(POST_BURN_STAGES).toEqual([
      "completed_idempotency_lookup_and_fingerprint_check",
      "protected_lookup_if_no_completed_result",
      "guarded_handler",
    ]);
  });

  it.each(["invalid", "expired", "revoked", "bad_signature"])(
    "%s authentication inserts no burn row",
    () => {
      expect(decideReportingBurn({
        allPreBurnChecksPass: false,
        lifecycleRecheckPasses: true,
        nonceAlreadyClaimed: false,
        downstreamResult: "SUCCESS",
      })).toEqual({
        outcome: "REJECT_INVALID_AUTH",
        burnInserted: false,
        burnRetained: false,
      });
    },
  );

  it.each<DownstreamResult>([
    "PROTECTED_404",
    "STATE_409",
    "HANDLER_500",
    "HANDLER_FAILURE",
    "HANDLER_CRASH",
  ])("authenticated %s retains its committed burn", (downstreamResult) => {
    expect(decideReportingBurn({
      allPreBurnChecksPass: true,
      lifecycleRecheckPasses: true,
      nonceAlreadyClaimed: false,
      downstreamResult,
    })).toEqual({
      outcome: "CONTINUE_AFTER_BURN",
      burnInserted: true,
      burnRetained: true,
    });
  });
});

describe("serialized reporting-key lifecycle", () => {
  const preBootstrapHead: LifecycleHead = {
    nodeId: "node-a",
    implementerId: "impl-a",
    epoch: 0n,
    currentKeyId: null,
    priorKeyId: null,
    overlapExpiresAtMs: null,
    authHold: true,
    lifecycleEventId: null,
    updatedAtMs: 0,
  };
  const currentHead: LifecycleHead = {
    ...preBootstrapHead,
    epoch: 1n,
    currentKeyId: "key-current",
    authHold: false,
    lifecycleEventId: "event-1",
    updatedAtMs: 100,
  };
  const successorCommit = 1_000;
  const rotatedHead: LifecycleHead = {
    ...currentHead,
    epoch: 2n,
    currentKeyId: "key-new",
    priorKeyId: "key-current",
    overlapExpiresAtMs: successorCommit + REPORTING_KEY_OVERLAP_MS,
    lifecycleEventId: "event-2",
    updatedAtMs: successorCommit,
  };
  const rotationEvent: LifecycleEvent = {
    id: "event-2",
    nodeId: "node-a",
    implementerId: "impl-a",
    epoch: 2n,
    eventType: "KEY_ROTATED",
    subjectKeyId: "key-new",
    subjectSlot: "CURRENT",
    previousEventHash: "a".repeat(64),
    eventHash: "b".repeat(64),
    committedAtMs: successorCommit,
    projectedHead: rotatedHead,
  };
  const keyStates = [
    {
      keyId: "key-current", nodeId: "node-a", implementerId: "impl-a", state: "ACTIVE" as const,
    },
    {
      keyId: "key-new", nodeId: "node-a", implementerId: "impl-a", state: "PENDING" as const,
    },
  ];
  const revokedHead: LifecycleHead = {
    ...currentHead,
    epoch: 2n,
    currentKeyId: null,
    authHold: true,
    lifecycleEventId: "event-revoke",
    updatedAtMs: 700,
  };
  const revokeEvent: LifecycleEvent = {
    id: "event-revoke",
    nodeId: "node-a",
    implementerId: "impl-a",
    epoch: 2n,
    eventType: "KEY_REVOKED",
    subjectKeyId: "key-current",
    subjectSlot: "CURRENT",
    previousEventHash: "a".repeat(64),
    eventHash: "e".repeat(64),
    committedAtMs: 700,
    projectedHead: revokedHead,
  };

  it("freezes one head and append-only event uniqueness per node+implementer epoch", () => {
    expect(REPORTING_LIFECYCLE_HEAD_FIELDS).toEqual([
      "node_id",
      "implementer_id",
      "epoch",
      "current_key_id",
      "prior_key_id",
      "overlap_expires_at",
      "auth_hold",
      "lifecycle_event_id",
      "updated_at",
    ]);
    expect(REPORTING_LIFECYCLE_EVENT_FIELDS).toEqual([
      "id", "node_id", "implementer_id", "epoch", "event_type", "current_key_id",
      "prior_key_id", "overlap_expires_at", "auth_hold", "successor_registered_at",
      "nonce_evidence_id", "nonce_purpose", "enrolment_evidence_id", "public_evidence_text",
      "public_evidence_sha256", "previous_event_hash", "event_hash", "committed_at",
    ]);
    expect(REPORTING_LIFECYCLE_EVENT_UNIQUENESS_FIELDS).toEqual([
      "node_id",
      "implementer_id",
      "epoch",
    ]);
    expect(REPORTING_KEY_STATES).toEqual(["PENDING", "ACTIVE", "RETIRED", "REVOKED"]);
    expect(REPORTING_LIFECYCLE_EVENT_TYPES).toEqual([
      "FIRST_KEY_ACTIVATED", "KEY_ROTATED", "PRIOR_KEY_RETIRED", "KEY_REVOKED",
      "AUTH_HOLD_SET", "AUTH_HOLD_RELEASED",
    ]);
    expect(LEGAL_LIFECYCLE_KEY_TRANSITIONS).toEqual([
      { eventType: "FIRST_KEY_ACTIVATED", from: "PENDING", to: "ACTIVE" },
      { eventType: "KEY_ROTATED", from: "PENDING", to: "ACTIVE" },
      { eventType: "PRIOR_KEY_RETIRED", from: "ACTIVE", to: "RETIRED" },
      { eventType: "KEY_REVOKED", from: "ACTIVE", to: "REVOKED" },
    ]);
    expect(LIFECYCLE_EVENT_HASH_CHAIN).toEqual({
      eventsAppendOnly: true,
      eventBytesImmutable: true,
      predecessorHashRequiredAfterFirstEvent: true,
      predecessorHashMustEqualPriorEventHash: true,
    });
  });

  it("activates the first key from the canonical epoch-zero head", () => {
    const firstHead: LifecycleHead = {
      ...preBootstrapHead,
      epoch: 1n,
      currentKeyId: "key-current",
      authHold: false,
      lifecycleEventId: "event-1",
      updatedAtMs: 100,
    };
    const first = commitLifecycleHead({
      currentHead: preBootstrapHead,
      expectedEpoch: 0n,
      currentEventHash: null,
      keyStates: [{
        keyId: "key-current", nodeId: "node-a", implementerId: "impl-a", state: "PENDING",
      }],
      event: {
        id: "event-1",
        nodeId: "node-a",
        implementerId: "impl-a",
        epoch: 1n,
        eventType: "FIRST_KEY_ACTIVATED",
        subjectKeyId: "key-current",
        subjectSlot: "CURRENT",
        previousEventHash: null,
        eventHash: "a".repeat(64),
        committedAtMs: 100,
        projectedHead: firstHead,
      },
    });
    expect(first).toEqual({
      outcome: "COMMITTED",
      committedHead: firstHead,
      committedTransition: { keyId: "key-current", fromState: "PENDING", toState: "ACTIVE" },
    });
  });

  it("commits only an authoritative rotation whose cited head and hash predecessor match", () => {
    const first = commitLifecycleHead({
      currentHead,
      expectedEpoch: 1n,
      currentEventHash: "a".repeat(64),
      keyStates,
      event: rotationEvent,
    });
    expect(first).toEqual({
      outcome: "COMMITTED",
      committedHead: rotatedHead,
      committedTransition: { keyId: "key-new", fromState: "PENDING", toState: "ACTIVE" },
    });

    const second = commitLifecycleHead({
      currentHead: rotatedHead,
      expectedEpoch: 1n,
      currentEventHash: "b".repeat(64),
      keyStates: [
        { keyId: "key-current", nodeId: "node-a", implementerId: "impl-a", state: "ACTIVE" },
        { keyId: "key-new", nodeId: "node-a", implementerId: "impl-a", state: "ACTIVE" },
      ],
      event: rotationEvent,
    });
    expect(second.outcome).toBe("STALE_HEAD");
    expect(commitLifecycleHead({
      currentHead,
      expectedEpoch: 1n,
      currentEventHash: "a".repeat(64),
      keyStates,
      event: {
        ...rotationEvent,
        projectedHead: { ...rotatedHead, authHold: true },
      },
    }).outcome).toBe("HEAD_PROJECTION_MISMATCH");
    expect(commitLifecycleHead({
      currentHead,
      expectedEpoch: 1n,
      currentEventHash: "a".repeat(64),
      keyStates: keyStates.map((key) => key.keyId === "key-new"
        ? { ...key, implementerId: "impl-other" }
        : key),
      event: rotationEvent,
    }).outcome).toBe("KEY_STATE_MISMATCH");
    expect(commitLifecycleHead({
      currentHead,
      expectedEpoch: 1n,
      currentEventHash: "a".repeat(64),
      keyStates,
      event: { ...rotationEvent, previousEventHash: "wrong" },
    }).outcome).toBe("EVENT_HASH_CHAIN_MISMATCH");
  });

  it("rejects a second rotation while an active prior slot remains occupied", () => {
    const nextEvent: LifecycleEvent = {
      ...rotationEvent,
      id: "event-3",
      epoch: 3n,
      subjectKeyId: "key-next",
      previousEventHash: "b".repeat(64),
      eventHash: "c".repeat(64),
      committedAtMs: 2_000,
      projectedHead: {
        ...rotatedHead,
        epoch: 3n,
        currentKeyId: "key-next",
        priorKeyId: "key-new",
        overlapExpiresAtMs: 2_000 + REPORTING_KEY_OVERLAP_MS,
        lifecycleEventId: "event-3",
        updatedAtMs: 2_000,
      },
    };
    expect(commitLifecycleHead({
      currentHead: rotatedHead,
      expectedEpoch: 2n,
      currentEventHash: "b".repeat(64),
      keyStates: [
        { keyId: "key-current", nodeId: "node-a", implementerId: "impl-a", state: "ACTIVE" },
        { keyId: "key-new", nodeId: "node-a", implementerId: "impl-a", state: "ACTIVE" },
        { keyId: "key-next", nodeId: "node-a", implementerId: "impl-a", state: "PENDING" },
      ],
      event: nextEvent,
    }).outcome).toBe("PRIOR_SLOT_OCCUPIED");
  });

  it("revokes the sole current key into the permanently auth-held dead-end head", () => {
    expect(commitLifecycleHead({
      currentHead,
      expectedEpoch: 1n,
      currentEventHash: "a".repeat(64),
      keyStates: [keyStates[0]],
      event: revokeEvent,
    })).toEqual({
      outcome: "COMMITTED",
      committedHead: revokedHead,
      committedTransition: { keyId: "key-current", fromState: "ACTIVE", toState: "REVOKED" },
    });
  });

  it("rejects a subsequent auth-gated burn attempt once the dead-end head holds", () => {
    const commit = commitLifecycleHead({
      currentHead,
      expectedEpoch: 1n,
      currentEventHash: "a".repeat(64),
      keyStates: [keyStates[0]],
      event: revokeEvent,
    });
    expect(commit.outcome).toBe("COMMITTED");
    const deadEndHead = commit.committedHead as LifecycleHead;
    const lifecycleRecheckPasses = reportingAdmissionAllowed({
      nodeRestoreHold: false,
      lifecycleHeadAuthHold: deadEndHead.authHold,
    });
    expect(lifecycleRecheckPasses).toBe(false);
    expect(decideReportingBurn({
      allPreBurnChecksPass: true,
      lifecycleRecheckPasses,
      nonceAlreadyClaimed: false,
      downstreamResult: "SUCCESS",
    })).toEqual({
      outcome: "REJECT_LIFECYCLE_RECHECK",
      burnInserted: false,
      burnRetained: false,
    });
  });

  it("blocks re-bootstrapping the dead-end while a prior key slot is still occupied", () => {
    const collisionEvent: LifecycleEvent = {
      id: "event-revoke-2",
      nodeId: "node-a",
      implementerId: "impl-a",
      epoch: 3n,
      eventType: "KEY_REVOKED",
      subjectKeyId: "key-new",
      subjectSlot: "CURRENT",
      previousEventHash: "b".repeat(64),
      eventHash: "f".repeat(64),
      committedAtMs: 2_000,
      projectedHead: {
        ...rotatedHead,
        epoch: 3n,
        currentKeyId: null,
        authHold: true,
        lifecycleEventId: "event-revoke-2",
        updatedAtMs: 2_000,
      },
    };
    expect(commitLifecycleHead({
      currentHead: rotatedHead,
      expectedEpoch: 2n,
      currentEventHash: "b".repeat(64),
      keyStates: [
        { keyId: "key-current", nodeId: "node-a", implementerId: "impl-a", state: "ACTIVE" },
        { keyId: "key-new", nodeId: "node-a", implementerId: "impl-a", state: "ACTIVE" },
      ],
      event: collisionEvent,
    }).outcome).toBe("PRIOR_SLOT_OCCUPIED");
  });

  it("releases an authorization hold through its canonical event without a key transition", () => {
    const heldHead: LifecycleHead = {
      ...currentHead,
      epoch: 2n,
      authHold: true,
      lifecycleEventId: "event-hold",
      updatedAtMs: 500,
    };
    const releasedHead: LifecycleHead = {
      ...heldHead,
      epoch: 3n,
      authHold: false,
      lifecycleEventId: "event-release",
      updatedAtMs: 600,
    };
    expect(commitLifecycleHead({
      currentHead: heldHead,
      expectedEpoch: 2n,
      currentEventHash: "h".repeat(64),
      keyStates: [keyStates[0]],
      event: {
        id: "event-release",
        nodeId: "node-a",
        implementerId: "impl-a",
        epoch: 3n,
        eventType: "AUTH_HOLD_RELEASED",
        subjectKeyId: null,
        subjectSlot: null,
        previousEventHash: "h".repeat(64),
        eventHash: "r".repeat(64),
        committedAtMs: 600,
        projectedHead: releasedHead,
      },
    })).toEqual({
      outcome: "COMMITTED",
      committedHead: releasedHead,
      committedTransition: null,
    });
  });

  it("rejects terminal-key activation from authoritative state", () => {
    const terminalAdmission: LifecycleEvent = {
      ...rotationEvent,
      id: "event-1",
      epoch: 1n,
      eventType: "FIRST_KEY_ACTIVATED",
      subjectKeyId: "key-terminal",
      previousEventHash: null,
      committedAtMs: 500,
      projectedHead: {
        ...preBootstrapHead,
        epoch: 1n,
        currentKeyId: "key-terminal",
        authHold: false,
        lifecycleEventId: "event-1",
        updatedAtMs: 500,
      },
    };
    expect(commitLifecycleHead({
      currentHead: preBootstrapHead,
      expectedEpoch: 0n,
      currentEventHash: null,
      keyStates: [{
        keyId: "key-terminal", nodeId: "node-a", implementerId: "impl-a", state: "RETIRED",
      }],
      event: terminalAdmission,
    }).outcome).toBe("TERMINAL_KEY_REACTIVATION");
  });

  it("computes and verifies the exact strict half-open 24-hour overlap", () => {
    const expiry = successorCommit + REPORTING_KEY_OVERLAP_MS;
    const eligible = {
      isPriorSlot: true,
      keyState: "ACTIVE" as const,
      revokedAtMs: null,
      successorCommittedAtMs: successorCommit,
      storedOverlapExpiresAtMs: expiry,
      receivedAtMs: successorCommit,
    };
    expect(priorKeyEligible(eligible)).toBe(true);
    expect(priorKeyEligible({ ...eligible, receivedAtMs: successorCommit - 1 })).toBe(false);
    expect(priorKeyEligible({ ...eligible, receivedAtMs: expiry - 1 })).toBe(true);
    expect(priorKeyEligible({ ...eligible, receivedAtMs: expiry })).toBe(false);
    expect(priorKeyEligible({ ...eligible, keyState: "RETIRED" })).toBe(false);
    expect(priorKeyEligible({ ...eligible, keyState: "REVOKED", revokedAtMs: successorCommit })).toBe(false);
    expect(priorKeyEligible({ ...eligible, revokedAtMs: successorCommit })).toBe(false);
    expect(priorKeyEligible({ ...eligible, isPriorSlot: false })).toBe(false);
    expect(priorKeyEligible({
      ...eligible,
      storedOverlapExpiresAtMs: expiry + 1,
      receivedAtMs: expiry,
    })).toBe(false);
  });

  it("distinguishes three-gate first bootstrap from existing-key-anchored rotation", () => {
    expect(REGISTRATION_EVIDENCE_MODES).toEqual([
      "FIRST_KEY_BOOTSTRAP",
      "EXISTING_KEY_ANCHORED_ROTATION",
    ]);
    const base = {
      onboardingCredentialValid: true,
      implementerIdFromAuthenticatedCaller: true,
      nodeOriginOperatorApproval: true,
      existingKeyAnchorValid: false,
      proofOfPossessionValid: true,
    };
    expect(evaluateRegistrationEvidence({ ...base, mode: "FIRST_KEY_BOOTSTRAP" })).toBe(
      "ACCEPT_FIRST_KEY_BOOTSTRAP",
    );
    expect(evaluateRegistrationEvidence({
      ...base,
      mode: "FIRST_KEY_BOOTSTRAP",
      nodeOriginOperatorApproval: false,
    })).toBe("REJECT_BOOTSTRAP_EVIDENCE");
    expect(evaluateRegistrationEvidence({
      ...base,
      mode: "EXISTING_KEY_ANCHORED_ROTATION",
      existingKeyAnchorValid: true,
    })).toBe("ACCEPT_EXISTING_KEY_ROTATION");
    expect(evaluateRegistrationEvidence({
      ...base,
      mode: "EXISTING_KEY_ANCHORED_ROTATION",
    })).toBe("REJECT_ROTATION_ANCHOR");
  });

  it("cross-binds register nonce, new key, bootstrap evidence, and rotation authorization bytes", () => {
    expect(REGISTRATION_EVIDENCE_FIELDS).toEqual([
      "id", "node_id", "implementer_id", "new_reporting_key_id", "supersedes_key_id",
      "authorizing_key_id", "bootstrap_evidence_id", "nonce_evidence_id",
      "registration_purpose", "proof_of_possession_preimage_text",
      "proof_of_possession_preimage_sha256", "proof_of_possession_signature",
      "authorizing_preimage_text", "authorizing_preimage_sha256", "authorizing_signature",
      "issued_at", "expires_at", "created_at",
    ]);
    const bootstrap: RegistrationCrossBinding = {
      mode: "FIRST_KEY_BOOTSTRAP",
      nonce: {
        id: "nonce-row",
        purpose: "zp-reporting-register-v1",
        reportingKeyId: null,
        newReportingKeyId: "key-new",
        bootstrapEvidenceId: "bootstrap-evidence",
        requestPreimageText: "exact-register-preimage",
        requestPreimageSha256: "a".repeat(64),
        requestSignature: "proof-signature",
        issuedAt: "2026-07-19T00:00:00.000Z",
        expiresAt: "2026-07-19T00:05:00.000Z",
      },
      enrolment: {
        nonceEvidenceId: "nonce-row",
        registrationPurpose: "zp-reporting-register-v1",
        newReportingKeyId: "key-new",
        supersedesKeyId: null,
        authorizingKeyId: null,
        bootstrapEvidenceId: "bootstrap-evidence",
        proofOfPossessionPreimageText: "exact-register-preimage",
        proofOfPossessionPreimageSha256: "a".repeat(64),
        proofOfPossessionSignature: "proof-signature",
        authorizingPreimageText: null,
        authorizingPreimageSha256: null,
        authorizingSignature: null,
        issuedAt: "2026-07-19T00:00:00.000Z",
        expiresAt: "2026-07-19T00:05:00.000Z",
      },
      bootstrapEvidence: { id: "bootstrap-evidence", newReportingKeyId: "key-new" },
      rotationAuthorizer: null,
      proofOfPossessionVerified: true,
      authorizingSignatureVerified: false,
    };
    expect(evaluateRegistrationCrossBinding(bootstrap)).toBe("ACCEPT_BOOTSTRAP_CROSS_BINDING");
    for (const enrolmentChange of [
      { proofOfPossessionPreimageText: "changed-preimage" },
      { proofOfPossessionPreimageSha256: "b".repeat(64) },
      { proofOfPossessionSignature: "changed-signature" },
      { issuedAt: "2026-07-19T00:00:01.000Z" },
      { expiresAt: "2026-07-19T00:04:59.000Z" },
      { newReportingKeyId: "key-substituted" },
    ]) {
      expect(evaluateRegistrationCrossBinding({
        ...bootstrap,
        enrolment: { ...bootstrap.enrolment, ...enrolmentChange },
      })).toBe("REJECT_REGISTER_BINDING");
    }
    expect(evaluateRegistrationCrossBinding({
      ...bootstrap,
      bootstrapEvidence: { id: "other-evidence", newReportingKeyId: "key-new" },
    })).toBe("REJECT_BOOTSTRAP_CROSS_BINDING");
    expect(evaluateRegistrationCrossBinding({
      ...bootstrap,
      bootstrapEvidence: { id: "bootstrap-evidence", newReportingKeyId: "key-substituted" },
    })).toBe("REJECT_BOOTSTRAP_CROSS_BINDING");

    const rotation: RegistrationCrossBinding = {
      mode: "EXISTING_KEY_ANCHORED_ROTATION",
      nonce: {
        ...bootstrap.nonce,
        reportingKeyId: "key-current",
        bootstrapEvidenceId: null,
      },
      enrolment: {
        ...bootstrap.enrolment,
        supersedesKeyId: "key-current",
        authorizingKeyId: "key-current",
        bootstrapEvidenceId: null,
        authorizingPreimageText: "exact-authorizing-preimage",
        authorizingPreimageSha256: "b".repeat(64),
        authorizingSignature: "authorizing-signature",
      },
      bootstrapEvidence: null,
      rotationAuthorizer: {
        keyId: "key-current",
        preimageText: "exact-authorizing-preimage",
        preimageSha256: "b".repeat(64),
        signature: "authorizing-signature",
      },
      proofOfPossessionVerified: true,
      authorizingSignatureVerified: true,
    };
    expect(evaluateRegistrationCrossBinding(rotation)).toBe("ACCEPT_ROTATION_CROSS_BINDING");
    expect(evaluateRegistrationCrossBinding({
      ...rotation,
      rotationAuthorizer: { ...rotation.rotationAuthorizer!, keyId: "key-wrong" },
    })).toBe("REJECT_ROTATION_CROSS_BINDING");
    expect(evaluateRegistrationCrossBinding({
      ...rotation,
      rotationAuthorizer: { ...rotation.rotationAuthorizer!, preimageText: "changed" },
    })).toBe("REJECT_ROTATION_CROSS_BINDING");
    expect(evaluateRegistrationCrossBinding({
      ...rotation,
      rotationAuthorizer: { ...rotation.rotationAuthorizer!, signature: "changed" },
    })).toBe("REJECT_ROTATION_CROSS_BINDING");
    expect(evaluateRegistrationCrossBinding({
      ...rotation,
      authorizingSignatureVerified: false,
    })).toBe("REJECT_ROTATION_CROSS_BINDING");
  });
});

describe("mutation idempotency", () => {
  it("freezes separate key uniqueness and the logical signed fingerprint", () => {
    expect(MUTATION_IDEMPOTENCY_UNIQUENESS_FIELDS).toEqual([
      "node_id",
      "implementer_id",
      "route_id",
      "idempotency_key",
    ]);
    expect(LOGICAL_FINGERPRINT_FIELDS).toEqual(["method", "raw_target", "body_sha256"]);
    expect(LOGICAL_FINGERPRINT_EXCLUDED_FIELDS).toEqual([
      "nonce",
      "reporting_key_id",
      "lifecycle_epoch",
      "issued_at",
      "expires_at",
      "received_at",
      "idempotency_key",
    ]);
    expect(FINGERPRINT_GUARDED_ROUTE_IDS).toEqual([
      "operation_armed",
      "verification_complete",
    ]);
    expect(GUARDED_FINGERPRINT_UNIQUENESS_FIELDS).toEqual([
      "node_id", "implementer_id", "route_id", "method", "raw_target", "body_sha256",
    ]);
    expect(GUARDED_FINGERPRINT_PARTIAL_UNIQUENESS).toEqual({
      fields: GUARDED_FINGERPRINT_UNIQUENESS_FIELDS,
      whereRouteIdIn: FINGERPRINT_GUARDED_ROUTE_IDS,
    });
    expect(MUTATION_IDEMPOTENCY_FIELDS).toEqual([
      "id", "node_id", "implementer_id", "route_id", "idempotency_key",
      "reporting_nonce_id", "child_record_id", "method", "raw_target", "body_sha256",
      "logical_fingerprint", "response_status", "response_bytes", "completed_at", "created_at",
    ]);
    expect(MUTATION_IDEMPOTENCY_PERSISTENCE).toEqual({
      durablePendingRowsAllowed: false,
      requiredCompletionFields: ["response_status", "response_bytes", "completed_at"],
      mutationAndCompletedResultAtomic: true,
      completedParentRequiresMatchingChild: true,
    });
    expect(MUTATION_EVIDENCE_BINDING_FIELDS).toEqual([
      "reporting_nonce_id", "mutation_idempotency_id", "child_record_id", "method",
      "raw_target", "body_sha256", "logical_fingerprint",
    ]);
    expect(MUTATION_EVIDENCE_IMMUTABILITY).toEqual({
      nonceEvidenceAppendOnly: true,
      nonceEvidenceImmutable: true,
      idempotencyEvidenceAppendOnly: true,
      idempotencyEvidenceImmutable: true,
      responseEvidenceImmutable: true,
    });
  });

  it("replays across fresh nonce, key rotation, time, and changed unsigned header", () => {
    expect(sameLogicalFingerprint(FINGERPRINT, {
      ...FINGERPRINT,
      nonce: "nonce-b",
      reportingKeyId: "key-b",
      lifecycleEpoch: 2n,
      issuedAt: "2026-07-20T00:00:00.000Z",
      expiresAt: "2026-07-20T00:01:00.000Z",
      idempotencyKey: "idem-b",
    })).toBe(true);
  });

  it.each([
    { method: "GET" },
    { rawTarget: "/v1/operations/id/verification-complete?cursor=/" },
    { bodySha256: "b".repeat(64) },
  ])("conflicts when a signed fingerprint component changes", (change) => {
    expect(sameLogicalFingerprint(FINGERPRINT, { ...FINGERPRINT, ...change })).toBe(false);
  });

  it("enforces the guarded-route partial fingerprint claim despite a changed unsigned header", () => {
    const first = {
      nodeId: "node-a",
      implementerId: "impl-a",
      routeId: "operation_armed" as const,
      method: "POST",
      rawTarget: "/v1/operations/id/armed?cursor=%2F",
      bodySha256: "a".repeat(64),
      logicalFingerprint: "fingerprint-a",
      idempotencyKey: "visible-key-one!",
    };
    expect(guardedFingerprintAlreadyClaimed([], first)).toBe(false);
    expect(guardedFingerprintAlreadyClaimed([first], {
      ...first,
      idempotencyKey: "visible-key-two!",
      logicalFingerprint: "caller-controlled-different-value",
    })).toBe(true);
    expect(guardedFingerprintAlreadyClaimed([first], {
      ...first,
      bodySha256: "b".repeat(64),
      logicalFingerprint: "fingerprint-a",
    })).toBe(false);
    expect(guardedFingerprintAlreadyClaimed([first], {
      ...first,
      routeId: "verification_complete",
    })).toBe(false);
  });

  it("validates Idempotency-Key as 16-255 visible ASCII bytes", () => {
    expect(IDEMPOTENCY_KEY_CONTRACT).toEqual({
      minLength: 16,
      maxLength: 255,
      minCodePoint: 0x21,
      maxCodePoint: 0x7e,
    });
    expect(idempotencyKeyIsValid("!".repeat(16))).toBe(true);
    expect(idempotencyKeyIsValid("~".repeat(255))).toBe(true);
    expect(idempotencyKeyIsValid("!".repeat(15))).toBe(false);
    expect(idempotencyKeyIsValid("!".repeat(256))).toBe(false);
    expect(idempotencyKeyIsValid(`${"!".repeat(15)} `)).toBe(false);
    expect(idempotencyKeyIsValid(`${"!".repeat(15)}\n`)).toBe(false);
    expect(idempotencyKeyIsValid(`${"!".repeat(15)}é`)).toBe(false);
  });

  it("resolves completed idempotency before deleted-object lookup and conflicts there first", () => {
    const response = persistExactResponse(
      200,
      new Uint8Array([123, 125]),
      "2026-07-19T00:00:00.000Z",
      false,
    );
    if (response === null) throw new Error("fixture response did not persist");
    expect(decidePostBurn({
      completed: { fingerprint: FINGERPRINT, response },
      requestFingerprint: { ...FINGERPRINT, nonce: "fresh-nonce" },
      protectedObjectExists: false,
    })).toEqual({
      outcome: "REPLAY_EXACT_RESPONSE",
      protectedLookupPerformed: false,
      response,
    });
    expect(decidePostBurn({
      completed: { fingerprint: FINGERPRINT, response },
      requestFingerprint: { ...FINGERPRINT, bodySha256: "b".repeat(64) },
      protectedObjectExists: false,
    })).toEqual({
      outcome: "CONFLICTING_FINGERPRINT",
      protectedLookupPerformed: false,
      response: null,
    });
    expect(decidePostBurn({
      completed: null,
      requestFingerprint: FINGERPRINT,
      protectedObjectExists: false,
    }).outcome).toBe("PROTECTED_NOT_FOUND");
  });

  it("persists immutable status/bytes atomically and replays byte copies exactly", () => {
    const source = new Uint8Array([0, 255, 13, 10]);
    const completedAt = "2026-07-19T00:00:00.000Z";
    const persisted = persistExactResponse(200, source, completedAt, false);
    if (persisted === null) throw new Error("fixture response did not persist");
    expect(Object.isFrozen(persisted)).toBe(true);
    expect(Object.isFrozen(persisted.bytes)).toBe(true);
    source[0] = 99;
    expect(persisted).toEqual({ status: 200, bytes: [0, 255, 13, 10], completedAt });

    const replayOne = replayExactResponse(persisted);
    const replayTwo = replayExactResponse(persisted);
    expect([...replayOne]).toEqual([0, 255, 13, 10]);
    expect(replayOne).not.toBe(replayTwo);
    replayOne[1] = 1;
    expect([...replayExactResponse(persisted)]).toEqual([0, 255, 13, 10]);

    expect(persistExactResponse(200, source, completedAt, true)).toBeNull();
    expect(persistExactResponse(99, source, completedAt, false)).toBeNull();
    expect(persistExactResponse(200, source, "", false)).toBeNull();
  });

  it("rejects pending or orphan completed idempotency parents", () => {
    expect(decideMutationAtomicity({
      parentState: "COMPLETED",
      matchingChildExists: true,
    })).toBe("COMMIT_COMPLETED_PAIR");
    expect(decideMutationAtomicity({
      parentState: "PENDING",
      matchingChildExists: false,
    })).toBe("REJECT_DURABLE_PENDING");
    expect(decideMutationAtomicity({
      parentState: "COMPLETED",
      matchingChildExists: false,
    })).toBe("REJECT_ORPHAN_COMPLETED_PARENT");
    expect(decideMutationAtomicity({
      parentState: "NONE",
      matchingChildExists: true,
    })).toBe("REJECT_ORPHAN_CHILD");
  });

  it("requires nonce, idempotency, and child mutation evidence to bind identical request facts", () => {
    const binding: MutationBindingProjection = {
      reportingNonceId: "nonce-row",
      idempotencyId: "idempotency-row",
      childRecordId: "child-row",
      method: "POST",
      rawTarget: "/v1/operations/id/armed?cursor=%2F",
      bodySha256: "a".repeat(64),
      logicalFingerprint: "logical-fingerprint",
    };
    expect(mutationEvidenceBindingsMatch(binding, { ...binding }, { ...binding })).toBe(true);
    for (const change of [
      { reportingNonceId: "other-nonce" },
      { idempotencyId: "other-idempotency" },
      { childRecordId: "other-child" },
      { method: "GET" },
      { rawTarget: "/v1/operations/id/armed?cursor=/" },
      { bodySha256: "b".repeat(64) },
      { logicalFingerprint: "other-fingerprint" },
    ]) {
      expect(mutationEvidenceBindingsMatch(binding, { ...binding, ...change }, binding)).toBe(false);
    }
  });
});

describe("restore, retention, and custody", () => {
  it("hard-holds until external markers and trusted event-hash continuity are verified", () => {
    const markers = { lifecycleEpoch: 9n, nonceBurnHighWater: 41n };
    const restored = {
      markers,
      eventHash: "a".repeat(64),
      nextEventPreviousHash: "a".repeat(64),
    };
    const external = {
      markers,
      lifecycleEpochVerified: true,
      nonceBurnHighWaterVerified: true,
      trustedEventHash: "a".repeat(64),
    };
    expect(restoreRequiresAuthHold(restored, null)).toBe(true);
    expect(restoreRequiresAuthHold(restored, {
      ...external,
      lifecycleEpochVerified: false,
    })).toBe(true);
    expect(restoreRequiresAuthHold(restored, {
      ...external,
      nonceBurnHighWaterVerified: false,
    })).toBe(true);
    expect(restoreRequiresAuthHold({
      ...restored,
      markers: { ...markers, lifecycleEpoch: 8n },
    }, external)).toBe(true);
    expect(restoreRequiresAuthHold({
      ...restored,
      markers: { ...markers, nonceBurnHighWater: 40n },
    }, external)).toBe(true);
    expect(restoreRequiresAuthHold({
      ...restored,
      markers: { lifecycleEpoch: 10n, nonceBurnHighWater: 42n },
    }, external)).toBe(true);
    expect(restoreRequiresAuthHold({
      ...restored,
      eventHash: "b".repeat(64),
      nextEventPreviousHash: "b".repeat(64),
    }, external)).toBe(true);
    expect(restoreRequiresAuthHold({
      ...restored,
      nextEventPreviousHash: "b".repeat(64),
    }, external)).toBe(true);
    expect(restoreRequiresAuthHold({
      ...restored,
      eventHash: "",
      nextEventPreviousHash: "",
    }, { ...external, trustedEventHash: "" })).toBe(true);
    expect(restoreRequiresAuthHold(restored, external)).toBe(false);
    expect(RESTORE_POLICY.automaticHoldRelease).toBe(false);
    expect(RESTORE_POLICY.equalLocalMarkersReleaseHold).toBe(false);
    expect(RESTORE_POLICY.releaseRequires).toEqual([
      "external_lifecycle_epoch_verified_exact_equal",
      "external_nonce_burn_high_water_verified_exact_equal",
      "trusted_event_hash_equal",
      "next_event_previous_hash_continuous",
    ]);
  });

  it("admits reporting only when node restore hold and lifecycle-head auth hold are both clear", () => {
    expect(reportingAdmissionAllowed({
      nodeRestoreHold: false,
      lifecycleHeadAuthHold: false,
    })).toBe(true);
    expect(reportingAdmissionAllowed({
      nodeRestoreHold: true,
      lifecycleHeadAuthHold: false,
    })).toBe(false);
    expect(reportingAdmissionAllowed({
      nodeRestoreHold: false,
      lifecycleHeadAuthHold: true,
    })).toBe(false);
    expect(reportingAdmissionAllowed({
      nodeRestoreHold: true,
      lifecycleHeadAuthHold: true,
    })).toBe(false);
  });

  it("forbids read-burn pruning until a safety freeze and keeps mutation/lifecycle evidence", () => {
    expect(REPORTING_RETENTION).toEqual({
      readNonceBurn: "NO_PRUNE_UNTIL_SAFETY_SOURCE_AND_MARGIN_FROZEN",
      mutationNonceBurn: "PERMANENT",
      mutationIdempotency: "PERMANENT",
      lifecycleEvidence: "PERMANENT",
    });
  });

  it("enforces the exact public-key identity field set and corrected registered_at name", () => {
    expect(REPORTING_KEY_IDENTITY_ALLOWED_FIELDS).toEqual([
      "id",
      "node_id",
      "implementer_id",
      "public_key",
      "registered_at",
    ]);
    expect(reportingKeyIdentityIsPublicOnly(REPORTING_KEY_IDENTITY_ALLOWED_FIELDS)).toBe(true);
    for (const field of REPORTING_KEY_IDENTITY_FORBIDDEN_FIELDS) {
      expect(reportingKeyIdentityIsPublicOnly([
        ...REPORTING_KEY_IDENTITY_ALLOWED_FIELDS,
        field,
      ])).toBe(false);
    }
    expect(reportingKeyIdentityIsPublicOnly([
      ...REPORTING_KEY_IDENTITY_ALLOWED_FIELDS,
      "unknown_field",
    ])).toBe(false);
    expect(reportingKeyIdentityIsPublicOnly([
      ...REPORTING_KEY_IDENTITY_ALLOWED_FIELDS.slice(0, -1),
      "created_at",
    ])).toBe(false);
    expect(reportingKeyIdentityIsPublicOnly([
      "id", "node_id", "implementer_id", "public_key",
    ])).toBe(false);
  });
});
