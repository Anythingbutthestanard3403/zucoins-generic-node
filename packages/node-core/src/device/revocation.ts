// Device revocation — non-deleting, immediate, with nonce/session invalidation.
//
// Hard rules:
// 1. SET revoked_at = now; never DELETE the operator_device_keys row.
// 2. Historic enrollment/blessing signatures remain valid as historic proof.
// 3. Outstanding enrollment challenges for the node are invalidated so a
// stale in-flight ceremony cannot complete with a since-revoked authorizer.
// 4. Approval-challenge + session invalidation go through side-effect ports
// (device-key analog of session revocation).
// 5. Wallet / destination custody classification is unreachable — this module
// never imports wallet or destination code.

import type { EnrollmentChallengeStore } from "./challenge.js";
import { invalidateIssuedEnrollmentChallenges } from "./challenge.js";
import type { DeviceKeyStore } from "./store.js";
import type { BreakGlassAuthorityStore } from "./break-glass-store.js";
import type {
  DeviceRevocationAuditEntry,
  DeviceRevocationResult,
  EnrolledDeviceKey,
} from "./types.js";

export interface DeviceRevocationAuditLog {
  append(entry: DeviceRevocationAuditEntry): void;
}

export class InMemoryDeviceRevocationAuditLog implements DeviceRevocationAuditLog {
  readonly entries: DeviceRevocationAuditEntry[] = [];

  append(entry: DeviceRevocationAuditEntry): void {
    this.entries.push(entry);
  }
}

/**
 * Side effects outside the device registry. Implemented by the node shell.
 * Approval-challenge nonces the revoked device was party to (approving-side)
 * and operator sessions bound to the device must not remain completable.
 */
export interface DeviceRevocationSideEffects {
  /** Invalidate approval challenges where this device is the approving-side party. */
  invalidateApprovalChallengesForDevice(args: {
    readonly nodeId: string;
    readonly deviceKeyId: string;
    readonly revokedAt: string;
  }): void;
  /** Revoke operator sessions associated with the device or its operator context. */
  invalidateSessionsForDevice(args: {
    readonly nodeId: string;
    readonly deviceKeyId: string;
    readonly revokedAt: string;
  }): void;
}

export class NoopDeviceRevocationSideEffects implements DeviceRevocationSideEffects {
  invalidateApprovalChallengesForDevice(): void {
    /* intentionally empty — shell wires the real ports */
  }
  invalidateSessionsForDevice(): void {
    /* intentionally empty */
  }
}

export interface RevokeDeviceInput {
  readonly nodeId: string;
  readonly targetDeviceKeyId: string;
  readonly nowMs: number;
  /**
   * Active enrolled device authorizing the revocation (normal path).
   * Must be non-revoked and on the same node. May equal the target (self-revoke).
   */
  readonly authorizingDeviceKeyId?: string;
  readonly authorizingDevicePublicKey?: string;
  /**
   * When true, authorize via a frozen active break-glass authority instead
   * of an enrolled device (lost-all-devices / sole-compromised-device recovery).
   */
  readonly breakGlass?: boolean;
  readonly breakGlassKeyId?: string;
  readonly breakGlassPublicKey?: string;
}

export interface RevokeDeviceDeps {
  readonly deviceStore: DeviceKeyStore;
  readonly challengeStore: EnrollmentChallengeStore;
  readonly breakGlassStore: BreakGlassAuthorityStore;
  readonly auditLog: DeviceRevocationAuditLog;
  readonly sideEffects: DeviceRevocationSideEffects;
}

/**
 * Revoke an enrolled device key. Non-deleting, immediate, audited.
 * Invalidates outstanding enrollment challenges for the node and invokes
 * side-effect ports for approval challenges and sessions.
 */
export function revokeDevice(deps: RevokeDeviceDeps, input: RevokeDeviceInput): DeviceRevocationResult {
  const revokedAt = new Date(input.nowMs).toISOString();

  const target = deps.deviceStore.findById(input.targetDeviceKeyId);
  if (target === null || target.nodeId !== input.nodeId) {
    const detail = "target device key is not enrolled for this node";
    deps.auditLog.append({
      outcome: "REJECTED",
      code: "TARGET_UNKNOWN",
      nodeId: input.nodeId,
      targetDeviceKeyId: input.targetDeviceKeyId,
      authorizingKeyId: input.authorizingDeviceKeyId ?? input.breakGlassKeyId ?? null,
      invalidatedEnrollmentChallenges: 0,
      detail,
      at: revokedAt,
    });
    return { ok: false, code: "TARGET_UNKNOWN", detail };
  }

  // Authorize: enrolled device OR frozen break-glass.
  let authorizingKeyId: string;
  if (input.breakGlass === true) {
    const bgPub = input.breakGlassPublicKey;
    const bgId = input.breakGlassKeyId;
    if (bgPub === undefined || bgId === undefined) {
      const detail = "break-glass revocation requires key id and public key";
      deps.auditLog.append({
        outcome: "REJECTED",
        code: "AUTHORIZER_UNKNOWN",
        nodeId: input.nodeId,
        targetDeviceKeyId: input.targetDeviceKeyId,
        authorizingKeyId: bgId ?? null,
        invalidatedEnrollmentChallenges: 0,
        detail,
        at: revokedAt,
      });
      return { ok: false, code: "AUTHORIZER_UNKNOWN", detail };
    }
    const authority = deps.breakGlassStore.findActiveByNodeAndPublicKey(input.nodeId, bgPub);
    if (authority === null) {
      const any = deps.breakGlassStore.findByNodeAndPublicKey(input.nodeId, bgPub);
      const code =
        any !== null && any.revokedAt !== null ? "AUTHORIZER_REVOKED" : "AUTHORIZER_UNKNOWN";
      const detail =
        code === "AUTHORIZER_REVOKED"
          ? "break-glass authority has been revoked"
          : "no active frozen break-glass authority for this public key";
      deps.auditLog.append({
        outcome: "REJECTED",
        code,
        nodeId: input.nodeId,
        targetDeviceKeyId: input.targetDeviceKeyId,
        authorizingKeyId: bgId,
        invalidatedEnrollmentChallenges: 0,
        detail,
        at: revokedAt,
      });
      return { ok: false, code, detail };
    }
    if (authority.id !== bgId) {
      const detail = "break-glass key id does not match store row";
      deps.auditLog.append({
        outcome: "REJECTED",
        code: "AUTHORIZER_KEY_ID_MISMATCH",
        nodeId: input.nodeId,
        targetDeviceKeyId: input.targetDeviceKeyId,
        authorizingKeyId: bgId,
        invalidatedEnrollmentChallenges: 0,
        detail,
        at: revokedAt,
      });
      return { ok: false, code: "AUTHORIZER_KEY_ID_MISMATCH", detail };
    }
    authorizingKeyId = authority.id;
  } else {
    const authId = input.authorizingDeviceKeyId;
    const authPub = input.authorizingDevicePublicKey;
    if (authId === undefined || authPub === undefined) {
      const detail = "revocation requires an enrolled authorizer or break-glass";
      deps.auditLog.append({
        outcome: "REJECTED",
        code: "AUTHORIZER_UNKNOWN",
        nodeId: input.nodeId,
        targetDeviceKeyId: input.targetDeviceKeyId,
        authorizingKeyId: null,
        invalidatedEnrollmentChallenges: 0,
        detail,
        at: revokedAt,
      });
      return { ok: false, code: "AUTHORIZER_UNKNOWN", detail };
    }
    const active = deps.deviceStore.findActiveByNodeAndPublicKey(input.nodeId, authPub);
    if (active === null) {
      const any = deps.deviceStore.findByNodeAndPublicKey(input.nodeId, authPub);
      const code = any !== null && any.revokedAt !== null ? "AUTHORIZER_REVOKED" : "AUTHORIZER_UNKNOWN";
      const detail =
        code === "AUTHORIZER_REVOKED"
          ? "authorizing device key has been revoked"
          : "authorizing public key is not enrolled for this node";
      deps.auditLog.append({
        outcome: "REJECTED",
        code,
        nodeId: input.nodeId,
        targetDeviceKeyId: input.targetDeviceKeyId,
        authorizingKeyId: authId,
        invalidatedEnrollmentChallenges: 0,
        detail,
        at: revokedAt,
      });
      return { ok: false, code, detail };
    }
    if (active.id !== authId) {
      const detail = "authorizing key_id does not match enrolled device row";
      deps.auditLog.append({
        outcome: "REJECTED",
        code: "AUTHORIZER_KEY_ID_MISMATCH",
        nodeId: input.nodeId,
        targetDeviceKeyId: input.targetDeviceKeyId,
        authorizingKeyId: authId,
        invalidatedEnrollmentChallenges: 0,
        detail,
        at: revokedAt,
      });
      return { ok: false, code: "AUTHORIZER_KEY_ID_MISMATCH", detail };
    }
    authorizingKeyId = active.id;
  }

  // Idempotent revoke: already-revoked target is success without re-invalidating.
  if (target.revokedAt !== null) {
    deps.auditLog.append({
      outcome: "REVOKED",
      code: "OK",
      nodeId: input.nodeId,
      targetDeviceKeyId: input.targetDeviceKeyId,
      authorizingKeyId,
      invalidatedEnrollmentChallenges: 0,
      detail: "device already revoked (idempotent)",
      at: revokedAt,
    });
    return { ok: true, deviceKey: target, invalidatedEnrollmentChallenges: 0, alreadyRevoked: true };
  }

  deps.deviceStore.revoke(target.id, revokedAt);

  // Re-read after revoke (store returns updated row).
  const revoked = deps.deviceStore.findById(target.id);
  if (revoked === null || revoked.revokedAt === null) {
    // Store seam failed closed — treat as hard error for the caller.
    const detail = "device store failed to set revoked_at";
    deps.auditLog.append({
      outcome: "REJECTED",
      code: "STORE_FAILURE",
      nodeId: input.nodeId,
      targetDeviceKeyId: input.targetDeviceKeyId,
      authorizingKeyId,
      invalidatedEnrollmentChallenges: 0,
      detail,
      at: revokedAt,
    });
    return { ok: false, code: "STORE_FAILURE", detail };
  }

  // Invalidate outstanding enrollment challenges so a since-revoked device
  // cannot complete an in-flight enrolment ceremony as authorizer.
  const invalidatedEnrollmentChallenges = invalidateIssuedEnrollmentChallenges(
    deps.challengeStore,
    input.nodeId,
  );

  deps.sideEffects.invalidateApprovalChallengesForDevice({
    nodeId: input.nodeId,
    deviceKeyId: target.id,
    revokedAt,
  });
  deps.sideEffects.invalidateSessionsForDevice({
    nodeId: input.nodeId,
    deviceKeyId: target.id,
    revokedAt,
  });

  deps.auditLog.append({
    outcome: "REVOKED",
    code: "OK",
    nodeId: input.nodeId,
    targetDeviceKeyId: input.targetDeviceKeyId,
    authorizingKeyId,
    invalidatedEnrollmentChallenges,
    detail: "device revoked; enrollment challenges and side-effect nonces/sessions invalidated",
    at: revokedAt,
  });

  return {
    ok: true,
    deviceKey: revoked,
    invalidatedEnrollmentChallenges,
    alreadyRevoked: false,
  };
}

/** Pure helper for tests/reviewers: prove a device row was not deleted. */
export function deviceRowStillPresent(
  store: DeviceKeyStore,
  id: string,
): EnrolledDeviceKey | null {
  return store.findById(id);
}
