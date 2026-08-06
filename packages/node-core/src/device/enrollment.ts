// Device enrollment coordinator — thin layer over the suite ceremony.
//
// Hard gates before any operator_device_keys insert:
// 1. Parse wire preimage only via parseDeviceEnrol (purpose\n prefix + rebuild).
// 2. Bind + single-consume a node-origin enrollment challenge.
// 3. Authorizer must be either:
// (a) an enrolled, non-revoked device for the same node, OR
// (b) an explicitly frozen, non-revoked break-glass authority
// when input.breakGlass === true.
// Bare login / TOTP-only is never an authorizer path.
// 4. verifyDeviceEnrol over the rebuilt preimage with the store-resolved key.
// 5. New-device proof-of-possession over the same preimage bytes.
// Audit records every attempt (ok + each rejection); never private keys.

import { Buffer } from "node:buffer";

import { verifyRawEd25519 } from "../protocol/ed25519-verify.js";
import { InvalidScalarError } from "../protocol/scalars.js";
import { InvalidFieldError } from "../protocol/suite/encoders.js";
import { assertPrimeOrderEd25519PublicKey, WeakEd25519KeyError } from "../protocol/suite/ed25519-point.js";
import { parseDeviceEnrol, SuiteParseError } from "../protocol/suite/parsers.js";
import { SuiteSerializeError } from "../protocol/suite/serialize.js";
import {
  SuiteVerifyError,
  verifyDeviceEnrol,
  type SignedSuiteTupleEnvelope,
} from "../protocol/suite/verify.js";

import type { EnrollmentAuditLog } from "./audit.js";
import type { BreakGlassAuthorityStore } from "./break-glass-store.js";
import {
  consumeEnrollmentChallenge,
  type EnrollmentChallengeStore,
} from "./challenge.js";
import type { DeviceKeyStore } from "./store.js";
import type {
  DeviceEnrolmentRejectionCode,
  DeviceEnrolmentResult,
  EnrolledDeviceKey,
  EnrollmentAuditEntry,
} from "./types.js";

export interface EnrolmentVerificationInput {
  /**
   * Exact A.1.1 wire preimage: `purpose + "\n" + JSON.stringify(payload)`.
   * Must be the only construction path — ad-hoc tuple JSON is rejected by parse.
   */
  readonly preimageText: string;
  /** Authorizing-device envelope (key_id + signature + declared digest). */
  readonly authorizingKeyId: string;
  readonly authorizingPublicKey: string;
  readonly authorizingSignature: string;
  readonly preimageSha256: string;
  /**
   * New-device proof-of-possession: Ed25519 signature (padded base64url) over the
   * same canonical preimage bytes, verified against `new_device_public_key`.
   */
  readonly newDevicePopSignature: string;
  readonly nowMs: number;
  /**
   * When true, authorizer is resolved from the frozen break-glass store
   * instead of operator_device_keys (A.4.3 alternative signer). Requires
   * `deps.breakGlassStore`. Bare session/TOTP alone still cannot enroll.
   */
  readonly breakGlass?: boolean;
}

export interface EnrolmentDeps {
  readonly deviceStore: DeviceKeyStore;
  readonly challengeStore: EnrollmentChallengeStore;
  readonly auditLog: EnrollmentAuditLog;
  /** Required when input.breakGlass is true; ignored on the normal path. */
  readonly breakGlassStore?: BreakGlassAuthorityStore;
}

function verifyPopSignature(
  preimageBytes: Uint8Array,
  signatureText: string,
  publicKeyText: string,
): boolean {
  try {
    return verifyRawEd25519({
      publicKeyBytes: Buffer.from(publicKeyText, "base64url"),
      preimageBytes,
      signatureBytes: Buffer.from(signatureText, "base64url"),
    });
  } catch {
    return false;
  }
}

function mapParseFailure(err: unknown): { code: DeviceEnrolmentRejectionCode; detail: string } {
  if (err instanceof SuiteParseError) {
    switch (err.reason) {
      case "purpose_mismatch":
        return { code: "PURPOSE_PREFIX_MISMATCH", detail: "A.1.1 purpose prefix missing or mismatched" };
      case "non_canonical_bytes":
        return { code: "NON_CANONICAL_PREIMAGE", detail: "preimage is not suite-canonical rebuild" };
      case "invalid_json":
        return { code: "INVALID_JSON", detail: "preimage payload is not valid JSON object" };
      case "invalid_utf8":
        return { code: "INVALID_UTF8", detail: "preimage is not well-formed UTF-8" };
      default:
        return { code: "INVALID_FIELD", detail: `suite parse rejected (${String(err.reason)})` };
    }
  }
  if (err instanceof SuiteSerializeError) {
    if (err.reason === "expiry_window_exceeded") {
      return { code: "WINDOW_TOO_LONG", detail: err.message };
    }
    if (err.reason === "expiry_not_after_issue") {
      return { code: "WINDOW_NON_POSITIVE", detail: err.message };
    }
    if (err.reason === "unknown_purpose") {
      return { code: "INVALID_PURPOSE", detail: err.message };
    }
    return { code: "INVALID_FIELD", detail: err.message };
  }
  if (err instanceof InvalidFieldError) {
    if (err.fieldKind === "Label") {
      return { code: "LABEL_DISALLOWED", detail: err.message };
    }
    if (err.fieldKind.includes("PublicKey") || err.fieldKind.includes("Pubkey")) {
      return { code: "INVALID_PUBLIC_KEY", detail: err.message };
    }
    return { code: "INVALID_FIELD", detail: err.message };
  }
  if (err instanceof InvalidScalarError) {
    return { code: "INVALID_FIELD", detail: err.message };
  }
  if (err instanceof WeakEd25519KeyError) {
    return { code: "INVALID_PUBLIC_KEY", detail: "new_device_public_key fails Ed25519 prime-subgroup check" };
  }
  if (err instanceof SuiteVerifyError) {
    if (err.reason === "signature_invalid") {
      return { code: "SIGNATURE_INVALID", detail: "authorizing device signature verification failed" };
    }
    if (err.reason === "digest_mismatch") {
      return { code: "DIGEST_MISMATCH", detail: "declared preimage_sha256 does not match rebuilt digest" };
    }
    if (err.reason === "key_id_mismatch") {
      return { code: "AUTHORIZER_KEY_ID_MISMATCH", detail: "envelope key_id does not match resolved authorizer" };
    }
    return { code: "SIGNATURE_INVALID", detail: err.message };
  }
  return { code: "INVALID_FIELD", detail: err instanceof Error ? err.message : "enrollment rejected" };
}

function reject(
  deps: EnrolmentDeps,
  input: EnrolmentVerificationInput,
  partial: {
    code: DeviceEnrolmentRejectionCode;
    detail: string;
    nodeId?: string | null;
    challengeId?: string | null;
    challengeNonce?: string | null;
    newDeviceKeyId?: string | null;
    newDevicePublicKey?: string | null;
  },
): DeviceEnrolmentResult {
  const entry: EnrollmentAuditEntry = {
    outcome: "REJECTED",
    code: partial.code,
    nodeId: partial.nodeId ?? null,
    challengeId: partial.challengeId ?? null,
    challengeNonce: partial.challengeNonce ?? null,
    authorizingKeyId: input.authorizingKeyId,
    authorizingPublicKey: input.authorizingPublicKey,
    newDeviceKeyId: partial.newDeviceKeyId ?? null,
    newDevicePublicKey: partial.newDevicePublicKey ?? null,
    detail: partial.detail,
    at: new Date(input.nowMs).toISOString(),
  };
  deps.auditLog.append(entry);
  return { ok: false, code: partial.code, detail: partial.detail };
}

/**
 * Verify the zp-device-enrol-v1 ceremony and append the new device key.
 * Fail-closed: bare login / unenrolled authorizer / missing PoP / unissued challenge
 * never write operator_device_keys.
 */
export function verifyAndEnrolDevice(
  deps: EnrolmentDeps,
  input: EnrolmentVerificationInput,
): DeviceEnrolmentResult {
  // 1. Suite-canonical parse (purpose prefix + field 1 + rebuild). Label/pubkey/window
  // validation happens inside serializeSuiteTuple via the frozen registry encoders.
  let parsed;
  try {
    parsed = parseDeviceEnrol(input.preimageText);
  } catch (err) {
    const mapped = mapParseFailure(err);
    return reject(deps, input, mapped);
  }

  const payload = parsed.payload;
  const nodeId = payload.node_id;
  const newDeviceKeyId = payload.new_device_key_id;
  const newDevicePublicKey = payload.new_device_public_key;

  // 2. Challenge bind + single-consume (node-origin nonce window).
  const consumed = consumeEnrollmentChallenge(deps.challengeStore, {
    nonce: payload.nonce,
    nodeId,
    issuedAt: payload.issued_at,
    expiresAt: payload.expires_at,
    nowMs: input.nowMs,
  });
  if (!consumed.ok) {
    return reject(deps, input, {
      code: consumed.code,
      detail: consumed.detail,
      nodeId,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  // Ceremony wall-clock: even if challenge is live, reject past expires_at.
  if (input.nowMs > Date.parse(payload.expires_at)) {
    return reject(deps, input, {
      code: "ENROLMENT_EXPIRED",
      detail: "enrolment ceremony has expired",
      nodeId,
      challengeId: consumed.challenge.id,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  // 3. Authorizer resolution — enrolled device OR frozen break-glass (A.4.3).
  // Active lookup is the mutation-sensitive gate (review D1).
  let authorizerKeyId: string;
  let authorizerPublicKey: string;
  let authorizerVia: "device" | "break_glass";

  if (input.breakGlass === true) {
    const bgStore = deps.breakGlassStore;
    if (bgStore === undefined) {
      return reject(deps, input, {
        code: "BREAK_GLASS_AUTHORITY_UNKNOWN",
        detail: "break-glass enrollment requires a configured break-glass authority store",
        nodeId,
        challengeId: consumed.challenge.id,
        challengeNonce: payload.nonce,
        newDeviceKeyId,
        newDevicePublicKey,
      });
    }
    const activeBg = bgStore.findActiveByNodeAndPublicKey(nodeId, input.authorizingPublicKey);
    if (activeBg === null) {
      const anyBg = bgStore.findByNodeAndPublicKey(nodeId, input.authorizingPublicKey);
      if (anyBg !== null && anyBg.revokedAt !== null) {
        return reject(deps, input, {
          code: "BREAK_GLASS_AUTHORITY_REVOKED",
          detail: "break-glass authority has been revoked",
          nodeId,
          challengeId: consumed.challenge.id,
          challengeNonce: payload.nonce,
          newDeviceKeyId,
          newDevicePublicKey,
        });
      }
      return reject(deps, input, {
        code: "BREAK_GLASS_AUTHORITY_UNKNOWN",
        detail: "authorizing public key is not a frozen break-glass authority for this node",
        nodeId,
        challengeId: consumed.challenge.id,
        challengeNonce: payload.nonce,
        newDeviceKeyId,
        newDevicePublicKey,
      });
    }
    if (activeBg.id !== input.authorizingKeyId) {
      return reject(deps, input, {
        code: "BREAK_GLASS_KEY_ID_MISMATCH",
        detail: "authorizing key_id does not match frozen break-glass authority row",
        nodeId,
        challengeId: consumed.challenge.id,
        challengeNonce: payload.nonce,
        newDeviceKeyId,
        newDevicePublicKey,
      });
    }
    authorizerKeyId = activeBg.id;
    authorizerPublicKey = activeBg.publicKey;
    authorizerVia = "break_glass";
  } else {
    const activeAuthorizer = deps.deviceStore.findActiveByNodeAndPublicKey(
      nodeId,
      input.authorizingPublicKey,
    );
    if (activeAuthorizer === null) {
      const anyRow = deps.deviceStore.findByNodeAndPublicKey(nodeId, input.authorizingPublicKey);
      if (anyRow !== null && anyRow.revokedAt !== null) {
        return reject(deps, input, {
          code: "AUTHORIZER_REVOKED",
          detail: "authorizing device key has been revoked",
          nodeId,
          challengeId: consumed.challenge.id,
          challengeNonce: payload.nonce,
          newDeviceKeyId,
          newDevicePublicKey,
        });
      }
      return reject(deps, input, {
        code: "AUTHORIZER_UNKNOWN",
        detail: "authorizing public key is not enrolled for this node",
        nodeId,
        challengeId: consumed.challenge.id,
        challengeNonce: payload.nonce,
        newDeviceKeyId,
        newDevicePublicKey,
      });
    }
    if (activeAuthorizer.id !== input.authorizingKeyId) {
      return reject(deps, input, {
        code: "AUTHORIZER_KEY_ID_MISMATCH",
        detail: "authorizing key_id does not match enrolled device row",
        nodeId,
        challengeId: consumed.challenge.id,
        challengeNonce: payload.nonce,
        newDeviceKeyId,
        newDevicePublicKey,
      });
    }
    authorizerKeyId = activeAuthorizer.id;
    authorizerPublicKey = activeAuthorizer.publicKey;
    authorizerVia = "device";
  }

  // 4. Suite verifier: device key class + rebuilt preimage + signature.
  // Break-glass signs the same zp-device-enrol-v1 tuple under the device key class
  // (registry / A.4.3: "existing trusted device or break-glass ceremony").
  const envelope: SignedSuiteTupleEnvelope = {
    key_id: input.authorizingKeyId as SignedSuiteTupleEnvelope["key_id"],
    preimage_text: input.preimageText,
    preimage_sha256: input.preimageSha256,
    signature: input.authorizingSignature as SignedSuiteTupleEnvelope["signature"],
  };
  try {
    verifyDeviceEnrol(envelope, {
      keyId: authorizerKeyId as SignedSuiteTupleEnvelope["key_id"],
      keyClass: "device",
      publicKey: authorizerPublicKey as never,
    });
  } catch (err) {
    const mapped = mapParseFailure(err);
    return reject(deps, input, {
      ...mapped,
      nodeId,
      challengeId: consumed.challenge.id,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  // 5. New-device proof-of-possession before insert.
  try {
    assertPrimeOrderEd25519PublicKey(newDevicePublicKey as never);
  } catch (err) {
    const mapped = mapParseFailure(err);
    return reject(deps, input, {
      ...mapped,
      nodeId,
      challengeId: consumed.challenge.id,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }
  const popOk = verifyPopSignature(
    parsed.preimageBytes,
    input.newDevicePopSignature,
    newDevicePublicKey,
  );
  if (!popOk) {
    return reject(deps, input, {
      code: "POP_INVALID",
      detail: "new-device proof-of-possession signature failed",
      nodeId,
      challengeId: consumed.challenge.id,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  // 6. Duplicate public key on node.
  const existing = deps.deviceStore.findByNodeAndPublicKey(nodeId, newDevicePublicKey);
  if (existing !== null) {
    return reject(deps, input, {
      code: "DUPLICATE_KEY",
      detail: "device key already enrolled for this node",
      nodeId,
      challengeId: consumed.challenge.id,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  const deviceKey: EnrolledDeviceKey = {
    id: newDeviceKeyId,
    nodeId,
    publicKey: newDevicePublicKey,
    label: payload.label,
    enrolledAt: payload.issued_at,
    revokedAt: null,
  };
  deps.deviceStore.insert(deviceKey);

  deps.auditLog.append({
    outcome: "ENROLLED",
    code: "OK",
    nodeId,
    challengeId: consumed.challenge.id,
    challengeNonce: payload.nonce,
    authorizingKeyId: input.authorizingKeyId,
    authorizingPublicKey: input.authorizingPublicKey,
    newDeviceKeyId,
    newDevicePublicKey,
    detail:
      authorizerVia === "break_glass"
        ? "device enrolled via frozen break-glass authority"
        : "device enrolled",
    at: new Date(input.nowMs).toISOString(),
  });

  return { ok: true, deviceKey };
}


/**
 * First-device (genesis) enrolment when operator_device_keys is empty for the node.
 *
 * A.4.3 requires an enrolled device or frozen break-glass as authorizer for
 * subsequent enrolments. The empty-registry case is the sole SPA-reachable
 * genesis path: the new device self-signs (authorizer == new device) under a
 * node-origin enrollment challenge + PoP, gated by operator session+TOTP at
 * the HTTP layer. Once any active device exists, this path fails closed and
 * callers must use verifyAndEnrolDevice with an enrolled authorizer.
 */
export interface GenesisEnrolmentInput {
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly newDevicePopSignature: string;
  readonly nowMs: number;
}

export function verifyAndEnrolGenesisDevice(
  deps: EnrolmentDeps,
  input: GenesisEnrolmentInput,
): DeviceEnrolmentResult {
  let parsed;
  try {
    parsed = parseDeviceEnrol(input.preimageText);
  } catch (err) {
    const mapped = mapParseFailure(err);
    return reject(deps, {
      preimageText: input.preimageText,
      authorizingKeyId: "",
      authorizingPublicKey: "",
      authorizingSignature: "",
      preimageSha256: input.preimageSha256,
      newDevicePopSignature: input.newDevicePopSignature,
      nowMs: input.nowMs,
    }, mapped);
  }

  const payload = parsed.payload;
  const nodeId = payload.node_id;
  const newDeviceKeyId = payload.new_device_key_id;
  const newDevicePublicKey = payload.new_device_public_key;

  // Hard gate: only when the node has zero active devices.
  if (deps.deviceStore.listActiveByNode(nodeId).length > 0) {
    return reject(deps, {
      preimageText: input.preimageText,
      authorizingKeyId: newDeviceKeyId,
      authorizingPublicKey: newDevicePublicKey,
      authorizingSignature: input.newDevicePopSignature,
      preimageSha256: input.preimageSha256,
      newDevicePopSignature: input.newDevicePopSignature,
      nowMs: input.nowMs,
    }, {
      code: "AUTHORIZER_UNKNOWN",
      detail: "genesis enrol only permitted when no active devices are enrolled",
      nodeId,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  const consumed = consumeEnrollmentChallenge(deps.challengeStore, {
    nonce: payload.nonce,
    nodeId,
    issuedAt: payload.issued_at,
    expiresAt: payload.expires_at,
    nowMs: input.nowMs,
  });
  if (!consumed.ok) {
    return reject(deps, {
      preimageText: input.preimageText,
      authorizingKeyId: newDeviceKeyId,
      authorizingPublicKey: newDevicePublicKey,
      authorizingSignature: input.newDevicePopSignature,
      preimageSha256: input.preimageSha256,
      newDevicePopSignature: input.newDevicePopSignature,
      nowMs: input.nowMs,
    }, {
      code: consumed.code,
      detail: consumed.detail,
      nodeId,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  if (input.nowMs > Date.parse(payload.expires_at)) {
    return reject(deps, {
      preimageText: input.preimageText,
      authorizingKeyId: newDeviceKeyId,
      authorizingPublicKey: newDevicePublicKey,
      authorizingSignature: input.newDevicePopSignature,
      preimageSha256: input.preimageSha256,
      newDevicePopSignature: input.newDevicePopSignature,
      nowMs: input.nowMs,
    }, {
      code: "ENROLMENT_EXPIRED",
      detail: "enrolment ceremony has expired",
      nodeId,
      challengeId: consumed.challenge.id,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  // Self-authorize: suite verifier under the new device public key + PoP.
  const envelope: SignedSuiteTupleEnvelope = {
    key_id: newDeviceKeyId as SignedSuiteTupleEnvelope["key_id"],
    preimage_text: input.preimageText,
    preimage_sha256: input.preimageSha256,
    signature: input.newDevicePopSignature as SignedSuiteTupleEnvelope["signature"],
  };
  try {
    verifyDeviceEnrol(envelope, {
      keyId: newDeviceKeyId as SignedSuiteTupleEnvelope["key_id"],
      keyClass: "device",
      publicKey: newDevicePublicKey as never,
    });
  } catch (err) {
    const mapped = mapParseFailure(err);
    return reject(deps, {
      preimageText: input.preimageText,
      authorizingKeyId: newDeviceKeyId,
      authorizingPublicKey: newDevicePublicKey,
      authorizingSignature: input.newDevicePopSignature,
      preimageSha256: input.preimageSha256,
      newDevicePopSignature: input.newDevicePopSignature,
      nowMs: input.nowMs,
    }, {
      ...mapped,
      nodeId,
      challengeId: consumed.challenge.id,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  try {
    assertPrimeOrderEd25519PublicKey(newDevicePublicKey as never);
  } catch (err) {
    const mapped = mapParseFailure(err);
    return reject(deps, {
      preimageText: input.preimageText,
      authorizingKeyId: newDeviceKeyId,
      authorizingPublicKey: newDevicePublicKey,
      authorizingSignature: input.newDevicePopSignature,
      preimageSha256: input.preimageSha256,
      newDevicePopSignature: input.newDevicePopSignature,
      nowMs: input.nowMs,
    }, {
      ...mapped,
      nodeId,
      challengeId: consumed.challenge.id,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  const popOk = verifyPopSignature(
    parsed.preimageBytes,
    input.newDevicePopSignature,
    newDevicePublicKey,
  );
  if (!popOk) {
    return reject(deps, {
      preimageText: input.preimageText,
      authorizingKeyId: newDeviceKeyId,
      authorizingPublicKey: newDevicePublicKey,
      authorizingSignature: input.newDevicePopSignature,
      preimageSha256: input.preimageSha256,
      newDevicePopSignature: input.newDevicePopSignature,
      nowMs: input.nowMs,
    }, {
      code: "POP_INVALID",
      detail: "new-device proof-of-possession signature failed",
      nodeId,
      challengeId: consumed.challenge.id,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  const existing = deps.deviceStore.findByNodeAndPublicKey(nodeId, newDevicePublicKey);
  if (existing !== null) {
    return reject(deps, {
      preimageText: input.preimageText,
      authorizingKeyId: newDeviceKeyId,
      authorizingPublicKey: newDevicePublicKey,
      authorizingSignature: input.newDevicePopSignature,
      preimageSha256: input.preimageSha256,
      newDevicePopSignature: input.newDevicePopSignature,
      nowMs: input.nowMs,
    }, {
      code: "DUPLICATE_KEY",
      detail: "device key already enrolled for this node",
      nodeId,
      challengeId: consumed.challenge.id,
      challengeNonce: payload.nonce,
      newDeviceKeyId,
      newDevicePublicKey,
    });
  }

  const deviceKey: EnrolledDeviceKey = {
    id: newDeviceKeyId,
    nodeId,
    publicKey: newDevicePublicKey,
    label: payload.label,
    enrolledAt: payload.issued_at,
    revokedAt: null,
  };
  deps.deviceStore.insert(deviceKey);

  deps.auditLog.append({
    outcome: "ENROLLED",
    code: "OK",
    nodeId,
    challengeId: consumed.challenge.id,
    challengeNonce: payload.nonce,
    authorizingKeyId: newDeviceKeyId,
    authorizingPublicKey: newDevicePublicKey,
    newDeviceKeyId,
    newDevicePublicKey,
    detail: "first device enrolled via genesis self-authorize path",
    at: new Date(input.nowMs).toISOString(),
  });

  return { ok: true, deviceKey };
}
