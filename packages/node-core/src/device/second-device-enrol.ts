// Second-device enrolment ceremony over the `zp-device-enrol-v1` preimage, with a 300s
// ceiling on the enrolment window.
//
// QR / deep-link payload is ONLY { challenge_id, node_origin } — never private keys,
// never authorizing signatures, never TOTP. Node-origin PWA only.
//
// Flow:
// 1. Enrolled device A issues a node-origin enrollment challenge (+ ceremony row).
// 2. A shows QR with challenge_id + node_origin.
// 3. Device B opens node origin, generates WebCrypto keypair, binds pubkey+label+PoP intent.
// 4. A reviews bound pubkey, signs zp-device-enrol-v1, posts authorization (+ TOTP at HTTP).
// 5. B signs PoP over the same preimage; complete runs verifyAndEnrolDevice.
// Expired / replayed challenges fail closed. Audit via EnrollmentAuditLog.

import { createHash, randomUUID } from "node:crypto";

import { buildDeviceEnrol } from "../protocol/suite/builders.js";
import { parseUuid, parseWalletPublicKey } from "../protocol/scalars.js";

import {
  issueEnrollmentChallenge,
  type EnrollmentChallengeStore,
} from "./challenge.js";
import {
  verifyAndEnrolDevice,
  type EnrolmentDeps,
} from "./enrollment.js";
import type { EnrolledDeviceKey } from "./types.js";

export const SECOND_DEVICE_QR_KEYS = ["challenge_id", "node_origin"] as const;

/** Forbidden keys in any QR / deep-link JSON (AC: no private key material). */
export const SECOND_DEVICE_QR_FORBIDDEN_KEYS = [
  "private_key",
  "privateKey",
  "secret",
  "seed",
  "authorizing_signature",
  "device_signature",
  "totp",
  "totp_code",
  "master_key",
  "preimage_text",
] as const;

export type SecondDeviceCeremonyStatus =
  | "ISSUED"
  | "BOUND"
  | "AUTHORIZED"
  | "ENROLLED"
  | "EXPIRED"
  | "SUPERSEDED";

export interface SecondDeviceCeremony {
  readonly challengeId: string;
  readonly nodeId: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly status: SecondDeviceCeremonyStatus;
  readonly issuedByOperatorId: string | null;
  readonly newDevicePublicKey: string | null;
  readonly label: string | null;
  readonly newDeviceKeyId: string | null;
  readonly authorizingKeyId: string | null;
  readonly authorizingPublicKey: string | null;
  readonly authorizingSignature: string | null;
  readonly preimageText: string | null;
  readonly preimageSha256: string | null;
  readonly newDevicePopSignature: string | null;
  readonly enrolledDeviceId: string | null;
}

export interface SecondDeviceCeremonyStore {
  findByChallengeId(challengeId: string): SecondDeviceCeremony | null;
  insert(row: SecondDeviceCeremony): void;
  update(row: SecondDeviceCeremony): void;
}

export class InMemorySecondDeviceCeremonyStore implements SecondDeviceCeremonyStore {
  private readonly byId = new Map<string, SecondDeviceCeremony>();

  findByChallengeId(challengeId: string): SecondDeviceCeremony | null {
    return this.byId.get(challengeId) ?? null;
  }

  insert(row: SecondDeviceCeremony): void {
    if (this.byId.has(row.challengeId)) {
      throw new Error(`duplicate second-device ceremony: ${row.challengeId}`);
    }
    this.byId.set(row.challengeId, row);
  }

  update(row: SecondDeviceCeremony): void {
    if (!this.byId.has(row.challengeId)) {
      throw new Error(`unknown second-device ceremony: ${row.challengeId}`);
    }
    this.byId.set(row.challengeId, row);
  }
}

export interface SecondDeviceQrPayload {
  readonly challenge_id: string;
  readonly node_origin: string;
}

export function buildSecondDeviceQrPayload(
  challengeId: string,
  nodeOrigin: string,
): SecondDeviceQrPayload {
  const origin = nodeOrigin.replace(/\/+$/u, "");
  return { challenge_id: challengeId, node_origin: origin };
}

/** Schema guard: QR JSON may only carry challenge_id + node_origin. */
export function assertSafeSecondDeviceQr(payload: unknown): SecondDeviceQrPayload {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new Error("qr payload must be a plain object");
  }
  const obj = payload as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (key !== "challenge_id" && key !== "node_origin") {
      throw new Error(`qr payload forbids key: ${key}`);
    }
  }
  for (const forbidden of SECOND_DEVICE_QR_FORBIDDEN_KEYS) {
    if (forbidden in obj) {
      throw new Error(`qr payload forbids key: ${forbidden}`);
    }
  }
  const challengeId = obj.challenge_id;
  const nodeOrigin = obj.node_origin;
  if (typeof challengeId !== "string" || challengeId.length === 0) {
    throw new Error("qr payload challenge_id required");
  }
  if (typeof nodeOrigin !== "string" || nodeOrigin.length === 0) {
    throw new Error("qr payload node_origin required");
  }
  // Hand-scan values — never JSON.stringify in device/ (construction-site census).
  for (const v of Object.values(obj)) {
    if (typeof v === "string" && /private|secret|seed|totp/i.test(v)) {
      throw new Error("qr payload must not embed secret material");
    }
  }
  return { challenge_id: challengeId, node_origin: nodeOrigin.replace(/\/+$/u, "") };
}

export type SecondDeviceIssueResult =
  | {
      readonly ok: true;
      readonly ceremony: SecondDeviceCeremony;
      readonly qr: SecondDeviceQrPayload;
      /** Deep-link path on node origin (no secrets). */
      readonly deep_link_path: string;
    }
  | { readonly ok: false; readonly code: string; readonly detail: string };

export function issueSecondDeviceCeremony(
  deps: {
    readonly challengeStore: EnrollmentChallengeStore;
    readonly ceremonyStore: SecondDeviceCeremonyStore;
    readonly nodeId: string;
    readonly nodeOrigin: string;
    readonly nowMs: number;
    readonly issuedByOperatorId?: string | null;
  },
): SecondDeviceIssueResult {
  const issued = issueEnrollmentChallenge(deps.challengeStore, {
    nodeId: deps.nodeId,
    nowMs: deps.nowMs,
  });
  if (!issued.ok) {
    return { ok: false, code: issued.code, detail: issued.detail };
  }
  const ch = issued.challenge;
  const ceremony: SecondDeviceCeremony = {
    challengeId: ch.id,
    nodeId: ch.nodeId,
    nonce: ch.nonce,
    issuedAt: ch.issuedAt,
    expiresAt: ch.expiresAt,
    status: "ISSUED",
    issuedByOperatorId: deps.issuedByOperatorId ?? null,
    newDevicePublicKey: null,
    label: null,
    newDeviceKeyId: null,
    authorizingKeyId: null,
    authorizingPublicKey: null,
    authorizingSignature: null,
    preimageText: null,
    preimageSha256: null,
    newDevicePopSignature: null,
    enrolledDeviceId: null,
  };
  deps.ceremonyStore.insert(ceremony);
  const qr = buildSecondDeviceQrPayload(ch.id, deps.nodeOrigin);
  return {
    ok: true,
    ceremony,
    qr,
    deep_link_path: `/devices/enrol?challenge_id=${encodeURIComponent(ch.id)}`,
  };
}

export type SecondDeviceBindResult =
  | { readonly ok: true; readonly ceremony: SecondDeviceCeremony }
  | { readonly ok: false; readonly code: string; readonly detail: string };

export function bindSecondDevicePublicKey(
  ceremonyStore: SecondDeviceCeremonyStore,
  input: {
    readonly challengeId: string;
    readonly newDevicePublicKey: string;
    readonly label: string;
    readonly nowMs: number;
  },
): SecondDeviceBindResult {
  const row = ceremonyStore.findByChallengeId(input.challengeId);
  if (row === null) {
    return { ok: false, code: "CHALLENGE_UNKNOWN", detail: "no enrolment ceremony for challenge_id" };
  }
  if (row.status !== "ISSUED") {
    return {
      ok: false,
      code: "CHALLENGE_NOT_ISSUED",
      detail: `ceremony status is ${row.status}, expected ISSUED`,
    };
  }
  if (input.nowMs > Date.parse(row.expiresAt)) {
    ceremonyStore.update({ ...row, status: "EXPIRED" });
    return { ok: false, code: "CHALLENGE_EXPIRED", detail: "enrolment challenge has expired" };
  }
  let pubkey: string;
  try {
    pubkey = parseWalletPublicKey(input.newDevicePublicKey) as string;
  } catch {
    return { ok: false, code: "INVALID_PUBLIC_KEY", detail: "new_device_public_key invalid" };
  }
  const label = input.label.trim();
  if (label.length === 0 || label.length > 80) {
    return { ok: false, code: "LABEL_DISALLOWED", detail: "label must be 1–80 characters" };
  }
  const newDeviceKeyId = randomUUID();
  const next: SecondDeviceCeremony = {
    ...row,
    status: "BOUND",
    newDevicePublicKey: pubkey,
    label,
    newDeviceKeyId,
  };
  ceremonyStore.update(next);
  return { ok: true, ceremony: next };
}

export type SecondDeviceAuthorizeResult =
  | {
      readonly ok: true;
      readonly ceremony: SecondDeviceCeremony;
      readonly preimage_text: string;
      readonly preimage_sha256: string;
    }
  | { readonly ok: false; readonly code: string; readonly detail: string };

/**
 * Device A posts the authorizing signature over the rebuilt A.4.3 preimage.
 * Does not enrol — B must still submit PoP (or A may include pop if same session lab).
 */
export function authorizeSecondDeviceEnrol(
  ceremonyStore: SecondDeviceCeremonyStore,
  input: {
    readonly challengeId: string;
    readonly authorizingKeyId: string;
    readonly authorizingPublicKey: string;
    readonly authorizingSignature: string;
    readonly nowMs: number;
  },
): SecondDeviceAuthorizeResult {
  const row = ceremonyStore.findByChallengeId(input.challengeId);
  if (row === null) {
    return { ok: false, code: "CHALLENGE_UNKNOWN", detail: "no enrolment ceremony for challenge_id" };
  }
  if (row.status !== "BOUND" && row.status !== "AUTHORIZED") {
    return {
      ok: false,
      code: "CHALLENGE_NOT_BOUND",
      detail: `ceremony status is ${row.status}, expected BOUND`,
    };
  }
  if (input.nowMs > Date.parse(row.expiresAt)) {
    ceremonyStore.update({ ...row, status: "EXPIRED" });
    return { ok: false, code: "CHALLENGE_EXPIRED", detail: "enrolment challenge has expired" };
  }
  if (
    row.newDevicePublicKey === null ||
    row.label === null ||
    row.newDeviceKeyId === null
  ) {
    return { ok: false, code: "CHALLENGE_NOT_BOUND", detail: "new device public key not bound" };
  }

  let built;
  try {
    built = buildDeviceEnrol({
      node_id: parseUuid(row.nodeId),
      new_device_key_id: parseUuid(row.newDeviceKeyId),
      new_device_public_key: parseWalletPublicKey(row.newDevicePublicKey),
      label: row.label as never,
      nonce: parseUuid(row.nonce),
      issued_at: row.issuedAt,
      expires_at: row.expiresAt,
    });
  } catch (err) {
    return {
      ok: false,
      code: "INVALID_FIELD",
      detail: err instanceof Error ? err.message : "failed to build enrol preimage",
    };
  }

  const next: SecondDeviceCeremony = {
    ...row,
    status: "AUTHORIZED",
    authorizingKeyId: input.authorizingKeyId,
    authorizingPublicKey: input.authorizingPublicKey,
    authorizingSignature: input.authorizingSignature,
    preimageText: built.preimageText,
    preimageSha256: built.sha256,
  };
  ceremonyStore.update(next);
  return {
    ok: true,
    ceremony: next,
    preimage_text: built.preimageText,
    preimage_sha256: built.sha256,
  };
}

export type SecondDeviceCompleteResult =
  | { readonly ok: true; readonly deviceKey: EnrolledDeviceKey }
  | { readonly ok: false; readonly code: string; readonly detail: string };

export function completeSecondDeviceEnrol(
  deps: EnrolmentDeps & { readonly ceremonyStore: SecondDeviceCeremonyStore },
  input: {
    readonly challengeId: string;
    readonly newDevicePopSignature: string;
    readonly nowMs: number;
    /** Lab/break-glass path only. */
    readonly breakGlass?: boolean;
  },
): SecondDeviceCompleteResult {
  const row = deps.ceremonyStore.findByChallengeId(input.challengeId);
  if (row === null) {
    return { ok: false, code: "CHALLENGE_UNKNOWN", detail: "no enrolment ceremony for challenge_id" };
  }
  if (row.status === "ENROLLED") {
    return { ok: false, code: "CHALLENGE_NOT_ISSUED", detail: "challenge already consumed (replay)" };
  }
  if (row.status !== "AUTHORIZED") {
    return {
      ok: false,
      code: "NOT_AUTHORIZED",
      detail: `ceremony status is ${row.status}, expected AUTHORIZED`,
    };
  }
  if (input.nowMs > Date.parse(row.expiresAt)) {
    deps.ceremonyStore.update({ ...row, status: "EXPIRED" });
    return { ok: false, code: "CHALLENGE_EXPIRED", detail: "enrolment challenge has expired" };
  }
  if (
    row.preimageText === null ||
    row.preimageSha256 === null ||
    row.authorizingKeyId === null ||
    row.authorizingPublicKey === null ||
    row.authorizingSignature === null
  ) {
    return { ok: false, code: "NOT_AUTHORIZED", detail: "authorization incomplete" };
  }

  // Digest self-check (byte-exact preimage).
  const digest = createHash("sha256").update(row.preimageText, "utf8").digest("hex");
  if (digest !== row.preimageSha256) {
    return { ok: false, code: "DIGEST_MISMATCH", detail: "stored preimage digest mismatch" };
  }

  const result = verifyAndEnrolDevice(deps, {
    preimageText: row.preimageText,
    authorizingKeyId: row.authorizingKeyId,
    authorizingPublicKey: row.authorizingPublicKey,
    authorizingSignature: row.authorizingSignature,
    preimageSha256: row.preimageSha256,
    newDevicePopSignature: input.newDevicePopSignature,
    nowMs: input.nowMs,
    breakGlass: input.breakGlass,
  });

  if (!result.ok) {
    return { ok: false, code: result.code, detail: result.detail };
  }

  deps.ceremonyStore.update({
    ...row,
    status: "ENROLLED",
    newDevicePopSignature: input.newDevicePopSignature,
    enrolledDeviceId: result.deviceKey.id,
  });

  return { ok: true, deviceKey: result.deviceKey };
}

/** Public peek for device B (no secrets). */
export function peekSecondDeviceCeremony(
  ceremonyStore: SecondDeviceCeremonyStore,
  challengeId: string,
  nowMs: number,
): {
  readonly challenge_id: string;
  readonly status: SecondDeviceCeremonyStatus;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly node_id: string;
  readonly nonce: string | null;
  readonly label: string | null;
  readonly new_device_key_id: string | null;
  readonly new_device_public_key: string | null;
  readonly preimage_text: string | null;
  readonly preimage_sha256: string | null;
  readonly expired: boolean;
} | null {
  const row = ceremonyStore.findByChallengeId(challengeId);
  if (row === null) return null;
  const expired = nowMs > Date.parse(row.expiresAt);
  if (expired && row.status !== "ENROLLED" && row.status !== "EXPIRED") {
    ceremonyStore.update({ ...row, status: "EXPIRED" });
  }
  return {
    challenge_id: row.challengeId,
    status: expired && row.status !== "ENROLLED" ? "EXPIRED" : row.status,
    issued_at: row.issuedAt,
    expires_at: row.expiresAt,
    node_id: row.nodeId,
    // Nonce only after bind so B can rebuild/sign PoP with A; still not a private key.
    nonce: row.status === "ISSUED" || row.status === "BOUND" || row.status === "AUTHORIZED"
      ? row.nonce
      : null,
    label: row.label,
    new_device_key_id: row.newDeviceKeyId,
    new_device_public_key: row.newDevicePublicKey,
    preimage_text: row.status === "AUTHORIZED" || row.status === "ENROLLED" ? row.preimageText : null,
    preimage_sha256:
      row.status === "AUTHORIZED" || row.status === "ENROLLED" ? row.preimageSha256 : null,
    expired: expired && row.status !== "ENROLLED",
  };
}
