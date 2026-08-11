// Consumer-side verifiers for the three A.6 implementer-scoped continuity
// purposes (zp-implementer-event-v1 / -checkpoint-v1 / -keyrotation-v1).
//
// These purposes are byte-frozen in `@zucoins/generic-node-contracts/implementer-events`
// and signed with the node's EVENT_SIGNING key (key class `node_event`). They are NOT
// registered in the suite serializer registry — their preimages are built by the
// contracts package's own byte-exact builders (`buildImplementerEventPreimage` et al.)
// and must be verified against those builders, never by re-stringifying parsed JSON
// (byte-exact signing rule).
//
// Discipline matches suite/verify.ts:
//   1. purpose prefix before any signature check (A.9 #10);
//   2. key class for the purpose must be `node_event` and match the caller's key;
//   3. envelope key_id binds to the resolved key;
//   4. digest of the retained preimage_text bytes must equal preimage_sha256;
//   5. Ed25519 signature over the retained preimage bytes.
//
// GET /v1/events serves zp-implementer-event-v1 (events[]) and
// zp-implementer-checkpoint-v1 (checkpoints[]). zp-implementer-keyrotation-v1 is
// byte-frozen with the same key class but is not yet served on a tenant route.

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import {
  buildImplementerCheckpointPreimage,
  buildImplementerEventPreimage,
  buildImplementerKeyRotationPreimage,
  IMPLEMENTER_CHECKPOINT_PURPOSE,
  IMPLEMENTER_EVENT_PURPOSE,
  IMPLEMENTER_KEYROTATION_PURPOSE,
  type ImplementerCheckpointPayload,
  type ImplementerEventPayload,
  type ImplementerKeyRotationPayload,
} from "@zucoins/generic-node-contracts/implementer-events";

import { verifyRawEd25519 } from "../ed25519-verify.js";
import type {
  ResolvedSuiteVerificationKey,
  SignedSuiteTupleEnvelope,
  SuiteVerifyReason,
} from "../suite/verify.js";
import { SuiteVerifyError } from "../suite/verify.js";

export type ImplementerContinuityPurpose =
  | typeof IMPLEMENTER_EVENT_PURPOSE
  | typeof IMPLEMENTER_CHECKPOINT_PURPOSE
  | typeof IMPLEMENTER_KEYROTATION_PURPOSE;

/** Every implementer-scoped continuity purpose is signed by the node event key. */
export const IMPLEMENTER_CONTINUITY_KEY_CLASS = "node_event" as const;

const PURPOSE_PREFIX: Readonly<Record<ImplementerContinuityPurpose, string>> = {
  [IMPLEMENTER_EVENT_PURPOSE]: `${IMPLEMENTER_EVENT_PURPOSE}\n`,
  [IMPLEMENTER_CHECKPOINT_PURPOSE]: `${IMPLEMENTER_CHECKPOINT_PURPOSE}\n`,
  [IMPLEMENTER_KEYROTATION_PURPOSE]: `${IMPLEMENTER_KEYROTATION_PURPOSE}\n`,
};

export interface ParsedImplementerTuple<TPayload> {
  readonly payload: TPayload;
  readonly preimageText: string;
  readonly preimageBytes: Uint8Array;
  readonly sha256: string;
}

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

function verifyRawSignature(preimageBytes: Uint8Array, signatureText: string, publicKeyText: string): boolean {
  return verifyRawEd25519({
    publicKeyBytes: Buffer.from(publicKeyText, "base64url"),
    preimageBytes,
    signatureBytes: Buffer.from(signatureText, "base64url"),
  });
}

function assertNodeEventKey(
  purpose: ImplementerContinuityPurpose,
  key: ResolvedSuiteVerificationKey,
): void {
  // Purpose → key-class table is closed: every implementer continuity purpose is node_event.
  // Refuse any other class before touching the signature (suite discipline: purpose/key-class first).
  void purpose;
  if (key.keyClass !== IMPLEMENTER_CONTINUITY_KEY_CLASS) {
    throw new SuiteVerifyError("key_class_mismatch");
  }
}

function assertPurposePrefix(purpose: ImplementerContinuityPurpose, preimageText: string): void {
  if (!preimageText.startsWith(PURPOSE_PREFIX[purpose])) {
    // Surface as a parse-style rejection via SuiteVerifyError would lose the
    // purpose-before-signature ordering story; callers map any throw to a reason string.
    // Use signature_invalid is wrong — use a distinct throw that maps cleanly.
    throw new ImplementerParseError("purpose_mismatch");
  }
}

export type ImplementerParseReason =
  | "purpose_mismatch"
  | "invalid_json"
  | "non_canonical_bytes"
  | "payload_purpose_mismatch";

export class ImplementerParseError extends Error {
  readonly code = "IMPLEMENTER_PARSE";

  constructor(readonly reason: ImplementerParseReason) {
    super(`implementer tuple parse rejected (${reason})`);
    this.name = "ImplementerParseError";
  }
}

function parseJsonObject(preimageText: string, purpose: ImplementerContinuityPurpose): Record<string, unknown> {
  assertPurposePrefix(purpose, preimageText);
  const jsonText = preimageText.slice(PURPOSE_PREFIX[purpose].length);
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    throw new ImplementerParseError("invalid_json");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ImplementerParseError("invalid_json");
  }
  return parsed as Record<string, unknown>;
}

function requireString(obj: Record<string, unknown>, field: string): string {
  const value = obj[field];
  if (typeof value !== "string") throw new ImplementerParseError("invalid_json");
  return value;
}

function requireStringOrNull(obj: Record<string, unknown>, field: string): string | null {
  const value = obj[field];
  if (value === null) return null;
  if (typeof value !== "string") throw new ImplementerParseError("invalid_json");
  return value;
}

function requireCanonicalVersion(obj: Record<string, unknown>): 1 {
  if (obj.canonical_version !== 1) throw new ImplementerParseError("invalid_json");
  return 1;
}

function parseImplementerEventPayload(obj: Record<string, unknown>): ImplementerEventPayload {
  if (obj.purpose !== IMPLEMENTER_EVENT_PURPOSE) {
    throw new ImplementerParseError("payload_purpose_mismatch");
  }
  return {
    purpose: IMPLEMENTER_EVENT_PURPOSE,
    canonical_version: requireCanonicalVersion(obj),
    node_id: requireString(obj, "node_id"),
    implementer_id: requireString(obj, "implementer_id"),
    event_id: requireString(obj, "event_id"),
    implementer_seq: requireString(obj, "implementer_seq"),
    operation_id: requireStringOrNull(obj, "operation_id"),
    wallet_id: requireStringOrNull(obj, "wallet_id"),
    event_type: requireString(obj, "event_type"),
    data_sha256: requireString(obj, "data_sha256"),
    node_event_hash: requireString(obj, "node_event_hash"),
    implementer_previous_event_hash: requireStringOrNull(obj, "implementer_previous_event_hash"),
    created_at: requireString(obj, "created_at"),
  };
}

function parseImplementerCheckpointPayload(obj: Record<string, unknown>): ImplementerCheckpointPayload {
  if (obj.purpose !== IMPLEMENTER_CHECKPOINT_PURPOSE) {
    throw new ImplementerParseError("payload_purpose_mismatch");
  }
  return {
    purpose: IMPLEMENTER_CHECKPOINT_PURPOSE,
    canonical_version: requireCanonicalVersion(obj),
    node_id: requireString(obj, "node_id"),
    implementer_id: requireString(obj, "implementer_id"),
    checkpoint_epoch: requireString(obj, "checkpoint_epoch"),
    implementer_seq_head: requireString(obj, "implementer_seq_head"),
    implementer_event_hash: requireString(obj, "implementer_event_hash"),
    signing_key_id: requireString(obj, "signing_key_id"),
    created_at: requireString(obj, "created_at"),
  };
}

function parseImplementerKeyRotationPayload(obj: Record<string, unknown>): ImplementerKeyRotationPayload {
  if (obj.purpose !== IMPLEMENTER_KEYROTATION_PURPOSE) {
    throw new ImplementerParseError("payload_purpose_mismatch");
  }
  return {
    purpose: IMPLEMENTER_KEYROTATION_PURPOSE,
    canonical_version: requireCanonicalVersion(obj),
    node_id: requireString(obj, "node_id"),
    implementer_id: requireString(obj, "implementer_id"),
    implementer_seq: requireString(obj, "implementer_seq"),
    retired_key_id: requireString(obj, "retired_key_id"),
    new_key_id: requireString(obj, "new_key_id"),
    new_public_key: requireString(obj, "new_public_key"),
    supersedes_key_id: requireStringOrNull(obj, "supersedes_key_id"),
    implementer_previous_event_hash: requireStringOrNull(obj, "implementer_previous_event_hash"),
    created_at: requireString(obj, "created_at"),
  };
}

/**
 * Rebuild the byte-exact preimage via the contracts builder and demand the wire
 * preimage_text matches byte-for-byte. Rejects field reorder, whitespace drift,
 * and any non-canonical framing without ever signing reconstructed JSON.
 */
function assertCanonicalPreimage(expectedPurpose: ImplementerContinuityPurpose, wireText: string, rebuilt: string): void {
  if (rebuilt !== wireText) {
    throw new ImplementerParseError("non_canonical_bytes");
  }
  // Rebuild always starts with the expected purpose; belt-and-braces.
  if (!rebuilt.startsWith(PURPOSE_PREFIX[expectedPurpose])) {
    throw new ImplementerParseError("purpose_mismatch");
  }
}

function finishVerify<TPayload>(
  purpose: ImplementerContinuityPurpose,
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"node_event">,
  payload: TPayload,
  rebuiltPreimage: string,
): ParsedImplementerTuple<TPayload> {
  assertNodeEventKey(purpose, key);
  if (envelope.key_id !== key.keyId) throw new SuiteVerifyError("key_id_mismatch");

  assertCanonicalPreimage(purpose, envelope.preimage_text, rebuiltPreimage);

  const preimageBytes = Buffer.from(envelope.preimage_text, "utf8");
  const sha256 = sha256HexUtf8(envelope.preimage_text);
  if (sha256 !== envelope.preimage_sha256) throw new SuiteVerifyError("digest_mismatch");
  if (!verifyRawSignature(preimageBytes, envelope.signature, key.publicKey)) {
    throw new SuiteVerifyError("signature_invalid");
  }
  return {
    payload,
    preimageText: envelope.preimage_text,
    preimageBytes,
    sha256,
  };
}

export function verifyImplementerEvent(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"node_event">,
): ParsedImplementerTuple<ImplementerEventPayload> {
  // Purpose before signature (suite discipline).
  const obj = parseJsonObject(envelope.preimage_text, IMPLEMENTER_EVENT_PURPOSE);
  const payload = parseImplementerEventPayload(obj);
  const rebuilt = buildImplementerEventPreimage(payload);
  return finishVerify(IMPLEMENTER_EVENT_PURPOSE, envelope, key, payload, rebuilt);
}

export function verifyImplementerCheckpoint(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"node_event">,
): ParsedImplementerTuple<ImplementerCheckpointPayload> {
  const obj = parseJsonObject(envelope.preimage_text, IMPLEMENTER_CHECKPOINT_PURPOSE);
  const payload = parseImplementerCheckpointPayload(obj);
  const rebuilt = buildImplementerCheckpointPreimage(payload);
  return finishVerify(IMPLEMENTER_CHECKPOINT_PURPOSE, envelope, key, payload, rebuilt);
}

export function verifyImplementerKeyRotation(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"node_event">,
): ParsedImplementerTuple<ImplementerKeyRotationPayload> {
  const obj = parseJsonObject(envelope.preimage_text, IMPLEMENTER_KEYROTATION_PURPOSE);
  const payload = parseImplementerKeyRotationPayload(obj);
  const rebuilt = buildImplementerKeyRotationPreimage(payload);
  return finishVerify(IMPLEMENTER_KEYROTATION_PURPOSE, envelope, key, payload, rebuilt);
}

/** Key-class lookup for implementer continuity purposes (mirrors registry.keyClassForPurpose). */
export function keyClassForImplementerPurpose(
  purpose: string,
): typeof IMPLEMENTER_CONTINUITY_KEY_CLASS | undefined {
  if (
    purpose === IMPLEMENTER_EVENT_PURPOSE ||
    purpose === IMPLEMENTER_CHECKPOINT_PURPOSE ||
    purpose === IMPLEMENTER_KEYROTATION_PURPOSE
  ) {
    return IMPLEMENTER_CONTINUITY_KEY_CLASS;
  }
  return undefined;
}

export function mayKeyClassSignImplementerPurpose(
  purpose: string,
  keyClass: string,
): boolean {
  const expected = keyClassForImplementerPurpose(purpose);
  if (expected === undefined) return false;
  return expected === keyClass;
}

export type { SuiteVerifyReason };
export { SuiteVerifyError };
