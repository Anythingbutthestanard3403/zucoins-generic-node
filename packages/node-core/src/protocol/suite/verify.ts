// Verifiers for every signed Appendix – suite-tuple purpose ('s
// wallet-head fingerprint is unsigned by design and has no verifier here). Each verifier binds the
// envelope's declared key id to the resolved key, binds the resolved key's class to the purpose's
// registered signing class (registry.ts's `keyClassForPurpose`), reparses the envelope's
// preimage text through this purpose's own strict parser (which rejects a cross-purpose preimage by
// prefix mismatch before any signature check runs — A.9 #10), confirms the caller's declared digest
// matches the reparsed digest, and only then checks the Ed25519 signature.
//
// `verifyReportingRegisterProof` is the one exception to "verify against a resolved key": A.5.1's
// proof-of-possession tuple is self-signed by the key it is enrolling, so the verification key comes
// from the parsed payload itself, not a caller-supplied `ResolvedSuiteVerificationKey`. Because that
// public key is attacker-supplied, A.5.1 requires point validation (identity/small-subgroup/non-
// prime-subgroup rejection) BEFORE the signature check — `assertPrimeOrderEd25519PublicKey`
// (ed25519-point.ts).
import { Buffer } from "node:buffer";

import { verifyRawEd25519 } from "../ed25519-verify.js";
import type { Ed25519Signature, Uuid, WalletPublicKey } from "../scalars.js";
import { assertPrimeOrderEd25519PublicKey } from "./ed25519-point.js";
import {
  parseDestinationBless,
  parseDeviceEnrol,
  parseMoveInternalExpectedArtifact,
  parseNodeEvent,
  parseReceiveExpectedArtifact,
  parseReportRequest,
  parseReportingRegister,
  parseSendExternalApproval,
  parseSendExternalExpectedArtifact,
  type DestinationBlessPayload,
  type DeviceEnrolPayload,
  type MoveInternalExpectedPayload,
  type NodeEventPayload,
  type ParsedSuiteTuple,
  type ReceiveExpectedPayload,
  type ReportRequestPayload,
  type ReportingRegisterPayload,
  type SendExternalApprovalPayload,
  type SendExternalExpectedPayload,
} from "./parsers.js";
import { keyClassForPurpose, type SuiteKeyClass } from "./registry.js";

export type SuiteVerifyReason = "key_class_mismatch" | "key_id_mismatch" | "digest_mismatch" | "signature_invalid";

// Verification-time rejection only. A malformed preimage still surfaces as `SuiteParseError` (or a
// field-level error) from the parser this module calls internally — never re-wrapped.
export class SuiteVerifyError extends Error {
  readonly code = "SUITE_VERIFY";

  constructor(readonly reason: SuiteVerifyReason) {
    super(`suite verification rejected (${reason})`);
    this.name = "SuiteVerifyError";
  }
}

export interface ResolvedSuiteVerificationKey<TClass extends SuiteKeyClass = SuiteKeyClass> {
  readonly keyId: Uuid;
  readonly keyClass: TClass;
  readonly publicKey: WalletPublicKey;
}

export interface SignedSuiteTupleEnvelope {
  readonly key_id: Uuid;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly signature: Ed25519Signature;
}

function verifyRawSignature(preimageBytes: Uint8Array, signatureText: string, publicKeyText: string): boolean {
  return verifyRawEd25519({
    publicKeyBytes: Buffer.from(publicKeyText, "base64url"),
    preimageBytes,
    signatureBytes: Buffer.from(signatureText, "base64url"),
  });
}

function verifyEnvelope<TPayload, TClass extends SuiteKeyClass>(
  purpose: string,
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<TClass>,
  parser: (source: string | Uint8Array) => ParsedSuiteTuple<TPayload>,
): ParsedSuiteTuple<TPayload> {
  const expectedClass = keyClassForPurpose(purpose);
  if (expectedClass === undefined || expectedClass === "unsigned" || expectedClass !== key.keyClass) {
    throw new SuiteVerifyError("key_class_mismatch");
  }
  if (envelope.key_id !== key.keyId) throw new SuiteVerifyError("key_id_mismatch");

  const parsed = parser(envelope.preimage_text);
  if (parsed.sha256 !== envelope.preimage_sha256) throw new SuiteVerifyError("digest_mismatch");
  if (!verifyRawSignature(parsed.preimageBytes, envelope.signature, key.publicKey)) {
    throw new SuiteVerifyError("signature_invalid");
  }
  return parsed;
}

export function verifyReceiveExpectedArtifact(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"node_identity">,
): ParsedSuiteTuple<ReceiveExpectedPayload> {
  return verifyEnvelope("zp-receive-expected-v1", envelope, key, parseReceiveExpectedArtifact);
}

export function verifyMoveInternalExpectedArtifact(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"node_identity">,
): ParsedSuiteTuple<MoveInternalExpectedPayload> {
  return verifyEnvelope("zp-move-internal-expected-v1", envelope, key, parseMoveInternalExpectedArtifact);
}

export function verifySendExternalExpectedArtifact(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"node_identity">,
): ParsedSuiteTuple<SendExternalExpectedPayload> {
  return verifyEnvelope("zp-send-external-expected-v1", envelope, key, parseSendExternalExpectedArtifact);
}

export function verifySendExternalApprovalDeviceSignature(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"device">,
): ParsedSuiteTuple<SendExternalApprovalPayload> {
  return verifyEnvelope("zp-send-external-approval-v1", envelope, key, parseSendExternalApproval);
}

export function verifyDestinationBless(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"device">,
): ParsedSuiteTuple<DestinationBlessPayload> {
  return verifyEnvelope("zp-destination-bless-v1", envelope, key, parseDestinationBless);
}

export function verifyDeviceEnrol(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"device">,
): ParsedSuiteTuple<DeviceEnrolPayload> {
  return verifyEnvelope("zp-device-enrol-v1", envelope, key, parseDeviceEnrol);
}

export function verifyReportRequest(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"reporting">,
): ParsedSuiteTuple<ReportRequestPayload> {
  return verifyEnvelope("zp-report-request-v1", envelope, key, parseReportRequest);
}

export function verifyNodeEvent(
  envelope: SignedSuiteTupleEnvelope,
  key: ResolvedSuiteVerificationKey<"node_event">,
): ParsedSuiteTuple<NodeEventPayload> {
  return verifyEnvelope("zp-node-event-v1", envelope, key, parseNodeEvent);
}

export interface ReportingRegisterProof {
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly signature: Ed25519Signature;
}

// A.5.1 proof-of-possession: the signer is the key being enrolled, taken from the parsed payload
// itself (never an envelope key-id lookup — the node has no prior registration to look up against
// yet). Point validity is checked before the signature, exactly as A.5.1 sequences it.
export function verifyReportingRegisterProof(proof: ReportingRegisterProof): ParsedSuiteTuple<ReportingRegisterPayload> {
  const parsed = parseReportingRegister(proof.preimage_text);
  if (parsed.sha256 !== proof.preimage_sha256) throw new SuiteVerifyError("digest_mismatch");
  const candidateKey = parsed.payload.new_reporting_public_key;
  assertPrimeOrderEd25519PublicKey(candidateKey);
  if (!verifyRawSignature(parsed.preimageBytes, proof.signature, candidateKey)) {
    throw new SuiteVerifyError("signature_invalid");
  }
  return parsed;
}
