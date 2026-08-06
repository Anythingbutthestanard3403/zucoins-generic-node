/**
 * The consumer-boundary contract (implementer-controlled-origin model; instruction-origin
 * identity).
 *
 * the presentation scope audit — the REFERENCE CONSUMER of the frozen presentation handoff: the exact, pure decision
 * sequence an implementer product runs on the customer-facing side of the presentation-scope concern boundary before
 * it is entitled to present an instruction as genuine. It exists so the boundary frozen by
 * `presentation-handoff.contract.ts` is exercised end to end by running code rather than asserted
 * by a table — the substitution property is a test result here, not a claim.
 *
 * It composes ONLY primitives owned elsewhere and never re-derives one: the artifacts concern's
 * `verifyExpectedArtifact` (artifact authenticity), the presentation-scope concern.1's `verifyIdentityPin` (key identity
 * against the independently-established pin) and `DISCOVERY_PATH`, the presentation-scope concern.2's frozen capability
 * set, and the presentation-scope concern.1's `isSubstitutionProof` (origin-class decision). Those are exactly the two
 * FROZEN_AVAILABLE capabilities (ARTIFACT_VERIFICATION, IDENTITY_PIN_CHECK); no deferred
 * capability is touched and no interface for one is fabricated.
 *
 * The two checks that make it substitution-proof rather than merely signature-checking:
 *
 *  (1) PIN-FIRST. The pin comparison runs against a key the consumer resolved INDEPENDENTLY (via
 *      `DISCOVERY_PATH`), not against the key the handoff names. A substituted artifact signed by
 *      an attacker's own perfectly valid ACTIVE key therefore fails here — it is individually
 *      valid and still rejected, which is the whole of R-07.
 *  (2) OPERATION BINDING. Even an artifact re-signed by the GENUINE node identity key is rejected
 *      unless the payload's `operation_id` equals the operation the handoff is about. Without
 *      this, a relaying platform could swap in a different, genuinely-signed instruction and every
 *      cryptographic check would still pass.
 *
 * Being a reference consumer it is deliberately transport-free and I/O-free: resolving the key
 * from `DISCOVERY_PATH` is the caller's job (it is the step that must not run on platform-hosted
 * code), and the Ed25519/SHA-256 implementation is injected, per.
 */
import type { NodeIdentityKeyRecord } from "../artifacts/signing-contract.ts";
import {
  verifyExpectedArtifact,
  type ArtifactVerificationCrypto,
  type VerifyRejectReason,
} from "../artifacts/verify.ts";
import { DISCOVERY_PATH, verifyIdentityPin, type PinRejectReason } from "./identity-pin.contract.ts";
import { isSubstitutionProof } from "./origin-classes.contract.ts";
import { isValidPresentationHandoffShape, type PresentationHandoff } from "./presentation-handoff.contract.ts";

/** Closed set of reasons the reference consumer refuses to present an instruction as genuine.
 *  Frozen and ordered by the sequence in which the checks run — the FIRST failing check wins,
 *  the same fail-closed discipline as the artifacts concern's `verifyExpectedArtifact`.*/
export const CONSUMER_REJECT_REASONS = [
  "handoff_shape_invalid",
  "discovery_path_mismatch",
  "pin_not_verified",
  "artifact_not_verified",
  "operation_id_unbound",
  "origin_not_substitution_proof",
] as const;
export type ConsumerRejectReason = (typeof CONSUMER_REJECT_REASONS)[number];

export type ConsumerVerdict =
  | { readonly presentable: true; readonly operationId: string; readonly digest: string }
  | {
      readonly presentable: false;
      readonly reason: ConsumerRejectReason;
      /** The underlying concern's own reason code, never re-worded. */
      readonly detail?: PinRejectReason | VerifyRejectReason | string;
    };

export interface ConsumerVerifyInput {
  /** UNTRUSTED. Whatever arrived over the boundary; shape is validated, never assumed. */
  readonly handoff: unknown;
  /**
   * The node identity key the consumer resolved for itself from `DISCOVERY_PATH`. It is a
   * parameter precisely because this resolution is the step a compromised platform must not be
   * the one to perform (hosted code may relay, but it cannot
   * establish or replace the pin and must not be the only code performing verification).
   */
  readonly resolvedKey: NodeIdentityKeyRecord;
  readonly nowUnixMs: number;
}

const refuse = (reason: ConsumerRejectReason, detail?: string): ConsumerVerdict => ({
  presentable: false,
  reason,
  detail,
});

/** The payload half of a suite preimage: everything after the purpose-prefix line. Only called
 *  once `verifyExpectedArtifact` has already proven the preimage is well-formed, byte-canonical
 *  and correctly signed, so this parse cannot be reached with attacker-shaped input. */
const payloadOf = (preimageText: string): Record<string, unknown> =>
  JSON.parse(preimageText.slice(preimageText.indexOf("\n") + 1)) as Record<string, unknown>;

/**
 * Run the full consumer-boundary decision for one handoff. Pure apart from the injected crypto;
 * returns `presentable: true` only when the instruction is safe to show to a customer AS GENUINE
 * on the origin class the handoff declares.
 */
export const verifyPresentationHandoff = async (
  input: ConsumerVerifyInput,
  crypto: ArtifactVerificationCrypto,
): Promise<ConsumerVerdict> => {
  const { handoff, resolvedKey, nowUnixMs } = input;

  // 1. Closed-shape check (C-05): anything outside the frozen field set — including smuggled
  //    wallet key material — is rejected structurally, before any field is read.
  if (!isValidPresentationHandoffShape(handoff)) {
    return refuse("handoff_shape_invalid");
  }
  const trusted: PresentationHandoff = handoff;

  // 2. The pin must be the one published at the frozen discovery path; a handoff pointing the
  //    consumer somewhere else is an attempt to relocate the check onto attacker ground.
  if (trusted.discoveryPath !== DISCOVERY_PATH) {
    return refuse("discovery_path_mismatch", trusted.discoveryPath);
  }

  // 3. PIN FIRST — against the independently resolved key, before any signature is examined.
  const pinVerdict = verifyIdentityPin(trusted.nodeIdentityPin, resolvedKey, nowUnixMs);
  if (!pinVerdict.verified) {
    return refuse("pin_not_verified", pinVerdict.reason);
  }

  // 4. Artifact authenticity under the PINNED key (the artifacts concern), with the purpose the handoff claims.
  //    the artifacts concern documents that the injected crypto may THROW on malformed base64 rather than return
  //    a reject reason (suiteVerificationCrypto.ts preserves each caller's throw behaviour). That
  //    is fine inside the package, but this is an untrusted boundary, so the throw is converted to
  //    a refusal here rather than escaping into the consumer's presentation code.
  let artifactVerdict: Awaited<ReturnType<typeof verifyExpectedArtifact>>;
  try {
    artifactVerdict = await verifyExpectedArtifact(
      {
        envelope: trusted.artifactEnvelope,
        key: resolvedKey,
        signedAtUnixMs: nowUnixMs,
        expectedPurpose: trusted.artifactPurpose,
        pinnedPublicKeyB64: trusted.nodeIdentityPin.publicKeyB64,
      },
      crypto,
    );
  } catch {
    return refuse("artifact_not_verified", "malformed_signature_encoding");
  }
  if (!artifactVerdict.ok) {
    return refuse("artifact_not_verified", artifactVerdict.reason);
  }

  // 5. OPERATION BINDING — the artifact must be about the operation this handoff is about. This
  //    is the only check that catches a substitution performed with the genuine node key.
  const operationId = payloadOf(trusted.artifactEnvelope.preimage_text).operation_id;
  if (operationId !== trusted.operationId) {
    return refuse("operation_id_unbound", typeof operationId === "string" ? operationId : typeof operationId);
  }

  // 6. Origin class — a verified pin on platform-hosted code still proves nothing, because the
  //    platform controls the check itself (frozen unconditionally in ORIGIN_CLASS_CLAIMS).
  if (!isSubstitutionProof(trusted.originClass, true)) {
    return refuse("origin_not_substitution_proof", trusted.originClass);
  }

  return { presentable: true, operationId: trusted.operationId, digest: artifactVerdict.digest };
};

export const SOURCE = "consumer boundary; implementer-controlled-origin model; instruction-origin-identity" as const;
