// Merchant-hosted payment-instruction origin. Part of the installable SDK.
//
// The customer instruction originates on a node- or merchant-controlled surface and
// includes the generic receive expected artifact; that surface verifies the artifact with a
// node identity key pinned through a channel INDEPENDENT of hosted ZuPayments BEFORE showing
// or releasing the receiver, exact ZKZ amount, request correlation, and expiry. Hosted
// ZuPayments may relay data, but it cannot establish or replace the pin and must not be the
// only code performing verification.
//
// This module is the merchant-controlled presentation surface. It composes ONLY frozen
// primitives owned elsewhere — never re-derives one:
//   * `verifyPresentationHandoff` (the reference consumer boundary: pin-first, artifact
//     authenticity under the pinned key, operation binding, origin-class substitution proof);
//   * the node-signed `zp-receive-expected-v1` expected artifact (bound to operation_id,
//     receiver_pubkey, amount_zkz, expiry);
//   * `bootstrapIdentityPin` (the independently-established node-key pin).
//
// The two checks that make it substitution-proof (mirrors consumer-boundary.ts):
//   (1) PIN-FIRST — the artifact is verified against the merchant's INDEPENDENTLY pinned node
//       identity key, not the key the relay named. A substituted artifact signed by an attacker's
//       own perfectly valid ACTIVE key therefore fails here.
//   (2) DISPLAY-FROM-ARTIFACT — the receiver, exact ZKZ amount, and expiry the payer sees are
//       read from the VERIFIED artifact preimage, never from the relay's unverified fields.
//       A relay that forges the amount in its own envelope cannot move it onto the payer's
//       screen, because this module refuses to present anything before the artifact verifies and
//       then reads every displayed value from the node-signed preimage.
//
// Transport-free and I/O-free by design: resolving the pinned key from discovery (the step a
// compromised platform must not perform) and the Ed25519/SHA-256 implementation are the caller's
// job, per the frozen boundary. No wallet private key, signing capability, or custody material
// ever crosses this surface.

import {
  verifyPresentationHandoff,
  DISCOVERY_PATH,
  type ConsumerRejectReason,
  type NodeIdentityPin,
  type NodeIdentityKeyRecord,
  type OriginClass,
  type PresentationHandoff,
} from "@zucoins/generic-node-contracts/instruction-origin";
import type { ArtifactVerificationCrypto } from "@zucoins/generic-node-contracts/artifacts";
import type { ArtifactEnvelope } from "@zucoins/node-core/verifier/consumer";

/**
 * The bound receive instruction a merchant surface may present to a payer AFTER the node-signed
 * expected artifact verifies against the independently pinned node identity. Every field is
 * read from the verified artifact preimage (node-signed) — never from the relay — so a forged
 * amount or receiver in the relay envelope never reaches the payer.
 */
export interface VerifiedReceiveInstruction {
  readonly operationId: string;
  /** Artifact-bound receiver identity — the wallet the payer will sign to. */
  readonly receiverPubkey: string;
  /** Artifact-bound ZKZ amount (exact, node-signed). The payer sees this, not the relay's amount. */
  readonly amountZkz: string;
  /** Artifact-bound expiry (unix seconds string, or null for no expiry). */
  readonly expiryUnixTimeSecs: string | null;
  /** Artifact digest the reference consumer returned — correlates to verification-material. */
  readonly artifactDigest: string;
}

export type InstructionOriginResult =
  | { readonly presentable: true; readonly instruction: VerifiedReceiveInstruction }
  | { readonly presentable: false; readonly reason: ConsumerRejectReason; readonly detail?: string };

/**
 * Input to the merchant-hosted instruction-origin surface.
 *
 * `relay` is UNTRUSTED — whatever the hosted platform (or any relay) handed the merchant server.
 * `pinnedKey` is the node identity key the merchant resolved for itself from the frozen
 * discovery path, through a channel independent of hosted ZuPayments. Resolving that
 * key is the step a compromised platform must not be the one to perform, so it is a parameter.
 */
export interface InstructionOriginInput {
  /** UNTRUSTED relay handoff: operation id + the node-signed expected artifact the relay carried. */
  readonly operationId: string;
  readonly artifact: ArtifactEnvelope;
  /** The artifact purpose this presentation is for (e.g. `zp-receive-expected-v1`). */
  readonly artifactPurpose: string;
  /** The merchant's independently-established node identity pin. */
  readonly nodeIdentityPin: NodeIdentityPin;
  /** The node identity key the merchant resolved for itself from DISCOVERY_PATH. */
  readonly resolvedKey: NodeIdentityKeyRecord;
  /** Origin class the presentation is being rendered on (must be a substitution-proof class). */
  readonly originClass: OriginClass;
  readonly nowUnixMs: number;
  /** Injected Ed25519/SHA-256 implementation (per the frozen boundary). */
  readonly crypto: ArtifactVerificationCrypto;
}

/**
 * The payload half of a suite preimage: everything after the purpose-prefix line. Only called
 * once `verifyPresentationHandoff` has proven the preimage is well-formed, byte-canonical and
 * correctly signed under the pinned key, so this parse cannot be reached with attacker-shaped
 * input. (Same discipline as consumer-boundary.ts `payloadOf`.)
 */
function payloadOf(preimageText: string): Record<string, unknown> {
  return JSON.parse(preimageText.slice(preimageText.indexOf("\n") + 1)) as Record<string, unknown>;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/**
 * Verify a relayed receive instruction at the merchant-controlled surface and, only when it is
 * safe to present as genuine, return the bound receiver / amount / expiry read from the
 * node-signed artifact preimage.
 *
 * Returns `presentable: false` for any pin, artifact, operation-binding, or origin-class failure
 * — the merchant surface shows nothing until the artifact verifies. The displayed amount is the
 * artifact's bound `amount_zkz`, never the relay's, so a forged-amount relay is rejected before
 * the payer sees a substituted instruction.
 */
export async function verifyReceiveInstructionOrigin(
  input: InstructionOriginInput,
): Promise<InstructionOriginResult> {
  const handoff: PresentationHandoff = {
    operationId: input.operationId,
    artifactPurpose: input.artifactPurpose as PresentationHandoff["artifactPurpose"],
    artifactEnvelope: input.artifact,
    nodeIdentityPin: input.nodeIdentityPin,
    discoveryPath: DISCOVERY_PATH,
    originClass: input.originClass,
  };

  const verdict = await verifyPresentationHandoff(
    { handoff, resolvedKey: input.resolvedKey, nowUnixMs: input.nowUnixMs },
    input.crypto,
  );

  if (!verdict.presentable) {
    return { presentable: false, reason: verdict.reason, detail: verdict.detail };
  }

  // The artifact verified under the pinned key — read the bound display fields from its
  // preimage. These are node-signed; the relay's own fields are never consulted for display.
  const payload = payloadOf(input.artifact.preimage_text);
  const receiverPubkey = asString(payload.receiver_pubkey);
  const amountZkz = asString(payload.amount_zkz);
  const expiry = asString(payload.expiry_unix_time_secs);
  if (receiverPubkey === null || amountZkz === null) {
    // Unreachable post-verify: the zp-receive-expected-v1 artifact contract guarantees these fields are present
    // and well-formed in a verified preimage. Refusing rather than guessing keeps a malformed
    // (but somehow signed) artifact off the payer's screen.
    return { presentable: false, reason: "artifact_not_verified", detail: "missing_bound_fields" };
  }

  return {
    presentable: true,
    instruction: {
      operationId: verdict.operationId,
      receiverPubkey,
      amountZkz,
      expiryUnixTimeSecs: expiry,
      artifactDigest: verdict.digest,
    },
  };
}

export { DISCOVERY_PATH };
