// construct the exact SEND_EXTERNAL sender inner (step 6).
// SEND_EXTERNAL expiry single-source.
//
// Pure construction only — no signer, no SQL, no durable write. Expiry is derived
// exactly once here as floor(node_clock)+SEND_REDEMPTION_WINDOW_SECS and frozen into
// the preimage. Reuse serializer (buildSplitChainInnerV2) for the 14-field ordering.

import { parseObservedZkzBalance } from "./amounts.js";
import {
  parseExpiryUnixTimeSecs,
  parsePreviousStateSignature,
  parseUnixTimeSecsV2,
  parseWalletPublicKey,
} from "./scalars.js";
import {
  issueCoherentWalletBaselineV2ForVerifiedHead,
  buildSplitChainInnerV2,
  type SplitChainInnerV2Capability,
} from "./transactions.js";
import type { SendBaselineCapture } from "./send-baseline.js";
import { unixSecsTextFromClockMs } from "./unix-secs.js";
import type { WalletStateProjection } from "./wallet-role.js";
import {
  deriveSendRedemptionExpiryUnixSecs,
  redemptionExpiryAtFromSecs,
} from "./send-redemption.js";

export { SEND_REDEMPTION_WINDOW_SECS } from "./send-redemption.js";

export interface ConstructedSendInner {
  /** Exact JSON.stringify bytes the signer will be handed (the byte-exact signing rule). */
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  /** Integer-SECONDS string frozen into the preimage (T2). */
  readonly expiryUnixTimeSecs: string;
  /** Whole-second timestamptz projection of T2 for external_send_sign_intents. */
  readonly redemptionExpiryAt: string;
  /** Floor seconds of the formation clock used for unix_time_secs + T2 anchor. */
  readonly formationUnixTimeSecs: string;
  /** Capability retained only until the durable intent commits; never handed to the signer. */
  readonly capability: SplitChainInnerV2Capability;
}

export interface ConstructSendInnerInput {
  readonly capture: SendBaselineCapture;
  /** Node clock at formation, Unix milliseconds. */
  readonly nodeClockMs: number;
}

function baselineKind(projection: WalletStateProjection): "GENESIS" | "HEAD" {
  return projection.role === "genesis" ? "GENESIS" : "HEAD";
}

/**
 * Step 6 — construct the exact sender inner once. Expiry is derived here and
 * only here; callers must not recompute it on redelivery.
 */
export function constructSendInner(input: ConstructSendInnerInput): ConstructedSendInner {
  const { capture, nodeClockMs } = input;
  const formationUnixTimeSecs = unixSecsTextFromClockMs("constructSendInner", nodeClockMs);
  const expiryUnixTimeSecs = deriveSendRedemptionExpiryUnixSecs(nodeClockMs);

  const sender = issueCoherentWalletBaselineV2ForVerifiedHead({
    kind: baselineKind(capture.sourceBaseline),
    publicKey: parseWalletPublicKey(capture.sourceWalletPublicKey),
    balance: parseObservedZkzBalance(capture.sourceBaseline.B),
    previousSettledStep2Signature: parsePreviousStateSignature(capture.sourceBaseline.S),
  });
  const receiver = issueCoherentWalletBaselineV2ForVerifiedHead({
    kind: baselineKind(capture.destinationBaseline),
    publicKey: parseWalletPublicKey(capture.destinationAddress),
    balance: parseObservedZkzBalance(capture.destinationBaseline.B),
    previousSettledStep2Signature: parsePreviousStateSignature(capture.destinationBaseline.S),
  });

  const capability = buildSplitChainInnerV2({
    unixTimeSecs: parseUnixTimeSecsV2(formationUnixTimeSecs),
    sender,
    receiver,
    transferAmount: capture.amountZkz,
    expiryUnixTimeSecs: parseExpiryUnixTimeSecs(expiryUnixTimeSecs),
  });

  return {
    innerPreimageText: capability.innerPreimageText,
    innerSha256: capability.innerPreimageSha256,
    expiryUnixTimeSecs,
    redemptionExpiryAt: redemptionExpiryAtFromSecs(expiryUnixTimeSecs),
    formationUnixTimeSecs,
    capability,
  };
}
