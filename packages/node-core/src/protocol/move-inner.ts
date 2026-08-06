// construct the exact MOVE_INTERNAL SplitChain inner (step 1).
// three public money operations.
//
// Pure construction only — no signer, no SQL, no durable write. MOVE has no
// redemption-expiry field in the node-formed inner (unlike SEND_EXTERNAL); optional
// expiry/message are omitted unless the caller supplies them. Reuses
// serializer (buildSplitChainInnerV2) for the fixed 14-field key sequence.
//
// Economic construction (step 1, verbatim):
// sender = source_pubkey
// receiver = destination_pubkey
// source post-balance = source_T0.B0 - amount
// destination post-balance = destination_T0.B0 + amount
// previous_step_1_state_signature = source_T0.S0
// previous_step_2_state_signature = destination_T0.S0

import { parseObservedZkzBalance } from "./amounts.js";
import {
  parseExpiryUnixTimeSecs,
  parsePreviousStateSignature,
  parseUnixTimeSecsV2,
  parseWalletPublicKey,
  type ExpiryUnixTimeSecs,
} from "./scalars.js";
import {
  issueCoherentWalletBaselineV2ForVerifiedHead,
  buildSplitChainInnerV2,
  type SplitChainInnerV2Capability,
} from "./transactions.js";
import type { DualBaselineCapture } from "./move-baseline.js";
import { unixSecsTextFromClockMs } from "./unix-secs.js";
import type { WalletStateProjection } from "./wallet-role.js";

export interface ConstructedMoveInner {
  /** Exact JSON.stringify bytes the signer will be handed (the byte-exact signing rule). */
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  /** Floor seconds of the formation clock used for unix_time_secs. */
  readonly formationUnixTimeSecs: string;
  /** Transfer amount frozen into the inner economics (matches capture.amountZkz). */
  readonly amountZkz: string;
  /** Capability retained only until the durable attempt commits; never handed to the signer. */
  readonly capability: SplitChainInnerV2Capability;
}

export interface ConstructMoveInnerInput {
  readonly capture: DualBaselineCapture;
  /** Node clock at formation, Unix milliseconds. */
  readonly nodeClockMs: number;
  /** Optional protocol-level expiry (A.1.2 field 13). Omitted from the preimage when absent. */
  readonly expiryUnixTimeSecs?: ExpiryUnixTimeSecs;
  /** Optional protocol-level message (A.1.2 field 14). Omitted from the preimage when absent. */
  readonly message?: string;
}

export type MoveInnerBuildFailureReason =
  | "same_wallet"
  | "invalid_source_baseline"
  | "invalid_destination_baseline"
  | "construction_rejected";

export class MoveInnerBuildError extends Error {
  readonly code = "MOVE_INNER_BUILD_REJECTED";

  constructor(readonly reason: MoveInnerBuildFailureReason) {
    super(`MOVE_INTERNAL inner construction rejected (${reason})`);
    this.name = "MoveInnerBuildError";
  }
}

function baselineKind(projection: WalletStateProjection): "GENESIS" | "HEAD" {
  return projection.role === "genesis" ? "GENESIS" : "HEAD";
}

/**
 * Step 1 — construct the exact MOVE_INTERNAL inner once from the dual-baseline
 * capture established by. Callers must not rebuild after the durable attempt commits;
 * the signer reads only the persisted `inner_preimage_text`.
 */
export function constructMoveInner(input: ConstructMoveInnerInput): ConstructedMoveInner {
  const { capture, nodeClockMs } = input;

  if (capture.sourceWalletPublicKey === capture.destinationWalletPublicKey) {
    throw new MoveInnerBuildError("same_wallet");
  }

  const formationUnixTimeSecs = unixSecsTextFromClockMs("constructMoveInner", nodeClockMs);

  let sender;
  try {
    sender = issueCoherentWalletBaselineV2ForVerifiedHead({
      kind: baselineKind(capture.sourceBaseline),
      publicKey: parseWalletPublicKey(capture.sourceWalletPublicKey),
      balance: parseObservedZkzBalance(capture.sourceBaseline.B),
      previousSettledStep2Signature: parsePreviousStateSignature(capture.sourceBaseline.S),
    });
  } catch {
    throw new MoveInnerBuildError("invalid_source_baseline");
  }

  let receiver;
  try {
    receiver = issueCoherentWalletBaselineV2ForVerifiedHead({
      kind: baselineKind(capture.destinationBaseline),
      publicKey: parseWalletPublicKey(capture.destinationWalletPublicKey),
      balance: parseObservedZkzBalance(capture.destinationBaseline.B),
      previousSettledStep2Signature: parsePreviousStateSignature(capture.destinationBaseline.S),
    });
  } catch {
    throw new MoveInnerBuildError("invalid_destination_baseline");
  }

  // Explicit object construction — forbids Object.assign and spread in protocol
  // production files. Each branch emits exactly the optional fields present; buildSplitChainInnerV2
  // reads optional keys by fixed name via snapshotExactObject, so only presence/absence reaches
  // the signed preimage.
  let capability: SplitChainInnerV2Capability;
  try {
    if (input.expiryUnixTimeSecs !== undefined && input.message !== undefined) {
      capability = buildSplitChainInnerV2({
        unixTimeSecs: parseUnixTimeSecsV2(formationUnixTimeSecs),
        sender,
        receiver,
        transferAmount: capture.amountZkz,
        expiryUnixTimeSecs: parseExpiryUnixTimeSecs(input.expiryUnixTimeSecs),
        message: input.message,
      });
    } else if (input.expiryUnixTimeSecs !== undefined) {
      capability = buildSplitChainInnerV2({
        unixTimeSecs: parseUnixTimeSecsV2(formationUnixTimeSecs),
        sender,
        receiver,
        transferAmount: capture.amountZkz,
        expiryUnixTimeSecs: parseExpiryUnixTimeSecs(input.expiryUnixTimeSecs),
      });
    } else if (input.message !== undefined) {
      capability = buildSplitChainInnerV2({
        unixTimeSecs: parseUnixTimeSecsV2(formationUnixTimeSecs),
        sender,
        receiver,
        transferAmount: capture.amountZkz,
        message: input.message,
      });
    } else {
      capability = buildSplitChainInnerV2({
        unixTimeSecs: parseUnixTimeSecsV2(formationUnixTimeSecs),
        sender,
        receiver,
        transferAmount: capture.amountZkz,
      });
    }
  } catch {
    throw new MoveInnerBuildError("construction_rejected");
  }

  return {
    innerPreimageText: capability.innerPreimageText,
    innerSha256: capability.innerPreimageSha256,
    formationUnixTimeSecs,
    amountZkz: capture.amountZkz,
    capability,
  };
}
