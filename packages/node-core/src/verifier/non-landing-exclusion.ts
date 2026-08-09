// SEND_EXTERNAL non-landing exclusion oracle — the two live chain reads F1.2's close
// decision needs (`freshHeadEqualsSourceT0`, `completePathExclusionProved`).
//
// SEND_EXTERNAL is the one operation the node never submits: the recipient completes step 2
// and submits it, so the node cannot learn from its own records whether the money moved. It
// has to go and look. This module is that look, and it produces exactly two positives:
//
//   FRESH_HEAD_EQUALS_T0     the source wallet's freshly read authoritative head is
//                            byte-identical to the baseline the send was formed against.
//                            Nothing has left that wallet, so the send cannot have started.
//   COMPLETE_PATH_EXCLUSION  the head has moved, but every body from T0 to the head is
//                            present, verified, gap-free, duplicate-free and cycle-free,
//                            and none of them carries this send's step-1 signature. The
//                            send is excluded from a complete path.
//
// Everything else is INDETERMINATE, carrying the same frozen `LandingProofFault` vocabulary
// the positive walks use: a missing body, a link gap, a conflict, a duplicate, a cycle, a
// malformed or anomalous body, budget exhaustion, or a head that moved across the
// verification window all decide nothing. There is no generic PROVEN_NOT_LANDED oracle
// (landing-path oracle) and this module does not become one — a complete path is the only
// negative it admits, and an incomplete one is silence.
//
// Finding our own send ON the path is its own outcome (OWN_SEND_ON_PATH), never a fault and
// never an exclusion: that is a late landing, and driving it to EXTERNAL_SEND_LANDED belongs
// to the positive lander, which owns the nine-predicate verifier and the landing commit.
//
// Nothing here is re-implemented: `verifyHop` re-derives every column from the exact signed
// text, `pathContinuityFault` is the one shared per-hop continuity gate, and the head is read
// twice through the same `ReadFreshHead` port the positive walks anchor on. This module
// mints no proof, writes nothing, and touches no lease.

import type { LandingProofFault } from "../protocol/reconcile/landing-proof.js";
import { GENESIS_PROJECTION } from "../protocol/wallet-role.js";

import {
  DEFAULT_MAX_PATH_BODY_OCTETS,
  resolvePathBudget,
  verifyHop,
  type PathBaseline,
  type RetainedPathBodySource,
} from "./ancestry-walker.js";
import {
  DEFAULT_MAX_PATH_DEPTH,
  anchorFromRead,
  pathContinuityFault,
  type ReadFreshHead,
} from "./landing-path-oracle.js";

export interface SendNonLandingExclusionInput {
  readonly walletPublicKey: string;
  /** The send's recorded Ts0 for the source wallet: its retained body, or GENESIS. */
  readonly baseline: PathBaseline;
  /** The step-1 signature the node signed for this send — the thing being excluded. */
  readonly step1Signature: string;
  /** Tightening-only overrides; a value above the default ceiling fails closed. */
  readonly maxPathDepth?: number;
  readonly maxPathBodyOctets?: number;
}

export type SendNonLandingOutcome =
  | {
      readonly kind: "FRESH_HEAD_EQUALS_T0";
      readonly headObservationId: string;
    }
  | {
      readonly kind: "COMPLETE_PATH_EXCLUSION";
      readonly headObservationId: string;
      readonly depth: number;
    }
  | {
      readonly kind: "OWN_SEND_ON_PATH";
      readonly bodySha256: string;
    }
  | {
      readonly kind: "INDETERMINATE";
      readonly fault: LandingProofFault;
    };

function indeterminate(fault: LandingProofFault): SendNonLandingOutcome {
  return { kind: "INDETERMINATE", fault };
}

/**
 * Decide whether this SEND's completed body can be excluded from the source wallet's
 * authoritative chain.
 *
 * Returns a positive outcome only when the head is byte-identical to T0, or when the
 * complete T0→head path is assembled from retained bodies and our send is absent from it,
 * AND a second head read confirms the head did not move meanwhile. Every other result is
 * INDETERMINATE, which authorizes no close, no lease release and no retry.
 */
export async function proveSendNonLanding(
  input: SendNonLandingExclusionInput,
  source: RetainedPathBodySource,
  readFreshHead: ReadFreshHead,
): Promise<SendNonLandingOutcome> {
  const wallet = input.walletPublicKey;
  const maxDepth = resolvePathBudget(input.maxPathDepth, DEFAULT_MAX_PATH_DEPTH);
  const maxOctets = resolvePathBudget(input.maxPathBodyOctets, DEFAULT_MAX_PATH_BODY_OCTETS);
  // A caller that cannot name a finite budget inside the default ceiling gets nothing.
  if (maxDepth === null || maxOctets === null) return indeterminate("BUDGET_EXHAUSTED");

  // Reverify T0 before spending a gateway read: a baseline that does not hold up decides
  // nothing, and its own re-derived S is what the walk starts from.
  let baselineS = GENESIS_PROJECTION.S;
  let baselineText: string | null = null;
  let baselineSha256: string | null = null;
  if (input.baseline.kind === "HEAD") {
    const t0 = verifyHop(input.baseline.body, wallet);
    if (typeof t0 === "string") return indeterminate(t0);
    if (t0.stepOneSignature === input.step1Signature) {
      // T0 already IS our own send — the baseline binding contradicts the question asked.
      return { kind: "OWN_SEND_ON_PATH", bodySha256: t0.completedTransactionSha256 };
    }
    baselineS = t0.sSignature;
    baselineText = t0.completedTransactionText;
    baselineSha256 = t0.completedTransactionSha256;
  }

  // Anchor on the authoritative head as it reads right now, before any retained body is
  // admitted — the exclusion is proven against the chain, not against storage.
  const anchorRead = await readFreshHead(wallet);

  // A genesis head excludes everything only when T0 was genesis too. A genesis head under a
  // non-genesis T0 is the chain contradicting our own baseline, never a proof of anything.
  if (anchorRead.envelope.classification === "GENESIS") {
    if (baselineText !== null) return indeterminate("ANOMALOUS_OR_CONTRADICTORY");
    const confirmGenesis = await readFreshHead(wallet);
    if (confirmGenesis.envelope.classification !== "GENESIS") return indeterminate("CONFLICT");
    return { kind: "FRESH_HEAD_EQUALS_T0", headObservationId: confirmGenesis.observationId };
  }

  const anchor = anchorFromRead(anchorRead, wallet);
  if (typeof anchor === "string") return indeterminate(anchor);

  // Byte comparison, not digest comparison: exact equality always includes the bytes.
  const headUnchanged = baselineText !== null && anchor.completedTransactionText === baselineText;

  let depth = 0;
  if (!headUnchanged) {
    // Forward walk T0 → head over retained bodies, hunting for our own step-1 signature.
    const seenBodyDigests = new Set<string>(baselineSha256 === null ? [] : [baselineSha256]);
    const seenStateSignatures = new Set<string>(baselineText === null ? [] : [baselineS]);
    // A genesis baseline has no predecessor state, so the first hop is the one body allowed
    // to carry P="" — the same exemption the supplied-bodies oracle gives its first body.
    let previousS: string | undefined = baselineText === null ? undefined : baselineS;
    let currentS = baselineS;
    let currentSha256 = baselineSha256;
    let currentText = baselineText;
    let totalOctets = 0;

    while (currentSha256 !== anchor.completedTransactionSha256) {
      if (depth >= maxDepth) return indeterminate("BUDGET_EXHAUSTED");

      const resolution = await source.resolveSuccessorByBacklink(wallet, currentS);
      // A hole in the retained path is exactly the case the complete-path rule refuses to
      // decide: absence of a body is not absence of a transaction.
      if (resolution.kind === "NONE") return indeterminate("MISSING_BODY");
      if (resolution.kind === "AMBIGUOUS") return indeterminate("CONFLICT");

      const next = verifyHop(resolution.body, wallet);
      if (typeof next === "string") return indeterminate(next);

      const continuity = pathContinuityFault({
        bodySha256: next.completedTransactionSha256,
        S: next.sSignature,
        P: next.pSignature,
        previousS,
        seenBodyDigests,
        seenStateSignatures,
      });
      if (continuity !== null) return indeterminate(continuity);

      // Conflicting bodies under one digest are a fork, not a choice.
      if ((await source.countDistinctBodiesWithDigest(next.completedTransactionSha256)) > 1) {
        return indeterminate("CONFLICT");
      }

      totalOctets += Buffer.byteLength(next.completedTransactionText, "utf8");
      if (totalOctets > maxOctets) return indeterminate("BUDGET_EXHAUSTED");

      // The whole point of the walk. Our send sitting anywhere on the path means it landed;
      // the positive lander owns that, and no exclusion may be reported from here.
      if (next.stepOneSignature === input.step1Signature) {
        return { kind: "OWN_SEND_ON_PATH", bodySha256: next.completedTransactionSha256 };
      }

      seenBodyDigests.add(next.completedTransactionSha256);
      seenStateSignatures.add(next.sSignature);
      previousS = next.sSignature;
      currentS = next.sSignature;
      currentSha256 = next.completedTransactionSha256;
      currentText = next.completedTransactionText;
      depth += 1;
    }

    // Declared backstop, same as the positive walk's: the loop exits on digest equality, so
    // differing text here needs a SHA-256 collision. "Digests agreed" is not the property.
    if (currentText !== anchor.completedTransactionText) return indeterminate("CONFLICT");
  }

  // Re-read: a head that moved across the verification window decides nothing either way,
  // and a head that moved is precisely the shape a late landing takes.
  const confirmRead = await readFreshHead(wallet);
  const confirmed = anchorFromRead(confirmRead, wallet);
  if (typeof confirmed === "string") return indeterminate(confirmed);
  if (confirmed.completedTransactionSha256 !== anchor.completedTransactionSha256) {
    return indeterminate("CONFLICT");
  }

  return headUnchanged
    ? { kind: "FRESH_HEAD_EQUALS_T0", headObservationId: confirmRead.observationId }
    : { kind: "COMPLETE_PATH_EXCLUSION", headObservationId: confirmRead.observationId, depth };
}
