// the landing-path oracle any-depth complete-path landing oracle (RECEIVE + SEND).
// This is the WALK landing-proof.ts declares it does not implement. It is the only
// producer of a positive LandingPathProof: the reconcile layer consumes the outcome, it
// never mints one.
//
// The load-bearing property is that landing is an OBSERVATION, never an assertion. The
// anchor head is obtained from `readFreshHead` — a live confirm-read of the authoritative
// head — and every digest compared here is recomputed from exact signed text by
// verifySettledTransaction. No caller-supplied digest, token, balance, or "landed" flag is
// read anywhere in this module; supplied bodies are untrusted evidence until each one
// reverifies (landing-path oracle: "intermediate bodies are untrusted supplied evidence until verified
// and fresh-head-anchored").
//
// The head is read TWICE — once to anchor, once to confirm after the walk. A head that
// moved during the verification window is CONFLICT, not a stale positive: a bare head
// mismatch proves neither landed nor non-landed. Every failure
// path in this module returns a LandingProofFailure, which the reconcile layer folds to
// INDETERMINATE; there is no negative landing verdict here, because landing-path oracle says there is no
// generic PROVEN_NOT_LANDED oracle.

import {
  evaluateExternalSendDelta,
  evaluateReceiveDelta,
} from "../protocol/economic-predicates.js";
import {
  mintLandingPathProofFromOracle,
} from "../protocol/reconcile/landing-oracle-mint.js";
import type {
  LandingProofFailure,
  LandingProofFault,
  LandingProofOutcome,
} from "../protocol/reconcile/landing-proof.js";
import { type PathObservation } from "../protocol/reconcile/observation-input.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "../protocol/wallet-role.js";
import { type GatewayEnvelopeVerdict, type ParsedSettledTransaction } from "./gateway-envelope.js";
import { verifySettledTransaction, type VerifiedTransactionVerdict } from "./transaction-verify.js";

// "verifier resource/budget exhaustion" bound. The gateway supplies no historical
// body lookup, so a path is only ever as long as the evidence a caller retained; this caps
// the verification work an unbounded supplied sequence can demand.
export const DEFAULT_MAX_PATH_DEPTH = 64;

// One live read of the authoritative head for a wallet. Production wires this to the
// bounded jittered gateway read (gateway/read.ts, `get_transaction__v1`) plus the
// envelope parse; `observationId` is the observation-ledger row that read landed.
export interface FreshHeadRead {
  readonly observationId: string;
  readonly envelope: GatewayEnvelopeVerdict;
}

export type ReadFreshHead = (walletPubkeyBase64Urlsafe: string) => Promise<FreshHeadRead>;

export interface ReceiveLandingOracleInput {
  readonly walletPubkeyBase64Urlsafe: string;
  // The receiver's accepted T0 body, or null for a genesis baseline. Its projection is
  // re-derived here from exact signed text — never accepted as a supplied projection, and
  // never a cached balance column (step 3).
  readonly t0Body: ParsedSettledTransaction | null;
  // The exact retained full body of the attempt whose landing is in question.
  readonly expectedBody: ParsedSettledTransaction;
  // The supplied continuation in sequence, T_expected+1 ... T_head. Empty asserts the
  // expected body is itself the head (zero-depth LANDED_EXACT case).
  readonly successorBodies: readonly ParsedSettledTransaction[];
  readonly operation: { readonly amountZkz: string; readonly receiverPubkey: string };
  readonly maxDepth?: number;
}

// The LandingProofFailure constructor. Shared with retained-storage walk
// (ancestry-walker.ts) so the two landing-path oracle proof paths cannot fork their failure shape.
export function fault(reason: LandingProofFault): LandingProofFailure {
  return { kind: "PROOF_INCOMPLETE", fault: reason };
}

// A body's verification result mapped onto the frozen fault vocabulary: shape/preimage
// failures are MALFORMED_BODY; a signature or role that does not hold is a contradiction
// between the supplied evidence and the chain, not a malformed input.
function verifyBody(
  body: ParsedSettledTransaction,
  walletPubkeyBase64Urlsafe: string,
): VerifiedTransactionVerdict | LandingProofFault {
  const verdict = verifySettledTransaction(body, walletPubkeyBase64Urlsafe);
  switch (verdict.verdict) {
    case "VERIFIED":
      return verdict;
    case "MALFORMED_TRANSACTION":
      return "MALFORMED_BODY";
    default:
      return "ANOMALOUS_OR_CONTRADICTORY";
  }
}

// The confirm-read: a live head read, verified for the queried wallet. A genesis head has
// no body to anchor a path at, and a malformed envelope yields no head at all.
//
// Shared with ancestry-walker.ts. The whole verdict is returned rather than a narrowed
// {text, digest} pair so the byte-exact reconstruction and its digest always travel
// together with the projection they were derived from — a caller comparing a terminal hop
// to the head by bytes ("Exact equality always includes byte comparison") and a caller
// comparing by digest are reading the same verified object, never two anchors.
export function anchorFromRead(
  read: FreshHeadRead,
  walletPubkeyBase64Urlsafe: string,
): VerifiedTransactionVerdict | LandingProofFault {
  const envelope: GatewayEnvelopeVerdict = read.envelope;
  if (envelope.classification === "GENESIS") {
    return "MISSING_BODY";
  }
  if (envelope.classification !== "HEAD") {
    return "MALFORMED_BODY";
  }
  return verifyBody(envelope.parsed, walletPubkeyBase64Urlsafe);
}

function isFault(value: VerifiedTransactionVerdict | LandingProofFault): value is LandingProofFault {
  return typeof value === "string";
}

/**
 * per-hop continuity gate — the ONE copy, run by both landing-proof walks: this
 * module's caller-supplies-the-bodies oracle and ancestry-walker.ts's retained-storage
 * walk. Returns the fault the hop fails on, or null when it is admissible.
 *
 * The SEQUENCE is load-bearing and is why this lives in one place. The seen-body-digest check
 * must precede the seen-state-signature check so a ringing source — one that hands back a
 * body already on the path — terminates as DUPLICATE rather than walking forever. Under
 * sound signatures S determines the body, so the state-signature guard is the redundant
 * backstop that keeps both walks TOTAL if the digest set is ever defeated; it is not
 * claimed to be independently reachable.
 *
 * The backlink `P(W,T[i]) == S(W,T[i-1])` is asserted last, against the projection the
 * SIGNED BYTES produced rather than any column an index was probed on — it is the sole
 * evidence that two verified bodies are adjacent on this wallet's chain.
 *
 * `previousS` is undefined only for the first body of a supplied sequence, which has no
 * predecessor on the path to be adjacent to; the retained-storage walk seeds its expected
 * body outside its loop and so always supplies one.
 *
 * The empty-P clause is a backstop, not an independently reachable cause: S is a verified
 * body's `step_2_signature`, which cannot be empty for a VERIFIED verdict, so `P === ""`
 * already fails the inequality against any real predecessor. It fails closed on a
 * genesis-adjacent body (P="" at genesis) reaching this gate by some other route.
 */
export function pathContinuityFault(hop: {
  readonly bodySha256: string;
  readonly S: string;
  readonly P: string;
  readonly previousS: string | undefined;
  readonly seenBodyDigests: ReadonlySet<string>;
  readonly seenStateSignatures: ReadonlySet<string>;
}): LandingProofFault | null {
  if (hop.seenBodyDigests.has(hop.bodySha256)) return "DUPLICATE";
  if (hop.seenStateSignatures.has(hop.S)) return "CYCLE";
  if (hop.previousS !== undefined && (hop.P === "" || hop.P !== hop.previousS)) return "GAP";
  return null;
}

/**
 * Classify whether a RECEIVE_EXTERNAL attempt landed.
 *
 * Returns a positive LandingPathProof only when the freshly read authoritative head is
 * reached by a verified, gap-free, duplicate-free, cycle-free sequence of exact full
 * bodies starting at the expected attempt, the expected attempt satisfies the operation's
 * economic predicate against a re-derived T0, and the head is unchanged across the
 * verification window. Every other result is a LandingProofFailure, which authorizes no
 * landing, no non-landing, and no retry/rebuild/resubmit or lease release.
 */
export async function proveReceiveLanding(
  input: ReceiveLandingOracleInput,
  readFreshHead: ReadFreshHead,
): Promise<LandingProofOutcome> {
  const wallet = input.walletPubkeyBase64Urlsafe;
  const depth = input.successorBodies.length;
  const maxDepth = input.maxDepth ?? DEFAULT_MAX_PATH_DEPTH;
  if (depth > maxDepth) {
    return fault("BUDGET_EXHAUSTED");
  }

  // Anchor: the authoritative head as it reads right now.
  const anchorRead = await readFreshHead(wallet);
  const anchor = anchorFromRead(anchorRead, wallet);
  if (isFault(anchor)) {
    return fault(anchor);
  }

  // Step 3 — the economic predicate against T0, recomputed from exact signed text.
  // A genesis baseline is the only case with no body; every other T0 is reverified here
  // rather than trusted as a stored projection.
  let baseline: WalletStateProjection = GENESIS_PROJECTION;
  if (input.t0Body !== null) {
    const t0 = verifyBody(input.t0Body, wallet);
    if (isFault(t0)) {
      return fault(t0);
    }
    baseline = t0.projection;
  }

  const bodies = [input.expectedBody, ...input.successorBodies];
  const seenBodyDigests = new Set<string>();
  const seenStateSignatures = new Set<string>();
  let previous: VerifiedTransactionVerdict | undefined;
  let expected: VerifiedTransactionVerdict | undefined;
  let last: VerifiedTransactionVerdict | undefined;

  for (const body of bodies) {
    const verified = verifyBody(body, wallet);
    if (isFault(verified)) {
      return fault(verified);
    }
    const continuity = pathContinuityFault({
      bodySha256: verified.completedTransactionSha256,
      S: verified.projection.S,
      P: verified.projection.P,
      previousS: previous?.projection.S,
      seenBodyDigests,
      seenStateSignatures,
    });
    if (continuity !== null) {
      return fault(continuity);
    }
    seenBodyDigests.add(verified.completedTransactionSha256);
    seenStateSignatures.add(verified.projection.S);
    expected ??= verified;
    previous = verified;
    last = verified;
  }

  // `bodies` always holds at least the expected body, so both are assigned; the guard
  // keeps the narrowing local rather than asserting it.
  if (expected === undefined || last === undefined) {
    return fault("MISSING_BODY");
  }

  const economic = evaluateReceiveDelta({
    baseline,
    candidateTx: expected.transaction,
    reservedWalletPublicKey: wallet,
    operation: { amountZkz: input.operation.amountZkz, receiverPubkey: input.operation.receiverPubkey },
  });
  if (!economic.ok) {
    return fault("ANOMALOUS_OR_CONTRADICTORY");
  }

  // The path must terminate AT the freshly read head. At depth 0 that means the expected
  // body is the head; a shortfall there means the bodies between it and the head were
  // never supplied. At depth >= 1 a supplied sequence that stops short is a gap.
  if (last.completedTransactionSha256 !== anchor.completedTransactionSha256) {
    return fault(depth === 0 ? "MISSING_BODY" : "GAP");
  }

  // The current-exact-head rule: re-read and require the head is the same one the path
  // was anchored against. A head that moved mid-verification decides nothing.
  const confirmRead = await readFreshHead(wallet);
  const confirmed = anchorFromRead(confirmRead, wallet);
  if (isFault(confirmed)) {
    return fault(confirmed);
  }
  if (confirmed.completedTransactionSha256 !== anchor.completedTransactionSha256) {
    return fault("CONFLICT");
  }

  return mintLandingPathProofFromOracle({
    walletPubkeyBase64Urlsafe: wallet,
    expectedBodySha256: expected.completedTransactionSha256,
    freshHeadBodySha256: confirmed.completedTransactionSha256,
    freshHeadObservationId: confirmRead.observationId,
    depth,
  });
}


export interface SendLandingOracleInput {
  readonly walletPubkeyBase64Urlsafe: string;
  // Source T0 body, or null only if the source was genesis (unusual for a funded send).
  readonly t0Body: ParsedSettledTransaction | null;
  // Exact retained full body of the recipient-completed SEND attempt (attempt 1).
  readonly expectedBody: ParsedSettledTransaction;
  // Continuation T_expected+1 ... T_head. Empty asserts expected is itself the head.
  readonly successorBodies: readonly ParsedSettledTransaction[];
  readonly operation: {
    readonly amountZkz: string;
    readonly sourcePubkey: string;
    readonly destinationAddress: string;
  };
  readonly maxDepth?: number;
}

/**
 * Classify whether a SEND_EXTERNAL attempt landed on the SOURCE wallet.
 *
 * Same any-depth complete-path walk as `proveReceiveLanding`, with the external-send
 * economic predicate against source T0. A positive proof is LANDED_EXACT (depth 0) or
 * LANDED_COMPLETE_PATH (depth >= 1). Every other result is LandingProofFailure →
 * INDETERMINATE; nothing here authorizes non-landing, retry, rebuild, resubmit, or
 * lease release. The unadopted one-hop LANDED_DIRECT_SUCCESSOR shortcut is not used.
 */
export async function proveSendLanding(
  input: SendLandingOracleInput,
  readFreshHead: ReadFreshHead,
): Promise<LandingProofOutcome> {
  const wallet = input.walletPubkeyBase64Urlsafe;
  const depth = input.successorBodies.length;
  const maxDepth = input.maxDepth ?? DEFAULT_MAX_PATH_DEPTH;
  if (depth > maxDepth) {
    return fault("BUDGET_EXHAUSTED");
  }

  const anchorRead = await readFreshHead(wallet);
  const anchor = anchorFromRead(anchorRead, wallet);
  if (isFault(anchor)) {
    return fault(anchor);
  }

  let baseline: WalletStateProjection = GENESIS_PROJECTION;
  if (input.t0Body !== null) {
    const t0 = verifyBody(input.t0Body, wallet);
    if (isFault(t0)) {
      return fault(t0);
    }
    baseline = t0.projection;
  }

  const bodies = [input.expectedBody, ...input.successorBodies];
  const seenBodyDigests = new Set<string>();
  const seenStateSignatures = new Set<string>();
  let previous: VerifiedTransactionVerdict | undefined;
  let expected: VerifiedTransactionVerdict | undefined;
  let last: VerifiedTransactionVerdict | undefined;

  for (const body of bodies) {
    const verified = verifyBody(body, wallet);
    if (isFault(verified)) {
      return fault(verified);
    }
    const continuity = pathContinuityFault({
      bodySha256: verified.completedTransactionSha256,
      S: verified.projection.S,
      P: verified.projection.P,
      previousS: previous?.projection.S,
      seenBodyDigests,
      seenStateSignatures,
    });
    if (continuity !== null) {
      return fault(continuity);
    }
    seenBodyDigests.add(verified.completedTransactionSha256);
    seenStateSignatures.add(verified.projection.S);
    expected ??= verified;
    previous = verified;
    last = verified;
  }

  if (expected === undefined || last === undefined) {
    return fault("MISSING_BODY");
  }

  const economic = evaluateExternalSendDelta({
    baseline,
    candidateTx: expected.transaction,
    sourceWalletPublicKey: wallet,
    operation: {
      amountZkz: input.operation.amountZkz,
      sourcePubkey: input.operation.sourcePubkey,
      destinationAddress: input.operation.destinationAddress,
    },
  });
  if (!economic.ok) {
    return fault("ANOMALOUS_OR_CONTRADICTORY");
  }

  if (last.completedTransactionSha256 !== anchor.completedTransactionSha256) {
    return fault(depth === 0 ? "MISSING_BODY" : "GAP");
  }

  const confirmRead = await readFreshHead(wallet);
  const confirmed = anchorFromRead(confirmRead, wallet);
  if (isFault(confirmed)) {
    return fault(confirmed);
  }
  if (confirmed.completedTransactionSha256 !== anchor.completedTransactionSha256) {
    return fault("CONFLICT");
  }

  return mintLandingPathProofFromOracle({
    walletPubkeyBase64Urlsafe: wallet,
    expectedBodySha256: expected.completedTransactionSha256,
    freshHeadBodySha256: confirmed.completedTransactionSha256,
    freshHeadObservationId: confirmRead.observationId,
    depth,
  });
}

export interface ExactHeadLandingInput {
  readonly walletPubkeyBase64Urlsafe: string;
  // The digest of the exact signed body whose landing is in question. The economic
  // predicate (source debit == destination credit == amount) is already enforced when this
  // body was formed from its captured baseline (byte-exact per the signing rule); this oracle
  // only answers whether that exact body is the wallet's current head, never re-derives it.
  readonly expectedBodySha256: string;
}

/**
 * depth-0 exact-head case for callers with no retained-storage path reconstruction
 * (MOVE_INTERNAL's reconcile: `move-advanced-ports.ts`). Same anchor/confirm double-read and
 * mint as `proveReceiveLanding`/`proveSendLanding`, without their single-wallet economic
 * predicate — which does not apply to a bilateral MOVE and is redundant with the byte-exact
 * body already fixed at FORM time. A body that is not exactly the freshly read head is
 * unprovable here: there is no supplied continuation to walk, so any gap is MISSING_BODY.
 */
export async function proveExactHeadLanding(
  input: ExactHeadLandingInput,
  readFreshHead: ReadFreshHead,
): Promise<LandingProofOutcome> {
  const wallet = input.walletPubkeyBase64Urlsafe;

  const anchorRead = await readFreshHead(wallet);
  const anchor = anchorFromRead(anchorRead, wallet);
  if (isFault(anchor)) {
    return fault(anchor);
  }
  if (anchor.completedTransactionSha256 !== input.expectedBodySha256) {
    return fault("MISSING_BODY");
  }

  // The current-exact-head rule: re-read and require the head is still the one anchored.
  const confirmRead = await readFreshHead(wallet);
  const confirmed = anchorFromRead(confirmRead, wallet);
  if (isFault(confirmed)) {
    return fault(confirmed);
  }
  if (confirmed.completedTransactionSha256 !== anchor.completedTransactionSha256) {
    return fault("CONFLICT");
  }

  return mintLandingPathProofFromOracle({
    walletPubkeyBase64Urlsafe: wallet,
    expectedBodySha256: input.expectedBodySha256,
    freshHeadBodySha256: confirmed.completedTransactionSha256,
    freshHeadObservationId: confirmRead.observationId,
    depth: 0,
  });
}

// The oracle's outcome as the reconcile layer's path-evidence input, so
// classifyReceiveReconcile consumes a proven observation rather than a hand-built one.
export function landingProofToPathObservation(outcome: LandingProofOutcome): PathObservation {
  return outcome.kind === "PROOF_INCOMPLETE"
    ? { result: "PROOF_INCOMPLETE", fault: outcome.fault }
    : { result: "PROOF", proof: outcome };
}
