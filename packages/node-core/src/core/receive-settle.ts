// RECEIVE_EXTERNAL settle step — steps 8–13, under the exact-byte rules, the signUnderLease
// chokepoint, the operation_transactions phase ladder, and the one-in-flight-per-wallet and byte-exact signing rules, 4.
//
// This is the production caller of core/receive-submit-once.ts. Before that module had
// no production importer at all: the guards catalogued it as the RECEIVE_EXTERNAL
// No-blind-retry submit entry while the only code that ever reached it was test code. The census in
// test/receive-settle-census.guard.test.ts now fails if that regresses.
//
// The step is entered at whichever rung of the phase ladder the durable row actually sits on, not
// only at the first. Steps 9 and 11 commit before the work that follows them precisely so a
// crash is resumable, and a resume reuses the persisted text verbatim rather than re-deriving
// it. A resume that finds the completed body already durable reconciles through the
// confirm-read BEFORE any submit path is entered — the never-blind-retry rule forbids the blind resubmit
// that would otherwise be the obvious thing to do with a signed body and no known outcome.
//
// Placement: this lives in core/, not receive/, because the node-core dependency fence
// (test/boundaries.test.ts ALLOWED_INTERNAL_IMPORTS) gives `receive` no edge to `core`, and the
// settle step must reach the signer boundary, the phase ladder, and the submit-once service.
// It is the RECEIVE twin of core/move-form-and-sign.ts + core/move-submit-claim.ts.

import { Buffer } from "node:buffer";

import { buildGatewayActionRequest } from "../gateway/request.js";
import { verifyRawEd25519 } from "../protocol/ed25519-verify.js";
import type { ReconcileIndeterminateReason } from "../protocol/reconcile/types.js";
import type { MetricsHooks } from "./metrics.js";
import {
  receiveSubmitOnce,
  type ReceiveSubmitClaim,
  type SubmitClaimStore,
} from "./receive-submit-once.js";
// A.1.2 freezes ONE two-key step-2 preimage shape and ONE three-key settled shape for every
// operation kind. These builders are therefore shared rather than twinned: a second byte-exact
// assembler for RECEIVE would be a second thing to keep byte-identical (the byte-exact signing rule).
import {
  assertPersistedInnerRoundTrips,
  buildMoveCompletedTransactionText as buildCompletedTransactionText,
  buildMoveStep2PreimageText as buildStep2PreimageText,
  hashMovePreimageText as hashPreimageText,
} from "./move-step2.js";
import {
  assertSignerLeadership,
  signUnderLease,
  type MoneyPathSignerGates,
  type SignerBoundaryDeps,
} from "./signer-boundary.js";
import type { AttemptPhase } from "./execution-phase.js";
import type { SqlQueryFn } from "./sql-query-fn.js";
import { advanceAttemptPhase } from "./transaction-material-store.js";
import type { SubmitGatewayActionOptions } from "../gateway/submit.js";
import { type NowIsoFn, defaultNowIso } from "../gateway/records.js";

/** The frozen submit action name. Mirrors @zucoins/generic-node-contracts SUBMIT_ACTION_NAME;
 * node-core carries no dependency on the contracts package, so the equality is
 * asserted in test/receive-settle-census.guard.test.ts rather than imported. */
export const RECEIVE_SUBMIT_ACTION_NAME = "submit_transaction__v1";

/** Step 10 signs the step-2 preimage; the purpose is the frozen signer-boundary literal. */
const RECEIVE_STEP2_PURPOSE = "SPLITCHAIN_STEP_2";

export const RECEIVE_SETTLE_REJECTIONS = [
  "PREIMAGE_DRIFT",
  "PAYER_STEP1_SIGNATURE_INVALID",
  "RECEIVER_KEY_NOT_NAMED_BY_INNER",
  "RESUME_MATERIAL_MISSING",
] as const;

export type ReceiveSettleRejection = (typeof RECEIVE_SETTLE_REJECTIONS)[number];

/**
 * The ladder rungs a settle pass may legally be entered at. Anything past
 * `STEP1_SIGNATURE_PERSISTED` is a crash resume: the material at and below that rung is already
 * durable and is reused byte-for-byte. Typed as a subset of {@link AttemptPhase} so a rename in
 * the frozen ladder breaks compilation here rather than silently narrowing to `never`.
 */
export type ReceiveSettleEntryPhase = Extract<
  AttemptPhase,
  "STEP1_SIGNATURE_PERSISTED" | "STEP2_PREIMAGE_PERSISTED" | "STEP2_SIGNATURE_PERSISTED"
>;

/**
 * One durable receive attempt as the row actually stands. Every text field is the exact
 * persisted bytes; nothing here is re-derived from a parsed object.
 */
export interface ReceiveSettleAttempt {
  readonly operationId: string;
  /** The receive-attempt identity the submit claim is minted against. */
  readonly receiveAttemptId: string;
  readonly receiverWalletId: string;
  /**
   * The receiver public key the wallets row carries. It is not trusted as the signing key: it
   * is compared to the key the SIGNED inner names for step 2, and the settle refuses on any
   * disagreement (see {@link verifyPersistedCandidate}).
   */
  readonly receiverPublicKey: string;
  readonly leaseEpoch: bigint;
  /** Exact bytes of the payer's inner preimage as captured before parsing (step 2). */
  readonly innerPreimageText: string;
  /** The payer's detached step-1 signature over {@link innerPreimageText}. */
  readonly payerStep1Signature: string;
  /** The durable ladder position this pass enters at. */
  readonly attemptPhase: ReceiveSettleEntryPhase;
  /** Persisted step 9 text. Required from `STEP2_PREIMAGE_PERSISTED` on. */
  readonly step2PreimageText?: string | null;
  /** Persisted step 11 signature. Required at `STEP2_SIGNATURE_PERSISTED`. */
  readonly step2Signature?: string | null;
  /** Persisted step 11 body. Required at `STEP2_SIGNATURE_PERSISTED`. */
  readonly completedTransactionText?: string | null;
}

/**
 * Confirm-read step 1: one read of the receiver wallet's authoritative head through the bounded
 * read path (`get_transaction__v1`), reduced to the one field that answers "is the head my
 * transaction?" — the head body's `step_2_signature`, read straight off the parsed envelope.
 *
 * A signature is used rather than a body digest deliberately: it is a scalar the envelope parse
 * already yields, so nothing has to re-serialize a gateway-supplied object to compare it, and
 * two distinct transactions cannot share one (the byte-exact signing rule stays out of the reconcile path).
 *
 * `null` means the wallet has no readable head (genesis, or a response the envelope stage
 * refused). That is not evidence of non-landing — see {@link settleReceiveAttempt}.
 */
export type ReadReceiverHeadStep2Signature = (
  receiverPublicKey: string,
) => Promise<string | null>;

export interface ReceiveSettleDeps {
  /** Statement seam for the two one-way phase advances. Driver-free. */
  readonly query: SqlQueryFn;
  readonly signerDeps: SignerBoundaryDeps & MoneyPathSignerGates;
  readonly claimStore: SubmitClaimStore;
  readonly submitOptions: SubmitGatewayActionOptions;
  /** The single initial submit decision created with the step 11 commit. */
  readonly submitDecisionId: string;
  /**
   * The confirm-read. Required, not optional: a resume that could not observe would have
   * to choose between stranding the attempt and resubmitting blind, and neither is admissible.
   */
  readonly readReceiverHeadStep2Signature: ReadReceiverHeadStep2Signature;
  readonly nowIso?: NowIsoFn;
  readonly metricsHooks?: MetricsHooks;
}

export interface ReceiveSettleSignedMaterial {
  readonly step2PreimageText: string;
  readonly step2PreimageSha256: string;
  readonly step2Signature: string;
  readonly completedTransactionText: string;
  readonly completedTransactionSha256: string;
}

export type ReceiveSettleOutcome =
  | ({
      readonly kind: "SUBMITTED";
      readonly claim: ReceiveSubmitClaim;
    } & ReceiveSettleSignedMaterial)
  /**
   * Step 13: the submit outcome is unknown, or another worker already owned the one
   * claim. Both mean the same thing to the caller — reconcile by observation
   * (`get_transaction__v1`). Never submit again (the never-blind-retry rule).
   */
  | ({
      readonly kind: "RECONCILE_REQUIRED";
      readonly claim: ReceiveSubmitClaim;
      readonly reason: ReconcileIndeterminateReason;
    } & ReceiveSettleSignedMaterial)
  /**
   * The confirm-read answered the no-blind-retry question for a resumed attempt: the receiver's
   * authoritative head IS this attempt's signed body, so the one submit reached the chain and
   * must never be repeated.
   *
   * This is NOT a landing-path oracle landing proof and confers no landing authority — proving a landing is
   * the any-depth oracle's job (verifier/landing-path-oracle.ts) and the commit to
   * RECEIVE_LANDED is receive/landing-commit.ts. This outcome only closes the resubmit
   * question, which is the one this module is allowed to answer.
   */
  | ({
      readonly kind: "OBSERVED_AT_HEAD";
    } & ReceiveSettleSignedMaterial)
  | {
      readonly kind: "REJECTED";
      readonly reason: ReceiveSettleRejection;
      readonly detail: string;
    };

/**
 * Step 8. Parses the persisted exact inner text, byte-compares `JSON.stringify(inner)`
 * against it, and revalidates the persisted payer step-1 signature against those exact bytes.
 *
 * Both checks run before any step-2 material is constructed: a drifted preimage or an invalid
 * payer signature must never reach the receiver signer.
 */
export function verifyPersistedCandidate(attempt: ReceiveSettleAttempt): ReceiveSettleRejection | null {
  let parsed: unknown;
  try {
    assertPersistedInnerRoundTrips(attempt.innerPreimageText);
    parsed = JSON.parse(attempt.innerPreimageText);
  } catch {
    return "PREIMAGE_DRIFT";
  }
  // The payer key is read out of the signed inner, never taken as a separate row field: a
  // signature only means anything against the key the signed text itself names (the exact
  // key-role rule). A row that disagreed with the inner could otherwise pick its own verifier.
  const payerPubkey = (parsed as { readonly step_1_key_public__base64urlsafe?: unknown })
    .step_1_key_public__base64urlsafe;
  if (typeof payerPubkey !== "string" || payerPubkey.length === 0) {
    return "PREIMAGE_DRIFT";
  }
  const valid = verifyRawEd25519({
    publicKeyBytes: Buffer.from(payerPubkey, "base64url"),
    preimageBytes: Buffer.from(attempt.innerPreimageText, "utf8"),
    signatureBytes: Buffer.from(attempt.payerStep1Signature, "base64url"),
  });
  if (!valid) return "PAYER_STEP1_SIGNATURE_INVALID";
  // The same discipline applied to the payer, applied to the key this node is about to sign
  // WITH: the row field is checked against the key the signed inner names for step 2, never
  // used on its own authority. A row that disagreed with the inner would otherwise have the
  // node produce a step-2 signature by a key the transaction does not name — a burned
  // one-shot claim for a body the chain can never accept. Same check as the MOVE twin
  // (core/move-form-inner.ts, destination_pubkey vs step_2_key_public__base64urlsafe).
  const receiverPubkey = (parsed as { readonly step_2_key_public__base64urlsafe?: unknown })
    .step_2_key_public__base64urlsafe;
  if (typeof receiverPubkey !== "string" || receiverPubkey !== attempt.receiverPublicKey) {
    return "RECEIVER_KEY_NOT_NAMED_BY_INNER";
  }
  return null;
}

const isNonEmpty = (value: string | null | undefined): value is string =>
  typeof value === "string" && value.length > 0;

/**
 * Signature equality on the decoded bytes rather than on the text.
 *
 * Everything this node persists carries the PADDED base64url spelling (held on the write
 * path by parseEd25519Signature). The head value does not come from there: it arrives through
 * the envelope stage, which requires a head's `step_2_signature` to be a non-empty string
 * and nothing more — canonical scalar validation is a later stage, not the envelope's.
 * So a gateway that emitted the unpadded
 * spelling would make a text comparison miss, `OBSERVED_AT_HEAD` unreachable, and every resumed
 * attempt fall through to the claim check. Two spellings of one signature are one signature.
 */
const isSameSignature = (head: string, persisted: string): boolean =>
  Buffer.from(head, "base64url").equals(Buffer.from(persisted, "base64url"));

const REJECTION_DETAILS: Record<ReceiveSettleRejection, string> = {
  PREIMAGE_DRIFT: "persisted inner preimage did not survive a byte-exact JSON round trip",
  PAYER_STEP1_SIGNATURE_INVALID:
    "persisted payer step-1 signature does not verify against the exact persisted inner text",
  RECEIVER_KEY_NOT_NAMED_BY_INNER:
    "the receiver key on the row is not the step-2 key the signed inner names",
  RESUME_MATERIAL_MISSING:
    "the durable phase claims step-2 material this row does not carry; a resume never rebuilds it",
};

const reject = (operationId: string, reason: ReceiveSettleRejection): ReceiveSettleOutcome => ({
  kind: "REJECTED",
  reason,
  detail: `operation ${operationId}: ${REJECTION_DETAILS[reason]}`,
});

/**
 * Steps 8–13 for one durable candidate: revalidate, persist the step-2 preimage, co-sign
 * under the receiver lease, persist the signature and completed body, and submit exactly once.
 *
 * The one-in-flight-per-wallet rule is enforced structurally rather than by a check here: step 10 goes through
 * {@link signUnderLease}, which re-reads `wallet_active_leases` and refuses unless THIS
 * operation holds the receiver wallet's active lease at this epoch. A second operation on the
 * same wallet therefore cannot reach step 12 at all, so no second in-flight transaction for the
 * wallet can ever be formed — there is no path around the signer to guard separately.
 *
 * A pass entered at `STEP2_SIGNATURE_PERSISTED` is the exception that proves it: it has nothing
 * left to sign, so it reaches step 12 without crossing the chokepoint. That branch restates
 * leadership and the operate gate itself before it observes or submits — see below.
 *
 * The never-blind-retry rule is enforced twice over. {@link receiveSubmitOnce}'s arbitrated claim is the
 * structural half: this function calls it once and has no retry branch, so a second pass over
 * an attempt whose submit already started finds the claim lost and skips the gateway entirely.
 * The observational half is {@link ReceiveSettleDeps.readReceiverHeadStep2Signature}: a pass
 * entered at `STEP2_SIGNATURE_PERSISTED` confirm-reads the receiver head before it goes near
 * the submit path at all, so the ambiguous case is reconciled rather than retried.
 */
export async function settleReceiveAttempt(
  attempt: ReceiveSettleAttempt,
  deps: ReceiveSettleDeps,
): Promise<ReceiveSettleOutcome> {
  const nowIso = deps.nowIso ?? defaultNowIso;

  // Step 8 — guard before any construction, on a resume as much as on a first pass.
  const rejection = verifyPersistedCandidate(attempt);
  if (rejection !== null) return reject(attempt.operationId, rejection);

  const resuming = attempt.attemptPhase !== "STEP1_SIGNATURE_PERSISTED";

  // Step 8 (construction) — splice the persisted inner verbatim; nothing re-serializes it.
  // On a resume the step-2 preimage is already durable and the receiver signer may already have
  // seen those exact bytes, so they are read back rather than rebuilt: re-deriving would make
  // the signed text and the stored text two separately produced things (the byte-exact signing rule).
  let step2PreimageText: string;
  if (resuming) {
    if (!isNonEmpty(attempt.step2PreimageText)) {
      return reject(attempt.operationId, "RESUME_MATERIAL_MISSING");
    }
    step2PreimageText = attempt.step2PreimageText;
  } else {
    step2PreimageText = buildStep2PreimageText(
      attempt.innerPreimageText,
      attempt.payerStep1Signature,
    );
  }
  const step2PreimageSha256 = hashPreimageText(step2PreimageText);

  // Step 9 — DB-TX commits BEFORE the receiver signer is called. The signer reads only the
  // persisted step-2 preimage, so a crash between here and step 10 resumes from durable text.
  if (!resuming) {
    await advanceAttemptPhase(deps.query, attempt.operationId, "STEP2_PREIMAGE_PERSISTED", {
      step_2_preimage_text: step2PreimageText,
      step_2_preimage_sha256: step2PreimageSha256,
    });
  }

  let step2Signature: string;
  let completedTransactionText: string;
  if (attempt.attemptPhase === "STEP2_SIGNATURE_PERSISTED") {
    // Steps 10 and 11 are already durable. Signing again would be a second call to the money
    // signer for one attempt, and the one-way UPDATE would refuse the advance anyway.
    if (!isNonEmpty(attempt.step2Signature) || !isNonEmpty(attempt.completedTransactionText)) {
      return reject(attempt.operationId, "RESUME_MATERIAL_MISSING");
    }
    step2Signature = attempt.step2Signature;
    completedTransactionText = attempt.completedTransactionText;
  } else {
    // Step 10 — SIGN(step_2_preimage_id) under the receiver lease capability. This is the
    // signing chokepoint: leadership, money gates, lease re-read, vault unseal, and audit all live
    // inside it. It returns a signature and a digest, never key material (the key-custody rule).
    const signed = await signUnderLease(deps.signerDeps, {
      walletId: attempt.receiverWalletId,
      operationId: attempt.operationId,
      leaseEpoch: attempt.leaseEpoch,
      purpose: RECEIVE_STEP2_PURPOSE,
      preimageText: step2PreimageText,
      expectedPreimageSha256: step2PreimageSha256,
    });
    step2Signature = signed.signature;

    // Step 11 — the settled body is derived from the persisted step-2 preimage, so the
    // completed transaction cannot disagree with the bytes the receiver signer actually saw.
    completedTransactionText = buildCompletedTransactionText(step2PreimageText, step2Signature);
    // the one-in-flight-per-wallet rule: the lease read inside signUnderLease and this write are separate
    // autocommit statements, so a release committed between them would leave a step-2 signature
    // durable — and submittable below — under a lease this node no longer holds. The advance
    // carries the same capability the signer used, re-checked under a row lock as it commits, so
    // a concurrent release and this signature can never both succeed.
    await advanceAttemptPhase(
      deps.query,
      attempt.operationId,
      "STEP2_SIGNATURE_PERSISTED",
      {
        step_2_signature: step2Signature,
        completed_transaction_text: completedTransactionText,
        completed_transaction_sha256: hashPreimageText(completedTransactionText),
      },
      {
        walletId: attempt.receiverWalletId,
        operationId: attempt.operationId,
        leaseEpoch: attempt.leaseEpoch,
      },
    );
  }
  const completedTransactionSha256 = hashPreimageText(completedTransactionText);

  const material: ReceiveSettleSignedMaterial = {
    step2PreimageText,
    step2PreimageSha256,
    step2Signature,
    completedTransactionText,
    completedTransactionSha256,
  };

  if (attempt.attemptPhase === "STEP2_SIGNATURE_PERSISTED") {
    // This is the one route to the gateway that does NOT pass through signUnderLease: steps 10
    // and 11 are already durable, so there is nothing left to sign and the signing chokepoint is
    // not standing between this pass and the wire. The gates it would have applied are restated
    // here rather than assumed — a node that lost signer leadership during an overlapping
    // deployment, or whose engines have quiesced, must not push a money body merely because the
    // body was signed before the loss (the signing chokepoint and custody claim boundary).
    // assertWalletMaySign is
    // deliberately not restated: it guards the act of signing, and nothing is signed here.
    // assertMoneyAdmitted is applied per tick by the caller.
    assertSignerLeadership(deps.signerDeps.leadership);
    deps.signerDeps.assertCanOperate();

    // Confirm-read / the never-blind-retry rule. This body was durable before this pass began, so a submit
    // MAY already have crossed the wire. Observe the receiver's authoritative head BEFORE any
    // submit path is entered: a resumed attempt is never blind-resubmitted.
    const headSignature = await deps.readReceiverHeadStep2Signature(attempt.receiverPublicKey);
    if (headSignature !== null && isSameSignature(headSignature, step2Signature)) {
      return { kind: "OBSERVED_AT_HEAD", ...material };
    }
    // A head that is not this body proves neither landed nor non-landed (the closing rule),
    // so it is deliberately NOT what authorises the submit below. That authority is the durable
    // claim: receiveSubmitOnce mints before crossing the irreversible boundary, so a claim
    // exists if and only if a submit was started. The mint therefore submits only when no
    // submit ever started, and otherwise returns AMBIGUOUS without touching the gateway.
  }

  // Step 12 — claim and invoke SUBMIT(attempt_1) once. The request carries the three-key
  // settled shape as its action data; the inner is handed over as the exact parsed persisted
  // object so no field is reordered on the way out (the byte-exact signing rule).
  const settled = JSON.parse(completedTransactionText) as Record<string, unknown>;
  const signedRequest = buildGatewayActionRequest(RECEIVE_SUBMIT_ACTION_NAME, settled);

  const result = await receiveSubmitOnce({
    receiveAttemptId: attempt.receiveAttemptId,
    signedRequest,
    authorization: {
      submitDecisionId: deps.submitDecisionId,
      operationId: attempt.operationId,
      transactionAttemptNo: 1,
    },
    submitOptions: deps.submitOptions,
    claimStore: deps.claimStore,
    nowIso,
    metricsHooks: deps.metricsHooks,
  });

  if (result.kind === "AMBIGUOUS") {
    // Step 13 / the never-blind-retry rule. No resubmit, no rebuild — the caller reconciles by
    // observation and the receiver lease stays held.
    return { kind: "RECONCILE_REQUIRED", claim: result.claim, reason: result.reason, ...material };
  }

  return { kind: "SUBMITTED", claim: result.claim, ...material };
}
