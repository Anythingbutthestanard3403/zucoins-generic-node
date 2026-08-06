// Offline unit proof of the RECEIVE_EXTERNAL execute ceremony.
//
// Real Ed25519 keys are generated per test so step-1/step-2 signatures are genuine;
// no network, no database, no wallet file. The live runner substitutes real adapters.
//

import {
  createHash,
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  addZkz,
  parsePositiveZkzAmount,
  parseZkzBalance,
  subtractZkz,
} from "../../src/protocol/amounts.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "../../src/protocol/wallet-role.js";
import {
  parseGatewayEnvelope,
  type ParsedSettledTransaction,
} from "../../src/verifier/gateway-envelope.js";
import type { FreshHeadRead } from "../../src/verifier/landing-path-oracle.js";
import { verifySettledTransaction } from "../../src/verifier/transaction-verify.js";

import { RECEIVE_AMOUNT_HARD_CAP } from "./receive-preflight.js";
import { createRunnerLock } from "./runner-lock.js";
import {
  evaluateReceiveLandingPredicates,
  executeAuthorizedReceiveExternal,
  type ReceiveExecuteDeps,
  type ReceiveExecuteDisposition,
  type ReceiveExecuteInput,
  type ReceiveLandingPathEvidence,
  type ReceiveObservation,
  type ReceiveRowCounts,
  type ReceiveSubmitOutcomeKind,
} from "./receive-execute.js";
import {
  SAMPLE_PAYER_KEYHOLDER,
  SAMPLE_RECEIVE_OPERATION_ID,
  SAMPLE_RECEIVE_PAYER_ADDRESS,
  SAMPLE_RECEIVE_RECEIVER_ID,
  fakeReceiveProbe,
  readyReceiveStateWithOperation,
  sampleReceiveAuth,
  sampleReceiveOperationRow,
} from "./receive-fakes.js";

/** The fake mutates its counters as the ceremony advances; evidence exposes them readonly. */
type MutableReceiveRowCounts = { -readonly [K in keyof ReceiveRowCounts]: ReceiveRowCounts[K] };

// ─── Ed25519 helpers ─────────────────────────────────────────────────────────

function toPaddedBase64Url(bytes: Buffer): string {
  return bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function ed25519Pair(): {
  privateKey: KeyObject;
  publicKey: string;
  sign: (text: string) => string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const rawPub = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  return {
    privateKey,
    publicKey: toPaddedBase64Url(Buffer.from(rawPub)),
    sign: (text: string) =>
      toPaddedBase64Url(edSign(null, Buffer.from(text, "utf8"), privateKey)),
  };
}

// ─── chain vectors ───────────────────────────────────────────────────
//
// The buried-landing tests need REAL settled bodies on the receiver wallet, because the
// oracle reverifies every one from its exact signed bytes. These helpers build them; the
// fake node below chains them onto the attempt the ceremony actually formed, so the walk
// runs over the node's own transaction rather than a look-alike.

/** A gateway HEAD envelope carrying exactly one settled body. */
function headEnvelope(settledText: string): FreshHeadRead {
  return {
    observationId: `obs-head-${createHash("sha256").update(settledText).digest("hex").slice(0, 8)}`,
    envelope: parseGatewayEnvelope(
      new TextEncoder().encode(
        `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
      ),
    ),
  };
}

function parsedBody(settledText: string): ParsedSettledTransaction {
  const verdict = headEnvelope(settledText).envelope;
  if (verdict.classification !== "HEAD") {
    throw new Error(`expected HEAD envelope verdict, got ${verdict.classification}`);
  }
  return verdict.parsed;
}

/**
 * One settled `unique_combinable` v2 transaction, signed for real in the order:
 * step 1 over `JSON.stringify(inner)` by the sender key, step 2 over
 * `JSON.stringify({inner, step_1_signature})` by the receiver key. Byte-exact — the field
 * order below IS the signed preimage (the byte-exact signing rule).
 */
function settledTx(spec: {
  readonly sender: ReturnType<typeof ed25519Pair>;
  readonly receiver: ReturnType<typeof ed25519Pair>;
  readonly senderRemaining: string;
  readonly receiverAmount: string;
  readonly previousStep1: string;
  readonly previousStep2: string;
  readonly unixTimeSecs: string;
}): { readonly text: string; readonly body: ParsedSettledTransaction } {
  const inner = {
    type: "unique_combinable" as const,
    version: "2" as const,
    unix_time_secs: spec.unixTimeSecs,
    signer_steps: 2 as const,
    step_1_signer: "sender" as const,
    step_2_signer: "receiver" as const,
    step_1_key_public__base64urlsafe: spec.sender.publicKey,
    step_2_key_public__base64urlsafe: spec.receiver.publicKey,
    step_1_state: { amount: spec.senderRemaining },
    step_2_state: { amount: spec.receiverAmount },
    previous_step_1_state_signature: spec.previousStep1,
    previous_step_2_state_signature: spec.previousStep2,
  };
  const step1Signature = spec.sender.sign(JSON.stringify(inner));
  const step2Signature = spec.receiver.sign(
    JSON.stringify({ inner, step_1_signature: step1Signature }),
  );
  const text = JSON.stringify({
    inner,
    step_1_signature: step1Signature,
    step_2_signature: step2Signature,
  });
  return { text, body: parsedBody(text) };
}

/** Role-relative projection read back out of a body by the verifier the oracle also uses. */
function projectionOf(body: ParsedSettledTransaction, wallet: string): WalletStateProjection {
  const verdict = verifySettledTransaction(body, wallet);
  if (verdict.verdict !== "VERIFIED") {
    throw new Error(`fixture body does not verify for ${wallet}: ${verdict.verdict}`);
  }
  return verdict.projection;
}

// ─── Deterministic fake node ─────────────────────────────────────────────────

const ATTEMPT_ID = "attempt-receive-1";
const NODE_CLOCK_MS = 1_785_153_600_123;

function observation(
  role: ReceiveObservation["role"],
  publicKey: string,
  projection: WalletStateProjection,
  body: string,
): ReceiveObservation {
  return {
    role,
    publicKey,
    observationId: `obs-${role}`,
    projection,
    rawResponseSha256: createHash("sha256").update(body, "utf8").digest("hex"),
    rawResponseByteLength: Buffer.byteLength(body, "utf8"),
  };
}

interface FakeNode {
  readonly deps: ReceiveExecuteDeps;
  readonly input: ReceiveExecuteInput;
  readonly counts: {
    leaseCalls: number;
    gatewayReads: number;
    signerCalls: number;
    armCalls: number;
    submitCalls: number;
    readsBeforeLease: number;
    candidateWrites: number;
    signedWrites: number;
  };
  readonly rows: MutableReceiveRowCounts;
  readonly signedTexts: string[];
  readonly receiver: ReturnType<typeof ed25519Pair>;
  readonly payer: ReturnType<typeof ed25519Pair>;
}

interface FakeNodeOptions {
  readonly amount?: string;
  readonly payerBalance?: string;
  readonly leaseFails?: boolean;
  readonly signFails?: boolean;
  /**
   * Signer RESOLVES this text instead of signing. A seam that returns garbage rather than
   * throwing is the other live guard behind the ceremony's `catch (err)` at the step-2 sign
   * — `parseEd25519Signature(step2Signature)` — which `signFails` cannot reach, because a
   * throwing seam refuses before the parse ever runs.
   */
  readonly signReturns?: string;
  readonly submitOutcome?: ReceiveSubmitOutcomeKind;
  readonly landingFound?: boolean;
  /** Corrupt one landing predicate so coordinator must escalate. */
  readonly landingBreak?: "settled" | "predecessor" | "balance";
  /**
   * Report ONE flag false while every operand stays truthful. `landingBreak` corrupts the
   * operand too, so the downstream operand bind escalates whether or not the flag clause is
   * read at all — these isolate the flag clause itself.
   */
  readonly landingFlagLie?: "settled" | "predecessor" | "balance";
  /**
   * Landing seam that asserts all three predicates true while reporting operands that are
   * not ours. Only an coordinator that binds the operands — not just the flags — refuses.
   * The single-operand modes lie about exactly one, so each half of the coordinator's
   * bind is falsifiable on its own rather than only as a pair.
   */
  readonly landingLiesAboutOperands?: "both" | "step2-only" | "balance-only";
  /**
   * Receiver head at RECEIVE_T0. "non-genesis" gives S !== P, which is the only shape in
   * which comparing the candidate against S0 is distinguishable from comparing it to P0.
   */
  readonly receiverT0?: "genesis" | "non-genesis";
  readonly forceT0ObserveBeforeLease?: boolean;
  readonly armFails?: boolean;
  /**
   * Corrupt exactly one input the external payer supplies. The four candidate-validation variants
   * leave the receiver link, both economic deltas and the byte-exact re-stringify intact,
   * so an abort is attributable to the step-3 check alone. `links-to-p0` inverts that: it
   * breaks the receiver link and nothing else. `reformatted-json` breaks only
   * the byte-exact re-stringify — every field value stays valid and the payer
   * genuinely signs the reformatted bytes. The last four break exactly one of the four
   * remaining candidate-intake facts: the receiver credit, the step-2 key role, the
   * sender link and the sender debit. Every variant is genuinely payer-signed over its own
   * bytes, so only the named guard can reject it. The last two corrupt the signature SCALAR
   * and nothing else — the inner, and therefore the step-1 key it names, stays intact, so
   * the refusal is attributable to the signature's grammar rather than to the key.
   */
  readonly corruptStep1?:
    | "forged-signature"
    | "unparseable-signature"
    | "short-signature"
    | "wrong-step1-key"
    | "stale-expiry"
    | "mutated-message"
    | "links-to-p0"
    | "reformatted-json"
    | "receiver-delta"
    | "wrong-step2-key"
    | "links-to-sender-p"
    | "sender-delta";
  /**
   * Corrupt what the persist seam READS BACK, leaving the candidate that passed intake
   * step 3 untouched. Only the step-8 revalidation of the persisted bytes can catch
   * either variant, and each is caught by a different one of its two checks.
   */
  readonly corruptPersistedStep1?: "mangled-text" | "substituted-candidate";
  /**
   * Wire the optional `collectReceiverLandingPath` seam over a REAL receiver
   * chain. Absent (the default) means the node retained nothing to walk, which every
   * pre-existing test relies on.
   *
   * The chain is anchored on the settled body the ceremony itself formed, recovered from
   * the fake's own persist record — never rebuilt from the arguments the seam is handed.
   */
  readonly landingPath?: {
    /** Genuine burial hops chained onto our attempt. 0 leaves our attempt at the head. */
    readonly successors?: number;
    /**
     * Return a foreign body as `expectedBody` — a different real inbound of the SAME amount
     * to the SAME receiver, which satisfies every oracle predicate. Only an coordinator
     * that binds `expectedBody` back to its own persisted bytes refuses it.
     */
    readonly decoyExpectedBody?: boolean;
    /**
     * Return our own attempt's bytes with the node's step-2 co-signature swapped for a
     * foreign one. Everything the byte-exact bind reads is otherwise ours, so this is the
     * only mode that reaches the bind's `verdict !== "VERIFIED"` arm.
     */
    readonly forgedExpectedStep2?: boolean;
    /** Replace the successor at this depth (1-based) with a body that does not back-link. */
    readonly decoyAtDepth?: number;
    /** Supply no successors while the head has advanced — the walk cannot bridge. */
    readonly withholdSuccessors?: boolean;
    /** Answer the oracle's two confirm-reads with different heads. */
    readonly headMovesDuringWalk?: boolean;
    /** The seam exists but retained nothing for this attempt. */
    readonly retainedNothing?: boolean;
    /** The seam read throws. */
    readonly throws?: boolean;
    /** The oracle's confirm-read throws, so the walk itself throws (not the seam read). */
    readonly freshHeadThrows?: boolean;
    /**
     * Hand back an `expectedBody` with no well-formed `inner`.
     * `verifySettledTransaction` throws (Object.keys on undefined) instead of returning a
     * verdict; the coordinator's identity-bind catch must map that to LANDING_INDETERMINATE
     * so the throw cannot strand `runnerLockHandle`.
     */
    readonly malformedExpectedBody?: boolean;
  };
}

function makeFakeNode(options: FakeNodeOptions = {}): FakeNode {
  const receiver = ed25519Pair();
  const payer = ed25519Pair();
  // An unauthorized keyholder used only by the corruptStep1 variants.
  const imposter = ed25519Pair();
  const amount = options.amount ?? "0.000001";
  const payerBalance = options.payerBalance ?? "1";
  // Synthetic head for the funded payer. S !== P for the same reason the receiver head is
  // non-genesis below: only a payer whose two link fields differ can tell a candidate linked
  // to sender S0 apart from one linked to sender P0 (step 5 / receive-execute.ts:936).
  const payerHeadSig = ed25519Pair().sign("payer-prior-settled");
  const payerPrevStep1Sig = ed25519Pair().sign("payer-prior-step-1");
  // A REAL receiver T0 body, needed only when the landing-path seam is wired: the
  // oracle re-derives the T0 baseline from exact signed text, so a synthetic projection has
  // no body to re-derive from. The projection below is read back OUT of the body by the same
  // verifier the oracle uses, so the fixture cannot drift from the bytes it ships.
  const t0Payer = ed25519Pair();
  const chainT0 =
    options.landingPath === undefined
      ? null
      : settledTx({
          sender: t0Payer,
          receiver,
          senderRemaining: "9",
          receiverAmount: "1",
          previousStep1: "",
          previousStep2: "",
          unixTimeSecs: "1785153000",
        });
  // Receiver head at T0. Genesis has S === P === "", so only the non-genesis shape can
  // tell a candidate linked to S0 apart from one linked to P0.
  const receiverT0Projection: WalletStateProjection =
    chainT0 !== null
      ? projectionOf(chainT0.body, receiver.publicKey)
      : options.receiverT0 === "non-genesis"
        ? {
            role: "receiver",
            S: ed25519Pair().sign("receiver-prior-step-2"),
            P: ed25519Pair().sign("receiver-prior-step-1"),
            // Canonical ZKZ carries no trailing zeros — "0.500000" is rejected outright.
            B: "0.5",
            I: "e".repeat(64),
          }
        : GENESIS_PROJECTION;

  const counts = {
    leaseCalls: 0,
    gatewayReads: 0,
    signerCalls: 0,
    armCalls: 0,
    submitCalls: 0,
    readsBeforeLease: 0,
    candidateWrites: 0,
    signedWrites: 0,
  };
  const rows: MutableReceiveRowCounts = {
    receiverLeases: 0,
    armAcknowledgements: 0,
    candidates: 0,
    step2Preimages: 0,
    step2Signatures: 0,
    submitDecisions: 0,
    gatewaySubmitAttempts: 0,
  };
  const signedTexts: string[] = [];
  let leaseHeld = false;
  let persistedCode: string | null = null;
  let persistedSettled: string | null = null;
  let persistedStep2: string | null = null;

  const deps: ReceiveExecuteDeps = {
    leases: {
      acquireReceiverLease: async ({ operationId, receiverWalletId }) => {
        counts.leaseCalls += 1;
        if (options.leaseFails === true) {
          throw new Error("receiver wallet already has an active lease");
        }
        leaseHeld = true;
        rows.receiverLeases = 1;
        return {
          walletId: receiverWalletId,
          operationId,
          leaseEpoch: 3n,
          role: "RECEIVER",
          lifecycle: "ACTIVE",
        };
      },
    },
    observe: {
      observeVerified: async ({ publicKey, role }) => {
        counts.gatewayReads += 1;
        if (!leaseHeld) counts.readsBeforeLease += 1;
        if (role === "RECEIVE_T0") {
          return observation(
            role,
            publicKey,
            receiverT0Projection,
            '{"status":true,"role":"RECEIVE_T0"}',
          );
        }
        // Sender preflight: funded payer head, S !== P.
        const proj: WalletStateProjection = {
          role: "sender",
          S: payerHeadSig,
          P: payerPrevStep1Sig,
          B: payerBalance,
          I: "d".repeat(64),
        };
        return observation(role, publicKey, proj, '{"status":true,"role":"SENDER"}');
      },
      observeReceiverLanding: async ({
        persistedSettledTransactionText,
        persistedStep2Signature,
        receiverT0S0,
        receiverT0B0,
        amount: amt,
      }) => {
        counts.gatewayReads += 1;
        if (options.landingFound === false) return null;
        // The head this seam reports comes from the fake's OWN chain state, never from the
        // operands it was handed. An echo cannot contradict its source: a seam that derives
        // `observedP` from the `receiverT0S0` argument makes the comparison `x === x`, so
        // every coordinator-side operand choice is confirmed tautologically and every guard
        // reading it is unfalsifiable by construction, however many mutations are run at it.
        // The arguments below are used only as the PERSISTED side of the comparison — the
        // coordinator's own view — which is exactly the split the live adapter has (a fresh
        // `get_transaction__v1` on one side, what we wrote on the other).
        const chainSettled = persistedSettled;
        const chainStep2 = persistedStep2;
        const chainReceiverS0 = receiverT0Projection.S;
        const chainReceiverB1 = String(
          addZkz(parseZkzBalance(receiverT0Projection.B), parsePositiveZkzAmount(amount)),
        );
        if (options.landingLiesAboutOperands !== undefined) {
          // A seam that asserts the ceremony landed while handing back a head that is not
          // ours. The flags are the seam's own claim; the operands contradict them. Each
          // mode leaves the other operand truthful, so the two halves of the coordinator's
          // operand bind fail independently.
          const lie = options.landingLiesAboutOperands;
          return {
            publicKey: receiver.publicKey,
            observationId: "obs-landing-decoy",
            step2Signature:
              lie === "balance-only" ? (chainStep2 ?? "") : "DECOY-STEP2-SIGNATURE-NOT-OURS",
            balanceAfter: lie === "step2-only" ? chainReceiverB1 : "999.999999",
            balanceDeltaMatchesAmount: true,
            predecessorMatchesT0S0: true,
            settledTextMatchesPersisted: true,
            rawResponseSha256: createHash("sha256").update("decoy", "utf8").digest("hex"),
            rawResponseByteLength: 5,
            observedAtIso: "2026-07-28T00:00:01.000Z",
          };
        }
        // Happy path: the chain carries what the node actually wrote, the receiver head's
        // own S0, and its own B0+amount. No head is visible until the settled body was
        // persisted — that is the truthful model, not a fall-back to the argument.
        if (chainSettled === null || chainStep2 === null) return null;
        const observedSettled =
          options.landingBreak === "settled" ? chainSettled + "\n" : chainSettled;
        const observedStep2 =
          options.landingBreak === "settled" ? "wrong-step2-signature" : chainStep2;
        const observedP =
          options.landingBreak === "predecessor" ? "wrong-predecessor-S" : chainReceiverS0;
        const observedB =
          options.landingBreak === "balance"
            ? String(addZkz(parseZkzBalance(chainReceiverB1), parsePositiveZkzAmount("0.000001")))
            : chainReceiverB1;
        const flags = evaluateReceiveLandingPredicates({
          headPresent: true,
          observedSettledTransactionText: observedSettled,
          persistedSettledTransactionText,
          observedStep2Signature: observedStep2,
          persistedStep2Signature,
          observedP,
          receiverT0S0,
          observedB,
          receiverT0B0,
          amount: amt,
        });
        if (flags === null) return null;
        const flagLie = options.landingFlagLie;
        return {
          publicKey: receiver.publicKey,
          observationId: "obs-landing",
          step2Signature: observedStep2,
          balanceAfter: observedB,
          balanceDeltaMatchesAmount:
            flagLie === "balance" ? false : flags.balanceDeltaMatchesAmount,
          predecessorMatchesT0S0:
            flagLie === "predecessor" ? false : flags.predecessorMatchesT0S0,
          settledTextMatchesPersisted:
            flagLie === "settled" ? false : flags.settledTextMatchesPersisted,
          rawResponseSha256: createHash("sha256").update("landing", "utf8").digest("hex"),
          rawResponseByteLength: 7,
          observedAtIso: "2026-07-28T00:00:01.000Z",
        };
      },
      ...(options.landingPath === undefined
        ? {}
        : {
            /**
             * An INDEPENDENT miniature receiver chain, not an echo.
             *
             * The bodies returned here are built from the fake's own chain state: `chainT0`
             * (formed before the ceremony ran) and `persistedSettled` (recorded by the
             * persist seam when the node wrote its signed body). The two arguments are used
             * ONLY as a lookup key deciding whether this seam has anything for the attempt
             * being asked about — never as the value returned. A seam that parsed
             * `persistedSettledTransactionText` into the body it hands back would make the
             * coordinator's identity bind `x === x` and unfalsifiable by construction,
             * which is exactly what the decoy modes below exist to disprove.
             */
            collectReceiverLandingPath: async ({
              persistedSettledTransactionText,
              persistedStep2Signature,
            }): Promise<ReceiveLandingPathEvidence | null> => {
              const spec = options.landingPath;
              if (spec === undefined) return null;
              if (spec.throws === true) throw new Error("landing-path read unavailable");
              if (spec.retainedNothing === true) return null;
              if (chainT0 === null || persistedSettled === null || persistedStep2 === null) {
                return null;
              }
              // Lookup-key use: this seam only answers for the attempt it actually retained.
              if (
                persistedSettledTransactionText !== persistedSettled ||
                persistedStep2Signature !== persistedStep2
              ) {
                return null;
              }
              const ourBody = parsedBody(persistedSettled);
              // A different REAL inbound of the same amount to the same receiver, chained off
              // the same T0. It satisfies every oracle predicate our attempt satisfies —
              // signatures, backlink, economic delta — and differs only in payer and
              // `unix_time_secs`. Only the coordinator's byte-exact bind tells them apart.
              const decoy = settledTx({
                sender: ed25519Pair(),
                receiver,
                senderRemaining: "7",
                receiverAmount: String(
                  addZkz(
                    parseZkzBalance(receiverT0Projection.B),
                    parsePositiveZkzAmount(amount),
                  ),
                ),
                previousStep1: chainT0.body.step_1_signature,
                previousStep2: chainT0.body.step_2_signature,
                unixTimeSecs: "1785153911",
              });
              // Our exact persisted prefix with only the node's step-2 co-signature swapped.
              // String surgery on the last field, so every byte the bind compares before it
              // is identical to what this run persisted (the byte-exact signing rule — nothing re-formed).
              const forged = parsedBody(
                persistedSettled.replace(
                  /"step_2_signature":"[^"]*"\}$/,
                  `"step_2_signature":"${ed25519Pair().sign("not-our-step-2")}"}`,
                ),
              );
              const expectedBody: ParsedSettledTransaction =
                spec.malformedExpectedBody === true
                  ? // No `inner` — forces verifySettledTransaction to throw rather than
                    // return a non-VERIFIED verdict. Intentional shape violation.
                    ({} as ParsedSettledTransaction)
                  : spec.decoyExpectedBody === true
                    ? decoy.body
                    : spec.forgedExpectedStep2 === true
                      ? forged
                      : ourBody;

              // Genuine burial hops, each back-linking to the one before it.
              const successors: { text: string; body: ParsedSettledTransaction }[] = [];
              let prev = { text: persistedSettled, body: ourBody };
              let runningB = parseZkzBalance(
                projectionOf(ourBody, receiver.publicKey).B,
              );
              for (let depth = 1; depth <= (spec.successors ?? 0); depth += 1) {
                runningB = addZkz(runningB, parsePositiveZkzAmount("0.5"));
                const linkTo =
                  spec.decoyAtDepth === depth
                    ? // A body that does not continue the chain: it back-links to T0, so the
                      // per-hop `P == S` check breaks at exactly this depth.
                      chainT0
                    : prev;
                const hop = settledTx({
                  sender: ed25519Pair(),
                  receiver,
                  senderRemaining: "6",
                  receiverAmount: String(runningB),
                  previousStep1: linkTo.body.step_1_signature,
                  previousStep2: linkTo.body.step_2_signature,
                  unixTimeSecs: `17851540${10 + depth}`,
                });
                successors.push(hop);
                prev = hop;
              }

              const headText = prev.text;
              let reads = 0;
              return {
                t0Body: chainT0.body,
                expectedBody,
                successorBodies: spec.withholdSuccessors === true
                  ? []
                  : successors.map((s) => s.body),
                readFreshHead: async () => {
                  reads += 1;
                  // The oracle does not wrap this callback, so a throwing confirm-read
                  // propagates out of `proveReceiveLanding` — the only way to reach the
                  // ceremony's landing-walk catch.
                  if (spec.freshHeadThrows === true) {
                    throw new Error("confirm-read transport failed mid-walk");
                  }
                  // The oracle reads the head twice. A head that moved between the two
                  // is CONFLICT, never a stale positive.
                  if (spec.headMovesDuringWalk === true && reads > 1) {
                    return headEnvelope(
                      settledTx({
                        sender: ed25519Pair(),
                        receiver,
                        senderRemaining: "5",
                        receiverAmount: String(addZkz(runningB, parsePositiveZkzAmount("0.5"))),
                        previousStep1: prev.body.step_1_signature,
                        previousStep2: prev.body.step_2_signature,
                        unixTimeSecs: "1785154999",
                      }).text,
                    );
                  }
                  return headEnvelope(headText);
                },
              };
            },
          }),
    },
    arm: {
      armOnce: async ({ transferCodeText }) => {
        counts.armCalls += 1;
        if (counts.armCalls > 1) throw new Error("second arm rejected");
        if (options.armFails === true) throw new Error("t0_mismatch");
        rows.armAcknowledgements = 1;
        return {
          armedAt: "2026-07-28T00:00:00.100Z",
          codeReleasedAt: "2026-07-28T00:00:00.101Z",
          releasedTransferCodeText: transferCodeText,
        };
      },
    },
    signer: {
      signStep2: async ({ preimageText }) => {
        counts.signerCalls += 1;
        if (options.signFails === true) throw new Error("signer unavailable");
        signedTexts.push(preimageText);
        return options.signReturns ?? receiver.sign(preimageText);
      },
    },
    persist: {
      admitOperation: async () => {
        /* CREATED */
      },
      persistFormation: async ({ transferCodeText }) => {
        persistedCode = transferCodeText;
        return { statusAfter: "READY" };
      },
      persistCandidateAndStep2Preimage: async ({ innerPreimageText, step1Signature }) => {
        counts.candidateWrites += 1;
        if (counts.candidateWrites > 1) throw new Error("second candidate rejected");
        rows.candidates = 1;
        rows.step2Preimages = 1;
        // Round-trips what it was handed, the way a real SELECT after the INSERT does.
        // The variants below stand in for storage that mangled the row and for storage
        // that returned somebody else's row.
        if (options.corruptPersistedStep1 === "mangled-text") {
          return {
            step2PreimageId: "step2-preimage-1",
            persistedInnerPreimageText: `${innerPreimageText} `,
            persistedStep1Signature: step1Signature,
          };
        }
        if (options.corruptPersistedStep1 === "substituted-candidate") {
          // A different inner, genuinely signed by the authorized payer: the step-8
          // signature check verifies it, so only the identity check rejects it.
          const other = '{"substituted":"candidate"}';
          return {
            step2PreimageId: "step2-preimage-1",
            persistedInnerPreimageText: other,
            persistedStep1Signature: payer.sign(other),
          };
        }
        return {
          step2PreimageId: "step2-preimage-1",
          persistedInnerPreimageText: innerPreimageText,
          persistedStep1Signature: step1Signature,
        };
      },
      persistSignedAndSubmitDecision: async ({
        step2Signature,
        settledTransactionText,
      }) => {
        counts.signedWrites += 1;
        if (counts.signedWrites > 1) throw new Error("second signed body rejected");
        rows.step2Signatures = 1;
        rows.submitDecisions = 1;
        persistedStep2 = step2Signature;
        persistedSettled = settledTransactionText;
        return { submitDecisionId: "submit-decision-1" };
      },
      recordSubmitAttempt: async () => {
        rows.gatewaySubmitAttempts = 1;
      },
      countRows: async () => ({ ...rows }),
    },
    submit: {
      submitOnce: async () => {
        counts.submitCalls += 1;
        if (counts.submitCalls > 1) {
          throw new Error("INVARIANT: second submit must never be called");
        }
        const outcome = options.submitOutcome ?? "ACK";
        return {
          outcome,
          detail: outcome === "ACK" ? '{"status":true}' : `outcome=${outcome}`,
          rawResponseSha256: createHash("sha256").update("submit", "utf8").digest("hex"),
          rawResponseByteLength: 6,
          gatewayStatusCode: outcome === "ACK" ? 200 : 400,
        };
      },
    },
    payer: {
      buildAndSignStep1: async ({
        receiverT0,
        amount: amt,
        receiverPubkey,
        expiryUnixTimeSecs,
        receiveMessage,
      }) => {
        // Build a byte-exact inner matching economic predicates.
        const senderRemain = subtractZkz(
          parseZkzBalance(payerBalance),
          parsePositiveZkzAmount(amt),
        );
        const receiverAfter = addZkz(
          parseZkzBalance(receiverT0.B),
          parsePositiveZkzAmount(amt),
        );
        const formationFloor = Math.floor(NODE_CLOCK_MS / 1000);
        const unixTimeSecs = `${formationFloor}.123`;
        // Fixed insertion order — A.8.1 sequence (the byte-exact signing rule).
        const inner = {
          type: "unique_combinable",
          version: "2",
          unix_time_secs: unixTimeSecs,
          signer_steps: 2,
          step_1_signer: "sender",
          step_2_signer: "receiver",
          step_1_key_public__base64urlsafe: payer.publicKey,
          step_2_key_public__base64urlsafe: receiverPubkey,
          step_1_state: { amount: String(senderRemain) },
          step_2_state: { amount: String(receiverAfter) },
          // The sender link is the payer's own settled head S0 — never its P0.
          previous_step_1_state_signature:
            options.corruptStep1 === "links-to-sender-p" ? payerPrevStep1Sig : payerHeadSig,
          // The one thing forbids getting wrong: P0 in place of S0.
          previous_step_2_state_signature:
            options.corruptStep1 === "links-to-p0" ? receiverT0.P : receiverT0.S,
          expiry__unix_time_secs: expiryUnixTimeSecs,
          message: receiveMessage,
        };
        // Mutate values in place only — insertion order is the signed byte order (the byte-exact signing rule).
        if (options.corruptStep1 === "wrong-step1-key") {
          inner.step_1_key_public__base64urlsafe = imposter.publicKey;
        } else if (options.corruptStep1 === "stale-expiry") {
          inner.expiry__unix_time_secs = String(Number(expiryUnixTimeSecs) - 600);
        } else if (options.corruptStep1 === "mutated-message") {
          inner.message = `${receiveMessage}-tampered`;
        } else if (options.corruptStep1 === "receiver-delta") {
          // Credit the receiver twice the authorized amount — B0 + 2×amount, never B0 + amount.
          inner.step_2_state = {
            amount: String(
              addZkz(parseZkzBalance(String(receiverAfter)), parsePositiveZkzAmount(amt)),
            ),
          };
        } else if (options.corruptStep1 === "wrong-step2-key") {
          inner.step_2_key_public__base64urlsafe = imposter.publicKey;
        } else if (options.corruptStep1 === "sender-delta") {
          // Debit the sender less than the authorized amount.
          inner.step_1_state = { amount: String(parseZkzBalance(payerBalance)) };
        }
        // Pretty-printing parses back to the identical object, so every field check passes
        // and only the byte-exact re-stringify can reject it (the byte-exact signing rule).
        const innerPreimageText =
          options.corruptStep1 === "reformatted-json"
            ? JSON.stringify(inner, null, 2)
            : JSON.stringify(inner);
        // "wrong-step1-key" signs with the key the inner names, so only the key-role
        // assertion can catch it; "forged-signature" leaves the inner correct and signs
        // with an unauthorized key, so only Ed25519 verification can catch it.
        const step1Signature =
          options.corruptStep1 === "wrong-step1-key" ||
          options.corruptStep1 === "forged-signature"
            ? imposter.sign(innerPreimageText)
            : payer.sign(innerPreimageText);
        // Signature-scalar corruptions. Neither touches the inner, so the step-1 key still
        // parses and still names the authorized payer: the only thing that can reject these
        // is the signature's own grammar gate, inside verifyStep1Signature.
        //   "unparseable-signature" is not base64url at all.
        //   "short-signature" is well-formed padded base64url over the real signature's
        //   first 32 bytes — a valid encoding of the wrong length, so the refusal is
        //   attributable to the length and not to the alphabet.
        const deliveredStep1Signature =
          options.corruptStep1 === "unparseable-signature"
            ? "not-a-signature"
            : options.corruptStep1 === "short-signature"
              ? toPaddedBase64Url(Buffer.from(step1Signature, "base64url").subarray(0, 32))
              : step1Signature;
        return {
          innerPreimageText,
          step1Signature: deliveredStep1Signature,
          // Always the authorized payer: the adjacent seam field is exactly what must NOT
          // be trusted as evidence about the signed bytes.
          payerPubkey: payer.publicKey,
        };
      },
    },
    nodeClockMs: () => NODE_CLOCK_MS,
  };

  // Preflight probe: CREATED-stage op + generated pubkeys (eligibility + payer identity).
  const state = readyReceiveStateWithOperation(ATTEMPT_ID);
  state.receivers.set(SAMPLE_RECEIVE_RECEIVER_ID, {
    walletId: SAMPLE_RECEIVE_RECEIVER_ID,
    pubkey: receiver.publicKey,
    keyOrigin: "node_generated",
    walletState: "AVAILABLE",
    recoveryVerifiedAt: "2026-07-20T12:00:00.000Z",
    nodeControlled: true,
    backupPresent: true,
    backupCapturedAt: "2026-07-27T00:00:00.000Z",
  });
  // Drop sample payer; register the real generated payer pubkey.
  state.payers.clear();
  state.payers.set(payer.publicKey, {
    payerAddress: payer.publicKey,
    resolvesToNodeBlessedSet: false,
    isNodeControlledWallet: false,
    keyholderId: SAMPLE_PAYER_KEYHOLDER,
    independentControlNote:
      "offline test disposable payer; private key held only in-process for this unit test",
  });
  // Keep CREATED op row; align amount with the test amount.
  state.operations.set(
    SAMPLE_RECEIVE_OPERATION_ID,
    sampleReceiveOperationRow(SAMPLE_RECEIVE_OPERATION_ID, { amountZkz: amount }),
  );

  const input: ReceiveExecuteInput = {
    attemptId: ATTEMPT_ID,
    operationId: SAMPLE_RECEIVE_OPERATION_ID,
    receiverWalletId: SAMPLE_RECEIVE_RECEIVER_ID,
    receiverPubkey: receiver.publicKey,
    externalPayerAddress: payer.publicKey,
    amount,
    authorization: sampleReceiveAuth(ATTEMPT_ID),
    runnerLock: createRunnerLock(),
    runnerHolderId: "fixture-runner",
    preflightProbe: fakeReceiveProbe(state),
    forceT0ObserveBeforeLease: options.forceT0ObserveBeforeLease,
  };

  void SAMPLE_RECEIVE_PAYER_ADDRESS;
  void persistedCode;

  return { deps, input, counts, rows, signedTexts, receiver, payer };
}

describe("executeAuthorizedReceiveExternal — full ceremony", () => {
  it("runs the full ceremony once and lands verified", async () => {
    const node = makeFakeNode();
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(true);
    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(result.evidence.leaseHeldBeforeT0Read).toBe(true);
    expect(result.evidence.singleSubmitOnly).toBe(true);
    expect(result.evidence.nodeSubmitSeamExercised).toBe(true);
    expect(node.counts.leaseCalls).toBe(1);
    expect(node.counts.armCalls).toBe(1);
    expect(node.counts.signerCalls).toBe(1);
    expect(node.counts.submitCalls).toBe(1);
    expect(node.counts.readsBeforeLease).toBe(0);
    expect(result.evidence.candidate?.receiverLinkComparedTo).toBe("S0");
    expect(result.evidence.rowCounts).toEqual({
      receiverLeases: 1,
      armAcknowledgements: 1,
      candidates: 1,
      step2Preimages: 1,
      step2Signatures: 1,
      submitDecisions: 1,
      gatewaySubmitAttempts: 1,
    });
    expect(result.evidence.submit?.submitCallCount).toBe(1);
    expect(result.evidence.landing?.balanceDeltaMatchesAmount).toBe(true);
    // Gateway read count: T0 + sender preflight + landing = 3
    expect(result.evidence.gatewayReadCount).toBe(3);
  });

  it("exposes a node submit seam (unlike SEND_EXTERNAL)", () => {
    const node = makeFakeNode();
    expect(Object.keys(node.deps)).toContain("submit");
    expect(node.deps.submit).toBeDefined();
  });

  it("acquires the receiver lease before the T0 gateway read", async () => {
    const node = makeFakeNode({ leaseFails: true });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SUBMIT");
    expect(node.counts.gatewayReads).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
    // The two submit flags are measurements, not constants: no submit happened here, so
    // both must read false. If either is ever hardcoded true again, this fails.
    expect(result.evidence.nodeSubmitSeamExercised).toBe(false);
    expect(result.evidence.singleSubmitOnly).toBe(false);
  });

  it("ceremony mutation: T0 observe before lease → ESCALATE_INVARIANT_BREACH", async () => {
    const node = makeFakeNode({ forceT0ObserveBeforeLease: true });
    const result = await executeAuthorizedReceiveExternal(node.deps, {
      ...node.input,
      forceT0ObserveBeforeLease: true,
    });
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.leaseHeldBeforeT0Read).toBe(false);
    expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
  });

  it("never calls the signer before the durable step-2 preimage commits", async () => {
    const node = makeFakeNode();
    // Break candidate persist
    node.deps.persist.persistCandidateAndStep2Preimage = async () => {
      throw new Error("candidate DB-TX rolled back");
    };
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SUBMIT");
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
  });

  it("submits exactly once and never retries on AMBIGUOUS", async () => {
    const node = makeFakeNode({ submitOutcome: "AMBIGUOUS" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    expect(result.evidence.abortTrigger).toBe("SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
    expect(node.counts.submitCalls).toBe(1);
    // A second call would throw in the fake — prove we don't reach it.
    await expect(
      node.deps.submit.submitOnce({
        operationId: SAMPLE_RECEIVE_OPERATION_ID,
        attemptNo: 1,
        settledTransactionText: "{}",
        submitDecisionId: "x",
      }),
    ).rejects.toThrow(/second submit/);
  });

  it("classifies gateway REJECT without a second submit", async () => {
    const node = makeFakeNode({ submitOutcome: "REJECT" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("SUBMIT_REJECTED");
    expect(node.counts.submitCalls).toBe(1);
    expect(result.evidence.landing).toBeNull();
  });

  it("holds and reconciles when the independent landing read finds nothing", async () => {
    const node = makeFakeNode({ landingFound: false });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    expect(result.evidence.landing).toBeNull();
    expect(node.counts.submitCalls).toBe(1);
  });

  it("refuses a null plan even when the preflight gate itself is bypassed", async () => {
    // requirePreflight: false skips the readiness refusal but not the plan; a preflight that
    // is not ready still resolves plan === null, and executing on it would mean executing
    // with no receiver, payer or amount agreed. Fail closed.
    const node = makeFakeNode();
    const empty = readyReceiveStateWithOperation(ATTEMPT_ID);
    empty.receivers.clear();
    const result = await executeAuthorizedReceiveExternal(node.deps, {
      ...node.input,
      preflightProbe: fakeReceiveProbe(empty),
      requirePreflight: false,
    });
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("PREFLIGHT_NOT_READY");
    expect(result.evidence.plan).toBeNull();
    expect(
      result.evidence.trail.some((l) => l.includes("preflight ready but plan null")),
    ).toBe(true);
    expect(node.counts.leaseCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
  });

  it("refuses preflight-not-ready without any lease or submit", async () => {
    const node = makeFakeNode();
    // Empty probe → preflight fails
    const empty = readyReceiveStateWithOperation(ATTEMPT_ID);
    empty.receivers.clear();
    const result = await executeAuthorizedReceiveExternal(node.deps, {
      ...node.input,
      preflightProbe: fakeReceiveProbe(empty),
    });
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("PREFLIGHT_NOT_READY");
    // The plan-null guard downstream refuses the same probe with the same disposition, so
    // the disposition alone cannot tell the two apart — pin this one to its own trail line.
    expect(
      result.evidence.trail.some((l) => l.includes("preflight not ready — refusing execute")),
    ).toBe(true);
    expect(node.counts.leaseCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
  });

  it("signs the exact persisted step-2 preimage bytes (the byte-exact signing rule)", async () => {
    const node = makeFakeNode();
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(true);
    expect(node.signedTexts).toHaveLength(1);
    expect(node.signedTexts[0]).toBe(result.evidence.candidate?.step2PreimageText);
    // Step-2 preimage is {"inner":…,"step_1_signature":…} template-spliced.
    expect(node.signedTexts[0]?.startsWith('{"inner":')).toBe(true);
    expect(node.signedTexts[0]).toContain('"step_1_signature":');
  });

  it("records receiver_link_compared_to = S0 never P0", async () => {
    const node = makeFakeNode();
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.evidence.candidate?.receiverLinkComparedTo).toBe("S0");
    expect(
      result.evidence.trail.some((l) => l.includes("compared_to=S0, never P0")),
    ).toBe(true);
  });

  // ─── the receiver link is S0, never P0 ───────────────────────
  //
  // Genesis has S === P === "", so the two are indistinguishable there and no genesis
  // test can tell them apart. These two run against a receiver head where S !== P: the
  // first proves the ceremony still completes when the candidate links to S0, the second
  // proves it refuses the SAME ceremony when only the linked field changes to P0. Together
  // they pin the comparison itself, not the label the evidence prints.

  it("completes against a non-genesis receiver T0 whose candidate links to S0", async () => {
    const node = makeFakeNode({ receiverT0: "non-genesis" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(true);
    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(result.evidence.candidate?.receiverLinkComparedTo).toBe("S0");
    expect(node.counts.submitCalls).toBe(1);
  });

  it("aborts a candidate linked to receiver P0 instead of S0", async () => {
    const node = makeFakeNode({ receiverT0: "non-genesis", corruptStep1: "links-to-p0" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SUBMIT");
    expect(
      result.evidence.trail.some((l) => l.includes("RECEIVER_LINK_MISMATCH")),
    ).toBe(true);
    // Nothing signed, nothing persisted, single submit slot unspent.
    expect(result.evidence.candidate).toBeNull();
    expect(node.counts.candidateWrites).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
    expect(node.rows.gatewaySubmitAttempts).toBe(0);
  });

  it("refuses an over-cap amount even when preflight is bypassed", async () => {
    // requirePreflight: false is the only way to reach execution with preflight's own cap
    // check skipped — exactly the path the in-execute cap guard exists to stop.
    const node = makeFakeNode({ amount: "0.02" });
    const result = await executeAuthorizedReceiveExternal(node.deps, {
      ...node.input,
      requirePreflight: false,
    });
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SUBMIT");
    expect(
      result.evidence.trail.some((l) => l.includes("exceeds hard cap 0.01")),
    ).toBe(true);
    expect(node.counts.leaseCalls).toBe(0);
    expect(node.counts.gatewayReads).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
  });

  // The cap is an INCLUSIVE ceiling (Test-cap / allow ≤ 0.01 ZKZ), so `> 0` and `>= 0`
  // differ only exactly AT the boundary. The 0.02 row above refuses under either, which is
  // why it left the comparison unfalsifiable; these two pin one tick either side of it.

  it("accepts an amount exactly at the hard cap", async () => {
    const node = makeFakeNode({ amount: RECEIVE_AMOUNT_HARD_CAP });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(true);
    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(
      result.evidence.trail.some((l) => l.includes("exceeds hard cap")),
    ).toBe(false);
    expect(node.counts.submitCalls).toBe(1);
  });

  it("refuses an amount one tick over the hard cap", async () => {
    const node = makeFakeNode({ amount: "0.010001" });
    const result = await executeAuthorizedReceiveExternal(node.deps, {
      ...node.input,
      requirePreflight: false,
    });
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SUBMIT");
    expect(
      result.evidence.trail.some((l) => l.includes("exceeds hard cap 0.01")),
    ).toBe(true);
    expect(node.counts.submitCalls).toBe(0);
  });

  // ─── a captured inner that PARSES but is not an object ──────────────
  //
  // `JSON.parse` accepts "null" and "42" as readily as an object. Before round 3 the field
  // reads that follow ran OUTSIDE the parse try, so a payer seam returning "null" raised a
  // TypeError that escaped the ceremony: the caller got a rejected promise instead of a
  // refusal, losing the evidence bundle AND the runner-lock handle it must release — a lock
  // leak on the money path. The handle assertion is the part that catches it; `ok === false`
  // could not, because nothing was returned at all. The census test "no bare throw escapes
  // the ceremony" greps the source for `throw`, so an implicit TypeError was invisible to it,
  // and SEAM_THROW_ROWS covered only the sibling shape that fails to parse at all.

  it.each([
    { name: "null", innerPreimageText: "null" },
    { name: "a bare number", innerPreimageText: "42" },
  ])("refuses — and returns — when the captured step-1 inner parses to $name", async (row) => {
    const node = makeFakeNode();
    const buildAndSignStep1 = node.deps.payer.buildAndSignStep1.bind(node.deps.payer);
    node.deps.payer.buildAndSignStep1 = async (i) => ({
      ...(await buildAndSignStep1(i)),
      innerPreimageText: row.innerPreimageText,
    });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SUBMIT");
    expect(
      result.evidence.trail.some((l) => l.includes("inner is not a JSON object")),
    ).toBe(true);
    // The ceremony RETURNED: the runner lock comes back to the caller rather than stranded.
    expect(result.runnerLockHandle).not.toBeNull();
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
  });

  it("escalates a captured inner that does not re-serialize byte-exactly (the byte-exact signing rule)", async () => {
    const node = makeFakeNode({ corruptStep1: "reformatted-json" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
    expect(
      result.evidence.trail.some((l) => l.includes("the byte-exact signing rule")),
    ).toBe(true);
    // The payer's signature over those exact bytes verifies — step 3 passed — so this is
    // attributable to the re-stringify check alone.
    expect(
      result.evidence.trail.some((l) =>
        l.includes("step-1 key role + expiry + message + Ed25519 signature verified"),
      ),
    ).toBe(true);
    expect(node.counts.candidateWrites).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
  });

  it("aborts when arm barrier fails — no candidate, no submit", async () => {
    const node = makeFakeNode({ armFails: true });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SUBMIT");
    expect(node.counts.candidateWrites).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
  });

  // ─── candidate validation  ───────────────
  //
  // Each variant corrupts exactly one payer-supplied input and asserts the ceremony
  // aborts BEFORE the receiver's key signs and before the operation's single submit
  // slot is spent. The trail assertion pins each variant to its own check, so one
  // guard cannot vacuously satisfy all four.

  async function expectStep1Rejection(
    corruptStep1: NonNullable<FakeNodeOptions["corruptStep1"]>,
    trailMarker: string,
  ): Promise<void> {
    const node = makeFakeNode({ corruptStep1 });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SUBMIT");
    expect(result.evidence.trail.some((line) => line.includes(trailMarker))).toBe(true);
    // Nothing persisted, nothing signed, and the single submit slot is still unspent.
    expect(node.counts.candidateWrites).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
    expect(node.rows.candidates).toBe(0);
    expect(node.rows.step2Signatures).toBe(0);
    expect(node.rows.gatewaySubmitAttempts).toBe(0);
    expect(result.evidence.nodeSubmitSeamExercised).toBe(false);
    expect(result.evidence.singleSubmitOnly).toBe(false);
  }

  it("rejects a forged step-1 signature (valid grammar, unauthorized signer)", async () => {
    await expectStep1Rejection("forged-signature", "STEP1_SIGNATURE_INVALID");
  });

  // `verifyStep1Signature` refuses through a `return false`, not a `finish(false, …)`, so
  // neither the rejection-site census nor the F1/F4 mutant families could see these two
  // until round 3 added F5 and the helper census. Both leave the step-1 key intact so the
  // refusal is attributable to the signature scalar alone.

  it("rejects a step-1 signature that is not a well-formed Ed25519 scalar", async () => {
    // Never reaches a crypto call: the frozen scalar parser refuses the grammar first.
    await expectStep1Rejection("unparseable-signature", "STEP1_SIGNATURE_INVALID");
  });

  it("rejects a well-formed step-1 signature of the wrong length", async () => {
    // Valid padded base64url, valid key, 32 bytes where 64 are required.
    await expectStep1Rejection("short-signature", "STEP1_SIGNATURE_INVALID");
  });

  it("rejects a step-1 key that is not the authorized external payer", async () => {
    // The seam still reports payerPubkey === plan.externalPayerAddress, and the signature
    // genuinely verifies under the inner's own key — only reading the key from INSIDE the
    // signed bytes catches this.
    await expectStep1Rejection("wrong-step1-key", "WRONG_KEY_ROLE: step_1 key");
  });

  it("rejects a step-1 inner carrying a stale expiry", async () => {
    await expectStep1Rejection("stale-expiry", "EXPIRY_MISMATCH");
  });

  it("rejects a step-1 inner carrying a mutated message", async () => {
    await expectStep1Rejection("mutated-message", "MESSAGE_MISMATCH");
  });

  // ─── revalidation of the PERSISTED candidate ─────────────────
  //
  // The candidate that reached the persist seam passed every step-3 check, so these
  // two abort only because the bytes came back out of storage rather than out of the
  // in-memory candidate. Both stop before the receiver's key signs, so the operation's
  // single submit slot is still unspent.

  async function expectPersistRoundTripRejection(
    corruptPersistedStep1: NonNullable<FakeNodeOptions["corruptPersistedStep1"]>,
    trailMarker: string,
  ): Promise<void> {
    const node = makeFakeNode({ corruptPersistedStep1 });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SUBMIT");
    expect(result.evidence.trail.some((line) => line.includes(trailMarker))).toBe(true);
    // The candidate row was written — that is the point — but nothing was signed or sent.
    expect(node.counts.candidateWrites).toBe(1);
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.submitCalls).toBe(0);
    expect(node.rows.step2Signatures).toBe(0);
    expect(node.rows.gatewaySubmitAttempts).toBe(0);
    expect(result.evidence.nodeSubmitSeamExercised).toBe(false);
    expect(result.evidence.singleSubmitOnly).toBe(false);
  }

  it("rejects persisted step-1 bytes that no longer carry a valid signature", async () => {
    await expectPersistRoundTripRejection("mangled-text", "STEP1_SIGNATURE_INVALID");
  });

  it("rejects a persisted candidate that is not the one validated at step 3", async () => {
    // Verifies genuinely under the payer's key, so the signature check passes — only
    // comparing the read-back against the validated candidate catches the substitution.
    await expectPersistRoundTripRejection(
      "substituted-candidate",
      "STEP1_PERSIST_ROUNDTRIP_MISMATCH",
    );
  });

  // The step-2 sign guard has TWO independently reachable halves behind one `catch (err)`:
  // the seam throwing, and the seam RESOLVING something that is not an Ed25519 signature.
  // `signFails` only ever exercised the first, so deleting `parseEd25519Signature(
  // step2Signature)` survived — the ceremony would have spliced garbage into the settled
  // body and submitted it. This row is the killing test for that call.

  it("aborts before submit when the signer resolves a malformed step-2 signature", async () => {
    const node = makeFakeNode({ signReturns: "not-a-signature" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.trail.some((l) => l.includes("step-2 sign failed"))).toBe(true);
    expect(node.counts.signerCalls).toBe(1);
    expect(node.counts.submitCalls).toBe(0);
  });

  it("holds INDETERMINATE when landing settled-body predicate fails (wrong head bytes)", async () => {
    // This was ESCALATE_INVARIANT_BREACH, and that was the defect. A head whose
    // bytes are not ours simply names a different transaction; the receiver pubkey is public
    // and the lease is node-side, so a second external inbound produces exactly this reading
    // over a receive that DID land. With nothing retained to walk it is INDETERMINATE: the
    // lease is held and reconciled, and non-landing is not claimed either.
    const node = makeFakeNode({ landingBreak: "settled" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortAction).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    expect(result.evidence.landing?.settledTextMatchesPersisted).toBe(false);
    expect(node.counts.submitCalls).toBe(1);
  });

  it("holds INDETERMINATE when the landing seam reports settled false over operands that all bind", async () => {
    // The identity flag alone, with every operand truthful: only the coordinator's
    // identity-first split reads it, and it must route here rather than to a breach.
    const node = makeFakeNode({ landingFlagLie: "settled" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.evidence.landing?.settledTextMatchesPersisted).toBe(false);
    expect(result.evidence.landing?.predecessorMatchesT0S0).toBe(true);
    expect(result.evidence.landing?.balanceDeltaMatchesAmount).toBe(true);
    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
  });

  it("escalates when landing predecessor P !== T0.S0 (wrong head link)", async () => {
    const node = makeFakeNode({ landingBreak: "predecessor" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.landing?.predecessorMatchesT0S0).toBe(false);
    // Settled + delta still true — only pred fails; proves no OR dilation path.
    expect(result.evidence.landing?.settledTextMatchesPersisted).toBe(true);
    expect(result.evidence.landing?.balanceDeltaMatchesAmount).toBe(true);
    expect(node.counts.submitCalls).toBe(1);
  });

  it("escalates when landing balance delta !== amount", async () => {
    const node = makeFakeNode({ landingBreak: "balance" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.landing?.balanceDeltaMatchesAmount).toBe(false);
    expect(result.evidence.landing?.settledTextMatchesPersisted).toBe(true);
    expect(result.evidence.landing?.predecessorMatchesT0S0).toBe(true);
    expect(node.counts.submitCalls).toBe(1);
  });

  it("escalates a landing seam whose three flags are true over operands that are not ours", async () => {
    // The seam computes the flags, so the flags are its own claim. Here it claims a clean
    // landing while handing back somebody else's head — only an coordinator that binds
    // the operands it was handed to what it persisted refuses this.
    const node = makeFakeNode({ landingLiesAboutOperands: "both" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
    expect(result.evidence.landing?.settledTextMatchesPersisted).toBe(true);
    expect(result.evidence.landing?.predecessorMatchesT0S0).toBe(true);
    expect(result.evidence.landing?.balanceDeltaMatchesAmount).toBe(true);
    expect(
      result.evidence.trail.some((l) => l.includes("LANDING_OPERAND_MISMATCH")),
    ).toBe(true);
    // Post-submit escalation, never a settle: the coins may or may not have moved, so the
    // one thing that must not happen is calling it verified.
    expect(node.counts.submitCalls).toBe(1);
    expect(result.evidence.trail.some((l) => l.includes("LANDED_VERIFIED"))).toBe(false);
  });

  // The operand bind is a two-clause conjunction. A decoy that varies both operands at
  // once holds whichever clause survives, so these vary exactly one each: deleting either
  // clause reddens exactly one of them.

  it("escalates when only the observed step-2 signature is not ours", async () => {
    const node = makeFakeNode({ landingLiesAboutOperands: "step2-only" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
    expect(
      result.evidence.trail.some((l) => l.includes("LANDING_OPERAND_MISMATCH")),
    ).toBe(true);
    expect(result.evidence.trail.some((l) => l.includes("LANDED_VERIFIED"))).toBe(false);
  });

  it("escalates when only the observed balance-after is not ours", async () => {
    const node = makeFakeNode({ landingLiesAboutOperands: "balance-only" });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
    expect(
      result.evidence.trail.some((l) => l.includes("LANDING_OPERAND_MISMATCH")),
    ).toBe(true);
    expect(result.evidence.trail.some((l) => l.includes("LANDED_VERIFIED"))).toBe(false);
  });

  // The three-flag landing check is a disjunction, and the operand bind directly after it
  // catches a corrupted operand on its own — so a fixture that corrupts BOTH (landingBreak)
  // escalates whether or not its flag clause is read. These report one flag false over
  // operands that all bind, which only the flag clause itself can refuse.

  // `settled` is excluded: a false identity flag means the head is not our
  // attempt at all, which is a read outcome and never a determinate breach. Its killing
  // test is "holds INDETERMINATE when the landing seam reports settled false…" below.
  it.each(["predecessor", "balance"] as const)(
    "escalates when the landing seam reports %s false over operands that all bind",
    async (flag) => {
      const node = makeFakeNode({ landingFlagLie: flag });
      const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
      expect(result.ok).toBe(false);
      expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
      expect(
        result.evidence.trail.some((l) => l.includes("landing predicates failed")),
      ).toBe(true);
      // The operands are ours, so the bind below cannot be what refused this.
      expect(
        result.evidence.trail.some((l) => l.includes("LANDING_OPERAND_MISMATCH")),
      ).toBe(false);
      expect(result.evidence.landing?.step2Signature).toBe(
        result.evidence.candidate?.step2Signature,
      );
      expect(node.counts.submitCalls).toBe(1);
      expect(result.evidence.trail.some((l) => l.includes("LANDED_VERIFIED"))).toBe(false);
    },
  );

  // ─── Predicate guards, one row per guard ───────────────────────────────────
  //
  // Each row corrupts exactly one thing, so the refusal is attributable to the named
  // check alone. A row is cheaper than another FakeNodeOptions flag, and adding one is
  // what receive-execute-harness-guards.census.test.ts requires before a new refusal path can
  // exist — the enumeration is no longer a person's list.

  interface GuardRow {
    readonly name: string;
    readonly options?: FakeNodeOptions;
    readonly patch?: (node: FakeNode) => void;
    readonly disposition: ReceiveExecuteDisposition;
    readonly marker: string;
    readonly submitCalls: number;
  }

  const GUARD_ROWS: readonly GuardRow[] = [
    {
      name: "arm released transfer-code bytes differ from the persisted withheld code",
      patch: (node) => {
        const armOnce = node.deps.arm.armOnce.bind(node.deps.arm);
        node.deps.arm.armOnce = async (i) => {
          const armed = await armOnce(i);
          return { ...armed, releasedTransferCodeText: `${armed.releasedTransferCodeText} ` };
        };
      },
      disposition: "ESCALATE_INVARIANT_BREACH",
      marker: "released code bytes differ",
      submitCalls: 0,
    },
    {
      name: "formation persist reports a status other than READY",
      patch: (node) => {
        node.deps.persist.persistFormation = async () =>
          ({ statusAfter: "CREATED" }) as unknown as { statusAfter: "READY" };
      },
      disposition: "ESCALATE_INVARIANT_BREACH",
      marker: "INVARIANT: status after formation",
      submitCalls: 0,
    },
    {
      name: "candidate credits the receiver more than the authorized amount",
      options: { corruptStep1: "receiver-delta" },
      disposition: "ABORTED_BEFORE_SUBMIT",
      marker: "receiver delta mismatch",
      submitCalls: 0,
    },
    {
      name: "candidate names a step-2 key that is not the reserved receiver",
      options: { corruptStep1: "wrong-step2-key" },
      disposition: "ABORTED_BEFORE_SUBMIT",
      marker: "WRONG_KEY_ROLE: step_2 key",
      submitCalls: 0,
    },
    {
      name: "candidate links to the sender's P0 instead of its S0",
      options: { corruptStep1: "links-to-sender-p" },
      disposition: "ABORTED_BEFORE_SUBMIT",
      marker: "SENDER_PREFLIGHT_LINK_MISMATCH",
      submitCalls: 0,
    },
    {
      name: "candidate debits the sender less than the authorized amount",
      options: { corruptStep1: "sender-delta" },
      disposition: "ABORTED_BEFORE_SUBMIT",
      marker: "sender delta mismatch",
      submitCalls: 0,
    },
  ];

  it.each(GUARD_ROWS)("refuses when $name", async (row) => {
    const node = makeFakeNode(row.options ?? {});
    row.patch?.(node);
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe(row.disposition);
    expect(result.evidence.trail.some((l) => l.includes(row.marker))).toBe(true);
    expect(node.counts.submitCalls).toBe(row.submitCalls);
    expect(result.evidence.trail.some((l) => l.includes("LANDED_VERIFIED"))).toBe(false);
  });

  // The row-count check is a seven-clause conjunction; one row per clause, so deleting any
  // single clause reddens exactly one test rather than none.
  const ROW_COUNT_FIELDS: readonly (keyof ReceiveRowCounts)[] = [
    "receiverLeases",
    "armAcknowledgements",
    "candidates",
    "step2Preimages",
    "step2Signatures",
    "submitDecisions",
    "gatewaySubmitAttempts",
  ];

  it.each(ROW_COUNT_FIELDS)(
    "escalates when the single-shot row count %s is not 1",
    async (field) => {
      const node = makeFakeNode();
      node.deps.persist.countRows = async () => ({ ...node.rows, [field]: 2 });
      const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
      expect(result.ok).toBe(false);
      expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
      expect(
        result.evidence.trail.some((l) =>
          l.includes("row counts violate single-shot ceremony"),
        ),
      ).toBe(true);
      expect(node.counts.submitCalls).toBe(1);
      expect(result.evidence.trail.some((l) => l.includes("LANDED_VERIFIED"))).toBe(false);
    },
  );

  // ─── Seam-throw handlers, one row per seam ─────────────────────────────────
  //
  // Every seam call in the ceremony sits in a try/catch whose disposition depends only on
  // which side of the single submit slot it is on. Asserting that class invariant — rather
  // than a bespoke message per site — means a seam added to ReceiveExecuteDeps is covered
  // by adding its name here.

  interface SeamThrowRow {
    readonly name: string;
    readonly phase: "pre-submit" | "post-submit";
    readonly options?: FakeNodeOptions;
    readonly inputOverride?: Partial<ReceiveExecuteInput>;
    readonly patch?: (node: FakeNode) => void;
  }

  /** Wrap observeVerified so one role's projection comes back malformed. */
  function corruptObservedBalance(node: FakeNode, role: ReceiveObservation["role"]): void {
    const observeVerified = node.deps.observe.observeVerified.bind(node.deps.observe);
    node.deps.observe.observeVerified = async (i) => {
      const obs = await observeVerified(i);
      if (i.role !== role) return obs;
      return { ...obs, projection: { ...obs.projection, B: "not-a-zkz-balance" } };
    };
  }

  const SEAM_THROW_ROWS: readonly SeamThrowRow[] = [
    {
      name: "the hard-cap comparison is handed a malformed amount",
      phase: "pre-submit",
      options: { amount: "not-an-amount" },
      inputOverride: { requirePreflight: false },
    },
    {
      name: "persist.admitOperation throws",
      phase: "pre-submit",
      patch: (node) => {
        node.deps.persist.admitOperation = async () => {
          throw new Error("admit DB-TX rolled back");
        };
      },
    },
    {
      name: "leases.acquireReceiverLease throws",
      phase: "pre-submit",
      options: { leaseFails: true },
    },
    {
      name: "observe.observeVerified throws on the RECEIVE_T0 read",
      phase: "pre-submit",
      patch: (node) => {
        node.deps.observe.observeVerified = async () => {
          throw new Error("gateway unreachable");
        };
      },
    },
    {
      name: "transfer-code formation throws on a malformed receiver B0",
      phase: "pre-submit",
      patch: (node) => {
        corruptObservedBalance(node, "RECEIVE_T0");
      },
    },
    {
      name: "persist.persistFormation throws",
      phase: "pre-submit",
      patch: (node) => {
        node.deps.persist.persistFormation = async () => {
          throw new Error("formation DB-TX rolled back");
        };
      },
    },
    { name: "arm.armOnce throws", phase: "pre-submit", options: { armFails: true } },
    {
      name: "payer.buildAndSignStep1 throws",
      phase: "pre-submit",
      patch: (node) => {
        node.deps.payer.buildAndSignStep1 = async () => {
          throw new Error("external payer unavailable");
        };
      },
    },
    {
      name: "the captured step-1 inner is not parseable JSON",
      phase: "pre-submit",
      patch: (node) => {
        const buildAndSignStep1 = node.deps.payer.buildAndSignStep1.bind(node.deps.payer);
        node.deps.payer.buildAndSignStep1 = async (i) => ({
          ...(await buildAndSignStep1(i)),
          innerPreimageText: "{not json",
        });
      },
    },
    {
      name: "the captured step-1 inner omits step_2_state entirely",
      phase: "pre-submit",
      patch: (node) => {
        const buildAndSignStep1 = node.deps.payer.buildAndSignStep1.bind(node.deps.payer);
        node.deps.payer.buildAndSignStep1 = async (i) => {
          const signed = await buildAndSignStep1(i);
          // Keep the receiver link intact so the abort is attributable to the delta check
          // reading a field that is not there, not to an earlier guard.
          const inner = JSON.parse(signed.innerPreimageText) as Record<string, unknown>;
          delete inner.step_2_state;
          const innerPreimageText = JSON.stringify(inner);
          return {
            ...signed,
            innerPreimageText,
            step1Signature: node.payer.sign(innerPreimageText),
          };
        };
      },
    },
    {
      name: "observe.observeVerified throws on the sender preflight read",
      phase: "pre-submit",
      patch: (node) => {
        const observeVerified = node.deps.observe.observeVerified.bind(node.deps.observe);
        node.deps.observe.observeVerified = async (i) => {
          if (i.role === "RECEIVE_SENDER_PREFLIGHT") throw new Error("gateway unreachable");
          return observeVerified(i);
        };
      },
    },
    {
      name: "the sender delta check is handed a malformed sender balance",
      phase: "pre-submit",
      patch: (node) => {
        corruptObservedBalance(node, "RECEIVE_SENDER_PREFLIGHT");
      },
    },
    {
      name: "persist.persistCandidateAndStep2Preimage throws",
      phase: "pre-submit",
      patch: (node) => {
        node.deps.persist.persistCandidateAndStep2Preimage = async () => {
          throw new Error("candidate DB-TX rolled back");
        };
      },
    },
    { name: "signer.signStep2 throws", phase: "post-submit", options: { signFails: true } },
    {
      name: "persist.persistSignedAndSubmitDecision throws",
      phase: "post-submit",
      patch: (node) => {
        node.deps.persist.persistSignedAndSubmitDecision = async () => {
          throw new Error("signed body DB-TX rolled back");
        };
      },
    },
    {
      name: "persist.countRows throws",
      phase: "post-submit",
      patch: (node) => {
        node.deps.persist.countRows = async () => {
          throw new Error("row-count read failed");
        };
      },
    },
    {
      name: "observe.observeReceiverLanding throws",
      phase: "post-submit",
      patch: (node) => {
        node.deps.observe.observeReceiverLanding = async () => {
          throw new Error("gateway unreachable during landing read");
        };
      },
    },
  ];

  it.each(SEAM_THROW_ROWS)("aborts fail-closed when $name", async (row) => {
    const node = makeFakeNode(row.options ?? {});
    row.patch?.(node);
    const result = await executeAuthorizedReceiveExternal(node.deps, {
      ...node.input,
      ...row.inputOverride,
    });
    expect(result.ok).toBe(false);
    expect(result.evidence.trail.some((l) => l.includes("LANDED_VERIFIED"))).toBe(false);
    if (row.phase === "pre-submit") {
      expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SUBMIT");
      expect(node.counts.signerCalls).toBe(0);
      expect(node.counts.submitCalls).toBe(0);
      expect(node.rows.gatewaySubmitAttempts).toBe(0);
      expect(result.evidence.nodeSubmitSeamExercised).toBe(false);
    } else {
      expect(result.evidence.disposition).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
      expect(result.evidence.abortTrigger).toBe("SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
      expect(node.counts.submitCalls).toBeLessThanOrEqual(1);
    }
  });

  // The never-blind-retry rule's own site: a submit whose transport threw is AMBIGUOUS, never retried
  // and never promoted. Reaching AMBIGUOUS through the seam RETURNING it (the test above)
  // does not exercise this catch, so it gets a test of its own.
  it("holds without a second submit when the submit transport throws (the never-blind-retry rule)", async () => {
    const node = makeFakeNode();
    node.deps.submit.submitOnce = async () => {
      node.counts.submitCalls += 1;
      throw new Error("ECONNRESET after the request bytes were written");
    };
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
    expect(result.ok).toBe(false);
    expect(node.counts.submitCalls).toBe(1);
    expect(result.evidence.submit?.outcome).toBe("AMBIGUOUS");
    expect(result.evidence.submit?.submitCallCount).toBe(1);
    expect(result.evidence.submit?.detail).toContain("ECONNRESET");
    expect(result.evidence.disposition).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    expect(result.evidence.abortTrigger).toBe("SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
    expect(result.evidence.singleSubmitOnly).toBe(true);
    expect(result.evidence.trail.some((l) => l.includes("LANDED_VERIFIED"))).toBe(false);
  });
});

describe("evaluateReceiveLandingPredicates — strict equality, no OR dilations", () => {
  const base = {
    headPresent: true as const,
    observedSettledTransactionText: '{"inner":{},"step_1_signature":"a","step_2_signature":"b"}',
    persistedSettledTransactionText: '{"inner":{},"step_1_signature":"a","step_2_signature":"b"}',
    observedStep2Signature: "b",
    persistedStep2Signature: "b",
    observedP: "",
    receiverT0S0: "",
    observedB: "0.000001",
    receiverT0B0: "0",
    amount: "0.000001",
  };

  it("allMatch when exact settled + P===T0.S0 + ΔB", () => {
    const f = evaluateReceiveLandingPredicates(base);
    expect(f).not.toBeNull();
    expect(f!.allMatch).toBe(true);
    expect(f!.settledTextMatchesPersisted).toBe(true);
    expect(f!.predecessorMatchesT0S0).toBe(true);
    expect(f!.balanceDeltaMatchesAmount).toBe(true);
  });

  it("null when head absent", () => {
    expect(evaluateReceiveLandingPredicates({ ...base, headPresent: false })).toBeNull();
  });

  it("settled false on includes-style substring (not exact bytes)", () => {
    const f = evaluateReceiveLandingPredicates({
      ...base,
      // Envelope-style includes would pass; exact equality must fail.
      observedSettledTransactionText: `WRAP${base.persistedSettledTransactionText}WRAP`,
    });
    expect(f!.settledTextMatchesPersisted).toBe(false);
    expect(f!.allMatch).toBe(false);
  });

  // ─── settledTextMatchesPersisted is a conjunction of four clauses ─────────
  //
  // The coordinator-level "settled" break corrupts the body AND the step-2 signature
  // together, so it holds whether the conjunction has one clause or four. These vary
  // exactly one clause each, so deleting any of the three below reddens exactly one.

  it("settled false when only the step-2 signature differs (body byte-identical)", () => {
    const f = evaluateReceiveLandingPredicates({
      ...base,
      observedStep2Signature: "not-our-step-2",
    });
    expect(f!.settledTextMatchesPersisted).toBe(false);
    expect(f!.allMatch).toBe(false);
  });

  it("settled false when persisted body is empty even though observed equals it", () => {
    // "" === "" would otherwise read as a match, promoting a head with no settled bytes.
    const f = evaluateReceiveLandingPredicates({
      ...base,
      observedSettledTransactionText: "",
      persistedSettledTransactionText: "",
    });
    expect(f!.settledTextMatchesPersisted).toBe(false);
    expect(f!.allMatch).toBe(false);
  });

  it("settled false when persisted step-2 signature is empty even though observed equals it", () => {
    const f = evaluateReceiveLandingPredicates({
      ...base,
      observedStep2Signature: "",
      persistedStep2Signature: "",
    });
    expect(f!.settledTextMatchesPersisted).toBe(false);
    expect(f!.allMatch).toBe(false);
  });

  it("predecessor false when P !== T0.S0 even if S would equal step2", () => {
    // Historical dilation: proj.S === step2 was treated as pred ok. Strict P only.
    const f = evaluateReceiveLandingPredicates({
      ...base,
      observedP: "not-t0-s0",
      receiverT0S0: "",
    });
    expect(f!.predecessorMatchesT0S0).toBe(false);
    expect(f!.allMatch).toBe(false);
  });

  it("balance false when B !== B0+amount", () => {
    const f = evaluateReceiveLandingPredicates({
      ...base,
      observedB: "0.000002",
    });
    expect(f!.balanceDeltaMatchesAmount).toBe(false);
    expect(f!.allMatch).toBe(false);
  });

  it("wrong head cannot allMatch (missing exact body + wrong P)", () => {
    const f = evaluateReceiveLandingPredicates({
      ...base,
      observedSettledTransactionText: '{"status":true}',
      observedStep2Signature: "other",
      observedP: "phantom",
      observedB: "0",
    });
    expect(f!.settledTextMatchesPersisted).toBe(false);
    expect(f!.predecessorMatchesT0S0).toBe(false);
    expect(f!.balanceDeltaMatchesAmount).toBe(false);
    expect(f!.allMatch).toBe(false);
  });
});

// ─── — a buried RECEIVE landing is a landing, not an invariant breach ──
//
// The receiver pubkey is a public address and the receiver lease is a node-side lock, so a
// second external inbound can land between our submit and the terminal head read. Before
// this suite, that advanced head drove all three predicates false and the ceremony
// escalated INVARIANT_BREACH over a receive that had in fact landed.
//
// Every body below is a real Ed25519-signed `unique_combinable` v2 transaction on the SAME
// receiver wallet, and the walk runs over the settled body the ceremony itself formed — the
// fake recovers it from its own persist record, never from the arguments the seam is handed.
//
describe("buried receive landing disposition", () => {
  it("the fixture is a real chain: T0 → our attempt → burial back-link on the receiver", async () => {
    // Guards the vectors themselves. If these stop being an adjacent segment, every
    // assertion below would pass vacuously against a chain that proves nothing.
    const node = makeFakeNode({ landingFound: false, landingPath: { successors: 1 } });
    let captured: ReceiveLandingPathEvidence | null = null;
    const seam = node.deps.observe.collectReceiverLandingPath!;
    node.deps.observe.collectReceiverLandingPath = async (input) => {
      captured = await seam.call(node.deps.observe, input);
      return captured;
    };
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    const ev = captured! as ReceiveLandingPathEvidence;
    expect(ev.t0Body).not.toBeNull();
    // Our attempt back-links to T0, and the burial back-links to our attempt.
    expect(ev.expectedBody.inner.previous_step_2_state_signature).toBe(
      ev.t0Body!.step_2_signature,
    );
    expect(ev.successorBodies[0]!.inner.previous_step_2_state_signature).toBe(
      ev.expectedBody.step_2_signature,
    );
    expect(ev.successorBodies[0]!.step_2_signature).not.toBe(ev.expectedBody.step_2_signature);
    // And the body walked really is the one the ceremony signed and persisted — not a
    // look-alike the fixture built on the side.
    expect(JSON.stringify(ev.expectedBody)).toBe(
      result.evidence.candidate?.settledTransactionText,
    );
  });

  // ── The defect, and that it is actually fixed ──────────────────────────────

  it("PROBE-D1: a second external inbound between submit and the terminal read is a LANDING, not a breach", async () => {
    const node = makeFakeNode({ landingFound: false, landingPath: { successors: 1 } });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDED_BURIED_COMPLETE_PATH");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.ok).toBe(true);
    expect(result.evidence.abortAction).toBe("COMPLETE_LANDED_VERIFIED");
    expect(result.evidence.landingProof).toMatchObject({
      kind: "LANDED_COMPLETE_PATH",
      depth: 1,
      walletPubkeyBase64Urlsafe: node.receiver.publicKey,
    });
    // A landing proof authorizes no second anything (the one-in-flight-per-wallet and never-blind-retry rules).
    expect(node.counts.signerCalls).toBe(1);
    expect(node.counts.submitCalls).toBe(1);
    expect(result.evidence.singleSubmitOnly).toBe(true);
  });

  it("PROBE-D0: the walk still proves depth 0 when our attempt IS the head", async () => {
    // No over-correction: a fix that refuses everything passes every decoy probe and
    // destroys the feature. A late landing the head read simply missed is still a landing.
    const node = makeFakeNode({ landingFound: false, landingPath: { successors: 0 } });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(result.ok).toBe(true);
    expect(result.evidence.landingProof).toMatchObject({ kind: "LANDED_EXACT" });
    expect(node.counts.submitCalls).toBe(1);
  });

  it("PROBE-D2: two burial hops still classify as a landing at depth 2", async () => {
    const node = makeFakeNode({ landingFound: false, landingPath: { successors: 2 } });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDED_BURIED_COMPLETE_PATH");
    expect(result.ok).toBe(true);
    expect(result.evidence.landingProof).toMatchObject({
      kind: "LANDED_COMPLETE_PATH",
      depth: 2,
    });
  });

  it("the happy path is untouched — a head that carries our attempt still lands verified", async () => {
    const node = makeFakeNode({ landingPath: { successors: 1 } });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    // The head read found our body, so the walk is never consulted at all.
    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(result.ok).toBe(true);
    expect(result.evidence.landingProof).toBeNull();
  });

  // ── The decoys. Each must refuse, and none may refuse as INVARIANT_BREACH. ──

  it("DECOY-IDENTITY: a look-alike inbound offered as our attempt is refused, never settled", async () => {
    // The decoy is a REAL inbound of the same amount to the same receiver, chained off the
    // same T0: it reverifies, it back-links, and it satisfies the economic predicate.
    // Believing it would settle THIS operation and release the receiver lease on somebody
    // else's transaction — the one-in-flight-per-wallet rule's exact hazard. The coordinator's byte-exact bind
    // of `expectedBody` to its own persisted body refuses it BEFORE the walk; deleting that
    // bind does not settle the decoy here (the oracle's own anchoring then refuses it as
    // PROOF_INCOMPLETE/MISSING_BODY, since this fixture's fresh head is our genuine body) —
    // it moves the refusal after the walk, which is exactly what the `landingProof` and
    // trail assertions below pin. Do not read "only this bind stands between the decoy and a
    // settle": read "this bind is what refuses it without asking the oracle to."
    const node = makeFakeNode({
      landingFound: false,
      landingPath: { successors: 1, decoyExpectedBody: true },
    });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).not.toBe("LANDED_BURIED_COMPLETE_PATH");
    expect(result.evidence.disposition).not.toBe("LANDED_VERIFIED");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(
      result.evidence.trail.some((l) =>
        l.includes("landing-path evidence names a body that is not our attempt"),
      ),
    ).toBe(true);
    // Refused BEFORE the walk could mint a positive proof.
    expect(result.evidence.landingProof).toBeNull();
    expect(node.counts.submitCalls).toBe(1);
  });

  it("DECOY-D0: a look-alike offered while our attempt is still the head is refused too", async () => {
    // The depth-1 decoy above could in principle be refused by the burial hop rather than by
    // identity. At depth 0 there is no hop to hide behind: the head IS our body, and the only
    // thing standing between a look-alike and a settled positive is the byte-exact bind.
    const node = makeFakeNode({
      landingFound: false,
      landingPath: { successors: 0, decoyExpectedBody: true },
    });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).not.toBe("LANDED_VERIFIED");
    expect(result.evidence.disposition).not.toBe("LANDED_BURIED_COMPLETE_PATH");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.landingProof).toBeNull();
    expect(node.counts.submitCalls).toBe(1);
  });

  it("DECOY-FORGED-STEP2: our bytes with a foreign step-2 co-signature are refused", async () => {
    // Reaches the bind's `verdict !== "VERIFIED"` arm, which no other case exercises: the
    // decoys above are real bodies that verify. Everything before the last field is ours, so
    // only signature reverification separates this from a settled positive.
    const node = makeFakeNode({
      landingFound: false,
      landingPath: { successors: 1, forgedExpectedStep2: true },
    });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.landingProof).toBeNull();
    expect(
      result.evidence.trail.some(
        (l) =>
          l.includes("landing-path evidence names a body that is not our attempt") &&
          !l.includes("verdict=VERIFIED"),
      ),
    ).toBe(true);
  });

  it("PROBE-TABLE: the disposition every scenario actually reaches", async () => {
    // One place a reader can read the real dispositions off, instead of inferring them
    // from the assertions above. Genuine landings must stay landings — a fix that refused
    // everything would pass every decoy and destroy the feature.
    const scenarios: readonly (readonly [string, FakeNodeOptions])[] = [
      ["genuine depth 0", { landingFound: false, landingPath: { successors: 0 } }],
      ["genuine depth 1", { landingFound: false, landingPath: { successors: 1 } }],
      ["genuine depth 2", { landingFound: false, landingPath: { successors: 2 } }],
      [
        "decoy depth 0",
        { landingFound: false, landingPath: { successors: 0, decoyExpectedBody: true } },
      ],
      [
        "decoy depth 1",
        { landingFound: false, landingPath: { successors: 1, decoyExpectedBody: true } },
      ],
      [
        "decoy mid-walk depth 2",
        { landingFound: false, landingPath: { successors: 2, decoyAtDepth: 2 } },
      ],
    ];
    const seen: Record<string, string> = {};
    for (const [name, options] of scenarios) {
      const node = makeFakeNode(options);
      const result = await executeAuthorizedReceiveExternal(node.deps, node.input);
      seen[name] = result.evidence.disposition;
    }
    expect(seen).toEqual({
      "genuine depth 0": "LANDED_VERIFIED",
      "genuine depth 1": "LANDED_BURIED_COMPLETE_PATH",
      "genuine depth 2": "LANDED_BURIED_COMPLETE_PATH",
      "decoy depth 0": "LANDING_INDETERMINATE",
      "decoy depth 1": "LANDING_INDETERMINATE",
      "decoy mid-walk depth 2": "LANDING_INDETERMINATE",
    });
  });

  it("DECOY-MIDWALK: a body planted at depth 2 that does not back-link is INDETERMINATE", async () => {
    const node = makeFakeNode({
      landingFound: false,
      landingPath: { successors: 2, decoyAtDepth: 2 },
    });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.landingProof).toMatchObject({ kind: "PROOF_INCOMPLETE" });
  });

  it("MUTATION: withhold the intervening body and the walk cannot bridge — INDETERMINATE", async () => {
    // Identical run, one change: the successor the forward-walk needs is withheld, so the
    // path stops short of the head. If the walk were a no-op — or if the disposition were
    // read off the head instead of anchored on our attempt — this would still report a
    // landing and PROBE-D1 would be unfalsifiable.
    const node = makeFakeNode({
      landingFound: false,
      landingPath: { successors: 1, withholdSuccessors: true },
    });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.landingProof).toMatchObject({ kind: "PROOF_INCOMPLETE" });
    // INDETERMINATE holds the lease and reconciles; it never escalates and never resubmits.
    expect(result.evidence.abortAction).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    expect(node.counts.submitCalls).toBe(1);
  });

  it("MUTATION: a head that moved during the walk is INDETERMINATE, never a stale positive", async () => {
    const node = makeFakeNode({
      landingFound: false,
      landingPath: { successors: 1, headMovesDuringWalk: true },
    });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.landingProof).toMatchObject({ kind: "PROOF_INCOMPLETE" });
  });

  it("MUTATION: LANDED_EXACT that contradicts a head read which lacked our attempt is INDETERMINATE", async () => {
    // `landingBreak: "settled"` gives a NON-null observation saying the head is not our
    // attempt. A walk that then claims our attempt IS the head contradicts it, and heads only
    // advance — routes a contradictory wallet path to INDETERMINATE, not to a landing.
    const node = makeFakeNode({ landingBreak: "settled", landingPath: { successors: 0 } });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(
      result.evidence.trail.some((l) => l.includes("contradictory wallet path")),
    ).toBe(true);
  });

  it("MUTATION: a landing-path read that throws is INDETERMINATE, never a breach", async () => {
    const node = makeFakeNode({ landingBreak: "settled", landingPath: { throws: true } });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(
      result.evidence.trail.some((l) => l.includes("landing-path evidence read threw")),
    ).toBe(true);
  });

  it("MUTATION: a landing WALK that throws is INDETERMINATE, never a breach", async () => {
    // Distinct from the seam read above: the seam answers, the identity bind passes, and the
    // throw comes out of `proveReceiveLanding` itself via its confirm-read. Without this the
    // ceremony's landing-walk catch is an undeclared, untested path — and a rethrow there
    // would escape `executeAuthorizedReceiveExternal` with the receiver lease still held and
    // no disposition at all.
    const node = makeFakeNode({
      landingFound: false,
      landingPath: { successors: 1, freshHeadThrows: true },
    });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortAction).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    expect(result.evidence.landingProof).toBeNull();
    expect(result.evidence.trail.some((l) => l.includes("landing walk threw"))).toBe(true);
  });

  it("MUTATION: expectedBody with no inner is INDETERMINATE — verifySettledTransaction throw cannot strand the lock", async () => {
    // The identity-bind call sits between two wrapped seam interactions. A body with no
    // well-formed `inner` throws inside narrowSplitChainInner rather than returning a
    // verdict; without the bind's own catch the TypeError escapes finish() and strands
    // runnerLockHandle. This test is what makes the new F4 catch clause killable.
    const node = makeFakeNode({
      landingFound: false,
      landingPath: { successors: 1, malformedExpectedBody: true },
    });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.disposition).not.toBe("LANDED_VERIFIED");
    expect(result.evidence.disposition).not.toBe("LANDED_BURIED_COMPLETE_PATH");
    expect(result.evidence.abortAction).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    expect(result.evidence.landingProof).toBeNull();
    expect(result.runnerLockHandle).not.toBeNull();
    expect(
      result.evidence.trail.some((l) => l.includes("landing-path expectedBody verify threw")),
    ).toBe(true);
    expect(node.counts.submitCalls).toBe(1);
  });

  it("a node that retained nothing to walk is INDETERMINATE — never an invariant breach", async () => {
    const node = makeFakeNode({ landingBreak: "settled", landingPath: { retainedNothing: true } });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortAction).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
  });

  it("no landing-path seam at all (the default node) is INDETERMINATE, not a breach", async () => {
    const node = makeFakeNode({ landingBreak: "settled" });
    expect(node.deps.observe.collectReceiverLandingPath).toBeUndefined();
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
  });

  // ── Determinate breaches are untouched ─────────────────────────────────────

  it("a head that IS our attempt keeps its determinate breaches (balance)", async () => {
    // settledTextMatchesPersisted stays TRUE, so the head is our own body and a wrong balance
    // is a real contradiction about a transaction we know is ours. The walk must not launder
    // it, even with path evidence available.
    const node = makeFakeNode({ landingBreak: "balance", landingPath: { successors: 1 } });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.landing?.settledTextMatchesPersisted).toBe(true);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
    expect(result.evidence.landingProof).toBeNull();
  });

  it("a head that IS our attempt keeps its determinate breaches (predecessor)", async () => {
    const node = makeFakeNode({ landingBreak: "predecessor", landingPath: { successors: 1 } });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.landing?.settledTextMatchesPersisted).toBe(true);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.landingProof).toBeNull();
  });

  it("a seam asserting three true flags over operands that are not ours still escalates", async () => {
    const node = makeFakeNode({
      landingLiesAboutOperands: "both",
      landingPath: { successors: 1 },
    });
    const result = await executeAuthorizedReceiveExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(
      result.evidence.trail.some((l) => l.includes("LANDING_OPERAND_MISMATCH")),
    ).toBe(true);
    expect(result.evidence.landingProof).toBeNull();
  });

  it("the buried-landing seam call passes through the gateway-read gate", async () => {
    const walked = makeFakeNode({ landingFound: false, landingPath: { successors: 1 } });
    const notWalked = makeFakeNode({ landingFound: false });
    const a = await executeAuthorizedReceiveExternal(walked.deps, walked.input);
    const b = await executeAuthorizedReceiveExternal(notWalked.deps, notWalked.input);

    // The extra read is counted, so it cannot escape the ceremony's read budget.
    expect(a.evidence.gatewayReadCount).toBe(b.evidence.gatewayReadCount + 1);
  });
});
