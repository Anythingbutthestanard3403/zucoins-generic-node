// Test support for the policy suites: real Ed25519 SplitChain transactions built
// from deterministic seed keys, so the negative cases the frozen goldens cannot express
// (wrong amount, broken backlink, two different transactions, a re-signed partial) are
// still genuine signed bytes rather than hand-assembled strings.
//
// The signing shape is the protocol's, byte for byte: step_1 signs JSON.stringify(inner),
// step_2 signs JSON.stringify({inner, step_1_signature}). The inner object is written in the
// protocol's exact insertion sequence and never rebuilt, so the bytes here are the bytes the
// verifier re-derives. Same construction as the canonical golden emitter.
import { createPrivateKey, createPublicKey, sign } from "node:crypto";

import { parseGatewayEnvelope, type ParsedSettledTransaction } from "../../verifier/gateway-envelope.js";

type PrivateKey = ReturnType<typeof createPrivateKey>;

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

export const keyFromSeed = (seedByte: number): PrivateKey =>
  createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, seedByte),
    ]),
    type: "pkcs8",
    format: "der",
  });

/** The 44-character padded base64url wallet public key the scalar grammar requires. */
export const publicKeyFromSeed = (seedByte: number): string =>
  paddedBase64Url(
    createPublicKey(keyFromSeed(seedByte)).export({ format: "der", type: "spki" }).subarray(-32),
  );

export const signText = (text: string, seedByte: number): string =>
  paddedBase64Url(sign(null, Buffer.from(text, "utf8"), keyFromSeed(seedByte)));

export interface TransactionSpec {
  readonly senderSeed: number;
  readonly receiverSeed: number;
  /** step_1_state.amount — the sender's balance AFTER this transaction. */
  readonly senderBalanceAfter: string;
  /** step_2_state.amount — the receiver's balance AFTER this transaction. */
  readonly receiverBalanceAfter: string;
  readonly previousStep1Signature?: string;
  readonly previousStep2Signature?: string;
  readonly expiry?: string;
  readonly message?: string;
  readonly unixTimeSecs?: string;
  /** Sign step 1 with another seed to produce a genuinely invalid step-1 signature. */
  readonly step1SigningSeed?: number;
}

export interface BuiltTransaction {
  readonly parsed: ParsedSettledTransaction;
  readonly settledText: string;
  readonly innerPreimageText: string;
  readonly step1Signature: string;
  readonly step2Signature: string;
  readonly senderPublicKey: string;
  readonly receiverPublicKey: string;
}

export function buildTransaction(spec: TransactionSpec): BuiltTransaction {
  const senderPublicKey = publicKeyFromSeed(spec.senderSeed);
  const receiverPublicKey = publicKeyFromSeed(spec.receiverSeed);

  // Insertion sequence — written literally, never sorted or spread.
  const inner: Record<string, unknown> = {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: spec.unixTimeSecs ?? "1784332800.125",
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: senderPublicKey,
    step_2_key_public__base64urlsafe: receiverPublicKey,
    step_1_state: { amount: spec.senderBalanceAfter },
    step_2_state: { amount: spec.receiverBalanceAfter },
    previous_step_1_state_signature: spec.previousStep1Signature ?? "",
    previous_step_2_state_signature: spec.previousStep2Signature ?? "",
  };
  if (spec.expiry !== undefined) inner.expiry__unix_time_secs = spec.expiry;
  if (spec.message !== undefined) inner.message = spec.message;

  const innerPreimageText = JSON.stringify(inner);
  const step1Signature = signText(innerPreimageText, spec.step1SigningSeed ?? spec.senderSeed);
  const step2Signature = signText(
    JSON.stringify({ inner, step_1_signature: step1Signature }),
    spec.receiverSeed,
  );
  const settledText = `{"inner":${innerPreimageText},"step_1_signature":${JSON.stringify(step1Signature)},"step_2_signature":${JSON.stringify(step2Signature)}}`;

  return {
    parsed: parseSettled(settledText),
    settledText,
    innerPreimageText,
    step1Signature,
    step2Signature,
    senderPublicKey,
    receiverPublicKey,
  };
}

/** Through the real envelope stage, so the policies never see a hand-made parse tree. */
export function parseSettled(settledText: string): ParsedSettledTransaction {
  const verdict = parseGatewayEnvelope(
    new TextEncoder().encode(`{"status":true,"code":"success","message":"","data":[${settledText}]}`),
  );
  if (verdict.classification !== "HEAD") {
    throw new Error(`expected a HEAD envelope verdict, got ${verdict.classification}`);
  }
  return verdict.parsed;
}
