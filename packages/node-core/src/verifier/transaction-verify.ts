// the transaction verification stage: consumes the
// HEAD verdict of the envelope parser (gateway-envelope.ts) and decides whether
// the settled transaction it carries is exact for the queried wallet.
//
// Step 1 — pre-signature validation (inner-shape.ts): closed 14-field shape in
// the protocol's exact insertion sequence + branded scalars, before any
// signature byte is read.
// Step 2 — preimage reconstruction + dual Ed25519: step_1_preimage_text is
// JSON.stringify(inner) taken DIRECTLY on the insertion-sequenced parsed
// object — never re-parsed, key-sorted, prefixed, or hashed first
// (the byte-exact signing rule). SplitChain signs natively: it does not use the suite
// prefix; the suite serializer belongs only to the fingerprint below. Step 1 verifies under the
// sender key, then step 2 over JSON.stringify({inner, step_1_signature})
// under the receiver key (the signing matrix); a step-1 failure
// short-circuits — step 2 is never tried against an unverified step 1.
// Step 3 — role-relative state via the on-main projection (wallet-role.ts):
// byte-exact key comparison, exactly one of sender/receiver; both or
// neither is WALLET_ROLE_INVALID.
// Step 4 — the `zp-wallet-head-fingerprint-v1` semantic fingerprint, built
// only after steps 1–3 pass via the ONE suite constructor
// (`buildWalletHeadFingerprint`); unsigned SHA-256 (landing-path oracle; platform holds zero keys).
// `b_amount` is foreign-preserving (Byte-exact).
//
// Pure: typed input, typed verdict out; no DB write, no state
// mutation, no retry authority (this stage's codes carry retry authority: none).
// clean-room: no v1 verification code copied; compatibility-literal allowlist: the `zp-*-v1` literal is never
// renamed.
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { verifyRawEd25519 } from "../protocol/ed25519-verify.js";
import type { SettledSplitChainTransaction } from "../protocol/inner.js";
import { parseEd25519Signature, parseWalletPublicKey } from "../protocol/scalars.js";
import { buildWalletHeadFingerprint } from "../protocol/suite/builders.js";
import { projectRoleRelativeState, type WalletStateProjection } from "../protocol/wallet-role.js";
import type { ParsedSettledTransaction } from "./gateway-envelope.js";
import { narrowSplitChainInner, type InnerShapeRejection } from "./inner-shape.js";

// Mirrored byte-for-byte from its canonical freeze at
// packages/generic-node-contracts/src/compat-literals/compat-literals.contract.ts
// (`WALLET_HEAD_FINGERPRINT_PURPOSE`, A.7). The contracts package's `exports` map exposes
// no `./compat-literals` subpath, so node-core mirrors the frozen literal instead of
// importing it; transaction-verify.test.ts pins the mirror against the source line so a
// freeze change cannot drift silently (same precedent as
// GATEWAY_RESPONSE_FIELDS mirror).
export const WALLET_HEAD_FINGERPRINT_PURPOSE = "zp-wallet-head-fingerprint-v1";

// A.7 payload — the exact 10-field sequence. The fingerprint is the one member of the
// zp-*-v1 family that is hashed, not signed (landing-path oracle).
export const WALLET_HEAD_FINGERPRINT_FIELDS = [
  "purpose",
  "canonical_version",
  "wallet_public_key",
  "state_kind",
  "s_signature",
  "p_signature",
  "b_amount",
  "inner_sha256",
  "step_1_signature",
  "step_2_signature",
] as const;

// This stage's verdicts align one-to-one with the observation_parse_result members a
// settled transaction can produce (genesis and envelope results belong to other stages).
export const TRANSACTION_VERIFY_OUTCOMES = [
  "VERIFIED",
  "UNVERIFIED_SIGNATURE",
  "WALLET_ROLE_INVALID",
  "MALFORMED_TRANSACTION",
] as const;

export type TransactionVerifyOutcome = (typeof TRANSACTION_VERIFY_OUTCOMES)[number];

export interface VerifiedTransactionVerdict {
  readonly verdict: "VERIFIED";
  // The envelope stage's own object, narrowed in place — never rebuilt, so
  // JSON.stringify(transaction) still reproduces the exact signed bytes (A.9 #15).
  readonly transaction: SettledSplitChainTransaction;
  readonly projection: WalletStateProjection;
  readonly innerPreimageText: string;
  readonly completedTransactionText: string;
  readonly completedTransactionSha256: string;
  // A.7 fingerprint over the queried wallet's HEAD material — hashed, not signed.
  readonly semanticFingerprint: string;
}

export interface UnverifiedSignatureVerdict {
  readonly verdict: "UNVERIFIED_SIGNATURE";
  readonly failedStep: 1 | 2;
}

export interface WalletRoleInvalidVerdict {
  readonly verdict: "WALLET_ROLE_INVALID";
  readonly detail: string;
}

// A preimage-reconstruction rejection: the inner passed shape narrowing and every
// branded scalar, but JSON.stringify could not re-serialize it. V8's serializer is
// recursive and throws RangeError on nesting beyond its depth limit (~6k levels), while
// its JSON.parse is iterative and accepts far deeper structures — so a hostile gateway
// can supply an envelope that parses and narrows yet is not re-serializable. Distinct
// from inner-shape.ts's two codes, which have all passed by the time this
// rejection is produced; an inner that cannot be reconstructed byte-exactly can never
// be verified, so it fails closed (typed input, typed verdict out).
export type PreimageEncodingRejection = {
  readonly reason: "preimage_encoding_failure";
  readonly detail: string;
};

export interface MalformedTransactionVerdict {
  readonly verdict: "MALFORMED_TRANSACTION";
  readonly rejection: InnerShapeRejection | PreimageEncodingRejection;
}

export type TransactionVerifyVerdict =
  | VerifiedTransactionVerdict
  | UnverifiedSignatureVerdict
  | WalletRoleInvalidVerdict
  | MalformedTransactionVerdict;

// A.7 input material: the queried wallet's role-relative state plus both SplitChain
// signatures. At genesis the shape is fixed (S="", P="", B="0", I=null, both step
// signatures null); at HEAD every field is populated.
export interface WalletHeadFingerprintMaterial {
  readonly walletPublicKey: string;
  readonly stateKind: "GENESIS" | "HEAD";
  readonly sSignature: string;
  readonly pSignature: string;
  readonly bAmount: string;
  readonly innerSha256: string | null;
  readonly step1Signature: string | null;
  readonly step2Signature: string | null;
}

// A.7 digest — ONE constructor shared with observation re-read (suite serializer only).
// Hand-rolled JSON.stringify preimages are forbidden here: encodeZkzBalance is
// foreign-preserving (parseObservedZkzBalance), so write-path and read-path digests
// agree on Byte-exact/canonical ZKZ amount contract non-canonical head balances (e.g. "2.50").
export function buildWalletHeadFingerprintPreimage(material: WalletHeadFingerprintMaterial): string {
  return buildWalletHeadFingerprint({
    wallet_public_key: material.walletPublicKey as never,
    state_kind: material.stateKind as never,
    s_signature: material.sSignature as never,
    p_signature: material.pSignature as never,
    b_amount: material.bAmount as never,
    inner_sha256: material.innerSha256 as never,
    step_1_signature: material.step1Signature as never,
    step_2_signature: material.step2Signature as never,
  }).preimageText;
}

export function computeWalletHeadFingerprint(material: WalletHeadFingerprintMaterial): string {
  return buildWalletHeadFingerprint({
    wallet_public_key: material.walletPublicKey as never,
    state_kind: material.stateKind as never,
    s_signature: material.sSignature as never,
    p_signature: material.pSignature as never,
    b_amount: material.bAmount as never,
    inner_sha256: material.innerSha256 as never,
    step_1_signature: material.step1Signature as never,
    step_2_signature: material.step2Signature as never,
  }).sha256;
}

// Ed25519 over the exact preimage bytes (UTF-8). Unparseable key or signature
// bytes fail closed BEFORE any crypto call; raw verify is never an open throw.
function verifySplitChainSignature(
  preimageText: string,
  publicKeyText: string,
  signatureText: string,
): boolean {
  let canonicalKey: string;
  let canonicalSignature: string;
  try {
    canonicalKey = parseWalletPublicKey(publicKeyText);
    canonicalSignature = parseEd25519Signature(signatureText);
  } catch {
    return false;
  }
  return verifyRawEd25519({
    publicKeyBytes: Buffer.from(canonicalKey, "base64url"),
    preimageBytes: Buffer.from(preimageText, "utf8"),
    signatureBytes: Buffer.from(canonicalSignature, "base64url"),
  });
}

// Reconstruct one signed preimage text byte-exactly: JSON.stringify directly on the
// insertion-sequenced parsed object, never reformatted (the byte-exact signing rule). A RangeError
// here is a typed fail-closed rejection, never an uncaught throw — the recursive
// serializer can fail on nesting the iterative JSON.parse accepted (see
// PreimageEncodingRejection). Any other failure cannot arise from JSON.parse'd
// gateway bytes and is rethrown, not silenced.
function reconstructPreimageText(value: unknown): string | PreimageEncodingRejection {
  try {
    return JSON.stringify(value);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    return {
      reason: "preimage_encoding_failure",
      detail: "preimage JSON.stringify exceeded the engine's serialization depth limit",
    };
  }
}

// The verification stage over one HEAD-verdict settled transaction, for one queried
// wallet public key. The input is never mutated; the verdict is deterministic in the
// (parsed, key) pair.
export function verifySettledTransaction(
  parsed: ParsedSettledTransaction,
  queriedWalletPublicKey: string,
): TransactionVerifyVerdict {
  // Step 1 — closed-set shape and branded scalars, before any signature byte.
  const narrowing = narrowSplitChainInner(parsed.inner);
  if (!narrowing.ok) {
    return { verdict: "MALFORMED_TRANSACTION", rejection: narrowing.rejection };
  }
  const inner = narrowing.inner;

  // Step 2 — reconstruct each preimage directly on the insertion-sequenced parsed
  // object and verify the dual Ed25519 chain in signing-matrix sequence: step 1
  // under the sender key, then step 2 under the receiver key. A reconstruction that
  // the engine cannot serialize fails closed BEFORE any signature byte is read.
  const innerPreimageText = reconstructPreimageText(inner);
  if (typeof innerPreimageText !== "string") {
    return { verdict: "MALFORMED_TRANSACTION", rejection: innerPreimageText };
  }
  const step1Verified = verifySplitChainSignature(
    innerPreimageText,
    inner.step_1_key_public__base64urlsafe,
    parsed.step_1_signature,
  );
  if (!step1Verified) {
    return { verdict: "UNVERIFIED_SIGNATURE", failedStep: 1 };
  }

  // Only reachable behind a genuine step-1 signature, but guarded for the same
  // fail-closed contract as the inner preimage above.
  const step2PreimageText = reconstructPreimageText({
    inner,
    step_1_signature: parsed.step_1_signature,
  });
  if (typeof step2PreimageText !== "string") {
    return { verdict: "MALFORMED_TRANSACTION", rejection: step2PreimageText };
  }
  const step2Verified = verifySplitChainSignature(
    step2PreimageText,
    inner.step_2_key_public__base64urlsafe,
    parsed.step_2_signature,
  );
  if (!step2Verified) {
    return { verdict: "UNVERIFIED_SIGNATURE", failedStep: 2 };
  }

  // Step 3 — role-relative state: exactly one role holds for the queried key.
  const transaction = parsed as unknown as SettledSplitChainTransaction;
  const roleResult = projectRoleRelativeState(transaction, queriedWalletPublicKey);
  if (!roleResult.ok) {
    return { verdict: "WALLET_ROLE_INVALID", detail: roleResult.detail };
  }
  const projection = roleResult.projection;

  // Step 4 — settled-text evidence (the fixed top-level sequence, byte-exact with the
  // signed preimages) and the semantic fingerprint; both only after steps 1–3 pass.
  const completedTransactionText =
    `{"inner":${innerPreimageText}` +
    `,"step_1_signature":${JSON.stringify(parsed.step_1_signature)}` +
    `,"step_2_signature":${JSON.stringify(parsed.step_2_signature)}}`;
  const completedTransactionSha256 = createHash("sha256")
    .update(completedTransactionText, "utf8")
    .digest("hex");
  const semanticFingerprint = computeWalletHeadFingerprint({
    walletPublicKey: queriedWalletPublicKey,
    stateKind: "HEAD",
    sSignature: projection.S,
    pSignature: projection.P,
    bAmount: projection.B,
    innerSha256: projection.I,
    step1Signature: parsed.step_1_signature,
    step2Signature: parsed.step_2_signature,
  });

  return {
    verdict: "VERIFIED",
    transaction,
    projection,
    innerPreimageText,
    completedTransactionText,
    completedTransactionSha256,
    semanticFingerprint,
  };
}
