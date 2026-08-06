// vectors for the transaction verification stage:
// byte-exact golden reproduction of BOTH frozen transactions (expected bytes
// read from the frozen fixtures/manifest, never regenerated), the six-item
// crypto test list, and the purity/boundary pins. The stage is exercised through the
// real pipeline seam: fixture bytes → envelope verdict → this stage.
// Negative-path/fuzz batteries live in transaction-verify.fuzz.test.ts and
// transaction-verify.scalar-fuzz.test.ts; schema CHECK alignment lives in
// transaction-verify.record-alignment.test.ts.
import { Buffer } from "node:buffer";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseGatewayEnvelope, type ParsedSettledTransaction } from "./gateway-envelope.js";
import * as transactionVerifyModule from "./transaction-verify.js";
import {
  TRANSACTION_VERIFY_OUTCOMES,
  WALLET_HEAD_FINGERPRINT_FIELDS,
  WALLET_HEAD_FINGERPRINT_PURPOSE,
  buildWalletHeadFingerprintPreimage,
  computeWalletHeadFingerprint,
  verifySettledTransaction,
  type VerifiedTransactionVerdict,
} from "./transaction-verify.js";

const GEN_DIR = new URL("../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// The pipeline seam: raw envelope bytes through the stage, HEAD verdict out.
function headParsed(name: string): ParsedSettledTransaction {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${fixtureText(name)}]}`,
  );
  const verdict = parseGatewayEnvelope(bytes);
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope verdict");
  return verdict.parsed;
}

function verified(name: string, walletKey: string): VerifiedTransactionVerdict {
  const verdict = verifySettledTransaction(headParsed(name), walletKey);
  if (verdict.verdict !== "VERIFIED") throw new Error(`expected VERIFIED, got ${verdict.verdict}`);
  return verdict;
}

// The exact signed inner bytes, cut from the frozen settled text (never re-serialized).
function innerSegment(settledText: string): string {
  return settledText.slice('{"inner":'.length, settledText.indexOf(',"step_1_signature":'));
}

// The step-2 preimage recovered from the completed text: everything before the step-2
// signature field, closed with the final brace.
function step2PreimageOf(completedText: string): string {
  return `${completedText.slice(0, completedText.lastIndexOf(',"step_2_signature":'))}` + "}";
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function publicKeyObject(paddedBase64UrlKey: string) {
  const der = Buffer.concat([
    ED25519_SPKI_PREFIX,
    Buffer.from(paddedBase64UrlKey, "base64url"),
  ]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

interface ManifestRoleProjection {
  readonly S: string;
  readonly P: string;
  readonly B: string;
}

interface ManifestTransactionGoldens {
  readonly step_1_sha256: string;
  readonly step_1_signature: string;
  readonly step_2_sha256: string;
  readonly step_2_signature: string;
  readonly settled_sha256: string;
  readonly role_relative_projection: Record<string, ManifestRoleProjection>;
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
  predecessor: ManifestTransactionGoldens;
  target: ManifestTransactionGoldens & {
    receiver_terminal_head: { preimage_sha256: string; fingerprint: string };
  };
};

const SENDER_KEY = MANIFEST.public_keys.seed_02;
const RECEIVER_KEY = MANIFEST.public_keys.seed_03;
const PREDECESSOR_SENDER_KEY = MANIFEST.public_keys.seed_05;

function expectProjection(
  verdict: VerifiedTransactionVerdict,
  expected: ManifestRoleProjection,
  role: string,
  innerSha256: string,
): void {
  expect(verdict.projection.role).toBe(role);
  expect(verdict.projection.S).toBe(expected.S);
  expect(verdict.projection.P).toBe(expected.P);
  expect(verdict.projection.B).toBe(expected.B);
  expect(verdict.projection.I).toBe(innerSha256);
}

describe("A.8.1 golden reproduction — target transaction (sender 02, receiver 03)", () => {
  it("returns VERIFIED for the receiver with every byte-exact artifact from the manifest", () => {
    const parsed = headParsed("target.settled.json");
    const verdict = verifySettledTransaction(parsed, RECEIVER_KEY);
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;

    // The reconstructed preimage IS the frozen signed bytes.
    expect(verdict.innerPreimageText).toBe(innerSegment(fixtureText("target.settled.json")));
    expect(sha256Hex(verdict.innerPreimageText)).toBe(MANIFEST.target.step_1_sha256);
    expect(sha256Hex(step2PreimageOf(verdict.completedTransactionText))).toBe(
      MANIFEST.target.step_2_sha256,
    );

    // The completed text round-trips the fixture bytes exactly.
    expect(verdict.completedTransactionText).toBe(fixtureText("target.settled.json"));
    expect(verdict.completedTransactionSha256).toBe(MANIFEST.target.settled_sha256);
    expect(verdict.transaction).toBe(parsed); // narrowed in place, never rebuilt

    // Receiver projection per the manifest (P="", B="2.25").
    expectProjection(
      verdict,
      MANIFEST.target.role_relative_projection.seed_03_receiver,
      "receiver",
      MANIFEST.target.step_1_sha256,
    );

    // The frozen receiver terminal head fingerprint.
    expect(verdict.semanticFingerprint).toBe(MANIFEST.target.receiver_terminal_head.fingerprint);
    expect(verdict.semanticFingerprint).toBe(
      "d03a98b770684e577667f9bde01276b196b98db31663f23b0900623d6dffca2a",
    );
  });

  it("reproduces the frozen fingerprint preimage byte-for-byte (receiver-head-fingerprint.txt)", () => {
    const verdict = verified("target.settled.json", RECEIVER_KEY);
    const material = {
      walletPublicKey: RECEIVER_KEY,
      stateKind: "HEAD" as const,
      sSignature: verdict.projection.S,
      pSignature: verdict.projection.P,
      bAmount: verdict.projection.B,
      innerSha256: verdict.projection.I,
      step1Signature: verdict.transaction.step_1_signature,
      step2Signature: verdict.transaction.step_2_signature,
    };
    const fixtureLines = fixtureText("receiver-head-fingerprint.txt").split("\n");
    const fixturePreimage = `${fixtureLines[0]}\n${fixtureLines[1]}`;
    expect(buildWalletHeadFingerprintPreimage(material)).toBe(fixturePreimage);
    expect(sha256Hex(fixturePreimage)).toBe(MANIFEST.target.receiver_terminal_head.preimage_sha256);
  });

  it("returns VERIFIED for the sender with the sender-side projection (P=predecessor S, B=\"7.75\")", () => {
    const verdict = verified("target.settled.json", SENDER_KEY);
    expectProjection(
      verdict,
      MANIFEST.target.role_relative_projection.seed_02_sender,
      "sender",
      MANIFEST.target.step_1_sha256,
    );
    // Role-relative material differs from the receiver's, so the fingerprint differs.
    expect(verdict.semanticFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(verdict.semanticFingerprint).not.toBe(MANIFEST.target.receiver_terminal_head.fingerprint);
  });
});

describe("A.8.1 golden reproduction — predecessor transaction (sender 05, receiver 02)", () => {
  it("returns VERIFIED for the receiver with the genesis-link projection (P=\"\", B=\"10\")", () => {
    const verdict = verified("predecessor.settled.json", SENDER_KEY); // seed 02 is receiver here
    expect(verdict.completedTransactionText).toBe(fixtureText("predecessor.settled.json"));
    expect(verdict.completedTransactionSha256).toBe(MANIFEST.predecessor.settled_sha256);
    expect(sha256Hex(verdict.innerPreimageText)).toBe(MANIFEST.predecessor.step_1_sha256);
    expect(sha256Hex(step2PreimageOf(verdict.completedTransactionText))).toBe(
      MANIFEST.predecessor.step_2_sha256,
    );
    expectProjection(
      verdict,
      MANIFEST.predecessor.role_relative_projection.seed_02_receiver,
      "receiver",
      MANIFEST.predecessor.step_1_sha256,
    );
  });

  it("returns VERIFIED for the funded sender with the A.9 #17 boundary predecessor link", () => {
    const verdict = verified("predecessor.settled.json", PREDECESSOR_SENDER_KEY);
    const expected = MANIFEST.predecessor.role_relative_projection.seed_05_sender;
    expectProjection(verdict, expected, "sender", MANIFEST.predecessor.step_1_sha256);
    expect(expected.P).toBe(
      "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ==",
    );
    expect(expected.B).toBe("0"); // zero is a valid amount
  });
});

describe("crypto item 1 — both valid signatures pass over the exact preimages", () => {
  it("cross-checks both frozen signatures with node:crypto directly over the reconstructed preimages", () => {
    const verdict = verified("target.settled.json", RECEIVER_KEY);
    const step1Ok = edVerify(
      null,
      Buffer.from(verdict.innerPreimageText, "utf8"),
      publicKeyObject(SENDER_KEY),
      Buffer.from(MANIFEST.target.step_1_signature, "base64url"),
    );
    const step2Ok = edVerify(
      null,
      Buffer.from(step2PreimageOf(verdict.completedTransactionText), "utf8"),
      publicKeyObject(RECEIVER_KEY),
      Buffer.from(MANIFEST.target.step_2_signature, "base64url"),
    );
    expect(step1Ok).toBe(true);
    expect(step2Ok).toBe(true);
  });
});

describe("crypto item 2 — each perturbation fails closed", () => {
  it("rejects a key-rotated inner (type moved to the last position)", () => {
    const parsed = headParsed("target.settled.json");
    const { type, ...rest } = parsed.inner;
    const verdict = verifySettledTransaction(
      { ...parsed, inner: { ...rest, type } as typeof parsed.inner },
      RECEIVER_KEY,
    );
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection.reason).toBe("unexpected_inner_shape");
  });

  it("rejects a mutated step-1 signature (one character flipped inside the alphabet)", () => {
    const parsed = headParsed("target.settled.json");
    const flipped = `x${parsed.step_1_signature.slice(1)}`;
    const verdict = verifySettledTransaction({ ...parsed, step_1_signature: flipped }, RECEIVER_KEY);
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict.verdict !== "UNVERIFIED_SIGNATURE") return;
    expect(verdict.failedStep).toBe(1);
  });

  it("rejects the wrong signer key for step 1 (predecessor sender key substituted)", () => {
    const parsed = headParsed("target.settled.json");
    const inner = { ...parsed.inner, step_1_key_public__base64urlsafe: PREDECESSOR_SENDER_KEY };
    const verdict = verifySettledTransaction({ ...parsed, inner }, RECEIVER_KEY);
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict.verdict !== "UNVERIFIED_SIGNATURE") return;
    expect(verdict.failedStep).toBe(1);
  });

  it("rejects a numeric amount (string-only per)", () => {
    const parsed = headParsed("target.settled.json");
    const inner = { ...parsed.inner, step_1_state: { amount: 7.75 } } as typeof parsed.inner;
    const verdict = verifySettledTransaction({ ...parsed, inner }, RECEIVER_KEY);
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection).toMatchObject({
      reason: "invalid_scalar",
      scalarKind: "ZkzBalance",
      scalarReason: "wrong_type",
    });
  });

  it("rejects an unpadded wallet public key", () => {
    const parsed = headParsed("target.settled.json");
    const inner = {
      ...parsed.inner,
      step_1_key_public__base64urlsafe: SENDER_KEY.slice(0, -1),
    } as typeof parsed.inner;
    const verdict = verifySettledTransaction({ ...parsed, inner }, RECEIVER_KEY);
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection).toMatchObject({
      reason: "invalid_scalar",
      scalarKind: "WalletPublicKey",
    });
  });

  it("rejects an unknown top-level inner field", () => {
    const parsed = headParsed("target.settled.json");
    const inner = { ...parsed.inner, extra_field: "x" } as typeof parsed.inner;
    const verdict = verifySettledTransaction({ ...parsed, inner }, RECEIVER_KEY);
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection.reason).toBe("unexpected_inner_shape");
  });
});

describe("crypto item 3 — role-relative P/B extraction is correct per role", () => {
  it("extracts sender and receiver material from the same transaction without cross-wiring", () => {
    const sender = verified("target.settled.json", SENDER_KEY);
    const receiver = verified("target.settled.json", RECEIVER_KEY);
    // S is T.step_2_signature in EITHER role; P and B are role-relative (the closing
    // note: never the other role's previous-signature or amount).
    expect(sender.projection.S).toBe(receiver.projection.S);
    expect(sender.projection.P).toBe(MANIFEST.target.role_relative_projection.seed_02_sender.P);
    expect(receiver.projection.P).toBe("");
    expect(sender.projection.B).toBe("7.75");
    expect(receiver.projection.B).toBe("2.25");
  });
});

describe("crypto item 5 — envelope mutation does not alter valid transaction signatures", () => {
  it("yields the identical VERIFIED verdict under a perturbed envelope wrapper", () => {
    const txText = fixtureText("target.settled.json");
    const plain = new TextEncoder().encode(`{"status":true,"code":"success","message":"","data":[${txText}]}`);
    const perturbed = new TextEncoder().encode(
      `  {"status":true,"code":"success","message":"perturbed wrapper text","data":[ ${txText} ]}\n`,
    );
    const plainVerdict = parseGatewayEnvelope(plain);
    const perturbedVerdict = parseGatewayEnvelope(perturbed);
    if (plainVerdict.classification !== "HEAD" || perturbedVerdict.classification !== "HEAD") {
      throw new Error("expected HEAD envelope verdicts");
    }
    const first = verifySettledTransaction(plainVerdict.parsed, RECEIVER_KEY);
    const second = verifySettledTransaction(perturbedVerdict.parsed, RECEIVER_KEY);
    expect(first.verdict).toBe("VERIFIED");
    expect(second).toEqual(first);
    if (second.verdict !== "VERIFIED" || first.verdict !== "VERIFIED") return;
    expect(second.completedTransactionSha256).toBe(MANIFEST.target.settled_sha256);
  });
});

describe("crypto item 6 — exact byte round-trip, invalid UTF-8 included", () => {
  it("round-trips the signed inner bytes: the preimage re-parses to the identical object", () => {
    const parsed = headParsed("target.settled.json");
    const verdict = verified("target.settled.json", RECEIVER_KEY);
    expect(JSON.parse(verdict.innerPreimageText)).toEqual(parsed.inner);
    expect(Object.keys(JSON.parse(verdict.innerPreimageText))).toEqual(
      Object.keys(parsed.inner),
    );
  });

  it("is never reached by invalid UTF-8: the envelope stage fails closed first, digest intact", () => {
    const decodable = new TextEncoder().encode(
      `{"status":true,"code":"success","message":"","data":[${fixtureText("target.settled.json")}]}`,
    );
    const undecodable = Uint8Array.from(decodable, (byte, index) => (index === 60 ? 0xff : byte));
    const verdict = parseGatewayEnvelope(undecodable);
    expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
    expect(verdict.rawSha256).toBe(
      createHash("sha256").update(undecodable).digest("hex"),
    );
  });
});

describe("purity, boundary, and freeze pins — the never-blind-retry rule", () => {
  it("never mutates its input and narrows the transaction in place", () => {
    const parsed = headParsed("target.settled.json");
    const snapshot = JSON.stringify(parsed);
    const verdict = verifySettledTransaction(parsed, RECEIVER_KEY);
    expect(JSON.stringify(parsed)).toBe(snapshot);
    if (verdict.verdict !== "VERIFIED") throw new Error("expected VERIFIED");
    expect(verdict.transaction).toBe(parsed);
    expect(verdict.transaction.inner).toBe(parsed.inner);
  });

  it("is deterministic across repeated calls", () => {
    const first = verifySettledTransaction(headParsed("target.settled.json"), RECEIVER_KEY);
    const second = verifySettledTransaction(headParsed("target.settled.json"), RECEIVER_KEY);
    expect(second).toEqual(first);
  });

  it("exports only pure surface — no capability, class, or submit/retry authority", () => {
    const moduleExports = Object.entries(transactionVerifyModule).map(
      ([name, value]) => `${name}:${typeof value}`,
    );
    expect(moduleExports.sort()).toEqual(
      [
        "TRANSACTION_VERIFY_OUTCOMES:object",
        "WALLET_HEAD_FINGERPRINT_FIELDS:object",
        "WALLET_HEAD_FINGERPRINT_PURPOSE:string",
        "buildWalletHeadFingerprintPreimage:function",
        "computeWalletHeadFingerprint:function",
        "verifySettledTransaction:function",
      ].sort(),
    );
  });

  it("pins the A.7 fingerprint payload to its exact 10-field sequence", () => {
    expect([...WALLET_HEAD_FINGERPRINT_FIELDS]).toEqual([
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
    ]);
    const preimage = buildWalletHeadFingerprintPreimage({
      walletPublicKey: RECEIVER_KEY,
      stateKind: "GENESIS",
      sSignature: "",
      pSignature: "",
      bAmount: "0",
      innerSha256: null,
      step1Signature: null,
      step2Signature: null,
    });
    const [purposeLine, payloadLine] = preimage.split("\n");
    expect(purposeLine).toBe(WALLET_HEAD_FINGERPRINT_PURPOSE);
    expect(Object.keys(JSON.parse(payloadLine))).toEqual([...WALLET_HEAD_FINGERPRINT_FIELDS]);
    expect(computeWalletHeadFingerprint({
      walletPublicKey: RECEIVER_KEY,
      stateKind: "GENESIS",
      sSignature: "",
      pSignature: "",
      bAmount: "0",
      innerSha256: null,
      step1Signature: null,
      step2Signature: null,
    })).toMatch(/^[0-9a-f]{64}$/);
  });

  it("maps this stage's outcomes onto the observation_parse_result members", () => {
    expect([...TRANSACTION_VERIFY_OUTCOMES]).toEqual([
      "VERIFIED",
      "UNVERIFIED_SIGNATURE",
      "WALLET_ROLE_INVALID",
      "MALFORMED_TRANSACTION",
    ]);
  });
});

describe("WALLET_HEAD_FINGERPRINT_PURPOSE mirror parity — A.7 / compatibility-literal allowlist freeze", () => {
  it("matches the canonical freeze in generic-node-contracts byte-for-byte", () => {
    const sourceText = readFileSync(
      fileURLToPath(
        new URL(
          "../../../generic-node-contracts/src/compat-literals/compat-literals.contract.ts",
          import.meta.url,
        ),
      ),
      "utf8",
    );
    expect(sourceText).toContain(
      `export const WALLET_HEAD_FINGERPRINT_PURPOSE = "zp-wallet-head-fingerprint-v1" as const;`,
    );
    expect(WALLET_HEAD_FINGERPRINT_PURPOSE).toBe("zp-wallet-head-fingerprint-v1");
  });
});
