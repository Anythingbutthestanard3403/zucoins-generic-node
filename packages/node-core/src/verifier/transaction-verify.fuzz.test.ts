// negative-path and fuzz batteries for the transaction verification stage: the
// A.9 #15 JSONB-reconstruction attack (shape-level AND byte-level defeats), signature
// swap / cross-transaction reuse / one-bit flip / wrong key, the crypto item 4 role
// battery (self-transfer and absent-wallet queries), and signed positive variants for
// the optional-field shapes. Mutating fixture bytes or test-signing with the A.8 seeds
// builds adversarial INPUTS — expected bytes are never regenerated (the seeds are
// public test material per A.8; A.9 #16: golden keys never live). Shape and scalar
// grammar batteries live in transaction-verify.scalar-fuzz.test.ts.
import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseGatewayEnvelope, type ParsedSettledTransaction } from "./gateway-envelope.js";
import { verifySettledTransaction } from "./transaction-verify.js";

const GEN_DIR = new URL("../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

function headParsed(name: string): ParsedSettledTransaction {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${fixtureText(name)}]}`,
  );
  const verdict = parseGatewayEnvelope(bytes);
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope verdict");
  return verdict.parsed;
}

// JSON round-trip preserves insertion sequence, so a clone stays a valid base for
// single-field mutations.
function cloneTx(tx: ParsedSettledTransaction): ParsedSettledTransaction {
  return JSON.parse(JSON.stringify(tx)) as ParsedSettledTransaction;
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};
const SENDER_KEY = MANIFEST.public_keys.seed_02;
const RECEIVER_KEY = MANIFEST.public_keys.seed_03;
const PREDECESSOR_SENDER_KEY = MANIFEST.public_keys.seed_05;

// A.8 test-only seed derivation, same construction as the contracts package's frozen
// golden tests: a 32-byte filled seed behind the RFC 8032 PKCS8 prefix.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function paddedBase64Url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

function seedKeyPair(seedByte: number): {
  publicKeyText: string;
  signText: (text: string) => string;
} {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.alloc(32, seedByte)]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKeyText = paddedBase64Url(spki.subarray(spki.length - 32));
  return {
    publicKeyText,
    signText: (text) => paddedBase64Url(edSign(null, Buffer.from(text, "utf8"), privateKey)),
  };
}

// Sign a settled transaction over the exact preimage texts with the
// given seed roles — used ONLY to build adversarial or shape-variant inputs.
function settledSignedBy(
  inner: ParsedSettledTransaction["inner"],
  step1Seed: number,
  step2Seed: number,
): ParsedSettledTransaction {
  const step1Signature = seedKeyPair(step1Seed).signText(JSON.stringify(inner));
  const step2Signature = seedKeyPair(step2Seed).signText(
    JSON.stringify({ inner, step_1_signature: step1Signature }),
  );
  return { inner, step_1_signature: step1Signature, step_2_signature: step2Signature };
}

describe("seed derivation pins against the frozen manifest", () => {
  it("derives the exact A.8 public keys from the test-only seeds", () => {
    expect(seedKeyPair(0x02).publicKeyText).toBe(SENDER_KEY);
    expect(seedKeyPair(0x03).publicKeyText).toBe(RECEIVER_KEY);
    expect(seedKeyPair(0x05).publicKeyText).toBe(PREDECESSOR_SENDER_KEY);
  });
});

describe("A.9 #15 — JSONB-reconstruction attack is a negative vector", () => {
  it("defeats a sorted-key reconstruction at the shape stage (before any crypto)", () => {
    const original = headParsed("target.settled.json");
    const sortedInner: Record<string, unknown> = {};
    for (const key of Object.keys(original.inner).sort()) {
      sortedInner[key] = (original.inner as Record<string, unknown>)[key];
    }
    const verdict = verifySettledTransaction(
      { ...original, inner: sortedInner as typeof original.inner },
      RECEIVER_KEY,
    );
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection.reason).toBe("unexpected_inner_shape");
  });

  it("defeats a whitespace preimage at the signature stage (byte-exactness, crypto item 2)", () => {
    // The signature below is valid — over the pretty-printed bytes. The verifier
    // reconstructs the compact preimage from the parsed object, so the bytes differ
    // and verification must fail.
    const tx = cloneTx(headParsed("target.settled.json"));
    const prettyPreimage = JSON.stringify(tx.inner, null, 1);
    expect(prettyPreimage).not.toBe(JSON.stringify(tx.inner));
    expect(JSON.parse(prettyPreimage)).toEqual(tx.inner);
    const signed = { ...tx, step_1_signature: seedKeyPair(0x02).signText(prettyPreimage) };
    const verdict = verifySettledTransaction(signed, RECEIVER_KEY);
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict.verdict !== "UNVERIFIED_SIGNATURE") return;
    expect(verdict.failedStep).toBe(1);
  });

  it("defeats metadata key rotation inside a state object — even unchecked fields ride in the signed bytes", () => {
    const base = cloneTx(headParsed("target.settled.json"));
    const inner = {
      ...base.inner,
      step_1_state: { amount: "7.75", metadata: { alpha: "1", beta: "2" } },
    } as typeof base.inner;
    const signed = settledSignedBy(inner, 0x02, 0x03);
    expect(verifySettledTransaction(signed, RECEIVER_KEY).verdict).toBe("VERIFIED");

    const rotated = cloneTx(signed);
    (rotated.inner as Record<string, unknown>).step_1_state = {
      amount: "7.75",
      metadata: { beta: "2", alpha: "1" },
    };
    const verdict = verifySettledTransaction(rotated, RECEIVER_KEY);
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict.verdict !== "UNVERIFIED_SIGNATURE") return;
    expect(verdict.failedStep).toBe(1);
  });

  it("accepts a sequence-preserving rebuild — the defense is byte-based, not identity-based", () => {
    const tx = headParsed("target.settled.json");
    const rebuilt = { ...tx, inner: { ...tx.inner } };
    expect(rebuilt).not.toBe(tx);
    expect(JSON.stringify(rebuilt)).toBe(JSON.stringify(tx));
    expect(verifySettledTransaction(rebuilt, RECEIVER_KEY).verdict).toBe("VERIFIED");
  });
});

describe("signature battery — swap, reuse, bit flip, wrong key", () => {
  it("rejects swapped step signatures at step 1 (step 2 is never tried)", () => {
    const tx = headParsed("target.settled.json");
    const swapped = {
      ...tx,
      step_1_signature: tx.step_2_signature,
      step_2_signature: tx.step_1_signature,
    };
    const verdict = verifySettledTransaction(swapped, RECEIVER_KEY);
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict.verdict !== "UNVERIFIED_SIGNATURE") return;
    expect(verdict.failedStep).toBe(1);
  });

  it("rejects cross-transaction signature reuse in both directions", () => {
    const target = headParsed("target.settled.json");
    const predecessor = headParsed("predecessor.settled.json");
    const wrongStep1 = { ...target, step_1_signature: predecessor.step_1_signature };
    const step1Verdict = verifySettledTransaction(wrongStep1, RECEIVER_KEY);
    expect(step1Verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (step1Verdict.verdict === "UNVERIFIED_SIGNATURE") expect(step1Verdict.failedStep).toBe(1);

    const wrongStep2 = { ...predecessor, step_2_signature: target.step_2_signature };
    const step2Verdict = verifySettledTransaction(wrongStep2, SENDER_KEY);
    expect(step2Verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (step2Verdict.verdict === "UNVERIFIED_SIGNATURE") expect(step2Verdict.failedStep).toBe(2);
  });

  it("rejects a one-bit flip in each signature at the correct step", () => {
    const tx = headParsed("target.settled.json");
    // 'w' (0b110000) -> 'x' (0b110001): a single bit of the first signature byte.
    expect(tx.step_1_signature.startsWith("w")).toBe(true);
    const flipped1 = { ...tx, step_1_signature: `x${tx.step_1_signature.slice(1)}` };
    const verdict1 = verifySettledTransaction(flipped1, RECEIVER_KEY);
    expect(verdict1.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict1.verdict === "UNVERIFIED_SIGNATURE") expect(verdict1.failedStep).toBe(1);

    // 'u' (base64url index 46, 0b101110) -> 'v' (47, 0b101111): one bit of the first byte.
    expect(tx.step_2_signature.startsWith("u")).toBe(true);
    const flipped2 = { ...tx, step_2_signature: `v${tx.step_2_signature.slice(1)}` };
    const verdict2 = verifySettledTransaction(flipped2, RECEIVER_KEY);
    expect(verdict2.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict2.verdict === "UNVERIFIED_SIGNATURE") expect(verdict2.failedStep).toBe(2);
  });

  it("rejects the wrong signer key for step 2 while step 1 still passes", () => {
    // The inner stays byte-identical so the frozen step-1 signature still verifies;
    // step 2 is signed by the wrong seed (0x05) and verified under the inner's seed-03
    // step-2 key — the failure lands on step 2 exactly.
    const tx = headParsed("target.settled.json");
    const wrongStep2 = seedKeyPair(0x05).signText(
      JSON.stringify({ inner: tx.inner, step_1_signature: tx.step_1_signature }),
    );
    const verdict = verifySettledTransaction({ ...tx, step_2_signature: wrongStep2 }, RECEIVER_KEY);
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict.verdict !== "UNVERIFIED_SIGNATURE") return;
    expect(verdict.failedStep).toBe(2);
  });

  it("rejects an empty step-1 signature fail-closed before any crypto call", () => {
    const tx = headParsed("target.settled.json");
    const verdict = verifySettledTransaction({ ...tx, step_1_signature: "" }, RECEIVER_KEY);
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict.verdict !== "UNVERIFIED_SIGNATURE") return;
    expect(verdict.failedStep).toBe(1);
  });
});

describe("crypto item 4 — self-transfer and absent-wallet queries fail", () => {
  it("rejects a self-transfer (queried key holds BOTH step positions) as WALLET_ROLE_INVALID", () => {
    const base = cloneTx(headParsed("target.settled.json"));
    const inner = {
      ...base.inner,
      step_2_key_public__base64urlsafe: SENDER_KEY,
    } as typeof base.inner;
    // Both steps validly signed — by the SAME key; signatures must pass so the failure
    // is provably the role predicate.
    const selfTransfer = settledSignedBy(inner, 0x02, 0x02);
    const verdict = verifySettledTransaction(selfTransfer, SENDER_KEY);
    expect(verdict.verdict).toBe("WALLET_ROLE_INVALID");
  });

  it("rejects a wallet absent from both positions", () => {
    const verdict = verifySettledTransaction(headParsed("target.settled.json"), PREDECESSOR_SENDER_KEY);
    expect(verdict.verdict).toBe("WALLET_ROLE_INVALID");
  });

  it("rejects an empty and a garbage queried key as absent (byte-exact comparison only)", () => {
    expect(verifySettledTransaction(headParsed("target.settled.json"), "").verdict).toBe(
      "WALLET_ROLE_INVALID",
    );
    expect(verifySettledTransaction(headParsed("target.settled.json"), "not-a-key").verdict).toBe(
      "WALLET_ROLE_INVALID",
    );
  });
});

describe("optional-field shapes — signed positive variants", () => {
  it("accepts the 13-field shape (message only) when signed over that exact shape", () => {
    const base = cloneTx(headParsed("predecessor.settled.json")); // carries neither optional
    const inner = { ...base.inner, message: "zp1:golden-note" } as typeof base.inner;
    const signed = settledSignedBy(inner, 0x05, 0x02);
    const verdict = verifySettledTransaction(signed, SENDER_KEY); // seed 02 = receiver here
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;
    expect(verdict.projection.B).toBe("10");
  });

  it("accepts the 13-field shape (expiry only) when signed over that exact shape", () => {
    const base = cloneTx(headParsed("predecessor.settled.json"));
    const inner = { ...base.inner, expiry__unix_time_secs: "1784336400" } as typeof base.inner;
    const signed = settledSignedBy(inner, 0x05, 0x02);
    expect(verifySettledTransaction(signed, SENDER_KEY).verdict).toBe("VERIFIED");
  });

  it("accepts a zero amount (canonical ZKZ amount contract) when signed over that exact shape", () => {
    const base = cloneTx(headParsed("predecessor.settled.json"));
    const inner = {
      ...base.inner,
      step_2_state: { amount: "0" },
    } as typeof base.inner;
    const signed = settledSignedBy(inner, 0x05, 0x02);
    const verdict = verifySettledTransaction(signed, SENDER_KEY);
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;
    expect(verdict.projection.B).toBe("0");
  });
});

describe("F1 — deeply nested metadata fails closed with a typed verdict, never a throw", () => {
  // V8's JSON.parse is iterative and accepts nesting far beyond what its recursive
  // JSON.stringify can serialize, so a hostile gateway — the exact adversary this
  // stage defends against — can return a HEAD-shaped envelope whose
  // step_1_state.metadata is nested past the serializer's reach: the envelope stage
  // parses it, shape narrowing passes (metadata is opaque), and the preimage
  // reconstruction is the first place the depth bites.
  //
  // The exact depth at which the recursive serializer throws RangeError is
  // implementation-defined: it tracks V8's stack budget, which moves with the Node
  // version, OS, CPU arch, and — for these tests specifically — the test worker's
  // stack size. A hardcoded "breaking" depth is therefore not portable. On a host
  // whose worker stack is large enough to serialize the chosen depth, the stringify
  // does NOT throw, the fixture falls through to signature verification (its
  // signature was computed over normal, non-deep metadata), and this stage returns
  // UNVERIFIED_SIGNATURE instead of MALFORMED_TRANSACTION — a non-defect reddening
  // (a fixed 10_000 was below the limit on larger-stack hosts). Both
  // outcomes still REJECT the transaction (it is never VERIFIED); only the typed
  // reason moves. To pin the reason deterministically on every host, measure this
  // engine's actual limit and straddle it rather than guessing a constant.
  function deepMetadataJson(depth: number): string {
    return `{"nested":`.repeat(depth) + "true" + "}".repeat(depth);
  }

  // Smallest nesting depth whose recursive JSON.stringify throws RangeError on THIS
  // engine, exercised exactly as the fixture is (iterative JSON.parse of the deep
  // text, then the recursive JSON.stringify the verifier performs). Doubles up from a
  // depth that is known to serialize until one throws, then binary-searches the
  // boundary — correct for any stack budget, including pathologically small ones.
  function measureStringifyDepthLimit(): number {
    const throwsAt = (depth: number): boolean => {
      const value = JSON.parse(deepMetadataJson(depth));
      try {
        JSON.stringify(value);
        return false;
      } catch (error) {
        if (error instanceof RangeError) return true;
        throw error;
      }
    };
    let lo = 1; // depth 1 always serializes
    let hi = 2;
    while (!throwsAt(hi)) {
      lo = hi;
      hi *= 2;
    }
    while (hi - lo > 1) {
      const mid = (lo + hi) >>> 1;
      if (throwsAt(mid)) hi = mid;
      else lo = mid;
    }
    return hi;
  }

  const STRINGIFY_DEPTH_LIMIT = measureStringifyDepthLimit();
  // Comfortably past the limit so the RangeError fires even a few frames deeper,
  // inside the verifier, on every host; and comfortably below it so a safe-depth
  // control never trips the RangeError. The verifier's own call chain only lowers the
  // effective limit by a handful of frames, so both margins are ample.
  const BREAKING_DEPTH = STRINGIFY_DEPTH_LIMIT + 2_000;
  const SAFE_DEPTH = Math.max(64, STRINGIFY_DEPTH_LIMIT >> 2);

  // The exact adversarial chain: gateway bytes -> envelope HEAD verdict -> verifier.
  // The deep metadata is spliced into the settled record TEXT (a JS-side
  // JSON.stringify of the deep object would itself throw here) and only ever
  // JSON.parse'd by the envelope stage, exactly as the live attack delivers it.
  function headParsedWithMetadataDepth(depth: number): ParsedSettledTransaction {
    const base = headParsed("target.settled.json");
    const placeholderInner = {
      ...base.inner,
      step_1_state: { amount: "7.75", metadata: "__ZP_TEST_DEEP_METADATA__" },
    };
    const recordText = JSON.stringify({
      inner: placeholderInner,
      step_1_signature: base.step_1_signature,
      step_2_signature: base.step_2_signature,
    }).replace('"__ZP_TEST_DEEP_METADATA__"', deepMetadataJson(depth));
    const bytes = new TextEncoder().encode(
      `{"status":true,"code":"success","message":"","data":[${recordText}]}`,
    );
    const verdict = parseGatewayEnvelope(bytes);
    if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope verdict");
    return verdict.parsed;
  }

  it("returns MALFORMED_TRANSACTION (preimage_encoding_failure) for metadata nested beyond the stringify depth limit", () => {
    const verdict = verifySettledTransaction(
      headParsedWithMetadataDepth(BREAKING_DEPTH),
      RECEIVER_KEY,
    );
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection.reason).toBe("preimage_encoding_failure");
  });

  it("control: the identical shape at a safe depth still returns its normal typed verdict", () => {
    // Unsigned over the mutated inner, so the normal verdict is the QA-demonstrated
    // step-1 signature failure — depth-triggered rejection must not fire here.
    const verdict = verifySettledTransaction(headParsedWithMetadataDepth(SAFE_DEPTH), RECEIVER_KEY);
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict.verdict !== "UNVERIFIED_SIGNATURE") return;
    expect(verdict.failedStep).toBe(1);
  });

  it("control: the same safe-depth shape, properly signed, still VERIFIES (success path unchanged)", () => {
    const parsed = headParsedWithMetadataDepth(SAFE_DEPTH);
    const signed = settledSignedBy(parsed.inner, 0x02, 0x03);
    expect(verifySettledTransaction(signed, RECEIVER_KEY).verdict).toBe("VERIFIED");
  });
});
