import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

import { ready, keypairFromSeedByte, digestPreimage, signPreimage } from "../testkit/independentCrypto.ts";
import { defaultSuiteVerificationCrypto } from "../testkit/suiteVerificationCrypto.ts";
import { readGoldenText } from "../testkit/byteGolden.ts";
import { verifyExpectedArtifact, type ArtifactEnvelope, type VerifyRejectReason } from "./verify.ts";
import { type NodeIdentityKeyRecord } from "./signing-contract.ts";
import { EXPECTED_ARTIFACTS } from "./expected-artifacts.contract.ts";

/**
 * The amounts-grammar freeze (numeric positivity + canonical decimal grammar, hardened by
 * the dual-run addendum) as wired into the artifact verifier.
 *
 * The `zkz_amount_positive` field type used to be checked with a bounded-grammar regex PLUS a
 * bare string comparison `value !== "0"` (see git history of ./verify.ts). That
 * string check only ever excludes the literal three-character string `"0"` — every other
 * mathematical representation of zero ("0.0", "0.00", "0." + 32 zeros, ...) satisfied the old
 * grammar and slipped past the `!== "0"` guard, so a zero-amount artifact could pass field
 * validation. This suite proves the replacement (the shared the amounts concern `validateOperationAmount`
 * predicate, `../amounts/validators.ts`) rejects every one of those forms, plus the wider
 * canonical-grammar/precision/magnitude surface it now also enforces, while every previously
 * valid canonical amount continues to verify end-to-end unchanged.
 */

const NODE_PUB = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";

let nodePrivateKey: Uint8Array;

beforeAll(async () => {
  await ready();
  nodePrivateKey = keypairFromSeedByte(0x00).privateKey;
});

const nodeKey = (over: Partial<NodeIdentityKeyRecord> = {}): NodeIdentityKeyRecord => ({
  keyId: "node-identity-golden",
  role: "node_identity",
  publicKeyB64: NODE_PUB,
  status: "ACTIVE",
  validFromUnixMs: 0,
  validUntilUnixMs: null,
  ...over,
});

const load = (purpose: string): { prefix: string; payload: Record<string, unknown> } => {
  const pre = readGoldenText(`artifacts/${purpose}.preimage.txt`);
  const nl = pre.indexOf("\n");
  return { prefix: pre.slice(0, nl), payload: JSON.parse(pre.slice(nl + 1)) as Record<string, unknown> };
};

/** Builds an envelope with the golden (now-stale) signature — sufficient for field-level
 *  rejections, which are decided before the digest/signature checks run (see ./verify.ts). */
const envelopeWithStaleSig = (prefix: string, payload: Record<string, unknown>): ArtifactEnvelope => {
  const preimage_text = `${prefix}\n${JSON.stringify(payload)}`;
  const sig = readGoldenText(`artifacts/${prefix}.sig.b64`);
  return { key_id: "k", preimage_text, preimage_sha256: digestPreimage(preimage_text), signature: sig };
};

/** Builds a FRESHLY signed envelope so a positive-boundary vector can be proven to pass the
 *  verifier end-to-end, not merely the field-level type check. */
const envelopeFreshlySigned = (prefix: string, payload: Record<string, unknown>): ArtifactEnvelope => {
  const preimage_text = `${prefix}\n${JSON.stringify(payload)}`;
  return {
    key_id: "node-identity-golden",
    preimage_text,
    preimage_sha256: digestPreimage(preimage_text),
    signature: signPreimage(preimage_text, nodePrivateKey),
  };
};

const expectAmountRejected = async (amount: string) => {
  const { prefix, payload } = load("zp-receive-expected-v1");
  const result = await verifyExpectedArtifact({
    envelope: envelopeWithStaleSig(prefix, { ...payload, amount_zkz: amount }),
    key: nodeKey(),
    signedAtUnixMs: 1,
  }, defaultSuiteVerificationCrypto);
  expect(result.ok).toBe(false);
  if (!result.ok) {
    const reason: VerifyRejectReason = result.reason;
    expect(reason).toBe("field_value_invalid");
  }
};

const expectAmountAccepted = async (amount: string) => {
  const { prefix, payload } = load("zp-receive-expected-v1");
  const result = await verifyExpectedArtifact({
    envelope: envelopeFreshlySigned(prefix, { ...payload, amount_zkz: amount }),
    key: nodeKey(),
    signedAtUnixMs: 1,
    expectedPurpose: "zp-receive-expected-v1",
    pinnedPublicKeyB64: NODE_PUB,
  }, defaultSuiteVerificationCrypto);
  expect(result.ok).toBe(true);
};

describe("zkz_amount_positive: every mathematical zero rejected (, the amounts-grammar freeze)", () => {
  it('MONEY-PATH REGRESSION: "0.00" -- the exact input the OLD `value !== "0"` string predicate ' +
      "would have PASSED (matches the old grammar, is not the literal string \"0\") -- now fails", async () => {
    await expectAmountRejected("0.00");
  });

  it('canonical zero "0" is rejected (numeric, not string, positivity)', async () => {
    await expectAmountRejected("0");
  });

  it('"0.0" (mathematically zero, non-canonical) is rejected', async () => {
    await expectAmountRejected("0.0");
  });

  it('"0." + 32 fractional zeros (mathematically zero, max precision) is rejected', async () => {
    await expectAmountRejected(`0.${"0".repeat(32)}`);
  });

  it('"-0" (signed zero) is rejected', async () => {
    await expectAmountRejected("-0");
  });

  it('"-1" (negative) is rejected', async () => {
    await expectAmountRejected("-1");
  });

  it('"+1" (explicit sign) is rejected', async () => {
    await expectAmountRejected("+1");
  });

  it('"1e0" (exponent form) is rejected', async () => {
    await expectAmountRejected("1e0");
  });

  it('"1E1" (uppercase exponent form) is rejected', async () => {
    await expectAmountRejected("1E1");
  });

  it('"00" (leading zero) is rejected', async () => {
    await expectAmountRejected("00");
  });

  it('"01" (leading zero) is rejected', async () => {
    await expectAmountRejected("01");
  });

  it('"00.5" (leading zero with fraction) is rejected', async () => {
    await expectAmountRejected("00.5");
  });

  it("a positive value with 33 fractional digits (beyond the 32 dp precision cap) is rejected", async () => {
    await expectAmountRejected(`1.${"1".repeat(33)}`);
  });

  it("100000000 (== 1e8, at/beyond the exclusive upper bound) is rejected", async () => {
    await expectAmountRejected("100000000");
  });
});

describe("zkz_amount_positive: positive boundary values still verify end-to-end", () => {
  it("the smallest valid positive amount (32 fractional zeros then a trailing 1) still verifies", async () => {
    await expectAmountAccepted(`0.${"0".repeat(31)}1`);
  });

  it("the largest valid amount just under the 1e8 upper bound, at max 32 dp precision, still verifies", async () => {
    await expectAmountAccepted(`99999999.${"9".repeat(32)}`);
  });

  it("a typical multi-digit decimal amount still verifies", async () => {
    await expectAmountAccepted("1234.56");
  });

  it("the pinned golden amount 2.25 still verifies (byte/behavior preserved for real artifacts)", async () => {
    await expectAmountAccepted("2.25");
  });
});

describe("the amounts concern predicate coherence: no second amount parser (, structural)", () => {
  const verifySource = readFileSync(fileURLToPath(new URL("./verify.ts", import.meta.url)), "utf8");

  it("imports the amount predicate from the shared amounts concern", () => {
    expect(verifySource).toMatch(/from ["']\.\.\/amounts\/validators\.ts["']/);
    expect(verifySource).toContain("validateOperationAmount");
  });

  it("carries no local reimplementation of the old string-only zero check or the amount grammar", () => {
    // The exact defect this ticket removes: a bare string comparison standing in for numeric
    // positivity, which only ever excludes the literal string "0".
    expect(verifySource).not.toMatch(/!==\s*["']0["']/);
    // A private copy of the canonical decimal grammar (packages/generic-node-contracts/src/
    // amounts/grammar.ts's `[1-9][0-9]{0,7}` integer-part clause) would be a second parser.
    expect(verifySource).not.toMatch(/\[1-9\]\[0-9\]\{0,7\}/);
    expect(verifySource).not.toContain("ZKZ_POSITIVE_RE");
  });

  it("every AMOUNT-role field on all three expected artifacts is typed zkz_amount_positive (so all route through the shared predicate)", () => {
    for (const manifest of EXPECTED_ARTIFACTS) {
      const amountFields = manifest.fields.filter((f) => f.role === "AMOUNT");
      expect(amountFields.length).toBeGreaterThan(0);
      for (const field of amountFields) {
        expect(field.type).toBe("zkz_amount_positive");
      }
    }
  });
});
