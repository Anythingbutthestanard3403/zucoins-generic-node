// computeInnerDigest byte-golden + non-ASCII message signing golden.
// Proves: (1) a canonically-ordered inner object produces a known SHA256 digest;
// (2) a differently-ordered object with identical values produces a DIFFERENT digest
// (key-order sensitivity — the byte-exact signing rule: byte-exact JSON.stringify signing);
// (3) non-ASCII/multi-byte messages are handled deterministically by JSON.stringify
// and computeInnerDigest (UTF-8, no escaping of BMP chars beyond JSON requirements).
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { computeInnerDigest } from "../src/protocol/inner.js";
import type { SplitChainInnerV2 } from "../src/protocol/inner.js";
import {
  A8_INNER_PREIMAGE_SHA256,
  NON_ASCII_INNER_PREIMAGE_BYTE_LENGTH,
  NON_ASCII_INNER_PREIMAGE_SHA256,
  NON_ASCII_INNER_PREIMAGE_TEXT,
  NON_ASCII_MESSAGE,
} from "./fixtures/splitchain-v2-byte-evidence.js";

function canonicalInner(message: string): SplitChainInnerV2 {
  const inner = Object.create(null) as Record<string, unknown>;
  inner.type = "unique_combinable";
  inner.version = "2";
  inner.unix_time_secs = "1784332800.125";
  inner.signer_steps = 2;
  inner.step_1_signer = "sender";
  inner.step_2_signer = "receiver";
  inner.step_1_key_public__base64urlsafe = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
  inner.step_2_key_public__base64urlsafe = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
  inner.step_1_state = { amount: "7.75" };
  inner.step_2_state = { amount: "2.25" };
  inner.previous_step_1_state_signature = "";
  inner.previous_step_2_state_signature = "";
  inner.expiry__unix_time_secs = "1784336400";
  inner.message = message;
  return inner as unknown as SplitChainInnerV2;
}

function reorderedInner(): SplitChainInnerV2 {
  const inner = Object.create(null) as Record<string, unknown>;
  inner.message = "zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3";
  inner.expiry__unix_time_secs = "1784336400";
  inner.previous_step_2_state_signature = "";
  inner.previous_step_1_state_signature = "";
  inner.step_2_state = { amount: "2.25" };
  inner.step_1_state = { amount: "7.75" };
  inner.step_2_key_public__base64urlsafe = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
  inner.step_1_key_public__base64urlsafe = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
  inner.step_2_signer = "receiver";
  inner.step_1_signer = "sender";
  inner.signer_steps = 2;
  inner.unix_time_secs = "1784332800.125";
  inner.version = "2";
  inner.type = "unique_combinable";
  return inner as unknown as SplitChainInnerV2;
}

describe("computeInnerDigest byte-golden", () => {
  it("canonical field order produces the known A8 SHA256 digest", () => {
    const inner = canonicalInner("zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3");
    const digest = computeInnerDigest(inner);
    expect(digest).toBe(A8_INNER_PREIMAGE_SHA256);
    expect(digest).toBe("f0e12e993cc4d6b452162cd49b2699b9f912d7a2bf3d8ddd418e3a29c6bbf0b7");
  });

  it("reordered keys with identical values produce a DIFFERENT digest (key-order sensitivity)", () => {
    const canonical = canonicalInner("zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3");
    const reordered = reorderedInner();

    const canonicalDigest = computeInnerDigest(canonical);
    const reorderedDigest = computeInnerDigest(reordered);

    expect(reorderedDigest).not.toBe(canonicalDigest);
    expect(reorderedDigest).toBe("47b1bf5f23a85290f04a1b93c1ac7c40b201f14026b11ad02d8732d49805eb2d");
  });

  it("digest is deterministic across repeated calls", () => {
    const inner = canonicalInner("zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3");
    expect(computeInnerDigest(inner)).toBe(computeInnerDigest(inner));
  });
});

describe("non-ASCII message signing golden", () => {
  it("JSON.stringify preserves non-ASCII characters raw (no unicode escaping of BMP/emoji)", () => {
    const inner = canonicalInner(NON_ASCII_MESSAGE);
    const preimage = JSON.stringify(inner);

    expect(preimage).toBe(NON_ASCII_INNER_PREIMAGE_TEXT);
    expect(preimage).toContain("\u2014");
    expect(preimage).toContain("\u00a5");
    expect(preimage).toContain("\ud83d\udcb0");
    expect(preimage).not.toContain("\\u2014");
    expect(preimage).not.toContain("\\u00a5");
  });

  it("UTF-8 byte length exceeds char length for multi-byte message", () => {
    const preimage = NON_ASCII_INNER_PREIMAGE_TEXT;
    const byteLength = Buffer.byteLength(preimage, "utf8");
    expect(byteLength).toBe(NON_ASCII_INNER_PREIMAGE_BYTE_LENGTH);
    expect(byteLength).toBeGreaterThan(preimage.length);
  });

  it("computeInnerDigest produces the known SHA256 for non-ASCII message inner", () => {
    const inner = canonicalInner(NON_ASCII_MESSAGE);
    const digest = computeInnerDigest(inner);
    expect(digest).toBe(NON_ASCII_INNER_PREIMAGE_SHA256);
    expect(digest).toBe("38e82d51e251ae2755fc933a9033fe794c5dc97d0cb33f77cde87dcb0f787dc5");
  });

  it("digest is deterministic for non-ASCII message across repeated calls", () => {
    const inner = canonicalInner(NON_ASCII_MESSAGE);
    expect(computeInnerDigest(inner)).toBe(computeInnerDigest(inner));
  });

  it("independent SHA256 of the preimage text matches computeInnerDigest", () => {
    const independentDigest = createHash("sha256")
      .update(NON_ASCII_INNER_PREIMAGE_TEXT, "utf8")
      .digest("hex");
    expect(independentDigest).toBe(NON_ASCII_INNER_PREIMAGE_SHA256);
  });
});
