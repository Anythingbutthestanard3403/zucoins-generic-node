// Golden reproduction proof. The serializer must reproduce every canonical fields suite
// golden byte-exact BEFORE any new vector is trusted (project golden discipline). Three independent
// checks per vector: (1) the produced preimageText equals the verbatim A.8.2 line; (2) its SHA-256
// equals the A.8 pinned digest (independent of this code); (3) for signed tuples, the deterministic
// Ed25519 signature over the produced bytes — from the A.8 seed key — equals the A.8 pinned
// signature AND verifies. Check (3) is the strongest: an Ed25519 signature reproduces only over
// byte-identical input, so a match proves the produced bytes ARE the spec author's signed bytes.
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import { serializeSuiteTuple } from "../src/protocol/suite/index.js";
import { SUITE_GOLDENS } from "./__vectors__/suite-appendix-a.js";

// A.8 keys are derived from 32-byte Ed25519 seeds filled with the indicated byte (identical
// technique to the freeze test).
function privFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}
const b64url = (buf: Buffer): string =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
const pubOf = (priv: ReturnType<typeof privFromSeed>): string =>
  b64url(createPublicKey(priv).export({ type: "spki", format: "der" }).subarray(-32));

// The A.8 role public keys, keyed by seed byte — the serializer's produced preimage must be the one
// these keys signed.
const ROLE_PUBKEY: Record<number, string> = {
  0x00: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
  0x01: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
  0x04: "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=",
};

describe("suite serializer reproduces the canonical fields goldens", () => {
  it("covers every registered suite purpose (12 goldens across 10 purposes)", () => {
    expect(SUITE_GOLDENS.map((g) => g.id)).toEqual([
      "receive-expected",
      "move-internal-expected",
      "send-external-expected",
      "send-external-approval",
      "destination-bless",
      "device-enrol",
      "report-request",
      "reporting-register",
      "node-event-a",
      "node-event-b",
      "wallet-head-fingerprint",
      "wallet-head-fingerprint-genesis",
    ]);
  });

  // Both `state_kind` variants of the one unsigned purpose are published, and the GENESIS
  // line differs from HEAD only in the fields A.7 says vary — a guard against a future edit
  // "fixing" genesis by reusing HEAD material or by dropping the null triple.
  it("publishes both A.7 state_kind variants of the fingerprint, distinct and null-triple-bearing", () => {
    const byId = new Map(SUITE_GOLDENS.map((g) => [g.id, g]));
    const head = byId.get("wallet-head-fingerprint");
    const genesis = byId.get("wallet-head-fingerprint-genesis");
    expect(head?.values.state_kind).toBe("HEAD");
    expect(genesis?.values.state_kind).toBe("GENESIS");
    expect(genesis?.sha256).not.toBe(head?.sha256);
    // Same wallet, one state earlier — the pair is a genuine before/after of one key.
    expect(genesis?.values.wallet_public_key).toBe(head?.values.wallet_public_key);
    // The null triple is JSON null in the emitted bytes, not omitted and not "" (A.9 vector 1).
    for (const field of ["inner_sha256", "step_1_signature", "step_2_signature"] as const) {
      expect(genesis?.values[field]).toBeNull();
      expect(genesis?.preimageText).toContain(`"${field}":null`);
    }
    expect(genesis?.preimageText).toContain('"s_signature":"","p_signature":"","b_amount":"0"');
  });

  for (const golden of SUITE_GOLDENS) {
    describe(golden.id, () => {
      const produced = serializeSuiteTuple(golden.purpose, golden.values);

      it("produces the exact A.8.2 preimage text (bytes compared)", () => {
        expect(produced.preimageText).toBe(golden.preimageText);
        expect(Buffer.from(produced.preimageBytes).equals(Buffer.from(golden.preimageText, "utf8"))).toBe(true);
        // The single LF domain separator is present exactly once, before the payload JSON.
        expect(produced.preimageText.indexOf("\n")).toBe(golden.purpose.length);
        expect(produced.preimageText.endsWith("\n")).toBe(false);
      });

      it("produces the A.8 pinned SHA-256 (hex compared, independent of this code)", () => {
        expect(produced.sha256).toBe(golden.sha256);
      });

      if (golden.seedByte !== null && golden.signature !== null) {
        it("reproduces and verifies the A.8 Ed25519 signature over the produced bytes", () => {
          const priv = privFromSeed(golden.seedByte as number);
          expect(pubOf(priv)).toBe(ROLE_PUBKEY[golden.seedByte as number]);
          const bytes = Buffer.from(produced.preimageBytes);
          const produced_sig = b64url(sign(null, bytes, priv));
          expect(produced_sig).toBe(golden.signature);
          expect(verify(null, bytes, createPublicKey(priv), Buffer.from(golden.signature as string, "base64url"))).toBe(true);
        });
      }
    });
  }
});
