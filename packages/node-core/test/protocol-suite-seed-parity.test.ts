// Cross-implementation parity items not already covered by
// protocol-suite-builders.test.ts (cross-purpose determinism, golden reproduction through the
// builders) or protocol-suite-verify.test.ts (per-golden signature re-derivation for the three
// signing seeds 0x00/0x01/0x04):
//
// (1) seed -> public key re-derivation for ALL FIVE canonical fields seed bytes, including 0x02
//     (sender wallet) and 0x03 (receiver wallet) — the two that never sign a suite tuple, so
// own golden test (which only re-derives the three signing seeds it actually needs
//     a signature from) and this suite's own verify test do not exercise them. They still appear as
//     data fields (e.g. `receiver_pubkey`, `source_pubkey`) in the A.8 goldens, so completing the
//     seed roster proves the whole A.8 key table — not just the signing subset — traces back to its
//     documented seeds, independent of node-core's own code.
// (2) NFC/NFD preservation through the BUILDER layer (own negatives test already proves
//     this at the `serializeSuiteTuple` layer directly; this asserts the property survives this
//     typed `buildDeviceEnrol` wrapper too).
// (3) A.9 #6 (amount edge cases: leading zero, exponent, sign, trailing zero, >32 decimals) is NOT
//     duplicated here — node-authored amounts go through `encodePositiveZkzAmount` →
//     parsePositiveZkzAmount (protocol-amounts.test.ts). A.7 `encodeZkzBalance` is foreign-
//     preserving (parseObservedZkzBalance) and only rejects structural grammar violations.
import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { describe, expect, it } from "vitest";

import { buildDeviceEnrol } from "../src/protocol/suite/builders.js";
import { SUITE_GOLDENS, type SuiteGoldenVector } from "./__vectors__/suite-appendix-a.js";

function privFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}
const b64url = (buf: Buffer): string => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
const pubFromSeed = (byte: number): string =>
  b64url(createPublicKey(privFromSeed(byte)).export({ type: "spki", format: "der" }).subarray(-32));

// canonical fields role table (lines 402-408): all five seed bytes, not only the three that sign.
const A8_SEED_ROLES: ReadonlyArray<{ readonly seedByte: number; readonly role: string; readonly publicKey: string }> = [
  { seedByte: 0x00, role: "node identity/event", publicKey: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=" },
  { seedByte: 0x01, role: "device", publicKey: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=" },
  { seedByte: 0x02, role: "sender wallet", publicKey: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=" },
  { seedByte: 0x03, role: "receiver wallet", publicKey: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=" },
  { seedByte: 0x04, role: "reporting", publicKey: "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=" },
];

describe("seed -> public key re-derivation for all five A.8 seeds", () => {
  for (const { seedByte, role, publicKey } of A8_SEED_ROLES) {
    it(`seed 0x${seedByte.toString(16).padStart(2, "0")} (${role}) derives the pinned A.8 public key`, () => {
      expect(pubFromSeed(seedByte)).toBe(publicKey);
    });
  }

  it("every A.8 public key referenced anywhere in the goldens corpus is one of the five derived keys", () => {
    const derived = new Set(A8_SEED_ROLES.map((entry) => entry.publicKey));
    const referenced = new Set<string>();
    for (const vector of SUITE_GOLDENS) {
      for (const value of Object.values(vector.values)) {
        if (typeof value === "string" && /^[A-Za-z0-9_-]{43}=$/.test(value)) referenced.add(value);
      }
    }
    expect(referenced.size).toBeGreaterThan(0);
    for (const key of referenced) expect(derived.has(key)).toBe(true);
  });
});

describe("NFC/NFD preservation through the builder layer", () => {
  it("buildDeviceEnrol never NFC-normalizes an NFD label", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "device-enrol") as SuiteGoldenVector;
    const { purpose: _purpose, canonical_version: _version, ...input } = golden.values as Record<string, unknown>;
    const decomposedNfd = `e${String.fromCharCode(0x0301)}`;
    const precomposedNfc = String.fromCharCode(0x00e9);
    const produced = buildDeviceEnrol({ ...input, label: decomposedNfd } as Parameters<typeof buildDeviceEnrol>[0]);
    expect(produced.preimageText.includes(decomposedNfd)).toBe(true);
    expect(produced.preimageText.includes(precomposedNfc)).toBe(false);
  });
});
