// the compat-literals concern.3 compatibility gate: every inventoried literal round-trips exactly — byte-length, UTF-8
// encoding, and a pinned SHA-256 digest of the bare literal string (tamper-evidence for this
// concern's own data, since the compat-literals concern owns no signed/Ed25519 goldens of its own).
//
// Canonical: DEC the compatibility-literal preservation rule.
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { COMPATIBILITY_LITERAL_INVENTORY } from "./inventory.contract.ts";
import { isKnownCompatibilityLiteral, findCompatibilityLiteralCaseInsensitive } from "./verify.ts";

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

/**
 * Pinned SHA-256 of each bare literal's exact UTF-8 bytes. A one-character spelling or case
 * change anywhere in `compat-literals.contract.ts` changes its digest here and fails this test —
 * exactly the byte-golden pattern other concerns use for signed preimages, scoped to the literal
 * strings themselves since the compat-literals concern signs nothing.
 */
const PINNED_LITERAL_DIGESTS: Readonly<Record<string, string>> = {
  "zp-receive-expected-v1": "4539bae00976f961344f4d458aa17f94e6a1a99ad1d17c7efa4365015e41bd94",
  "zp-move-internal-expected-v1": "b58aa4c75a6735c657a39d156534280e4deef369db8ddd03e856691ac9754a22",
  "zp-send-external-expected-v1": "e22553c3c63c5f35763b32120cdada480d6d6f3219b8419b7a5915a5e19e1e8c",
  "zp-send-external-approval-v1": "09d3670c7e4f616fba1ad937a5bfa94e4f72066fd04648e23f5017faa60db008",
  "zp-destination-bless-v1": "86af16d00196f814bffded620461c878b626e6a1fb030d177f510fc35a11728e",
  "zp-device-enrol-v1": "4b2c1169b4981a41cf107f9344c5c1c23cab6a16f7e1191467fa7c8168185cc6",
  "zp-report-request-v1": "39743654caa28e0a15d0a3b4c93eea88675d8b7f6db47aa97078174f09d63e7f",
  "zp-node-event-v1": "8d9aa2dce9216ef65a31ea3e4335af90c4c9a7689ad5c9395bd5abe25442b6c0",
  "zp-wallet-head-fingerprint-v1": "fe52a848872d61fc1e74cc797481d4f69e9d0d880842f07f532dc8760fc90dbe",
  "zp-wallet-secret-v1": "f3a4b771aeb68200bfa7a5cafa3a53f4aadc0f35c2d9b8b84158364d0b82c493",
  "zp-reporting-register-v1": "a10df34cd8a482ab6024cbb8a1050ffa5f24eeeaa16a42b94558e1067439d960",
  "zp1:": "d2a6fc096934591071aed356cb85dead0fc042ddba7de0708b7b493606702175",
  "X-ZP-TOTP": "cdd1836149bd07c2ec744a4e25311a2b45499233b164a4e3ec2c95762221e568",
  "X-ZP-Reporting-Key-Id": "ae1c878e40b69f2d84ed78b8b29377196ae2d878b098f4dd5ea7d7dd55676596",
  "X-ZP-Reporting-Timestamp": "143b26d44bab4eb5196954575308600d5d0f75869e5cf34e9f42ff1ccc2c83ea",
  "X-ZP-Reporting-Expires-At": "eb2c436ccd3d35c829377aab8cb15a7911ad4b52e7acb47cc7f7f72aa37b3d7b",
  "X-ZP-Reporting-Nonce": "12cc63ad34e679fcb6826075d0b824c25af3a38880098a03d83db605fc8f86cf",
  "X-ZP-Reporting-Signature": "ff5d8fecbba6f8e81e3fdb5e4efccdc44925df061dd2c1076921e04a84d2a663",
  "X-ZuPay-Node": "4594dc2ac0d405cd391dc9864043a844df8a7f8ff53b95ed9c1b0e6c0744577c",
  "X-ZuPay-Timestamp": "d764eed1b212cd9694a3cd9c7602380ea0ffb3e77058c39f93d343897a3c85a2",
  "X-ZuPay-Signature": "0266a8991e3e7ee635b1fa40e06eb1caa271f04f010ebc877b818b5b4f4bfbad",
  zupay: "eb0d639c79b8613fef1a8dbb48a29e90720df9010ae2b114f4c3874427d4a0d5",
  zupayments: "b9a9b5680e78b1ca3db51b4cebc4d89c3a27f7dd6b071878a3e090f489c2829e",
  "zupay-reporting-v1": "3d0b61823391f4912f5da8bf6879aa572af1d67b79d33dc72c31bad4370ebf95",
  "zupay-reporting-transport-v1": "96c59299307a27dc84d369a267b3313a829b8a2a9056599210c0073ffc8e72e4",
  "zupay-reporting-handshake-v1": "de173ba12b51538c2a65f05b37ecd60eeb39bbac2ad2ac2ebdb7cba034f1bd3f",
  "/.well-known/zupay-node": "dda8ab425784285ac77ebe21b4dad7297423f84ac4023832e7a561937b22a49f",
  "/sdk/zupayments.js": "2b91ace921427c1577b9a41d9445ced142726ec380aa37788bdeefc979af2cf4",
  "@zupayments/": "a3e6fa1b66a8f1fb9e3d699c473cde64b1783815717ca444615e008788c6cee0",
};

describe("the compat-literals concern.3 compatibility gate: literal round-trip (byte/case-exact)", () => {
  it("has one pinned digest per inventoried literal (no drift between the two lists)", () => {
    expect(Object.keys(PINNED_LITERAL_DIGESTS).sort()).toEqual(
      COMPATIBILITY_LITERAL_INVENTORY.map((e) => e.literal).sort(),
    );
  });

  it("every literal's fresh SHA-256 matches its pinned digest (byte-exact round trip)", () => {
    for (const entry of COMPATIBILITY_LITERAL_INVENTORY) {
      expect(sha256(entry.literal)).toBe(PINNED_LITERAL_DIGESTS[entry.literal]);
    }
  });

  it("rejects a byte-mutated literal (negative path: trailing whitespace changes the digest)", () => {
    const mutated = `${COMPATIBILITY_LITERAL_INVENTORY[0]!.literal} `;
    expect(sha256(mutated)).not.toBe(PINNED_LITERAL_DIGESTS[COMPATIBILITY_LITERAL_INVENTORY[0]!.literal]);
  });

  it("rejects a case-mutated header even though it round-trips case-insensitively (negative path)", () => {
    const canonical = "X-ZP-TOTP";
    const mutated = "x-zp-totp";
    expect(sha256(mutated)).not.toBe(PINNED_LITERAL_DIGESTS[canonical]);
    expect(isKnownCompatibilityLiteral(mutated)).toBe(false);
    expect(findCompatibilityLiteralCaseInsensitive(mutated)?.literal).toBe(canonical);
  });
});
