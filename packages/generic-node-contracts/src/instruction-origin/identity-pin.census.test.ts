// the presentation-scope concern.1 census: the node-published identity/rotation-evidence shape, the implementer pin
// representation, and the pure pin-verification predicate — including the mandatory negative
// that demonstrates the exact compromised-platform substitution attack
// this predicate exists to defeat: an attacker-controlled key that is itself ACTIVE and would
// otherwise pass ordinary acceptance is still rejected because it does not match the pin.
import { describe, expect, it } from "vitest";

import { assertClosedSet, expectRejects } from "../testkit/freeze.ts";
import type { NodeIdentityKeyRecord } from "../artifacts/signing-contract.ts";
import {
  DISCOVERY_PATH,
  PIN_REJECT_REASONS,
  identityKeyFingerprint,
  isRotationEvidenceChainCoherent,
  isRotationEvidenceChainMonotonic,
  verifyIdentityPin,
  type NodeIdentityPin,
  type PublishedIdentityKeyEntry,
} from "./identity-pin.contract.ts";

const NOW = 1_700_000_000_000;

const genuineKey: NodeIdentityKeyRecord = {
  keyId: "key-genuine-1",
  role: "node_identity",
  publicKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  status: "ACTIVE",
  validFromUnixMs: NOW - 1_000,
  validUntilUnixMs: null,
};

const genuinePin: NodeIdentityPin = {
  keyId: genuineKey.keyId,
  publicKeyB64: genuineKey.publicKeyB64,
  fingerprintSha256: identityKeyFingerprint(genuineKey.publicKeyB64),
  validFromUnixMs: NOW - 1_000,
  validUntilUnixMs: null,
};

describe("identity-pin census: DISCOVERY_PATH is the frozen discovery literal", () => {
  it("matches the route already frozen in operations/routes.contract.ts", () => {
    expect(DISCOVERY_PATH).toBe("/.well-known/zupay-node");
  });
});

describe("the presentation-scope concern.1 census: PIN_REJECT_REASONS is the exact closed set", () => {
  it("matches the frozen membership", () => {
    assertClosedSet(PIN_REJECT_REASONS, [
      "key_id_mismatch",
      "pubkey_mismatch",
      "fingerprint_mismatch",
      "pin_not_yet_valid",
      "pin_expired",
      "underlying_key_not_accepted",
    ]);
  });
});

describe("the presentation-scope concern.1 golden: identityKeyFingerprint reproduces the A.8 node-identity fingerprint", () => {
  // Golden-toolchain reproduction (v2 Appendix A toolchain protocol): a Python `cryptography`
  // Ed25519 key derived from seed = 32 x 0x00 reproduces the A.8 node-identity public key
  // `O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=` byte-exact — this validates the toolchain
  // before minting anything (never hand-fabricate). Only then is `identityKeyFingerprint` of
  // that exact 44-char padded base64 string computed and pinned below as the lowercase hex
  // SHA-256 literal. This independently reproduces the sha256 already frozen in
  // `artifacts/manifest.ts` for `golden/node-identity.pub.b64` — same bytes, same digest.
  const A8_NODE_IDENTITY_PUBKEY_B64 = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";

  it("matches the frozen fingerprint literal", () => {
    expect(identityKeyFingerprint(A8_NODE_IDENTITY_PUBKEY_B64)).toBe(
      "8eb7cca2ecabb7fb12e9d6f356ff4c204c64cb94f0db87b0ccad4649f69c7de0",
    );
  });
});

describe("the presentation-scope concern.1 census: rotation evidence chain sequencing", () => {
  const chain: PublishedIdentityKeyEntry[] = [
    {
      keyId: "k1",
      publicKeyB64: "a",
      status: "RETIRED",
      validFromUnixMs: 100,
      validUntilUnixMs: 200,
      supersedesKeyId: null,
    },
    {
      keyId: "k2",
      publicKeyB64: "b",
      status: "ACTIVE",
      validFromUnixMs: 200,
      validUntilUnixMs: null,
      supersedesKeyId: "k1",
    },
  ];

  it("an append-only, non-decreasing chain is monotonic", () => {
    expect(isRotationEvidenceChainMonotonic(chain)).toBe(true);
  });

  it("a swapped (out-of-sequence) chain is rejected", () => {
    expect(isRotationEvidenceChainMonotonic([chain[1], chain[0]])).toBe(false);
  });

  it("a chain with a correctly linked supersedesKeyId is coherent", () => {
    expect(isRotationEvidenceChainCoherent(chain)).toBe(true);
  });

  it("a bootstrap entry with a non-null supersedesKeyId is incoherent", () => {
    const badBootstrap: PublishedIdentityKeyEntry[] = [{ ...chain[0], supersedesKeyId: "nonexistent" }, chain[1]];
    expect(isRotationEvidenceChainCoherent(badBootstrap)).toBe(false);
  });

  it("a later entry whose supersedesKeyId does not match the preceding entry's keyId is incoherent", () => {
    const misLinked: PublishedIdentityKeyEntry[] = [chain[0], { ...chain[1], supersedesKeyId: "not-k1" }];
    expect(isRotationEvidenceChainCoherent(misLinked)).toBe(false);
  });

  it("a swapped (out-of-sequence) chain is also incoherent", () => {
    expect(isRotationEvidenceChainCoherent([chain[1], chain[0]])).toBe(false);
  });
});

describe("the presentation-scope concern.1 positive: a genuine, matching, currently-valid key verifies", () => {
  it("verifyIdentityPin accepts", () => {
    expect(verifyIdentityPin(genuinePin, genuineKey, NOW)).toEqual({ verified: true });
  });
});

describe("the presentation-scope concern.1 mandatory negative: the substitution attack — a valid-looking attacker key is rejected", () => {
  it("an attacker's own ACTIVE, currently-valid key with a DIFFERENT key id and pubkey fails on key_id_mismatch, not silently passing acceptance", () => {
    const attackerKey: NodeIdentityKeyRecord = {
      keyId: "key-attacker-1",
      role: "node_identity",
      publicKeyB64: "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=",
      status: "ACTIVE",
      validFromUnixMs: NOW - 1_000,
      validUntilUnixMs: null,
    };
    expect(verifyIdentityPin(genuinePin, attackerKey, NOW)).toEqual({
      verified: false,
      reason: "key_id_mismatch",
    });
  });

  it("expectRejects: a mutated key id is caught by the pin comparison", () => {
    expectRejects(
      () => ({ ...genuineKey, keyId: "different-key-id" }) satisfies NodeIdentityKeyRecord,
      (mutated) => expect(verifyIdentityPin(genuinePin, mutated, NOW)).toEqual({ verified: true }),
    );
  });
});

describe("the presentation-scope concern.1 negatives: every other reject reason is reachable", () => {
  it("pubkey_mismatch: same key id, different bytes", () => {
    const mutated: NodeIdentityKeyRecord = { ...genuineKey, publicKeyB64: "different-pubkey-bytes=" };
    expect(verifyIdentityPin(genuinePin, mutated, NOW)).toEqual({
      verified: false,
      reason: "pubkey_mismatch",
    });
  });

  it("fingerprint_mismatch: key id and pubkey both match, but the pin's fingerprint does not", () => {
    const mutatedPin: NodeIdentityPin = { ...genuinePin, fingerprintSha256: "0".repeat(64) };
    expect(verifyIdentityPin(mutatedPin, genuineKey, NOW)).toEqual({
      verified: false,
      reason: "fingerprint_mismatch",
    });
  });

  it("pin_not_yet_valid: now is before the pin's own validFrom", () => {
    const futurePin: NodeIdentityPin = { ...genuinePin, validFromUnixMs: NOW + 1_000 };
    expect(verifyIdentityPin(futurePin, genuineKey, NOW)).toEqual({
      verified: false,
      reason: "pin_not_yet_valid",
    });
  });

  it("pin_expired: now is after the pin's own validUntil", () => {
    const expiredPin: NodeIdentityPin = { ...genuinePin, validUntilUnixMs: NOW - 1 };
    expect(verifyIdentityPin(expiredPin, genuineKey, NOW)).toEqual({
      verified: false,
      reason: "pin_expired",
    });
  });

  it("underlying_key_not_accepted: the matching key is REVOKED", () => {
    const revoked: NodeIdentityKeyRecord = { ...genuineKey, status: "REVOKED" };
    expect(verifyIdentityPin(genuinePin, revoked, NOW)).toEqual({
      verified: false,
      reason: "underlying_key_not_accepted",
    });
  });
});
