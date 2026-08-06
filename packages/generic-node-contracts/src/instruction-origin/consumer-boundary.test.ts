/**
 * the presentation scope audit — the substitution-attack property, proven end to end against the on-main the presentation-scope concern.1
 * the presentation-scope concern.2 / the artifacts concern primitives and the byte-exact Appendix A goldens. No live HTTP app exists at
 * The foundation slice, so the boundary is driven through the contract functions themselves, which is the only
 * layer the freeze actually governs.
 *
 * The property under test (the implementer-controlled-origin model): a platform that can substitute content
 * cannot make a substituted instruction verify against an INDEPENDENTLY pinned node identity.
 * Asserting that is worthless unless the substituted artifact is otherwise beyond reproach, so
 * both attack vectors here are individually valid and are proven so before being rejected:
 *
 *   VECTOR A — attacker key. A different receive artifact, correctly signed by the attacker's own
 *   perfectly valid ACTIVE key. Proven to verify cleanly under its own key record, then rejected
 *   by the reference consumer on the pin.
 *
 *   VECTOR B — genuine node key. A different receive artifact, re-signed by the REAL node identity
 *   key, so digest, canonicality, key binding, pin and signature all pass. Caught only by the
 *   operation binding. Without step 5 of the reference consumer this attack succeeds, which is
 *   what makes that step load-bearing rather than decorative.
 *
 * Covers the API embed/discovery surfaces, integration handoff, and A.3.1/A.8; the
 * instruction-origin identity rule.
 */
import { describe, expect, it, beforeAll } from "vitest";

import {
  CONSUMER_REJECT_REASONS,
  verifyPresentationHandoff,
  type ConsumerVerdict,
} from "./consumer-boundary.ts";
import {
  DISCOVERY_PATH,
  identityKeyFingerprint,
  isRotationEvidenceChainCoherent,
  isRotationEvidenceChainMonotonic,
  verifyIdentityPin,
  type NodeIdentityPin,
  type PublishedIdentityKeyEntry,
} from "./identity-pin.contract.ts";
import {
  CAPABILITY_MANIFEST,
  capabilityDescriptor,
  isFrozenAvailable,
  isNonCapability,
} from "./capability-manifest.contract.ts";
import { isSubstitutionProof, type OriginClass } from "./origin-classes.contract.ts";
import {
  SUBSTITUTION_THREAT_TABLE,
  isThreatTableRowConsistent,
  isValidPresentationHandoffShape,
  type PresentationHandoff,
} from "./presentation-handoff.contract.ts";
import type { NodeIdentityKeyRecord } from "../artifacts/signing-contract.ts";
import { verifyExpectedArtifact, type ArtifactEnvelope } from "../artifacts/verify.ts";
import { readGoldenText } from "../testkit/byteGolden.ts";
import {
  digestPreimage,
  encodeBase64Url,
  keypairFromSeedByte,
  ready,
  signPreimage,
  type RawKeypair,
} from "../testkit/independentCrypto.ts";
import { defaultSuiteVerificationCrypto } from "../testkit/suiteVerificationCrypto.ts";

const PURPOSE = "zp-receive-expected-v1" as const;
const GENUINE_KEY_ID = "node-identity-golden";
const NOW = 1_784_336_000_000;

/** A.8 deterministic keys: 0x00 is the node identity; 0x02 and 0x03 are this suite's
 *  attacker and rotation keys (unused elsewhere, so no golden can drift under them). */
let nodeKp: RawKeypair;
let attackerKp: RawKeypair;
let rotatedKp: RawKeypair;

beforeAll(async () => {
  await ready();
  nodeKp = keypairFromSeedByte(0x00);
  attackerKp = keypairFromSeedByte(0x02);
  rotatedKp = keypairFromSeedByte(0x03);
});

const pubOf = (kp: RawKeypair): string => encodeBase64Url(kp.publicKey);

const keyRecord = (over: Partial<NodeIdentityKeyRecord> = {}): NodeIdentityKeyRecord => ({
  keyId: GENUINE_KEY_ID,
  role: "node_identity",
  publicKeyB64: pubOf(nodeKp),
  status: "ACTIVE",
  validFromUnixMs: 0,
  validUntilUnixMs: null,
  ...over,
});

const pinFor = (key: NodeIdentityKeyRecord): NodeIdentityPin => ({
  keyId: key.keyId,
  publicKeyB64: key.publicKeyB64,
  fingerprintSha256: identityKeyFingerprint(key.publicKeyB64),
  validFromUnixMs: 0,
  validUntilUnixMs: null,
});

/** The frozen receive golden, split into its purpose-prefix line and its canonical payload. */
const goldenPreimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
const goldenPayload = JSON.parse(goldenPreimage.slice(goldenPreimage.indexOf("\n") + 1)) as Record<string, unknown>;
const GOLDEN_OPERATION_ID = goldenPayload.operation_id as string;

/** Rebuild an envelope from a payload object, signed by `kp`. Key insertion sequence is preserved
 *  by the spread, so JSON.stringify stays byte-canonical and the frozen field sequence holds. */
const sign = (payload: Record<string, unknown>, kp: RawKeypair, keyId: string): ArtifactEnvelope => {
  const preimage_text = `${PURPOSE}\n${JSON.stringify(payload)}`;
  return {
    key_id: keyId,
    preimage_text,
    preimage_sha256: digestPreimage(preimage_text),
    signature: signPreimage(preimage_text, kp.privateKey),
  };
};

/** A DIFFERENT but individually valid receive instruction: another operation, another amount. */
const OTHER_OPERATION_ID = "44444444-4444-4444-8444-444444444444";
const otherPayload = (): Record<string, unknown> => ({
  ...goldenPayload,
  operation_id: OTHER_OPERATION_ID,
  discriminator: OTHER_OPERATION_ID,
  amount_zkz: "9.75",
});

const handoff = (over: Partial<PresentationHandoff> = {}): PresentationHandoff => ({
  operationId: GOLDEN_OPERATION_ID,
  artifactPurpose: PURPOSE,
  artifactEnvelope: sign(goldenPayload, nodeKp, GENUINE_KEY_ID),
  nodeIdentityPin: pinFor(keyRecord()),
  discoveryPath: DISCOVERY_PATH,
  originClass: "node-origin",
  ...over,
});

const run = (h: unknown, resolvedKey: NodeIdentityKeyRecord): Promise<ConsumerVerdict> =>
  verifyPresentationHandoff({ handoff: h, resolvedKey, nowUnixMs: NOW }, defaultSuiteVerificationCrypto);

describe("the presentation scope audit consumer-boundary reference verifier — the honest path", () => {
  it("accepts the genuine golden artifact on a node-controlled origin with the pinned key", async () => {
    const verdict = await run(handoff(), keyRecord());
    expect(verdict).toEqual({
      presentable: true,
      operationId: GOLDEN_OPERATION_ID,
      digest: digestPreimage(goldenPreimage),
    });
  });

  it("drives the frozen byte-exact golden, not a locally re-invented fixture", () => {
    // If the golden or the signing construction drifts, the happy path above stops being evidence.
    expect(handoff().artifactEnvelope.preimage_text).toBe(goldenPreimage);
    expect(handoff().artifactEnvelope.signature).toBe(readGoldenText(`artifacts/${PURPOSE}.sig.b64`));
    expect(handoff().nodeIdentityPin.publicKeyB64).toBe(readGoldenText("artifacts/node-identity.pub.b64").trim());
  });

  it("every refusal reason is drawn from the frozen closed set", async () => {
    const seen = new Set<string>();
    for (const [h, key] of [
      [handoff({ discoveryPath: "/.well-known/elsewhere" }), keyRecord()],
      [handoff(), keyRecord({ keyId: "other" })],
      [
        handoff({
          artifactEnvelope: { ...handoff().artifactEnvelope, signature: signPreimage(goldenPreimage, attackerKp.privateKey) },
        }),
        keyRecord(),
      ],
      [handoff({ operationId: OTHER_OPERATION_ID }), keyRecord()],
      [handoff({ originClass: "platform-hosted" }), keyRecord()],
      [{ notAHandoff: true }, keyRecord()],
    ] as const) {
      const verdict = await run(h, key);
      expect(verdict.presentable).toBe(false);
      if (!verdict.presentable) seen.add(verdict.reason);
    }
    // Non-vacuity: every frozen reason is actually reachable, so none is dead decoration.
    expect([...seen].sort()).toEqual([...CONSUMER_REJECT_REASONS].sort());
  });
});

describe("the presentation scope audit VECTOR A — platform substitutes an artifact signed by the attacker's own valid key", () => {
  const attackerKeyId = "attacker-active-key";

  it("the substituted artifact is INDIVIDUALLY VALID under the attacker's own key record", async () => {
    const attackerKey = keyRecord({ keyId: attackerKeyId, publicKeyB64: pubOf(attackerKp) });
    const verdict = await verifyExpectedArtifact(
      {
        envelope: sign(otherPayload(), attackerKp, attackerKeyId),
        key: attackerKey,
        signedAtUnixMs: NOW,
        expectedPurpose: PURPOSE,
        pinnedPublicKeyB64: attackerKey.publicKeyB64,
      },
      defaultSuiteVerificationCrypto,
    );
    // Beyond reproach in isolation: correct digest, canonical payload, valid signature, live key.
    expect(verdict).toEqual({ ok: true, purpose: PURPOSE, digest: expect.any(String) });
  });

  it("and is REJECTED against the independently pinned node identity — a different key id", async () => {
    const attackerKey = keyRecord({ keyId: attackerKeyId, publicKeyB64: pubOf(attackerKp) });
    const verdict = await run(
      handoff({ operationId: OTHER_OPERATION_ID, artifactEnvelope: sign(otherPayload(), attackerKp, attackerKeyId) }),
      attackerKey,
    );
    expect(verdict).toEqual({ presentable: false, reason: "pin_not_verified", detail: "key_id_mismatch" });
  });

  it("and is REJECTED when the attacker reuses the genuine key id under its own key material", async () => {
    const impostor = keyRecord({ publicKeyB64: pubOf(attackerKp) });
    const verdict = await run(
      handoff({ operationId: OTHER_OPERATION_ID, artifactEnvelope: sign(otherPayload(), attackerKp, GENUINE_KEY_ID) }),
      impostor,
    );
    expect(verdict).toEqual({ presentable: false, reason: "pin_not_verified", detail: "pubkey_mismatch" });
  });

  it("and is REJECTED when the pinned key is honestly resolved but the artifact was attacker-signed", async () => {
    // The pin holds; the substitution now fails on the signature instead. Same outcome, different
    // gate — the property does not depend on which single check happens to catch it.
    const verdict = await run(
      handoff({ operationId: OTHER_OPERATION_ID, artifactEnvelope: sign(otherPayload(), attackerKp, GENUINE_KEY_ID) }),
      keyRecord(),
    );
    expect(verdict).toEqual({ presentable: false, reason: "artifact_not_verified", detail: "signature_invalid" });
  });
});

describe("the presentation scope audit VECTOR B — platform substitutes a DIFFERENT instruction signed by the GENUINE node key", () => {
  it("every cryptographic check passes: the substituted artifact verifies under the pinned key", async () => {
    const verdict = await verifyExpectedArtifact(
      {
        envelope: sign(otherPayload(), nodeKp, GENUINE_KEY_ID),
        key: keyRecord(),
        signedAtUnixMs: NOW,
        expectedPurpose: PURPOSE,
        pinnedPublicKeyB64: pubOf(nodeKp),
      },
      defaultSuiteVerificationCrypto,
    );
    expect(verdict).toEqual({ ok: true, purpose: PURPOSE, digest: expect.any(String) });
  });

  it("and the pin verifies too — nothing below the operation binding can catch this", () => {
    expect(verifyIdentityPin(pinFor(keyRecord()), keyRecord(), NOW)).toEqual({ verified: true });
  });

  it("yet the reference consumer REJECTS it: the artifact is about a different operation", async () => {
    const verdict = await run(
      handoff({ artifactEnvelope: sign(otherPayload(), nodeKp, GENUINE_KEY_ID) }),
      keyRecord(),
    );
    expect(verdict).toEqual({ presentable: false, reason: "operation_id_unbound", detail: OTHER_OPERATION_ID });
  });

  it("the same substituted artifact IS presentable once the handoff genuinely names that operation", async () => {
    // Positive control: the binding rejects mismatch, not the substituted payload's existence —
    // so the previous rejection is the binding doing work, not an unrelated validation failure.
    const verdict = await run(
      handoff({ operationId: OTHER_OPERATION_ID, artifactEnvelope: sign(otherPayload(), nodeKp, GENUINE_KEY_ID) }),
      keyRecord(),
    );
    expect(verdict.presentable).toBe(true);
  });
});

describe("the presentation scope audit origin class — a platform-hosted render is never presentable as genuine", () => {
  it("rejects platform-hosted even with a verified pin and a flawless genuine artifact", async () => {
    const verdict = await run(handoff({ originClass: "platform-hosted" }), keyRecord());
    expect(verdict).toEqual({
      presentable: false,
      reason: "origin_not_substitution_proof",
      detail: "platform-hosted",
    });
  });

  it("accepts an implementer-controlled origin on the same evidence", async () => {
    const verdict = await run(handoff({ originClass: "implementer-controlled-origin" }), keyRecord());
    expect(verdict.presentable).toBe(true);
  });

  it("the frozen threat table agrees with the running consumer, row by row", async () => {
    for (const row of SUBSTITUTION_THREAT_TABLE) {
      // The table's own internal consistency (data vs decision function) is the presentation scope audit's freeze;
      // this binds BOTH to the executable boundary.
      expect(isThreatTableRowConsistent(row)).toBe(true);
      // An unverified pin is modelled the way a real attacker produces one: the key the consumer
      // independently resolves is not the pinned key.
      const resolved = row.independentPinVerified ? keyRecord() : keyRecord({ keyId: "attacker-active-key" });
      const verdict = await run(handoff({ originClass: row.originClass }), resolved);
      expect({ scenario: row.scenario, presentable: verdict.presentable }).toEqual({
        scenario: row.scenario,
        presentable: row.substitutionProof,
      });
    }
  });

  it("negative control: a fabricated row claiming platform-hosted is substitution-proof is inconsistent", () => {
    const fabricated = { ...SUBSTITUTION_THREAT_TABLE[0], substitutionProof: true };
    expect(isThreatTableRowConsistent(fabricated)).toBe(false);
    expect(isSubstitutionProof("platform-hosted" satisfies OriginClass, true)).toBe(false);
  });
});

describe("the presentation scope audit C-05 — no custody material can cross the boundary", () => {
  it("rejects a handoff carrying wallet key material, by closed shape rather than by name", async () => {
    const smuggled = { ...handoff(), walletPrivateKey: "should-never-exist" };
    expect(isValidPresentationHandoffShape(smuggled)).toBe(false);
    expect(await run(smuggled, keyRecord())).toEqual({ presentable: false, reason: "handoff_shape_invalid" });
  });

  it("fails CLOSED on a malformed signature encoding instead of throwing into presentation code", async () => {
    // the artifacts concern's injected crypto throws on non-base64 input; an untrusted boundary must not leak that.
    const verdict = await run(
      handoff({ artifactEnvelope: { ...handoff().artifactEnvelope, signature: `${"x".repeat(86)}==` } }),
      keyRecord(),
    );
    expect(verdict).toEqual({
      presentable: false,
      reason: "artifact_not_verified",
      detail: "malformed_signature_encoding",
    });
  });

  it("rejects a handoff that relocates the pin check away from the frozen discovery path", async () => {
    const verdict = await run(handoff({ discoveryPath: "/.well-known/attacker" }), keyRecord());
    expect(verdict).toEqual({
      presentable: false,
      reason: "discovery_path_mismatch",
      detail: "/.well-known/attacker",
    });
  });

  it("fails CLOSED on an undeclared originClass (valid golden crypto) — never throws into presentation code", async () => {
    // claimsForOriginClass throws on undeclared classes; the shape gate must refuse first so the
    // untrusted boundary never surfaces that throw.
    for (const originClass of ["attacker-origin", ""] as const) {
      const poisoned = handoff({ originClass: originClass as OriginClass });
      expect(isValidPresentationHandoffShape(poisoned)).toBe(false);
      await expect(run(poisoned, keyRecord())).resolves.toEqual({
        presentable: false,
        reason: "handoff_shape_invalid",
      });
    }
  });
});

describe("the presentation scope audit the presentation-scope concern.1 integration — pinned-key bootstrap and rotation", () => {
  const bootstrap = (): PublishedIdentityKeyEntry => ({
    keyId: GENUINE_KEY_ID,
    publicKeyB64: pubOf(nodeKp),
    status: "RETIRED",
    validFromUnixMs: 0,
    validUntilUnixMs: NOW - 1,
    supersedesKeyId: null,
  });
  const rotated = (): PublishedIdentityKeyEntry => ({
    keyId: "node-identity-rotated",
    publicKeyB64: pubOf(rotatedKp),
    status: "ACTIVE",
    validFromUnixMs: NOW - 1,
    validUntilUnixMs: null,
    supersedesKeyId: GENUINE_KEY_ID,
  });

  it("a bootstrap-then-rotation evidence chain is monotonic and coherent", () => {
    const chain = [bootstrap(), rotated()];
    expect(isRotationEvidenceChainMonotonic(chain)).toBe(true);
    expect(isRotationEvidenceChainCoherent(chain)).toBe(true);
  });

  it("negative control: a bootstrap entry claiming to supersede something is incoherent", () => {
    expect(isRotationEvidenceChainCoherent([{ ...bootstrap(), supersedesKeyId: "invented" }])).toBe(false);
  });

  it("after rotation the OLD pin no longer verifies, and a handoff under it is not presentable", async () => {
    const rotatedKey = keyRecord({ keyId: rotated().keyId, publicKeyB64: rotated().publicKeyB64 });
    expect(verifyIdentityPin(pinFor(keyRecord()), rotatedKey, NOW)).toEqual({
      verified: false,
      reason: "key_id_mismatch",
    });
    const verdict = await run(handoff(), rotatedKey);
    expect(verdict).toEqual({ presentable: false, reason: "pin_not_verified", detail: "key_id_mismatch" });
  });

  it("a handoff re-pinned and re-signed under the rotated key is presentable again", async () => {
    const rotatedKey = keyRecord({ keyId: rotated().keyId, publicKeyB64: rotated().publicKeyB64 });
    const verdict = await run(
      handoff({
        nodeIdentityPin: pinFor(rotatedKey),
        artifactEnvelope: sign(goldenPayload, rotatedKp, rotatedKey.keyId),
      }),
      rotatedKey,
    );
    expect(verdict.presentable).toBe(true);
  });

  it("a REVOKED key is refused even when the pin matches it exactly", async () => {
    const revoked = keyRecord({ status: "REVOKED" });
    const verdict = await run(handoff(), revoked);
    expect(verdict).toEqual({ presentable: false, reason: "pin_not_verified", detail: "underlying_key_not_accepted" });
  });
});

describe("the presentation scope audit the presentation-scope concern.2 integration — the verifier kit the consumer is built from", () => {
  it("uses exactly the two FROZEN_AVAILABLE capabilities and no deferred one", () => {
    expect(isFrozenAvailable("ARTIFACT_VERIFICATION")).toBe(true);
    expect(isFrozenAvailable("IDENTITY_PIN_CHECK")).toBe(true);
    const deferred = capabilityDescriptor("PROOF_MATERIAL_ACCESS");
    expect(deferred.status).toBe("DEFERRED");
    // Nothing to call: a deferred capability exports no interface to fabricate against.
    expect(deferred.exportedSymbols).toEqual([]);
  });

  it("the symbols the consumer actually invokes are the ones the kit declares", async () => {
    const declared = new Set(CAPABILITY_MANIFEST.filter((c) => isFrozenAvailable(c.id)).flatMap((c) => [...c.exportedSymbols]));
    expect(declared.has("verifyExpectedArtifact")).toBe(true);
    expect(declared.has("verifyIdentityPin")).toBe(true);
    // And both are genuinely on the executed path: removing either changes the verdict above.
    expect((await run(handoff(), keyRecord({ keyId: "other" }))).presentable).toBe(false);
  });

  it("presentation and origin policy remain NON-capabilities — the kit verifies, it does not render", () => {
    expect(isNonCapability("CUSTOMER_INSTRUCTION_UI")).toBe(true);
    expect(isNonCapability("ORIGIN_POLICY_DECISION")).toBe(true);
  });
});
