// the reporting-auth register tuple freeze + census gate for the reporting identity / handshake contract.
//
// Governing contract: the canonical suite serializer, golden fixture, and negative vectors;
// signing-custody; signed reporting; the pull-cursor authority decision. Proves: (a) the serialized manifest matches the
// golden; (b) the `zp-reporting-register-v1` preimage is byte-exact and digest-pinned; (c) the
// proof-of-possession signature is reproducible from the A.8 seed-0x04 reporting key and verifies
// (the handshake, end to end); (d) census — Ed25519 only, no HMAC/bearer, disjoint from the legacy
// push purposes, key purposes separated; and (e) a negative per A.9 fact class.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import golden from "./gen/reporting-auth.json" with { type: "json" };
import {
  REGISTER_FIELD_ORDER,
  REGISTER_GOLDEN_PAYLOAD,
  REGISTER_GOLDEN_PREIMAGE,
  REPORTING_REGISTER_PURPOSE,
  buildRegisterPreimage,
} from "./register-tuple.js";
import {
  ALLOWED_CREDENTIAL_MECHANISMS,
  FORBIDDEN_CREDENTIAL_MECHANISMS,
  LEGACY_PUSH_PURPOSES,
  REPORTING_CROSS_PURPOSE_FORBIDDEN,
  REPORTING_KEY_ALLOWED_PURPOSES,
  V2_REPORTING_PURPOSES,
  ED25519_SMALL_ORDER_ENCODINGS_HEX,
} from "./keys.js";
import {
  REGISTER_GOLDEN_POP_SIGNATURE,
  REGISTER_GOLDEN_PREIMAGE_SHA256,
  REGISTER_GOLDEN_REPORTING_PUBKEY,
} from "./digests.js";
import {
  credentialMechanismAllowed,
  isLegalReportingKeyTransition,
  reportingKeyMaySign,
  requestTupleMatchesBinding,
  decodeCanonicalEd25519Signature,
  decodeCanonicalReportingPublicKey,
  REGISTER_PROOF_VERIFICATION_STAGES,
  verifyRegisterProofOfPossession,
  verifyRegisterPreimage,
} from "./verifier.js";
import { buildReportingAuthManifest } from "./manifest.js";

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");
const paddedB64Url = (buf: Buffer): string =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
const readArtifact = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`./gen/${name}`, import.meta.url)), "utf8");
const CANONICAL_ED25519_TORSION_ENCODINGS_HEX = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
] as const;

// Ed25519 private key from a 32-byte seed filled with one byte (the A.8 fixture derivation).
function keyFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

const replaceRegisterKey = (key: string): string =>
  buildRegisterPreimage({ ...REGISTER_GOLDEN_PAYLOAD, new_reporting_public_key: key });
const allUnusedPadBitAliases = (encoded: string): readonly string[] => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const index = encoded.indexOf("=") - 1;
  const value = alphabet.indexOf(encoded[index]!);
  const unusedBitCount = encoded.endsWith("==") ? 4 : 2;
  const base = value & ~((1 << unusedBitCount) - 1);
  return Array.from({ length: (1 << unusedBitCount) - 1 }, (_, alias) =>
    `${encoded.slice(0, index)}${alphabet[base | alias + 1]}${encoded.slice(index + 1)}`,
  );
};

function nodeVerifyDetached({
  publicKey,
  preimage,
  signature,
}: {
  readonly publicKey: Uint8Array;
  readonly preimage: Uint8Array;
  readonly signature: Uint8Array;
}): boolean {
  const spki = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(publicKey),
  ]);
  return verify(
    null,
    Buffer.from(preimage),
    createPublicKey({ key: spki, format: "der", type: "spki" }),
    Buffer.from(signature),
  );
}

describe("the reporting-auth register tuple reporting-auth manifest freeze", () => {
  it("serialized manifest matches the committed golden snapshot", () => {
    expect(buildReportingAuthManifest()).toEqual(golden);
  });
});

describe("the reporting-auth register tuple zp-reporting-register-v1 byte-exact golden", () => {
  it("the golden preimage equals its raw artifact and matches its pinned digest", () => {
    const raw = readArtifact("zp-reporting-register-v1.preimage.txt");
    expect(REGISTER_GOLDEN_PREIMAGE).toBe(raw);
    expect(Buffer.byteLength(REGISTER_GOLDEN_PREIMAGE, "utf8")).toBe(477);
    expect(sha256(REGISTER_GOLDEN_PREIMAGE)).toBe(REGISTER_GOLDEN_PREIMAGE_SHA256);
    expect(sha256(raw)).toBe(REGISTER_GOLDEN_PREIMAGE_SHA256);
  });

  it("uses the A.1.1 serializer with purpose as prefix and payload field 1", () => {
    const lf = REGISTER_GOLDEN_PREIMAGE.indexOf("\n");
    expect(REGISTER_GOLDEN_PREIMAGE.slice(0, lf)).toBe(REPORTING_REGISTER_PURPOSE);
    expect(REGISTER_GOLDEN_PREIMAGE.slice(lf + 1).startsWith(`{"purpose":"${REPORTING_REGISTER_PURPOSE}"`)).toBe(
      true,
    );
    expect([...REGISTER_FIELD_ORDER][0]).toBe("purpose");
    expect([...REGISTER_FIELD_ORDER][1]).toBe("canonical_version");
  });

  it("passes the structural verifier", () => {
    expect(verifyRegisterPreimage(REGISTER_GOLDEN_PREIMAGE)).toEqual({ ok: true, reason: null });
  });
});

describe("the reporting-auth register tuple proof of possession (A.8 seed-0x04 reporting key)", () => {
  it("reproduces the fixture pubkey, the pinned signature, and verifies", () => {
    const priv = keyFromSeed(0x04);
    const pub = createPublicKey(priv);
    const rawPub = pub.export({ type: "spki", format: "der" }).subarray(-32);
    // The derived pubkey must equal the A.8 reporting key — cross-validates our crypto against the
    // frozen suite before we trust the signature golden.
    expect(paddedB64Url(rawPub)).toBe(REGISTER_GOLDEN_REPORTING_PUBKEY);
    expect(REGISTER_GOLDEN_PAYLOAD.new_reporting_public_key).toBe(REGISTER_GOLDEN_REPORTING_PUBKEY);

    const bytes = Buffer.from(REGISTER_GOLDEN_PREIMAGE, "utf8");
    const sig = sign(null, bytes, priv);
    expect(paddedB64Url(sig)).toBe(REGISTER_GOLDEN_POP_SIGNATURE);
    expect(verify(null, bytes, pub, sig)).toBe(true);
  });

  it("accepts the existing valid golden through point validation before PoP", () => {
    const trace: string[] = [];
    expect(
      verifyRegisterProofOfPossession(REGISTER_GOLDEN_PREIMAGE, REGISTER_GOLDEN_POP_SIGNATURE, {
        validatePublicKeyPoint: () => {
          trace.push("point");
          return true;
        },
        verifyDetached: (input) => {
          trace.push("pop");
          return nodeVerifyDetached(input);
        },
      }),
    ).toEqual({ ok: true, reason: null });
    expect(trace).toEqual(["point", "pop"]);
  });
});

describe("reporting-key canonical decoding and sequenced PoP", () => {
  const callbacksWithTrace = (trace: string[]) => ({
    validatePublicKeyPoint: () => (trace.push("point"), true),
    verifyDetached: () => (trace.push("pop"), true),
  });

  it("exports a runtime-frozen exact seven-stage verifier sequence", () => {
    expect(Object.isFrozen(REGISTER_PROOF_VERIFICATION_STAGES)).toBe(true);
    expect(REGISTER_PROOF_VERIFICATION_STAGES).toEqual([
      "structural_register_preimage",
      "public_key_padded_base64url_decode_32_byte_length_exact_reencode",
      "public_key_canonical_compressed_encoding_y_less_than_p_and_negative_zero_reject",
      "public_key_exact_eight_torsion_reject",
      "signature_padded_base64url_decode_64_byte_length_exact_reencode",
      "injected_full_public_key_point_validation",
      "proof_of_possession_detached_verification",
    ]);
  });

  it("freezes the exact sequenced libsodium torsion blacklist", () => {
    expect(Object.isFrozen(ED25519_SMALL_ORDER_ENCODINGS_HEX)).toBe(true);
    expect(ED25519_SMALL_ORDER_ENCODINGS_HEX).toEqual(CANONICAL_ED25519_TORSION_ENCODINGS_HEX);
  });

  it.each(CANONICAL_ED25519_TORSION_ENCODINGS_HEX)("rejects torsion encoding %s before callbacks", (hex) => {
    const key = paddedB64Url(Buffer.from(hex, "hex"));
    expect(decodeCanonicalReportingPublicKey(key)).toBeNull();
    const trace: string[] = [];
    expect(
      verifyRegisterProofOfPossession(replaceRegisterKey(key), REGISTER_GOLDEN_POP_SIGNATURE, {
        ...callbacksWithTrace(trace),
      }).ok,
    ).toBe(false);
    expect(trace).toEqual([]);
  });

  it("rejects every unused-pad-bit alias for both key and signature before callbacks", () => {
    const keyAliases = allUnusedPadBitAliases(REGISTER_GOLDEN_REPORTING_PUBKEY);
    const signatureAliases = allUnusedPadBitAliases(REGISTER_GOLDEN_POP_SIGNATURE);
    expect(keyAliases).toHaveLength(3);
    expect(signatureAliases).toHaveLength(15);

    for (const key of keyAliases) {
      const trace: string[] = [];
      expect(decodeCanonicalReportingPublicKey(key)).toBeNull();
      expect(
        verifyRegisterProofOfPossession(
          replaceRegisterKey(key),
          REGISTER_GOLDEN_POP_SIGNATURE,
          callbacksWithTrace(trace),
        ).ok,
      ).toBe(false);
      expect(trace).toEqual([]);
    }
    for (const signature of signatureAliases) {
      const trace: string[] = [];
      expect(decodeCanonicalEd25519Signature(signature)).toBeNull();
      expect(
        verifyRegisterProofOfPossession(
          REGISTER_GOLDEN_PREIMAGE,
          signature,
          callbacksWithTrace(trace),
        ).ok,
      ).toBe(false);
      expect(trace).toEqual([]);
    }
  });

  it.each([
    ["y=p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
    ["y=p+1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
    ["identity-sign-bit alias", "0100000000000000000000000000000000000000000000000000000000000080"],
    ["y=p-1 sign-bit alias", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
  ])("rejects noncanonical compressed encoding %s before callbacks", (_name, hex) => {
    const key = paddedB64Url(Buffer.from(hex, "hex"));
    const trace: string[] = [];
    expect(decodeCanonicalReportingPublicKey(key)).toBeNull();
    expect(
      verifyRegisterProofOfPossession(
        replaceRegisterKey(key),
        REGISTER_GOLDEN_POP_SIGNATURE,
        callbacksWithTrace(trace),
      ).ok,
    ).toBe(false);
    expect(trace).toEqual([]);
  });

  it.each([31, 33])("rejects a %i-byte public key before callbacks", (length) => {
    const key = paddedB64Url(Buffer.alloc(length, 2));
    const trace: string[] = [];
    expect(decodeCanonicalReportingPublicKey(key)).toBeNull();
    expect(
      verifyRegisterProofOfPossession(
        replaceRegisterKey(key),
        REGISTER_GOLDEN_POP_SIGNATURE,
        callbacksWithTrace(trace),
      ).ok,
    ).toBe(false);
    expect(trace).toEqual([]);
  });

  it.each([63, 65])("rejects a %i-byte signature before callbacks", (length) => {
    const signature = paddedB64Url(Buffer.alloc(length, 2));
    const trace: string[] = [];
    expect(decodeCanonicalEd25519Signature(signature)).toBeNull();
    expect(
      verifyRegisterProofOfPossession(
        REGISTER_GOLDEN_PREIMAGE,
        signature,
        callbacksWithTrace(trace),
      ).ok,
    ).toBe(false);
    expect(trace).toEqual([]);
  });

  it.each([
    ["false", false],
    ["truthy string", "true"],
    ["truthy object", {}],
    ["boxed boolean", new Boolean(true)],
    ["Promise", Promise.resolve(true)],
  ])("fails closed when point validation returns %s and never calls PoP", (_name, returned) => {
    const trace: string[] = [];
    expect(
      verifyRegisterProofOfPossession(REGISTER_GOLDEN_PREIMAGE, REGISTER_GOLDEN_POP_SIGNATURE, {
        validatePublicKeyPoint: () => (trace.push("point"), returned),
        verifyDetached: () => (trace.push("pop"), true),
      }).ok,
    ).toBe(false);
    expect(trace).toEqual(["point"]);
  });

  it("fails closed when point validation throws and never calls PoP", () => {
    const trace: string[] = [];
    expect(
      verifyRegisterProofOfPossession(REGISTER_GOLDEN_PREIMAGE, REGISTER_GOLDEN_POP_SIGNATURE, {
        validatePublicKeyPoint: () => {
          trace.push("point");
          throw new Error("point");
        },
        verifyDetached: () => (trace.push("pop"), true),
      }).ok,
    ).toBe(false);
    expect(trace).toEqual(["point"]);
  });

  it.each([
    ["false", false],
    ["truthy string", "true"],
    ["truthy object", {}],
    ["boxed boolean", new Boolean(true)],
    ["Promise", Promise.resolve(true)],
  ])("fails closed when detached verification returns %s", (_name, returned) => {
    const trace: string[] = [];
    expect(
      verifyRegisterProofOfPossession(REGISTER_GOLDEN_PREIMAGE, REGISTER_GOLDEN_POP_SIGNATURE, {
        validatePublicKeyPoint: () => (trace.push("point"), true),
        verifyDetached: () => (trace.push("pop"), returned),
      }).ok,
    ).toBe(false);
    expect(trace).toEqual(["point", "pop"]);
  });

  it("fails closed when detached verification throws after point success", () => {
    const trace: string[] = [];
    expect(
      verifyRegisterProofOfPossession(REGISTER_GOLDEN_PREIMAGE, REGISTER_GOLDEN_POP_SIGNATURE, {
        validatePublicKeyPoint: () => (trace.push("point"), true),
        verifyDetached: () => {
          trace.push("pop");
          throw new Error("pop");
        },
      }).ok,
    ).toBe(false);
    expect(trace).toEqual(["point", "pop"]);
  });

  it("lets canonical off-curve bytes reach the point validator, which rejects before PoP", () => {
    const offCurveKey = paddedB64Url(Buffer.from(`02${"00".repeat(31)}`, "hex"));
    const preimage = replaceRegisterKey(offCurveKey);
    const trace: string[] = [];
    expect(decodeCanonicalReportingPublicKey(offCurveKey)).not.toBeNull();
    expect(verifyRegisterPreimage(preimage).ok).toBe(true);
    expect(
      verifyRegisterProofOfPossession(preimage, REGISTER_GOLDEN_POP_SIGNATURE, {
        validatePublicKeyPoint: () => (trace.push("point"), false),
        verifyDetached: () => (trace.push("pop"), true),
      }).ok,
    ).toBe(false);
    expect(trace).toEqual(["point"]);
  });

  it("rejects the identity-key R=identity S=0 forgery before permissive callbacks", () => {
    const identity = Buffer.from(CANONICAL_ED25519_TORSION_ENCODINGS_HEX[0], "hex");
    const forgedSignature = paddedB64Url(Buffer.concat([identity, Buffer.alloc(32)]));
    const trace: string[] = [];
    expect(
      verifyRegisterProofOfPossession(
        replaceRegisterKey(paddedB64Url(identity)),
        forgedSignature,
        callbacksWithTrace(trace),
      ).ok,
    ).toBe(false);
    expect(trace).toEqual([]);
  });

  it("uses a named detached input with fresh copies and original exact UTF-8 preimage bytes", () => {
    const expectedPreimage = Buffer.from(REGISTER_GOLDEN_PREIMAGE, "utf8");
    const expectedSignature = Buffer.from(REGISTER_GOLDEN_POP_SIGNATURE, "base64url");
    let pointBytes: Uint8Array | undefined;
    const result = verifyRegisterProofOfPossession(
      REGISTER_GOLDEN_PREIMAGE,
      REGISTER_GOLDEN_POP_SIGNATURE,
      {
        validatePublicKeyPoint: (key) => {
          pointBytes = key;
          key.fill(0);
          return true;
        },
        verifyDetached: (input) => {
          expect(Object.keys(input)).toEqual(["publicKey", "preimage", "signature"]);
          expect(input.publicKey).not.toBe(pointBytes);
          expect(paddedB64Url(Buffer.from(input.publicKey))).toBe(REGISTER_GOLDEN_REPORTING_PUBKEY);
          expect(Buffer.from(input.preimage)).toEqual(expectedPreimage);
          expect(Buffer.from(input.signature)).toEqual(expectedSignature);
          input.publicKey.fill(0);
          input.preimage.fill(0);
          input.signature.fill(0);
          return true;
        },
      },
    );
    expect(result).toEqual({ ok: true, reason: null });

    expect(
      verifyRegisterProofOfPossession(REGISTER_GOLDEN_PREIMAGE, REGISTER_GOLDEN_POP_SIGNATURE, {
        validatePublicKeyPoint: (key) =>
          paddedB64Url(Buffer.from(key)) === REGISTER_GOLDEN_REPORTING_PUBKEY,
        verifyDetached: ({ preimage, signature }) =>
          Buffer.from(preimage).equals(expectedPreimage) &&
          Buffer.from(signature).equals(expectedSignature),
      }).ok,
    ).toBe(true);
  });

  it("returns a fresh success result from every successful verification", () => {
    const callbacks = {
      validatePublicKeyPoint: () => true,
      verifyDetached: () => true,
    };
    const first = verifyRegisterProofOfPossession(
      REGISTER_GOLDEN_PREIMAGE,
      REGISTER_GOLDEN_POP_SIGNATURE,
      callbacks,
    );
    const second = verifyRegisterProofOfPossession(
      REGISTER_GOLDEN_PREIMAGE,
      REGISTER_GOLDEN_POP_SIGNATURE,
      callbacks,
    );
    const structuralFirst = verifyRegisterPreimage(REGISTER_GOLDEN_PREIMAGE);
    const structuralSecond = verifyRegisterPreimage(REGISTER_GOLDEN_PREIMAGE);
    expect(first).not.toBe(second);
    expect(structuralFirst).not.toBe(structuralSecond);
    (first as { ok: boolean; reason: string | null }).ok = false;
    (structuralFirst as { ok: boolean; reason: string | null }).reason = "mutated";
    expect(second).toEqual({ ok: true, reason: null });
    expect(structuralSecond).toEqual({ ok: true, reason: null });
  });
});

describe("the reporting-auth register tuple census: Ed25519-only, legacy-disjoint, purpose-separated", () => {
  it("permits only the Ed25519 signed tuple; HMAC and bearer are forbidden", () => {
    expect([...ALLOWED_CREDENTIAL_MECHANISMS]).toEqual(["ed25519_signed_tuple"]);
    for (const mechanism of FORBIDDEN_CREDENTIAL_MECHANISMS) {
      expect(credentialMechanismAllowed(mechanism)).toBe(false);
    }
    expect(FORBIDDEN_CREDENTIAL_MECHANISMS).toContain("hmac");
    expect(FORBIDDEN_CREDENTIAL_MECHANISMS.some((m) => m.startsWith("bearer"))).toBe(true);
  });

  it("keeps the v2 pull purposes disjoint from the frozen legacy push purposes", () => {
    const legacy = new Set<string>(LEGACY_PUSH_PURPOSES);
    for (const p of V2_REPORTING_PURPOSES) {
      expect(legacy.has(p)).toBe(false);
    }
    expect(LEGACY_PUSH_PURPOSES).toContain("zupay-reporting-v1");
  });

  it("separates the reporting key's purposes from wallet/artifact/device purposes", () => {
    const forbidden = new Set<string>(REPORTING_CROSS_PURPOSE_FORBIDDEN);
    for (const p of REPORTING_KEY_ALLOWED_PURPOSES) {
      expect(forbidden.has(p)).toBe(false);
    }
  });
});

describe("the reporting-auth register tuple negative path (one per A.9 fact class)", () => {
  const jsonOf = (p: string): string => p.slice(p.indexOf("\n") + 1);

  it("A.9 #1 — a field reorder is rejected", () => {
    const reordered =
      `${REPORTING_REGISTER_PURPOSE}\n` +
      JSON.stringify({
        canonical_version: 1,
        purpose: REPORTING_REGISTER_PURPOSE,
        node_id: REGISTER_GOLDEN_PAYLOAD.node_id,
        implementer_id: REGISTER_GOLDEN_PAYLOAD.implementer_id,
        new_reporting_key_id: REGISTER_GOLDEN_PAYLOAD.new_reporting_key_id,
        new_reporting_public_key: REGISTER_GOLDEN_PAYLOAD.new_reporting_public_key,
        supersedes_key_id: REGISTER_GOLDEN_PAYLOAD.supersedes_key_id,
        nonce: REGISTER_GOLDEN_PAYLOAD.nonce,
        issued_at: REGISTER_GOLDEN_PAYLOAD.issued_at,
        expires_at: REGISTER_GOLDEN_PAYLOAD.expires_at,
      });
    expect(verifyRegisterPreimage(reordered).ok).toBe(false);
  });

  it("A.9 #2 — a prefix/payload purpose mismatch is rejected", () => {
    expect(verifyRegisterPreimage(`zp-report-request-v1\n${jsonOf(REGISTER_GOLDEN_PREIMAGE)}`).ok).toBe(
      false,
    );
  });

  it("A.9 #3 — canonical_version as string \"1\" is rejected", () => {
    const stringVersion = REGISTER_GOLDEN_PREIMAGE.replace('"canonical_version":1', '"canonical_version":"1"');
    expect(verifyRegisterPreimage(stringVersion).ok).toBe(false);
  });

  it("A.9 #4 — an uppercase (non-canonical) UUID is rejected", () => {
    // new_reporting_key_id carries hex letters (unlike the all-digit node_id), so uppercasing it
    // actually produces a non-canonical UUID for the verifier to reject.
    const upper = buildRegisterPreimage({
      ...REGISTER_GOLDEN_PAYLOAD,
      new_reporting_key_id: REGISTER_GOLDEN_PAYLOAD.new_reporting_key_id.toUpperCase(),
    });
    expect(verifyRegisterPreimage(upper).ok).toBe(false);
  });

  it("A.9 #5 — an unpadded new_reporting_public_key is rejected", () => {
    const unpadded = buildRegisterPreimage({
      ...REGISTER_GOLDEN_PAYLOAD,
      new_reporting_public_key: REGISTER_GOLDEN_PAYLOAD.new_reporting_public_key.replace(/=$/, ""),
    });
    expect(verifyRegisterPreimage(unpadded).ok).toBe(false);
  });

  it("A.9 register — supersedes_key_id omitted instead of null is rejected", () => {
    // A.9 register-specific: the nullable field must be present as JSON null, never dropped.
    const dropped = `${REPORTING_REGISTER_PURPOSE}\n${jsonOf(REGISTER_GOLDEN_PREIMAGE).replace(
      ',"supersedes_key_id":null',
      "",
    )}`;
    expect(verifyRegisterPreimage(dropped).ok).toBe(false);
  });

  it("A.9 register — a non-null supersedes_key_id (rotation) is accepted", () => {
    const rotate = buildRegisterPreimage({
      ...REGISTER_GOLDEN_PAYLOAD,
      supersedes_key_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    });
    expect(verifyRegisterPreimage(rotate).ok).toBe(true);
  });

  it("A.9 register — an enrolment window over 300 seconds is rejected", () => {
    const wide = buildRegisterPreimage({
      ...REGISTER_GOLDEN_PAYLOAD,
      expires_at: "2026-07-18T00:05:00.001Z",
    });
    expect(verifyRegisterPreimage(wide)).toEqual({ ok: false, reason: "enrolment window exceeds 300 seconds" });
  });

  it("A.9 #10 — cross-purpose signing by the reporting key is rejected", () => {
    expect(reportingKeyMaySign("zp-node-event-v1")).toBe(false);
    expect(reportingKeyMaySign("zp-receive-expected-v1")).toBe(false);
    expect(reportingKeyMaySign("zp-report-request-v1")).toBe(true);
  });

  it("lifecycle — reactivating a terminal key is rejected", () => {
    expect(isLegalReportingKeyTransition("REVOKED", "ACTIVE")).toBe(false);
    expect(isLegalReportingKeyTransition("RETIRED", "ACTIVE")).toBe(false);
    expect(isLegalReportingKeyTransition("PENDING", "ACTIVE")).toBe(true);
  });

  it("tenant binding — a wrong-tenant request tuple is rejected", () => {
    const binding = {
      reporting_key_id: REGISTER_GOLDEN_PAYLOAD.new_reporting_key_id,
      node_id: REGISTER_GOLDEN_PAYLOAD.node_id,
      implementer_id: REGISTER_GOLDEN_PAYLOAD.implementer_id,
    };
    expect(
      requestTupleMatchesBinding(binding, {
        node_id: REGISTER_GOLDEN_PAYLOAD.node_id,
        implementer_id: "deadbeef-dead-4ead-8ead-deaddeaddead",
      }),
    ).toBe(false);
    expect(
      requestTupleMatchesBinding(binding, {
        node_id: REGISTER_GOLDEN_PAYLOAD.node_id,
        implementer_id: REGISTER_GOLDEN_PAYLOAD.implementer_id,
      }),
    ).toBe(true);
  });
});
