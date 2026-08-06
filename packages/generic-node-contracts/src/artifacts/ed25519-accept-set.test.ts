/**
 *  — Ed25519 NEGATIVE vectors for the DEPENDENCY-INJECTED default suite crypto
 * (`testkit/suiteVerificationCrypto.ts`, built from the wallet's `libsodium-wrappers` family).
 *
 * The A.8 goldens are positive-only. These vectors prove the DI default is NOT a more
 * permissive Ed25519 implementation than the wallet libsodium the signed bytes were minted with —
 * i.e. that moving the crypto behind an injection seam changed no accept-set semantics (the byte-exact signing rule
 * 3). Each vector asserts REJECTION by the injected default, and — critically — proves that
 * rejection is caused by a specific accept-set guard rather than a generic invalid signature:
 *
 *   1. non-canonical S / malleability — a permissive verifier omitting the `S < L` check would
 *      accept (R, S + L) because it reduces to the same S mod L; libsodium rejects non-canonical S.
 *   2. small-subgroup / torsion forgeries — each vector is a cofactorless-VALID signature under a
 *      torsion public key A, constructed so that EVERY libsodium reject path except the torsion-A
 *      guard is neutralized: R is a genuine non-torsion point, S is canonical (S < L), and the
 *      cofactorless relation `[S]B == R + [k]A` holds exactly. The injected default therefore REJECTS
 *      each vector SOLELY because A is torsion — proven by the flip control: the lenient reference
 *      `verifyCofactorlessOmittingSmallOrderAGuard` (libsodium's checks MINUS only the torsion-A
 *      guard, in `testkit/cofactoredEd25519.ts`) ACCEPTS the identical triple. That single-check
 *      asymmetry is A-ATTRIBUTABLE — removing the guard alone flips REJECT to ACCEPT, so the guard is
 *      load-bearing (the byte-exact signing rule). A ranges over the frozen the reporting-auth register tuple torsion deny-list
 *      `ED25519_SMALL_ORDER_ENCODINGS_HEX`.
 *
 * The node-identity seed-byte key is test-only and MUST never sign live ZKZ (A.8, A.9).
 */
import { beforeAll, describe, expect, it } from "vitest";

import { decodeBase64Url, encodeBase64Url } from "../testkit/independentCrypto.ts";
import { defaultSuiteVerificationCrypto } from "../testkit/suiteVerificationCrypto.ts";
import {
  cofactoredVerifyPreimageSignature,
  verifyCofactorlessOmittingSmallOrderAGuard,
} from "../testkit/cofactoredEd25519.ts";
import { readGoldenText } from "../testkit/byteGolden.ts";
import { ED25519_SMALL_ORDER_ENCODINGS_HEX } from "../reporting-auth/keys.ts";
import { EXECUTION_TIMEOUTS } from "../testkit/executionPolicy.ts";

// Ed25519 group modulus L = 2^252 + 27742317777372353535851937790883648493 (RFC 8032). A canonical
// signature scalar S satisfies 0 <= S < L; libsodium rejects any S >= L as non-canonical.
const ED25519_GROUP_ORDER_L = (1n << 252n) + 27742317777372353535851937790883648493n;

const NODE_PUB_B64 = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";

const goldenPreimage = (): string => readGoldenText("artifacts/zp-receive-expected-v1.preimage.txt");
const goldenSignatureB64 = (): string => readGoldenText("artifacts/zp-receive-expected-v1.sig.b64");

const leBytesToBigInt = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
};

const bigIntToLe32 = (value: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  let remaining = value;
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
};

const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

const verifyUnderDefault = (signatureB64Url: string, publicKeyB64Url: string): boolean =>
  defaultSuiteVerificationCrypto.verifyPreimageSignature({
    preimageText: goldenPreimage(),
    signatureB64Url,
    publicKeyB64Url,
  });

// Every case here is a real libsodium verification of the golden preimage — pure CPU, and the
// class that degraded most under fork oversubscription. Budget and its measured
// justification live in ../testkit/executionPolicy.ts.
describe(": injected default crypto preserves the wallet libsodium Ed25519 accept-set", { timeout: EXECUTION_TIMEOUTS.ed25519 }, () => {
  beforeAll(async () => {
    await defaultSuiteVerificationCrypto.ready();
  });

  it("POSITIVE CONTROL: the golden node signature verifies under the golden node public key", () => {
    expect(verifyUnderDefault(goldenSignatureB64(), NODE_PUB_B64)).toBe(true);
  });

  it("REJECTS a non-canonical-S malleated signature (S := S + L, so S >= L)", () => {
    const signature = decodeBase64Url(goldenSignatureB64()); // 64 bytes: R (32) || S (32)
    expect(signature.length).toBe(64);
    const r = signature.slice(0, 32);
    const s = signature.slice(32, 64);

    const malleatedScalar = bigIntToLe32(leBytesToBigInt(s) + ED25519_GROUP_ORDER_L);
    const malleated = new Uint8Array(64);
    malleated.set(r, 0);
    malleated.set(malleatedScalar, 32);
    const malleatedSignatureB64 = encodeBase64Url(malleated);

    // The malleated signature is a distinct 64-byte encoding that reduces to the same S mod L.
    expect(malleatedSignatureB64).not.toBe(goldenSignatureB64());
    // libsodium enforces canonical S — the malleated signature is rejected, not accepted.
    expect(verifyUnderDefault(malleatedSignatureB64, NODE_PUB_B64)).toBe(false);
  });

  it("the lenient reference verifier is faithful (accepts the genuine golden signature, rejects a tampered one)", () => {
    const genuine = decodeBase64Url(goldenSignatureB64());
    const nodePublicKey = decodeBase64Url(NODE_PUB_B64);
    // A real signature satisfies the cofactorless relation, hence also the cofactored one: the
    // lenient reference must accept it, proving it is not an accept-everything stub.
    expect(cofactoredVerifyPreimageSignature(goldenPreimage(), genuine, nodePublicKey)).toBe(true);
    // Flip one byte of S: both the lenient reference and the injected default reject it.
    const tampered = Uint8Array.from(genuine);
    tampered[40] ^= 0x01;
    expect(cofactoredVerifyPreimageSignature(goldenPreimage(), tampered, nodePublicKey)).toBe(false);
    expect(verifyUnderDefault(encodeBase64Url(tampered), NODE_PUB_B64)).toBe(false);
  });

  // A-ATTRIBUTABLE torsion forgery vectors. Each is a COFACTORLESS-VALID Ed25519 signature (R, S)
  // under a torsion public key A: [S]B == R + [k]A holds exactly, with k = SHA-512(R || A ||
  // preimage) mod L. Every libsodium reject path EXCEPT has_small_order(A) is deliberately cleared —
  // R is a genuine non-torsion point, S < L is canonical, R and A are canonically encoded — so the
  // injected default's REJECTION is attributable SOLELY to the torsion-A guard. Removing only that
  // guard (verifyCofactorlessOmittingSmallOrderAGuard) FLIPS every vector to ACCEPT.
  //
  // These are the fix for the prior VACUOUS vectors (R = neutral, S = 0): there R was itself a
  // torsion point, so libsodium rejected on has_small_order(R) and the cofactorless relation
  // independently of A, making the parametrization over A inert. Here R is non-torsion and the
  // relation holds, so only the A-guard can be the cause. Construction (Chalkias-Garillot-Nikolaenko,
  // "Taming the Many EdDSAs", 2020, mixed-torsion family with the torsion component in A): pick
  // canonical S, then grind R = [S]B - [j]A over torsion multiples j until SHA-512(R||A||preimage)
  // == j (mod n), n = torsion size of A, so [k]A = [j]A cancels. For the 7 keys of torsion size > 1
  // the torsion component genuinely participates ([k]A != neutral); the size-1 neutral key (idx 0) is
  // the sole degenerate case ([k]A == neutral), still A-attributable. The A values are exactly
  // ED25519_SMALL_ORDER_ENCODINGS_HEX (asserted below). `subgroupSize` is the torsion size of A.
  const A_ATTRIBUTABLE_FORGERY_VECTORS: readonly {
    readonly aHex: string;
    readonly rHex: string;
    readonly sHex: string;
    readonly subgroupSize: number;
  }[] = [
    {
      subgroupSize: 1,
      aHex: "0100000000000000000000000000000000000000000000000000000000000000",
      rHex: "3a1b3abd05ba5a3a2c1880944da059bc17c707c66c6b1fd2d174f8c632005c3e",
      sHex: "ffeeddccbbaa99887766554433221100efcdab9078563412eeffc000afec0d00",
    },
    {
      subgroupSize: 2,
      aHex: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      rHex: "70648df845e1d739da10f76dd8def94090b414f77df5ac6f9bb92cf00e13a3cc",
      sHex: "00efddcccbaa99887766554433221100efcdab9078563412eeffc000afec0d00",
    },
    {
      subgroupSize: 4,
      aHex: "0000000000000000000000000000000000000000000000000000000000000000",
      rHex: "2d10956bb6947e373363931668aa1966bdf8c0553203a5c09445ea7a946bee0f",
      sHex: "00efddccdbaa99887766554433221100efcdab9078563412eeffc000afec0d00",
    },
    {
      subgroupSize: 4,
      aHex: "0000000000000000000000000000000000000000000000000000000000000080",
      rHex: "e65ccdc385d2304706929582103d0c46487a92fab2c4378729b8479144a62581",
      sHex: "00efddccebaa99887766554433221100efcdab9078563412eeffc000afec0d00",
    },
    {
      subgroupSize: 8,
      aHex: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
      rHex: "fb5e91e640440add941c06f4afd05d95c8e74059498db1d155baee7b335eabbb",
      sHex: "00efddccfbaa99887766554433221100efcdab9078563412eeffc000afec0d00",
    },
    {
      subgroupSize: 8,
      aHex: "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
      rHex: "de6827ce2397a5c28dbf46faeb977c1f3d8f3fd36d1e7510dc8405640531c952",
      sHex: "01efddcc0bab99887766554433221100efcdab9078563412eeffc000afec0d00",
    },
    {
      subgroupSize: 8,
      aHex: "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
      rHex: "49db42d30aaf5a03d8193d448e491b2105318fb6827fb6fbbe948e7486498fde",
      sHex: "01efddcc1bab99887766554433221100efcdab9078563412eeffc000afec0d00",
    },
    {
      subgroupSize: 8,
      aHex: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
      rHex: "378167698bb458a9f494c42ebdee672d81425cb3d3e4b32c5548308a87fc39b5",
      sHex: "ffeeddcc2bab99887766554433221100efcdab9078563412eeffc000afec0d00",
    },
  ] as const;

  // The vector set covers exactly the frozen torsion deny-list — no torsion A is left unexercised.
  it("covers every frozen torsion encoding exactly once as a public key A", () => {
    const covered = A_ATTRIBUTABLE_FORGERY_VECTORS.map((v) => v.aHex).sort();
    expect(covered).toEqual([...ED25519_SMALL_ORDER_ENCODINGS_HEX].sort());
  });

  it.each(A_ATTRIBUTABLE_FORGERY_VECTORS)(
    "A-attributable torsion forgery under public key A (torsion size $subgroupSize): cofactorless-valid, so the injected default REJECTS SOLELY on the torsion-A guard while removing that guard alone ACCEPTS",
    ({ aHex, rHex, sHex }) => {
      const publicKey = hexToBytes(aHex);
      const signature = new Uint8Array(64);
      signature.set(hexToBytes(rHex), 0);
      signature.set(hexToBytes(sHex), 32);

      // Guard-neutralization preconditions — every libsodium reject path EXCEPT has_small_order(A)
      // is cleared, so the surviving rejection can only be the torsion-A guard:
      //  - A IS one of the torsion deny-list encodings (the guard's target):
      expect(ED25519_SMALL_ORDER_ENCODINGS_HEX).toContain(aHex);
      //  - R is NOT a torsion deny-list encoding (a sanity check on non-torsion R):
      expect(ED25519_SMALL_ORDER_ENCODINGS_HEX).not.toContain(rHex);
      //  - S is canonical (S < L): a permissive verifier omitting the canonical-S check is not what
      //    rejects here:
      expect(leBytesToBigInt(signature.slice(32, 64))).toBeLessThan(ED25519_GROUP_ORDER_L);

      // FLIP CONTROL — A-attribution. The lenient reference runs libsodium's exact accept-set MINUS
      // only the torsion-A guard (it still requires canonical S, on-curve/canonical R and A, a
      // NON-torsion R, and the cofactorless [S]B == R + [k]A). Its ACCEPT therefore proves the
      // cofactorless relation holds AND R is non-torsion AND S/A are canonical for this triple:
      expect(verifyCofactorlessOmittingSmallOrderAGuard(goldenPreimage(), signature, publicKey)).toBe(
        true,
      );
      // The injected default REJECTS the identical (preimage, signature, A) triple. The only
      // difference between the two verifiers is the torsion-A guard, so that guard is what rejects —
      // the injected default preserves the wallet libsodium torsion-A accept-set.
      expect(verifyUnderDefault(encodeBase64Url(signature), encodeBase64Url(publicKey))).toBe(false);

      // Secondary non-vacuity: even the maximally-lenient cofactored verifier accepts it (a
      // cofactorless-valid triple is also cofactored-valid).
      expect(cofactoredVerifyPreimageSignature(goldenPreimage(), signature, publicKey)).toBe(true);
    },
  );
});
