/**
 *  — TEST-ONLY *lenient* Ed25519 reference verifiers, used only by
 * `artifacts/ed25519-accept-set.test.ts` to prove the injected default suite crypto's small-subgroup
 * rejections are LOAD-BEARING and specifically ATTRIBUTABLE to the torsion-public-key guard, rather
 * than a generic key mismatch or the cofactored-vs-cofactorless difference.
 *
 * Two references live here, both against the same `[S]B == R + [k]A` / cofactored math primitives:
 *
 *   1. `verifyCofactorlessOmittingSmallOrderAGuard` — the PRECISE counterfactual. It runs libsodium's
 *      exact accept-set (canonical `S < L`; on-curve + canonical `y < p` decode of R and A;
 *      `has_small_order(R)` rejection; the COFACTORLESS relation `[S]B == R + [k]A`) MINUS one and
 *      only one check: the torsion/small-subgroup rejection of the public key A. So for a triple this
 *      ACCEPTS while the injected default REJECTS, the sole difference between the two verifiers is
 *      the torsion-A guard — the rejection is A-ATTRIBUTABLE. This is the flip control: removing only
 *      that guard turns REJECT into ACCEPT. The negative vectors are cofactorless-VALID
 *      (`[S]B == R + [k]A` holds exactly) with a genuine non-torsion R and canonical S, so no other
 *      libsodium check can be what rejects them.
 *
 *   2. `cofactoredVerifyPreimageSignature` — a maximally-lenient witness that additionally relaxes
 *      the relation to the COFACTORED `[8]([S]B) == [8]R + [8]([k]A)` and drops the canonical-S and
 *      torsion-R requirements. It is retained as a secondary non-vacuity check and to pin reference
 *      faithfulness (it must ACCEPT the genuine Appendix A golden and REJECT a tampered one). Because
 *      a cofactorless-valid triple is also cofactored-valid, it too accepts the vectors — but
 *      attribution to the A-guard specifically rests on reference (1), not this one.
 *
 * Construction of the vectors (committed as static hex in the test): Chalkias–Garillot–Nikolaenko,
 * "Taming the Many EdDSAs" (2020) mixed-torsion family with the torsion component in A — pick
 * canonical S, then grind `R = [S]B - [j]A` over torsion multiples `j` until
 * `SHA-512(R||A||preimage) ≡ j (mod n)` for `n` the torsion size of A, so `[k]A = [j]A` cancels and
 * `[S]B == R + [k]A` holds exactly.
 *
 * These are NOT general-purpose verifiers and MUST never be shipped to a runtime: they decode
 * arbitrary curve points and skip exactly the checks a real verifier needs. They live in `testkit/`
 * (never imported by a frozen contract module) and use only bigint field arithmetic plus SHA-512
 * from `node:crypto` — no new dependency, no libsodium ed25519 primitive (the non-sumo
 * `libsodium-wrappers` build exposes none).
 */
import { createHash } from "node:crypto";

// Curve field modulus p = 2^255 - 19 and the group modulus L = 2^252 + ... (RFC 8032 section 5.1).
const P = (1n << 255n) - 19n;
const GROUP_MODULUS_L = (1n << 252n) + 27742317777372353535851937790883648493n;

const fieldMod = (value: bigint): bigint => ((value % P) + P) % P;

const fieldPow = (base: bigint, exponent: bigint): bigint => {
  let result = 1n;
  let acc = fieldMod(base);
  let exp = exponent;
  while (exp > 0n) {
    if (exp & 1n) result = fieldMod(result * acc);
    acc = fieldMod(acc * acc);
    exp >>= 1n;
  }
  return result;
};

const fieldInv = (value: bigint): bigint => fieldPow(value, P - 2n);

// Edwards curve constant d = -121665 / 121666 (mod p) and the field square root of -1.
const CURVE_D = fieldMod(fieldMod(-121665n) * fieldInv(121666n));
const SQRT_MINUS_ONE = fieldPow(2n, (P - 1n) / 4n);

type Point = readonly [bigint, bigint];

// The neutral element of the group (the encoding 0x0100..00 decodes to this).
const NEUTRAL: Point = [0n, 1n];

const leBytesToBigInt = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
};

/** RFC 8032 section 5.1.3 x-coordinate recovery for a given y and sign bit; null when y encodes no point. */
const recoverX = (y: bigint, signBit: number): bigint | null => {
  if (y >= P) return null;
  const y2 = fieldMod(y * y);
  const u = fieldMod(y2 - 1n);
  const v = fieldMod(CURVE_D * y2 + 1n);
  const v3 = fieldMod(fieldMod(v * v) * v);
  const v7 = fieldMod(fieldMod(v3 * v3) * v);
  let x = fieldMod(u * v3 * fieldPow(fieldMod(u * v7), (P - 5n) / 8n));
  const check = fieldMod(v * x * x);
  if (check === fieldMod(u)) {
    // x already satisfies v*x^2 == u
  } else if (check === fieldMod(-u)) {
    x = fieldMod(x * SQRT_MINUS_ONE);
  } else {
    return null;
  }
  if ((x & 1n) !== BigInt(signBit)) x = fieldMod(-x);
  return x;
};

/** Decompress a 32-byte little-endian point encoding; null when it decodes to no curve point. */
const decompressPoint = (encoded: Uint8Array): Point | null => {
  const bytes = Uint8Array.from(encoded);
  const signBit = (bytes[31] >> 7) & 1;
  bytes[31] &= 0x7f;
  const y = leBytesToBigInt(bytes);
  const x = recoverX(y, signBit);
  return x === null ? null : [x, y];
};

/** Twisted-Edwards (a = -1) point addition. */
const addPoints = (a: Point, b: Point): Point => {
  const [x1, y1] = a;
  const [x2, y2] = b;
  const common = fieldMod(CURVE_D * x1 * x2 % P * y1 % P * y2);
  const x3 = fieldMod(fieldMod(x1 * y2 + x2 * y1) * fieldInv(fieldMod(1n + common)));
  const y3 = fieldMod(fieldMod(y1 * y2 + x1 * x2) * fieldInv(fieldMod(1n - common)));
  return [x3, y3];
};

/** Scalar multiplication [scalar]point via double-and-add. */
const scalarMultiply = (scalar: bigint, point: Point): Point => {
  let result: Point = NEUTRAL;
  let addend = point;
  let remaining = scalar;
  while (remaining > 0n) {
    if (remaining & 1n) result = addPoints(result, addend);
    addend = addPoints(addend, addend);
    remaining >>= 1n;
  }
  return result;
};

const pointsEqual = (a: Point, b: Point): boolean => a[0] === b[0] && a[1] === b[1];

// Base point B: By = 4/5 (mod p), Bx recovered with sign bit 0 (RFC 8032 section 5.1).
const BASE_POINT: Point = (() => {
  const by = fieldMod(4n * fieldInv(5n));
  const bx = recoverX(by, 0);
  if (bx === null) throw new Error("ed25519 base point recovery failed");
  return [bx, by];
})();

const sha512 = (bytes: Uint8Array): Uint8Array =>
  Uint8Array.from(createHash("sha512").update(bytes).digest());

/**
 * Lenient COFACTORED Ed25519 verification: returns true when `[8]([S]B) == [8]R + [8]([k]A)`, with
 * `k = SHA-512(R || A || preimage) mod L` and `S` taken as-is (no canonical `S < L` requirement, no
 * small-subgroup rejection of `A`). Returns false when a component fails to decode or the relation
 * does not hold. This ACCEPTS forgeries that libsodium rejects — that is its only reason to exist.
 */
export const cofactoredVerifyPreimageSignature = (
  preimageText: string,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean => {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  const rEncoded = signature.slice(0, 32);
  const a = decompressPoint(publicKey);
  const r = decompressPoint(rEncoded);
  if (a === null || r === null) return false;
  const s = leBytesToBigInt(signature.slice(32, 64));
  const preimageBytes = new TextEncoder().encode(preimageText);
  const challengeInput = new Uint8Array(rEncoded.length + publicKey.length + preimageBytes.length);
  challengeInput.set(rEncoded, 0);
  challengeInput.set(publicKey, rEncoded.length);
  challengeInput.set(preimageBytes, rEncoded.length + publicKey.length);
  const k = leBytesToBigInt(sha512(challengeInput)) % GROUP_MODULUS_L;
  const lhs = scalarMultiply(8n, scalarMultiply(s, BASE_POINT));
  const rhs = addPoints(scalarMultiply(8n, r), scalarMultiply(8n, scalarMultiply(k, a)));
  return pointsEqual(lhs, rhs);
};

/** True iff P lies in the torsion (small) subgroup — [8]P is the neutral element. */
const isSmallOrderPoint = (point: Point): boolean => pointsEqual(scalarMultiply(8n, point), NEUTRAL);

/**
 * Lenient COFACTORLESS Ed25519 verification that is byte-for-byte identical to the injected libsodium
 * default in every accept-set check EXCEPT it OMITS the torsion (small-subgroup) public-key
 * rejection. It still enforces, exactly as libsodium does:
 *   - canonical scalar `S < L` (rejects non-canonical S),
 *   - R and A decode to on-curve points with canonical `y < p` encodings (rejects otherwise),
 *   - `has_small_order(R)` — R must NOT be a torsion point,
 *   - the COFACTORLESS relation `[S]B == R + [k]A`, `k = SHA-512(R || A || preimage) mod L`.
 * It DELIBERATELY does not reject a torsion A. Consequently, a (preimage, signature, A) triple that
 * this ACCEPTS while the injected libsodium default REJECTS isolates exactly one difference — the
 * torsion-A guard — so that rejection is attributable SOLELY to that guard (the byte-exact signing rule). MUST
 * never be shipped to a runtime.
 */
export const verifyCofactorlessOmittingSmallOrderAGuard = (
  preimageText: string,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean => {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  const rEncoded = signature.slice(0, 32);
  const s = leBytesToBigInt(signature.slice(32, 64));
  if (s >= GROUP_MODULUS_L) return false; // canonical-S guard (kept, matches libsodium)
  const a = decompressPoint(publicKey);
  const r = decompressPoint(rEncoded);
  if (a === null || r === null) return false; // on-curve + canonical (y<p) encoding (kept)
  if (isSmallOrderPoint(r)) return false; // has_small_order(R) guard (kept)
  // has_small_order(A) guard DELIBERATELY OMITTED — that single omission is the whole experiment.
  const preimageBytes = new TextEncoder().encode(preimageText);
  const challengeInput = new Uint8Array(rEncoded.length + publicKey.length + preimageBytes.length);
  challengeInput.set(rEncoded, 0);
  challengeInput.set(publicKey, rEncoded.length);
  challengeInput.set(preimageBytes, rEncoded.length + publicKey.length);
  const k = leBytesToBigInt(sha512(challengeInput)) % GROUP_MODULUS_L;
  const lhs = scalarMultiply(s, BASE_POINT); // cofactorLESS: [S]B == R + [k]A
  const rhs = addPoints(r, scalarMultiply(k, a));
  return pointsEqual(lhs, rhs);
};
