// Ed25519 compressed-point validation for the reporting-register
// proof-of-possession verifier. A.5.1 requires the verifier to reject a non-canonical,
// wrong-length, non-canonically-re-encoded, small-subgroup, or identity public key before it
// checks the PoP signature. `parseWalletPublicKey` (scalars.ts) already enforces byte-length and
// canonical re-encoding; it does not decompress the curve point, so a small-subgroup or identity
// key with an otherwise well-formed encoding passes it. This module closes that gap with full
// point decompression and a prime-subgroup membership check.
//
// Standard field arithmetic and point decompression, retyped onto this module's
// WalletPublicKey scalar with its own error discipline (no attacker bytes in the thrown error).

import { Buffer } from "node:buffer";

import type { WalletPublicKey } from "../scalars.js";

export class WeakEd25519KeyError extends Error {
  readonly code = "WEAK_ED25519_KEY";

  constructor() {
    super("public key is the identity element, small-subgroup, or otherwise not a prime-subgroup point");
    this.name = "WeakEd25519KeyError";
  }
}

interface ExtendedPoint {
  readonly x: bigint;
  readonly y: bigint;
  readonly z: bigint;
  readonly t: bigint;
}

const FIELD = (1n << 255n) - 19n;
const SUBGROUP_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;

function mod(value: bigint): bigint {
  const reduced = value % FIELD;
  return reduced < 0n ? reduced + FIELD : reduced;
}

function power(baseValue: bigint, exponentValue: bigint): bigint {
  let base = mod(baseValue);
  let exponent = exponentValue;
  let result = 1n;
  while (exponent > 0n) {
    if ((exponent & 1n) === 1n) result = mod(result * base);
    base = mod(base * base);
    exponent >>= 1n;
  }
  return result;
}

const CURVE_D = mod(-121665n * power(121666n, FIELD - 2n));
const SQRT_MINUS_ONE = power(2n, (FIELD - 1n) / 4n);
const IDENTITY: ExtendedPoint = Object.freeze({ x: 0n, y: 1n, z: 1n, t: 0n });

function littleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] ?? 0);
  }
  return value;
}

function add(left: ExtendedPoint, right: ExtendedPoint): ExtendedPoint {
  const a = mod((left.y - left.x) * (right.y - right.x));
  const b = mod((left.y + left.x) * (right.y + right.x));
  const c = mod(2n * CURVE_D * left.t * right.t);
  const d = mod(2n * left.z * right.z);
  const e = mod(b - a);
  const f = mod(d - c);
  const g = mod(d + c);
  const h = mod(b + a);
  return { x: mod(e * f), y: mod(g * h), z: mod(f * g), t: mod(e * h) };
}

function double(point: ExtendedPoint): ExtendedPoint {
  const a = mod(point.x * point.x);
  const b = mod(point.y * point.y);
  const c = mod(2n * point.z * point.z);
  const d = mod(-a);
  const e = mod((point.x + point.y) * (point.x + point.y) - a - b);
  const g = mod(d + b);
  const f = mod(g - c);
  const h = mod(d - b);
  return { x: mod(e * f), y: mod(g * h), z: mod(f * g), t: mod(e * h) };
}

function multiply(point: ExtendedPoint, scalarValue: bigint): ExtendedPoint {
  let scalar = scalarValue;
  let result = IDENTITY;
  let addend = point;
  while (scalar > 0n) {
    if ((scalar & 1n) === 1n) result = add(result, addend);
    addend = double(addend);
    scalar >>= 1n;
  }
  return result;
}

function isIdentity(point: ExtendedPoint): boolean {
  return point.x === 0n && mod(point.y - point.z) === 0n;
}

function decodePoint(encoded: Uint8Array): ExtendedPoint {
  if (encoded.length !== 32) throw new WeakEd25519KeyError();
  const bytes = Uint8Array.from(encoded);
  const sign = (bytes[31] ?? 0) >>> 7;
  bytes[31] = (bytes[31] ?? 0) & 0x7f;
  const y = littleEndian(bytes);
  if (y >= FIELD) throw new WeakEd25519KeyError();

  const ySquared = mod(y * y);
  const numerator = mod(ySquared - 1n);
  const denominator = mod(CURVE_D * ySquared + 1n);
  if (denominator === 0n) throw new WeakEd25519KeyError();
  const xSquared = mod(numerator * power(denominator, FIELD - 2n));
  let x = power(xSquared, (FIELD + 3n) / 8n);
  if (mod(x * x - xSquared) !== 0n) x = mod(x * SQRT_MINUS_ONE);
  if (mod(x * x - xSquared) !== 0n) throw new WeakEd25519KeyError();
  if (x === 0n && sign === 1) throw new WeakEd25519KeyError();
  const xSign = (x & 1n) === 1n ? 1 : 0;
  if (xSign !== sign) x = mod(-x);
  return { x, y, z: 1n, t: mod(x * y) };
}

// Rejects the identity element, cofactor-8 torsion points, and any point outside the main prime
// subgroup. Throws before any signature is checked against the key — A.5.1 requires point validity
// as a precondition of the PoP check, never a fallback after the signature check fails.
export function assertPrimeOrderEd25519PublicKey(key: WalletPublicKey): void {
  const point = decodePoint(Buffer.from(key, "base64url"));
  if (isIdentity(point) || isIdentity(multiply(point, 8n))) {
    throw new WeakEd25519KeyError();
  }
  if (!isIdentity(multiply(point, SUBGROUP_ORDER))) {
    throw new WeakEd25519KeyError();
  }
}
