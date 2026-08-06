// Live MOVE_INTERNAL preflight — shared types and decimal-string money comparison.
//
// the one-in-flight-per-wallet rule (one in-flight per wallet) and 4 (never
// blind-retry). Amounts are decimal strings compared without floating point.

/** Wallet balance or transfer amount in the protocol's decimal-string wire form. */
export type Amount = string;

export type AmountComparison = -1 | 0 | 1;

/** -1 / 0 / 1 numeric comparison of two decimal amount strings. */
export function compareAmounts(a: Amount, b: Amount): AmountComparison {
  const pa = parseAmount(a);
  const pb = parseAmount(b);
  if (pa.neg !== pb.neg) {
    if (pa.neg && !isZeroMagnitude(pa)) return -1;
    if (pb.neg && !isZeroMagnitude(pb)) return 1;
  }
  const sign = pa.neg ? -1 : 1;
  const intCmp = compareMagnitude(pa.int, pb.int);
  if (intCmp !== 0) return (intCmp * sign) as AmountComparison;
  return (compareFraction(pa.frac, pb.frac) * sign) as AmountComparison;
}

/** |a - b| <= tolerance, all as decimal strings. */
export function amountWithinTolerance(a: Amount, b: Amount, tolerance: Amount): boolean {
  const diff = compareAmounts(a, b) <= 0 ? subtractAmounts(b, a) : subtractAmounts(a, b);
  return compareAmounts(diff, tolerance) <= 0;
}

interface ParsedAmount {
  readonly neg: boolean;
  readonly int: string;
  readonly frac: string;
}

function parseAmount(value: Amount): ParsedAmount {
  const match = /^(-?)(\d+)(?:\.(\d+))?$/.exec(value.trim());
  if (match === null) {
    throw new Error(`malformed amount: ${JSON.stringify(value)}`);
  }
  const sign = match[1] ?? "";
  const int = stripLeadingZeros(match[2] ?? "0");
  const frac = (match[3] ?? "").replace(/0+$/, "");
  return { neg: sign === "-", int, frac };
}

function isZeroMagnitude(p: ParsedAmount): boolean {
  return p.int === "0" && p.frac === "";
}

function stripLeadingZeros(digits: string): string {
  const stripped = digits.replace(/^0+/, "");
  return stripped === "" ? "0" : stripped;
}

function compareMagnitude(a: string, b: string): AmountComparison {
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function compareFraction(a: string, b: string): AmountComparison {
  const scale = Math.max(a.length, b.length);
  const fa = a.padEnd(scale, "0");
  const fb = b.padEnd(scale, "0");
  if (fa < fb) return -1;
  if (fa > fb) return 1;
  return 0;
}

/** a - b for decimal strings where a >= b (caller guarantees). */
export function subtractAmounts(a: Amount, b: Amount): Amount {
  const pa = parseAmount(a);
  const pb = parseAmount(b);
  const scale = Math.max(pa.frac.length, pb.frac.length);
  const ai = toScaledBigInt(pa, scale);
  const bi = toScaledBigInt(pb, scale);
  const diff = ai - bi;
  if (scale === 0) return diff.toString();
  const raw = diff.toString().padStart(scale + 1, "0");
  const intPart = stripLeadingZeros(raw.slice(0, raw.length - scale));
  const fracPart = raw.slice(raw.length - scale).replace(/0+$/, "");
  return fracPart === "" ? intPart : `${intPart}.${fracPart}`;
}

function toScaledBigInt(p: ParsedAmount, scale: number): bigint {
  const digits = stripLeadingZeros(p.int + p.frac.padEnd(scale, "0"));
  return BigInt(digits);
}

/** Signed decimal-string difference (after - before). */
export function signedDelta(before: Amount, after: Amount): Amount {
  const cmp = compareAmounts(after, before);
  if (cmp === 0) return "0";
  if (cmp > 0) return subtractAmounts(after, before);
  return `-${subtractAmounts(before, after)}`;
}

/**
 * Dual-control authorization bound to one exact attempt. The live-chain
 * owner greenlight is retired; what remains is an attempt-bound dual-control attestation
 * that the runner records before arming any submit path.
 */
export interface DualControlAuthorization {
  /**
   * Must equal the plan's non-empty attemptId — a token for a different run never
   * clears preflight. Empty / whitespace-only values fail dual-control binding.
   */
  readonly attemptId: string;
  /** Operator / dual-control attestation id (key-free). */
  readonly attestationId: string;
  /** ISO-8601 UTC timestamp the attestation was recorded. */
  readonly recordedAt: string;
}

/**
 * Sealed key-free description of one authorized live MOVE_INTERNAL. Built by preflight
 * and carried into execution. Wallet identities only — never a private key
 * (the key-custody rule).
 */
export interface MoveInternalPlan {
  readonly kind: "MOVE_INTERNAL";
  readonly attemptId: string;
  readonly sourceWalletId: string;
  readonly destinationWalletId: string;
  /** Exact fractional ZKZ the run will move. */
  readonly amount: Amount;
  readonly authorization: DualControlAuthorization;
}
