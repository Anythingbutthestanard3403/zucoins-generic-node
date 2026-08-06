import { AMOUNT_REJECTION_REASONS, type AmountRejectionReason } from "./manifest.js";

// the amounts vector matrix — the published ZKZ amount vector matrix. Downstream consumers (the amounts downstream consumer/the fixture-provenance concern)
// import these to test their own amount handling against the frozen contract. Every vector
// is verified here against the live .1/.2 contract and byte-frozen as a JSON snapshot under
// __vectors__/ (digest-pinned). splitchain emission parity is maintained (see emission set).

export type AmountCheckExpectation =
  | { readonly ok: true; readonly canonical: string }
  | { readonly ok: false; readonly reason: AmountRejectionReason };

export type AmountBoundaryVector = {
  readonly input: string;
  readonly kind: string;
  readonly balance: AmountCheckExpectation;
  readonly operation: AmountCheckExpectation;
};

export type AmountArithmeticVector = {
  readonly a: string;
  readonly op: "add" | "subtract";
  readonly b: string;
  readonly expected: string;
};

export type AmountEmissionVector = { readonly input: string; readonly output: string };

const R = AMOUNT_REJECTION_REASONS;
const GREATEST = `99999999.${"9".repeat(32)}`;
const SMALLEST = `0.${"0".repeat(31)}1`;

const grammarReject = { ok: false, reason: R.grammar } as const;

export const AMOUNT_BOUNDARY_VECTORS = [
  { input: "0", kind: "zero", balance: { ok: true, canonical: "0" }, operation: { ok: false, reason: R.notPositive } },
  { input: SMALLEST, kind: "smallest-unit", balance: { ok: true, canonical: SMALLEST }, operation: { ok: true, canonical: SMALLEST } },
  { input: GREATEST, kind: "greatest-below-bound", balance: { ok: true, canonical: GREATEST }, operation: { ok: true, canonical: GREATEST } },
  { input: "99999999", kind: "greatest-integer", balance: { ok: true, canonical: "99999999" }, operation: { ok: true, canonical: "99999999" } },
  { input: "2.5", kind: "normal", balance: { ok: true, canonical: "2.5" }, operation: { ok: true, canonical: "2.5" } },
  { input: "100000000", kind: "exact-bound", balance: grammarReject, operation: grammarReject },
  { input: "100000000.1", kind: "above-bound", balance: grammarReject, operation: grammarReject },
  { input: "100000001", kind: "above-bound-integer", balance: grammarReject, operation: grammarReject },
  { input: "1e5", kind: "exponent", balance: grammarReject, operation: grammarReject },
  { input: "01", kind: "leading-zero", balance: grammarReject, operation: grammarReject },
  { input: "00.1", kind: "leading-zero-fraction", balance: grammarReject, operation: grammarReject },
  { input: "1.", kind: "trailing-dot", balance: grammarReject, operation: grammarReject },
  { input: "-1", kind: "negative", balance: grammarReject, operation: grammarReject },
  { input: "-0", kind: "negative-zero", balance: grammarReject, operation: grammarReject },
  { input: `0.${"1".repeat(33)}`, kind: "excess-precision", balance: grammarReject, operation: grammarReject },
  { input: "2.50", kind: "non-canonical", balance: { ok: false, reason: R.nonCanonical }, operation: { ok: false, reason: R.nonCanonical } },
  { input: "0.0", kind: "non-canonical-zero", balance: { ok: false, reason: R.nonCanonical }, operation: { ok: false, reason: R.nonCanonical } },
] as const satisfies readonly AmountBoundaryVector[];

export const AMOUNT_ARITHMETIC_VECTORS = [
  { a: "10", op: "subtract", b: "2.5", expected: "7.5" },
  { a: "3", op: "add", b: "2.5", expected: "5.5" },
  { a: "0", op: "add", b: "2.5", expected: "2.5" },
  { a: "2.5", op: "subtract", b: "2.5", expected: "0" },
  { a: "0.1", op: "add", b: "0.2", expected: "0.3" },
  { a: "0.3", op: "subtract", b: "0.1", expected: "0.2" },
  { a: "1", op: "subtract", b: "1", expected: "0" },
  { a: "99999999", op: "add", b: SMALLEST, expected: `99999999.${"0".repeat(31)}1` },
] as const satisfies readonly AmountArithmeticVector[];

export const AMOUNT_EMISSION_VECTORS = [
  { input: "2.50", output: "2.5" },
  { input: "2.000", output: "2" },
  { input: "0.250000", output: "0.25" },
  { input: "5.0", output: "5" },
  { input: "0.0000001", output: "0.0000001" },
  { input: "0.00000000000000000001", output: "0.00000000000000000001" },
  { input: "99999999.5", output: "99999999.5" },
  { input: SMALLEST, output: SMALLEST },
  { input: `0.${"1".repeat(32)}`, output: `0.${"1".repeat(32)}` },
  { input: "7.50", output: "7.5" },
  { input: "1000.000", output: "1000" },
] as const satisfies readonly AmountEmissionVector[];

export const amountVectors = {
  boundary: AMOUNT_BOUNDARY_VECTORS,
  arithmetic: AMOUNT_ARITHMETIC_VECTORS,
  emission: AMOUNT_EMISSION_VECTORS,
} as const;
