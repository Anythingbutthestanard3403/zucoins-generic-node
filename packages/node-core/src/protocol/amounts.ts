import {
  addAmounts,
  compareAmounts,
  emitAmount,
  matchesCanonicalGrammar,
  subtractAmounts,
  validateBalanceAmount,
  validateOperationAmount,
  type AmountRejectionReason,
} from "@zucoins/generic-node-contracts/amounts";

import { InvalidScalarError } from "./scalars.js";

declare const ZKZ_BALANCE_BRAND: unique symbol;
declare const POSITIVE_ZKZ_AMOUNT_BRAND: unique symbol;
declare const OBSERVED_ZKZ_BALANCE_BRAND: unique symbol;

/** Canonical node-authored balance text. Zero is valid. */
export type ZkzBalance = string & { readonly [ZKZ_BALANCE_BRAND]: "ZkzBalance" };

/** Canonical node-authored operation/artifact amount text. Zero is invalid. */
export type PositiveZkzAmount = string & {
  readonly [POSITIVE_ZKZ_AMOUNT_BRAND]: "PositiveZkzAmount";
};

/**
 * Grammar-valid OBSERVED foreign-signed balance text (the byte-exact signing rule). Carried verbatim
 * from an authoritative wallet head — possibly a legitimately non-canonical spelling such as
 * "2.50" — and never re-judged against node-authored canonical strictness at the observation
 * boundary. Zero is valid. Not a construction brand: node-authored paths must re-emit it
 * canonically (reemitObservedZkzCanonical) before arithmetic or emission.
 */
export type ObservedZkzBalance = string & {
  readonly [OBSERVED_ZKZ_BALANCE_BRAND]: "ObservedZkzBalance";
};

export type CanonicalZkz = ZkzBalance | PositiveZkzAmount;

// The byte-exact signing rule / canonical ZKZ amount contract: a foreign signed amount is judged by the structural grammar ONLY. A
// grammatical-but-non-canonical foreign form (e.g. "2.50") is well-formed, not an anomaly — there
// is deliberately no NON_CANONICAL member, so foreign bytes can never be re-judged against
// node-authored canonical strictness. This is the frozen amount grammar
// (`matchesCanonicalGrammar`), which node-core's test suite cross-checks for parity.
export type ForeignAmountAnomaly = "NON_STRING" | "INVALID_FORMAT";

/**
 * Evidence-only inspection. It intentionally carries no branded semantic amount: callers must
 * preserve the original signed container and explicitly call a canonical parser before promotion.
 */
export interface ForeignSignedAmountInspection {
  readonly exactText: string | null;
  readonly wellFormed: boolean;
  readonly anomaly: ForeignAmountAnomaly | null;
  readonly requiresRawContainerPreservation: true;
  readonly semanticPromotion: "REQUIRES_EXPLICIT_CANONICAL_PARSE";
}

export class AmountOverflowError extends Error {
  readonly code = "ZKZ_AMOUNT_OVERFLOW";

  constructor() {
    super("ZKZ arithmetic exceeded the exclusive protocol bound");
    this.name = "AmountOverflowError";
  }
}

export class AmountUnderflowError extends Error {
  readonly code = "ZKZ_AMOUNT_UNDERFLOW";

  constructor() {
    super("ZKZ subtraction produced a negative balance");
    this.name = "AmountUnderflowError";
  }
}

const UPPER_BOUND_EXCLUSIVE = "100000000";
const MAX_COMPUTED_AMOUNT_TEXT_LENGTH = 128;

// Construction-only syntax: unsigned ordinary decimal, bounded integer width, and arbitrary
// fractional precision up to the strict text limit. NOT an external/signed-text validator.
const COMPUTED_AMOUNT_PATTERN = /^(0|[1-9][0-9]{0,8})(?:\.[0-9]+)?$/;

function requireAmountString(
  value: unknown,
  scalarKind: "ZkzBalance" | "PositiveZkzAmount" | "ComputedZkz",
): string {
  if (typeof value !== "string") {
    throw new InvalidScalarError(scalarKind, "wrong_type");
  }
  return value;
}

function rejectionReasonToFailure(reason: AmountRejectionReason): InvalidScalarError["reason"] {
  switch (reason) {
    case "amount_grammar_violation":
      return "invalid_format";
    case "amount_not_canonical":
      return "non_canonical";
    case "amount_not_positive":
      return "not_positive";
    case "amount_out_of_range":
      return "out_of_range";
  }
}

export function parseZkzBalance(value: unknown): ZkzBalance {
  const text = requireAmountString(value, "ZkzBalance");
  const check = validateBalanceAmount(text);
  if (!check.ok) {
    throw new InvalidScalarError("ZkzBalance", rejectionReasonToFailure(check.reason));
  }
  return check.canonical as ZkzBalance;
}

export function parsePositiveZkzAmount(value: unknown): PositiveZkzAmount {
  const text = requireAmountString(value, "PositiveZkzAmount");
  const check = validateOperationAmount(text);
  if (!check.ok) {
    throw new InvalidScalarError("PositiveZkzAmount", rejectionReasonToFailure(check.reason));
  }
  return check.canonical as PositiveZkzAmount;
}

/** Revalidates a branded value and returns its exact canonical fixed-point text. */
export function formatZkz(value: CanonicalZkz): string {
  // Brands are compile-time only and may be forged across an untyped boundary.
  return parseZkzBalance(value);
}

/**
 * Construction-only quantizer for an internally computed unsigned decimal string. Not an external
 * or foreign-signed amount parser: trust boundaries must call parseZkzBalance or
 * parsePositiveZkzAmount, which reject >32 dp and noncanonical spelling instead of rewriting it.
 */
export function roundDownComputedZkz(value: unknown): ZkzBalance {
  const text = requireAmountString(value, "ComputedZkz");
  if (text.length > MAX_COMPUTED_AMOUNT_TEXT_LENGTH) {
    throw new InvalidScalarError("ComputedZkz", "invalid_length");
  }
  if (!COMPUTED_AMOUNT_PATTERN.test(text)) {
    throw new InvalidScalarError("ComputedZkz", "invalid_format");
  }
  // The grammar admitted a non-negative finite decimal; the exclusive bound is the only remaining
  // overflow gate. A 9-digit integer part is necessarily >= 1e8.
  if (text.split(".", 1)[0].length >= 9) {
    throw new AmountOverflowError();
  }
  // ROUND_DOWN of a non-negative decimal is truncation: cap the fraction at 32 digits, then drop
  // trailing zeros to reach canonical shortest form. The contracts package exposes no rounding
  // primitive (emitAmount is the no-arg-toFixed canonical-emission surface), so the quantizer
  // edits the validated decimal text structurally (split/slice/join) — no numeric coercion and no
  // byte-rewriting replace.
  const [integerPart, fractionPart = ""] = text.split(".");
  let fraction = fractionPart.slice(0, 32);
  while (fraction.endsWith("0")) {
    fraction = fraction.slice(0, -1);
  }
  const canonical = fraction.length > 0 ? [integerPart, fraction].join(".") : integerPart;
  return parseZkzBalance(canonical);
}

export function compareZkz(a: CanonicalZkz, b: CanonicalZkz): -1 | 0 | 1 {
  return compareAmounts(formatZkz(a), formatZkz(b));
}

export function addZkz(a: CanonicalZkz, b: CanonicalZkz): ZkzBalance {
  const result = addAmounts(formatZkz(a), formatZkz(b));
  if (compareAmounts(result, UPPER_BOUND_EXCLUSIVE) >= 0) {
    throw new AmountOverflowError();
  }
  return parseZkzBalance(result);
}

export function subtractZkz(a: CanonicalZkz, b: CanonicalZkz): ZkzBalance {
  const result = subtractAmounts(formatZkz(a), formatZkz(b));
  if (compareAmounts(result, "0") < 0) {
    throw new AmountUnderflowError();
  }
  return parseZkzBalance(result);
}

export function inspectForeignSignedAmount(value: unknown): ForeignSignedAmountInspection {
  if (typeof value !== "string") {
    return {
      exactText: null,
      wellFormed: false,
      anomaly: "NON_STRING",
      requiresRawContainerPreservation: true,
      semanticPromotion: "REQUIRES_EXPLICIT_CANONICAL_PARSE",
    };
  }

  // The byte-exact signing rule / canonical ZKZ amount contract: foreign signed bytes are judged by the STRUCTURAL grammar alone, never
  // re-canonicalized. A legitimately non-canonical foreign form such as "2.50" is well-formed and
  // preserved verbatim — NOT flagged as an anomaly and NOT reformatted to "2.5". A grammar
  // violation is recorded as evidence, never rewritten or dropped.
  const wellFormed = matchesCanonicalGrammar(value);
  return {
    exactText: value,
    wellFormed,
    anomaly: wellFormed ? null : "INVALID_FORMAT",
    requiresRawContainerPreservation: true,
    semanticPromotion: "REQUIRES_EXPLICIT_CANONICAL_PARSE",
  };
}

/**
 * Observation-boundary balance parser (the byte-exact signing rule). Validates an OBSERVED foreign-signed
 * balance by the structural grammar ALONE — never node-authored canonical emit equality — so a
 * legitimately non-canonical head spelling such as "2.50" is accepted and preserved byte-for-byte
 * instead of being false-rejected into a stuck settlement. Construction stays strict: it re-emits
 * canonically via reemitObservedZkzCanonical, because the node only ever authors shortest form.
 */
export function parseObservedZkzBalance(value: unknown): ObservedZkzBalance {
  const inspection = inspectForeignSignedAmount(value);
  if (!inspection.wellFormed) {
    throw new InvalidScalarError(
      "ZkzBalance",
      inspection.anomaly === "NON_STRING" ? "wrong_type" : "invalid_format",
    );
  }
  return inspection.exactText as ObservedZkzBalance;
}

/**
 * Node-authored bridge from the foreign-observed layer to the canonical layer. Re-emits an observed
 * balance to its canonical shortest form for arithmetic or emission. This does NOT reformat any
 * signed payload (the byte-exact signing rule): the observed bytes live in the signed head and are preserved
 * verbatim there; this only normalizes a value the node recomputes internally. Numerically
 * identity-preserving ("2.50" -> "2.5").
 */
export function reemitObservedZkzCanonical(value: ObservedZkzBalance): ZkzBalance {
  return parseZkzBalance(emitAmount(value));
}
