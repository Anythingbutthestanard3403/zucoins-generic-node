import { readFileSync } from "node:fs";

import { BigNumber } from "bignumber.js";
import { afterEach, describe, expect, it } from "vitest";

import {
  AmountOverflowError,
  AmountUnderflowError,
  addZkz,
  compareZkz,
  formatZkz,
  inspectForeignSignedAmount,
  parsePositiveZkzAmount,
  parseZkzBalance,
  roundDownComputedZkz,
  subtractZkz,
  type ZkzBalance,
} from "../src/protocol/amounts.js";
import { InvalidScalarError } from "../src/protocol/scalars.js";
// Frozen amount contract (byte authority) — imported as the parity oracle for the
// byte-exact-signing foreign surface. Relative source import, matching the
// established-vector cross-read pattern in this suite.
import { inspectForeignAmount } from "../../generic-node-contracts/src/amounts/foreign.ts";

interface BoundaryExpectation {
  readonly ok: boolean;
  readonly canonical?: string;
  readonly reason?: string;
}

interface BoundaryVector {
  readonly input: string;
  readonly kind: string;
  readonly balance: BoundaryExpectation;
  readonly operation: BoundaryExpectation;
}

interface ArithmeticVector {
  readonly a: string;
  readonly op: "add" | "subtract";
  readonly b: string;
  readonly expected: string;
}

interface EmissionVector {
  readonly input: string;
  readonly output: string;
}

function readVectors<T>(name: string): T {
  return JSON.parse(
    readFileSync(
      new URL(`../../generic-node-contracts/src/amounts/__vectors__/${name}`, import.meta.url),
      "utf8",
    ),
  ) as T;
}

const ORIGINAL_GLOBAL_CONFIG = BigNumber.config();

afterEach(() => {
  BigNumber.config(ORIGINAL_GLOBAL_CONFIG);
});

describe("canonical ZKZ trust-boundary parsing", () => {
  it("enforces the zero-allowed balance and positive-operation split", () => {
    expect(parseZkzBalance("0")).toBe("0");
    expect(parseZkzBalance("0.00000000000000000000000000000001")).toBe(
      "0.00000000000000000000000000000001",
    );
    expect(parsePositiveZkzAmount("0.00000000000000000000000000000001")).toBe(
      "0.00000000000000000000000000000001",
    );
    expect(() => parsePositiveZkzAmount("0")).toThrow(InvalidScalarError);
  });

  it("accepts the greatest legal value and rejects the exclusive bound", () => {
    const greatest = `99999999.${"9".repeat(32)}`;
    expect(parseZkzBalance(greatest)).toBe(greatest);
    expect(parsePositiveZkzAmount(greatest)).toBe(greatest);
    for (const value of ["100000000", "100000000.0", "100000001"]) {
      expect(() => parseZkzBalance(value)).toThrow(InvalidScalarError);
    }
  });

  it("rejects coercion, exponent, locale, sign, negative zero, and noncanonical spelling", () => {
    const invalid: unknown[] = [
      0,
      0.1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      null,
      undefined,
      {},
      "NaN",
      "Infinity",
      "-Infinity",
      "1e5",
      "1E5",
      "1_000",
      "1,000",
      "1 000",
      "+1",
      "-1",
      "-0",
      "01",
      "00.1",
      ".5",
      "1.",
      " 1",
      "1 ",
      "١",
      "2.50",
      "0.0",
      `0.${"1".repeat(33)}`,
    ];
    for (const value of invalid) {
      expect(() => parseZkzBalance(value)).toThrow(InvalidScalarError);
    }
  });

  it("revalidates branded inputs at runtime instead of trusting casts", () => {
    const forged = "2.50" as unknown as ZkzBalance;
    expect(() => formatZkz(forged)).toThrow(InvalidScalarError);
    expect(() => addZkz(forged, parseZkzBalance("1"))).toThrow(InvalidScalarError);
  });
});

describe("construction-only quantization and exact arithmetic", () => {
  it("rounds computed decimal strings down to 32 dp and then fully revalidates", () => {
    expect(roundDownComputedZkz(`1.${"6".repeat(32)}9`)).toBe(`1.${"6".repeat(32)}`);
    expect(roundDownComputedZkz(`0.${"0".repeat(32)}9`)).toBe("0");
    expect(roundDownComputedZkz("2.5000")).toBe("2.5");
    expect(roundDownComputedZkz("0.0")).toBe("0");
    expect(roundDownComputedZkz(`99999999.${"9".repeat(33)}`)).toBe(
      `99999999.${"9".repeat(32)}`,
    );
  });

  it("does not let the construction quantizer become an untrusted general parser", () => {
    const invalid: unknown[] = [
      1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      "1e-1",
      "+1",
      "-0",
      "-1",
      "01",
      ".5",
      " 1",
      "1 ",
      "Infinity",
    ];
    for (const value of invalid) {
      expect(() => roundDownComputedZkz(value)).toThrow(InvalidScalarError);
    }
    const maximumLengthIntermediate = `0.${"1".repeat(126)}`;
    expect(maximumLengthIntermediate).toHaveLength(128);
    expect(roundDownComputedZkz(maximumLengthIntermediate)).toBe(`0.${"1".repeat(32)}`);
    expect(() => roundDownComputedZkz(`0.${"1".repeat(127)}`)).toThrow(InvalidScalarError);
    expect(() => roundDownComputedZkz(`0.${"1".repeat(100_000)}`)).toThrow(
      InvalidScalarError,
    );
    expect(() => roundDownComputedZkz("100000000")).toThrow(AmountOverflowError);
  });

  it("formats, compares, adds, and subtracts exact canonical balances", () => {
    const oneTenth = parseZkzBalance("0.1");
    const twoTenths = parseZkzBalance("0.2");
    const threeTenths = parseZkzBalance("0.3");
    expect(formatZkz(oneTenth)).toBe("0.1");
    expect(compareZkz(oneTenth, twoTenths)).toBe(-1);
    expect(compareZkz(twoTenths, twoTenths)).toBe(0);
    expect(compareZkz(threeTenths, twoTenths)).toBe(1);
    expect(addZkz(oneTenth, twoTenths)).toBe("0.3");
    expect(subtractZkz(threeTenths, oneTenth)).toBe("0.2");
  });

  it("returns typed overflow and underflow failures", () => {
    const greatest = parseZkzBalance(`99999999.${"9".repeat(32)}`);
    const unit = parseZkzBalance(`0.${"0".repeat(31)}1`);
    expect(() => addZkz(greatest, unit)).toThrow(AmountOverflowError);
    expect(() => subtractZkz(parseZkzBalance("0"), unit)).toThrow(AmountUnderflowError);
  });

  it("is isolated from process-global BigNumber configuration", () => {
    BigNumber.config({
      DECIMAL_PLACES: 2,
      ROUNDING_MODE: BigNumber.ROUND_UP,
      EXPONENTIAL_AT: 1,
    });

    expect(roundDownComputedZkz(`0.${"3".repeat(32)}9`)).toBe(`0.${"3".repeat(32)}`);
    expect(addZkz(parseZkzBalance("0.1"), parseZkzBalance("0.2"))).toBe("0.3");
    expect(formatZkz(parseZkzBalance(`0.${"0".repeat(31)}1`))).toBe(
      `0.${"0".repeat(31)}1`,
    );
  });
});

describe("frozen-vector parity", () => {
  it("matches every published balance and operation boundary result", () => {
    const vectors = readVectors<BoundaryVector[]>("boundary.vectors.json");
    for (const vector of vectors) {
      if (vector.balance.ok) {
        expect(parseZkzBalance(vector.input)).toBe(vector.balance.canonical);
      } else {
        expect(() => parseZkzBalance(vector.input), vector.kind).toThrow(InvalidScalarError);
      }

      if (vector.operation.ok) {
        expect(parsePositiveZkzAmount(vector.input)).toBe(vector.operation.canonical);
      } else {
        expect(() => parsePositiveZkzAmount(vector.input), vector.kind).toThrow(
          InvalidScalarError,
        );
      }
    }
  });

  it("matches every published arithmetic vector", () => {
    const vectors = readVectors<ArithmeticVector[]>("arithmetic.vectors.json");
    for (const vector of vectors) {
      const a = parseZkzBalance(vector.a);
      const b = parseZkzBalance(vector.b);
      const actual = vector.op === "add" ? addZkz(a, b) : subtractZkz(a, b);
      expect(actual).toBe(vector.expected);
    }
  });

  it("matches published canonical emission without laundering trust-boundary input", () => {
    const vectors = readVectors<EmissionVector[]>("emission.vectors.json");
    for (const vector of vectors) {
      expect(roundDownComputedZkz(vector.input)).toBe(vector.output);
      expect(formatZkz(parseZkzBalance(vector.output))).toBe(vector.output);
      if (vector.input !== vector.output) {
        expect(() => parseZkzBalance(vector.input)).toThrow(InvalidScalarError);
      }
    }
  });
});

describe("independent BigInt-scaled randomized oracle", () => {
  const scale = 10n ** 32n;
  const maximum = 100000000n * scale;
  const mask = (1n << 256n) - 1n;

  function canonicalText(value: bigint): string {
    const integer = value / scale;
    const fraction = (value % scale).toString().padStart(32, "0").replace(/0+$/, "");
    return fraction === "" ? integer.toString() : `${integer}.${fraction}`;
  }

  it("checks every generated add/subtract case, including all overflow and underflow cases", () => {
    let state = 0x9e3779b97f4a7c15n;
    let overflowCases = 0;
    let underflowCases = 0;

    const next = (): bigint => {
      state =
        (state * 0x5851f42d4c957f2d14057b7ef767814fn +
          0x14057b7ef767814f5851f42d4c957f2dn) &
        mask;
      return state % maximum;
    };

    for (let index = 0; index < 512; index += 1) {
      const leftScaled = next();
      const rightScaled = next();
      const left = parseZkzBalance(canonicalText(leftScaled));
      const right = parseZkzBalance(canonicalText(rightScaled));

      expect(compareZkz(left, right)).toBe(
        leftScaled < rightScaled ? -1 : leftScaled > rightScaled ? 1 : 0,
      );

      const sum = leftScaled + rightScaled;
      if (sum >= maximum) {
        overflowCases += 1;
        expect(() => addZkz(left, right)).toThrow(AmountOverflowError);
      } else {
        expect(addZkz(left, right)).toBe(canonicalText(sum));
      }

      if (leftScaled < rightScaled) {
        underflowCases += 1;
        expect(() => subtractZkz(left, right)).toThrow(AmountUnderflowError);
      } else {
        expect(subtractZkz(left, right)).toBe(canonicalText(leftScaled - rightScaled));
      }
    }

    expect(overflowCases).toBeGreaterThan(0);
    expect(underflowCases).toBeGreaterThan(0);
  });
});

describe("foreign signed amount evidence", () => {
  it("preserves exact text and never returns a semantic brand", () => {
    // The byte-exact signing rule: a legitimately non-canonical foreign form is WELL-FORMED and preserved
    // byte-for-byte, never re-judged against node-authored canonical strictness or reformatted
    // to "2.5". (Previously asserted the divergent wellFormed:false / anomaly:"NON_CANONICAL",
    // which blessed the QA-FAIL defect.)
    expect(inspectForeignSignedAmount("2.50")).toEqual({
      exactText: "2.50",
      wellFormed: true,
      anomaly: null,
      requiresRawContainerPreservation: true,
      semanticPromotion: "REQUIRES_EXPLICIT_CANONICAL_PARSE",
    });
    expect(inspectForeignSignedAmount("1e5")).toEqual({
      exactText: "1e5",
      wellFormed: false,
      anomaly: "INVALID_FORMAT",
      requiresRawContainerPreservation: true,
      semanticPromotion: "REQUIRES_EXPLICIT_CANONICAL_PARSE",
    });
    expect(inspectForeignSignedAmount(2.5)).toEqual({
      exactText: null,
      wellFormed: false,
      anomaly: "NON_STRING",
      requiresRawContainerPreservation: true,
      semanticPromotion: "REQUIRES_EXPLICIT_CANONICAL_PARSE",
    });

    const canonicalEvidence = inspectForeignSignedAmount("2.5");
    expect(canonicalEvidence.exactText).toBe("2.5");
    expect(canonicalEvidence.wellFormed).toBe(true);
    expect(parseZkzBalance(canonicalEvidence.exactText)).toBe("2.5");
  });

  // bind node-core's foreign inspection to the frozen amount
  // contract (`inspectForeignAmount`) so the two gates can never silently re-diverge on the
  // byte-exact-signing foreign surface. Parity = agreement on the well-formedness verdict AND exact
  // byte preservation; node-core keeps its own richer envelope vocabulary on top.
  describe("foreign-inspection parity", () => {
    const foreignCases = [
      // The exact inputs previously found divergent (non-canonical, well-formed).
      "2.50",
      "2.000",
      "0.0",
      // Already-canonical foreign forms.
      "2.5",
      "0",
      // own malformed foreign cases (grammar violations).
      "1e5",
      "-1",
      "abc",
      "100000000",
      `0.${"1".repeat(33)}`,
    ];

    it.each(foreignCases)("agrees with inspectForeignAmount on %j", (input) => {
      const node = inspectForeignSignedAmount(input);
      const contract = inspectForeignAmount(input);
      // Well-formedness verdict must match the frozen contract.
      expect(node.wellFormed).toBe(contract.wellFormed);
      // Exact original bytes preserved identically on both sides (never reformatted).
      expect(node.exactText).toBe(contract.bytes);
      expect(node.exactText).toBe(input);
      // A well-formed foreign amount carries no anomaly on either side; a malformed one does.
      if (contract.wellFormed) {
        expect(node.anomaly).toBeNull();
        expect(contract.anomaly).toBeNull();
      } else {
        expect(node.anomaly).not.toBeNull();
        expect(contract.anomaly).not.toBeNull();
      }
    });

    it("treats the verdict's divergent inputs as well-formed, not anomalies", () => {
      for (const input of ["2.50", "2.000", "0.0"]) {
        const node = inspectForeignSignedAmount(input);
        expect(node.wellFormed).toBe(true);
        expect(node.anomaly).toBeNull();
        expect(node.exactText).toBe(input);
        // And the frozen contract agrees.
        expect(inspectForeignAmount(input).wellFormed).toBe(true);
      }
    });
  });
});

// A true package consume of the frozen amount contract is deferred (the contracts package
// exposes no root import surface yet), so node-core still re-derives the byte-identical foreign
// grammar. Until the consume lands, this SEEDED, deterministic property sweep binds node-core's
// foreign inspection to the real `inspectForeignAmount` across a wide input space, so drift
// protection is not limited to the enumerated cases above. The seed is a fixed constant: every
// sample — and therefore every failure — reproduces byte-for-byte, with no unseeded randomness in
// a money-path test. Parity = identical well-formedness verdict AND identical exact-byte
// preservation; node-core keeps its own richer envelope vocabulary on top.
describe("foreign-inspection property parity (seeded)", () => {
  // Frozen so failures reproduce exactly.
  const PRNG_SEED = 20270182;
  // Park–Miller MINSTD modulus and multiplier. Pure integer multiply/modulo staying < 2^53
  // (16807 * 2147483646 < 3.6e13), so it is exactly reproducible and needs no bitwise ops.
  const MINSTD_MODULUS = 2147483647;
  const MINSTD_MULTIPLIER = 16807;
  const SAMPLES_PER_CLASS = 128;
  const MAX_FRACTION_DIGITS = 32;
  const MAX_INTEGER_DIGITS = 8;

  function createRng(seed: number): () => number {
    let state = seed % MINSTD_MODULUS;
    if (state <= 0) {
      state += MINSTD_MODULUS - 1;
    }
    return () => {
      state = (state * MINSTD_MULTIPLIER) % MINSTD_MODULUS;
      return (state - 1) / (MINSTD_MODULUS - 1);
    };
  }

  type ForeignSampleClass = "canonical" | "grammarLegalNonCanonical" | "grammarIllegal";

  interface ForeignSample {
    readonly input: string;
    readonly klass: ForeignSampleClass;
  }

  function buildSamples(): readonly ForeignSample[] {
    const rng = createRng(PRNG_SEED);
    const randInt = (min: number, max: number): number =>
      min + Math.floor(rng() * (max - min + 1));
    const digitRun = (count: number, allowLeadingZero: boolean): string => {
      let out = "";
      for (let i = 0; i < count; i += 1) {
        const forbidLeadingZero = i === 0 && !allowLeadingZero;
        out += String(randInt(forbidLeadingZero ? 1 : 0, 9));
      }
      return out;
    };
    const integerPart = (): string =>
      rng() < 0.15 ? "0" : digitRun(randInt(1, MAX_INTEGER_DIGITS), false);

    const samples: ForeignSample[] = [];

    // Class 1 — canonical: bounded integer, optional fraction whose final digit is non-zero (no
    // trailing zero, no leading-zero integer, so it is already in canonical form).
    for (let i = 0; i < SAMPLES_PER_CLASS; i += 1) {
      const int = integerPart();
      if (rng() < 0.5) {
        samples.push({ input: int, klass: "canonical" });
        continue;
      }
      const fracLen = randInt(1, MAX_FRACTION_DIGITS);
      const frac =
        fracLen === 1
          ? String(randInt(1, 9))
          : `${digitRun(fracLen - 1, true)}${randInt(1, 9)}`;
      samples.push({ input: `${int}.${frac}`, klass: "canonical" });
    }

    // Class 2 — grammar-legal but NON-canonical: a fraction ending in one or more zeros (e.g.
    // "2.50", "5.00", "0.0"). Grammar-legal, yet a canonical-equality gate would reject it — this
    // class is exactly what the defect mishandled, so it is what gives the sweep teeth.
    for (let i = 0; i < SAMPLES_PER_CLASS; i += 1) {
      const int = integerPart();
      const trailingZeros = randInt(1, 4);
      const leadLen = randInt(0, MAX_FRACTION_DIGITS - trailingZeros - 1);
      const lead = leadLen === 0 ? "" : digitRun(leadLen, true);
      const frac = `${lead}${"0".repeat(trailingZeros)}`;
      samples.push({ input: `${int}.${frac}`, klass: "grammarLegalNonCanonical" });
    }

    // Class 3 — grammar-illegal: rejected identically by both gates (verdict parity = both false).
    const illegalFixed = [
      "",
      " ",
      ".",
      "-1",
      "+1",
      "1.",
      ".5",
      "01",
      "00.5",
      "1,000",
      "1 ",
      " 1",
      "1\n",
      "1e5",
      "2E3",
      "0x1f",
      "NaN",
      "Infinity",
      "-Infinity",
      "null",
      "undefined",
      "true",
      "1.2.3",
      "0.",
      "1e",
      "abc",
      "1_000",
    ];
    for (const value of illegalFixed) {
      samples.push({ input: value, klass: "grammarIllegal" });
    }
    let illegalCount = illegalFixed.length;
    while (illegalCount < SAMPLES_PER_CLASS) {
      const kind = randInt(0, 4);
      if (kind === 0) {
        // More than eight integer digits.
        samples.push({ input: digitRun(randInt(9, 15), false), klass: "grammarIllegal" });
      } else if (kind === 1) {
        // More than 32 fractional digits.
        samples.push({ input: `0.${"0".repeat(randInt(33, 40))}`, klass: "grammarIllegal" });
      } else if (kind === 2) {
        // Signed.
        samples.push({ input: `-${integerPart()}`, klass: "grammarIllegal" });
      } else if (kind === 3) {
        // Exponent.
        samples.push({ input: `${integerPart()}e${randInt(1, 9)}`, klass: "grammarIllegal" });
      } else {
        // Trailing dot.
        samples.push({ input: `${integerPart()}.`, klass: "grammarIllegal" });
      }
      illegalCount += 1;
    }

    return samples;
  }

  const samples = buildSamples();

  it("never diverges from inspectForeignAmount across the seeded input sweep", () => {
    for (const { input } of samples) {
      const node = inspectForeignSignedAmount(input);
      const contract = inspectForeignAmount(input);
      // Same well-formedness verdict as the frozen contract.
      expect(node.wellFormed).toBe(contract.wellFormed);
      // Exact original bytes preserved identically on both sides — never reformatted.
      expect(node.exactText).toBe(contract.bytes);
      expect(node.exactText).toBe(input);
      // A well-formed foreign amount carries no anomaly; a malformed one carries one on both sides.
      if (contract.wellFormed) {
        expect(node.anomaly).toBeNull();
      } else {
        expect(node.anomaly).not.toBeNull();
      }
    }
  });

  it("actually exercises each input class, including divergence-sensitive non-canonical forms", () => {
    const counts: Record<ForeignSampleClass, number> = {
      canonical: 0,
      grammarLegalNonCanonical: 0,
      grammarIllegal: 0,
    };
    for (const { klass } of samples) {
      counts[klass] += 1;
    }
    expect(counts.canonical).toBeGreaterThan(0);
    expect(counts.grammarLegalNonCanonical).toBeGreaterThan(0);
    expect(counts.grammarIllegal).toBeGreaterThan(0);

    // Every grammar-legal-non-canonical sample must be well-formed under the frozen contract:
    // these are exactly the inputs the pre-fix node gate wrongly flagged, so this keeps the sweep's
    // teeth guaranteed even if the seed or generator later changes.
    for (const { input, klass } of samples) {
      if (klass === "grammarLegalNonCanonical") {
        expect(inspectForeignAmount(input).wellFormed).toBe(true);
      }
    }
  });
});
