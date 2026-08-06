import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";
import {
  AMOUNT_BOUNDARY_VECTORS,
  AMOUNT_ARITHMETIC_VECTORS,
  AMOUNT_EMISSION_VECTORS,
} from "./vectors.js";
import { validateBalanceAmount, validateOperationAmount } from "./validators.js";
import { emitAmount, addAmounts, subtractAmounts } from "./emitter.js";

// Byte-frozen published vector files (digest-pinned for downstream consumers, the amounts downstream consumer/the fixture-provenance concern).
// Any edit must be a deliberate re-pin; regenerate + re-pin per CONTRACT.md.
const PINS = {
  "boundary.vectors.json": "c07dcc7e71b93aa8035876a64d71da75b454c48ca875a7c4401bce4fb89f379c",
  "arithmetic.vectors.json": "d4fd6df701b4ce89c243c95c6a30d079cb032ebb5ad0eaa99193f53513b7b912",
  "emission.vectors.json": "2f42b0a53a6a0425d5b2401cf98a8909bee545da65c3022b747bd45c528a0bd5",
} as const;

function vectorBytes(name: string): Buffer {
  return readFileSync(fileURLToPath(new URL(`./__vectors__/${name}`, import.meta.url)));
}

describe("published vector files — byte-frozen, digest-pinned", () => {
  for (const [name, digest] of Object.entries(PINS)) {
    it(`${name} matches its pinned sha256 and has no trailing newline`, () => {
      const bytes = vectorBytes(name);
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(digest);
      expect(bytes[bytes.length - 1]).not.toBe(0x0a);
    });
  }
});

describe("published vectors — snapshot sync with the as-const source", () => {
  it("boundary snapshot equals AMOUNT_BOUNDARY_VECTORS", () => {
    expect(JSON.parse(vectorBytes("boundary.vectors.json").toString())).toEqual(
      AMOUNT_BOUNDARY_VECTORS,
    );
  });
  it("arithmetic snapshot equals AMOUNT_ARITHMETIC_VECTORS", () => {
    expect(JSON.parse(vectorBytes("arithmetic.vectors.json").toString())).toEqual(
      AMOUNT_ARITHMETIC_VECTORS,
    );
  });
  it("emission snapshot equals AMOUNT_EMISSION_VECTORS", () => {
    expect(JSON.parse(vectorBytes("emission.vectors.json").toString())).toEqual(
      AMOUNT_EMISSION_VECTORS,
    );
  });
});

describe("published vectors — each is correct against the live contract", () => {
  it.each(AMOUNT_BOUNDARY_VECTORS)("boundary $kind ($input)", (v) => {
    expect(validateBalanceAmount(v.input)).toEqual(v.balance);
    expect(validateOperationAmount(v.input)).toEqual(v.operation);
  });
  it.each(AMOUNT_ARITHMETIC_VECTORS)("arithmetic $a $op $b = $expected", (v) => {
    const out = v.op === "add" ? addAmounts(v.a, v.b) : subtractAmounts(v.a, v.b);
    expect(out).toBe(v.expected);
  });
  it.each(AMOUNT_EMISSION_VECTORS)("emission $input -> $output", (v) => {
    expect(emitAmount(v.input)).toBe(v.output);
  });
});

describe("published vectors — coverage census + negatives per class", () => {
  it("boundary matrix covers every required class from the checklist", () => {
    const kinds = new Set(AMOUNT_BOUNDARY_VECTORS.map((v) => v.kind));
    for (const required of [
      "zero",
      "smallest-unit",
      "greatest-below-bound",
      "exact-bound",
      "above-bound",
      "exponent",
      "leading-zero",
      "trailing-dot",
      "negative",
      "excess-precision",
      "non-canonical",
    ]) {
      expect(kinds).toContain(required);
    }
  });
  it("boundary matrix carries a rejection for each rejection reason (negatives)", () => {
    const opReasons = new Set(
      AMOUNT_BOUNDARY_VECTORS.map((v) => (v.operation.ok ? null : v.operation.reason)),
    );
    expect(opReasons).toContain("amount_grammar_violation");
    expect(opReasons).toContain("amount_not_canonical");
    expect(opReasons).toContain("amount_not_positive");
  });
  it("emission vectors include non-canonical inputs that get trimmed (negative canonicality)", () => {
    const trimmed = AMOUNT_EMISSION_VECTORS.filter((v) => v.input !== v.output);
    expect(trimmed.length).toBeGreaterThan(0);
  });
});
