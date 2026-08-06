// money-path invariant: operations.amount_zkz must enforce
// NUMERIC positivity, not a string `<> '0'`. This test CONSUMES the frozen positive predicate
// (ZKZ_AMOUNT_CHECK_DOMAINS.zkz_amount_positive_text) from @zucoins/generic-node-contracts and
// proves (a) operations.sql binds amount_zkz to the zkz_amount_positive_text domain carrying
// that exact predicate, with no zkz_amount_text / `<> '0'` bypass surviving, and (b) the
// predicate REJECTS every numerically-zero string form the old string check accepted
// ('0', '0.0', '0.00', '0.' + 32 zeros, '0.') while ACCEPTING genuine positive amounts.
// The frozen domain predicate is authoritative over any earlier draft schema text.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { ZKZ_AMOUNT_CHECK_DOMAINS } from "../../generic-node-contracts/src/amounts/manifest.ts";
import { OPERATIONS_SCHEMA_FILE } from "../src/schema/operations.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(resolve(here, "../src/schema", OPERATIONS_SCHEMA_FILE), "utf8");

// The exact frozen SQL predicate records for a strictly-positive persisted amount.
const positivePredicate = ZKZ_AMOUNT_CHECK_DOMAINS.zkz_amount_positive_text;

// Faithful in-JS evaluation of the SQL CHECK `VALUE ~ '<regex>' AND VALUE::numeric > 0`,
// using the regex extracted verbatim from the frozen predicate. Postgres `::numeric` is exact
// arbitrary precision; Number() is exact for these short canonical forms (<= 32 dp, |value| <
// 1e8, so no double underflow to 0 for any legal positive), which is all the `> 0` decision
// needs.
// ponytail: Number() proxy for ::numeric, exact on this bounded 32-dp domain; swap to a
// bignum only if the amount grammar ever admits sub-1e-308 magnitudes (it cannot).
const grammarMatch = /'(\^[^']*\$)'/.exec(positivePredicate);
if (grammarMatch === null || grammarMatch[1] === undefined) {
  throw new Error(`could not extract canonical grammar from frozen predicate: ${positivePredicate}`);
}
const grammar = new RegExp(grammarMatch[1]);
const passesPositiveDomain = (value: string): boolean => grammar.test(value) && Number(value) > 0;

// The actual breaking inputs: numerically zero yet `<> '0'` as strings (plus '0' itself).
const zeroForms = ["0", "0.0", "0.00", `0.${"0".repeat(32)}`, "0."] as const;
const positiveForms = [
  "2.25",
  "1",
  `0.${"0".repeat(31)}1`,
  "99999999.99999999999999999999999999999999",
] as const;

describe("operations.amount_zkz numeric-positivity (zero-form bypass)", () => {
  it("the frozen positive predicate uses NUMERIC positivity, never a string `<> '0'`", () => {
    expect(positivePredicate).toContain("VALUE::numeric > 0");
    expect(positivePredicate).not.toContain("<> '0'");
  });

  it("operations.sql binds amount_zkz to the frozen zkz_amount_positive_text domain", () => {
    expect(sql).toContain("amount_zkz zkz_amount_positive_text NOT NULL,");
    expect(sql).toContain(
      `CREATE DOMAIN zkz_amount_positive_text AS text\n  CHECK (${positivePredicate});`,
    );
  });

  it("the earlier grammar-only domain and the string `<> '0'` bypass are gone", () => {
    // Assert on the EXECUTABLE schema statements; the file's header comment names the retired
    // forms on purpose, so match the full column/domain/check statements, not bare fragments.
    expect(sql).not.toContain("CREATE DOMAIN zkz_amount_text");
    expect(sql).not.toContain("amount_zkz zkz_amount_text NOT NULL,");
    expect(sql).not.toContain("CHECK (amount_zkz <> '0')");
  });

  it("rejects every numerically-zero string form the string `<> '0'` check accepted", () => {
    for (const form of zeroForms) {
      expect(passesPositiveDomain(form), `zero-form ${JSON.stringify(form)} must be rejected`).toBe(
        false,
      );
    }
  });

  it("witnesses that these zero-forms are the actual bypass inputs (`<> '0'` yet numerically 0)", () => {
    // Regression witness: each leaked past the old string check (differs from '0') while being
    // mathematically zero -- exactly what the numeric domain now rejects.
    for (const form of ["0.0", "0.00", `0.${"0".repeat(32)}`]) {
      expect(form !== "0").toBe(true); // would have passed the old `amount_zkz <> '0'`
      expect(Number(form)).toBe(0); // yet is mathematically zero
    }
  });

  it("accepts genuine positive amounts", () => {
    for (const form of positiveForms) {
      expect(passesPositiveDomain(form), `positive ${JSON.stringify(form)} must be accepted`).toBe(
        true,
      );
    }
  });
});
