import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import {
  VAULT_OPEN_FAILURE_CODES,
  NO_HYBRID_FALLBACK,
  classifyOpenOutcome,
  OPEN_CONDITIONS_ALL_PASS,
  type OpenConditions,
} from "./failure-behavior.ts";

describe("vault open failure behavior is frozen (the vault schema freeze; fail-closed)", () => {
  it("failure code vocabulary in the frozen check sequence", () => {
    assertFieldOrder(VAULT_OPEN_FAILURE_CODES, [
      "LENGTH_MISMATCH",
      "UNSUPPORTED_VERSION",
      "NON_CANONICAL_PUBLIC_KEY",
      "AUTH_TAG_FAILURE",
      "AAD_MISMATCH",
      "PUBLIC_KEY_MISMATCH",
    ]);
  });

  it("no hybrid fallback: every failure fails closed", () => {
    expect(NO_HYBRID_FALLBACK).toEqual({
      every_failure_fails_closed: true,
      fallback_to_shared_key_path: false,
      fallback_to_single_blob_path: false,
    });
  });

  it("all checks passing opens; any single failing check fails closed (negative path)", () => {
    expect(classifyOpenOutcome(OPEN_CONDITIONS_ALL_PASS)).toBe("OPEN_OK");

    const cases: ReadonlyArray<[Partial<OpenConditions>, string]> = [
      [{ lengthValid: false }, "LENGTH_MISMATCH"],
      [{ versionSupported: false }, "UNSUPPORTED_VERSION"],
      [{ pubkeyCanonical: false }, "NON_CANONICAL_PUBLIC_KEY"],
      [{ tagValid: false }, "AUTH_TAG_FAILURE"],
      [{ aadMatch: false }, "AAD_MISMATCH"],
      [{ pubkeyMatch: false }, "PUBLIC_KEY_MISMATCH"],
    ];
    for (const [override, expected] of cases) {
      const outcome = classifyOpenOutcome({ ...OPEN_CONDITIONS_ALL_PASS, ...override });
      expect(outcome).toBe(expected);
      expect(outcome).not.toBe("OPEN_OK");
    }
  });
});
