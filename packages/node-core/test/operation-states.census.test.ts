// census: binds protocol/operation-states.ts to the two sources of truth for the
// operation status vocabulary — the `operation_status` enum in schema/base-enums-domains.sql
// and the frozen per-kind ladders in @zucoins/generic-node-contracts.
//
// Until this file existed, TERMINAL_OPERATION_STATES was bound to nothing. A status added to the
// enum would simply not be in the terminal list, `isTerminalOperationState` would answer false
// for it, and every caller reading that false as "nonterminal" would be wrong — including
// scripts/remediate-orphaned-lease.mjs, whose custody guard would then fall through to the
// evidence sweep on a status it had never heard of (finding B3 on).
//
// The binding is on the UNION of the terminal and nonterminal lists, in both directions, which
// is what makes it a classification gate: an added status cannot satisfy the union without
// someone putting it in one list or the other.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { OPERATION_STATES as APPENDIX_B_STATES_BY_KIND } from "@zucoins/generic-node-contracts/operations";

import {
  NONTERMINAL_OPERATION_STATES,
  TERMINAL_OPERATION_STATES,
  isKnownOperationState,
} from "../src/protocol/operation-states.ts";

// Assembled here rather than exported from protocol/, whose source-safety gate forbids
// spread syntax in production files.
const CLASSIFIED: readonly string[] = [...TERMINAL_OPERATION_STATES, ...NONTERMINAL_OPERATION_STATES];

const here = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(resolve(here, "../src/schema/base-enums-domains.sql"), "utf8");

// The enum members as the DDL declares them, read out of the SQL rather than restated here —
// restating them would only prove this file agrees with itself.
function declaredOperationStatuses(): string[] {
  const block = /CREATE TYPE operation_status AS ENUM \(([^)]*)\);/.exec(sql);
  if (block === null) throw new Error("operation_status enum not found in base-enums-domains.sql");
  return [...(block[1] ?? "").matchAll(/'([A-Z_]+)'/g)].map((m) => m[1] ?? "");
}

const sorted = (values: readonly string[]): string[] => [...values].sort();

describe("operation status vocabulary census", () => {
  it("the terminal/nonterminal partition covers the operation_status enum exactly", () => {
    const declared = declaredOperationStatuses();
    expect(declared.length).toBeGreaterThanOrEqual(10);
    // Both directions: a status added to the DDL is missing from the union (left side short),
    // and a status invented in TypeScript has no column that can hold it (right side long).
    expect(sorted(CLASSIFIED)).toEqual(sorted(declared));
  });

  it("no status is classified both terminal and nonterminal", () => {
    expect(CLASSIFIED).toHaveLength(new Set(CLASSIFIED).size);
    expect(TERMINAL_OPERATION_STATES.length).toBeGreaterThan(0);
    expect(NONTERMINAL_OPERATION_STATES.length).toBeGreaterThan(0);
  });

  it("the vocabulary matches the union of the frozen per-kind ladders", () => {
    // Cross-package binding: the DDL and the contracts package are independent transcriptions of
    // the same ladder table, so drift in either one is visible here.
    const fromLadders = new Set(Object.values(APPENDIX_B_STATES_BY_KIND).flat());
    expect(sorted(CLASSIFIED)).toEqual(sorted([...fromLadders]));
  });

  it("isKnownOperationState accepts every declared status and nothing else", () => {
    for (const status of declaredOperationStatuses()) {
      expect(isKnownOperationState(status), `${status} is declared but unknown`).toBe(true);
    }
    // The drift case the guard exists for: a plausible-looking status that is not in the closed
    // set, and the lowercase/empty forms a sloppy caller might pass.
    for (const bogus of ["SETTLED", "receive_landed", "", "TERMINAL"]) {
      expect(isKnownOperationState(bogus)).toBe(false);
    }
  });
});
