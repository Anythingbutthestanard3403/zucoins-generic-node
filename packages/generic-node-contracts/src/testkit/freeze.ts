import { expect } from "vitest";

/**
 * Asserts `actual` contains exactly the same members as `frozen` (a closed set), ignoring
 * sequence. Use `assertFieldOrder` when the sequence itself is part of the frozen contract.
 */
export const assertClosedSet = <T>(actual: readonly T[], frozen: readonly T[]): void => {
  const actualSorted = [...actual].sort();
  const frozenSorted = [...frozen].sort();
  expect(actualSorted).toEqual(frozenSorted);
};

/**
 * Asserts `actual` equals `frozen` exactly, including sequence. Use for tuples where the
 * field/row sequence is itself a frozen fact (e.g. signed field sequence, transition table
 * row sequence).
 */
export const assertFieldOrder = <T>(actual: readonly T[], frozen: readonly T[]): void => {
  expect(actual).toEqual(frozen);
};

/**
 * Negative-path helper: `mutator` produces a deliberately invalid value; `assertion` is the
 * check that is expected to reject it. Fails the test if `assertion` does NOT throw.
 */
export const expectRejects = <T>(mutator: () => T, assertion: (mutated: T) => void): void => {
  expect(() => assertion(mutator())).toThrow();
};
