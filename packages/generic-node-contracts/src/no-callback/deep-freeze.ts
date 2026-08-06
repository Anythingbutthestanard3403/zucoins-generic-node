// Audit correction (defect 1) — recursive Object.freeze. A `readonly` / `as const` array
// is immutable only to the TYPE CHECKER; at runtime its rows and the array itself can still be
// mutated (push, index assignment, property assignment). Frozen channel/relocation data must be
// immutable at RUNTIME so injected node-push metadata cannot poison a verifier's input or any
// oracle derived from the same reference. Pure, no I/O.
//
// CONTRACT_FREEZE.
export function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const key of Object.getOwnPropertyNames(value)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
    Object.freeze(value);
  }
  return value;
}
