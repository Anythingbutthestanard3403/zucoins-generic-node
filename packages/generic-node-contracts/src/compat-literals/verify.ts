/**
 * Pure, stateless verifier functions over the frozen literal inventory (CONTRACT_FREEZE-legal:
 * no network/DB/fs/crypto seams). These operationalize the compatibility-literal preservation rule's "case- and byte-sensitive wherever
 * their defining contract says so" language into an exact-match check any lane can call instead
 * of re-deriving its own notion of "is this a retained literal."

 */
import { COMPATIBILITY_LITERAL_INVENTORY, type CompatibilityLiteralEntry } from "./inventory.contract.ts";

/**
 * Exact, case-sensitive membership check against the frozen inventory. A candidate that differs
 * from every entry by even one character — including case — is not a retained literal, regardless
 * of how close it looks (e.g. a fabricated `zp-fake-v1` purpose, or a lowercase `x-zp-totp` header
 * spelling never appears here even though header names are wire-case-insensitive; the canonical
 * documented spelling is the only one this registry recognizes).
 */
export const isKnownCompatibilityLiteral = (candidate: string): boolean =>
  COMPATIBILITY_LITERAL_INVENTORY.some((entry) => entry.literal === candidate);

export const findCompatibilityLiteral = (candidate: string): CompatibilityLiteralEntry | undefined =>
  COMPATIBILITY_LITERAL_INVENTORY.find((entry) => entry.literal === candidate);

/** Case-insensitive lookup — useful ONLY for proving a candidate differs solely by case. */
export const findCompatibilityLiteralCaseInsensitive = (
  candidate: string,
): CompatibilityLiteralEntry | undefined =>
  COMPATIBILITY_LITERAL_INVENTORY.find((entry) => entry.literal.toLowerCase() === candidate.toLowerCase());
