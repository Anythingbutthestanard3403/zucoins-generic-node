/**
 * SOURCE: the signing-custody vault contract (decryption rejects AAD mismatch, public/private
 * key mismatch, unsupported version, tag failure, length mismatch, non-canonical public key) +
 * the vault-storage decision (fail-closed, no shim). the vault schema freeze freezes the failure vocabulary and
 * the no-hybrid-fallback rule, with a pure fail-closed classifier.
 */

export const VAULT_OPEN_FAILURE_CODES = [
  "LENGTH_MISMATCH",
  "UNSUPPORTED_VERSION",
  "NON_CANONICAL_PUBLIC_KEY",
  "AUTH_TAG_FAILURE",
  "AAD_MISMATCH",
  "PUBLIC_KEY_MISMATCH",
] as const;
export type VaultOpenFailureCode = (typeof VAULT_OPEN_FAILURE_CODES)[number];

/** Every open failure fails closed; there is no fallback to a shared-key or single-blob path. */
export const NO_HYBRID_FALLBACK = {
  every_failure_fails_closed: true,
  fallback_to_shared_key_path: false,
  fallback_to_single_blob_path: false,
} as const;

export interface OpenConditions {
  readonly lengthValid: boolean;
  readonly versionSupported: boolean;
  readonly pubkeyCanonical: boolean;
  readonly tagValid: boolean;
  readonly aadMatch: boolean;
  readonly pubkeyMatch: boolean;
}

/**
 * Classify an open attempt. The check sequence matches VAULT_OPEN_FAILURE_CODES (first failing
 * check wins); a successful open requires every check to pass. Pure and total — no key access.
 */
export const classifyOpenOutcome = (
  conditions: OpenConditions,
): "OPEN_OK" | VaultOpenFailureCode => {
  if (!conditions.lengthValid) return "LENGTH_MISMATCH";
  if (!conditions.versionSupported) return "UNSUPPORTED_VERSION";
  if (!conditions.pubkeyCanonical) return "NON_CANONICAL_PUBLIC_KEY";
  if (!conditions.tagValid) return "AUTH_TAG_FAILURE";
  if (!conditions.aadMatch) return "AAD_MISMATCH";
  if (!conditions.pubkeyMatch) return "PUBLIC_KEY_MISMATCH";
  return "OPEN_OK";
};

const ALL_PASS: OpenConditions = {
  lengthValid: true,
  versionSupported: true,
  pubkeyCanonical: true,
  tagValid: true,
  aadMatch: true,
  pubkeyMatch: true,
};

/** The all-pass conditions used by tests as the positive baseline. */
export const OPEN_CONDITIONS_ALL_PASS = ALL_PASS;
