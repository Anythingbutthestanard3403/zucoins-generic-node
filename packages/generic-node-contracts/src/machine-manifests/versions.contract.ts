/**
 * Covers A.1.1 (`canonical_version` number 1; A.9 rule 3) and A.1.2 (SplitChain inner
 * version `"2"`);
 * protocol rules 1.2 and 3; enum additions are contract-version changes; the artifacts
 * freeze.
 *
 * the fixture-provenance purposes census — the frozen version vocabulary: the suite canonical version, the SplitChain inner
 * version/type/step literals, and the version-evolution rule. DATA ONLY so `gen/versions.json`
 * stays a clean review-diff snapshot.
 */

/** Manifest version (v1 `*_CONTRACT_VERSION` discipline): bump on any reviewed change. */
export const VERSIONS_CONTRACT_VERSION = 1 as const;

/**
 * Every `*-v1` v2-suite tuple carries `canonical_version` as the JSON NUMBER 1 — never the
 * string `"1"` or any other value (A.1.1; A.9 negative vector 3 rejects the string form).
 */
export const SUITE_CANONICAL_VERSION = 1 as const;

/** The SplitChain inner `version` field is the STRING `"2"` (protocol rule 3 position 2) — the
 *  opposite typing of the suite `canonical_version` number, deliberate per-encoding. */
export const SPLITCHAIN_INNER_VERSION = "2" as const;

/** The only SplitChain inner `type` literal the node builds (protocol rule 3 position 1). */
export const SPLITCHAIN_INNER_TYPE = "unique_combinable" as const;

/** The only `signer_steps` value (protocol rule 3 position 4). */
export const SPLITCHAIN_SIGNER_STEPS = 2 as const;

/** The frozen purpose suffix every live suite purpose carries (compatibility-literal preservation: never renamed).*/
export const SUITE_PURPOSE_SUFFIX = "-v1" as const;

/**
 * Version evolution (the artifacts freeze): a field/sequence/semantic change
 * to a frozen surface requires a NEW purpose/version with newly reviewed goldens — never an
 * in-place rewrite of a `-v1` surface. Adding, removing, renaming, or re-sequencing an enum
 * member is likewise a contract-version change, not an application-local migration.
 */
export const VERSION_EVOLUTION_RULE = {
  inPlaceEditOfV1Surface: false,
  changeRequiresNewPurposeAndReviewedGoldens: true,
  enumMembershipChangeIsContractVersionChange: true,
} as const;

export const SOURCE = "version literals A.1.1, A.1.2, A.9; artifacts-freeze" as const;
