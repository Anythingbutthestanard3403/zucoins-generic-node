/**
 * The compatibility-literal replacement policy: "A replacement requires an explicitly
 * versioned migration and compatibility plan; a repository-wide branding substitution is
 * forbidden." This is the one allowed path to ever change a retained literal, frozen as data
 * so no edit can treat a rename as a simple find-and-replace.
 */
export const REPLACEMENT_POLICY_RULE = "versioned-migration-only" as const;

export const REPLACEMENT_POLICY_FORBIDDEN = "repository-wide branding substitution" as const;

export const REPLACEMENT_POLICY = {
  rule: REPLACEMENT_POLICY_RULE,
  forbidden: REPLACEMENT_POLICY_FORBIDDEN,
  requirement:
    "Replacing any retained literal requires an explicitly versioned migration and compatibility " +
    "plan — for a signed/hashed literal (signed-purpose, wire-prefix, or a byte-sensitive name), " +
    "that means a NEW purpose/version string plus newly reviewed goldens, never an in-place rewrite " +
    "of a `-v1` surface. It may never be a broad search-and-replace across the repository.",
  sourceDocCitation: "compat-literal-preservation",
} as const;
