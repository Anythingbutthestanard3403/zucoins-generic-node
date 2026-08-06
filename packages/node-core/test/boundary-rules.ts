import { FORBIDDEN_TERMS } from "../../generic-node-contracts/src/scan/forbidden-terms.ts";

/**
 * Canonical product vocabulary exported by
 * `@zucoins/generic-node-contracts` — the single source of truth this dependency-coupling
 * gate shares with the source-text scanner, so the manifest gate can never drift narrower
 * than the vocabulary gate. A hand-maintained 6-term subset silently
 * dropped `treasury`, `withdrawal`, `sweep`, `payout`, `order`, `reservation`, `outbound`
 * and `drain`, letting product-named dependencies pass. Lowercased because both the
 * package-leaf check and the fragment check compare case-insensitively (so canonical `ZUC`
 * participates as `zuc`).
 */
const CANONICAL_PRODUCT_TERMS: readonly string[] = FORBIDDEN_TERMS.map((term) =>
  term.toLowerCase(),
);

/**
 * Concrete frozen v1 product package leaves that are forbidden as dependency
 * couplings but are not part of the product vocabulary: the checkout widget and the
 * hosted platform. Carried alongside the canonical terms so neither gate can drop them.
 */
const FROZEN_V1_PRODUCT_LEAVES = ["widget", "hosted-platform"] as const;

/**
 * Forbidden leaf package names: a dependency whose scope-stripped leaf equals any of these
 * is a product coupling. Matched by exact, case-insensitive leaf equality — never a
 * substring — so the compatibility scope `@zupayments/*` and brand `zucoins` are not
 * false-positived (their leaves are `splitchain`/`shared`/`node-core`, not a listed term).
 */
export const FORBIDDEN_PACKAGE_NAMES: readonly string[] = [
  ...CANONICAL_PRODUCT_TERMS,
  ...FROZEN_V1_PRODUCT_LEAVES,
];

/**
 * Forbidden dependency-target fragments: the concrete frozen v1 package paths and scopes,
 * plus a leading-slash `/<term>` path fragment for every forbidden leaf name — so a
 * `file:`/`link:` target pointing at a product package path is rejected even behind a
 * neutral local dependency name. The leading slash preserves the compatibility carve-out:
 * `@zupayments/…` never contains `/payment`, and `zupayments`/`zucoins` never contain
 * `/zuc`.
 */
export const FORBIDDEN_DEPENDENCY_FRAGMENTS: readonly string[] = [
  "apps/node",
  "apps/platform",
  "packages/widget",
  "packages/vault-client",
  "@zupayments/node",
  "@zupayments/platform",
  "@zupayments/widget",
  "@zupayments/vault-client",
  ...FORBIDDEN_PACKAGE_NAMES.map((name) => `/${name}`),
];
