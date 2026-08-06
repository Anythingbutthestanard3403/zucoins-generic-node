/**
 * Compatibility-literal preservation splits every retained literal into exactly four textual categories: the
 * documented `zp-*-v1` signed purposes, the `zp1:` on-chain receive-message prefix, the
 * `X-ZP-*` header family, and established `zupay`/`zupayments` compatibility names (including
 * the legacy `zupay-*`-spelled signed prefixes, the legacy `X-ZuPay-*` header spelling,
 * discovery/API route paths, and the `@zupayments/*` package scope, none of which literally
 * match the `zp-*-v1` or `X-ZP-*` patterns but are retained under this fourth clause). This
 * closed set mirrors that split; the compat-literals concern does not introduce a fifth category.
 */
export const LITERAL_KINDS = ["signed-purpose", "wire-prefix", "header", "name"] as const;

export type LiteralKind = (typeof LITERAL_KINDS)[number];
