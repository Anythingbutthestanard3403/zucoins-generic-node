/**
 * SOURCE: the compatibility-literal preservation decision and the state-event reference
 * forbidden-alias reject-list.
 *
 * the compatibility-literal preservation rule/R-09: the generic redesign does not rename established `zp-*-v1` signed purposes, the
 * `zp1:` receive-message prefix, `X-ZP-*` headers, or established `zupay`/`zupayments`
 * compatibility names.
 *
 * the generic-core scan concern's original MINIMAL seed (the first eight entries) is grown here by the compat-literals concern, which owns
 * the complete, authoritative the compatibility-literal preservation rule allowlist; it must never shrink an entry that a shipped
 * literal still depends on. The four event-name-glob entries below are a
 * different kind of exemption from the compatibility-literal preservation rule compatibility literals above them: they let
 * `forbidden-aliases.contract.ts` (the compat-literals concern) cite the state-event reference's own closed reject-list as data
 * without a `contract-allow` marker, since the compat-literals concern does not own `forbidden-terms.ts`'s
 * `FROZEN_EXEMPTION_COUNT` and cannot add new marked lines there. The
 * `apps/node/src/checkout/sdk-route.ts` entry (GRAFT pass) is the same class of
 * exemption for a different reason: it is a real, existing v1 route-mount path this concern's
 * `compat-literals`/`inventory`/`compatibility-gate` modules cite verbatim as the frozen
 * "machine-frozen-at" location of `/sdk/zupayments.js` — the forbidden stem it triggers
 * ("checkout") is an accidental substring of an unrelated, pre-existing file path, not new
 * product vocabulary.
 */
export const D99_ALLOWLIST = [
  "zp-receive-expected-v1",
  "zp-move-internal-expected-v1",
  "zp-send-external-expected-v1",
  "zp-node-event-v1",
  "zp1:",
  "X-ZP-",
  "zupay",
  "zupayments",
  "reservation.*",
  "payment.*",
  "checkout.*",
  "refund.*",
  "apps/node/src/checkout/sdk-route.ts",
] as const;

export type D99AllowlistedLiteral = (typeof D99_ALLOWLIST)[number];

export const SOURCE = "decision: compatibility-literals" as const;
