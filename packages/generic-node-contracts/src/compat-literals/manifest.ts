import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  ZP_V1_PURPOSES,
  ZP1_RECEIVE_MESSAGE_PREFIX,
  ZP1_RECEIVE_MESSAGE_PATTERN_DESCRIPTION,
  REPORTING_HEADER_NAMES,
  TOTP_HEADER_NAME,
  ZP_HEADER_FAMILY,
  ZUPAY_COMPAT_NAME,
  ZUPAYMENTS_COMPAT_NAME,
  ZUPAY_NODE_DISCOVERY_PATH,
  ZUPAYMENTS_SDK_ROUTE_PATH,
  ZUPAYMENTS_PACKAGE_SCOPE_PREFIX,
  LEGACY_REPORTING_DOMAIN_PREFIXES,
  LEGACY_ZUPAY_HEADER_NAMES,
  WALLET_SECRET_AAD_DOMAIN,
} from "./compat-literals.contract.ts";
import {
  FORBIDDEN_STATE_ALIASES,
  FORBIDDEN_EVENT_ALIASES,
  FORBIDDEN_EVENT_GLOBS,
  FORBIDDEN_ALIAS_EXCEPTIONS,
} from "./forbidden-aliases.contract.ts";
import { LITERAL_KINDS } from "./kinds.ts";
import { REPLACEMENT_POLICY } from "./replacement-policy.ts";
import { COMPATIBILITY_LITERAL_INVENTORY } from "./inventory.contract.ts";
import { LITERAL_CONSTRUCTION_SITES } from "./construction-sites.contract.ts";
import { CANONICAL_VERSION_FOR_PURPOSE, CANONICAL_VERSION_V1 } from "./canonical-version.contract.ts";

/**
 * The compat-literals concern's self-registered ConcernManifest (the concern-manifest registry
 * leave-behind shape; see testkit/concernManifest.ts). Registration export only — the
 * registry assembly is `src/registry.ts`; nothing else touches it.
 */
export const COMPAT_LITERALS_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "compat-literals",
  decisionRefs: ["compat-literal-preservation"],
  frozenValues: {
    ZP_V1_PURPOSES,
    ZP1_RECEIVE_MESSAGE_PREFIX,
    ZP1_RECEIVE_MESSAGE_PATTERN_DESCRIPTION,
    REPORTING_HEADER_NAMES,
    TOTP_HEADER_NAME,
    ZP_HEADER_FAMILY,
    ZUPAY_COMPAT_NAME,
    ZUPAYMENTS_COMPAT_NAME,
    ZUPAY_NODE_DISCOVERY_PATH,
    ZUPAYMENTS_SDK_ROUTE_PATH,
    ZUPAYMENTS_PACKAGE_SCOPE_PREFIX,
    LEGACY_REPORTING_DOMAIN_PREFIXES,
    LEGACY_ZUPAY_HEADER_NAMES,
    WALLET_SECRET_AAD_DOMAIN,
    FORBIDDEN_STATE_ALIASES,
    FORBIDDEN_EVENT_ALIASES,
    FORBIDDEN_EVENT_GLOBS,
    FORBIDDEN_ALIAS_EXCEPTIONS,
    LITERAL_KINDS,
    REPLACEMENT_POLICY,
    COMPATIBILITY_LITERAL_INVENTORY,
    LITERAL_CONSTRUCTION_SITES,
    CANONICAL_VERSION_FOR_PURPOSE,
    CANONICAL_VERSION_V1,
  },
  goldenRefs: [],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "forbidden-terms:packages/node-core/src",
    "forbidden-terms:apps/generic-node/src",
  ],
  sourceDocCitations: [
    "compat-literal-preservation",
    "canonical retained-literal families",
    "forbidden state/event aliases",
    "compatibility routes",
    "signing purposes and domains",
  ],
});
