import { REPORT_REQUEST_PURPOSE, REPORTING_REQUEST_HEADERS } from "../reporting-tuples/request-tuple.ts";
import { NODE_EVENT_PURPOSE } from "../reporting-tuples/event-tuple.ts";
import { REPORTING_REGISTER_PURPOSE } from "../reporting-auth/register-tuple.ts";
import { RECEIVE_MESSAGE_PREFIX } from "../transfer-code/transfer-code.contract.ts";
import { AAD_DOMAIN as WALLET_SECRET_AAD_DOMAIN } from "../vault/aad.contract.ts";

/**
 * Compatibility-literal preservation: the generic node never renames established `zp-*-v1`
 * signed purposes, the `zp1:` receive-message prefix, `X-ZP-*` headers, or established
 * compatibility names. Three of the ten purposes below (the two reporting tuples and the
 * node-event purpose), the five `X-ZP-Reporting-*` header names, the `zp1:` prefix, and the
 * `zp-wallet-secret-v1` AAD domain already have a byte-authoritative home in sibling concerns
 * (reporting-tuples, reporting-auth, transfer-code, vault) — imported here, not retyped, so
 * this module is never a second source of truth for those bytes. The remaining purposes, the
 * `X-ZP-TOTP` header, and the legacy `X-ZuPay-*`/`zupay-reporting-*-v1`/route/package-scope
 * names (byte-verified against the live v1 source files that still ship them) have no other
 * frozen home; this module is their first freeze.
 */

// Expected-artifact purposes. The artifacts concern owns the full field-sequence/shape freeze
// for these three; the bare purpose strings are frozen here independently under the
// compatibility-literal preservation rule.
export const RECEIVE_EXPECTED_PURPOSE = "zp-receive-expected-v1" as const;
export const MOVE_INTERNAL_EXPECTED_PURPOSE = "zp-move-internal-expected-v1" as const;
export const SEND_EXTERNAL_EXPECTED_PURPOSE = "zp-send-external-expected-v1" as const;

// Approval and custody tuples. Not frozen as named constants anywhere else.
export const SEND_EXTERNAL_APPROVAL_PURPOSE = "zp-send-external-approval-v1" as const;
export const DESTINATION_BLESS_PURPOSE = "zp-destination-bless-v1" as const;
export const DEVICE_ENROL_PURPOSE = "zp-device-enrol-v1" as const;

// Reporting request and reporting-key registration. Byte authority lives in the reporting
// concerns; re-exported here under their existing names.
export { REPORT_REQUEST_PURPOSE, REPORTING_REGISTER_PURPOSE };

// Neutral node event. Byte authority lives in reporting-tuples.
export { NODE_EVENT_PURPOSE };

// Wallet-head semantic fingerprint. The one member of the family that is hashed, not
// signed. Not frozen as a named constant anywhere else.
export const WALLET_HEAD_FINGERPRINT_PURPOSE = "zp-wallet-head-fingerprint-v1" as const;

/** The full `zp-*-v1` purpose family, in canonical declaration sequence. */
export const ZP_V1_PURPOSES = [
  RECEIVE_EXPECTED_PURPOSE,
  MOVE_INTERNAL_EXPECTED_PURPOSE,
  SEND_EXTERNAL_EXPECTED_PURPOSE,
  SEND_EXTERNAL_APPROVAL_PURPOSE,
  DESTINATION_BLESS_PURPOSE,
  DEVICE_ENROL_PURPOSE,
  REPORT_REQUEST_PURPOSE,
  REPORTING_REGISTER_PURPOSE,
  NODE_EVENT_PURPOSE,
  WALLET_HEAD_FINGERPRINT_PURPOSE,
] as const;

export type ZpV1Purpose = (typeof ZP_V1_PURPOSES)[number];

/**
 * Receive message — the exact signed SplitChain message is `"zp1:" + discriminator + ":"
 * + anchor`. The transfer-code concern owns this exact byte as `RECEIVE_MESSAGE_PREFIX` —
 * re-exported here under this module's own name rather than retyped, so this is never a
 * second source of truth. The pattern description documents the construction without
 * inventing a parser this package does not own.
 */
export const ZP1_RECEIVE_MESSAGE_PREFIX = RECEIVE_MESSAGE_PREFIX;
export const ZP1_RECEIVE_MESSAGE_PATTERN_DESCRIPTION = "zp1:<discriminator>:<anchor>" as const;

/**
 * The `X-ZP-*` header family. The five reporting headers already have a byte-authoritative home
 * (reporting-tuples' `REPORTING_REQUEST_HEADERS`) — derived here via `.map`, never retyped,
 * so a header rename there is a single edit, not two. `X-ZP-TOTP` (the admin TOTP gate header)
 * has no other frozen home yet.
 */
export const REPORTING_HEADER_NAMES = REPORTING_REQUEST_HEADERS.map((entry) => entry.header);

export const TOTP_HEADER_NAME = "X-ZP-TOTP" as const;

export const ZP_HEADER_FAMILY = [...REPORTING_HEADER_NAMES, TOTP_HEADER_NAME] as const;

/**
 * Established `zupay`/`zupayments` compatibility names. The discovery route
 * path itself is not exported as a standalone constant by `operations/routes.contract.ts` (it is
 * only embedded in a `RouteEntry` inside `PUBLIC_ROUTES`), so it is redeclared here; the census
 * test asserts equality against the live `PUBLIC_ROUTES` entry so the two can never drift
 * silently.
 */
export const ZUPAY_COMPAT_NAME = "zupay" as const;
export const ZUPAYMENTS_COMPAT_NAME = "zupayments" as const;
export const ZUPAY_NODE_DISCOVERY_PATH = "/.well-known/zupay-node" as const;

/**
 * Established `zupay`/`zupayments` compatibility surface, byte-verified against the live v1
 * route-mount site each literal still ships from (`apps/node/src/checkout/sdk-route.ts`,
 * package.json `name` fields under the unchanged `@zupayments/*` v1 scope — `@zucoins/*` is
 * the disjoint v2 scope, so there is no collision to resolve).
 */
export const ZUPAYMENTS_SDK_ROUTE_PATH = "/sdk/zupayments.js" as const;
export const ZUPAYMENTS_PACKAGE_SCOPE_PREFIX = "@zupayments/" as const;

/**
 * The legacy `zupay-reporting-*-v1` signed domain-prefix family — pre-existing v1
 * platform-ingest push-path signatures, explicitly disjoint from and unchanged by the v2
 * `zp-*-v1` reporting contract (the v2 contract does NOT emit the frozen
 * `zupay-reporting-v1`/`-transport-v1`/`-handshake-v1` bytes: no in-place rewrite, no
 * repurpose). Retained under the `zupay`/`zupayments` compatibility-name clause, not the
 * `zp-*-v1` purpose clause — kept out of `ZP_V1_PURPOSES` for exactly that reason. Still
 * shipping, byte-verified against the live v1 source: `apps/node/src/reporting/
 * envelope.ts` (REPORTING_PER_EVENT_DOMAIN), `transport-signer.ts`
 * (REPORTING_TRANSPORT_DOMAIN), `handshake-signer.ts` (REPORTING_HANDSHAKE_DOMAIN), and their
 * `apps/platform/src/server/ingest/auth-verifier.ts` / `apps/platform/src/nodes/handshake.ts`
 * counterparts.
 */
export const LEGACY_REPORTING_EVENT_DOMAIN = "zupay-reporting-v1" as const;
export const LEGACY_REPORTING_TRANSPORT_DOMAIN = "zupay-reporting-transport-v1" as const;
export const LEGACY_REPORTING_HANDSHAKE_DOMAIN = "zupay-reporting-handshake-v1" as const;

export const LEGACY_REPORTING_DOMAIN_PREFIXES = [
  LEGACY_REPORTING_EVENT_DOMAIN,
  LEGACY_REPORTING_TRANSPORT_DOMAIN,
  LEGACY_REPORTING_HANDSHAKE_DOMAIN,
] as const;

/**
 * The legacy `X-ZuPay-*` transport-header family — spells the full "ZuPay" word, distinct
 * from the `X-ZP-*` abbreviation the v2 reporting contract uses, but retained under the
 * `zupay`/`zupayments` compatibility-name clause rather than the `X-ZP-*` clause.
 * Byte-verified against `apps/node/src/reporting/transport-signer.ts` `INGEST_HEADERS`.
 */
export const LEGACY_ZUPAY_NODE_HEADER = "X-ZuPay-Node" as const;
export const LEGACY_ZUPAY_TIMESTAMP_HEADER = "X-ZuPay-Timestamp" as const;
export const LEGACY_ZUPAY_SIGNATURE_HEADER = "X-ZuPay-Signature" as const;

export const LEGACY_ZUPAY_HEADER_NAMES = [
  LEGACY_ZUPAY_NODE_HEADER,
  LEGACY_ZUPAY_TIMESTAMP_HEADER,
  LEGACY_ZUPAY_SIGNATURE_HEADER,
] as const;

/**
 * `zp-wallet-secret-v1`, the vault AEAD associated-data domain prefix. Not an
 * Ed25519-signed purpose — grouped with the `zp-*-v1` family only insofar as it follows the
 * same domain-separated-literal convention compatibility-literal preservation protects;
 * deliberately kept OUT of `ZP_V1_PURPOSES` (that array is the signed/hashed suite-tuple
 * purpose family specifically). Byte authority is `vault/aad.contract.ts` — imported here,
 * not retyped.
 */
export { WALLET_SECRET_AAD_DOMAIN };

export const SOURCE = "canonical retained-literal families; compatibility routes; compat-literal-preservation" as const;
