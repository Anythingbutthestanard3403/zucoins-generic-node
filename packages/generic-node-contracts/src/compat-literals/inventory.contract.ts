/**
 * The repository-wide, machine-readable retained-literal audit census `compat-literals.contract.ts`
 * itself does not carry — every retained literal with its exact defining contract, sensitivity, and
 * freeze status.
 *
 * The compat-literals concern does not itself construct or sign any of these literals — construction/signing authority
 * stays with the owning concern (`machineFrozenAt` below), or, for literals that predate the v2
 * redesign entirely, with the existing v1 code that already ships them ("legacy-v1:" citations).
 * Every `literal` field below is IMPORTED from `compat-literals.contract.ts` (this concern's own
 * byte authority) or a sibling concern's module — never retyped — so this table is a
 * read-only richer VIEW over those constants, not a second competing byte authority.
 *
 * DATA ONLY (no functions) — manifest-encoding tier 1.
 */
import type { LiteralKind } from "./kinds.ts";
import {
  RECEIVE_EXPECTED_PURPOSE,
  MOVE_INTERNAL_EXPECTED_PURPOSE,
  SEND_EXTERNAL_EXPECTED_PURPOSE,
  SEND_EXTERNAL_APPROVAL_PURPOSE,
  DESTINATION_BLESS_PURPOSE,
  DEVICE_ENROL_PURPOSE,
  REPORT_REQUEST_PURPOSE,
  NODE_EVENT_PURPOSE,
  WALLET_HEAD_FINGERPRINT_PURPOSE,
  WALLET_SECRET_AAD_DOMAIN,
  REPORTING_REGISTER_PURPOSE,
  ZP1_RECEIVE_MESSAGE_PREFIX,
  TOTP_HEADER_NAME,
  REPORTING_HEADER_NAMES,
  LEGACY_ZUPAY_NODE_HEADER,
  LEGACY_ZUPAY_TIMESTAMP_HEADER,
  LEGACY_ZUPAY_SIGNATURE_HEADER,
  ZUPAY_COMPAT_NAME,
  ZUPAYMENTS_COMPAT_NAME,
  LEGACY_REPORTING_EVENT_DOMAIN,
  LEGACY_REPORTING_TRANSPORT_DOMAIN,
  LEGACY_REPORTING_HANDSHAKE_DOMAIN,
  ZUPAY_NODE_DISCOVERY_PATH,
  ZUPAYMENTS_SDK_ROUTE_PATH,
  ZUPAYMENTS_PACKAGE_SCOPE_PREFIX,
} from "./compat-literals.contract.ts";

export interface CompatibilityLiteralEntry {
  /** The exact retained literal. Comparisons against this value are always exact-string. */
  readonly literal: string;
  readonly kind: LiteralKind;
  /** The contract that defines this literal, as a self-contained description. */
  readonly definingContract: string;
  /**
   * Whether the defining contract treats this literal's exact casing as significant. HTTP header
   * *names* are case-insensitive on the wire (RFC 7230) even where the signed *tuple field
   * values* those headers carry are byte-sensitive — see each header entry's note.
   */
  readonly caseSensitive: boolean;
  /** Whether this literal's exact bytes are hashed, signed, or otherwise cryptographically bound. */
  readonly byteSensitive: boolean;
  /**
   * Where this literal is machine-frozen today: a concern directory in this package,
   * "legacy-v1: <path>" for literals that already ship in existing v1 product code (unowned by
   * any concern here and not to be touched by one), or "docs-only" when no code anywhere has
   * claimed the construction yet.
   */
  readonly machineFrozenAt: string;
  readonly notes?: string;
}

const HEADER_CASE_NOTE =
  "Header NAME case is not wire-significant (RFC 7230); the spelling here is the canonical " +
  "documented/construction casing used at every call site. Case sensitivity binds the signed tuple " +
  "field VALUES the header carries, not the header name.";

/**
 * The complete retained-literal census, repository-wide. Registration sequence is not a
 * frozen fact here (unlike `ZP_V1_PURPOSES`'s canonical section sequence) —
 * `assertClosedSet` governs this array's census test, not `assertFieldOrder`.
 */
export const COMPATIBILITY_LITERAL_INVENTORY: readonly CompatibilityLiteralEntry[] = [
  // --- signed-purpose: the zp-*-v1 suite-construction family ---
  {
    literal: RECEIVE_EXPECTED_PURPOSE,
    kind: "signed-purpose",
    definingContract: "receive-expected signing purpose (canonical suite tuple)",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt:
      "packages/generic-node-contracts/src/artifacts (full field-sequence/shape freeze); this " +
      "module declares the bare purpose string independently, not gated on the artifacts shape freeze",
  },
  {
    literal: MOVE_INTERNAL_EXPECTED_PURPOSE,
    kind: "signed-purpose",
    definingContract: "move-internal-expected signing purpose (canonical suite tuple)",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt:
      "packages/generic-node-contracts/src/artifacts (full field-sequence/shape freeze); this " +
      "module declares the bare purpose string independently, not gated on the artifacts shape freeze",
  },
  {
    literal: SEND_EXTERNAL_EXPECTED_PURPOSE,
    kind: "signed-purpose",
    definingContract: "send-external-expected signing purpose (canonical suite tuple)",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt:
      "packages/generic-node-contracts/src/artifacts (full field-sequence/shape freeze); this " +
      "module declares the bare purpose string independently, not gated on the artifacts shape freeze",
  },
  {
    literal: SEND_EXTERNAL_APPROVAL_PURPOSE,
    kind: "signed-purpose",
    definingContract: "send-external approval signing tuple",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt: "docs-only — no code constructs this signing tuple yet",
  },
  {
    literal: DESTINATION_BLESS_PURPOSE,
    kind: "signed-purpose",
    definingContract: "destination-blessing signing tuple",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt: "docs-only — no code constructs the destination-blessing tuple yet",
  },
  {
    literal: DEVICE_ENROL_PURPOSE,
    kind: "signed-purpose",
    definingContract: "device-enrolment signing tuple",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt: "docs-only — no code constructs the device-enrolment tuple yet",
  },
  {
    literal: REPORT_REQUEST_PURPOSE,
    kind: "signed-purpose",
    definingContract: "reporting request signing tuple",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt: "packages/generic-node-contracts/src/reporting-tuples",
  },
  {
    literal: NODE_EVENT_PURPOSE,
    kind: "signed-purpose",
    definingContract: "signed node-event tuple",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt: "packages/generic-node-contracts/src/reporting-tuples",
  },
  {
    literal: WALLET_HEAD_FINGERPRINT_PURPOSE,
    kind: "signed-purpose",
    definingContract: "wallet-head semantic fingerprint (hashed, not signed)",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt: "docs-only — no code constructs the wallet-head fingerprint yet",
    notes:
      "Uses the same suite serializer + SHA-256 digest as the signed purposes above but is NOT " +
      "Ed25519-signed — a fingerprint, not a signature.",
  },
  {
    literal: WALLET_SECRET_AAD_DOMAIN,
    kind: "signed-purpose",
    definingContract: "vault AEAD associated-data domain",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt: "packages/generic-node-contracts/src/vault",
    notes:
      "An AEAD associated-data (AAD) domain prefix — `zp-wallet-secret-v1\\n<node_id>\\n<wallet_id>\\n" +
      "<key_version>\\n<public_key>\\n<key_origin>` — not an Ed25519-signed purpose. Grouped " +
      "here because it follows the same domain-separated-literal convention this census protects.",
  },
  {
    literal: REPORTING_REGISTER_PURPOSE,
    kind: "signed-purpose",
    definingContract: "reporting-key registration signing tuple",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt: "packages/generic-node-contracts/src/reporting-auth",
    notes:
      "The literal is machine-frozen in reporting-auth's register-tuple.ts, which is the byte " +
      "authority for the tuple's own bytes.",
  },

  // --- wire-prefix: the zp1: on-chain receive-message prefix ---
  {
    literal: ZP1_RECEIVE_MESSAGE_PREFIX,
    kind: "wire-prefix",
    definingContract: "on-chain receive-message prefix",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt: "packages/generic-node-contracts/src/transfer-code",
    notes: 'Construction: "zp1:" + discriminator + ":" + anchor (see construction-sites.contract.ts).',
  },

  // --- header: X-ZP-* family (reporting headers + admin TOTP gate) ---
  {
    literal: TOTP_HEADER_NAME,
    kind: "header",
    definingContract: "admin TOTP gate header",
    caseSensitive: false,
    byteSensitive: false,
    machineFrozenAt:
      "legacy-v1: apps/node/src/auth/totp-gate.ts verifyTotpForMutation primitive, read via " +
      'c.req.header("x-zp-totp") at every money-mutation route; sent via ' +
      "packages/vault-client/src/node-control/node-client.ts",
    notes: HEADER_CASE_NOTE,
  },
  ...REPORTING_HEADER_NAMES.map((header) => ({
    literal: header,
    kind: "header" as const,
    definingContract: "reporting request headers",
    caseSensitive: false,
    byteSensitive: false,
    machineFrozenAt: "packages/generic-node-contracts/src/reporting-tuples — request-tuple.ts",
    notes:
      header === REPORTING_HEADER_NAMES[0]
        ? HEADER_CASE_NOTE + " Selects the reporting-key registration; it is NOT itself a signed field."
        : HEADER_CASE_NOTE,
  })),
  // --- header: legacy X-ZuPay-* transport family (distinct spelling from X-ZP-*) ---
  {
    literal: LEGACY_ZUPAY_NODE_HEADER,
    kind: "header",
    definingContract: "legacy v1 ingest transport headers",
    caseSensitive: false,
    byteSensitive: false,
    machineFrozenAt: "legacy-v1: apps/node/src/reporting/transport-signer.ts INGEST_HEADERS.node",
    notes:
      HEADER_CASE_NOTE +
      " Distinct legacy family: spells the full \"ZuPay\" word, not the \"ZP\" abbreviation — does " +
      'not literally match the "X-ZP-*" clause but is retained under the "zupay" compatibility-' +
      "name clause instead (disjoint from, and unchanged by, the v2 reporting contract).",
  },
  {
    literal: LEGACY_ZUPAY_TIMESTAMP_HEADER,
    kind: "header",
    definingContract: "legacy v1 ingest transport headers",
    caseSensitive: false,
    byteSensitive: false,
    machineFrozenAt: "legacy-v1: apps/node/src/reporting/transport-signer.ts INGEST_HEADERS.timestamp",
    notes: HEADER_CASE_NOTE,
  },
  {
    literal: LEGACY_ZUPAY_SIGNATURE_HEADER,
    kind: "header",
    definingContract: "legacy v1 ingest transport headers",
    caseSensitive: false,
    byteSensitive: false,
    machineFrozenAt: "legacy-v1: apps/node/src/reporting/transport-signer.ts INGEST_HEADERS.signature",
    notes: HEADER_CASE_NOTE,
  },

  // --- name: established zupay/zupayments compatibility names ---
  {
    literal: ZUPAY_COMPAT_NAME,
    kind: "name",
    definingContract: "retained compatibility name",
    caseSensitive: true,
    byteSensitive: false,
    machineFrozenAt: "packages/generic-node-contracts/src/scan/allowlist.d99.ts (this package)",
  },
  {
    literal: ZUPAYMENTS_COMPAT_NAME,
    kind: "name",
    definingContract: "retained compatibility name",
    caseSensitive: true,
    byteSensitive: false,
    machineFrozenAt: "packages/generic-node-contracts/src/scan/allowlist.d99.ts (this package)",
  },
  {
    literal: LEGACY_REPORTING_EVENT_DOMAIN,
    kind: "name",
    definingContract: "legacy v1 per-event ingest signing domain (disjoint from and unchanged by the v2 contract)",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt:
      "legacy-v1: apps/node/src/reporting/envelope.ts REPORTING_PER_EVENT_DOMAIN; " +
      "apps/platform/src/server/ingest/auth-verifier.ts PER_EVENT_PREFIX",
    notes:
      "A legacy Ed25519-signed domain prefix (hashed into the per-event reporting signature) — " +
      'byte/case-sensitive despite being classified "name" (it spells the full "zupay" word per ' +
      "the compatibility-name clause, not the \"zp-*-v1\" purpose clause).",
  },
  {
    literal: LEGACY_REPORTING_TRANSPORT_DOMAIN,
    kind: "name",
    definingContract: "legacy v1 transport ingest signing domain",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt:
      "legacy-v1: apps/node/src/reporting/transport-signer.ts REPORTING_TRANSPORT_DOMAIN; " +
      "apps/platform/src/server/ingest/auth-verifier.ts TRANSPORT_PREFIX",
  },
  {
    literal: LEGACY_REPORTING_HANDSHAKE_DOMAIN,
    kind: "name",
    definingContract: "legacy v1 handshake ingest signing domain",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt:
      "legacy-v1: apps/node/src/reporting/handshake-signer.ts REPORTING_HANDSHAKE_DOMAIN; " +
      "apps/platform/src/nodes/handshake.ts + reporting-test-signer.ts HANDSHAKE_PREFIX",
  },
  {
    literal: ZUPAY_NODE_DISCOVERY_PATH,
    kind: "name",
    definingContract: "retained discovery route path",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt:
      "legacy-v1: apps/node/src/health/routes.ts (route mount); " +
      "apps/platform/src/nodes/handshake.ts WELL_KNOWN_PATH; ALSO re-frozen for v2 in " +
      "packages/generic-node-contracts/src/operations/routes.contract.ts PUBLIC_ROUTES — " +
      "the same literal path, not a second competing spelling.",
    notes: "A route path, not a signed literal — byte-sensitive because router path matching is exact-string.",
  },
  {
    literal: ZUPAYMENTS_SDK_ROUTE_PATH,
    kind: "name",
    definingContract: "retained SDK route path",
    caseSensitive: true,
    byteSensitive: true,
    machineFrozenAt: "legacy-v1: apps/node/src/checkout/sdk-route.ts (route mount)",
  },
  {
    literal: ZUPAYMENTS_PACKAGE_SCOPE_PREFIX,
    kind: "name",
    definingContract: "retained v1 package scope (@zucoins/* v2, @zupayments/* v1, disjoint)",
    caseSensitive: true,
    byteSensitive: false,
    machineFrozenAt:
      "legacy-v1: package.json \"name\" of apps/platform, apps/platform/dashboard, apps/node, " +
      "apps/node/admin, packages/widget, packages/vault-client, packages/splitchain, packages/shared",
    notes:
      "No migration is needed: the generic core lives entirely under the net-new @zucoins/* scope, " +
      "so there is no naming collision to resolve.",
  },
] as const;

/** Every literal string, in inventory registration sequence (for census/allowlist cross-checks). */
export const COMPATIBILITY_LITERAL_VALUES: readonly string[] = COMPATIBILITY_LITERAL_INVENTORY.map(
  (entry) => entry.literal,
);

export const SOURCE = "retained-literal census; forbidden aliases; compat-literal-preservation" as const;
