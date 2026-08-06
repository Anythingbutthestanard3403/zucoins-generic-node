// the reporting-auth register tuple — Reporting-channel key inventory, custody, purpose separation, and the Ed25519-only
// posture (no HMAC / no bearer), plus separation from the legacy platform-ingest push channel.
//
// Governing contract: signing-custody key inventory + purpose separation and signing matrix; the pull-cursor authority decision (two-key
// PULL contract). Canonical: the frozen rule (zero-decryptable-secret custody, the key-custody rule), the artifacts freeze rule/the compatibility-literal preservation rule
// (no reuse/repurpose of frozen legacy bytes).

export interface ReportingKeyClass {
  readonly key: string;
  readonly owner: "node" | "implementer";
  readonly algorithm: "ed25519";
  // What the NODE stores for this key — the load-bearing custody fact (the key-custody rule).
  readonly nodeStores: "public_only" | "private_and_public";
}

// The reporting channel uses exactly TWO Ed25519 keys, each purpose-specific and separate from the
// wallet key and the node identity key. Direction-inverted from the hosted-ingest pattern: the node holds
// only each implementer's reporting PUBLIC key (it cannot and must not hold N implementers' private
// halves); it holds its own event-key private half.
export const REPORTING_KEY_CLASSES = [
  { key: "reporting", owner: "implementer", algorithm: "ed25519", nodeStores: "public_only" },
  { key: "node_event", owner: "node", algorithm: "ed25519", nodeStores: "private_and_public" },
] as const satisfies readonly ReportingKeyClass[];

// Purpose separation. A reporting key may ONLY sign these purposes; the node event key
// only its own. Each key is otherwise cross-purpose-blocked (A.9 #10).
export const REPORTING_KEY_ALLOWED_PURPOSES = [
  "zp-reporting-register-v1",
  "zp-report-request-v1",
] as const;
export const NODE_EVENT_KEY_ALLOWED_PURPOSES = ["zp-node-event-v1"] as const;

// Purposes and material a reporting/event key must NEVER sign — the wallet, node-identity, and
// device-key surfaces. Kept as data so a future edit cannot silently grant cross-purpose authority.
export const REPORTING_CROSS_PURPOSE_FORBIDDEN = [
  "splitchain-inner",
  "zp-receive-expected-v1",
  "zp-move-internal-expected-v1",
  "zp-send-external-expected-v1",
  "zp-send-external-approval-v1",
  "zp-destination-bless-v1",
  "zp-device-enrol-v1",
] as const;

// Ed25519-only on the signed reporting channel. The acceptance criterion is "HMAC and bearer
// fallbacks are absent unless explicitly frozen" — they are not frozen, so they are forbidden.
export const ALLOWED_CREDENTIAL_MECHANISMS = ["ed25519_signed_tuple"] as const;
export const FORBIDDEN_CREDENTIAL_MECHANISMS = [
  "hmac",
  "bearer_ik",
  "bearer_sh",
  "basic",
  "cookie_session",
] as const;

// Separation from existing platform-ingest reporting (the pull-cursor authority rule/the artifacts freeze rule/the compatibility-literal preservation rule): the v2 pull channel uses
// NEW versioned purposes and must NOT emit the frozen legacy push-channel bytes, which stay owned
// by and unchanged for the legacy platform-ingest path.
export const V2_REPORTING_PURPOSES = [
  "zp-reporting-register-v1",
  "zp-report-request-v1",
  "zp-node-event-v1",
] as const;
export const LEGACY_PUSH_PURPOSES = [
  "zupay-reporting-v1",
  "zupay-reporting-transport-v1",
  "zupay-reporting-handshake-v1",
] as const;

// The complete frozen Ed25519 torsion deny-list. These are compressed-point bytes,
// expressed as lowercase hex so the zero-dependency contract can reject them before delegating
// full point validation to the runtime's injected curve implementation.
export const ED25519_SMALL_ORDER_ENCODINGS_HEX = Object.freeze([
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
] as const);
