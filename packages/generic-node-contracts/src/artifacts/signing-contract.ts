/**
 * The node-identity signing contract (A.3 preamble: "signed by the node identity key"; A.3.4:
 * "resolves the declared active node identity key"; A.8-A.9 deterministic keys and negative
 * vectors 10, 18; artifacts freeze).
 *
 * the artifacts reproduction proof CONTRACT_FREEZE: this freezes the node-identity signing contract as data + pure
 * stateless predicates only. There is NO key registry, DB, or private-key material here — the
 * durable node/identity-key registry is the named concern (BUILD_BLOCKED). A caller supplies a resolved
 * key record; these predicates decide acceptance. Rotation lineage, publication, and pinning
 * evidence are the presentation-scope concern/the named concern surfaces.
 */

/** Every expected artifact binds to the node IDENTITY key role. A wallet, device, reporting,
 *  or node-event key can never verify an expected artifact (A.9 negative vector 10). */
export const ARTIFACT_KEY_ROLE = "node_identity" as const;

/** Frozen node-identity key lifecycle states. */
export const NODE_IDENTITY_KEY_STATUSES = ["ACTIVE", "RETIRED", "REVOKED"] as const;
export type NodeIdentityKeyStatus = (typeof NODE_IDENTITY_KEY_STATUSES)[number];

/**
 * Frozen validity rules (the acceptance rule "wrong-purpose or expired keys cannot
 * authorize new activity while frozen historical verification remains possible").
 *
 * - ACTIVE: within its validity interval; authorizes NEW signing AND verifies historical.
 * - RETIRED: rotated out; authorizes NO new signing, but artifacts it signed while it was
 *   valid remain verifiable forever (frozen historical verification).
 * - REVOKED: compromised/withdrawn; its signatures authorize nothing and are not trusted for
 *   verification, even for artifacts dated inside the old validity interval. Revocation is
 *   strictly stronger than retirement.
 *
 * Rotation overlap: an outgoing and an incoming key may both be valid across an overlap window
 * (outgoing `valid_until` >= incoming `valid_from`). An artifact verifies against whichever key
 * covers its signing time; NEW signing is authorized only by an ACTIVE key whose window covers
 * "now".
 */
export const KEY_VALIDITY_RULES = {
  keyRole: ARTIFACT_KEY_ROLE,
  authorizesNewSigning: { ACTIVE: true, RETIRED: false, REVOKED: false },
  verifiesHistorical: { ACTIVE: true, RETIRED: true, REVOKED: false },
  rotationOverlapAllowed: true,
  revocationOverridesInterval: true,
} as const;

/** A resolved node-identity key record, as a registry (the named concern) would hand it to a verifier.
 *  Times are unix milliseconds; `validUntil: null` means open-ended (no scheduled retirement). */
export interface NodeIdentityKeyRecord {
  readonly keyId: string;
  readonly role: string;
  readonly publicKeyB64: string;
  readonly status: NodeIdentityKeyStatus;
  readonly validFromUnixMs: number;
  readonly validUntilUnixMs: number | null;
}

export const KEY_REJECT_REASONS = [
  "wrong_key_role",
  "revoked",
  "retired_cannot_sign_new",
  "not_active_cannot_sign_new",
  "before_valid_from",
  "after_valid_until",
] as const;
export type KeyRejectReason = (typeof KEY_REJECT_REASONS)[number];

export type KeyVerdict = { readonly accepted: true } | { readonly accepted: false; readonly reason: KeyRejectReason };

const accepted: KeyVerdict = { accepted: true };
const rejected = (reason: KeyRejectReason): KeyVerdict => ({ accepted: false, reason });

const coversInstant = (record: NodeIdentityKeyRecord, instantUnixMs: number): KeyVerdict => {
  if (instantUnixMs < record.validFromUnixMs) {
    return rejected("before_valid_from");
  }
  if (record.validUntilUnixMs !== null && instantUnixMs > record.validUntilUnixMs) {
    return rejected("after_valid_until");
  }
  return accepted;
};

/**
 * Pure predicate: may `record` verify an artifact signature dated `signedAtUnixMs`? Enforces
 * key-role (cross-purpose), non-revocation, and validity-window coverage. RETIRED keys still
 * verify historical signatures inside their old window.
 */
export const isKeyAcceptedForVerification = (
  record: NodeIdentityKeyRecord,
  signedAtUnixMs: number,
): KeyVerdict => {
  if (record.role !== ARTIFACT_KEY_ROLE) {
    return rejected("wrong_key_role");
  }
  if (record.status === "REVOKED") {
    return rejected("revoked");
  }
  return coversInstant(record, signedAtUnixMs);
};

/**
 * Pure predicate: may `record` authorize signing a NEW artifact at `nowUnixMs`? Stricter than
 * verification — requires an ACTIVE key whose window covers "now". A RETIRED (rotated-out) or
 * REVOKED key can never authorize new activity.
 */
export const isKeyAcceptedForNewSigning = (
  record: NodeIdentityKeyRecord,
  nowUnixMs: number,
): KeyVerdict => {
  if (record.role !== ARTIFACT_KEY_ROLE) {
    return rejected("wrong_key_role");
  }
  if (record.status === "REVOKED") {
    return rejected("revoked");
  }
  if (record.status === "RETIRED") {
    return rejected("retired_cannot_sign_new");
  }
  if (record.status !== "ACTIVE") {
    return rejected("not_active_cannot_sign_new");
  }
  return coversInstant(record, nowUnixMs);
};

export const SOURCE = "node-identity signing contract A.3, A.3.4, A.8-A.9; artifacts freeze" as const;
