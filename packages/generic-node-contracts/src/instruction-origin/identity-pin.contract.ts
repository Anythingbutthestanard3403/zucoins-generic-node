/**
 * The node-identity pin contract (API discovery; key rotation; instruction-origin identity;
 * artifacts freeze).
 *
 * the presentation-scope concern.1 CONTRACT_FREEZE: freezes (1) the shape of what the node PUBLISHES about its identity
 * key — discovery plus the rotation/revocation evidence chain — and (2) the shape of what an
 * implementer independently PINS, plus a pure predicate binding the two. This is data + pure
 * predicates only; there is no discovery server, no durable key registry, and no private key
 * material here. `NodeIdentityKeyStatus`, `NodeIdentityKeyRecord`, and the acceptance predicates
 * are the artifacts concern's (`../artifacts/signing-contract.ts`) and are imported, never redeclared — the
 * durable node/identity-key registry itself remains the named concern (BUILD_BLOCKED).
 *
 * Threat model this defeats (the implementer-controlled-origin model): a compromised hosted platform can present
 * ANY key as "the node's key" and even make it pass ordinary acceptance checks (e.g. by
 * publishing its own attacker key as ACTIVE through a channel it controls). `verifyIdentityPin`
 * closes that hole by requiring the presented key to equal one the implementer already pinned
 * through a channel independent of the platform — a substituted-but-otherwise-valid key is
 * rejected on `key_id_mismatch`/`pubkey_mismatch` before acceptance is even considered.
 */
import {
  isKeyAcceptedForVerification,
  type NodeIdentityKeyRecord,
  type NodeIdentityKeyStatus,
} from "../artifacts/signing-contract.ts";
import { sha256Hex, utf8Bytes } from "./identity-key-hash.ts";

/** Discovery path frozen by the API contract; matches the entry already frozen in
 *  operations/routes.contract.ts and route-policy/routes.ts (`GET`, public, no auth). Cited
 *  here as a plain literal, not re-declared as a route — the generic-core scan concern/the auth-errors/route-policy concern own the route catalog.*/
export const DISCOVERY_PATH = "/.well-known/zupay-node" as const;

/** One entry in the node's published rotation/revocation evidence chain — structurally
 *  identical to a resolved `NodeIdentityKeyRecord` (the artifacts concern), because discovery publishes
 *  exactly the fields a verifier resolves a key from, plus `supersedesKeyId`: the Appendix A
 *  `supersedes_key_id` linkage (UUID of the key this entry rotates, or `null` at bootstrap)
 *  — minimal revocation-chain evidence only; the durable revocation record is the named concern territory.*/
export interface PublishedIdentityKeyEntry {
  readonly keyId: string;
  readonly publicKeyB64: string;
  readonly status: NodeIdentityKeyStatus;
  readonly validFromUnixMs: number;
  readonly validUntilUnixMs: number | null;
  readonly supersedesKeyId: string | null;
}

/**
 * What the node publishes about its identity key: the node identifier,
 * the discovery path it is published at, and the full rotation evidence chain. The chain is
 * append-only and non-decreasing in `validFromUnixMs` — historical entries are never pruned or
 * reordered, matching the artifacts concern's `KEY_VALIDITY_RULES.verifiesHistorical` (a RETIRED key's past
 * signatures must remain independently verifiable forever). Discovery is NOT itself a trust
 * anchor: a consumer treats it only as key delivery, never as the pin's source.
 */
export interface NodePublishedIdentity {
  readonly nodeId: string;
  readonly discoveryPath: string;
  readonly rotationEvidenceChain: readonly PublishedIdentityKeyEntry[];
}

/** True iff `chain` is non-decreasing in `validFromUnixMs` (append-only rotation sequence). */
export const isRotationEvidenceChainMonotonic = (chain: readonly PublishedIdentityKeyEntry[]): boolean =>
  chain.every((entry, i) => i === 0 || chain[i - 1].validFromUnixMs <= entry.validFromUnixMs);

/** True iff `chain` is monotonic AND every entry's `supersedesKeyId` correctly links the
 *  rotation chain: the first (bootstrap) entry has `supersedesKeyId === null`, and every
 *  later entry's `supersedesKeyId` equals the immediately preceding entry's `keyId`. Minimal
 *  coherence check only — no richer revocation record (the named concern territory).*/
export const isRotationEvidenceChainCoherent = (chain: readonly PublishedIdentityKeyEntry[]): boolean =>
  isRotationEvidenceChainMonotonic(chain) &&
  chain.every((entry, i) =>
    i === 0 ? entry.supersedesKeyId === null : entry.supersedesKeyId === chain[i - 1].keyId,
  );

/**
 * Lowercase hex SHA-256 of the exact UTF-8 bytes of a 44-char padded base64 public-key string
 * (no trailing newline). An independent identity binding a pin asserts alongside the raw key
 * id/pubkey compare (fingerprint hardening): even if a raw-string compare were
 * ever bypassed by an encoding-normalization bug, the recomputed digest still catches a
 * byte-level substitution.
 */
export const identityKeyFingerprint = (publicKeyB64: string): string => sha256Hex(utf8Bytes(publicKeyB64));

/**
 * An implementer's independently-established pin of the node identity key (Q7 option 2): the
 * key id and public key the implementer trusts through a channel the hosted platform does not
 * control, plus the validity window the implementer's own pin record asserts. This window is
 * the PIN's bookkeeping, checked against — but never substituted for — the resolved key
 * record's own operational validity (`NodeIdentityKeyRecord`), so a pin cannot be silently
 * extended by anything the platform presents. `fingerprintSha256` is the pin's independently
 * recorded `identityKeyFingerprint` of `publicKeyB64`, re-verified against the resolved key.
 */
export interface NodeIdentityPin {
  readonly keyId: string;
  readonly publicKeyB64: string;
  readonly fingerprintSha256: string;
  readonly validFromUnixMs: number;
  readonly validUntilUnixMs: number | null;
}

export const PIN_REJECT_REASONS = [
  "key_id_mismatch",
  "pubkey_mismatch",
  "fingerprint_mismatch",
  "pin_not_yet_valid",
  "pin_expired",
  "underlying_key_not_accepted",
] as const;
export type PinRejectReason = (typeof PIN_REJECT_REASONS)[number];

export type PinVerdict =
  | { readonly verified: true }
  | { readonly verified: false; readonly reason: PinRejectReason };

const rejectPin = (reason: PinRejectReason): PinVerdict => ({ verified: false, reason });

/**
 * Pure predicate: does `resolvedKey` (whatever the implementer's presentation surface currently
 * resolves the node identity key to be — e.g. from discovery) match `pin` (the implementer's
 * independently-established expectation), AND is `resolvedKey` itself accepted for verification
 * right now (the artifacts concern `isKeyAcceptedForVerification`, imported — never re-derived here)?
 *
 * Sequence matters: the pin-identity comparison (key id, pubkey, fingerprint) runs FIRST and
 * fails closed on any mismatch, before delegating to the artifacts concern's acceptance check — a substituted
 * key that would otherwise pass acceptance (e.g. an attacker's own ACTIVE key) is caught here,
 * not there.
 */
export const verifyIdentityPin = (
  pin: NodeIdentityPin,
  resolvedKey: NodeIdentityKeyRecord,
  nowUnixMs: number,
): PinVerdict => {
  if (pin.keyId !== resolvedKey.keyId) {
    return rejectPin("key_id_mismatch");
  }
  if (pin.publicKeyB64 !== resolvedKey.publicKeyB64) {
    return rejectPin("pubkey_mismatch");
  }
  if (pin.fingerprintSha256 !== identityKeyFingerprint(resolvedKey.publicKeyB64)) {
    return rejectPin("fingerprint_mismatch");
  }
  if (nowUnixMs < pin.validFromUnixMs) {
    return rejectPin("pin_not_yet_valid");
  }
  if (pin.validUntilUnixMs !== null && nowUnixMs > pin.validUntilUnixMs) {
    return rejectPin("pin_expired");
  }
  const keyVerdict = isKeyAcceptedForVerification(resolvedKey, nowUnixMs);
  if (!keyVerdict.accepted) {
    return rejectPin("underlying_key_not_accepted");
  }
  return { verified: true };
};

export const SOURCE = "identity-pin contract; instruction-origin-identity; artifacts-freeze" as const;
