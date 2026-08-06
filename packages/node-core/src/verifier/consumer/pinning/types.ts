// node-identity-key pinning workflow types.
//
// Product-neutral runtime shapes for bootstrap → compare → origin bind →
// cache/refresh → rotation/revocation → stale/offline → substitution failure.
// No private keys; no signing; no hosted-platform pin source.

import type {
  NodeIdentityKeyRecord,
  NodeIdentityKeyStatus,
  NodeIdentityPin,
  OriginClass,
  PinRejectReason,
} from "@zucoins/generic-node-contracts/instruction-origin";
import type { ArtifactEnvelope, NodeVerificationKey } from "../types.js";

/** Frozen discovery path. Re-exported for consumer convenience. */
export { DISCOVERY_PATH } from "@zucoins/generic-node-contracts/instruction-origin";

/** Closed origin classes a product surface may declare. */
export type { OriginClass };

/** Implementer pin shape (key id + padded-b64 pubkey + SHA-256 fingerprint + pin window). */
export type { NodeIdentityPin, PinRejectReason, NodeIdentityKeyRecord, NodeIdentityKeyStatus };

/**
 * One public-key entry as returned by `GET /.well-known/zupay-node` (
 * `NodeIdentityDocument.expected_artifact_public_keys`). Validity lives in the
 * top-level `key_validity_intervals` array.
 */
export interface DiscoveryKeyWireEntry {
  readonly key_id: string;
  readonly public_key: string;
}

/** One top-level key validity interval (`key_validity_intervals`). */
export interface DiscoveryKeyValidityWire {
  readonly key_id: string;
  readonly valid_from: string;
  readonly valid_until: string | null;
}

/**
 * Minimal discovery document fields the pinning workflow reads. Full discovery
 * also carries event keys / suites / operations — those are out of scope here
 * (identity-key pin only; node identity keys cannot sign SplitChain inners).
 */
export interface DiscoveryIdentityWire {
  readonly node_id: string;
  readonly expected_artifact_public_keys: readonly DiscoveryKeyWireEntry[];
  readonly key_validity_intervals: readonly DiscoveryKeyValidityWire[];
}

/** How the operator obtained the out-of-band pin (must NOT be hosted ZuPayments). */
export const PIN_SOURCE_CHANNELS = [
  "operator_console_export",
  "node_admin_config",
  "dns_txt",
  "physical_ceremony",
  "other_independent",
] as const;
export type PinSourceChannel = (typeof PIN_SOURCE_CHANNELS)[number];

/**
 * Bootstrap input: operator-held identity material recorded through a channel
 * independent of hosted ZuPayments.
 */
export interface BootstrapPinInput {
  readonly nodeId: string;
  readonly keyId: string;
  /** Canonical padded base64url Ed25519 public key (44 chars including `=`). */
  readonly publicKeyB64: string;
  readonly sourceChannel: PinSourceChannel;
  /** Optional pin validity window (pin bookkeeping — never extended by discovery). */
  readonly validFromUnixMs?: number;
  readonly validUntilUnixMs?: number | null;
}

/** Durable pin cache entry a product may store offline (independent of discovery). */
export interface CachedIdentityPin {
  readonly nodeId: string;
  readonly pin: NodeIdentityPin;
  readonly sourceChannel: PinSourceChannel;
  /** Wall-clock ms when the operator last confirmed / re-pinned this entry. */
  readonly pinnedAtUnixMs: number;
  /**
   * Optional soft refresh hint (ms). Reaching it does NOT invalidate the pin;
   * it only signals the product may re-fetch discovery for operator review.
   * Silent auto-accept of a rotated key is forbidden.
   */
  readonly refreshAfterUnixMs: number | null;
}

/** Closed set of workflow-level refuse reasons. */
export const PINNING_REFUSE_REASONS = [
  "empty_discovery_keys",
  "no_matching_discovery_key",
  "discovery_key_id_ambiguous",
  "invalid_discovery_timestamp",
  "rotation_unpinned",
  "rotation_chain_incoherent",
  "revoked_or_unaccepted",
  "origin_not_authorized",
  "platform_hosted_not_substitution_proof",
  "stale_cache_missing",
  "node_id_mismatch",
  "artifact_not_authenticated",
  "pin_source_not_independent",
  // PinRejectReason values — kept explicit so the closed set is local.
  "key_id_mismatch",
  "pubkey_mismatch",
  "fingerprint_mismatch",
  "pin_not_yet_valid",
  "pin_expired",
  "underlying_key_not_accepted",
] as const;

export type PinningRefuseReason = (typeof PINNING_REFUSE_REASONS)[number];

export type PinningVerdict =
  | {
      readonly ok: true;
      /** Resolved key that matched the pin — use this (not a fresh unpinned discovery key). */
      readonly verificationKey: NodeVerificationKey;
      readonly pin: NodeIdentityPin;
      readonly originClass: OriginClass;
      readonly fromCacheOnly: boolean;
    }
  | {
      readonly ok: false;
      readonly reason: PinningRefuseReason;
      readonly detail?: string;
    };

/**
 * Input to the full pin-and-authenticate step a product surface runs before
 * presenting a customer instruction.
 */
export interface PinAndAuthenticateInput {
  readonly cached: CachedIdentityPin;
  /**
   * Fresh discovery document, or `null` when discovery is unreachable.
   * Offline path uses the cache only (stale/offline behavior).
   */
  readonly discovery: DiscoveryIdentityWire | null;
  readonly originClass: OriginClass;
  /** Expected-artifact envelope to authenticate under the pinned key. */
  readonly artifact: ArtifactEnvelope;
  readonly nowUnixMs: number;
  /** When true, refuse A.8 golden keys (A.9 item 16). Default false. */
  readonly liveChain?: boolean;
}

export type { ArtifactEnvelope, NodeVerificationKey };
