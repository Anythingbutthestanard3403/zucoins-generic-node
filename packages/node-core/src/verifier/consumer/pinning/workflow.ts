// Publish node-key pinning workflow (runtime).
//
// Composes `verifyIdentityPin` / `identityKeyFingerprint` /
// `isSubstitutionProof` with `authenticateArtifact`. Pure and
// I/O-free: discovery fetch and durable pin storage are the product's job.
//
// Boundary (relay-notice wire value):
// node owns identity/rotation evidence + signed expected artifacts
// product owns UI / origin policy / pin distribution / customer UX
// platform-hosted JavaScript is never substitution-proof

import {
  ARTIFACT_KEY_ROLE,
  identityKeyFingerprint,
  isSubstitutionProof,
  verifyIdentityPin,
  type NodeIdentityKeyRecord,
  type NodeIdentityPin,
  type OriginClass,
} from "@zucoins/generic-node-contracts/instruction-origin";

import { authenticateArtifact } from "../verify.js";
import type { NodeVerificationKey } from "../types.js";
import type {
  BootstrapPinInput,
  CachedIdentityPin,
  DiscoveryIdentityWire,
  DiscoveryKeyValidityWire,
  DiscoveryKeyWireEntry,
  PinAndAuthenticateInput,
  PinningVerdict,
} from "./types.js";

/** Default soft-refresh horizon: 7 days. Reaching it never auto-trusts a new key. */
export const DEFAULT_PIN_REFRESH_AFTER_MS = 7 * 24 * 60 * 60 * 1000;

function refuse(
  reason: Extract<PinningVerdict, { ok: false }>["reason"],
  detail?: string,
): PinningVerdict {
  return detail === undefined ? { ok: false, reason } : { ok: false, reason, detail };
}

/**
 * Exact fingerprint algorithm a verifier compares the discovery-served key
 * against the operator's out-of-band pin:
 * lowercase-hex SHA-256 of the UTF-8 bytes of the 44-char padded base64url
 * public-key string (no trailing newline, no normalization).
 *
 * Re-exported under this name so the workflow document and code share one symbol.
 */
export function fingerprintNodeIdentityKey(publicKeyB64: string): string {
  return identityKeyFingerprint(publicKeyB64);
}

/**
 * Bootstrap: record an operator-obtained node identity key as a durable pin.
 * Source channel MUST be independent of hosted ZuPayments (relay-notice wire value). Discovery is
 * NOT the pin's trust anchor — it may be used only to *display* a candidate the
 * operator then confirms out-of-band.
 */
export function bootstrapIdentityPin(
  input: BootstrapPinInput,
  nowUnixMs: number = Date.now(),
  refreshAfterMs: number | null = DEFAULT_PIN_REFRESH_AFTER_MS,
): CachedIdentityPin {
  const pin: NodeIdentityPin = {
    keyId: input.keyId,
    publicKeyB64: input.publicKeyB64,
    fingerprintSha256: fingerprintNodeIdentityKey(input.publicKeyB64),
    validFromUnixMs: input.validFromUnixMs ?? nowUnixMs,
    validUntilUnixMs: input.validUntilUnixMs === undefined ? null : input.validUntilUnixMs,
  };
  return {
    nodeId: input.nodeId,
    pin,
    sourceChannel: input.sourceChannel,
    pinnedAtUnixMs: nowUnixMs,
    refreshAfterUnixMs:
      refreshAfterMs === null ? null : nowUnixMs + refreshAfterMs,
  };
}

function parseRfc3339Ms(value: string): number | null {
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Convert one discovery wire key entry + its top-level validity interval into a
 * `NodeIdentityKeyRecord` for `verifyIdentityPin`. Discovery does not carry
 * lifecycle status; a key still inside its published validity window is treated
 * as ACTIVE for pin compare. Status-bearing rotation evidence (REVOKED/RETIRED)
 * is a separate input when the product has it — see `resolvePinnedKeyFromDiscovery`.
 */
export function discoveryEntryToKeyRecord(
  entry: DiscoveryKeyWireEntry,
  validity: DiscoveryKeyValidityWire,
  status: NodeIdentityKeyRecord["status"] = "ACTIVE",
): NodeIdentityKeyRecord | { readonly error: "invalid_discovery_timestamp" } {
  if (validity.key_id !== entry.key_id) {
    return { error: "invalid_discovery_timestamp" };
  }
  const validFromUnixMs = parseRfc3339Ms(validity.valid_from);
  if (validFromUnixMs === null) return { error: "invalid_discovery_timestamp" };
  let validUntilUnixMs: number | null = null;
  if (validity.valid_until !== null) {
    const until = parseRfc3339Ms(validity.valid_until);
    if (until === null) return { error: "invalid_discovery_timestamp" };
    validUntilUnixMs = until;
  }
  return {
    keyId: entry.key_id,
    role: ARTIFACT_KEY_ROLE,
    publicKeyB64: entry.public_key,
    status,
    validFromUnixMs,
    validUntilUnixMs,
  };
}

/**
 * Independent fingerprint comparison against a discovery document:
 * find the discovery key that matches the pin (by key id), then run
 * `verifyIdentityPin` (key id → pubkey → fingerprint → pin window → acceptance).
 *
 * A discovery key whose id differs from the pin is NOT silently adopted
 * (rotation_unpinned) — re-pin is an explicit operator step.
 */
export function resolvePinnedKeyFromDiscovery(
  cached: CachedIdentityPin,
  discovery: DiscoveryIdentityWire,
  nowUnixMs: number,
): PinningVerdict {
  if (discovery.node_id !== cached.nodeId) {
    return refuse("node_id_mismatch", discovery.node_id);
  }
  const keys = discovery.expected_artifact_public_keys;
  if (keys.length === 0) {
    return refuse("empty_discovery_keys");
  }

  const matches = keys.filter((k) => k.key_id === cached.pin.keyId);
  if (matches.length === 0) {
    // Discovery serves only unpinned keys → rotation without re-pin.
    return refuse(
      "rotation_unpinned",
      `pinned key_id ${cached.pin.keyId} absent from discovery; explicit re-pin required`,
    );
  }
  if (matches.length > 1) {
    return refuse("discovery_key_id_ambiguous", cached.pin.keyId);
  }

  const intervals = discovery.key_validity_intervals.filter(
    (i) => i.key_id === cached.pin.keyId,
  );
  if (intervals.length !== 1) {
    return refuse("invalid_discovery_timestamp");
  }

  const recordOrErr = discoveryEntryToKeyRecord(matches[0]!, intervals[0]!);
  if ("error" in recordOrErr) {
    return refuse("invalid_discovery_timestamp");
  }

  const pinVerdict = verifyIdentityPin(cached.pin, recordOrErr, nowUnixMs);
  if (!pinVerdict.verified) {
    return refuse(pinVerdict.reason);
  }

  const verificationKey: NodeVerificationKey = {
    keyId: cached.pin.keyId,
    publicKey: cached.pin.publicKeyB64,
  };
  return {
    ok: true,
    verificationKey,
    pin: cached.pin,
    // Origin is not decided here — caller supplies it at authenticate time.
    originClass: "node-origin",
    fromCacheOnly: false,
  };
}

/**
 * Stale/offline path: discovery unreachable, but a cached pin exists.
 * Builds a verification key from the cache alone. Does NOT contact the network.
 * Product still must bind origin at authenticate time.
 */
export function resolvePinnedKeyFromCache(
  cached: CachedIdentityPin,
  nowUnixMs: number,
): PinningVerdict {
  // Reconstruct a key record from the pin itself so window/fingerprint checks still run.
  const record: NodeIdentityKeyRecord = {
    keyId: cached.pin.keyId,
    role: ARTIFACT_KEY_ROLE,
    publicKeyB64: cached.pin.publicKeyB64,
    status: "ACTIVE",
    validFromUnixMs: cached.pin.validFromUnixMs,
    validUntilUnixMs: cached.pin.validUntilUnixMs,
  };
  const pinVerdict = verifyIdentityPin(cached.pin, record, nowUnixMs);
  if (!pinVerdict.verified) {
    return refuse(pinVerdict.reason);
  }
  return {
    ok: true,
    verificationKey: {
      keyId: cached.pin.keyId,
      publicKey: cached.pin.publicKeyB64,
    },
    pin: cached.pin,
    originClass: "node-origin",
    fromCacheOnly: true,
  };
}

/**
 * Origin binding: only node-origin or implementer-controlled-origin
 * with a verified independent pin may claim substitution-proof presentation.
 * `platform-hosted` is refused unconditionally — even with a verified pin —
 * because the platform controls the check itself.
 */
export function assertOriginAuthorized(
  originClass: OriginClass,
  pinIndependentlyVerified: boolean,
): PinningVerdict {
  if (originClass === "platform-hosted") {
    return refuse(
      "platform_hosted_not_substitution_proof",
      "platform-hosted JavaScript is never substitution-proof",
    );
  }
  if (!isSubstitutionProof(originClass, pinIndependentlyVerified)) {
    return refuse(
      "origin_not_authorized",
      `originClass=${originClass} pinVerified=${pinIndependentlyVerified}`,
    );
  }
  // Synthetic ok shell — caller discards verificationKey when only checking origin.
  return {
    ok: true,
    verificationKey: { keyId: "", publicKey: "" },
    pin: {
      keyId: "",
      publicKeyB64: "",
      fingerprintSha256: "",
      validFromUnixMs: 0,
      validUntilUnixMs: null,
    },
    originClass,
    fromCacheOnly: false,
  };
}

/**
 * Explicit re-pin after the operator has independently confirmed a new identity
 * key (rotation evidence observed out-of-band). Never call this on a bare
 * discovery fetch alone.
 */
export function repinAfterRotation(
  previous: CachedIdentityPin,
  next: BootstrapPinInput,
  nowUnixMs: number = Date.now(),
  refreshAfterMs: number | null = DEFAULT_PIN_REFRESH_AFTER_MS,
): CachedIdentityPin {
  if (next.nodeId !== previous.nodeId) {
    // Defensive: rotation stays on the same node identity.
    throw new Error(
      `repinAfterRotation: node_id mismatch previous=${previous.nodeId} next=${next.nodeId}`,
    );
  }
  return bootstrapIdentityPin(next, nowUnixMs, refreshAfterMs);
}

/**
 * Soft-refresh signal only. `true` means the product MAY re-fetch discovery for
 * operator review; it never authorizes trusting an unpinned key.
 */
export function pinRefreshDue(cached: CachedIdentityPin, nowUnixMs: number): boolean {
  if (cached.refreshAfterUnixMs === null) return false;
  return nowUnixMs >= cached.refreshAfterUnixMs;
}

/**
 * Full workflow step a product surface runs before presenting a customer
 * instruction:
 * 1. origin class must be authorized (not platform-hosted-only);
 * 2. resolve the pinned key (discovery compare, or cache-only if offline);
 * 3. authenticate the expected artifact under THAT pinned key
 * (`authenticateArtifact` — never a fresh unpinned discovery key).
 */
export function pinAndAuthenticateArtifact(input: PinAndAuthenticateInput): PinningVerdict {
  const originGate = assertOriginAuthorized(input.originClass, true);
  if (!originGate.ok) return originGate;

  let resolved: PinningVerdict;
  if (input.discovery === null) {
    resolved = resolvePinnedKeyFromCache(input.cached, input.nowUnixMs);
  } else {
    resolved = resolvePinnedKeyFromDiscovery(input.cached, input.discovery, input.nowUnixMs);
  }
  if (!resolved.ok) return resolved;

  const verificationKey: NodeVerificationKey = {
    ...resolved.verificationKey,
    liveChain: input.liveChain === true,
  };

  const auth = authenticateArtifact(input.artifact, verificationKey);
  if (!auth.authenticated) {
    return refuse("artifact_not_authenticated", auth.reason);
  }

  return {
    ok: true,
    verificationKey,
    pin: resolved.pin,
    originClass: input.originClass,
    fromCacheOnly: resolved.fromCacheOnly,
  };
}
