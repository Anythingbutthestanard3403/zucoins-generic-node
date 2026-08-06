// node-key pinning workflow tests.
//
// Cases covered:
// - bootstrap via independent channel
// fingerprint comparison against verifier (pinned key, not unpinned discovery)
// - rotation does not silently accept unpinned key
// - stale/offline cache still authenticates
// - substitution failure: attacker key / platform-hosted refused
// relay-notice wire value boundary stated in workflow doc (separate file)
//
// Negative-path assertions required: substitution + rotation_unpinned at minimum.
import { Buffer } from "node:buffer";
import { createHash, generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";

import { buildReceiveExpectedArtifact } from "../../../protocol/suite/builders.js";
import {
  parseEd25519Signature,
  parseSha256Hex,
  parseUuid,
  parseWalletPublicKey,
} from "../../../protocol/scalars.js";
import { parsePositiveZkzAmount } from "../../../protocol/amounts.js";
import type { ArtifactEnvelope } from "../types.js";
import {
  DEFAULT_PIN_REFRESH_AFTER_MS,
  DISCOVERY_PATH,
  PINNING_REFUSE_REASONS,
  PIN_SOURCE_CHANNELS,
  assertOriginAuthorized,
  bootstrapIdentityPin,
  fingerprintNodeIdentityKey,
  pinAndAuthenticateArtifact,
  pinRefreshDue,
  repinAfterRotation,
  resolvePinnedKeyFromCache,
  resolvePinnedKeyFromDiscovery,
  type CachedIdentityPin,
  type DiscoveryIdentityWire,
} from "./index.js";

// --- test key material (NOT A.8 golden seeds) --------------------------------

function ed25519Pair(): { publicKeyB64: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(12);
  return {
    publicKeyB64: Buffer.from(raw).toString("base64url") + "=",
    privateKey,
  };
}

const NODE = ed25519Pair();
const ATTACKER = ed25519Pair();

const NODE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const KEY_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const ATTACKER_KEY_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const NOW = 1_700_000_000_000;

// A separate wallet pubkey so the node identity key is not also used as a wallet.
const RECEIVER_WALLET = ed25519Pair().publicKeyB64;

function signPreimage(preimageBytes: Uint8Array, priv: KeyObject): string {
  const sig = edSign(null, Buffer.from(preimageBytes), priv);
  return sig.toString("base64url") + "==";
}

function buildArtifact(amount: string, signer: typeof NODE): ArtifactEnvelope {
  const preimage = buildReceiveExpectedArtifact({
    node_id: parseUuid(NODE_ID),
    implementer_id: parseUuid("44444444-4444-4444-8444-444444444444"),
    operation_id: parseUuid("55555555-5555-4555-8555-555555555555"),
    receiver_wallet_id: parseUuid("66666666-6666-4666-8666-666666666666"),
    receiver_pubkey: parseWalletPublicKey(RECEIVER_WALLET),
    amount_zkz: parsePositiveZkzAmount(amount),
    discriminator: parseUuid("77777777-7777-4777-8777-777777777777"),
    anchor: "zp1-anchor-test",
    receiver_t0_fingerprint: parseSha256Hex("a".repeat(64)),
    expiry_unix_time_secs: null,
    after_landing: { kind: "HOLD", destination_id: null },
    transfer_code_sha256: parseSha256Hex("b".repeat(64)),
  });
  return {
    key_id: parseUuid(KEY_ID),
    preimage_text: preimage.preimageText,
    preimage_sha256: parseSha256Hex(preimage.sha256 as string),
    signature: parseEd25519Signature(signPreimage(preimage.preimageBytes, signer.privateKey)),
  };
}

function discoveryFor(
  entries: Array<{ keyId: string; publicKeyB64: string; from?: string; until?: string | null }>,
  nodeId: string = NODE_ID,
): DiscoveryIdentityWire {
  return {
    node_id: nodeId,
    expected_artifact_public_keys: entries.map((e) => ({
      key_id: e.keyId,
      public_key: e.publicKeyB64,
    })),
    key_validity_intervals: entries.map((e) => ({
      key_id: e.keyId,
      valid_from: e.from ?? new Date(NOW - 60_000).toISOString(),
      valid_until: e.until === undefined ? null : e.until,
    })),
  };
}

function bootstrapGenuine(now: number = NOW): CachedIdentityPin {
  return bootstrapIdentityPin(
    {
      nodeId: NODE_ID,
      keyId: KEY_ID,
      publicKeyB64: NODE.publicKeyB64,
      sourceChannel: "operator_console_export",
    },
    now,
  );
}

// --- fingerprint algorithm ---------------------------------------------------

describe("fingerprint algorithm (exact bytes)", () => {
  it("is lowercase-hex SHA-256 of UTF-8 padded base64url pubkey (no newline)", () => {
    const expected = createHash("sha256").update(NODE.publicKeyB64, "utf8").digest("hex");
    expect(fingerprintNodeIdentityKey(NODE.publicKeyB64)).toBe(expected);
    expect(expected).toMatch(/^[0-9a-f]{64}$/);
  });

  it("differs for a single-byte pubkey substitution", () => {
    expect(fingerprintNodeIdentityKey(NODE.publicKeyB64)).not.toBe(
      fingerprintNodeIdentityKey(ATTACKER.publicKeyB64),
    );
  });

  it("DISCOVERY_PATH is the frozen compatibility-literal allowlist literal", () => {
    expect(DISCOVERY_PATH).toBe("/.well-known/zupay-node");
  });

  it("PINNING_REFUSE_REASONS is a closed non-empty set", () => {
    expect(PINNING_REFUSE_REASONS.length).toBeGreaterThan(10);
    expect(new Set(PINNING_REFUSE_REASONS).size).toBe(PINNING_REFUSE_REASONS.length);
  });

  it("PIN_SOURCE_CHANNELS excludes any hosted-platform channel", () => {
    for (const ch of PIN_SOURCE_CHANNELS) {
      expect(ch).not.toMatch(/platform|zupayments|hosted/i);
    }
  });
});

// --- bootstrap ---------------------------------------------------------------

describe("bootstrap (independent channel)", () => {
  it("records pin with fingerprint and soft-refresh horizon", () => {
    const cached = bootstrapGenuine();
    expect(cached.nodeId).toBe(NODE_ID);
    expect(cached.pin.keyId).toBe(KEY_ID);
    expect(cached.pin.publicKeyB64).toBe(NODE.publicKeyB64);
    expect(cached.pin.fingerprintSha256).toBe(fingerprintNodeIdentityKey(NODE.publicKeyB64));
    expect(cached.sourceChannel).toBe("operator_console_export");
    expect(cached.pinnedAtUnixMs).toBe(NOW);
    expect(cached.refreshAfterUnixMs).toBe(NOW + DEFAULT_PIN_REFRESH_AFTER_MS);
  });

  it("pinRefreshDue is soft-only (does not invalidate)", () => {
    const cached = bootstrapGenuine();
    expect(pinRefreshDue(cached, NOW)).toBe(false);
    expect(pinRefreshDue(cached, NOW + DEFAULT_PIN_REFRESH_AFTER_MS)).toBe(true);
    // Even when refresh is due, cache resolution still succeeds.
    expect(resolvePinnedKeyFromCache(cached, NOW + DEFAULT_PIN_REFRESH_AFTER_MS).ok).toBe(true);
  });
});

// --- discovery compare (pinned key, not unpinned) ----------------------------

describe("independent fingerprint comparison via discovery", () => {
  it("accepts discovery key that matches the out-of-band pin", () => {
    const cached = bootstrapGenuine();
    const discovery = discoveryFor([{ keyId: KEY_ID, publicKeyB64: NODE.publicKeyB64 }]);
    const verdict = resolvePinnedKeyFromDiscovery(cached, discovery, NOW);
    expect(verdict.ok).toBe(true);
    if (!verdict.ok) return;
    expect(verdict.verificationKey.keyId).toBe(KEY_ID);
    expect(verdict.verificationKey.publicKey).toBe(NODE.publicKeyB64);
    expect(verdict.fromCacheOnly).toBe(false);
  });

  it("rejects pubkey substitution under the same key id", () => {
    const cached = bootstrapGenuine();
    const discovery = discoveryFor([{ keyId: KEY_ID, publicKeyB64: ATTACKER.publicKeyB64 }]);
    expect(resolvePinnedKeyFromDiscovery(cached, discovery, NOW)).toEqual({
      ok: false,
      reason: "pubkey_mismatch",
    });
  });

  it("rejects node_id mismatch between cache and discovery", () => {
    const cached = bootstrapGenuine();
    const discovery = discoveryFor(
      [{ keyId: KEY_ID, publicKeyB64: NODE.publicKeyB64 }],
      "99999999-9999-4999-8999-999999999999",
    );
    expect(resolvePinnedKeyFromDiscovery(cached, discovery, NOW).ok).toBe(false);
    if (resolvePinnedKeyFromDiscovery(cached, discovery, NOW).ok) return;
    expect(resolvePinnedKeyFromDiscovery(cached, discovery, NOW)).toMatchObject({
      reason: "node_id_mismatch",
    });
  });
});

// --- rotation / revocation ---------------------------------------------------

describe("rotation does not silently trust an unpinned key", () => {
  it("rotation_unpinned when discovery drops the pinned key_id", () => {
    const cached = bootstrapGenuine();
    const rotated = discoveryFor([
      { keyId: ATTACKER_KEY_ID, publicKeyB64: ATTACKER.publicKeyB64 },
    ]);
    const verdict = resolvePinnedKeyFromDiscovery(cached, rotated, NOW);
    expect(verdict).toEqual({
      ok: false,
      reason: "rotation_unpinned",
      detail: expect.stringContaining(KEY_ID),
    });
  });

  it("explicit repinAfterRotation adopts the new key only after operator step", () => {
    const previous = bootstrapGenuine();
    const next = repinAfterRotation(
      previous,
      {
        nodeId: NODE_ID,
        keyId: ATTACKER_KEY_ID,
        publicKeyB64: ATTACKER.publicKeyB64,
        sourceChannel: "physical_ceremony",
      },
      NOW + 1_000,
    );
    expect(next.pin.keyId).toBe(ATTACKER_KEY_ID);
    expect(next.pin.publicKeyB64).toBe(ATTACKER.publicKeyB64);
    const discovery = discoveryFor([
      { keyId: ATTACKER_KEY_ID, publicKeyB64: ATTACKER.publicKeyB64 },
    ]);
    expect(resolvePinnedKeyFromDiscovery(next, discovery, NOW + 1_000).ok).toBe(true);
  });

  it("repinAfterRotation refuses a different node_id", () => {
    const previous = bootstrapGenuine();
    expect(() =>
      repinAfterRotation(previous, {
        nodeId: "99999999-9999-4999-8999-999999999999",
        keyId: ATTACKER_KEY_ID,
        publicKeyB64: ATTACKER.publicKeyB64,
        sourceChannel: "physical_ceremony",
      }),
    ).toThrow(/node_id mismatch/);
  });
});

// --- stale / offline ---------------------------------------------------------

describe("stale/offline: discovery unreachable, cached pin still verifies", () => {
  it("resolvePinnedKeyFromCache succeeds without discovery", () => {
    const cached = bootstrapGenuine();
    const verdict = resolvePinnedKeyFromCache(cached, NOW);
    expect(verdict.ok).toBe(true);
    if (!verdict.ok) return;
    expect(verdict.fromCacheOnly).toBe(true);
    expect(verdict.verificationKey.publicKey).toBe(NODE.publicKeyB64);
  });

  it("pinAndAuthenticateArtifact with discovery=null authenticates under cached pin", () => {
    const cached = bootstrapGenuine();
    const artifact = buildArtifact("1", NODE);
    // Force artifact key_id to match pin (builders may use different uuid parsing form).
    const envelope: ArtifactEnvelope = {
      ...artifact,
      key_id: parseUuid(KEY_ID),
    };
    const verdict = pinAndAuthenticateArtifact({
      cached,
      discovery: null,
      originClass: "node-origin",
      artifact: envelope,
      nowUnixMs: NOW,
    });
    expect(verdict.ok).toBe(true);
    if (!verdict.ok) return;
    expect(verdict.fromCacheOnly).toBe(true);
  });

  it("stale expired pin is refused even offline", () => {
    const cached = bootstrapIdentityPin(
      {
        nodeId: NODE_ID,
        keyId: KEY_ID,
        publicKeyB64: NODE.publicKeyB64,
        sourceChannel: "node_admin_config",
        validFromUnixMs: NOW - 10_000,
        validUntilUnixMs: NOW - 1,
      },
      NOW - 5_000,
    );
    expect(resolvePinnedKeyFromCache(cached, NOW)).toEqual({
      ok: false,
      reason: "pin_expired",
    });
  });
});

// --- origin binding ----------------------------------------------------------

describe("origin binding", () => {
  it("node-origin + verified pin is authorized", () => {
    expect(assertOriginAuthorized("node-origin", true).ok).toBe(true);
  });

  it("implementer-controlled-origin + verified pin is authorized", () => {
    expect(assertOriginAuthorized("implementer-controlled-origin", true).ok).toBe(true);
  });

  it("platform-hosted is refused even with a verified pin", () => {
    expect(assertOriginAuthorized("platform-hosted", true)).toEqual({
      ok: false,
      reason: "platform_hosted_not_substitution_proof",
      detail: expect.stringContaining("never substitution-proof"),
    });
  });

  it("node-origin without pin is not authorized", () => {
    expect(assertOriginAuthorized("node-origin", false).ok).toBe(false);
  });
});

// --- substitution failure (security-critical) ---------------------

describe("SUBSTITUTION FAILURE — compromised-platform attempt rejected", () => {
  it("artifact signed by attacker key is rejected against the genuine pin", () => {
    const cached = bootstrapGenuine();
    const forged = buildArtifact("9.99", ATTACKER); // 9.99 is already canonical (no trailing zero)
    // Attacker-signed envelope still claims the genuine key_id on the wire — classic sub.
    const envelope: ArtifactEnvelope = {
      ...forged,
      key_id: parseUuid(KEY_ID),
    };
    const verdict = pinAndAuthenticateArtifact({
      cached,
      discovery: discoveryFor([{ keyId: KEY_ID, publicKeyB64: NODE.publicKeyB64 }]),
      originClass: "node-origin",
      artifact: envelope,
      nowUnixMs: NOW,
    });
    expect(verdict.ok).toBe(false);
    if (verdict.ok) return;
    expect(verdict.reason).toBe("artifact_not_authenticated");
  });

  it("discovery presenting only the attacker key is rotation_unpinned (not auto-trusted)", () => {
    const cached = bootstrapGenuine();
    const genuineArtifact = buildArtifact("1", NODE);
    const envelope: ArtifactEnvelope = {
      ...genuineArtifact,
      key_id: parseUuid(KEY_ID),
    };
    const verdict = pinAndAuthenticateArtifact({
      cached,
      discovery: discoveryFor([
        { keyId: ATTACKER_KEY_ID, publicKeyB64: ATTACKER.publicKeyB64 },
      ]),
      originClass: "node-origin",
      artifact: envelope,
      nowUnixMs: NOW,
    });
    expect(verdict).toMatchObject({ ok: false, reason: "rotation_unpinned" });
  });

  it("platform-hosted surface is refused even when artifact+pin would otherwise verify", () => {
    const cached = bootstrapGenuine();
    const genuine = buildArtifact("1", NODE);
    const envelope: ArtifactEnvelope = {
      ...genuine,
      key_id: parseUuid(KEY_ID),
    };
    const verdict = pinAndAuthenticateArtifact({
      cached,
      discovery: discoveryFor([{ keyId: KEY_ID, publicKeyB64: NODE.publicKeyB64 }]),
      originClass: "platform-hosted",
      artifact: envelope,
      nowUnixMs: NOW,
    });
    expect(verdict).toMatchObject({
      ok: false,
      reason: "platform_hosted_not_substitution_proof",
    });
  });

  it("honest path: node-origin + matching pin + genuine artifact authenticates", () => {
    const cached = bootstrapGenuine();
    const genuine = buildArtifact("1", NODE);
    const envelope: ArtifactEnvelope = {
      ...genuine,
      key_id: parseUuid(KEY_ID),
    };
    const verdict = pinAndAuthenticateArtifact({
      cached,
      discovery: discoveryFor([{ keyId: KEY_ID, publicKeyB64: NODE.publicKeyB64 }]),
      originClass: "implementer-controlled-origin",
      artifact: envelope,
      nowUnixMs: NOW,
    });
    expect(verdict.ok).toBe(true);
    if (!verdict.ok) return;
    expect(verdict.originClass).toBe("implementer-controlled-origin");
    expect(verdict.verificationKey.publicKey).toBe(NODE.publicKeyB64);
    // Critical: the key used for auth is the PINNED key, not a side-channel discovery pick.
    expect(verdict.verificationKey.keyId).toBe(cached.pin.keyId);
  });
});
