// Boot-lane refusal of A.8 golden fixture keys (ZTR-1174 / A.9 item 16 counterpart).
//
// Consumer verify already refuses these keys on the inbound path when liveChain is set
// (`@zucoins/node-core/verifier/consumer`). This module is the node-side guard: a golden
// seed used as NODE_IDENTITY / EVENT_SIGNING or present in wallet custody must fail closed
// at boot — before any signing authority is armed — not merely be rejected by a
// downstream verifier.
//
// Reuses the fixture-key list and matcher from the consumer kit (single source of truth).
//
// Ordering contract (Review B / ZTR-1174 r2): assertNoGoldenFixtureKeysAtBoot MUST run on
// the ensure result BEFORE identity.sign / sendSignerHolder install / identityEnsured=true
// and BEFORE installEventSigner arms EVENT_SIGNING. Helpers below encode that order so
// unit tests can prove the probe never runs when the key is golden.

import {
  A8_GOLDEN_NODE_ID,
  A8_GOLDEN_PUBLIC_KEYS,
  isA8GoldenKey,
} from "@zucoins/node-core/verifier/consumer";

export class GoldenFixtureKeyBootError extends Error {
  readonly code = "golden_fixture_key_refused" as const;
  constructor(message: string) {
    super(message);
    this.name = "GoldenFixtureKeyBootError";
  }
}

export { A8_GOLDEN_NODE_ID, A8_GOLDEN_PUBLIC_KEYS, isA8GoldenKey };

export interface BootKeyIdentity {
  /** Optional key id (node_signing_keys.id or A.8 fixture node id). */
  readonly keyId?: string;
  /** Padded or unpadded base64url Ed25519 public key. */
  readonly publicKey: string;
  /** Human role for the error message (e.g. NODE_IDENTITY, wallet custody). */
  readonly role: string;
}

/**
 * Fail closed when any presented key is an A.8 golden fixture key.
 * Call from the boot lane after identity/event ensure and over wallet custody public keys,
 * before money workers arm.
 */
export function assertNoGoldenFixtureKeysAtBoot(
  keys: readonly BootKeyIdentity[],
): void {
  for (const key of keys) {
    // Node-id check first so the error names the right failure mode.
    if (key.keyId === A8_GOLDEN_NODE_ID) {
      throw new GoldenFixtureKeyBootError(
        `boot refused: A.8 golden fixture node id present as ${key.role}.`,
      );
    }
    const probe = {
      keyId: key.keyId ?? "00000000-0000-4000-8000-000000000000",
      publicKey: key.publicKey,
    };
    if (isA8GoldenKey(probe)) {
      throw new GoldenFixtureKeyBootError(
        `boot refused: A.8 golden fixture key present as ${key.role} (public key matches a published A.8 seed). ` +
          `Remove the fixture key from node identity / wallet custody before starting.`,
      );
    }
  }
}

export interface EnsuredSigningKey {
  readonly signingKeyId: string;
  readonly publicKey: string;
  /** Correspondence probe / runtime sign. Must not run before golden refuse. */
  sign(preimageBytes: Uint8Array): Uint8Array;
}

export interface ArmedIdentitySigner {
  readonly signingKeyId: string;
  readonly publicKey: string;
  sign(preimageBytes: Uint8Array): Uint8Array;
}

/**
 * NODE_IDENTITY arm path: golden-refuse the ensure result, THEN correspondence-probe,
 * THEN return the armable signer. Callers must not touch sendSignerHolder / identityEnsured
 * until this returns.
 */
export function refuseGoldenThenProbeIdentity(
  identity: EnsuredSigningKey,
): ArmedIdentitySigner {
  assertNoGoldenFixtureKeysAtBoot([
    {
      keyId: identity.signingKeyId,
      publicKey: identity.publicKey,
      role: "NODE_IDENTITY",
    },
  ]);
  // Prove reopen+sign only after refuse — discarded, never logged.
  identity.sign(new Uint8Array());
  return {
    signingKeyId: identity.signingKeyId,
    publicKey: identity.publicKey,
    sign: (preimageBytes: Uint8Array) => identity.sign(preimageBytes),
  };
}

/**
 * EVENT_SIGNING pre-arm gate: golden-refuse the ensure result BEFORE installEventSigner
 * probes or arms authority. Does not probe — installEventSigner still owns probe→arm.
 */
export function refuseGoldenEventSigningKey(eventKey: {
  readonly signingKeyId: string;
  readonly publicKey: string;
}): void {
  assertNoGoldenFixtureKeysAtBoot([
    {
      keyId: eventKey.signingKeyId,
      publicKey: eventKey.publicKey,
      role: "EVENT_SIGNING",
    },
  ]);
}
