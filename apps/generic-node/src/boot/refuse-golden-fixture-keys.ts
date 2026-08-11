// Boot-lane refusal of A.8 golden fixture keys (ZTR-1174 / A.9 item 16 counterpart).
//
// Consumer verify already refuses these keys on the inbound path when liveChain is set
// (`@zucoins/node-core/verifier/consumer`). This module is the node-side guard: a golden
// seed used as NODE_IDENTITY or present in wallet custody must fail closed at boot —
// before any signing is possible — not merely be rejected by a downstream verifier.
//
// Reuses the fixture-key list and matcher from the consumer kit (single source of truth).

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
 * Call from the boot lane after identity ensure and over wallet custody public keys,
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
