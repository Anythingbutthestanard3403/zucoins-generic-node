// VaultSigner over EncryptedWalletKeyStore for SEND form/sign (Key-custody: values wiped).

import { createPrivateKey, sign as nodeSign } from "node:crypto";
import type { Pool } from "pg";

import type { EncryptedWalletKeyStore, VaultSigner } from "@zucoins/node-core";

/**
 * Compose a VaultSigner that opens the sealed wallet secret, signs UTF-8 preimage bytes
 * with Ed25519, and wipes plaintext before return. Identity is loaded from wallets row
 * (never caller-supplied pubkey).
 */
export function createPoolVaultSigner(deps: {
  readonly pool: Pool;
  readonly vault: EncryptedWalletKeyStore;
  readonly nodeId: string;
}): VaultSigner {
  return {
    async sign(walletId: string, preimageBytes: Uint8Array): Promise<string> {
      const identity = await deps.pool.query<{
        id: string;
        public_key: string;
        key_origin: string;
      }>(
        `SELECT id::text AS id, public_key, key_origin
           FROM wallets WHERE id = $1::uuid AND node_id = $2::uuid LIMIT 1`,
        [walletId, deps.nodeId],
      );
      const row = identity.rows[0];
      if (row === undefined) {
        throw new Error(`vault sign: wallet ${walletId} not found`);
      }
      const secret = await deps.vault.open(
        {
          nodeId: deps.nodeId,
          walletId,
          keyVersion: 1,
          publicKey: row.public_key,
          keyOrigin: row.key_origin,
        },
        "SPLITCHAIN_STEP_1",
      );
      try {
        const bytes = secret.bytes;
        // 64-byte Ed25519 secret = seed(32) || public(32)
        if (bytes.length < 32) {
          throw new Error("vault sign: secret shorter than Ed25519 seed");
        }
        const seed = Buffer.from(bytes.subarray(0, 32));
        try {
          const pkcs8 = Buffer.concat([
            Buffer.from("302e020100300506032b657004220420", "hex"),
            seed,
          ]);
          const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
          const sig = nodeSign(null, Buffer.from(preimageBytes), key);
          return Buffer.from(sig).toString("base64url") + "==";
        } finally {
          seed.fill(0);
        }
      } finally {
        secret.wipe();
      }
    },
  };
}
