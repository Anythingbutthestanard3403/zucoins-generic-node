/**
 * SOURCE: the AAD/HKDF byte-encoding freeze ("PRK = root (the PBKDF2-SHA256 600k output, already uniform);
 * DEK_wallet = HKDF-Expand(root, info, L=32)"); the signing-custody-security spec the DEK-derivation rule (DEK_wallet
 * = HKDF-Expand(root, "zp-wallet-dek-v1\n<node_id>\n<wallet_id>\n<key_version>", 32)); RFC 5869
 * section 2.3 (HKDF-Expand). The info string is built by the frozen the vault schema freeze `buildWalletDekInfo`.
 *
 * WHY MANUAL: the AAD/HKDF byte-encoding freeze specifies HKDF-EXPAND with the boot `root` used
 * DIRECTLY as the PRK — the PBKDF2 output is already uniform, so there is no Extract step. Node's
 * `hkdfSync("sha256", ikm, salt, info, len)` ALWAYS runs Extract-then-Expand: even with an empty
 * salt it computes `PRK = HMAC(salt=HashLen-zeroes, ikm)` first, which is a DIFFERENT PRK from the
 * raw `root`, so its OKM is NOT byte-equal to `HKDF-Expand(root, info, 32)`. To reproduce the freeze's
 * exact bytes we implement Expand-only by hand: for L = 32 = HashLen, N = 1 and
 * `OKM = T(1) = HMAC-SHA256(PRK=root, info || 0x01)`. This is the single-block case; the general
 * loop is included for completeness but the wallet DEK only ever uses L = 32.
 */
import { createHmac } from "node:crypto";

import { buildWalletDekInfo, type WalletDekInfoInputs } from "../vault/hkdf-info.ts";

const HASH_LEN = 32;

/**
 * RFC 5869 section 2.3 HKDF-Expand, Expand-only (PRK supplied directly, no Extract).
 * `prk` is the boot `root`; `info` is the UTF-8 info string bytes; `length` ≤ 255 * HashLen.
 */
export const hkdfExpandSha256 = (prk: Uint8Array, info: Uint8Array, length: number): Uint8Array => {
  if (length <= 0 || length > 255 * HASH_LEN) {
    throw new Error(`hkdf-expand: length out of range: ${length}`);
  }
  const blocks = Math.ceil(length / HASH_LEN);
  const okm = Buffer.alloc(blocks * HASH_LEN);
  let previous = Buffer.alloc(0);
  for (let counter = 1; counter <= blocks; counter += 1) {
    const hmac = createHmac("sha256", Buffer.from(prk));
    hmac.update(previous);
    hmac.update(Buffer.from(info));
    hmac.update(Buffer.from([counter]));
    previous = hmac.digest();
    previous.copy(okm, (counter - 1) * HASH_LEN);
  }
  return new Uint8Array(okm.subarray(0, length));
};

/**
 * Wallet-DEK derivation: `DEK_wallet = HKDF-Expand(root, info, 32)` with
 * `info = "zp-wallet-dek-v1\n<node_id>\n<wallet_id>\n<key_version>"` (frozen the vault schema freeze builder).
 * `root` is the PBKDF2-SHA256-600k boot derivation over the operator-held master key; this
 * function takes the already-derived root and performs NO PBKDF2 (that step is the wallet-vault envelope freeze's frozen
 * once-at-boot parameter, pinned and tested in the vault lane).
 */
export const deriveWalletDek = (root: Uint8Array, inputs: WalletDekInfoInputs): Uint8Array =>
  hkdfExpandSha256(root, new TextEncoder().encode(buildWalletDekInfo(inputs)), HASH_LEN);

/** The exact single-block Expand form the wallet DEK uses — exposed so a test can pin the
 *  manual implementation to `HMAC-SHA256(root, info || 0x01)` and prove it is NOT the
 *  Extract-then-Expand value `hkdfSync` would produce. */
export const expandSingleBlock = (prk: Uint8Array, info: Uint8Array): Uint8Array => {
  const hmac = createHmac("sha256", Buffer.from(prk));
  hmac.update(Buffer.from(info));
  hmac.update(Buffer.from([0x01]));
  return new Uint8Array(hmac.digest());
};

export const HKDF_EXPAND_CONTRACT = {
  algorithm: "HKDF-SHA256-EXPAND-ONLY",
  prk: "ROOT_DIRECT (no Extract; PBKDF2 output already uniform)",
  single_block_form: "HMAC-SHA256(root, info || 0x01)",
  wallet_dek_length_bytes: HASH_LEN,
  node_hkdf_sync_equivalent: false,
  reason: "hkdfSync always runs Extract first, deriving a different PRK than the raw root",
} as const;
