import { createHmac, hkdfSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import { buildWalletDekInfo } from "../vault/hkdf-info.ts";
import {
  hkdfExpandSha256,
  deriveWalletDek,
  expandSingleBlock,
  HKDF_EXPAND_CONTRACT,
} from "./hkdf.ts";
import { NODE_ID, WALLET_DEFS, KEY_VERSION } from "./fixtures.ts";

/**
 * HKDF census. The AAD/HKDF byte-encoding freeze specifies `DEK_wallet = HKDF-Expand(root, info, 32)` with the boot
 * `root` used DIRECTLY as the PRK (the PBKDF2 output is already uniform — no Extract step). Node's
 * `hkdfSync` ALWAYS runs Extract-then-Expand, deriving a different PRK than the raw root, so its
 * OKM is NOT byte-equal. This test pins the manual Expand-only implementation to the single-block
 * form `HMAC-SHA256(root, info || 0x01)` and proves it diverges from `hkdfSync` — the dual-run
 * rationale that justifies the manual implementation.
 */
const ROOT = new Uint8Array(32).fill(0xa1);
const infoInputs = { nodeId: NODE_ID, walletId: WALLET_DEFS[0].id, keyVersion: String(KEY_VERSION) };
const infoBytes = new TextEncoder().encode(buildWalletDekInfo(infoInputs));

describe("HKDF-Expand-only wallet DEK derivation", () => {
  it("the wallet DEK is the single-block Expand form HMAC-SHA256(root, info || 0x01)", () => {
    const dek = deriveWalletDek(ROOT, infoInputs);
    expect(dek).toHaveLength(32);
    expect(Buffer.from(dek).toString("hex")).toBe(Buffer.from(expandSingleBlock(ROOT, infoBytes)).toString("hex"));

    const hmac = createHmac("sha256", Buffer.from(ROOT));
    hmac.update(Buffer.from(infoBytes));
    hmac.update(Buffer.from([0x01]));
    expect(Buffer.from(dek).toString("hex")).toBe(hmac.digest("hex"));
  });

  it("general hkdfExpandSha256 agrees with the single-block form at L = 32", () => {
    expect(Buffer.from(hkdfExpandSha256(ROOT, infoBytes, 32)).toString("hex")).toBe(
      Buffer.from(expandSingleBlock(ROOT, infoBytes)).toString("hex"),
    );
  });

  it("the manual Expand-only DEK is NOT byte-equal to hkdfSync (which always runs Extract first)", () => {
    const manual = deriveWalletDek(ROOT, infoInputs);
    // hkdfSync(ikm=root, salt=empty, info, 32) computes PRK = HMAC(salt=HashLen-zeroes, root) first.
    const fromHkdfSync = new Uint8Array(hkdfSync("sha256", Buffer.from(ROOT), Buffer.alloc(0), Buffer.from(infoBytes), 32));
    expect(Buffer.from(manual).toString("hex")).not.toBe(Buffer.from(fromHkdfSync).toString("hex"));
    expect(HKDF_EXPAND_CONTRACT.node_hkdf_sync_equivalent).toBe(false);
  });

  it("is deterministic and wallet-distinct (different wallet_id → different DEK)", () => {
    const dek1 = deriveWalletDek(ROOT, infoInputs);
    const dek1Again = deriveWalletDek(ROOT, infoInputs);
    expect(Buffer.from(dek1).toString("hex")).toBe(Buffer.from(dek1Again).toString("hex"));

    const dek2 = deriveWalletDek(ROOT, { ...infoInputs, walletId: WALLET_DEFS[1].id });
    expect(Buffer.from(dek2).toString("hex")).not.toBe(Buffer.from(dek1).toString("hex"));
  });

  it("rejects an out-of-range output length (negative path)", () => {
    expect(() => hkdfExpandSha256(ROOT, infoBytes, 0)).toThrow(/length out of range/);
    expect(() => hkdfExpandSha256(ROOT, infoBytes, 255 * 32 + 1)).toThrow(/length out of range/);
  });

  it("freezes the HKDF-Expand contract pins", () => {
    expect(HKDF_EXPAND_CONTRACT.algorithm).toBe("HKDF-SHA256-EXPAND-ONLY");
    expect(HKDF_EXPAND_CONTRACT.single_block_form).toBe("HMAC-SHA256(root, info || 0x01)");
    expect(HKDF_EXPAND_CONTRACT.wallet_dek_length_bytes).toBe(32);
  });
});
