import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { validateOperationAmount } from "../amounts/validators.ts";
import {
  Ed25519SignatureSchema,
  PositiveZkzAmountSchema,
  Sha256HexSchema,
  WalletPublicKeySchema,
} from "./scalars.ts";

const WALLET_PUBLIC_KEY = `${"A".repeat(43)}=`;
const ED25519_SIGNATURE = `${"A".repeat(86)}==`;
const SHA256_HEX = "a".repeat(64);
const AMOUNT = "99999999.12345678901234567890123456789012";

describe("the named concern canonical scalar positive fixtures", () => {
  it("accepts a canonical 44-character wallet public key", () => {
    expect(WALLET_PUBLIC_KEY).toHaveLength(44);
    expect(Buffer.from(WALLET_PUBLIC_KEY, "base64url")).toHaveLength(32);
    expect(WalletPublicKeySchema.safeParse(WALLET_PUBLIC_KEY).success).toBe(true);
  });

  it("accepts a canonical 88-character Ed25519 signature", () => {
    expect(ED25519_SIGNATURE).toHaveLength(88);
    expect(Buffer.from(ED25519_SIGNATURE, "base64url")).toHaveLength(64);
    expect(Ed25519SignatureSchema.safeParse(ED25519_SIGNATURE).success).toBe(true);
  });

  it("accepts a canonical lowercase SHA-256 digest", () => {
    expect(SHA256_HEX).toHaveLength(64);
    expect(Sha256HexSchema.safeParse(SHA256_HEX).success).toBe(true);
  });

  it("delegates to the amounts downstream consumer amount validator and preserves accepted bytes", () => {
    expect(validateOperationAmount(AMOUNT)).toEqual({ ok: true, canonical: AMOUNT });
    const result = PositiveZkzAmountSchema.safeParse(AMOUNT);
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data).toBe(AMOUNT);
    expect(Buffer.from(result.data)).toEqual(Buffer.from(AMOUNT));
  });

  it("rejects the unpadded key and signature forms", () => {
    expect(WalletPublicKeySchema.safeParse(WALLET_PUBLIC_KEY.slice(0, -1)).success).toBe(false);
    expect(Ed25519SignatureSchema.safeParse(ED25519_SIGNATURE.slice(0, -2)).success).toBe(false);
  });
});
