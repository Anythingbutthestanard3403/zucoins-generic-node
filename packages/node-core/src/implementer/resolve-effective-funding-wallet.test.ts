// ZTR-1288 · effective funding wallet resolution (discovery / implementer identity)
import { describe, expect, it } from "vitest";

import {
  resolveEffectiveFundingWallet,
  toFundingWalletWireFields,
} from "./resolve-effective-funding-wallet.js";

const W1 = "11111111-1111-4111-8111-111111111111";
const W2 = "22222222-2222-4222-8222-222222222222";
const P1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const P2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

describe("ZTR-1288 · resolveEffectiveFundingWallet", () => {
  it("prefers implementer explicit pin over node default", () => {
    const out = resolveEffectiveFundingWallet({
      implementerPin: { funding_wallet_id: W1, funding_wallet_public_key: P1 },
      nodeDefault: { funding_wallet_id: W2, funding_wallet_public_key: P2 },
    });
    expect(out).toEqual({
      funding_wallet_id: W1,
      funding_wallet_public_key: P1,
      source: "implementer",
      configured: true,
    });
  });

  it("falls back to node default when implementer pin is null", () => {
    const out = resolveEffectiveFundingWallet({
      implementerPin: { funding_wallet_id: null, funding_wallet_public_key: null },
      nodeDefault: { funding_wallet_id: W2, funding_wallet_public_key: P2 },
    });
    expect(out.source).toBe("node_default");
    expect(out.funding_wallet_id).toBe(W2);
    expect(out.funding_wallet_public_key).toBe(P2);
    expect(out.configured).toBe(true);
  });

  it("unset is explicit nulls — never invents a key", () => {
    const out = resolveEffectiveFundingWallet({
      implementerPin: { funding_wallet_id: null, funding_wallet_public_key: null },
      nodeDefault: { funding_wallet_id: null, funding_wallet_public_key: null },
    });
    expect(out).toEqual({
      funding_wallet_id: null,
      funding_wallet_public_key: null,
      source: "unset",
      configured: false,
    });
    expect(toFundingWalletWireFields(out)).toEqual({
      funding_wallet_id: null,
      funding_wallet_public_key: null,
    });
  });

  it("dangling id without pubkey is not configured (unhealthy signal)", () => {
    const out = resolveEffectiveFundingWallet({
      implementerPin: { funding_wallet_id: W1, funding_wallet_public_key: null },
      nodeDefault: { funding_wallet_id: W2, funding_wallet_public_key: P2 },
    });
    // Explicit pin wins even if pubkey missing — do not silently fall through to default.
    expect(out.source).toBe("implementer");
    expect(out.funding_wallet_id).toBe(W1);
    expect(out.funding_wallet_public_key).toBeNull();
    expect(out.configured).toBe(false);
  });
});
