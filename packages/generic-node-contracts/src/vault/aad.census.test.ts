import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import {
  AAD_DOMAIN,
  AAD_BINDING,
  SUBSTITUTION_CONTROL,
  SUPERSEDED_DRAFT_AAD,
} from "./aad.contract.ts";

describe("AAD binding is frozen (the vault model freeze; the vault-storage rule guard 2)", () => {
  it("the 6-field input set in sequence, reconstructed at open, never stored", () => {
    expect(AAD_DOMAIN).toBe("zp-wallet-secret-v1");
    assertFieldOrder(AAD_BINDING.input_fields, [
      "node_id",
      "wallet_id",
      "key_version",
      "public_key",
      "key_origin",
    ]);
    expect(AAD_BINDING.reconstructed_at_open).toBe(true);
    expect(AAD_BINDING.stored_as_column).toBe(false);
    expect(AAD_BINDING.exact_serialization_owner).toBe("vault.2");
  });

  it("cryptographic identity is the primary substitution control, AAD is defense in depth", () => {
    expect(SUBSTITUTION_CONTROL.primary).toBe(
      "DECRYPT_DERIVE_PUBKEY_ASSERT_EQ_WALLETS_PUBLIC_KEY",
    );
    expect(SUBSTITUTION_CONTROL.aad_role).toBe("DEFENSE_IN_DEPTH");
    expect(SUBSTITUTION_CONTROL.key_origin_smuggle_fails_closed).toBe(true);
  });

  it("the frozen binding hardens the superseded draft in exactly three respects (negative)", () => {
    // draft omits key_version and key_origin, and stored the AAD in a column
    expect(SUPERSEDED_DRAFT_AAD.input_fields).not.toContain("key_version");
    expect(SUPERSEDED_DRAFT_AAD.input_fields).not.toContain("key_origin");
    expect(SUPERSEDED_DRAFT_AAD.stored_as_column).toBe(true);
    expect(AAD_BINDING.input_fields).toContain("key_version");
    expect(AAD_BINDING.input_fields).toContain("key_origin");
    expect(AAD_BINDING.stored_as_column).toBe(false);
  });
});
