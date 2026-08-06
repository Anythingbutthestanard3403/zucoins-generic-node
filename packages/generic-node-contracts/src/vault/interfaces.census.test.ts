import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import {
  SEALING_API,
  SIGNER_BOUNDARY,
  LEADERSHIP_RULES,
  ZEROIZATION_INTERFACE,
} from "./interfaces.contract.ts";

describe("sealing / signer API and lifecycle interfaces are frozen (the vault schema freeze)", () => {
  it("the open API reconstructs the AAD and runs the substitution check", () => {
    expect(SEALING_API.open.reconstructs_aad_from).toBe(
      "AUTHORITATIVE_FIELDS_NEVER_STORED_COLUMN",
    );
    expect(SEALING_API.open.substitution_check).toBe(
      "DERIVE_PUBKEY_ASSERT_EQ_WALLETS_PUBLIC_KEY",
    );
    expect(SEALING_API.seal.derives_dek_via).toBe("HKDF_PER_WALLET");
  });

  it("the signer boundary holds no vault row lock and never returns a private key (negative)", () => {
    assertFieldOrder(SIGNER_BOUNDARY.capability_fields, [
      "walletId",
      "operationId",
      "leaseEpoch",
      "purpose",
      "preimageText",
      "expectedPreimageSha256",
    ]);
    expect(SIGNER_BOUNDARY.no_vault_row_lock).toBe(true);
    expect(SIGNER_BOUNDARY.never_returns_or_logs_private_key).toBe(true);
    expect(SIGNER_BOUNDARY.rereads_lease_before_decrypt).toBe(true);
  });

  it("leadership rules: single-writer mutations, rotation sole all-envelope writer, no fallback", () => {
    expect(LEADERSHIP_RULES.mutations_single_writer).toBe(true);
    expect(LEADERSHIP_RULES.rotation_is_sole_all_envelope_writer).toBe(true);
    expect(LEADERSHIP_RULES.no_hybrid_fallback).toBe(true);
  });

  it("zeroization interface: secure Uint8Array, never a JS string, mandatory wipe", () => {
    expect(ZEROIZATION_INTERFACE.buffer).toBe("SECURE_UINT8ARRAY");
    expect(ZEROIZATION_INTERFACE.never_js_string).toBe(true);
    assertFieldOrder(ZEROIZATION_INTERFACE.lifecycle, ["ALLOCATE", "DECRYPT_INTO", "SIGN", "WIPE"]);
    expect(ZEROIZATION_INTERFACE.wipe).toBe("SODIUM_MEMZERO_MANDATORY_POST_SIGN");
  });
});
