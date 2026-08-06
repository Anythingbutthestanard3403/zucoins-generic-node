import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import {
  VAULT_COLUMNS,
  VAULT_CONSTRAINTS,
  VAULT_KEY_IDENTITY,
} from "./vault-schema.contract.ts";

describe("vault schema is frozen (the vault schema freeze; the vault-storage decision)", () => {
  it("columns in DDL sequence, with no aad_text column", () => {
    assertFieldOrder(
      VAULT_COLUMNS.map((column) => column.name),
      [
        "wallet_id",
        "key_version",
        "ciphertext",
        "nonce",
        "auth_tag",
        "ciphertext_sha256",
        "created_at",
        "rotated_at",
      ],
    );
    expect(VAULT_COLUMNS.map((column) => column.name)).not.toContain("aad_text");
  });

  it("nonce and auth_tag byte-length checks match the frozen 96/128-bit sizes", () => {
    expect(VAULT_CONSTRAINTS.checks).toContain("octet_length(nonce) = 12");
    expect(VAULT_CONSTRAINTS.checks).toContain("octet_length(auth_tag) = 16");
    expect(VAULT_CONSTRAINTS.checks).toContain("key_version > 0");
  });

  it("structural UNIQUE(key_version, nonce), PK wallet_id, and no stored AAD", () => {
    expect(VAULT_CONSTRAINTS.table).toBe("vault");
    expect(VAULT_CONSTRAINTS.primary_key).toEqual(["wallet_id"]);
    expect(VAULT_CONSTRAINTS.unique).toEqual([["key_version", "nonce"]]);
    expect(VAULT_CONSTRAINTS.no_aad_text_column).toBe(true);
  });

  it("the row key identity is (wallet_id, key_version)", () => {
    expect(VAULT_KEY_IDENTITY).toEqual(["wallet_id", "key_version"]);
  });

  it("the draft column name is not used (negative: no vault_key_version)", () => {
    expect(VAULT_COLUMNS.map((column) => column.name)).toContain("key_version");
    expect(VAULT_COLUMNS.map((column) => column.name)).not.toContain("vault_key_version");
  });
});
