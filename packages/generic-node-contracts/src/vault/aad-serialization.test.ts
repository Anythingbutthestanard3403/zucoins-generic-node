import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { AAD_BINDING } from "./aad.contract.ts";
import {
  AAD_SERIALIZATION,
  AAD_FULL_FIELD_SEQUENCE,
  AAD_GOLDEN,
  buildWalletSecretAad,
} from "./aad-serialization.ts";

const sha256 = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

describe("byte-exact AAD serialization (the vault schema freeze; frozen encoding decision)", () => {
  it("is frozen-by-proxy with the newline-joined method", () => {
    expect(AAD_SERIALIZATION.status).toBe("FROZEN");
    expect(AAD_SERIALIZATION.method).toBe("NEWLINE_JOINED_UTF8");
  });

  it("the full field sequence is the domain followed by the vault model freeze's frozen AAD field set", () => {
    expect(AAD_FULL_FIELD_SEQUENCE).toEqual(["domain", ...AAD_BINDING.input_fields]);
  });

  it("the builder reproduces the golden bytes exactly and the pinned sha256", () => {
    expect(buildWalletSecretAad(AAD_GOLDEN.inputs)).toBe(AAD_GOLDEN.aad_text);
    expect(sha256(AAD_GOLDEN.aad_text)).toBe(AAD_GOLDEN.aad_sha256);
  });

  it("binds key_version and key_origin: mutating either changes the bytes (negative path)", () => {
    const changedVersion = buildWalletSecretAad({ ...AAD_GOLDEN.inputs, keyVersion: "2" });
    const changedOrigin = buildWalletSecretAad({ ...AAD_GOLDEN.inputs, keyOrigin: "imported" });
    expect(changedVersion).not.toBe(AAD_GOLDEN.aad_text);
    expect(changedOrigin).not.toBe(AAD_GOLDEN.aad_text);
  });

  it("the frozen AAD is not the superseded 4-field draft form (negative path)", () => {
    const draftForm = [
      "zp-wallet-secret-v1",
      AAD_GOLDEN.inputs.nodeId,
      AAD_GOLDEN.inputs.walletId,
      AAD_GOLDEN.inputs.publicKey,
    ].join("\n");
    expect(AAD_GOLDEN.aad_text).not.toBe(draftForm);
    expect(AAD_GOLDEN.aad_text).toContain("\n1\n"); // key_version present between wallet_id and public_key
  });
});
