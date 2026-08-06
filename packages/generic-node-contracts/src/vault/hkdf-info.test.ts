import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  HKDF_DEK_LABEL,
  HKDF_INFO_ENCODING,
  HKDF_PARAMS,
  CROSS_STORE_LABEL_SEPARATION,
  HKDF_INFO_GOLDEN,
  buildWalletDekInfo,
} from "./hkdf-info.ts";

const sha256 = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

describe("byte-exact HKDF info encoding (the vault threat-model freeze amendment; frozen encoding decision)", () => {
  it("is frozen-by-proxy, newline-joined, WITH its own domain label", () => {
    expect(HKDF_INFO_ENCODING.status).toBe("FROZEN");
    expect(HKDF_INFO_ENCODING.method).toBe("NEWLINE_JOINED_UTF8");
    expect(HKDF_INFO_ENCODING.domain_prefixed).toBe(true);
    expect(HKDF_INFO_ENCODING.field_sequence).toEqual([
      "domain",
      "node_id",
      "wallet_id",
      "key_version",
    ]);
    expect(HKDF_DEK_LABEL).toBe("zp-wallet-dek-v1");
  });

  it("the builder reproduces the amended golden bytes exactly and the pinned sha256", () => {
    expect(buildWalletDekInfo(HKDF_INFO_GOLDEN.inputs)).toBe(HKDF_INFO_GOLDEN.info_text);
    expect(sha256(HKDF_INFO_GOLDEN.info_text)).toBe(HKDF_INFO_GOLDEN.info_sha256);
  });

  it("carries its own domain label distinct from the AAD label (cross-store separation)", () => {
    expect(HKDF_INFO_GOLDEN.info_text.startsWith("zp-wallet-dek-v1\n")).toBe(true);
    expect(HKDF_DEK_LABEL).not.toBe("zp-wallet-secret-v1");
    expect(CROSS_STORE_LABEL_SEPARATION.requirement).toBe("GLOBALLY_UNIQUE_HKDF_LABEL_PER_STORE");
    expect(CROSS_STORE_LABEL_SEPARATION.sibling_store_labels_owned_elsewhere).toBe(true);
  });

  it("HKDF params are pinned: L=32, salt never per-row, IKM is the PBKDF2 root", () => {
    expect(HKDF_PARAMS.output_length_bytes).toBe(32);
    expect(HKDF_PARAMS.salt_per_row).toBe(false);
    expect(HKDF_PARAMS.ikm).toBe("ROOT");
    expect(HKDF_PARAMS.algorithm).toBe("HKDF-SHA256");
  });

  it("binds key_version and wallet_id: mutating either changes the bytes (negative path)", () => {
    expect(buildWalletDekInfo({ ...HKDF_INFO_GOLDEN.inputs, keyVersion: "2" })).not.toBe(
      HKDF_INFO_GOLDEN.info_text,
    );
    expect(
      buildWalletDekInfo({
        ...HKDF_INFO_GOLDEN.inputs,
        walletId: "33333333-3333-4333-8333-333333333333",
      }),
    ).not.toBe(HKDF_INFO_GOLDEN.info_text);
  });

  it("the label is part of the derived bytes: a labelless info differs (negative path)", () => {
    const labelless = [
      HKDF_INFO_GOLDEN.inputs.nodeId,
      HKDF_INFO_GOLDEN.inputs.walletId,
      HKDF_INFO_GOLDEN.inputs.keyVersion,
    ].join("\n");
    expect(HKDF_INFO_GOLDEN.info_text).not.toBe(labelless);
  });
});
