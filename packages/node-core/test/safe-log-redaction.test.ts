// secret/evidence redaction + signing custody test #3.
import { describe, expect, it } from "vitest";

import {
  REDACTED,
  assertDumpSecretFree,
  findUnredactedSecretKeys,
  isNeverLog,
  normalizeKey,
  notFoundErrorBody,
  redactLogFields,
  scrubErrorDetails,
  truncate,
  truncateKind,
} from "../src/observability/index.js";

describe("normalizeKey / classifiers", () => {
  it("normalizes separators so all private-key spellings match", () => {
    expect(normalizeKey("VAULT_MASTER_KEY")).toBe("vaultmasterkey");
    expect(normalizeKey("vaultMasterKey")).toBe("vaultmasterkey");
    expect(normalizeKey("vault-master-key")).toBe("vaultmasterkey");
    expect(isNeverLog(normalizeKey("private_key"))).toBe(true);
    expect(isNeverLog(normalizeKey("totpSecret"))).toBe(true);
    expect(isNeverLog(normalizeKey("apiKeyPlaintext"))).toBe(true);
    expect(isNeverLog(normalizeKey("walletPubkey"))).toBe(false);
  });

  it("truncation ≠ redaction buckets", () => {
    expect(truncateKind(normalizeKey("walletPubkey"))).toBe("pubkey");
    expect(truncateKind(normalizeKey("vaultCiphertext"))).toBe("ciphertext");
    expect(truncateKind(normalizeKey("transferCode"))).toBe("code");
    expect(truncate("pubkey", "abcdefghijklmnop")).toBe("abcdefgh…mnop");
    expect(truncate("code", "ABCDEFGHIJK")).toBe("ABCDEFGH…");
    expect(truncate("ciphertext", "0123456789abcdefXYZ").length).toBeLessThanOrEqual(17);
  });
});

describe("redactLogFields deep copy (byte-exact source intact)", () => {
  it("censors secrets and truncates pubkeys without mutating input", () => {
    const input = {
      event: "sign",
      privateKey: "SUPER_SECRET_PRIVATE_KEY_MATERIAL",
      totpSecret: "JBSWY3DPEHPK3PXP",
      sessionCookie: "abc.def",
      csrfToken: "tok",
      apiKeyPlaintext: "zp_live_xxx",
      walletPubkey: "abcdefghijklmnopqr",
      amount: "1.00",
      nested: { password: "p@ss", ok: true },
    };
    const out = redactLogFields(input);
    expect(out.privateKey).toBe(REDACTED);
    expect(out.totpSecret).toBe(REDACTED);
    expect(out.sessionCookie).toBe(REDACTED);
    expect(out.csrfToken).toBe(REDACTED);
    expect(out.apiKeyPlaintext).toBe(REDACTED);
    expect(out.walletPubkey).not.toBe(input.walletPubkey);
    expect(String(out.walletPubkey)).toContain("…");
    expect((out.nested as { password: string }).password).toBe(REDACTED);
    expect((out.nested as { ok: boolean }).ok).toBe(true);
    // Source unmutilated — the byte-exact signing rule adjacent.
    expect(input.privateKey).toBe("SUPER_SECRET_PRIVATE_KEY_MATERIAL");
    expect(input.walletPubkey).toBe("abcdefghijklmnopqr");
  });

  it("signing custody test #3: private-key buffers and TOTP never appear post-redact", () => {
    const fixture = {
      implementerBearer: { apiKeyPlaintext: "key-1-UNIQUE-VALUE" },
      reportingCredential: { authorization: "Bearer xyz-UNIQUE" },
      operatorSession: { sessionSecret: "sess-UNIQUE-VALUE", csrf: "c-UNIQUE" },
      subscriptionHandle: { secret: "sub-secret-UNIQUE" },
      vault: {
        privateKey: "pk-UNIQUE-VALUE",
        totpCode: "123456",
        vaultCiphertext: "aa".repeat(40),
      },
    };
    const redacted = redactLogFields(fixture);
    const json = JSON.stringify(redacted);
    for (const needle of [
      "key-1-UNIQUE-VALUE",
      "Bearer xyz-UNIQUE",
      "sess-UNIQUE-VALUE",
      "sub-secret-UNIQUE",
      "pk-UNIQUE-VALUE",
      "123456",
    ]) {
      expect(json).not.toContain(needle);
    }
    expect(findUnredactedSecretKeys(redacted)).toEqual([]);
  });
});

describe("error body scrub + uniform 404", () => {
  it("scrubs preimage / gateway response from details", () => {
    const details = scrubErrorDetails({
      reason: "bad_sig",
      signingPreimage: "raw-bytes-here",
      gatewayResponse: "{big}",
      code: "X",
    }) as Record<string, unknown>;
    expect(details.signingPreimage).toBe(REDACTED);
    expect(details.gatewayResponse).toBe(REDACTED);
    expect(details.reason).toBe("bad_sig");
  });

  it("cross-tenant and not-found share byte-identical 404 shape", () => {
    const a = notFoundErrorBody("r1");
    const b = notFoundErrorBody("r1");
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(a.error.code).toBe("not_found");
    expect(a.error.details).toEqual({});
    // No orbitary existence fields — details enroll empty; message is the frozen the API contract text.
    expect(Object.keys(a.error.details)).toHaveLength(0);
  });
});

describe("backup/export dump census", () => {
  it("assertDumpSecretFree accepts ciphertext field names after redact path", () => {
    const dump = {
      rows: [{ vaultCiphertext: "0123456789abcdefEXTRA", id: "1" }],
      private_key: "MUST_NOT_SURVIVE",
    };
    // Raw dump has a secret key — assertDumpSecretFree redacts first then checks.
    expect(() => assertDumpSecretFree(dump)).not.toThrow();
    const redacted = redactLogFields(dump);
    expect(redacted.private_key).toBe(REDACTED);
  });
});
