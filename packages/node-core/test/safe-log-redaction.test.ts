// secret/evidence redaction + signing custody test #3.
import { describe, expect, it } from "vitest";

import {
  MAX_DEPTH_MARKER,
  MAX_REDACT_DEPTH,
  REDACTED,
  assertDumpSecretFree,
  findUnredactedSecretKeys,
  isNeverLog,
  normalizeKey,
  notFoundErrorBody,
  redactLogFields,
  scrubErrorDetails,
  scrubText,
  truncate,
  truncateKind,
} from "../src/observability/index.js";

/** `{ l1: { l2: … } }` wrapping `leaf`, so `leaf`'s own keys sit at level+1. */
function nest(levels: number, leaf: Record<string, unknown>): Record<string, unknown> {
  let node: Record<string, unknown> = leaf;
  for (let level = levels; level >= 1; level -= 1) node = { [`l${level}`]: node };
  return node;
}

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

describe("recursion bound is fail-closed", () => {
  it("censors a never-log field nested at depth 12 instead of emitting it raw", () => {
    const deep = nest(11, { privateKey: "DEEP-UNIQUE-VALUE", note: "ordinary" });
    const json = JSON.stringify(redactLogFields(deep));
    expect(json).not.toContain("DEEP-UNIQUE-VALUE");
    expect(json).toContain(MAX_DEPTH_MARKER);
  });

  it("emits the marker, never the caller's value, past MAX_REDACT_DEPTH", () => {
    // One level inside the bound is still inspected normally; one past it is not.
    const inside = redactLogFields(nest(MAX_REDACT_DEPTH, { plain: "VISIBLE-UNIQUE" }));
    expect(JSON.stringify(inside)).toContain("VISIBLE-UNIQUE");
    const past = redactLogFields(nest(MAX_REDACT_DEPTH + 2, { plain: "HIDDEN-UNIQUE" }));
    expect(JSON.stringify(past)).not.toContain("HIDDEN-UNIQUE");
  });

  it("marker is distinct from REDACTED — censored and never-inspected differ", () => {
    expect(MAX_DEPTH_MARKER).not.toBe(REDACTED);
  });
});

describe("Error values carry no verbatim stack or message", () => {
  it("scrubs never-log assignments out of both message and stack", () => {
    const err = new Error("connect failed password=hunter2 host=db.internal");
    const out = redactLogFields({ err }) as {
      err: { type: string; message: string; stack?: string };
    };
    expect(out.err.type).toBe("Error");
    expect(out.err.message).toBe(`connect failed password=${REDACTED} host=db.internal`);
    // The stack's header line repeats the message — the same rules must reach it.
    expect(out.err.stack).toBeDefined();
    expect(String(out.err.stack)).not.toContain("hunter2");
    expect(err.message).toBe("connect failed password=hunter2 host=db.internal");
  });

  it("scrubText leaves a JSON fragment parseable and non-secret text alone", () => {
    expect(scrubText('{"password":"hunter2"}')).toBe('{"password":"hunter2"}');
    expect(scrubText("reason: bad_sig count=3")).toBe("reason: bad_sig count=3");
    expect(scrubText("VAULT_MASTER_KEY=abc123")).toBe(`VAULT_MASTER_KEY=${REDACTED}`);
    expect(scrubText("totpSecret: 123456")).toBe(`totpSecret: ${REDACTED}`);
  });
});

describe("redaction never mutates the caller's object", () => {
  it("deep-copies every level, including past the recursion bound", () => {
    const input = { outer: { inner: { password: "p@ss", amount: "1.00" } } };
    const out = redactLogFields(input) as { outer: { inner: Record<string, unknown> } };
    expect(out.outer).not.toBe(input.outer);
    expect(out.outer.inner).not.toBe(input.outer.inner);
    expect(out.outer.inner.password).toBe(REDACTED);
    // Byte-exact source intact — a money-path value routed through a log line.
    expect(input.outer.inner.password).toBe("p@ss");
    expect(input.outer.inner.amount).toBe("1.00");

    const deep = nest(11, { privateKey: "DEEP-UNIQUE-VALUE" });
    redactLogFields(deep);
    expect(JSON.stringify(deep)).toContain("DEEP-UNIQUE-VALUE");
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

  // The regression gate for the two-defects-cancelling-out problem: the census
  // used to share MAX_REDACT_DEPTH with the redactor, so the one range the
  // redactor leaked was the one range the census could not see.
  it("assertDumpSecretFree throws for a secret nested deeper than eight levels", () => {
    expect(() => assertDumpSecretFree(nest(11, { privateKey: "DEEP-UNIQUE-VALUE" }))).toThrow(
      /uncensored or uninspected/,
    );
  });

  it("findUnredactedSecretKeys reaches a secret-classed key past the old depth limit", () => {
    const hits = findUnredactedSecretKeys(nest(11, { privateKey: "DEEP-UNIQUE-VALUE" }));
    expect(hits).toEqual(["l1.l2.l3.l4.l5.l6.l7.l8.l9.l10.l11.privateKey"]);
  });

  it("walks arrays and terminates on cycles", () => {
    expect(findUnredactedSecretKeys({ rows: [{ private_key: "x" }] })).toEqual([
      "rows.0.private_key",
    ]);
    const cyclic: Record<string, unknown> = { id: "1" };
    cyclic.self = cyclic;
    expect(findUnredactedSecretKeys(cyclic)).toEqual([]);
  });
});
