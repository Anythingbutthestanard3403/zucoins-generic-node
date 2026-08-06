import { beforeAll, describe, expect, it } from "vitest";

import { ready, digestPreimage } from "../testkit/independentCrypto.ts";
import { defaultSuiteVerificationCrypto } from "../testkit/suiteVerificationCrypto.ts";
import { readGoldenText } from "../testkit/byteGolden.ts";
import {
  verifyApprovalPreimage,
  verifyApprovalDeviceSignature,
  type ApprovalEnvelope,
  type ApprovalVerifyRejectReason,
} from "./verify.ts";

const PURPOSE = "zp-send-external-approval-v1";
const DEVICE_PUB = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
const NODE_PUB = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";

const load = (): { prefix: string; payload: Record<string, unknown> } => {
  const pre = readGoldenText(`approval/${PURPOSE}.preimage.txt`);
  const nl = pre.indexOf("\n");
  return { prefix: pre.slice(0, nl), payload: JSON.parse(pre.slice(nl + 1)) as Record<string, unknown> };
};

const envelopeFrom = (prefix: string, payload: Record<string, unknown>): ApprovalEnvelope => {
  const preimage_text = `${prefix}\n${JSON.stringify(payload)}`;
  return { preimage_text, preimage_sha256: digestPreimage(preimage_text) };
};

const expectReject = (envelope: ApprovalEnvelope, reason: ApprovalVerifyRejectReason): void => {
  const result = verifyApprovalPreimage(envelope);
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.reason).toBe(reason);
  }
};

// Byte-golden digest anchoring (each file's sha256 + signature vs immovable inline A.8 literals,
// manifest and meta asserted equal to those literals, plus a content-mutation negative) lives in
// `goldens-anchor.census.test.ts`. This file exercises the verifier and the A.9 mutation vectors.
describe("the approval concern approval golden verifier (A.8)", () => {
  it("the golden preimage passes the approval byte-contract verifier", () => {
    const { prefix, payload } = load();
    const result = verifyApprovalPreimage(envelopeFrom(prefix, payload));
    expect(result).toEqual({
      ok: true,
      purpose: PURPOSE,
      digest: "d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146",
    });
  });
});

describe("the approval concern approval mutation vectors: each MUST fail verification (A.9)", () => {
  it("reordered field sequence -> field_sequence_mismatch", () => {
    const { prefix, payload } = load();
    const entries = Object.entries(payload);
    [entries[10], entries[11]] = [entries[11], entries[10]]; // swap issued_at and expires_at
    expectReject(envelopeFrom(prefix, Object.fromEntries(entries)), "field_sequence_mismatch");
  });

  it("omitted nullable references_operation_id -> field_sequence_mismatch", () => {
    const { prefix, payload } = load();
    const entries = Object.entries(payload).filter(([k]) => k !== "references_operation_id");
    expectReject(envelopeFrom(prefix, Object.fromEntries(entries)), "field_sequence_mismatch");
  });

  it("prefix purpose != payload purpose -> payload_purpose_mismatch", () => {
    const { payload } = load();
    expectReject(envelopeFrom("zp-send-external-expected-v1", payload), "payload_purpose_mismatch");
  });

  it("canonical_version as string \"1\" -> canonical_version_invalid", () => {
    const { prefix, payload } = load();
    expectReject(envelopeFrom(prefix, { ...payload, canonical_version: "1" }), "canonical_version_invalid");
  });

  it("amount as a JSON number -> field_value_invalid", () => {
    const { prefix, payload } = load();
    expectReject(envelopeFrom(prefix, { ...payload, amount_zkz: 2.25 }), "field_value_invalid");
  });

  it("uppercase (non-canonical) UUID -> field_value_invalid", () => {
    const { prefix, payload } = load();
    expectReject(
      envelopeFrom(prefix, { ...payload, node_id: "11111111-1111-4111-8111-11111111111A" }),
      "field_value_invalid",
    );
  });

  it("timestamp without the trailing Z -> field_value_invalid", () => {
    const { prefix, payload } = load();
    expectReject(envelopeFrom(prefix, { ...payload, issued_at: "2026-07-18T00:00:00.000" }), "field_value_invalid");
  });

  it("expires_at not later than issued_at -> expiry_not_after_issue", () => {
    const { prefix, payload } = load();
    expectReject(
      envelopeFrom(prefix, { ...payload, expires_at: payload.issued_at as string }),
      "expiry_not_after_issue",
    );
  });

  it("appended trailing newline (no signature to catch it) -> non_canonical_serialization", () => {
    const { prefix, payload } = load();
    const canonical = `${prefix}\n${JSON.stringify(payload)}`;
    const tampered = `${canonical}\n`;
    expectReject({ preimage_text: tampered, preimage_sha256: digestPreimage(tampered) }, "non_canonical_serialization");
  });

  it("unpadded source_pubkey (missing trailing '=') -> field_value_invalid (A.9 vector 5)", () => {
    const { prefix, payload } = load();
    const unpadded = (payload.source_pubkey as string).replace(/=+$/, "");
    expectReject(envelopeFrom(prefix, { ...payload, source_pubkey: unpadded }), "field_value_invalid");
  });

  it("source_selector with a non-WALLET_ID kind -> field_value_invalid (WALLET_ID closure)", () => {
    const { prefix, payload } = load();
    const sourceSelector = payload.source_selector as Record<string, unknown>;
    expectReject(
      envelopeFrom(prefix, { ...payload, source_selector: { kind: "ALIAS", wallet_id: sourceSelector.wallet_id } }),
      "field_value_invalid",
    );
  });

  it("source_selector with a third key -> field_value_invalid (WALLET_ID closure: exactly two keys)", () => {
    const { prefix, payload } = load();
    const sourceSelector = payload.source_selector as Record<string, unknown>;
    expectReject(
      envelopeFrom(prefix, { ...payload, source_selector: { ...sourceSelector, extra: "unexpected" } }),
      "field_value_invalid",
    );
  });
});

describe("the approval concern optional additive device signature (A.9 vectors 10, 13, 14)", () => {
  let sig: string;
  beforeAll(async () => {
    await ready();
    sig = readGoldenText(`approval/${PURPOSE}.sig.b64`);
  });

  it("the golden device signature verifies over the exact approval bytes under the device key", async () => {
    const { prefix, payload } = load();
    const envelope: ApprovalEnvelope = { ...envelopeFrom(prefix, payload), device_signature: sig, device_key_id: "d" };
    expect(await verifyApprovalDeviceSignature(envelope, DEVICE_PUB, defaultSuiteVerificationCrypto)).toBe(true);
  });

  it("a cross-key (node instead of device) verification fails", async () => {
    const { prefix, payload } = load();
    const envelope: ApprovalEnvelope = { ...envelopeFrom(prefix, payload), device_signature: sig };
    expect(await verifyApprovalDeviceSignature(envelope, NODE_PUB, defaultSuiteVerificationCrypto)).toBe(false);
  });

  it("a device signature over tampered bytes fails (no cross-purpose acceptance)", async () => {
    const { prefix, payload } = load();
    const tampered: ApprovalEnvelope = { ...envelopeFrom(prefix, { ...payload, amount_zkz: "9.99" }), device_signature: sig };
    expect(await verifyApprovalDeviceSignature(tampered, DEVICE_PUB, defaultSuiteVerificationCrypto)).toBe(false);
  });

  it("a TOTP-only approval carries no device signature, and none is fabricated from the TOTP", async () => {
    // No device_signature present -> the verifier yields false; a TOTP is NEVER treated as a tuple
    // signature (A.9 vector 13). The mandatory TOTP gate lives outside this byte verifier.
    const { prefix, payload } = load();
    expect(await verifyApprovalDeviceSignature(envelopeFrom(prefix, payload), DEVICE_PUB, defaultSuiteVerificationCrypto)).toBe(false);
  });
});
