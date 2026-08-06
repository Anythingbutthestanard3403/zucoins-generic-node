import { describe, expect, it } from "vitest";

import { digestPreimage } from "../testkit/independentCrypto.ts";
import { readGoldenText } from "../testkit/byteGolden.ts";
import {
  verifyApprovalPreimage,
  type ApprovalEnvelope,
  type ApprovalVerifyRejectReason,
} from "./verify.ts";

const PURPOSE = "zp-send-external-approval-v1";

// A genuinely valid approval preimage as the mutation base: the committed A.8 golden. Overriding
// exactly one field isolates the check under test — every other field stays golden-valid and
// `envelopeFrom` always rebuilds a canonical serialization plus its matching digest, so the field
// being mutated is the only thing that can flip the verdict.
const goldenPayload = (): Record<string, unknown> => {
  const pre = readGoldenText(`approval/${PURPOSE}.preimage.txt`);
  return JSON.parse(pre.slice(pre.indexOf("\n") + 1)) as Record<string, unknown>;
};

const envelopeFrom = (payload: Record<string, unknown>): ApprovalEnvelope => {
  const preimage_text = `${PURPOSE}\n${JSON.stringify(payload)}`;
  return { preimage_text, preimage_sha256: digestPreimage(preimage_text) };
};

const expectReject = (payload: Record<string, unknown>, reason: ApprovalVerifyRejectReason): void => {
  const result = verifyApprovalPreimage(envelopeFrom(payload));
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.reason).toBe(reason);
  }
};

const expectOk = (payload: Record<string, unknown>): void => {
  expect(verifyApprovalPreimage(envelopeFrom(payload)).ok).toBe(true);
};

describe("the approval concern approval verifier: valid base", () => {
  it("the unmodified golden preimage verifies (happy-path anchor for the mutations below)", () => {
    expectOk(goldenPayload());
  });
});

// Fixed SIGNED issue instant; the window is measured against this signed `issued_at`, never HTTP
// receipt / wall time. 300000 ms is the 300s ceremony ceiling. A.9: the
// verifier MUST reject an `expires_at` "more than 300 seconds after the signed issued_at" — so
// exactly +300.000s is legal ("more than" is strict) and +300.001s is rejected. The committed
// golden is itself the +300.000s boundary case (its window is exactly 300s), so accepting the
// boundary is not a taste call: a `>= 300s` reading would reject the frozen golden.
describe("approval expiry upper bound (A.9 / two-timer separation — 300s ceremony window)", () => {
  const ISSUED = "2026-01-01T00:00:00.000Z";

  it("rejects expires_at 300.001s after issued_at (> 300s) -> expiry_window_exceeded", () => {
    expectReject(
      { ...goldenPayload(), issued_at: ISSUED, expires_at: "2026-01-01T00:05:00.001Z" },
      "expiry_window_exceeded",
    );
  });

  it("accepts expires_at exactly 300.000s after issued_at (== 300s is legal; 'more than' is exclusive)", () => {
    expectOk({ ...goldenPayload(), issued_at: ISSUED, expires_at: "2026-01-01T00:05:00.000Z" });
  });

  it("accepts a well-within-window expires_at (60s after issued_at)", () => {
    expectOk({ ...goldenPayload(), issued_at: ISSUED, expires_at: "2026-01-01T00:01:00.000Z" });
  });

  it("regression-guards the lower bound: expires_at == issued_at still -> expiry_not_after_issue", () => {
    expectReject({ ...goldenPayload(), issued_at: ISSUED, expires_at: ISSUED }, "expiry_not_after_issue");
  });

  it("regression-guards the lower bound: expires_at before issued_at -> expiry_not_after_issue", () => {
    expectReject(
      { ...goldenPayload(), issued_at: ISSUED, expires_at: "2025-12-31T23:59:59.999Z" },
      "expiry_not_after_issue",
    );
  });
});

// Canonical amount bound: approval `amount_zkz` is the strictly-positive canonical-text domain
// (`zkz_amount_positive_text`). The old local `regex.test(value) && value !== '0'` gate leaked
// every input below: '0.00'/'0.0' are mathematically zero (numeric positivity rejects them, not a
// string `<> '0'` compare) and '2.50' is grammar-legal but non-canonical (canonical re-emission is
// '2.5'). All must now reject as `field_value_invalid`.
describe("approval amount predicate (hardened positivity — no string bypass)", () => {
  it.each(["0.00", "0.0", "2.50", "0"])("rejects bypass amount %j -> field_value_invalid", (amount) => {
    expectReject({ ...goldenPayload(), amount_zkz: amount }, "field_value_invalid");
  });

  it("accepts a canonical positive amount ('2.5')", () => {
    expectOk({ ...goldenPayload(), amount_zkz: "2.5" });
  });
});
