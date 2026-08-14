// ZTR-1301 — fail-closed ops.allow_node_verified parser + admission gate.
import { describe, expect, it } from "vitest";

import {
  DEFAULT_VERIFICATION_MODE,
  InMemoryAllowNodeVerifiedPolicy,
  admitVerificationMode,
  isNodeVerifiedAllowedByPolicy,
  parseAllowNodeVerifiedPolicyDocument,
  refuseAllNodeVerifiedPolicy,
  resolveVerificationMode,
  serializeAllowNodeVerifiedPolicyDocument,
} from "./allow-node-verified-policy.js";

const IMPL_A = "22222222-2222-4222-8222-222222222222";
const IMPL_B = "33333333-3333-4333-8333-333333333333";

describe("parseAllowNodeVerifiedPolicyDocument (fail-closed)", () => {
  it("absent / null / empty → disabled absent", () => {
    expect(parseAllowNodeVerifiedPolicyDocument(null)).toEqual({
      status: "disabled",
      disabledReason: "absent",
    });
    expect(parseAllowNodeVerifiedPolicyDocument(undefined)).toEqual({
      status: "disabled",
      disabledReason: "absent",
    });
    expect(parseAllowNodeVerifiedPolicyDocument("")).toEqual({
      status: "disabled",
      disabledReason: "invalid",
    });
  });

  it("invalid JSON / unknown keys / bad types → disabled invalid", () => {
    const bad1 = parseAllowNodeVerifiedPolicyDocument("{");
    expect(bad1.status).toBe("disabled");
    if (bad1.status === "disabled") expect(bad1.disabledReason).toBe("invalid");

    const bad2 = parseAllowNodeVerifiedPolicyDocument(
      JSON.stringify({ enabled: true, implementers: [], extra: 1 }),
    );
    expect(bad2.status).toBe("disabled");
    if (bad2.status === "disabled") expect(bad2.disabledReason).toBe("invalid");

    const bad3 = parseAllowNodeVerifiedPolicyDocument(
      JSON.stringify({ enabled: "yes", implementers: [] }),
    );
    expect(bad3.status).toBe("disabled");
    if (bad3.status === "disabled") expect(bad3.disabledReason).toBe("invalid");
  });

  it("enabled:false parks implementers (off)", () => {
    const doc = parseAllowNodeVerifiedPolicyDocument(
      serializeAllowNodeVerifiedPolicyDocument(
        [{ implementer_id: IMPL_A, enabled: true }],
        false,
      ),
    );
    expect(doc).toEqual({
      status: "disabled",
      disabledReason: "off",
      implementers: [{ implementer_id: IMPL_A, enabled: true }],
    });
  });

  it("enabled document admits only listed enabled implementers", () => {
    const doc = parseAllowNodeVerifiedPolicyDocument(
      serializeAllowNodeVerifiedPolicyDocument([
        { implementer_id: IMPL_A, enabled: true },
        { implementer_id: IMPL_B, enabled: false },
      ]),
    );
    expect(doc.status).toBe("enabled");
    expect(isNodeVerifiedAllowedByPolicy(doc, IMPL_A)).toBe(true);
    expect(isNodeVerifiedAllowedByPolicy(doc, IMPL_B)).toBe(false);
    expect(isNodeVerifiedAllowedByPolicy(doc, "44444444-4444-4444-8444-444444444444")).toBe(
      false,
    );
  });

  it("duplicate implementer ids invalidate the document", () => {
    const raw = JSON.stringify({
      enabled: true,
      implementers: [
        { implementer_id: IMPL_A, enabled: true },
        { implementer_id: IMPL_A, enabled: true },
      ],
    });
    const doc = parseAllowNodeVerifiedPolicyDocument(raw);
    expect(doc.status).toBe("disabled");
    if (doc.status === "disabled") expect(doc.disabledReason).toBe("invalid");
  });
});

describe("admitVerificationMode", () => {
  it("INDEPENDENT always ok", () => {
    expect(
      admitVerificationMode(
        "INDEPENDENT",
        { status: "disabled", disabledReason: "absent" },
        IMPL_A,
      ),
    ).toEqual({ ok: true });
  });

  it("NODE_VERIFIED refused without policy", () => {
    expect(
      admitVerificationMode(
        "NODE_VERIFIED",
        { status: "disabled", disabledReason: "absent" },
        IMPL_A,
      ),
    ).toEqual({ ok: false, code: "verification_mode_not_allowed" });
  });

  it("NODE_VERIFIED allowed when policy enables implementer", () => {
    const policy = parseAllowNodeVerifiedPolicyDocument(
      serializeAllowNodeVerifiedPolicyDocument([{ implementer_id: IMPL_A, enabled: true }]),
    );
    expect(admitVerificationMode("NODE_VERIFIED", policy, IMPL_A)).toEqual({ ok: true });
  });
});

describe("resolveVerificationMode", () => {
  it("omitted → DEFAULT INDEPENDENT", () => {
    expect(resolveVerificationMode(undefined)).toBe(DEFAULT_VERIFICATION_MODE);
    expect(resolveVerificationMode(null)).toBe("INDEPENDENT");
  });
});

describe("InMemoryAllowNodeVerifiedPolicy / refuseAll", () => {
  it("refuseAll never allows", async () => {
    const p = refuseAllNodeVerifiedPolicy();
    expect(await p.isNodeVerifiedAllowed(IMPL_A)).toBe(false);
  });

  it("allowImplementer enables one id", () => {
    const p = new InMemoryAllowNodeVerifiedPolicy();
    expect(p.isNodeVerifiedAllowed(IMPL_A)).toBe(false);
    p.allowImplementer(IMPL_A);
    expect(p.isNodeVerifiedAllowed(IMPL_A)).toBe(true);
    expect(p.isNodeVerifiedAllowed(IMPL_B)).toBe(false);
  });
});
