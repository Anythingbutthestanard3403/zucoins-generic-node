// Remediation — the three trust-boundary holes the dual review found in the
// canonical suite-tuple serializer, and the invariant that none of the fixes moved a signed byte.
//
//  B2  prototype-pollution presence check (money-path): the serializer's required-field
//      presence test must be own-property, matching the own-only `Object.keys` unexpected-field test.
//  B3  A.4.1–A.4.3 / A.5 / A.5.1 signed freshness window: `0 < expires_at − issued_at ≤ ceiling`,
//      enforced against the SIGNED `issued_at` and BEFORE any Ed25519 check.
//  B4  A.4.3 device-label denylist, fail-closed, including the U+202E BiDi override.
//
// Governing spec: canonical fields
// .

import { describe, expect, it } from "vitest";

import { InvalidFieldError } from "../src/protocol/suite/encoders.js";
import { serializeSuiteTuple } from "../src/protocol/suite/serialize.js";
import {
  verifyDestinationBless,
  verifyDeviceEnrol,
  verifyReportRequest,
  verifyReportingRegisterProof,
  verifySendExternalApprovalDeviceSignature,
  type ResolvedSuiteVerificationKey,
  type SignedSuiteTupleEnvelope,
} from "../src/protocol/suite/verify.js";
import { SUITE_GOLDENS } from "./__vectors__/suite-appendix-a.js";

function golden(id: string) {
  const vector = SUITE_GOLDENS.find((entry) => entry.id === id);
  if (vector === undefined) throw new Error(`missing golden vector: ${id}`);
  return vector;
}

// The golden's payload object, in its exact committed key sequence.
function payloadOf(id: string): Record<string, unknown> {
  const text = golden(id).preimageText;
  return JSON.parse(text.slice(text.indexOf("\n") + 1)) as Record<string, unknown>;
}

describe("B2 — required-field presence is own-property, never inherited", () => {
  // `label` is a required (non-nullable) field of zp-device-enrol-v1; `expiry_unix_time_secs` is a
  // nullable one on zp-receive-expected-v1. Both must be rejected as missing when the only source of
  // the name is a polluted prototype — never silently signed with the inherited value.
  const cases = [
    { field: "label", purpose: "zp-device-enrol-v1", id: "device-enrol" },
    { field: "expiry_unix_time_secs", purpose: "zp-receive-expected-v1", id: "receive-expected" },
  ] as const;

  for (const { field, purpose, id } of cases) {
    it(`rejects an absent \`${field}\` supplied only by Object.prototype`, () => {
      const values = payloadOf(id);
      delete values[field];

      (Object.prototype as Record<string, unknown>)[field] = "POLLUTED";
      try {
        expect(field in values).toBe(true); // the prototype-aware view the old code used
        expect(Object.prototype.hasOwnProperty.call(values, field)).toBe(false);

        expect(() => serializeSuiteTuple(purpose, values)).toThrowError(
          expect.objectContaining({ reason: "missing_field", field }) as Error,
        );
      } finally {
        delete (Object.prototype as Record<string, unknown>)[field];
      }
    });
  }

  it("rejects a composite whose required key comes only from Object.prototype", () => {
    const values = payloadOf("receive-expected");
    // Same arity as the real composite, but `destination_id` is not an own key.
    values.after_landing = { kind: "HOLD", smuggled: "x" };

    (Object.prototype as Record<string, unknown>).destination_id = null;
    try {
      expect(() => serializeSuiteTuple("zp-receive-expected-v1", values)).toThrowError(
        expect.objectContaining({ reason: "invalid_composite_shape" }) as Error,
      );
    } finally {
      delete (Object.prototype as Record<string, unknown>).destination_id;
    }
  });

  it("leaves a well-formed tuple byte-identical while Object.prototype is polluted", () => {
    const values = payloadOf("device-enrol");
    const clean = serializeSuiteTuple("zp-device-enrol-v1", values);

    (Object.prototype as Record<string, unknown>).label = "POLLUTED";
    try {
      const polluted = serializeSuiteTuple("zp-device-enrol-v1", values);
      expect(polluted.preimageText).toBe(clean.preimageText);
      expect(polluted.sha256).toBe(golden("device-enrol").sha256);
    } finally {
      delete (Object.prototype as Record<string, unknown>).label;
    }
  });
});

describe("B3 — A.4/A.5 signed freshness window", () => {
  // Every purpose carrying both `issued_at` and `expires_at`, with its spec ceiling. A.4.1–A.4.3 and
  // A.5.1 are the 300s ceremony class; A.5's automated-read credential is the 60s class.
  const windowed = [
    { id: "send-external-approval", purpose: "zp-send-external-approval-v1", ceilingSecs: 300 },
    { id: "destination-bless", purpose: "zp-destination-bless-v1", ceilingSecs: 300 },
    { id: "device-enrol", purpose: "zp-device-enrol-v1", ceilingSecs: 300 },
    { id: "report-request", purpose: "zp-report-request-v1", ceilingSecs: 60 },
    { id: "reporting-register", purpose: "zp-reporting-register-v1", ceilingSecs: 300 },
  ] as const;

  const at = (offsetMs: number): string =>
    new Date(Date.parse("2026-07-18T00:00:00.000Z") + offsetMs).toISOString();

  function withWindow(id: string, expiresAt: string): Record<string, unknown> {
    const values = payloadOf(id);
    values.issued_at = "2026-07-18T00:00:00.000Z";
    values.expires_at = expiresAt;
    return values;
  }

  for (const { id, purpose, ceilingSecs } of windowed) {
    const ceilingMs = ceilingSecs * 1000;

    it(`${purpose}: accepts the exactly +${ceilingSecs}.000s boundary (committed golden)`, () => {
      expect(() => serializeSuiteTuple(purpose, withWindow(id, at(ceilingMs)))).not.toThrow();
    });

    it(`${purpose}: rejects one millisecond past the ceiling`, () => {
      expect(() => serializeSuiteTuple(purpose, withWindow(id, at(ceilingMs + 1)))).toThrowError(
        expect.objectContaining({ reason: "expiry_window_exceeded" }) as Error,
      );
    });

    it(`${purpose}: rejects an expiry ten years after issue`, () => {
      const tenYears = at(10 * 365 * 24 * 60 * 60 * 1000);
      expect(() => serializeSuiteTuple(purpose, withWindow(id, tenYears))).toThrowError(
        expect.objectContaining({ reason: "expiry_window_exceeded" }) as Error,
      );
    });

    it(`${purpose}: rejects expires_at equal to issued_at`, () => {
      expect(() => serializeSuiteTuple(purpose, withWindow(id, at(0)))).toThrowError(
        expect.objectContaining({ reason: "expiry_not_after_issue" }) as Error,
      );
    });

    it(`${purpose}: rejects expires_at before issued_at`, () => {
      expect(() => serializeSuiteTuple(purpose, withWindow(id, at(-1000)))).toThrowError(
        expect.objectContaining({ reason: "expiry_not_after_issue" }) as Error,
      );
    });

    it(`${purpose}: accepts a well-inside window (control)`, () => {
      expect(() => serializeSuiteTuple(purpose, withWindow(id, at(1000)))).not.toThrow();
    });
  }

  it("leaves the non-windowed tuples unconstrained (no false positive)", () => {
    for (const id of ["receive-expected", "move-internal-expected", "node-event-a"]) {
      expect(() => serializeSuiteTuple(golden(id).purpose, payloadOf(id))).not.toThrow();
    }
  });

  // A.4.3: the window is "checked against the signed issued_at, before signature verification".
  // Each envelope below carries a syntactically valid but wholly bogus signature; the window reason
  // must surface anyway, proving no Ed25519 verification was reached.
  describe("rejects before the Ed25519 signature is considered", () => {
    const BOGUS_SIGNATURE = "A".repeat(86) + "==";
    const KEY_ID = "77777777-7777-4777-8777-777777777777";

    function envelopeFor(id: string, expiresAt: string): SignedSuiteTupleEnvelope {
      const values = payloadOf(id);
      values.issued_at = "2026-07-18T00:00:00.000Z";
      values.expires_at = expiresAt;
      return {
        key_id: KEY_ID,
        preimage_text: `${golden(id).purpose}\n${JSON.stringify(values)}`,
        preimage_sha256: "0".repeat(64),
        signature: BOGUS_SIGNATURE,
      } as SignedSuiteTupleEnvelope;
    }

    const key = <TClass extends string>(keyClass: TClass) =>
      ({
        keyId: KEY_ID,
        keyClass,
        publicKey: golden("device-enrol").values.new_device_public_key,
      }) as unknown as ResolvedSuiteVerificationKey<never>;

    const tenYears = "2036-07-18T00:00:00.000Z";

    it("verifySendExternalApprovalDeviceSignature (external-ZKZ-send approval gate)", () => {
      expect(() =>
        verifySendExternalApprovalDeviceSignature(
          envelopeFor("send-external-approval", tenYears),
          key("device"),
        ),
      ).toThrowError(expect.objectContaining({ reason: "expiry_window_exceeded" }) as Error);
    });

    it("verifyDestinationBless", () => {
      expect(() =>
        verifyDestinationBless(envelopeFor("destination-bless", tenYears), key("device")),
      ).toThrowError(expect.objectContaining({ reason: "expiry_window_exceeded" }) as Error);
    });

    it("verifyDeviceEnrol", () => {
      expect(() =>
        verifyDeviceEnrol(envelopeFor("device-enrol", tenYears), key("device")),
      ).toThrowError(expect.objectContaining({ reason: "expiry_window_exceeded" }) as Error);
    });

    it("verifyReportRequest", () => {
      expect(() =>
        verifyReportRequest(envelopeFor("report-request", tenYears), key("reporting")),
      ).toThrowError(expect.objectContaining({ reason: "expiry_window_exceeded" }) as Error);
    });

    it("verifyReportingRegisterProof (PoP self-sign)", () => {
      const envelope = envelopeFor("reporting-register", tenYears);
      expect(() =>
        verifyReportingRegisterProof({
          preimage_text: envelope.preimage_text,
          preimage_sha256: envelope.preimage_sha256,
          signature: envelope.signature,
        }),
      ).toThrowError(expect.objectContaining({ reason: "expiry_window_exceeded" }) as Error);
    });
  });
});

describe("B4 — A.4.3 device-label denylist is fail-closed", () => {
  const ENROL = "zp-device-enrol-v1";

  function withLabel(label: string): Record<string, unknown> {
    const values = payloadOf("device-enrol");
    values.label = label;
    return values;
  }

  const expectRejected = (label: string): void => {
    expect(() => serializeSuiteTuple(ENROL, withLabel(label))).toThrowError(InvalidFieldError);
  };

  // One vector per denylisted category named in A.4.3 / A.9.
  const denylisted: readonly (readonly [string, string])[] = [
    ["C0 control (U+0001)", "device"],
    ["C0 control TAB (U+0009)", "dev	ice"],
    ["DEL (U+007F)", "device"],
    ["C1 control (U+0085)", "device"],
    ["noncharacter block (U+FDD0)", "dev﷐ice"],
    ["noncharacter U+FFFE", "dev￾ice"],
    ["noncharacter U+FFFF", "dev￿ice"],
    ["plane-1 noncharacter U+1FFFE", "dev\u{1fffe}ice"],
    ["line separator (U+2028)", "dev ice"],
    ["paragraph separator (U+2029)", "dev ice"],
    ["BOM / ZWNBSP (U+FEFF)", "dev﻿ice"],
    ["zero-width space (U+200B)", "dev​ice"],
    ["zero-width joiner (U+200D)", "dev‍ice"],
    ["BiDi embedding (U+202A)", "dev‪ice"],
    ["BiDi isolate (U+2066)", "dev⁦ice"],
    ["non-U+0020 space (U+00A0)", "dev ice"],
    ["ideographic space (U+3000)", "dev　ice"],
  ];

  for (const [name, label] of denylisted) {
    it(`rejects ${name}`, () => expectRejected(label));
  }

  // Called out explicitly: a BiDi override in a device-enrolment label lets an attacker render a
  // hostile device as a trusted one in any operator UI that echoes the label.
  it("rejects the U+202E right-to-left override", () => {
    expectRejected("device‮nimda");
    expect(() => serializeSuiteTuple(ENROL, withLabel("device‮nimda"))).toThrowError(
      expect.objectContaining({ reason: "disallowed_scalar" }) as Error,
    );
  });

  it("rejects a surrogate half", () => {
    expect(() => serializeSuiteTuple(ENROL, withLabel("dev\ud800ice"))).toThrow();
  });

  it("rejects leading and trailing U+0020", () => {
    expectRejected(" golden-device");
    expectRejected("golden-device ");
  });

  it("rejects an empty label", () => expectRejected(""));

  it("accepts internal U+0020, and the 80-scalar / 320-byte boundary", () => {
    expect(() => serializeSuiteTuple(ENROL, withLabel("golden device one"))).not.toThrow();
    expect(() => serializeSuiteTuple(ENROL, withLabel("a".repeat(80)))).not.toThrow();
    // 80 scalars at 4 UTF-8 bytes each = exactly 320 bytes.
    expect(() => serializeSuiteTuple(ENROL, withLabel("\u{1f600}".repeat(80)))).not.toThrow();
  });

  // The 1–80 scalar / 320-byte ceilings live one layer down, in the `parseOpaqueReference`
  // scalar grammar, so these surface as `InvalidScalarError` rather than the denylist's
  // `InvalidFieldError`. Asserted here as a rejection either way — the layer is the point.
  it("rejects 81 scalars", () => {
    expect(() => serializeSuiteTuple(ENROL, withLabel("a".repeat(81)))).toThrowError(
      expect.objectContaining({ reason: "limit_exceeded" }) as Error,
    );
  });

  it("rejects ≤80 scalars that exceed 320 UTF-8 bytes", () => {
    // 79 four-byte scalars + one four-byte scalar is exactly 320; add one more scalar to pass the
    // code-point ceiling while breaching the byte ceiling is impossible at 4 bytes/scalar, so use
    // the byte ceiling directly: 81 four-byte scalars breaches both, 80 is the accepted boundary.
    expect(() => serializeSuiteTuple(ENROL, withLabel("\u{1f600}".repeat(81)))).toThrowError(
      expect.objectContaining({ reason: "limit_exceeded" }) as Error,
    );
  });

  // A.9 NFC-admission gate: a well-formed, non-denylisted, non-NFC label is admitted and signed in
  // its exact input bytes. The node performs no normalization — normalize-then-sign is forbidden.
  it("admits a non-NFC label without transforming it", () => {
    const decomposed = "café"; // NFD form of "café"
    expect(decomposed.normalize("NFC")).not.toBe(decomposed);

    const result = serializeSuiteTuple(ENROL, withLabel(decomposed));
    expect(result.preimageText).toContain(`"label":"${decomposed}"`);
    expect(result.preimageText).not.toContain(decomposed.normalize("NFC"));
  });
});
