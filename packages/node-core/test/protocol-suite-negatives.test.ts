// Negative vectors. Every serializer-scope canonical fields reject class, plus at least
// one negative per encoding class the task requires (bad tag, truncated length, wrong purpose, wrong
// key class, null-vs-empty confusion; external-serialization is covered in the census test). Each is
// fail-first: the mutated input MUST cause a rejection, never silently serialize.
//
// A.9 items #10–#16 (cross-purpose signature verification, nonce replay, TOTP-as-signature, device +
// TOTP guard, JSONB preimage reconstruction, live-chain key mode) are verifier/policy-layer rejects,
// NOT construction-time rejects — they belong to the parser/verifier slice (.3) and are
// intentionally out of this serializer's scope.
import { describe, expect, it } from "vitest";

import { InvalidScalarError } from "../src/protocol/scalars.js";
import {
  InvalidFieldError,
  SuiteSerializeError,
  keyClassForPurpose,
  mayKeyClassSign,
  serializeSuiteTuple,
} from "../src/protocol/suite/index.js";
import { SUITE_GOLDENS } from "./__vectors__/suite-appendix-a.js";

// Accepts either a golden id ("receive-expected") or a purpose literal ("zp-receive-expected-v1");
// for a purpose shared by two goldens (node-event) the first (golden A) is returned.
function valuesOf(key: string): Record<string, unknown> {
  const golden = SUITE_GOLDENS.find((g) => g.id === key || g.purpose === key);
  if (golden === undefined) throw new Error(`no golden fixture ${key}`);
  return { ...golden.values };
}

function captureError(fn: () => unknown): Error {
  try {
    fn();
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected the call to throw, but it returned normally");
}

const RECEIVE = "zp-receive-expected-v1";
const REGISTER = "zp-reporting-register-v1";
const EVENT = "zp-node-event-v1";
const FINGERPRINT = "zp-wallet-head-fingerprint-v1";

describe("negatives — field-tag / presence class (A.9 #1)", () => {
  it("rejects a missing field", () => {
    const values = valuesOf(RECEIVE);
    delete values.node_id;
    const error = captureError(() => serializeSuiteTuple(RECEIVE, values));
    expect(error).toBeInstanceOf(SuiteSerializeError);
    expect((error as SuiteSerializeError).reason).toBe("missing_field");
  });

  it("rejects an unexpected field (bad tag)", () => {
    const error = captureError(() => serializeSuiteTuple(RECEIVE, { ...valuesOf(RECEIVE), evil_extra: "x" }));
    expect(error).toBeInstanceOf(SuiteSerializeError);
    expect((error as SuiteSerializeError).reason).toBe("unexpected_field");
  });

  it("rejects a nullable field OMITTED instead of present-as-null (A.1.1 rule 7)", () => {
    const values = valuesOf(RECEIVE);
    delete values.expiry_unix_time_secs;
    const error = captureError(() => serializeSuiteTuple(RECEIVE, values));
    expect(error).toBeInstanceOf(SuiteSerializeError);
    expect((error as SuiteSerializeError).reason).toBe("missing_field");
  });

  it("normalizes caller key order to the frozen schema order (a reorder cannot be emitted)", () => {
    const values = valuesOf(RECEIVE);
    const scrambled: Record<string, unknown> = {};
    for (const key of Object.keys(values).reverse()) scrambled[key] = values[key];
    const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected");
    expect(serializeSuiteTuple(RECEIVE, scrambled).preimageText).toBe(golden?.preimageText);
  });
});

describe("negatives — versioned-purpose dispatch class (A.9 #2, #3)", () => {
  it("rejects an unregistered purpose", () => {
    const error = captureError(() => serializeSuiteTuple("zp-not-a-real-purpose-v1", {}));
    expect(error).toBeInstanceOf(SuiteSerializeError);
    expect((error as SuiteSerializeError).reason).toBe("unknown_purpose");
  });

  it("rejects a prefix/payload purpose mismatch (dispatch purpose != field 1)", () => {
    const values = { ...valuesOf(RECEIVE), purpose: "zp-send-external-expected-v1" };
    const error = captureError(() => serializeSuiteTuple(RECEIVE, values));
    expect(error).toBeInstanceOf(InvalidFieldError);
    expect((error as InvalidFieldError).reason).toBe("invalid_enum");
  });

  it("rejects canonical_version as the string \"1\"", () => {
    const error = captureError(() => serializeSuiteTuple(RECEIVE, { ...valuesOf(RECEIVE), canonical_version: "1" }));
    expect(error).toBeInstanceOf(InvalidScalarError);
  });

  it("rejects canonical_version other than the number 1", () => {
    expect(() => serializeSuiteTuple(RECEIVE, { ...valuesOf(RECEIVE), canonical_version: 2 })).toThrow();
  });
});

describe("negatives — scalar class (A.9 #4, #5, #6, #7)", () => {
  it("rejects a non-canonical (uppercase) UUID", () => {
    expect(() => serializeSuiteTuple(RECEIVE, { ...valuesOf(RECEIVE), node_id: "11111111-1111-4111-8111-11111111111A" })).toThrow(
      InvalidScalarError,
    );
  });

  it("rejects an unpadded / truncated public key (length class)", () => {
    // Drop the trailing "=" → 43 chars, no longer canonical padded base64url.
    expect(() =>
      serializeSuiteTuple(RECEIVE, { ...valuesOf(RECEIVE), receiver_pubkey: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E" }),
    ).toThrow(InvalidScalarError);
  });

  it("rejects an amount given as a JSON number (not a canonical string)", () => {
    expect(() => serializeSuiteTuple(RECEIVE, { ...valuesOf(RECEIVE), amount_zkz: 2.25 })).toThrow(InvalidScalarError);
  });

  it("rejects an amount with a leading zero, an exponent, a sign, a trailing zero, and >32 decimals", () => {
    for (const bad of ["02.25", "2.25e0", "-2.25", "2.250", `0.${"0".repeat(32)}1`]) {
      expect(() => serializeSuiteTuple(RECEIVE, { ...valuesOf(RECEIVE), amount_zkz: bad })).toThrow(InvalidScalarError);
    }
  });

  it("rejects a timestamp without exactly three fractional digits or without Z", () => {
    for (const bad of ["2026-07-18T00:00:00Z", "2026-07-18T00:00:00.00Z", "2026-07-18T00:00:00.000", "2026-13-45T00:00:00.000Z"]) {
      expect(() => serializeSuiteTuple("zp-send-external-approval-v1", { ...valuesOf("send-external-approval"), issued_at: bad })).toThrow(
        InvalidFieldError,
      );
    }
  });
});

describe("negatives — null-vs-empty confusion class", () => {
  it("rejects an empty string where a nullable UUID must be JSON null (\"\" != null)", () => {
    const error = captureError(() => serializeSuiteTuple(REGISTER, { ...valuesOf("reporting-register"), supersedes_key_id: "" }));
    expect(error).toBeInstanceOf(InvalidScalarError);
  });

  it("rejects JSON null where the empty-string sentinel is required (p_signature is \"\", never null)", () => {
    const error = captureError(() => serializeSuiteTuple(FINGERPRINT, { ...valuesOf("wallet-head-fingerprint"), p_signature: null }));
    expect(error).toBeInstanceOf(SuiteSerializeError);
    expect((error as SuiteSerializeError).reason).toBe("null_not_allowed");
  });

  it("accepts the empty-string sentinel where the field permits it (p_signature \"\")", () => {
    expect(serializeSuiteTuple(FINGERPRINT, valuesOf("wallet-head-fingerprint")).preimageText).toContain('"p_signature":""');
  });

  it("rejects an empty string where a nullable SHA-256 must be JSON null (previous_event_hash)", () => {
    expect(() => serializeSuiteTuple(EVENT, { ...valuesOf("node-event-a"), previous_event_hash: "" })).toThrow(InvalidScalarError);
  });
});

// A.9 negative vector 1 ("optional field omitted instead of null") tested against the
// frozen GENESIS bytes published at A.8.2. The genesis null triple is the one place in the
// suite where three fields are simultaneously null, so it is the sharpest omitted-vs-null fixture.
describe("negatives — A.7 GENESIS null-triple class (A.9 #1)", () => {
  const GENESIS = "wallet-head-fingerprint-genesis";
  const NULL_TRIPLE = ["inner_sha256", "step_1_signature", "step_2_signature"] as const;

  it("emits the genesis null triple as JSON null (positive control)", () => {
    const text = serializeSuiteTuple(FINGERPRINT, valuesOf(GENESIS)).preimageText;
    for (const field of NULL_TRIPLE) expect(text).toContain(`"${field}":null`);
  });

  it("rejects each null-triple field OMITTED instead of present-as-null", () => {
    for (const field of NULL_TRIPLE) {
      const values = valuesOf(GENESIS);
      delete values[field];
      const error = captureError(() => serializeSuiteTuple(FINGERPRINT, values));
      expect(error, field).toBeInstanceOf(SuiteSerializeError);
      expect((error as SuiteSerializeError).reason, field).toBe("missing_field");
    }
  });

  it("rejects each null-triple field given as \"\" instead of JSON null", () => {
    for (const field of NULL_TRIPLE) {
      expect(() => serializeSuiteTuple(FINGERPRINT, { ...valuesOf(GENESIS), [field]: "" }), field).toThrow(InvalidScalarError);
    }
  });

  it("rejects the genesis state signatures given as null instead of the \"\" sentinel", () => {
    for (const field of ["s_signature", "p_signature"] as const) {
      const error = captureError(() => serializeSuiteTuple(FINGERPRINT, { ...valuesOf(GENESIS), [field]: null }));
      expect(error, field).toBeInstanceOf(SuiteSerializeError);
      expect((error as SuiteSerializeError).reason, field).toBe("null_not_allowed");
    }
  });
});

describe("negatives — key-class dispatch class", () => {
  it("maps each purpose to exactly its signing key class", () => {
    expect(keyClassForPurpose(RECEIVE)).toBe("node_identity");
    expect(keyClassForPurpose("zp-send-external-approval-v1")).toBe("device");
    expect(keyClassForPurpose(REGISTER)).toBe("reporting");
    expect(keyClassForPurpose(EVENT)).toBe("node_event");
    expect(keyClassForPurpose(FINGERPRINT)).toBe("unsigned");
    expect(keyClassForPurpose("zp-not-real")).toBeUndefined();
  });

  it("refuses a signer of the wrong key class (cross-class signing blocked)", () => {
    expect(mayKeyClassSign(RECEIVE, "node_identity")).toBe(true);
    expect(mayKeyClassSign(RECEIVE, "reporting")).toBe(false);
    expect(mayKeyClassSign(RECEIVE, "device")).toBe(false);
    // The unsigned fingerprint is never signable by any class.
    expect(mayKeyClassSign(FINGERPRINT, "node_identity")).toBe(false);
    // An unknown purpose is never signable.
    expect(mayKeyClassSign("zp-not-real", "node_identity")).toBe(false);
  });
});

describe("negatives — composite (structured value) class", () => {
  it("rejects AfterLanding HOLD carrying a non-null destination_id", () => {
    const error = captureError(() =>
      serializeSuiteTuple(RECEIVE, { ...valuesOf(RECEIVE), after_landing: { kind: "HOLD", destination_id: "66666666-6666-4666-8666-666666666666" } }),
    );
    expect(error).toBeInstanceOf(InvalidFieldError);
    expect((error as InvalidFieldError).reason).toBe("invalid_composite_shape");
  });

  it("rejects an AfterLanding with an extra key", () => {
    expect(() =>
      serializeSuiteTuple(RECEIVE, { ...valuesOf(RECEIVE), after_landing: { kind: "HOLD", destination_id: null, extra: 1 } }),
    ).toThrow(InvalidFieldError);
  });

  it("rejects a SourceSelector with an unknown kind", () => {
    expect(() =>
      serializeSuiteTuple("zp-send-external-expected-v1", { ...valuesOf("send-external-expected"), source_selector: { kind: "POLICY", wallet_id: "55555555-5555-4555-8555-555555555555" } }),
    ).toThrow(InvalidFieldError);
  });
});

describe("negatives — reporting-register additional rejects (A.9 register block)", () => {
  it("rejects supersedes_key_id OMITTED instead of null", () => {
    const values = valuesOf("reporting-register");
    delete values.supersedes_key_id;
    const error = captureError(() => serializeSuiteTuple(REGISTER, values));
    expect(error).toBeInstanceOf(SuiteSerializeError);
    expect((error as SuiteSerializeError).reason).toBe("missing_field");
  });

  it("rejects a wrong-length new_reporting_public_key", () => {
    expect(() => serializeSuiteTuple(REGISTER, { ...valuesOf("reporting-register"), new_reporting_public_key: "AAAA=" })).toThrow(
      InvalidScalarError,
    );
  });
});

describe("no-normalization + no-appended-whitespace (A.9 #8, #9)", () => {
  it("never appends a trailing newline or surrounding whitespace to the preimage", () => {
    for (const golden of SUITE_GOLDENS) {
      const { preimageText } = serializeSuiteTuple(golden.purpose, golden.values);
      expect(preimageText).toBe(preimageText.trim());
      expect(preimageText.endsWith("\n")).toBe(false);
    }
  });

  it("preserves exact UTF-8 code points in a string field (never NFC/NFD normalizes)", () => {
    // NFD "e" + combining acute (U+0065 U+0301). The serializer must emit it verbatim and MUST NOT
    // fold it to the NFC precomposed U+00E9. Built via char codes so the source stays pure ASCII and
    // the two forms are unambiguous.
    const decomposedNfd = `e${String.fromCharCode(0x0301)}`;
    const precomposedNfc = String.fromCharCode(0x00e9);
    const { preimageText } = serializeSuiteTuple("zp-device-enrol-v1", { ...valuesOf("device-enrol"), label: decomposedNfd });
    expect(preimageText.includes(decomposedNfd)).toBe(true);
    expect(preimageText.includes(precomposedNfc)).toBe(false);
  });
});
