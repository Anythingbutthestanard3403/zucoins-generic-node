// Strict parser round-trip and canonical fields negative coverage across all 10
// registered purposes (not split into a "public barrel" vs. an "off-barrel" set the way @
// fd328e897255 organized it — this module has no barrel exclusion, so one parametrized matrix covers
// every purpose, folding 's off-barrel battery for report-request/device-enrol/node-event in
// rather than porting it as a separate file).
import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import {
  parseDestinationBless,
  parseDeviceEnrol,
  parseMoveInternalExpectedArtifact,
  parseNodeEvent,
  parseReceiveExpectedArtifact,
  parseReportRequest,
  parseReportingRegister,
  parseSendExternalApproval,
  parseSendExternalExpectedArtifact,
  parseWalletHeadFingerprint,
  SuiteParseError,
} from "../src/protocol/suite/parsers.js";
import { InvalidFieldError } from "../src/protocol/suite/encoders.js";
import { SuiteSerializeError } from "../src/protocol/suite/serialize.js";
import { InvalidScalarError } from "../src/protocol/scalars.js";
import { SUITE_GOLDENS, type SuiteGoldenVector } from "./__vectors__/suite-appendix-a.js";

type Parser = (source: string | Uint8Array) => { readonly payload: unknown; readonly preimageText: string; readonly sha256: string };

const PARSER_BY_ID: Record<string, Parser> = {
  "receive-expected": parseReceiveExpectedArtifact as Parser,
  "move-internal-expected": parseMoveInternalExpectedArtifact as Parser,
  "send-external-expected": parseSendExternalExpectedArtifact as Parser,
  "send-external-approval": parseSendExternalApproval as Parser,
  "destination-bless": parseDestinationBless as Parser,
  "device-enrol": parseDeviceEnrol as Parser,
  "report-request": parseReportRequest as Parser,
  "reporting-register": parseReportingRegister as Parser,
  "node-event-a": parseNodeEvent as Parser,
  "node-event-b": parseNodeEvent as Parser,
  "wallet-head-fingerprint": parseWalletHeadFingerprint as Parser,
  // One parser serves both A.7 state_kind variants; GENESIS differs only in field values.
  "wallet-head-fingerprint-genesis": parseWalletHeadFingerprint as Parser,
};

describe("parsers round-trip every A.8.2 golden (string and Uint8Array source)", () => {
  for (const golden of SUITE_GOLDENS) {
    it(`${golden.id}: parses back to the exact preimage and SHA-256`, () => {
      const parser = PARSER_BY_ID[golden.id] as Parser;
      const fromString = parser(golden.preimageText);
      expect(fromString.preimageText).toBe(golden.preimageText);
      expect(fromString.sha256).toBe(golden.sha256);
      const fromBytes = parser(Buffer.from(golden.preimageText, "utf8"));
      expect(fromBytes.preimageText).toBe(golden.preimageText);
      expect(fromBytes.sha256).toBe(golden.sha256);
    });
  }
});

function payloadOf(golden: SuiteGoldenVector): Record<string, unknown> {
  return JSON.parse(golden.preimageText.slice(golden.preimageText.indexOf("\n") + 1)) as Record<string, unknown>;
}

function sourceOf(purpose: string, payload: Record<string, unknown>): string {
  return `${purpose}\n${JSON.stringify(payload)}`;
}

describe("negatives — A.9 #1, #2, #3, #8: framing and dispatch mutations, every purpose", () => {
  for (const golden of SUITE_GOLDENS) {
    it(`${golden.id}: rejects BOM, trailing LF, CRLF separator, purpose mismatch, reordered fields, extra field, and missing field`, () => {
      const parser = PARSER_BY_ID[golden.id] as Parser;
      const payload = payloadOf(golden);
      const entries = Object.entries(payload);
      const reordered = Object.fromEntries([entries[1], entries[0], ...entries.slice(2)].filter((e): e is [string, unknown] => e !== undefined));
      const missing = { ...payload };
      delete missing[Object.keys(missing)[2] ?? "node_id"];
      const mutations: readonly string[] = [
        `\uFEFF${golden.preimageText}`,
        `${golden.preimageText}\n`,
        golden.preimageText.replace("\n{", "\r\n{"),
        sourceOf(golden.purpose, { ...payload, purpose: `${golden.purpose}-wrong` }),
        sourceOf(golden.purpose, reordered),
        sourceOf(golden.purpose, { ...payload, unexpected_field: "x" }),
        sourceOf(golden.purpose, missing),
      ];
      for (const mutation of mutations) expect(() => parser(mutation)).toThrow();
    });
  }
});

describe("negatives — A.9 #1: nullable field omitted instead of present-as-null", () => {
  it("receive-expected: omitting expiry_unix_time_secs is rejected (must be JSON null, never absent)", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected") as SuiteGoldenVector;
    const payload = payloadOf(golden);
    delete payload.expiry_unix_time_secs;
    expect(() => parseReceiveExpectedArtifact(sourceOf(golden.purpose, payload))).toThrow(SuiteSerializeError);
  });

  it("node-event-b: omitting wallet_id (already null) is rejected the same way", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "node-event-b") as SuiteGoldenVector;
    const payload = payloadOf(golden);
    delete payload.wallet_id;
    expect(() => parseNodeEvent(sourceOf(golden.purpose, payload))).toThrow(SuiteSerializeError);
  });
});

describe("negatives — A.9 #3: canonical_version wrong type or wrong value", () => {
  const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected") as SuiteGoldenVector;

  it("rejects canonical_version as the string \"1\"", () => {
    const payload = { ...payloadOf(golden), canonical_version: "1" };
    expect(() => parseReceiveExpectedArtifact(sourceOf(golden.purpose, payload))).toThrow(InvalidScalarError);
  });

  it("rejects canonical_version as 2", () => {
    const payload = { ...payloadOf(golden), canonical_version: 2 };
    expect(() => parseReceiveExpectedArtifact(sourceOf(golden.purpose, payload))).toThrow();
  });
});

describe("negatives — malformed UTF-8 and lone surrogates are rejected before JSON.parse", () => {
  it("rejects an invalid UTF-8 byte sequence in a Uint8Array source", () => {
    const prefix = Buffer.from("zp-receive-expected-v1\n", "utf8");
    const invalid = Buffer.concat([prefix, Buffer.from([0xc3, 0x28])]);
    expect(() => parseReceiveExpectedArtifact(invalid)).toThrow(SuiteParseError);
    expect(() => parseReceiveExpectedArtifact(invalid)).toThrowError(
      expect.objectContaining({ reason: "invalid_utf8" }) as Error,
    );
  });

  // L826 / Dec.2: "overlong encoding" is a DISTINCT malformed-UTF-8 reject class,
  // separate from the truncated/invalid-continuation sequence above and the lone surrogate below. Bytes
  // 0xC0 0xAF are the overlong 2-byte encoding of U+002F "/", a code point that MUST encode in one byte;
  // the fatal WHATWG decoder in the shared wire parser (parseSuitePurpose → decodeStrict) rejects it
  // before JSON.parse or any label predicate runs. Injected at the start of the zp-device-enrol-v1
  // `label` value so this is a genuine device-enrol label byte source, not a bare framing vector.
  it("rejects an overlong UTF-8 encoding in a zp-device-enrol-v1 label byte source", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "device-enrol") as SuiteGoldenVector;
    const marker = '"label":"';
    const at = golden.preimageText.indexOf(marker) + marker.length;
    const overlongSolidus = Buffer.from([0xc0, 0xaf]);
    const source = Buffer.concat([
      Buffer.from(golden.preimageText.slice(0, at), "utf8"),
      overlongSolidus,
      Buffer.from(golden.preimageText.slice(at), "utf8"),
    ]);
    expect(() => parseDeviceEnrol(source)).toThrow(SuiteParseError);
    expect(() => parseDeviceEnrol(source)).toThrowError(
      expect.objectContaining({ reason: "invalid_utf8" }) as Error,
    );
  });

  // L826 / Dec.2: "a lone surrogate" is the THIRD distinct malformed-UTF-8 reject
  // and MUST be a BYTE-level vector — the byte-decode path, NOT a JS-string scalar through serialize.
  // Bytes 0xED 0xA0 0x80 are the raw UTF-8-shaped encoding of a lone high surrogate (U+D800), which the
  // Unicode/WHATWG spec forbids; the fatal decoder rejects 0xED in the surrogate range at the Uint8Array
  // path (decodeStrict), before JSON.parse or any label/scalar predicate. Injected into the device-enrol
  // `label` value. This is the byte class; the scalar denylist (U+D800 as a JS-string scalar) is a
  // SEPARATE reject exercised via the serialize path elsewhere.
  it("rejects a lone surrogate byte sequence in a zp-device-enrol-v1 label byte source", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "device-enrol") as SuiteGoldenVector;
    const marker = '"label":"';
    const at = golden.preimageText.indexOf(marker) + marker.length;
    const loneHighSurrogate = Buffer.from([0xed, 0xa0, 0x80]);
    const source = Buffer.concat([
      Buffer.from(golden.preimageText.slice(0, at), "utf8"),
      loneHighSurrogate,
      Buffer.from(golden.preimageText.slice(at), "utf8"),
    ]);
    expect(() => parseDeviceEnrol(source)).toThrow(SuiteParseError);
    expect(() => parseDeviceEnrol(source)).toThrowError(
      expect.objectContaining({ reason: "invalid_utf8" }) as Error,
    );
  });

  it("rejects a lone high surrogate embedded in a string source", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected") as SuiteGoldenVector;
    expect(() => parseReceiveExpectedArtifact(`${golden.preimageText}\ud800`)).toThrow(SuiteParseError);
  });

  it("rejects a lone low surrogate embedded in a string source", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected") as SuiteGoldenVector;
    expect(() => parseReceiveExpectedArtifact(`\udc00${golden.preimageText}`)).toThrow(SuiteParseError);
  });

  it("rejects a non-Uint8Array, non-string source", () => {
    expect(() => parseReceiveExpectedArtifact(12345 as unknown as string)).toThrow(SuiteParseError);
  });
});

describe("negatives — composite and scalar mutations surface through the parser", () => {
  it("rejects an AfterLanding HOLD carrying a non-null destination_id", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected") as SuiteGoldenVector;
    const payload = { ...payloadOf(golden), after_landing: { kind: "HOLD", destination_id: "66666666-6666-4666-8666-666666666666" } };
    expect(() => parseReceiveExpectedArtifact(sourceOf(golden.purpose, payload))).toThrow(InvalidFieldError);
  });

  it("rejects an unpadded public key", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected") as SuiteGoldenVector;
    const payload = { ...payloadOf(golden), receiver_pubkey: String(payloadOf(golden).receiver_pubkey).replace(/=+$/, "") };
    expect(() => parseReceiveExpectedArtifact(sourceOf(golden.purpose, payload))).toThrow(InvalidScalarError);
  });

  it("rejects a non-canonical (uppercase) UUID", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected") as SuiteGoldenVector;
    const payload = { ...payloadOf(golden), node_id: "11111111-1111-4111-8111-11111111111A" };
    expect(() => parseReceiveExpectedArtifact(sourceOf(golden.purpose, payload))).toThrow(InvalidScalarError);
  });
});

describe("negatives — a non-canonical JSON spelling that still round-trips to the same value", () => {
  it("rejects canonical_version written as 1.0 (parses to the same number, different source bytes)", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected") as SuiteGoldenVector;
    const mutated = golden.preimageText.replace('"canonical_version":1,', '"canonical_version":1.0,');
    expect(() => parseReceiveExpectedArtifact(mutated)).toThrow(SuiteParseError);
  });

  it("rejects a space after the opening brace (valid JSON, non-canonical bytes)", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected") as SuiteGoldenVector;
    const mutated = golden.preimageText.replace('{"purpose":', '{ "purpose":');
    expect(() => parseReceiveExpectedArtifact(mutated)).toThrow(SuiteParseError);
  });
});
