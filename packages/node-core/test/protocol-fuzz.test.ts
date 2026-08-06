// property-based fuzz coverage for the protocol suite parsers and
// the SplitChain inner digest. Targets: all 10 registered suite parsers (parsers.ts),
// computeInnerDigest (inner.ts). DECODE-only — never re-signs or constructs signed material.
// The byte-exact signing rule: byte-exact JSON.stringify identity asserted on round-trips.
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { computeInnerDigest, type SplitChainInnerV2 } from "../src/protocol/inner.js";
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
} from "../src/protocol/suite/parsers.js";
import { SUITE_GOLDENS } from "./__vectors__/suite-appendix-a.js";

const NUM_RUNS = 500;
const HEX_64 = /^[0-9a-f]{64}$/;

type ParserFn = (source: string | Uint8Array) => {
  readonly payload: unknown;
  readonly preimageText: string;
  readonly sha256: string;
};

const ALL_PARSERS: readonly [string, string, ParserFn][] = [
  ["parseReceiveExpectedArtifact", "zp-receive-expected-v1", parseReceiveExpectedArtifact as ParserFn],
  ["parseMoveInternalExpectedArtifact", "zp-move-internal-expected-v1", parseMoveInternalExpectedArtifact as ParserFn],
  ["parseSendExternalExpectedArtifact", "zp-send-external-expected-v1", parseSendExternalExpectedArtifact as ParserFn],
  ["parseSendExternalApproval", "zp-send-external-approval-v1", parseSendExternalApproval as ParserFn],
  ["parseDestinationBless", "zp-destination-bless-v1", parseDestinationBless as ParserFn],
  ["parseDeviceEnrol", "zp-device-enrol-v1", parseDeviceEnrol as ParserFn],
  ["parseReportRequest", "zp-report-request-v1", parseReportRequest as ParserFn],
  ["parseReportingRegister", "zp-reporting-register-v1", parseReportingRegister as ParserFn],
  ["parseNodeEvent", "zp-node-event-v1", parseNodeEvent as ParserFn],
  ["parseWalletHeadFingerprint", "zp-wallet-head-fingerprint-v1", parseWalletHeadFingerprint as ParserFn],
];

describe("protocol suite parsers totality — never crash on arbitrary input", () => {
  for (const [name, , parser] of ALL_PARSERS) {
    it(`${name}: arbitrary strings yield a typed result or throw Error, never crash`, () => {
      fc.assert(
        fc.property(fc.string({ maxLength: 2048 }), (input) => {
          try {
            parser(input);
          } catch (error: unknown) {
            expect(error).toBeInstanceOf(Error);
          }
        }),
        { numRuns: NUM_RUNS },
      );
    });

    it(`${name}: arbitrary bytes yield a typed result or throw Error, never crash`, () => {
      fc.assert(
        fc.property(fc.uint8Array({ maxLength: 4096 }), (bytes) => {
          try {
            parser(bytes);
          } catch (error: unknown) {
            expect(error).toBeInstanceOf(Error);
          }
        }),
        { numRuns: NUM_RUNS },
      );
    });
  }
});

describe("protocol suite parsers — JSON-shaped adversarial input", () => {
  for (const [name, purpose, parser] of ALL_PARSERS) {
    it(`${name}: arbitrary JSON objects with purpose prefix never crash`, () => {
      fc.assert(
        fc.property(fc.jsonValue(), (value) => {
          const source = `${purpose}\n${JSON.stringify(value)}`;
          try {
            parser(source);
          } catch (error: unknown) {
            expect(error).toBeInstanceOf(Error);
          }
        }),
        { numRuns: NUM_RUNS },
      );
    });
  }
});

describe("protocol suite parsers — round-trip byte identity", () => {
  for (const golden of SUITE_GOLDENS) {
    it(`${golden.id}: parse(preimageText) yields exact preimage and sha256`, () => {
      const parserEntry = ALL_PARSERS.find(([parserName]) => {
        const goldenToParser: Record<string, string> = {
          "receive-expected": "parseReceiveExpectedArtifact",
          "move-internal-expected": "parseMoveInternalExpectedArtifact",
          "send-external-expected": "parseSendExternalExpectedArtifact",
          "send-external-approval": "parseSendExternalApproval",
          "destination-bless": "parseDestinationBless",
          "device-enrol": "parseDeviceEnrol",
          "report-request": "parseReportRequest",
          "reporting-register": "parseReportingRegister",
          "node-event-a": "parseNodeEvent",
          "node-event-b": "parseNodeEvent",
          "wallet-head-fingerprint": "parseWalletHeadFingerprint",
          "wallet-head-fingerprint-genesis": "parseWalletHeadFingerprint",
        };
        return parserName === goldenToParser[golden.id];
      });
      if (parserEntry === undefined) return;
      const parser = parserEntry[2];
      const result = parser(golden.preimageText);
      expect(result.preimageText).toBe(golden.preimageText);
      expect(result.sha256).toBe(golden.sha256);
      expect(JSON.stringify(result.payload)).toBe(
        JSON.stringify(JSON.parse(golden.preimageText.slice(golden.preimageText.indexOf("\n") + 1))),
      );
    });

    it(`${golden.id}: Uint8Array source yields identical result to string source`, () => {
      const parserEntry = ALL_PARSERS.find(([parserName]) => {
        const goldenToParser: Record<string, string> = {
          "receive-expected": "parseReceiveExpectedArtifact",
          "move-internal-expected": "parseMoveInternalExpectedArtifact",
          "send-external-expected": "parseSendExternalExpectedArtifact",
          "send-external-approval": "parseSendExternalApproval",
          "destination-bless": "parseDestinationBless",
          "device-enrol": "parseDeviceEnrol",
          "report-request": "parseReportRequest",
          "reporting-register": "parseReportingRegister",
          "node-event-a": "parseNodeEvent",
          "node-event-b": "parseNodeEvent",
          "wallet-head-fingerprint": "parseWalletHeadFingerprint",
          "wallet-head-fingerprint-genesis": "parseWalletHeadFingerprint",
        };
        return parserName === goldenToParser[golden.id];
      });
      if (parserEntry === undefined) return;
      const parser = parserEntry[2];
      const fromString = parser(golden.preimageText);
      const fromBytes = parser(Buffer.from(golden.preimageText, "utf8"));
      expect(fromBytes.preimageText).toBe(fromString.preimageText);
      expect(fromBytes.sha256).toBe(fromString.sha256);
    });
  }
});

describe("protocol suite parsers — truncation battery", () => {
  for (const golden of SUITE_GOLDENS.slice(0, 3)) {
    it(`${golden.id}: slicing at every byte position yields Error, never crash`, () => {
      const parserEntry = ALL_PARSERS.find(([parserName]) => {
        const goldenToParser: Record<string, string> = {
          "receive-expected": "parseReceiveExpectedArtifact",
          "move-internal-expected": "parseMoveInternalExpectedArtifact",
          "send-external-expected": "parseSendExternalExpectedArtifact",
        };
        return parserName === goldenToParser[golden.id];
      });
      if (parserEntry === undefined) return;
      const parser = parserEntry[2];
      const bytes = Buffer.from(golden.preimageText, "utf8");
      for (let cut = 0; cut < bytes.length; cut += 1) {
        const truncated = bytes.subarray(0, cut);
        try {
          parser(truncated);
        } catch (error: unknown) {
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  }
});

describe("computeInnerDigest — totality and determinism", () => {
  const baseInner: SplitChainInnerV2 = {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: "1784332800.125",
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
    step_2_key_public__base64urlsafe: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
    step_1_state: { amount: "7.75" },
    step_2_state: { amount: "2.25" },
    previous_step_1_state_signature: "",
    previous_step_2_state_signature: "",
  };

  it("always returns a 64-char lowercase hex digest for valid inner shapes", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 64 }), (amount) => {
        const inner: SplitChainInnerV2 = {
          ...baseInner,
          step_1_state: { amount: amount || "0" },
        };
        const digest = computeInnerDigest(inner);
        expect(digest).toMatch(HEX_64);
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it("is deterministic: distinct-but-equal objects produce the same digest", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 32 }), (message) => {
        const inner1: SplitChainInnerV2 = message
          ? { ...baseInner, message }
          : baseInner;
        // Reconstruct a distinct object with identical field values (not the same reference).
        const inner2: SplitChainInnerV2 = JSON.parse(JSON.stringify(inner1));
        expect(inner2).not.toBe(inner1);
        expect(computeInnerDigest(inner2)).toBe(computeInnerDigest(inner1));
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it("byte-exact: digest equals independent SHA-256 of JSON.stringify(inner)", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 64 }), (amount) => {
        const inner: SplitChainInnerV2 = {
          ...baseInner,
          step_1_state: { amount: amount || "0" },
        };
        const independent = createHash("sha256")
          .update(JSON.stringify(inner), "utf8")
          .digest("hex");
        expect(computeInnerDigest(inner)).toBe(independent);
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it("golden pin: canonical A.8.1 target inner produces the shipped INNER_SHA256", () => {
    // The A.8.1 SplitChain RECEIVE golden (target transaction) inner, whose SHA-256 is pinned
    // as INNER_SHA256 in suite-appendix-a.ts and TARGET_DIGESTS.step_1_sha256 in crypto-goldens.
    const canonicalInner: SplitChainInnerV2 = {
      type: "unique_combinable",
      version: "2",
      unix_time_secs: "1784332800.125",
      signer_steps: 2,
      step_1_signer: "sender",
      step_2_signer: "receiver",
      step_1_key_public__base64urlsafe: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
      step_2_key_public__base64urlsafe: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
      step_1_state: { amount: "7.75" },
      step_2_state: { amount: "2.25" },
      previous_step_1_state_signature:
        "IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==",
      previous_step_2_state_signature: "",
      expiry__unix_time_secs: "1784336400",
      message: "zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3",
    };
    const INNER_SHA256 = "ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51";
    expect(computeInnerDigest(canonicalInner)).toBe(INNER_SHA256);
    // Cross-check with independent SHA-256.
    const independent = createHash("sha256")
      .update(JSON.stringify(canonicalInner), "utf8")
      .digest("hex");
    expect(independent).toBe(INNER_SHA256);
  });
});
