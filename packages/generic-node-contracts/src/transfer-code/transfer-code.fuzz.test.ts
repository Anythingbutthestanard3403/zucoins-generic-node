// the named concern — property-based fuzz coverage for the pure transfer-code codec
// (transfer-code-codec.ts). Decode-only: these targets never re-sign and never touch a signed
// payload's byte path (the byte-exact signing rule) — they only read encoded text back into a value. No network,
// no DB, no key material (CONTRACT_FREEZE). fast-check drives adversarial inputs; every property
// runs at least 500 cases.
//
// The codec rejects malformed input by THROWING (URIError from decodeURIComponent, SyntaxError from
// JSON.parse) rather than returning a typed result, so the totality property here proves the honest
// safety contract: every call terminates and any rejection is a thrown Error instance — never a
// non-Error throw, never a process-level crash. The pure digest/key-sequence helpers are total and
// must never throw at all.
import { Buffer } from "node:buffer";

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { EXECUTION_TIMEOUTS } from "../testkit/executionPolicy.ts";

import {
  assertWireVersion,
  decodeTransferCode,
  encodeTransferCode,
  objectKeySequence,
  sha256Utf8,
  transferCodeSha256,
} from "./transfer-code-codec.ts";
import {
  TRANSFER_CODE_TOP_LEVEL_FIELDS,
  TRANSFER_CODE_TYPES,
  TRANSFER_CODE_WIRE_VERSION,
} from "./transfer-code.contract.ts";

const NUM_RUNS = 500;
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;

// Adversarial text inputs: raw 16-bit code units (includes lone surrogates), arbitrary JSON values
// stringified, arbitrary string dictionaries, and raw bytes lossily decoded — the broadest cheap
// surface for a string parser.
const adversarialText = fc.oneof(
  fc.string({ unit: "binary", maxLength: 4096 }),
  fc.jsonValue().map((value) => JSON.stringify(value)),
  fc.dictionary(fc.string({ maxLength: 16 }), fc.jsonValue()).map((value) => JSON.stringify(value)),
  fc.uint8Array({ maxLength: 4096 }).map((bytes) => Buffer.from(bytes).toString("utf8")),
);

// Runs `thunk` and reports whether it returned or raised. A raised value that is not an Error
// instance is a defect (an uncontrolled throw), so the caller asserts on it directly.
function attempt(thunk: () => unknown): { readonly returned: boolean; readonly thrown: unknown } {
  try {
    thunk();
    return { returned: true, thrown: undefined };
  } catch (error) {
    return { returned: false, thrown: error };
  }
}

// A well-formed receive-code envelope in the frozen top-level field sequence. Every field carries a
// definite JSON value (no undefined), so encode/decode round-trips byte-for-byte.
const validReceiveCode = fc.record({
  version: fc.constant(TRANSFER_CODE_WIRE_VERSION),
  type: fc.constantFrom(...TRANSFER_CODE_TYPES),
  incoming_data: fc.record({
    receiver_key_public__base64urlsafe: fc.string({ unit: "binary", minLength: 8, maxLength: 64 }),
    inner_state_amount: fc.integer({ min: 0, max: 99_999_999 }).map((value) => String(value)),
    expiry__unix_time_secs: fc.integer({ min: 1, max: 99_999_999 }).map((value) => String(value)),
    message: fc.string({ unit: "binary", maxLength: 64 }),
  }),
});

describe("transfer-code codec fuzz — Property A: totality / controlled rejection", { timeout: EXECUTION_TIMEOUTS.fuzz500 }, () => {
  it("decodeTransferCode terminates and only ever raises an Error instance", () => {
    fc.assert(
      fc.property(adversarialText, (input) => {
        const outcome = attempt(() => decodeTransferCode(input));
        if (outcome.returned) return true;
        return outcome.thrown instanceof Error;
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it("transferCodeSha256 is total and always yields 64 lowercase-hex chars", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary", maxLength: 4096 }), (input) => {
        expect(transferCodeSha256(input)).toMatch(SHA256_HEX_PATTERN);
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it("sha256Utf8 is total and always yields 64 lowercase-hex chars", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary", maxLength: 4096 }), (preimage) => {
        expect(sha256Utf8(preimage)).toMatch(SHA256_HEX_PATTERN);
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it("objectKeySequence is total and echoes the own-key sequence of any record", () => {
    fc.assert(
      fc.property(fc.dictionary(fc.string({ maxLength: 16 }), fc.jsonValue()), (record) => {
        expect(objectKeySequence(record)).toEqual(Object.keys(record));
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it("assertWireVersion either accepts the frozen version or raises an Error", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (version) => {
        const outcome = attempt(() => assertWireVersion({ version }));
        if (version === TRANSFER_CODE_WIRE_VERSION) return outcome.returned;
        return !outcome.returned && outcome.thrown instanceof Error;
      }),
      { numRuns: NUM_RUNS },
    );
  });
});

describe("transfer-code codec fuzz — Property B: round-trip identity", { timeout: EXECUTION_TIMEOUTS.fuzz500 }, () => {
  it("decode(encode(x)) equals the canonical JSON form of x for any JSON value", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        // JSON itself maps -0 to +0 on a stringify/parse round-trip; compare against that canonical
        // form so the assertion tests the codec, not JSON's own normalization.
        const canonical = JSON.parse(JSON.stringify(value)) as unknown;
        const decoded = decodeTransferCode(encodeTransferCode(value));
        expect(decoded).toEqual(canonical);
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it("round-trip preserves JSON.stringify byte-for-byte", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const decoded = decodeTransferCode(encodeTransferCode(value));
        expect(JSON.stringify(decoded)).toBe(JSON.stringify(value));
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it("re-encoding a decoded value reproduces the exact encoded bytes", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const encoded = encodeTransferCode(value);
        const reencoded = encodeTransferCode(decodeTransferCode(encoded));
        expect(reencoded).toBe(encoded);
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it("a well-formed receive code survives the round-trip with its field sequence intact", () => {
    fc.assert(
      fc.property(validReceiveCode, (code) => {
        const decoded = decodeTransferCode(encodeTransferCode(code)) as Record<string, unknown>;
        expect(decoded).toEqual(code);
        expect(Object.keys(decoded)).toEqual([...TRANSFER_CODE_TOP_LEVEL_FIELDS]);
        expect(() => assertWireVersion(decoded)).not.toThrow();
      }),
      { numRuns: NUM_RUNS },
    );
  });
});

describe("transfer-code codec fuzz — Property C: prefix discipline", { timeout: EXECUTION_TIMEOUTS.fuzz500 }, () => {
  it("a valid code with appended garbage still only ever raises an Error", () => {
    fc.assert(
      fc.property(
        validReceiveCode,
        fc.string({ unit: "binary", minLength: 1, maxLength: 64 }),
        (code, tail) => {
          const corrupted = `${encodeTransferCode(code)}${tail}`;
          const outcome = attempt(() => decodeTransferCode(corrupted));
          if (outcome.returned) return true;
          return outcome.thrown instanceof Error;
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });

  it("a valid code with a prepended valid-looking base64url prefix still rejects controllably", () => {
    fc.assert(
      fc.property(
        validReceiveCode,
        fc.string({ unit: "binary", minLength: 1, maxLength: 32 }),
        (code, head) => {
          const prefixed = `${Buffer.from(head, "utf8").toString("base64url")}${encodeTransferCode(code)}`;
          const outcome = attempt(() => decodeTransferCode(prefixed));
          if (outcome.returned) return true;
          return outcome.thrown instanceof Error;
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });

  it("truncating a valid encoded code at any position never crashes the decoder", () => {
    fc.assert(
      fc.property(validReceiveCode, fc.nat(), (code, seed) => {
        const encoded = encodeTransferCode(code);
        const cut = encoded.length === 0 ? 0 : seed % (encoded.length + 1);
        const outcome = attempt(() => decodeTransferCode(encoded.slice(0, cut)));
        if (outcome.returned) return true;
        return outcome.thrown instanceof Error;
      }),
      { numRuns: NUM_RUNS },
    );
  });
});
