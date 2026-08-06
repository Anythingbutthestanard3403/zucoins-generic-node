// adversarial byte-level vectors for the strict envelope parser:
// trailing-byte and multi-value JSON fuzzing (step 2), invalid-UTF-8 fuzzing
// against the lenient-decoder hazard (step 1), wrong-action-schema bodies (step 3), the
// envelope-shape fail-closed battery (step 3), and the settled-transaction fail-closed
// battery (step 5). Mutating fixture bytes to build adversarial INPUTS is permitted —
// these are attacks, never regenerated expected goldens. Happy-path and protocol vectors
// live in gateway-envelope.test.ts.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseGatewayEnvelope, type MalformedEnvelopeVerdict } from "./gateway-envelope.js";

const GEN_DIR = new URL("../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

function headEnvelopeText(txText: string): string {
  return `{"status":true,"code":"success","message":"","data":[${txText}]}`;
}

function encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function expectMalformed(bytes: Uint8Array, reason: MalformedEnvelopeVerdict["reason"]): void {
  const verdict = parseGatewayEnvelope(bytes);
  expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
  if (verdict.classification !== "MALFORMED_ENVELOPE") return;
  expect(verdict.reason).toBe(reason);
}

const TARGET_TEXT = fixtureText("target.settled.json");

describe("trailing-byte and multi-value fuzzing — envelope step 2", () => {
  it("accepts surrounding whitespace (JSON whitespace is not a trailing byte)", () => {
    expect(parseGatewayEnvelope(encode(`  ${headEnvelopeText(TARGET_TEXT)}\n\t `)).classification).toBe(
      "HEAD",
    );
  });

  it("rejects a single trailing non-whitespace byte", () => {
    expectMalformed(encode(`${headEnvelopeText(TARGET_TEXT)}X`), "not_exactly_one_json_value");
  });

  it("rejects a trailing JSON fragment", () => {
    expectMalformed(encode(`${headEnvelopeText(TARGET_TEXT)}{}`), "not_exactly_one_json_value");
  });

  it("rejects two concatenated JSON values", () => {
    const one = headEnvelopeText(TARGET_TEXT);
    expectMalformed(encode(`${one}${one}`), "not_exactly_one_json_value");
  });

  it("rejects two concatenated values even with whitespace between them", () => {
    const one = headEnvelopeText(TARGET_TEXT);
    expectMalformed(encode(`${one}   ${one}`), "not_exactly_one_json_value");
  });
});

describe("invalid-UTF-8 fuzzing — envelope step 1", () => {
  it("rejects a byte a lenient decoder silently turns into U+FFFD (and that would then parse as JSON)", () => {
    const envelopeText = headEnvelopeText(TARGET_TEXT);
    const decodable = encode(envelopeText);
    // Corrupt one byte inside the sender public key string value.
    const corruptionIndex = envelopeText.indexOf("gTl3Dqh9F19Wo1Rmw0x") + 5;
    const corrupted = Uint8Array.from(decodable, (byte, index) =>
      index === corruptionIndex ? 0xff : byte,
    );
    // The hazard this stage exists to defeat: the non-fatal decoder substitutes U+FFFD
    // and the corrupted body still parses — a lenient pipeline would accept it.
    const lenientText = new TextDecoder("utf-8").decode(corrupted);
    expect(lenientText).toContain("\uFFFD");
    expect(() => JSON.parse(lenientText)).not.toThrow();
    expectMalformed(corrupted, "utf8_decode_failed");
  });

  it("rejects a lone continuation byte", () => {
    const decodable = encode(headEnvelopeText(TARGET_TEXT));
    const corrupted = Uint8Array.from(decodable, (byte, index) => (index === 10 ? 0x80 : byte));
    expectMalformed(corrupted, "utf8_decode_failed");
  });

  it("rejects a truncated multi-byte sequence at the end of the body", () => {
    const decodable = encode(headEnvelopeText(TARGET_TEXT));
    const truncated = new Uint8Array([...decodable, 0xe2, 0x82]);
    expectMalformed(truncated, "utf8_decode_failed");
  });

  it("rejects a BOM-prefixed body (fail closed, no silent BOM stripping)", () => {
    const bomPrefixed = new Uint8Array([0xef, 0xbb, 0xbf, ...encode(headEnvelopeText(TARGET_TEXT))]);
    expectMalformed(bomPrefixed, "not_exactly_one_json_value");
  });
});

describe("wrong-action-schema fuzzing — envelope step 3", () => {
  it("rejects a well-formed submit_transaction__v1-shaped success body (data object, not a tx array)", () => {
    expectMalformed(
      encode(`{"status":true,"code":"success","message":"","data":{"transaction_hash":"abc"}}`),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it("rejects a success body whose data is a bare string", () => {
    expectMalformed(
      encode(`{"status":true,"code":"success","message":"","data":"ok"}`),
      "not_exactly_one_complete_settled_transaction",
    );
  });
});

describe("envelope-shape fail-closed battery — envelope step 3", () => {
  const txArray = `[${TARGET_TEXT}]`;

  it("rejects a permuted envelope key sequence", () => {
    expectMalformed(
      encode(`{"code":"success","status":true,"message":"","data":${txArray}}`),
      "envelope_shape_invalid",
    );
  });

  it("rejects an unknown extra envelope field", () => {
    expectMalformed(
      encode(`{"status":true,"code":"success","message":"","data":${txArray},"transport":"x"}`),
      "envelope_shape_invalid",
    );
  });

  it("rejects a missing data field", () => {
    expectMalformed(encode(`{"status":true,"code":"success","message":""}`), "envelope_shape_invalid");
  });

  it("rejects a missing message field", () => {
    expectMalformed(encode(`{"status":true,"code":"success","data":${txArray}}`), "envelope_shape_invalid");
  });

  it("rejects a non-boolean status", () => {
    expectMalformed(
      encode(`{"status":"true","code":"success","message":"","data":${txArray}}`),
      "envelope_shape_invalid",
    );
  });

  it("rejects a non-string code", () => {
    expectMalformed(
      encode(`{"status":true,"code":0,"message":"","data":${txArray}}`),
      "envelope_shape_invalid",
    );
  });

  it("rejects a null message", () => {
    expectMalformed(
      encode(`{"status":true,"code":"success","message":null,"data":${txArray}}`),
      "envelope_shape_invalid",
    );
  });

  it.each([
    ["a top-level array", `[{"status":true,"code":"s","message":"","data":${txArray}}]`],
    ["a top-level number", "123"],
    ["a top-level string", `"status"`],
    ["a top-level null", "null"],
    ["a top-level boolean", "true"],
  ])("rejects %s", (_label, body) => {
    expectMalformed(encode(body), "envelope_shape_invalid");
  });
});

describe("settled-transaction fail-closed battery — envelope step 5", () => {
  it("rejects multiple entries (the head-only gateway answers with at most one)", () => {
    const predecessorText = fixtureText("predecessor.settled.json");
    expectMalformed(
      encode(headEnvelopeText(`${TARGET_TEXT},${predecessorText}`)),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it("rejects the frozen step-2 partial fixture (inner + step-1 signature, no step-2 signature)", () => {
    expectMalformed(
      encode(headEnvelopeText(fixtureText("target.step-2.json"))),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it("rejects the frozen inner-only fragment (no signatures at all)", () => {
    expectMalformed(
      encode(headEnvelopeText(fixtureText("target.step-1.json"))),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it("rejects an empty step_2_signature", () => {
    const mutated = TARGET_TEXT.replace(/"step_2_signature":"[^"]*"/, `"step_2_signature":""`);
    expectMalformed(
      encode(headEnvelopeText(mutated)),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it("rejects an empty step_1_signature", () => {
    const mutated = TARGET_TEXT.replace(/"step_1_signature":"[^"]*"/, `"step_1_signature":""`);
    expectMalformed(
      encode(headEnvelopeText(mutated)),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it("rejects a missing step_1_signature", () => {
    const mutated = TARGET_TEXT.replace(/"step_1_signature":"[^"]*",/, "");
    expectMalformed(
      encode(headEnvelopeText(mutated)),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it("rejects an unknown transaction version", () => {
    const mutated = TARGET_TEXT.replace(`"version":"2"`, `"version":"3"`);
    expectMalformed(
      encode(headEnvelopeText(mutated)),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it("rejects an inner without a version field", () => {
    const mutated = TARGET_TEXT.replace(`"version":"2",`, "");
    expectMalformed(
      encode(headEnvelopeText(mutated)),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it("rejects an unknown extra top-level entry field", () => {
    const mutated = `${TARGET_TEXT.slice(0, -1)},"extra_field":1}`;
    expectMalformed(
      encode(headEnvelopeText(mutated)),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it("rejects a permuted entry key sequence", () => {
    const parsed = JSON.parse(TARGET_TEXT) as Record<string, unknown>;
    const permuted = JSON.stringify({
      step_2_signature: parsed.step_2_signature,
      inner: parsed.inner,
      step_1_signature: parsed.step_1_signature,
    });
    expectMalformed(
      encode(headEnvelopeText(permuted)),
      "not_exactly_one_complete_settled_transaction",
    );
  });

  it.each([
    ["a string entry", `"x"`],
    ["a null entry", "null"],
    ["an array entry", `[${TARGET_TEXT}]`],
    ["an array inner", `{"inner":[1,2],"step_1_signature":"a","step_2_signature":"b"}`],
    ["a null inner", `{"inner":null,"step_1_signature":"a","step_2_signature":"b"}`],
    ["a numeric step_1_signature", `{"inner":{"version":"2"},"step_1_signature":1,"step_2_signature":"b"}`],
  ])("rejects %s", (_label, entry) => {
    expectMalformed(
      encode(`{"status":true,"code":"success","message":"","data":[${entry}]}`),
      "not_exactly_one_complete_settled_transaction",
    );
  });
});
