// A.4 ceremony-ceiling / A.4.3 device-label vectors. The controls themselves live in src:
//
//   - 300s ceremony ceiling: `registry.ts` declares `windowSeconds: 300` for the four ceremony
//     purposes (A.4.1 approval, A.4.2 bless, A.4.3 enrol, A.5.1 reporting-register) and
//     `serialize.ts::enforceSignedWindow` enforces `0 < expires_at − issued_at ≤ windowSeconds`
//     inclusively, against the SIGNED `issued_at`, before any Ed25519 check.
//   - A.4.3 label rules: `encoders.ts::encodeLabel` + `isDisallowedLabelScalar` +
//     `DISALLOWED_LABEL_SPACES` carry the six-category fail-closed denylist, the
//     all-Zs-except-internal-U+0020 rejection, the leading/trailing-U+0020 rejection, and the
//     1–80-scalar / 320-byte ceilings (the latter via `parseOpaqueReference`).
//
// `protocol-suite-hardening.test.ts` (B3 + B4) already locks the inclusive boundary, the
// pre-signature ordering, and the bulk of the denylist. This file carries the REMAINING
// vectors that file does not name explicitly: the rest of the A.4.3 scalar-category boundary
// points, the "only U+0020" shape, and the required NFC-admission-gate vector — the
// byte-identity proof at the wire-parser layer (`parseDeviceEnrol`),
// including the NFC-vs-NFD twin form. Test-only: zero source changes, zero A.8 golden bytes
// touched (the byte-exact signing rule).
//
// Governing spec: canonical fields
// .

import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidFieldError } from "../src/protocol/suite/encoders.js";
import { parseDeviceEnrol } from "../src/protocol/suite/parsers.js";
import { serializeSuiteTuple } from "../src/protocol/suite/serialize.js";
import { SUITE_GOLDENS } from "./__vectors__/suite-appendix-a.js";

const ENROL = "zp-device-enrol-v1";

function payloadOf(id: string): Record<string, unknown> {
  const vector = SUITE_GOLDENS.find((entry) => entry.id === id);
  if (vector === undefined) throw new Error(`missing golden vector: ${id}`);
  return JSON.parse(vector.preimageText.slice(vector.preimageText.indexOf("\n") + 1)) as Record<string, unknown>;
}

function withLabel(label: string): Record<string, unknown> {
  const values = payloadOf("device-enrol");
  values.label = label;
  return values;
}

// A disallowed scalar embedded between two ordinary letters, so only the denylist rule under test
// can be the cause of rejection (mirrors the `labelAround` helper).
function labelAround(codePoint: number): string {
  return `a${String.fromCodePoint(codePoint)}b`;
}

const expectRejected = (label: string): void => {
  expect(() => serializeSuiteTuple(ENROL, withLabel(label))).toThrowError(InvalidFieldError);
};

describe("A.4.3 device-label denylist boundary points ", () => {
  // The category boundaries named explicitly that the hardening battery does
  // not. Each is a single scalar between two ordinary letters; the denylist is the only possible
  // cause of rejection. Categories are pinned to Unicode 17.0 (A.4.3 version pin).
  const boundaryPoints: readonly (readonly [string, number])[] = [
    ["C0 control U+0000 (NUL, lower bound)", 0x0000],
    ["C1 control U+009F (upper bound)", 0x009f],
    ["noncharacter U+FDEF (block upper bound)", 0xfdef],
    ["astral noncharacter U+10FFFF (every-plane xFFFE/xFFFF rule)", 0x10ffff],
    ["LRO U+202D (BiDi override, range interior)", 0x202d],
    ["pop directional isolate U+2069 (isolate range upper bound)", 0x2069],
    ["Zs ogham space mark U+1680", 0x1680],
    ["Zs en space U+2000 (Zs block lower bound)", 0x2000],
    ["Zs hair space U+200A (Zs block upper bound)", 0x200a],
    ["Zs narrow no-break space U+202F", 0x202f],
    ["Zs medium mathematical space U+205F", 0x205f],
  ];

  for (const [name, codePoint] of boundaryPoints) {
    it(`rejects ${name}`, () => {
      expectRejected(labelAround(codePoint));
      expect(() => serializeSuiteTuple(ENROL, withLabel(labelAround(codePoint)))).toThrowError(
        expect.objectContaining({ reason: "disallowed_scalar" }) as Error,
      );
    });
  }

  it("rejects a label that is only U+0020", () => {
    // Both edge-space rule and "no non-space content" — rejected either way; the vector set
    // listed this shape explicitly.
    expectRejected(" ");
  });

  it("accepts the boundary-valid labels", () => {
    // 80 ASCII scalars (upper scalar boundary), 79 ASCII + one astral scalar (proves the count is
    // by Unicode scalar, not UTF-16 code unit), a single internal U+0020, and the golden label.
    expect(() => serializeSuiteTuple(ENROL, withLabel("a".repeat(80)))).not.toThrow();
    expect(() => serializeSuiteTuple(ENROL, withLabel(`${"a".repeat(79)}${String.fromCodePoint(0x1f600)}`))).not.toThrow();
    expect(() => serializeSuiteTuple(ENROL, withLabel("north wing"))).not.toThrow();
    expect(() => serializeSuiteTuple(ENROL, withLabel("golden-device"))).not.toThrow();
  });
});

// "e" (U+0065) + COMBINING ACUTE ACCENT (U+0301): the NFD-decomposed form of "é". Written as
// explicit \u escapes (not literal combining characters) so editor / git Unicode normalization can
// never silently collapse this to the NFC form U+00E9.
const NFD_E_ACUTE = "\u0065\u0301";
// U+00E9 (LATIN SMALL LETTER E WITH ACUTE): the NFC-composed form of the same visual character.
const NFC_E_ACUTE = "\u00e9";

function enrolSourceWithLabel(label: string): string {
  const values = withLabel(label);
  return `${ENROL}\n${JSON.stringify(values)}`;
}

describe("A.9 NFC-admission gate is byte-identity at the wire parser ", () => {
  // Required vector: the gate admits a non-NFC label and signs the EXACT
  // submitted bytes — no normalize-then-sign (the byte-exact signing rule). Proven here at the wire-parser layer
  // (`parseDeviceEnrol`), which round-trips the decoded source against the rebuilt canonical
  // preimage byte-for-byte; admission with `preimageBytes === source bytes` is the strongest form.
  it("admits an NFD label unchanged, with the parsed preimage byte-identical to the exact input", () => {
    const label = `north${NFD_E_ACUTE}wing`;
    const requestSource = enrolSourceWithLabel(label);

    const parsed = parseDeviceEnrol(requestSource);

    // Admitted, untransformed: the payload label is the exact submitted scalar sequence.
    expect(parsed.payload.label).toBe(label);
    expect(Buffer.from(parsed.payload.label, "utf8").equals(Buffer.from(label, "utf8"))).toBe(true);
    // Byte-identity of the signed value: the preimage bytes equal the exact submitted source bytes.
    expect(Buffer.from(parsed.preimageBytes).equals(Buffer.from(requestSource, "utf8"))).toBe(true);
    expect(parsed.preimageText).toContain(`"label":"${label}"`);
    expect(parsed.preimageText).not.toContain(label.normalize("NFC"));
  });

  it("NFC and NFD forms of the same visual label carry different bytes; both are admitted, each preserving its own exact bytes", () => {
    const nfcLabel = `caf${NFC_E_ACUTE}`;
    const nfdLabel = `caf${NFD_E_ACUTE}`;

    // Same visual label, distinct scalar sequences and distinct UTF-8 bytes.
    expect(nfcLabel).not.toBe(nfdLabel);
    expect(Buffer.from(nfcLabel, "utf8").equals(Buffer.from(nfdLabel, "utf8"))).toBe(false);

    const nfcResult = parseDeviceEnrol(enrolSourceWithLabel(nfcLabel));
    const nfdResult = parseDeviceEnrol(enrolSourceWithLabel(nfdLabel));

    // The gate neither admits nor rejects based on normalization form; both forms are admitted,
    // each with its own exact bytes preserved untouched.
    expect(nfcResult.payload.label).toBe(nfcLabel);
    expect(nfdResult.payload.label).toBe(nfdLabel);
    expect(Buffer.from(nfcResult.payload.label, "utf8").equals(Buffer.from(nfcLabel, "utf8"))).toBe(true);
    expect(Buffer.from(nfdResult.payload.label, "utf8").equals(Buffer.from(nfdLabel, "utf8"))).toBe(true);
  });
});
