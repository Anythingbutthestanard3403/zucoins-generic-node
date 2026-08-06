// Byte-exact regression-lock — suite-tuple scalar passthrough guard.
// Spec: canonical fields v15 / signing custody r4 / protocol foundation
//
// The byte-exact signing rule: byte-exact JSON.stringify signing — never reformat. The three nullable scalar
// fields on zp-wallet-head-fingerprint-v1 (inner_sha256, step_1_signature, step_2_signature) are
// caller-supplied values that MUST pass through the serializer VERBATIM. They are never re-derived
// from a parsed inner JSONB, never recomputed, never normalized. This test uses distinctive marker
// values that could NOT be produced by any re-derivation: if the serializer recomputed these from
// parsed content, the markers would be replaced and every assertion below would FAIL.
import { describe, expect, it } from "vitest";

import { buildWalletHeadFingerprint } from "../src/protocol/suite/builders.js";
import { serializeSuiteTuple } from "../src/protocol/suite/serialize.js";
import type { WalletHeadFingerprintInput } from "../src/protocol/suite/builders.js";

// Distinctive markers: valid format (pass the encoder) but impossible to produce by re-derivation.
// inner_sha256: 64 lowercase hex chars — a repeating deadbeef pattern no real hash would yield.
const MARKER_INNER_SHA256 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
// step signatures: canonical base64url of repeating 0xDEADBEEF / 0xCAFEBABE bytes (64 bytes each).
// No real Ed25519 signature would produce these repeating patterns.
const MARKER_STEP_1 = "3q2-796tvu_erb7v3q2-796tvu_erb7v3q2-796tvu_erb7v3q2-796tvu_erb7v3q2-796tvu_erb7v3q2-7w==";
const MARKER_STEP_2 = "yv66vsr-ur7K_rq-yv66vsr-ur7K_rq-yv66vsr-ur7K_rq-yv66vsr-ur7K_rq-yv66vsr-ur7K_rq-yv66vg==";

// Shared valid fixture fields (from A.8.2 golden vectors).
const FIXTURE_PUBKEY = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=" as WalletHeadFingerprintInput["wallet_public_key"];
const FIXTURE_S_SIG = "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==" as WalletHeadFingerprintInput["s_signature"];

function buildWithMarkers(overrides: Partial<WalletHeadFingerprintInput> = {}) {
  const input: WalletHeadFingerprintInput = {
    wallet_public_key: FIXTURE_PUBKEY,
    state_kind: "HEAD",
    s_signature: FIXTURE_S_SIG,
    p_signature: "",
    b_amount: "2.25" as WalletHeadFingerprintInput["b_amount"],
    inner_sha256: MARKER_INNER_SHA256 as WalletHeadFingerprintInput["inner_sha256"],
    step_1_signature: MARKER_STEP_1 as WalletHeadFingerprintInput["step_1_signature"],
    step_2_signature: MARKER_STEP_2 as WalletHeadFingerprintInput["step_2_signature"],
    ...overrides,
  };
  return buildWalletHeadFingerprint(input);
}

describe("Byte-exact: inner_sha256 / step_1_signature / step_2_signature are caller-supplied scalars passed through VERBATIM", () => {
  it("inner_sha256 marker appears verbatim in the serialized preimage (never re-derived)", () => {
    const { preimageText } = buildWithMarkers();
    expect(preimageText).toContain(`"inner_sha256":"${MARKER_INNER_SHA256}"`);
  });

  it("step_1_signature marker appears verbatim in the serialized preimage (never re-derived)", () => {
    const { preimageText } = buildWithMarkers();
    expect(preimageText).toContain(`"step_1_signature":"${MARKER_STEP_1}"`);
  });

  it("step_2_signature marker appears verbatim in the serialized preimage (never re-derived)", () => {
    const { preimageText } = buildWithMarkers();
    expect(preimageText).toContain(`"step_2_signature":"${MARKER_STEP_2}"`);
  });

  it("all three markers survive a round-trip through serializeSuiteTuple unchanged", () => {
    const { preimageText } = buildWithMarkers();
    // The preimage is `purpose + "\n" + JSON.stringify(payload)` — extract the JSON portion.
    const jsonPortion = preimageText.slice(preimageText.indexOf("\n") + 1);
    const parsed = JSON.parse(jsonPortion) as Record<string, unknown>;
    expect(parsed.inner_sha256).toBe(MARKER_INNER_SHA256);
    expect(parsed.step_1_signature).toBe(MARKER_STEP_1);
    expect(parsed.step_2_signature).toBe(MARKER_STEP_2);
  });

  it("serializeSuiteTuple passes markers verbatim when called directly (bypassing the builder)", () => {
    const { preimageText } = serializeSuiteTuple("zp-wallet-head-fingerprint-v1", {
      purpose: "zp-wallet-head-fingerprint-v1",
      canonical_version: 1,
      wallet_public_key: FIXTURE_PUBKEY,
      state_kind: "HEAD",
      s_signature: FIXTURE_S_SIG,
      p_signature: "",
      b_amount: "2.25",
      inner_sha256: MARKER_INNER_SHA256,
      step_1_signature: MARKER_STEP_1,
      step_2_signature: MARKER_STEP_2,
    });
    expect(preimageText).toContain(`"inner_sha256":"${MARKER_INNER_SHA256}"`);
    expect(preimageText).toContain(`"step_1_signature":"${MARKER_STEP_1}"`);
    expect(preimageText).toContain(`"step_2_signature":"${MARKER_STEP_2}"`);
  });
});

describe("Byte-exact: genesis null passthrough — all three nullable fields emit JSON null", () => {
  it("null inner_sha256 / step_1_signature / step_2_signature serialize as JSON null (not omitted, not empty string)", () => {
    const { preimageText } = buildWithMarkers({
      state_kind: "GENESIS",
      inner_sha256: null,
      step_1_signature: null,
      step_2_signature: null,
    });
    expect(preimageText).toContain('"inner_sha256":null');
    expect(preimageText).toContain('"step_1_signature":null');
    expect(preimageText).toContain('"step_2_signature":null');
  });

  it("genesis null fields are distinct from empty-string sentinels in the same tuple", () => {
    const { preimageText } = buildWithMarkers({
      state_kind: "GENESIS",
      inner_sha256: null,
      step_1_signature: null,
      step_2_signature: null,
    });
    // p_signature uses the empty-string sentinel at genesis — it must remain "" not null.
    expect(preimageText).toContain('"p_signature":""');
    // The three nullable fields must be null, not "".
    expect(preimageText).not.toContain('"inner_sha256":""');
    expect(preimageText).not.toContain('"step_1_signature":""');
    expect(preimageText).not.toContain('"step_2_signature":""');
  });

  it("null passthrough via serializeSuiteTuple directly", () => {
    const { preimageText } = serializeSuiteTuple("zp-wallet-head-fingerprint-v1", {
      purpose: "zp-wallet-head-fingerprint-v1",
      canonical_version: 1,
      wallet_public_key: FIXTURE_PUBKEY,
      state_kind: "GENESIS",
      s_signature: "",
      p_signature: "",
      b_amount: "0",
      inner_sha256: null,
      step_1_signature: null,
      step_2_signature: null,
    });
    const jsonPortion = preimageText.slice(preimageText.indexOf("\n") + 1);
    const parsed = JSON.parse(jsonPortion) as Record<string, unknown>;
    expect(parsed.inner_sha256).toBeNull();
    expect(parsed.step_1_signature).toBeNull();
    expect(parsed.step_2_signature).toBeNull();
  });
});
