// Golden cross-check: verifies canonical_version pinning against the real deterministic
// golden preimages for the 7 of 10 purposes that have golden fixtures. The 3
// expected-artifact purposes have no authoritative golden fixture yet — inventory assertion
// tests below document their absence.
//
// Also includes a negative immutability test: fails if any canonical_version value is mutated.
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  CANONICAL_VERSION_FOR_PURPOSE,
  CANONICAL_VERSION_V1,
} from "./canonical-version.contract.ts";
import {
  RECEIVE_EXPECTED_PURPOSE,
  MOVE_INTERNAL_EXPECTED_PURPOSE,
  SEND_EXTERNAL_EXPECTED_PURPOSE,
  SEND_EXTERNAL_APPROVAL_PURPOSE,
  DESTINATION_BLESS_PURPOSE,
  DEVICE_ENROL_PURPOSE,
  REPORT_REQUEST_PURPOSE,
  NODE_EVENT_PURPOSE,
  WALLET_HEAD_FINGERPRINT_PURPOSE,
  REPORTING_REGISTER_PURPOSE,
  ZP_V1_PURPOSES,
} from "./compat-literals.contract.ts";
import { REPORTING_REGISTER_CANONICAL_VERSION } from "../reporting-auth/register-tuple.ts";

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

const parsePreimagePayload = (preimage: string): Record<string, unknown> => {
  const newlineIndex = preimage.indexOf("\n");
  const jsonPart = newlineIndex >= 0 ? preimage.slice(newlineIndex + 1) : preimage;
  return JSON.parse(jsonPart) as Record<string, unknown>;
};

// --- Golden preimages for the 7 purposes with golden fixtures ---
// Each is the exact golden preimage_text (\n = one LF byte, no trailing LF).

const A8_GOLDEN_PREIMAGES: Readonly<Record<string, string>> = {
  [SEND_EXTERNAL_APPROVAL_PURPOSE]:
    "zp-send-external-approval-v1\n" +
    JSON.stringify({
      purpose: "zp-send-external-approval-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
      operation_id: "33333333-3333-4333-8333-333333333333",
      source_selector: { kind: "WALLET_ID", wallet_id: "55555555-5555-4555-8555-555555555555" },
      source_pubkey: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
      destination_address: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
      amount_zkz: "2.25",
      references_operation_id: null,
      nonce: "99999999-9999-4999-8999-999999999999",
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:05:00.000Z",
    }),
  [DESTINATION_BLESS_PURPOSE]:
    "zp-destination-bless-v1\n" +
    JSON.stringify({
      purpose: "zp-destination-bless-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
      destination_id: "66666666-6666-4666-8666-666666666666",
      wallet_id: "44444444-4444-4444-8444-444444444444",
      wallet_pubkey: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
      nonce: "99999999-9999-4999-8999-999999999999",
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:05:00.000Z",
    }),
  [DEVICE_ENROL_PURPOSE]:
    "zp-device-enrol-v1\n" +
    JSON.stringify({
      purpose: "zp-device-enrol-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
      new_device_key_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      new_device_public_key: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
      label: "golden-device",
      nonce: "99999999-9999-4999-8999-999999999999",
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:05:00.000Z",
    }),
  [REPORT_REQUEST_PURPOSE]:
    "zp-report-request-v1\n" +
    JSON.stringify({
      purpose: "zp-report-request-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
      implementer_id: "22222222-2222-4222-8222-222222222222",
      method: "POST",
      path: "/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete",
      body_sha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      nonce: "99999999-9999-4999-8999-999999999999",
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:01:00.000Z",
    }),
  [REPORTING_REGISTER_PURPOSE]:
    "zp-reporting-register-v1\n" +
    JSON.stringify({
      purpose: "zp-reporting-register-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
      implementer_id: "22222222-2222-4222-8222-222222222222",
      new_reporting_key_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      new_reporting_public_key: "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=",
      supersedes_key_id: null,
      nonce: "99999999-9999-4999-8999-999999999999",
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:05:00.000Z",
    }),
  [NODE_EVENT_PURPOSE]:
    "zp-node-event-v1\n" +
    JSON.stringify({
      purpose: "zp-node-event-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
      event_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      seq: "1",
      operation_id: "33333333-3333-4333-8333-333333333333",
      wallet_id: "55555555-5555-4555-8555-555555555555",
      event_type: "receive.ready",
      data_sha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      previous_event_hash: null,
      created_at: "2026-07-18T00:00:00.000Z",
    }),
  [WALLET_HEAD_FINGERPRINT_PURPOSE]:
    "zp-wallet-head-fingerprint-v1\n" +
    JSON.stringify({
      purpose: "zp-wallet-head-fingerprint-v1",
      canonical_version: 1,
      wallet_public_key: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
      state_kind: "HEAD",
      s_signature:
        "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==",
      p_signature: "",
      b_amount: "2.25",
      inner_sha256: "ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51",
      step_1_signature:
        "wpAPEHD-wRRyfdoLM5FUgwS5OhCVwkQBV5w-XFDSx_VK19QiW5szD6Cuy1ogiNlIlvWtx4LlZPIdAm81eKX0BA==",
      step_2_signature:
        "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==",
    }),
};

const A8_GOLDEN_SHA256: Readonly<Record<string, string>> = {
  [SEND_EXTERNAL_APPROVAL_PURPOSE]:
    "d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146",
  [DESTINATION_BLESS_PURPOSE]:
    "9f9b0f61d152037f7d470bed2803e39b22b3f9830cf60f608f4b92c1f294fc70",
  [DEVICE_ENROL_PURPOSE]:
    "64e6a3213325f01253954b27abeb4ace733c6f57d0cbc888e5f3bd438b789dc9",
  [REPORT_REQUEST_PURPOSE]:
    "31a0edb52dea2b193bd56add32363b7afba1021c5f9820b8c2ee3ea263cfc463",
  [REPORTING_REGISTER_PURPOSE]:
    "98fba788ad4ba2141dc400f1cd0f58db3a03b34a00b5a04ecdcfe239e9912e7e",
  [NODE_EVENT_PURPOSE]:
    "9644a48d9f0a988c62321a371ad66f993ae4f428ae3a3ee48d0dc290e0560226",
  [WALLET_HEAD_FINGERPRINT_PURPOSE]:
    "d03a98b770684e577667f9bde01276b196b98db31663f23b0900623d6dffca2a",
};

const GOLDEN_PURPOSES = Object.keys(A8_GOLDEN_PREIMAGES);

const GOLDEN_LESS_PURPOSES = [
  RECEIVE_EXPECTED_PURPOSE,
  MOVE_INTERNAL_EXPECTED_PURPOSE,
  SEND_EXTERNAL_EXPECTED_PURPOSE,
] as const;

describe("A.8 golden cross-check: canonical_version matches pin for 7 golden purposes", () => {
  it("has exactly 7 golden purposes (guard against empty set)", () => {
    expect(GOLDEN_PURPOSES).toHaveLength(7);
  });

  for (const purpose of Object.keys(A8_GOLDEN_PREIMAGES)) {
    it(`A.8 golden "${purpose}" carries canonical_version matching the pin`, () => {
      const preimage = A8_GOLDEN_PREIMAGES[purpose]!;
      const payload = parsePreimagePayload(preimage);
      const pinnedVersion = CANONICAL_VERSION_FOR_PURPOSE[purpose as keyof typeof CANONICAL_VERSION_FOR_PURPOSE];
      expect(payload.canonical_version).toBe(pinnedVersion);
      expect(payload.canonical_version).toBe(CANONICAL_VERSION_V1);
    });
  }

  for (const purpose of Object.keys(A8_GOLDEN_PREIMAGES)) {
    it(`A.8 golden preimage SHA-256 for "${purpose}" matches pinned digest`, () => {
      const preimage = A8_GOLDEN_PREIMAGES[purpose]!;
      expect(sha256(preimage)).toBe(A8_GOLDEN_SHA256[purpose]);
    });
  }
});

describe("golden-less purposes: inventory assertions for 3 expected-artifact purposes", () => {
  it("has exactly 3 golden-less purposes", () => {
    expect(GOLDEN_LESS_PURPOSES).toHaveLength(3);
  });

  for (const purpose of GOLDEN_LESS_PURPOSES) {
    it(`"${purpose}" is in ZP_V1_PURPOSES and has canonical_version pinned to 1`, () => {
      expect((ZP_V1_PURPOSES as readonly string[]).includes(purpose)).toBe(true);
      expect(CANONICAL_VERSION_FOR_PURPOSE[purpose as keyof typeof CANONICAL_VERSION_FOR_PURPOSE]).toBe(
        CANONICAL_VERSION_V1,
      );
    });
  }

  it("every golden-less purpose is pinned to canonical_version 1", () => {
    for (const purpose of GOLDEN_LESS_PURPOSES) {
      expect(CANONICAL_VERSION_FOR_PURPOSE[purpose as keyof typeof CANONICAL_VERSION_FOR_PURPOSE]).toBe(1);
    }
  });

  it("golden + golden-less purposes together cover all 10 ZP_V1_PURPOSES", () => {
    const allCovered = [...GOLDEN_PURPOSES, ...GOLDEN_LESS_PURPOSES].sort();
    const allPurposes = [...ZP_V1_PURPOSES].sort();
    expect(allCovered).toEqual(allPurposes);
  });
});

describe("negative: canonical_version immutability", () => {
  it("every purpose in the pin map has canonical_version exactly 1", () => {
    for (const purpose of ZP_V1_PURPOSES) {
      expect(CANONICAL_VERSION_FOR_PURPOSE[purpose]).toBe(1);
    }
  });

  it("the pin map has exactly 10 entries (one per ZP_V1_PURPOSE)", () => {
    expect(Object.keys(CANONICAL_VERSION_FOR_PURPOSE)).toHaveLength(ZP_V1_PURPOSES.length);
  });

  it("CANONICAL_VERSION_V1 is the number 1, not a string or other type", () => {
    expect(CANONICAL_VERSION_V1).toBe(1);
    expect(typeof CANONICAL_VERSION_V1).toBe("number");
  });

  it("rejects a mutated canonical_version (negative path: version 2 is not pinned)", () => {
    const mutatedVersion = 2;
    for (const purpose of ZP_V1_PURPOSES) {
      expect(CANONICAL_VERSION_FOR_PURPOSE[purpose]).not.toBe(mutatedVersion);
    }
  });

  it("reporting-register canonical_version is imported from reporting-auth, not locally declared", () => {
    expect(CANONICAL_VERSION_FOR_PURPOSE[REPORTING_REGISTER_PURPOSE]).toBe(
      REPORTING_REGISTER_CANONICAL_VERSION,
    );
    expect(REPORTING_REGISTER_CANONICAL_VERSION).toBe(1);
  });
});
