import { describe, expect, it } from "vitest";

import {
  type ObservationParseResult,
  type ObservationRelationship,
} from "./enums.contract.ts";
import { type RecordInvariantId } from "./invariants.contract.ts";
import {
  verifyGatewayObservationRecord,
  isValidGatewayObservationRecord,
  type GatewayObservationRecord,
} from "./record-verifier.ts";

const SIG = `${"A".repeat(86)}==`;
const PUBKEY = `${"B".repeat(43)}=`;
const DIGEST = "a".repeat(64);
const BYTES = new Uint8Array([1, 2, 3]);

const base = {
  id: "obs-1",
  observer_id: "observer-1",
  endpoint_fingerprint: DIGEST,
  wallet_id: null,
  wallet_public_key: PUBKEY,
  wallet_seq: 1,
  observed_at: "2026-07-19T00:00:00Z",
  http_status: 200,
  raw_response_bytes: BYTES,
  raw_response_sha256: DIGEST,
  previous_recorded_observation_id: null,
  created_at: "2026-07-19T00:00:00Z",
} as const;

const VALID_HEAD: GatewayObservationRecord = {
  ...base,
  parse_result: "VERIFIED_HEAD",
  relationship: "SUCCESSOR",
  semantic_fingerprint: DIGEST,
  state_changed: true,
  wallet_role: "receiver",
  s_signature: SIG,
  p_signature: SIG,
  b_amount: "2.25",
  inner_preimage_text: '{"inner":"x"}',
  step_1_signature: SIG,
  step_2_signature: SIG,
  completed_transaction_text: '{"inner":{}}',
  completed_transaction_sha256: DIGEST,
};

const VALID_GENESIS: GatewayObservationRecord = {
  ...base,
  parse_result: "VERIFIED_GENESIS",
  relationship: "FIRST",
  semantic_fingerprint: DIGEST,
  state_changed: true,
  wallet_role: "genesis",
  s_signature: "",
  p_signature: "",
  b_amount: "0",
  inner_preimage_text: null,
  step_1_signature: null,
  step_2_signature: null,
  completed_transaction_text: null,
  completed_transaction_sha256: null,
};

const VALID_NONVERIFIED: GatewayObservationRecord = {
  ...base,
  parse_result: "MALFORMED_ENVELOPE",
  relationship: "NOT_APPLICABLE",
  semantic_fingerprint: null,
  state_changed: null,
  wallet_role: null,
  s_signature: null,
  p_signature: null,
  b_amount: null,
  inner_preimage_text: null,
  step_1_signature: null,
  step_2_signature: null,
  completed_transaction_text: null,
  completed_transaction_sha256: null,
};

describe("verifyGatewayObservationRecord accepts every valid shape (the observation dedup freeze)", () => {
  it("valid VERIFIED_HEAD, VERIFIED_GENESIS, and non-verified rows pass", () => {
    expect(verifyGatewayObservationRecord(VALID_HEAD)).toEqual([]);
    expect(verifyGatewayObservationRecord(VALID_GENESIS)).toEqual([]);
    expect(verifyGatewayObservationRecord(VALID_NONVERIFIED)).toEqual([]);
    expect(isValidGatewayObservationRecord(VALID_HEAD)).toBe(true);
  });

  it("a swept payer head with b_amount '0' is legal (the amounts-grammar freeze balance domain)", () => {
    expect(verifyGatewayObservationRecord({ ...VALID_HEAD, b_amount: "0" })).toEqual([]);
  });
});

interface NegativeCase {
  readonly name: string;
  readonly record: GatewayObservationRecord;
  readonly expected: RecordInvariantId;
}

const NEGATIVE_CASES: readonly NegativeCase[] = [
  {
    name: "unknown parse_result",
    record: { ...VALID_NONVERIFIED, parse_result: "BOGUS" as ObservationParseResult },
    expected: "ENUM_DOMAINS",
  },
  {
    name: "unknown relationship on a head",
    record: { ...VALID_HEAD, relationship: "BOGUS" as ObservationRelationship },
    expected: "ENUM_DOMAINS",
  },
  {
    name: "verified head missing semantic_fingerprint",
    record: { ...VALID_HEAD, semantic_fingerprint: null },
    expected: "FIELD_A_FINGERPRINT_IFF_VERIFIED",
  },
  {
    name: "non-verified row carrying a semantic_fingerprint",
    record: { ...VALID_NONVERIFIED, semantic_fingerprint: DIGEST },
    expected: "FIELD_A_FINGERPRINT_IFF_VERIFIED",
  },
  {
    name: "verified head missing state_changed",
    record: { ...VALID_HEAD, state_changed: null },
    expected: "FIELD_B_STATE_CHANGED_IFF_VERIFIED",
  },
  {
    name: "verified head missing completed_transaction_text",
    record: { ...VALID_HEAD, completed_transaction_text: null },
    expected: "FIELD_C_HEAD_MATERIAL_IFF_HEAD",
  },
  {
    name: "genesis with a non-empty s_signature",
    record: { ...VALID_GENESIS, s_signature: SIG },
    expected: "FIELD_D_GENESIS_SHAPE",
  },
  {
    name: "genesis with a non-zero b_amount",
    record: { ...VALID_GENESIS, b_amount: "1" },
    expected: "FIELD_D_GENESIS_SHAPE",
  },
  {
    name: "head with an unpadded s_signature",
    record: { ...VALID_HEAD, s_signature: "short" },
    expected: "FIELD_E_HEAD_SHAPE",
  },
  {
    name: "head with wallet_role genesis",
    record: { ...VALID_HEAD, wallet_role: "genesis" },
    expected: "FIELD_E_HEAD_SHAPE",
  },
  {
    name: "non-verified row with a non-NOT_APPLICABLE relationship",
    record: { ...VALID_NONVERIFIED, relationship: "SUCCESSOR" },
    expected: "FIELD_F_NONVERIFIED_SHAPE",
  },
  {
    name: "non-verified row carrying a wallet_role",
    record: { ...VALID_NONVERIFIED, wallet_role: "sender" },
    expected: "FIELD_F_NONVERIFIED_SHAPE",
  },
  {
    name: "wallet_seq of zero",
    record: { ...VALID_HEAD, wallet_seq: 0 },
    expected: "SCALAR_FORMATS",
  },
  {
    name: "endpoint_fingerprint that is not a sha256_hex",
    record: { ...VALID_HEAD, endpoint_fingerprint: "not-a-digest" },
    expected: "SCALAR_FORMATS",
  },
  {
    name: "b_amount at or above the 1e8 bound",
    record: { ...VALID_HEAD, b_amount: "100000000" },
    expected: "SCALAR_FORMATS",
  },
];

describe("verifyGatewayObservationRecord rejects mutated record shapes (the observation dedup freeze negative path)", () => {
  it.each(NEGATIVE_CASES)("rejects: $name -> $expected", ({ record, expected }) => {
    const violations = verifyGatewayObservationRecord(record);
    expect(violations).toContain(expected);
    expect(isValidGatewayObservationRecord(record)).toBe(false);
  });

  it("every frozen invariant id is reachable by at least one rejected record", () => {
    const reached = new Set(NEGATIVE_CASES.map((testCase) => testCase.expected));
    expect([...reached].sort()).toEqual(
      [
        "ENUM_DOMAINS",
        "FIELD_A_FINGERPRINT_IFF_VERIFIED",
        "FIELD_B_STATE_CHANGED_IFF_VERIFIED",
        "FIELD_C_HEAD_MATERIAL_IFF_HEAD",
        "FIELD_D_GENESIS_SHAPE",
        "FIELD_E_HEAD_SHAPE",
        "FIELD_F_NONVERIFIED_SHAPE",
        "SCALAR_FORMATS",
      ].sort(),
    );
  });
});
