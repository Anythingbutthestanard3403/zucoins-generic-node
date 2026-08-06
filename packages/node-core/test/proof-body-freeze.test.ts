import { describe, expect, it } from "vitest";

import {
  intakeProofBody,
  MAX_PROOF_BODY_BYTES,
  PROOF_BODY_FIELDS,
  proofBodySchema,
  type ProofBodyIntakeRequest,
  type ValidatedProofBody,
} from "../src/proof-body/index.js";

// Freeze tests for the proof-body intake envelope.
// Governing spec: the data model (lineage_path_bodies),
// observation verification (non-authority), canonical fields.

const SETTLED_TX =
  '{"inner":{"type":"unique_combinable","version":"2","unix_time_secs":"1784332800.125","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","step_2_key_public__base64urlsafe":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25"},"previous_step_1_state_signature":"IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==","previous_step_2_state_signature":"","expiry__unix_time_secs":"1784336400","message":"zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3"},"step_1_signature":"wpAPEHD-wRRyfdoLM5FUgwS5OhCVwkQBV5w-XFDSx_VK19QiW5szD6Cuy1ogiNlIlvWtx4LlZPIdAm81eKX0BA==","step_2_signature":"uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw=="}';

const INNER_PREIMAGE =
  '{"type":"unique_combinable","version":"2","unix_time_secs":"1784332800.125","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","step_2_key_public__base64urlsafe":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25"},"previous_step_1_state_signature":"IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==","previous_step_2_state_signature":"","expiry__unix_time_secs":"1784336400","message":"zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3"}';

const STEP_1_SIG =
  "wpAPEHD-wRRyfdoLM5FUgwS5OhCVwkQBV5w-XFDSx_VK19QiW5szD6Cuy1ogiNlIlvWtx4LlZPIdAm81eKX0BA==";
const STEP_2_SIG =
  "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==";

const VALID_BODY: ValidatedProofBody = {
  path_index: 0,
  source_kind: "PROOF_CHANNEL",
  completed_transaction_text: SETTLED_TX,
  completed_transaction_sha256: "5554ffa03050cb94173406a85a50aa72c4eca604ab630f0511e61bec7969aebf",
  completed_transaction_octets: new TextEncoder().encode(SETTLED_TX).byteLength,
  wallet_role: "sender",
  s_signature: STEP_2_SIG,
  p_signature:
    "IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==",
  b_amount: "7.75",
  inner_preimage_text: INNER_PREIMAGE,
  inner_sha256: "ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51",
  step_1_signature: STEP_1_SIG,
  step_2_signature: STEP_2_SIG,
  verification_manifest_text: '{"verifier":"fixture","body_index":0}',
  verification_manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

const VALID_BODY_JSON = JSON.stringify(VALID_BODY);
const VALID_RAW_BYTES = new TextEncoder().encode(VALID_BODY_JSON);

function makeRequest(rawBytes: Uint8Array): ProofBodyIntakeRequest {
  return {
    authenticated: {
      tenant_id: "22222222-2222-4222-8222-222222222222",
      operation_id: "33333333-3333-4333-8333-333333333333",
      wallet_role: "sender",
    },
    expected: {
      tenant_id: "22222222-2222-4222-8222-222222222222",
      operation_id: "33333333-3333-4333-8333-333333333333",
      wallet_role: "sender",
    },
    transport: {
      claimed_signature: "x".repeat(86) + "==",
      content_length: rawBytes.byteLength,
      media_type: "application/json",
      request_id: "99999999-9999-4999-8999-999999999999",
      provenance: "test",
    },
    rawBytes,
  };
}

describe("proof-body freeze: schema shape lock", () => {
  it("has the exact frozen key set from the spec", () => {
    const shapeKeys = Object.keys(proofBodySchema.shape);
    expect(shapeKeys).toEqual([...PROOF_BODY_FIELDS]);
  });

  it("frozen field list is exactly 15 fields in canonical sequence", () => {
    expect(PROOF_BODY_FIELDS).toEqual([
      "path_index",
      "source_kind",
      "completed_transaction_text",
      "completed_transaction_sha256",
      "completed_transaction_octets",
      "wallet_role",
      "s_signature",
      "p_signature",
      "b_amount",
      "inner_preimage_text",
      "inner_sha256",
      "step_1_signature",
      "step_2_signature",
      "verification_manifest_text",
      "verification_manifest_sha256",
    ]);
  });

  it("rejects any addition to the frozen field set", () => {
    const withExtra = { ...VALID_BODY, status: "settled" };
    const result = proofBodySchema.safeParse(withExtra);
    expect(result.success).toBe(false);
  });

  it("rejects any removal from the frozen field set", () => {
    const { path_index: _, ...rest } = VALID_BODY;
    const result = proofBodySchema.safeParse(rest);
    expect(result.success).toBe(false);
  });
});

describe("proof-body freeze: round-trip byte identity", () => {
  it("intake accepts a valid body and preserves raw bytes", () => {
    const result = intakeProofBody(makeRequest(VALID_RAW_BYTES));
    expect(result.accepted).toBe(true);
    if (!result.accepted) return;
    expect(result.rawBytes).toEqual(VALID_RAW_BYTES);
  });

  it("preserves completed_transaction_text byte-exactly through intake", () => {
    const result = intakeProofBody(makeRequest(VALID_RAW_BYTES));
    expect(result.accepted).toBe(true);
    if (!result.accepted) return;
    expect(result.body.completed_transaction_text).toBe(SETTLED_TX);
  });

  it("preserves inner_preimage_text byte-exactly through intake", () => {
    const result = intakeProofBody(makeRequest(VALID_RAW_BYTES));
    expect(result.accepted).toBe(true);
    if (!result.accepted) return;
    expect(result.body.inner_preimage_text).toBe(INNER_PREIMAGE);
  });

  it("JSON.stringify of accepted body equals the input JSON", () => {
    const result = intakeProofBody(makeRequest(VALID_RAW_BYTES));
    expect(result.accepted).toBe(true);
    if (!result.accepted) return;
    expect(JSON.stringify(result.body)).toBe(VALID_BODY_JSON);
  });
});

describe("proof-body freeze: non-authority principle", () => {
  it("rejects a supplied 'status' field", () => {
    const raw = new TextEncoder().encode(JSON.stringify({ ...VALID_BODY, status: "settled" }));
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects a supplied 'settled' field", () => {
    const raw = new TextEncoder().encode(JSON.stringify({ ...VALID_BODY, settled: true }));
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects a supplied 'verdict' field", () => {
    const raw = new TextEncoder().encode(
      JSON.stringify({ ...VALID_BODY, verdict: "LANDED_EXACT" }),
    );
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects a supplied 'landed' boolean field", () => {
    const raw = new TextEncoder().encode(JSON.stringify({ ...VALID_BODY, landed: true }));
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });
});

describe("proof-body freeze: rejection — never throws", () => {
  it("rejects malformed JSON with typed error", () => {
    const raw = new TextEncoder().encode("{not valid json");
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("INVALID_JSON");
  });

  it("rejects empty body as invalid JSON", () => {
    const raw = new TextEncoder().encode("");
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("INVALID_JSON");
  });

  it("rejects wrong type for completed_transaction_text", () => {
    const raw = new TextEncoder().encode(
      JSON.stringify({ ...VALID_BODY, completed_transaction_text: 123 }),
    );
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects wrong type for path_index (string)", () => {
    const raw = new TextEncoder().encode(JSON.stringify({ ...VALID_BODY, path_index: "0" }));
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects negative path_index", () => {
    const raw = new TextEncoder().encode(JSON.stringify({ ...VALID_BODY, path_index: -1 }));
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects invalid wallet_role", () => {
    const raw = new TextEncoder().encode(
      JSON.stringify({ ...VALID_BODY, wallet_role: "operator" }),
    );
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects invalid sha256 (uppercase)", () => {
    const raw = new TextEncoder().encode(
      JSON.stringify({
        ...VALID_BODY,
        completed_transaction_sha256:
          "5554FFA03050CB94173406A85A50AA72C4ECA604AB630F0511E61BEC7969AEBF",
      }),
    );
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects missing required fields", () => {
    const raw = new TextEncoder().encode("{}");
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects null body", () => {
    const raw = new TextEncoder().encode("null");
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects duplicate JSON keys", () => {
    const dup = `{"path_index":0,"path_index":1,"source_kind":"PROOF_CHANNEL","completed_transaction_text":"x","completed_transaction_sha256":"${"a".repeat(64)}","completed_transaction_octets":1,"wallet_role":"sender","s_signature":"${"A".repeat(86)}==","p_signature":"","b_amount":"1","inner_preimage_text":"x","inner_sha256":"${"b".repeat(64)}","step_1_signature":"${"C".repeat(86)}==","step_2_signature":"${"D".repeat(86)}==","verification_manifest_text":"x","verification_manifest_sha256":"${"e".repeat(64)}"}`;
    const raw = new TextEncoder().encode(dup);
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
  });

  it("rejects identity mismatch (tenant)", () => {
    const request = makeRequest(VALID_RAW_BYTES);
    const tampered: ProofBodyIntakeRequest = {
      ...request,
      expected: { ...request.expected, tenant_id: "00000000-0000-4000-8000-000000000000" },
    };
    const result = intakeProofBody(tampered);
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("TENANT_MISMATCH");
  });

  it("rejects inconsistent completed_transaction_octets", () => {
    const raw = new TextEncoder().encode(
      JSON.stringify({ ...VALID_BODY, completed_transaction_octets: 99999 }),
    );
    const result = intakeProofBody(makeRequest(raw));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });
});

describe("proof-body freeze: oversize rejection", () => {
  it("rejects bodies exceeding the byte bound", () => {
    const oversized = new Uint8Array(MAX_PROOF_BODY_BYTES + 1).fill(120);
    const result = intakeProofBody(makeRequest(oversized));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.code).toBe("OVERSIZE");
    expect(result.reason).toBe("BUDGET_EXCEEDED");
  });

  it("still captures raw bytes and sha256 on oversize rejection", () => {
    const oversized = new Uint8Array(MAX_PROOF_BODY_BYTES + 10).fill(120);
    const result = intakeProofBody(makeRequest(oversized));
    expect(result.accepted).toBe(false);
    if (result.accepted) return;
    expect(result.rawBytes.byteLength).toBe(MAX_PROOF_BODY_BYTES + 10);
    expect(result.rawSha256).toMatch(/^[0-9a-f]{64}$/);
  });
});
