import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  intakeProofBody,
  MAX_PROOF_BODY_BYTES,
  PROOF_BODY_FIELDS,
  proofBodySchema,
  type ProofBodyIntakeRequest,
  type ProofBodyIntakeResult,
  type ValidatedProofBody,
} from "../src/proof-body/index.js";

// proof-body intake envelope tests.
//
// Governing spec: the data model
// (lineage_path_bodies), the API contract (wire conventions and the
// INDETERMINATE reason taxonomy), signing custody (exact-byte rules),
// observation verification (capture-before-parse, non-authority).
//
// Covers the acceptance checklist: capture-before-parse, identity binding before
// schema validation, duplicate-key/ambiguous-encoding/wrong-identity rejection, byte-exact
// raw preservation, strict-schema rejection, the oversize budget, and the guarantee that a
// rejection never carries an authoritative projection.

const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const REQUEST_ID = "99999999-9999-4999-8999-999999999999";

const SETTLED_TX =
  '{"inner":{"type":"unique_combinable","version":"2","unix_time_secs":"1784332800.125","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","step_2_key_public__base64urlsafe":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25"},"previous_step_1_state_signature":"IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==","previous_step_2_state_signature":"","expiry__unix_time_secs":"1784336400","message":"zp1:33333333-3333-4333-8333-333333333333"},"step_1_signature":"wpAPEHD-wRRyfdoLM5FUgwS5OhCVwkQBV5w-XFDSx_VK19QiW5szD6Cuy1ogiNlIlvWtx4LlZPIdAm81eKX0BA==","step_2_signature":"uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw=="}';

const INNER_PREIMAGE =
  '{"type":"unique_combinable","version":"2","unix_time_secs":"1784332800.125","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25"}}';

const MANIFEST_TEXT = '{"verifier":"fixture","body_index":0}';

const SIG_S = "wpAPEHD-wRRyfdoLM5FUgwS5OhCVwkQBV5w-XFDSx_VK19QiW5szD6Cuy1ogiNlIlvWtx4LlZPIdAm81eKX0BA==";
const SIG_STEP_1 = "MsWTpjUtoofWFb13BCpLqLB6tgYiasFakfd2hufS2V2dHg7N2PdRe8n-wrqQhJKc3-Bml7xK6jUfEv2BBiPxAA==";
const SIG_STEP_2 = "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==";

const encoder = new TextEncoder();

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function byteLength(text: string): number {
  return encoder.encode(text).byteLength;
}

// Frozen field sequence. Building the object literal in this
// exact sequence makes JSON.stringify(body) the canonical wire form, so the byte-identity
// assertions below are meaningful.
function validBody(): ValidatedProofBody {
  return {
    path_index: 0,
    source_kind: "PROOF_CHANNEL",
    completed_transaction_text: SETTLED_TX,
    completed_transaction_sha256: sha256Hex(SETTLED_TX),
    completed_transaction_octets: byteLength(SETTLED_TX),
    wallet_role: "sender",
    s_signature: SIG_S,
    p_signature: "",
    b_amount: "7.75",
    inner_preimage_text: INNER_PREIMAGE,
    inner_sha256: sha256Hex(INNER_PREIMAGE),
    step_1_signature: SIG_STEP_1,
    step_2_signature: SIG_STEP_2,
    verification_manifest_text: MANIFEST_TEXT,
    verification_manifest_sha256: sha256Hex(MANIFEST_TEXT),
  };
}

function canonicalBytes(body: ValidatedProofBody = validBody()): Uint8Array {
  return encoder.encode(JSON.stringify(body));
}

interface IdentityOverrides {
  readonly authenticatedTenant?: string;
  readonly authenticatedOperation?: string;
  readonly authenticatedRole?: "sender" | "receiver";
  readonly expectedTenant?: string;
  readonly expectedOperation?: string;
  readonly expectedRole?: "sender" | "receiver";
}

function makeRequest(rawBytes: Uint8Array, overrides: IdentityOverrides = {}): ProofBodyIntakeRequest {
  return {
    authenticated: {
      tenant_id: overrides.authenticatedTenant ?? TENANT_ID,
      operation_id: overrides.authenticatedOperation ?? OPERATION_ID,
      wallet_role: overrides.authenticatedRole ?? "sender",
    },
    expected: {
      tenant_id: overrides.expectedTenant ?? TENANT_ID,
      operation_id: overrides.expectedOperation ?? OPERATION_ID,
      wallet_role: overrides.expectedRole ?? "sender",
    },
    transport: {
      claimed_signature: SIG_S,
      content_length: rawBytes.byteLength,
      media_type: "application/json; charset=utf-8",
      request_id: REQUEST_ID,
      provenance: "PROOF_CHANNEL",
    },
    rawBytes,
  };
}

function assertRejected(result: ProofBodyIntakeResult): asserts result is Extract<
  ProofBodyIntakeResult,
  { accepted: false }
> {
  if (result.accepted) {
    throw new Error("expected a rejected result");
  }
}

describe("proof-body intake: frozen schema shape", () => {
  it("freezes exactly the 15 lineage_path_bodies fields in canonical sequence", () => {
    expect([...PROOF_BODY_FIELDS]).toEqual([
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
    expect(Object.keys(proofBodySchema.shape)).toEqual([...PROOF_BODY_FIELDS]);
  });
});

describe("proof-body intake: capture-before-parse", () => {
  it("captures raw bytes and digest even when JSON parse fails", () => {
    const rawBytes = encoder.encode("{this is not json");
    const result = intakeProofBody(makeRequest(rawBytes));
    assertRejected(result);
    expect(result.code).toBe("INVALID_JSON");
    expect(result.rawBytes).toEqual(rawBytes);
    expect(result.rawSha256).toBe(createHash("sha256").update(rawBytes).digest("hex"));
  });

  it("captures raw bytes and digest even when UTF-8 decode fails", () => {
    const rawBytes = new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]);
    const result = intakeProofBody(makeRequest(rawBytes));
    assertRejected(result);
    expect(result.code).toBe("AMBIGUOUS_ENCODING");
    expect(result.rawBytes).toEqual(rawBytes);
    expect(result.rawSha256).toBe(createHash("sha256").update(rawBytes).digest("hex"));
  });

  it("captures raw bytes and digest on an oversize body before any parse", () => {
    const rawBytes = new Uint8Array(MAX_PROOF_BODY_BYTES + 1).fill(0x78);
    const result = intakeProofBody(makeRequest(rawBytes));
    assertRejected(result);
    expect(result.reason).toBe("BUDGET_EXCEEDED");
    expect(result.rawBytes.byteLength).toBe(MAX_PROOF_BODY_BYTES + 1);
    expect(result.rawSha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("proof-body intake: identity binding before schema validation", () => {
  it("accepts when the authenticated identity binds to the expected identity", () => {
    const result = intakeProofBody(makeRequest(canonicalBytes()));
    expect(result.accepted).toBe(true);
  });

  it("rejects a well-formed body whose tenant does not bind", () => {
    const result = intakeProofBody(
      makeRequest(canonicalBytes(), { expectedTenant: "00000000-0000-4000-8000-000000000000" }),
    );
    assertRejected(result);
    expect(result.reason).toBe("IDENTITY_MISMATCH");
    expect(result.code).toBe("TENANT_MISMATCH");
  });

  it("rejects a well-formed body whose operation does not bind", () => {
    const result = intakeProofBody(
      makeRequest(canonicalBytes(), { expectedOperation: "00000000-0000-4000-8000-000000000000" }),
    );
    assertRejected(result);
    expect(result.code).toBe("OPERATION_MISMATCH");
  });

  it("rejects a well-formed body whose role does not bind", () => {
    const result = intakeProofBody(makeRequest(canonicalBytes(), { expectedRole: "receiver" }));
    assertRejected(result);
    expect(result.code).toBe("ROLE_MISMATCH");
  });

  it("checks identity before schema validation (mismatch wins over a schema-invalid body)", () => {
    // The body is schema-invalid (empty object) AND identity-mismatched; the rejection must
    // be the identity mismatch, proving the binding check runs before schema validation.
    const result = intakeProofBody(
      makeRequest(encoder.encode("{}"), { expectedTenant: "00000000-0000-4000-8000-000000000000" }),
    );
    assertRejected(result);
    expect(result.code).toBe("TENANT_MISMATCH");
  });
});

describe("proof-body intake: ambiguous encoding", () => {
  it("rejects non-canonical (invalid) UTF-8", () => {
    const rawBytes = new Uint8Array([0x22, 0x80, 0x22]);
    const result = intakeProofBody(makeRequest(rawBytes));
    assertRejected(result);
    expect(result.reason).toBe("MALFORMED_ENVELOPE");
    expect(result.code).toBe("AMBIGUOUS_ENCODING");
  });

  it("rejects a UTF-8 BOM even when the rest is valid JSON", () => {
    const bom = new Uint8Array([0xef, 0xbb, 0xbf]);
    const body = canonicalBytes();
    const rawBytes = new Uint8Array(bom.byteLength + body.byteLength);
    rawBytes.set(bom, 0);
    rawBytes.set(body, bom.byteLength);
    const result = intakeProofBody(makeRequest(rawBytes));
    assertRejected(result);
    expect(result.code).toBe("AMBIGUOUS_ENCODING");
  });
});

describe("proof-body intake: duplicate JSON keys", () => {
  it("rejects a body with a duplicated object key", () => {
    const canonical = JSON.stringify(validBody());
    const duplicated = canonical.replace(
      '"wallet_role":"sender"',
      '"wallet_role":"sender","wallet_role":"receiver"',
    );
    const result = intakeProofBody(makeRequest(encoder.encode(duplicated)));
    assertRejected(result);
    expect(result.reason).toBe("MALFORMED_ENVELOPE");
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
  });

  it("accepts repeated string values that are not object keys", () => {
    // The same signature literal appears in several fields; only repeated KEYS are rejected.
    const result = intakeProofBody(makeRequest(canonicalBytes()));
    expect(result.accepted).toBe(true);
  });

  // Blocker regression: escape-variant keys that decode to the same string must be
  // detected as duplicates. JSON.parse treats `b_amount` and `b\u005famount` as one key
  // (last-wins); the scanner must agree.
  it("rejects escape-variant duplicate: b_amount vs b\\u005famount (escaped underscore)", () => {
    // \u005f is the underscore character. The raw JSON text has two distinct key spellings
    // that decode to the same key `b_amount`.
    const canonical = JSON.stringify(validBody());
    const forged = canonical.replace(
      '"b_amount":"7.75"',
      '"b_amount":"7.75","b\\u005famount":"999999.99"',
    );
    const result = intakeProofBody(makeRequest(encoder.encode(forged)));
    assertRejected(result);
    expect(result.reason).toBe("MALFORMED_ENVELOPE");
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
    expect(result.detail).toContain("b_amount");
  });

  it("rejects escape-variant duplicate: wallet_role vs wallet\\u005frole", () => {
    const canonical = JSON.stringify(validBody());
    const forged = canonical.replace(
      '"wallet_role":"sender"',
      '"wallet_role":"sender","wallet\\u005frole":"receiver"',
    );
    const result = intakeProofBody(makeRequest(encoder.encode(forged)));
    assertRejected(result);
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
    expect(result.detail).toContain("wallet_role");
  });

  it("rejects escape-variant duplicate: path_index via full \\uXXXX escaping", () => {
    // Every character of `path_index` spelled as \uXXXX escapes.
    const canonical = JSON.stringify(validBody());
    const escapedKey =
      "\\u0070\\u0061\\u0074\\u0068\\u005f\\u0069\\u006e\\u0064\\u0065\\u0078"; // path_index
    const forged = canonical.replace(
      '"path_index":0',
      `"path_index":0,"${escapedKey}":1`,
    );
    const result = intakeProofBody(makeRequest(encoder.encode(forged)));
    assertRejected(result);
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
    expect(result.detail).toContain("path_index");
  });

  it("rejects escape-variant duplicate for source_kind (\\u005f for underscore)", () => {
    const canonical = JSON.stringify(validBody());
    const forged = canonical.replace(
      '"source_kind":"PROOF_CHANNEL"',
      '"source_kind":"PROOF_CHANNEL","source\\u005fkind":"CANONICAL_LEDGER"',
    );
    const result = intakeProofBody(makeRequest(encoder.encode(forged)));
    assertRejected(result);
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
    expect(result.detail).toContain("source_kind");
  });

  it("rejects escape-variant duplicate for inner_sha256 (\\u005f for underscore)", () => {
    const canonical = JSON.stringify(validBody());
    const forged = canonical.replace(
      `"inner_sha256":"${sha256Hex(INNER_PREIMAGE)}"`,
      `"inner_sha256":"${sha256Hex(INNER_PREIMAGE)}","inner\\u005fsha256":"${"0".repeat(64)}"`,
    );
    const result = intakeProofBody(makeRequest(encoder.encode(forged)));
    assertRejected(result);
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
    expect(result.detail).toContain("inner_sha256");
  });

  it("rejects escape-variant duplicate for step_1_signature (\\u005f for underscore)", () => {
    const canonical = JSON.stringify(validBody());
    const forged = canonical.replace(
      `"step_1_signature":"${SIG_STEP_1}"`,
      `"step_1_signature":"${SIG_STEP_1}","step\\u005f1_signature":"forged"`,
    );
    const result = intakeProofBody(makeRequest(encoder.encode(forged)));
    assertRejected(result);
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
    expect(result.detail).toContain("step_1_signature");
  });
});

describe("proof-body intake: escape-variant duplicate keys (forgery vector)", () => {
  // The pre-fix findDuplicateKey compared RAW key tokens, so an escaped duplicate key
  // ("b_amount") and its plain form ("b_amount") read as two distinct keys to the
  // scanner but ONE key (last wins) to JSON.parse — letting a forged field slip past intake
  // while a byte-level reader takes the first occurrence. Each fixture below is ACCEPTED by
  // the pre-fix scanner (its findDuplicateKey returns null → schema sees exactly 15 collapsed
  // keys → body accepted) and MUST now fail closed with DUPLICATE_JSON_KEY.

  function collapsedKeys(rawBytes: Uint8Array): Record<string, unknown> {
    return JSON.parse(new TextDecoder().decode(rawBytes)) as Record<string, unknown>;
  }

  it("rejects an escaped-second duplicate that forges b_amount near the 1e8 ceiling", () => {
    const canonical = JSON.stringify(validBody());
    // Honest "7.75" first (plain key), forged "999999.99" second (escaped key). A last-wins
    // parse surfaces the forged amount; a byte-level reader takes 7.75 first.
    const forged = canonical.replace(
      '"b_amount":"7.75"',
      '"b_amount":"7.75","\\u0062_amount":"999999.99"',
    );
    const rawBytes = encoder.encode(forged);
    // Sanity: the forgery is really present, and a last-wins parse WOULD surface it.
    expect(collapsedKeys(rawBytes).b_amount).toBe("999999.99");
    const result = intakeProofBody(makeRequest(rawBytes));
    assertRejected(result);
    expect(result.reason).toBe("MALFORMED_ENVELOPE");
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
  });

  it("rejects an escaped-first duplicate of a non-amount field (wallet_role)", () => {
    const canonical = JSON.stringify(validBody());
    const forged = canonical.replace(
      '"wallet_role":"sender"',
      '"wallet_ro\\u006ce":"sender","wallet_role":"receiver"',
    );
    const rawBytes = encoder.encode(forged);
    expect(collapsedKeys(rawBytes).wallet_role).toBe("receiver");
    const result = intakeProofBody(makeRequest(rawBytes));
    assertRejected(result);
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
  });

  it("rejects a duplicate whose BOTH occurrences are escaped differently (inner_sha256)", () => {
    const canonical = JSON.stringify(validBody());
    const hex = sha256Hex(INNER_PREIMAGE);
    // Neither token is the plain form — proves the comparison is decoded-vs-decoded, not
    // merely raw-vs-decoded. Both escaped keys decode to inner_sha256.
    const forged = canonical.replace(
      `"inner_sha256":"${hex}"`,
      `"inner_\\u0073ha256":"${hex}","inner_sha\\u0032\\u0035\\u0036":"${hex}"`,
    );
    const rawBytes = encoder.encode(forged);
    const result = intakeProofBody(makeRequest(rawBytes));
    assertRejected(result);
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
  });

  it("still rejects a plain literal duplicate (regression guard for the decode change)", () => {
    const canonical = JSON.stringify(validBody());
    const duplicated = canonical.replace(
      '"b_amount":"7.75"',
      '"b_amount":"7.75","b_amount":"999999.99"',
    );
    const result = intakeProofBody(makeRequest(encoder.encode(duplicated)));
    assertRejected(result);
    expect(result.code).toBe("DUPLICATE_JSON_KEY");
  });
});

describe("proof-body intake: returned rawBytes are decoupled from the caller's buffer", () => {
  it("returns a defensive copy so caller mutation cannot desync rawBytes from rawSha256", () => {
    const rawBytes = canonicalBytes();
    const result = intakeProofBody(makeRequest(rawBytes));
    expect(result.accepted).toBe(true);
    const digestBefore = result.rawSha256;
    // Mutate the caller's original buffer AFTER intake returned.
    rawBytes.fill(0x00);
    // The result's bytes are untouched and still hash to the captured digest.
    expect(result.rawSha256).toBe(digestBefore);
    expect(createHash("sha256").update(result.rawBytes).digest("hex")).toBe(result.rawSha256);
    expect(result.rawBytes.some((b) => b !== 0x00)).toBe(true);
  });

  it("also decouples rawBytes on a rejected result", () => {
    const rawBytes = encoder.encode("{not valid json");
    const result = intakeProofBody(makeRequest(rawBytes));
    assertRejected(result);
    const digest = result.rawSha256;
    rawBytes.fill(0x00);
    expect(createHash("sha256").update(result.rawBytes).digest("hex")).toBe(digest);
  });
});

describe("proof-body intake: digest fields are not verified at intake (non-authority)", () => {
  it("accepts a well-formed body whose completed_transaction_sha256 does NOT match its text", () => {
    // Deliberate boundary: the digest is well-formed (64 lowercase hex) but is NOT
    // sha256(completed_transaction_text). Intake validates digest FORMAT only; the
    // verifier recomputes and byte-compares every digest against the fresh-head-anchored body
    // ("digest indexes are not equality authority", the data model). This test PINS that
    // asymmetry — if a digest self-check is ever added to intake, this fails and forces a
    // conscious decision rather than a silent encroachment on the verifier's authority.
    const wrongDigest = "0".repeat(64);
    const body: ValidatedProofBody = { ...validBody(), completed_transaction_sha256: wrongDigest };
    const result = intakeProofBody(makeRequest(canonicalBytes(body)));
    expect(result.accepted).toBe(true);
  });
});

describe("proof-body intake: valid body acceptance and byte-exact preservation", () => {
  it("accepts a valid body with every frozen field", () => {
    const result = intakeProofBody(makeRequest(canonicalBytes()));
    expect(result.accepted).toBe(true);
    if (!result.accepted) return;
    expect(result.body).toEqual(validBody());
  });

  it("preserves the exact raw bytes (no re-serialization step in between)", () => {
    const rawBytes = canonicalBytes();
    const result = intakeProofBody(makeRequest(rawBytes));
    expect(result.accepted).toBe(true);
    if (!result.accepted) return;
    expect(result.rawBytes).toEqual(rawBytes);
    expect(result.rawSha256).toBe(createHash("sha256").update(rawBytes).digest("hex"));
  });

  it("satisfies JSON.stringify byte identity for a canonical body", () => {
    const body = validBody();
    const canonical = JSON.stringify(body);
    const result = intakeProofBody(makeRequest(encoder.encode(canonical)));
    expect(result.accepted).toBe(true);
    if (!result.accepted) return;
    expect(JSON.stringify(result.body)).toBe(canonical);
  });

  it("preserves completed_transaction_text and inner_preimage_text byte-exactly", () => {
    const result = intakeProofBody(makeRequest(canonicalBytes()));
    expect(result.accepted).toBe(true);
    if (!result.accepted) return;
    expect(result.body.completed_transaction_text).toBe(SETTLED_TX);
    expect(result.body.inner_preimage_text).toBe(INNER_PREIMAGE);
  });

  it("accepts an empty p_signature (genesis predecessor) and a populated one", () => {
    const genesis = intakeProofBody(makeRequest(canonicalBytes()));
    expect(genesis.accepted).toBe(true);

    const withPredecessor: ValidatedProofBody = { ...validBody(), p_signature: SIG_STEP_1 };
    const populated = intakeProofBody(makeRequest(canonicalBytes(withPredecessor)));
    expect(populated.accepted).toBe(true);
  });
});

describe("proof-body intake: strict schema rejection", () => {
  it("rejects an unknown field (.strict())", () => {
    const withExtra = { ...validBody(), authoritative_verdict: "LANDED_EXACT" };
    const result = intakeProofBody(makeRequest(encoder.encode(JSON.stringify(withExtra))));
    assertRejected(result);
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects a missing required field", () => {
    const { b_amount: _omitted, ...rest } = validBody();
    const result = intakeProofBody(makeRequest(encoder.encode(JSON.stringify(rest))));
    assertRejected(result);
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects a JSON number for b_amount (amounts must be decimal strings)", () => {
    const raw = encoder.encode(JSON.stringify({ ...validBody(), b_amount: 7.75 }));
    const result = intakeProofBody(makeRequest(raw));
    assertRejected(result);
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects a source_kind other than PROOF_CHANNEL", () => {
    const wrongKind = { ...validBody(), source_kind: "CANONICAL_LEDGER" };
    const result = intakeProofBody(makeRequest(encoder.encode(JSON.stringify(wrongKind))));
    assertRejected(result);
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects an inconsistent completed_transaction_octets", () => {
    const wrongOctets = { ...validBody(), completed_transaction_octets: byteLength(SETTLED_TX) + 1 };
    const result = intakeProofBody(makeRequest(encoder.encode(JSON.stringify(wrongOctets))));
    assertRejected(result);
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });

  it("rejects an uppercase sha256 hex value", () => {
    const upper = { ...validBody(), inner_sha256: sha256Hex(INNER_PREIMAGE).toUpperCase() };
    const result = intakeProofBody(makeRequest(encoder.encode(JSON.stringify(upper))));
    assertRejected(result);
    expect(result.code).toBe("SCHEMA_VIOLATION");
  });
});

describe("proof-body intake: oversize budget", () => {
  it("rejects a body over 64 KiB as BUDGET_EXCEEDED", () => {
    const huge: ValidatedProofBody = {
      ...validBody(),
      verification_manifest_text: `{"pad":"${"x".repeat(MAX_PROOF_BODY_BYTES)}"}`,
    };
    const rawBytes = encoder.encode(JSON.stringify(huge));
    expect(rawBytes.byteLength).toBeGreaterThan(MAX_PROOF_BODY_BYTES);
    const result = intakeProofBody(makeRequest(rawBytes));
    assertRejected(result);
    expect(result.reason).toBe("BUDGET_EXCEEDED");
    expect(result.code).toBe("OVERSIZE");
  });
});

describe("proof-body intake: a rejection never produces authoritative projection fields", () => {
  const rejectionCases: ReadonlyArray<{ readonly name: string; readonly build: () => ProofBodyIntakeRequest }> = [
    {
      name: "invalid JSON",
      build: () => makeRequest(encoder.encode("{nope")),
    },
    {
      name: "ambiguous encoding",
      build: () => makeRequest(new Uint8Array([0xff, 0x80, 0x80])),
    },
    {
      name: "duplicate key",
      build: () =>
        makeRequest(
          encoder.encode(
            JSON.stringify(validBody()).replace('"path_index":0', '"path_index":0,"path_index":0'),
          ),
        ),
    },
    {
      name: "identity mismatch",
      build: () => makeRequest(canonicalBytes(), { expectedRole: "receiver" }),
    },
    {
      name: "schema violation",
      build: () => makeRequest(encoder.encode(JSON.stringify({ ...validBody(), b_amount: "not-an-amount" }))),
    },
    {
      name: "oversize",
      build: () => makeRequest(new Uint8Array(MAX_PROOF_BODY_BYTES + 1).fill(0x78)),
    },
  ];

  it.each(rejectionCases)("carries no projection body on rejection: $name", ({ build }) => {
    const result = intakeProofBody(build());
    assertRejected(result);
    expect(result.accepted).toBe(false);
    expect(result).not.toHaveProperty("body");
    expect(result.rawBytes).toBeInstanceOf(Uint8Array);
    expect(result.rawSha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("proof-body intake: never throws", () => {
  it("returns a typed result for every hostile input rather than throwing", () => {
    const hostile: Uint8Array[] = [
      new Uint8Array(0),
      encoder.encode("null"),
      encoder.encode("[]"),
      encoder.encode('"a string"'),
      encoder.encode('{"path_index":0,"path_index":1}'),
      new Uint8Array([0x00, 0x01, 0x02]),
    ];
    for (const rawBytes of hostile) {
      const result = intakeProofBody(makeRequest(rawBytes));
      expect(typeof result.accepted).toBe("boolean");
    }
  });
});

// deliberate asymmetry: intake does NOT cross-check the three supplied *_sha256
// digests against their texts. Digest verification is the verifier's exclusive job;
// the envelope only mirrors the octet storage CHECK. See intake.ts comment.
