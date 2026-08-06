// vectors for the strict `get_transaction__v1` envelope parser:
// genesis (protocol vector 1), head over the independently captured receive-golden
// fixtures, the pre-decode digest guarantee (steps 3–5), insertion-sequence
// preservation for downstream preimage reconstruction, and the purity/boundary
// checks (the never-blind-retry rule). Adversarial byte-level fuzzing lives in
// gateway-envelope.fuzz.test.ts.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import * as gatewayEnvelopeModule from "./gateway-envelope.js";
import {
  GATEWAY_RESPONSE_FIELDS,
  parseGatewayEnvelope,
  type GatewayEnvelopeVerdict,
} from "./gateway-envelope.js";

const GEN_DIR = new URL("../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function fixtureBytes(name: string): Uint8Array {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)));
}

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// Wraps settled-transaction bytes in a success envelope by raw text splice — the golden
// fixture bytes ride through verbatim (never re-serialized), exactly as the live gateway
// wraps them.
function headEnvelopeBytes(txText: string): Uint8Array {
  return new TextEncoder().encode(`{"status":true,"code":"success","message":"","data":[${txText}]}`);
}

function genesisEnvelopeBytes(dataLiteral: string): Uint8Array {
  return new TextEncoder().encode(
    `{"status":false,"code":"account_not_found","message":"no account","data":${dataLiteral}}`,
  );
}

// The exact inner construction sequence (positions 1–14) — the expected sequence for the
// insertion-sequence preservation proof.
const P_SECTION_3_INNER_SEQUENCE = [
  "type",
  "version",
  "unix_time_secs",
  "signer_steps",
  "step_1_signer",
  "step_2_signer",
  "step_1_key_public__base64urlsafe",
  "step_2_key_public__base64urlsafe",
  "step_1_state",
  "step_2_state",
  "previous_step_1_state_signature",
  "previous_step_2_state_signature",
  "expiry__unix_time_secs",
  "message",
] as const;

describe("receive-golden fixture provenance", () => {
  it("feeds bytes whose SHA-256 matches the frozen manifest's settled digests", () => {
    const manifest = JSON.parse(fixtureText("manifest.json")) as {
      target: { settled_sha256: string };
      predecessor: { settled_sha256: string };
    };
    expect(sha256Hex(fixtureBytes("target.settled.json"))).toBe(manifest.target.settled_sha256);
    expect(sha256Hex(fixtureBytes("predecessor.settled.json"))).toBe(
      manifest.predecessor.settled_sha256,
    );
  });
});

describe("genesis vector — chain-link equals prior settled step_2_signature / envelope step 4", () => {
  it("classifies the authoritative account-not-found result (data null) as GENESIS", () => {
    const bytes = genesisEnvelopeBytes("null");
    const verdict = parseGatewayEnvelope(bytes);
    expect(verdict.classification).toBe("GENESIS");
    expect(verdict.parsed).toBeNull();
    expect(verdict.rawBytes).toBe(bytes);
    expect(verdict.rawSha256).toBe(sha256Hex(bytes));
  });

  it("classifies the authoritative account-not-found result (data empty object) as GENESIS", () => {
    const verdict = parseGatewayEnvelope(genesisEnvelopeBytes("{}"));
    expect(verdict.classification).toBe("GENESIS");
    expect(verdict.parsed).toBeNull();
  });

  it("rejects v1's looser no_transaction_found heuristic as not genesis (fail closed)", () => {
    const bytes = new TextEncoder().encode(
      `{"status":false,"code":"no_transaction_found","message":"","data":{}}`,
    );
    const verdict = parseGatewayEnvelope(bytes);
    expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
    if (verdict.classification !== "MALFORMED_ENVELOPE") return;
    expect(verdict.reason).toBe("not_authoritative_genesis");
  });

  it("rejects a generic not-found application code as not genesis", () => {
    const bytes = new TextEncoder().encode(`{"status":false,"code":"not_found","message":"","data":null}`);
    const verdict = parseGatewayEnvelope(bytes);
    expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
    if (verdict.classification !== "MALFORMED_ENVELOPE") return;
    expect(verdict.reason).toBe("not_authoritative_genesis");
  });

  it("classifies status:true empty history [] as GENESIS (live virgin-wallet shape)", () => {
    const bytes = new TextEncoder().encode(
      `{"status":true,"code":"success","message":"OK","data":[]}`,
    );
    const verdict = parseGatewayEnvelope(bytes);
    expect(verdict.classification).toBe("GENESIS");
    expect(verdict.parsed).toBeNull();
    expect(verdict.rawSha256).toBe(sha256Hex(bytes));
  });

  it("classifies status:true empty history with opaque code as GENESIS (live gateway)", () => {
    // live probe: code is opaque; discriminator is status:true + data:[].
    const bytes = new TextEncoder().encode(
      `{"status":true,"code":"pq8xgr5opv","message":"OK","data":[]}`,
    );
    const verdict = parseGatewayEnvelope(bytes);
    expect(verdict.classification).toBe("GENESIS");
    expect(verdict.parsed).toBeNull();
  });

  it("rejects status:false empty history array without account_not_found (fail closed)", () => {
    const bytes = new TextEncoder().encode(
      `{"status":false,"code":"ok","message":"","data":[]}`,
    );
    const verdict = parseGatewayEnvelope(bytes);
    expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
    if (verdict.classification !== "MALFORMED_ENVELOPE") return;
    expect(verdict.reason).toBe("not_authoritative_genesis");
  });

  it("rejects account_not_found with a success status as contradictory", () => {
    const bytes = new TextEncoder().encode(
      `{"status":true,"code":"account_not_found","message":"","data":null}`,
    );
    const verdict = parseGatewayEnvelope(bytes);
    expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
  });

  it("rejects account_not_found carrying transaction data as not genesis", () => {
    const txText = fixtureText("target.settled.json");
    const bytes = new TextEncoder().encode(
      `{"status":false,"code":"account_not_found","message":"","data":[${txText}]}`,
    );
    const verdict = parseGatewayEnvelope(bytes);
    expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
    if (verdict.classification !== "MALFORMED_ENVELOPE") return;
    expect(verdict.reason).toBe("not_authoritative_genesis");
  });
});

describe("head vector — envelope step 5 over frozen fixtures", () => {
  it("classifies exactly one complete settled transaction as HEAD", () => {
    const bytes = headEnvelopeBytes(fixtureText("target.settled.json"));
    const verdict = parseGatewayEnvelope(bytes);
    expect(verdict.classification).toBe("HEAD");
    expect(verdict.rawSha256).toBe(sha256Hex(bytes));
    if (verdict.classification !== "HEAD") return;
    expect(verdict.parsed.step_2_signature).toBe(
      "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==",
    );
  });

  it("classifies a genesis-shaped settled transaction as HEAD, not GENESIS (empty predecessor link is transaction data, not account-not-found)", () => {
    // predecessor.settled.json carries an empty previous_step_2_state_signature (the
    // receiver's genesis link) — a settled transaction observed on chain is a head
    // result regardless; GENESIS is reserved for the authoritative account-not-found
    // envelope (chain-link equals prior settled step_2_signature).
    const verdict = parseGatewayEnvelope(headEnvelopeBytes(fixtureText("predecessor.settled.json")));
    expect(verdict.classification).toBe("HEAD");
    if (verdict.classification !== "HEAD") return;
    expect(verdict.parsed.inner.previous_step_2_state_signature).toBe("");
  });

  it("accepts a Buffer input identically to a Uint8Array", () => {
    const bytes = Buffer.from(headEnvelopeBytes(fixtureText("target.settled.json")));
    const verdict = parseGatewayEnvelope(bytes);
    expect(verdict.classification).toBe("HEAD");
  });
});

describe("insertion-sequence preservation — downstream guarantee", () => {
  it("preserves the exact 14-field inner sequence from the fixture bytes", () => {
    const verdict = parseGatewayEnvelope(headEnvelopeBytes(fixtureText("target.settled.json")));
    if (verdict.classification !== "HEAD") throw new Error("expected HEAD verdict");
    expect(Object.keys(verdict.parsed.inner)).toEqual([...P_SECTION_3_INNER_SEQUENCE]);
  });

  it("re-serializes the parsed entry byte-identically to the fixture text", () => {
    const txText = fixtureText("target.settled.json");
    const verdict = parseGatewayEnvelope(headEnvelopeBytes(txText));
    if (verdict.classification !== "HEAD") throw new Error("expected HEAD verdict");
    expect(JSON.stringify(verdict.parsed)).toBe(txText);
  });

  it("preserves the settled entry's fixed top-level sequence", () => {
    const verdict = parseGatewayEnvelope(headEnvelopeBytes(fixtureText("target.settled.json")));
    if (verdict.classification !== "HEAD") throw new Error("expected HEAD verdict");
    expect(Object.keys(verdict.parsed)).toEqual(["inner", "step_1_signature", "step_2_signature"]);
  });
});

describe("digest-before-decode — capture steps 3–5", () => {
  it("yields the SHA-256 of the exact original bytes even when decode fails", () => {
    const decodable = genesisEnvelopeBytes("null");
    const undecodable = Uint8Array.from(decodable, (byte, index) => (index === 60 ? 0xff : byte));
    const verdict = parseGatewayEnvelope(undecodable);
    expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
    if (verdict.classification !== "MALFORMED_ENVELOPE") return;
    expect(verdict.reason).toBe("utf8_decode_failed");
    expect(verdict.rawSha256).toBe(sha256Hex(undecodable));
    expect(verdict.rawSha256).not.toBe(sha256Hex(decodable));
    expect(verdict.rawBytes).toBe(undecodable);
  });

  it("digests the empty body before failing at the JSON step", () => {
    const verdict = parseGatewayEnvelope(new Uint8Array(0));
    expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
    expect(verdict.rawSha256).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    if (verdict.classification !== "MALFORMED_ENVELOPE") return;
    expect(verdict.reason).toBe("not_exactly_one_json_value");
  });
});

describe("purity and boundary — the never-blind-retry rule", () => {
  it("never mutates the input buffer", () => {
    const bytes = headEnvelopeBytes(fixtureText("target.settled.json"));
    const snapshot = Uint8Array.from(bytes);
    parseGatewayEnvelope(bytes);
    expect(bytes).toEqual(snapshot);
  });

  it("is deterministic across repeated calls on the same bytes", () => {
    const bytes = headEnvelopeBytes(fixtureText("target.settled.json"));
    const first = parseGatewayEnvelope(bytes);
    const second = parseGatewayEnvelope(bytes);
    expect(second).toEqual(first);
  });

  it("exports only pure surface — no capability, class, or submit/retry authority", () => {
    const moduleExports = Object.entries(gatewayEnvelopeModule).map(
      ([name, value]) => `${name}:${typeof value}`,
    );
    expect(moduleExports.sort()).toEqual(
      [
        "ENVELOPE_REJECTION_REASONS:object",
        "GATEWAY_ENVELOPE_CLASSIFICATIONS:object",
        "GATEWAY_RESPONSE_FIELDS:object",
        "GENESIS_ACCOUNT_NOT_FOUND_CODE:string",
        "GET_TRANSACTION_ACTION_NAME:string",
        "SETTLED_TRANSACTION_FIELDS:object",
        "SUPPORTED_TRANSACTION_VERSION:string",
        "parseGatewayEnvelope:function",
      ].sort(),
    );
  });
});

describe("GATEWAY_RESPONSE_FIELDS mirror parity — production gateway transport freeze", () => {
  it("matches the canonical freeze in generic-node-contracts byte-for-byte", () => {
    const sourceText = readFileSync(
      fileURLToPath(
        new URL(
          "../../../generic-node-contracts/src/transfer-code/candidate-intake.contract.ts",
          import.meta.url,
        ),
      ),
      "utf8",
    );
    expect(sourceText).toContain(
      `export const GATEWAY_RESPONSE_FIELDS = ["status", "code", "message", "data"] as const;`,
    );
    expect([...GATEWAY_RESPONSE_FIELDS]).toEqual(["status", "code", "message", "data"]);
  });
});

describe("verdict surface", () => {
  it("narrows GENESIS/HEAD/MALFORMED_ENVELOPE through the discriminated union", () => {
    const verdicts: GatewayEnvelopeVerdict[] = [
      parseGatewayEnvelope(genesisEnvelopeBytes("null")),
      parseGatewayEnvelope(headEnvelopeBytes(fixtureText("target.settled.json"))),
      parseGatewayEnvelope(new Uint8Array(0)),
    ];
    expect(verdicts.map((verdict) => verdict.classification)).toEqual([
      "GENESIS",
      "HEAD",
      "MALFORMED_ENVELOPE",
    ]);
  });
});
