// Schema alignment: every verdict this stage emits maps onto a
// `gateway_observations` row the frozen CHECK-constraint verifier
// (verifyGatewayObservationRecord) accepts, and the gate demonstrably bites on a
// mis-shaped row. VERIFIED maps to VERIFIED_HEAD head material; the three non-verified
// outcomes map 1:1 to their enum members with the CHECK-F null shape; genesis is
// modelled through GENESIS_PROJECTION + the A.7 genesis fingerprint so the downstream
// record layer needs no construction authority of its own.
import {
  OBSERVATION_PARSE_RESULTS,
  verifyGatewayObservationRecord,
  type GatewayObservationRecord,
} from "@zucoins/generic-node-contracts";
import { Buffer } from "node:buffer";
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { GENESIS_PROJECTION } from "../protocol/wallet-role.js";
import { parseGatewayEnvelope, type ParsedSettledTransaction } from "./gateway-envelope.js";
import {
  TRANSACTION_VERIFY_OUTCOMES,
  computeWalletHeadFingerprint,
  verifySettledTransaction,
  type VerifiedTransactionVerdict,
} from "./transaction-verify.js";

const GEN_DIR = new URL("../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

function headParsed(name: string): ParsedSettledTransaction {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${fixtureText(name)}]}`,
  );
  const verdict = parseGatewayEnvelope(bytes);
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope verdict");
  return verdict.parsed;
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};
const SENDER_KEY = MANIFEST.public_keys.seed_02;
const RECEIVER_KEY = MANIFEST.public_keys.seed_03;

function verifiedTarget(walletKey: string): VerifiedTransactionVerdict {
  const verdict = verifySettledTransaction(headParsed("target.settled.json"), walletKey);
  if (verdict.verdict !== "VERIFIED") throw new Error("expected VERIFIED");
  return verdict;
}

// A row skeleton satisfying every CHECK for some parse result; each test overrides
// exactly the fields its shape governs.
function observationRecord(overrides: Partial<GatewayObservationRecord>): GatewayObservationRecord {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    observer_id: "22222222-2222-4222-8222-222222222222",
    endpoint_fingerprint: "a".repeat(64),
    wallet_id: null,
    wallet_public_key: RECEIVER_KEY,
    wallet_seq: 1,
    observed_at: "2026-07-18T00:00:00.000Z",
    http_status: 200,
    raw_response_bytes: new Uint8Array([0x7b, 0x7d]),
    raw_response_sha256: "b".repeat(64),
    parse_result: "VERIFIED_HEAD",
    relationship: "FIRST",
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
    previous_recorded_observation_id: null,
    created_at: "2026-07-18T00:00:00.000Z",
    ...overrides,
  };
}

function headRecord(verdict: VerifiedTransactionVerdict, walletKey: string): GatewayObservationRecord {
  return observationRecord({
    parse_result: "VERIFIED_HEAD",
    relationship: "FIRST",
    wallet_public_key: walletKey,
    semantic_fingerprint: verdict.semanticFingerprint,
    state_changed: true,
    wallet_role: verdict.projection.role,
    s_signature: verdict.projection.S,
    p_signature: verdict.projection.P,
    b_amount: verdict.projection.B,
    inner_preimage_text: verdict.innerPreimageText,
    step_1_signature: verdict.transaction.step_1_signature,
    step_2_signature: verdict.transaction.step_2_signature,
    completed_transaction_text: verdict.completedTransactionText,
    completed_transaction_sha256: verdict.completedTransactionSha256,
  });
}

// Test-only re-signing over a mutated inner with the manifest's declared filled Ed25519
// seeds (02 = sender, 03 = receiver), preimages taken with JSON.stringify directly on the
// insertion-sequenced object — the same construction transaction-verify.ts performs.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function signAsSeed(preimageText: string, seed: number): string {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.alloc(32, seed)]),
    format: "der",
    type: "pkcs8",
  });
  return `${sign(null, Buffer.from(preimageText, "utf8"), privateKey).toString("base64url")}==`;
}

function resigned(mutate: (inner: Record<string, unknown>) => void): ParsedSettledTransaction {
  const tx = JSON.parse(
    JSON.stringify(headParsed("target.settled.json")),
  ) as ParsedSettledTransaction;
  const inner = tx.inner as Record<string, unknown>;
  mutate(inner);
  const step1Signature = signAsSeed(JSON.stringify(inner), 2);
  const step2Signature = signAsSeed(
    JSON.stringify({ inner, step_1_signature: step1Signature }),
    3,
  );
  return { ...tx, step_1_signature: step1Signature, step_2_signature: step2Signature };
}

describe("VERIFIED maps to a schema-valid VERIFIED_HEAD row", () => {
  it("satisfies every CHECK constraint for the receiver", () => {
    const verdict = verifiedTarget(RECEIVER_KEY);
    expect(verifyGatewayObservationRecord(headRecord(verdict, RECEIVER_KEY))).toEqual([]);
  });

  it("satisfies every CHECK constraint for the sender (padded predecessor P)", () => {
    const verdict = verifiedTarget(SENDER_KEY);
    const record = headRecord(verdict, SENDER_KEY);
    expect(record.wallet_role).toBe("sender");
    expect(verifyGatewayObservationRecord(record)).toEqual([]);
  });

  // The stage must not reject upstream what the frozen storage layer accepts downstream: the
  // `zkz_balance_text` domain (observation/scalars.contract.ts) is grammar-only, so a
  // foreign-signed non-canonical balance is a legal b_amount. This case proves the whole
  // path — verify, project, record — carries "2.50" verbatim (canonical ZKZ amount contract).
  it("satisfies every CHECK constraint with a verbatim non-canonical foreign b_amount", () => {
    const verdict = verifySettledTransaction(
      resigned((inner) => {
        inner.step_2_state = { amount: "2.50" };
      }),
      RECEIVER_KEY,
    );
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;

    const record = headRecord(verdict, RECEIVER_KEY);
    expect(record.b_amount).toBe("2.50");
    expect(verifyGatewayObservationRecord(record)).toEqual([]);
  });
});

describe("non-verified outcomes map to schema-valid CHECK-F rows", () => {
  it("UNVERIFIED_SIGNATURE carries the all-null non-verified shape", () => {
    const tx = headParsed("target.settled.json");
    const verdict = verifySettledTransaction(
      { ...tx, step_1_signature: `x${tx.step_1_signature.slice(1)}` },
      RECEIVER_KEY,
    );
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    const record = observationRecord({
      parse_result: "UNVERIFIED_SIGNATURE",
      relationship: "NOT_APPLICABLE",
    });
    expect(verifyGatewayObservationRecord(record)).toEqual([]);
  });

  it("WALLET_ROLE_INVALID carries the all-null non-verified shape", () => {
    const verdict = verifySettledTransaction(
      headParsed("target.settled.json"),
      MANIFEST.public_keys.seed_05,
    );
    expect(verdict.verdict).toBe("WALLET_ROLE_INVALID");
    const record = observationRecord({
      parse_result: "WALLET_ROLE_INVALID",
      relationship: "NOT_APPLICABLE",
    });
    expect(verifyGatewayObservationRecord(record)).toEqual([]);
  });

  it("MALFORMED_TRANSACTION carries the all-null non-verified shape", () => {
    const tx = headParsed("target.settled.json");
    const inner = { ...tx.inner, extra_field: "x" } as typeof tx.inner;
    const verdict = verifySettledTransaction({ ...tx, inner }, RECEIVER_KEY);
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    const record = observationRecord({
      parse_result: "MALFORMED_TRANSACTION",
      relationship: "NOT_APPLICABLE",
    });
    expect(verifyGatewayObservationRecord(record)).toEqual([]);
  });
});

describe("genesis modelling — VERIFIED_GENESIS row via GENESIS_PROJECTION", () => {
  it("satisfies the CHECK-D genesis shape with the A.7 genesis fingerprint", () => {
    const genesisFingerprint = computeWalletHeadFingerprint({
      walletPublicKey: RECEIVER_KEY,
      stateKind: "GENESIS",
      sSignature: GENESIS_PROJECTION.S,
      pSignature: GENESIS_PROJECTION.P,
      bAmount: GENESIS_PROJECTION.B,
      innerSha256: GENESIS_PROJECTION.I,
      step1Signature: null,
      step2Signature: null,
    });
    const record = observationRecord({
      parse_result: "VERIFIED_GENESIS",
      relationship: "FIRST",
      semantic_fingerprint: genesisFingerprint,
      state_changed: false,
      wallet_role: "genesis",
      s_signature: "",
      p_signature: "",
      b_amount: "0",
    });
    expect(verifyGatewayObservationRecord(record)).toEqual([]);
  });
});

describe("the schema gate bites on mis-shaped rows", () => {
  it("flags a row claiming VERIFIED_HEAD with a non-verified shape", () => {
    const record = observationRecord({
      parse_result: "VERIFIED_HEAD",
      relationship: "NOT_APPLICABLE",
    });
    const violations = verifyGatewayObservationRecord(record);
    expect(violations.length).toBeGreaterThan(0);
    expect(violations).toContain("FIELD_A_FINGERPRINT_IFF_VERIFIED");
    expect(violations).toContain("FIELD_C_HEAD_MATERIAL_IFF_HEAD");
    expect(violations).toContain("FIELD_E_HEAD_SHAPE");
  });

  it("flags a non-verified row leaking head material", () => {
    const verdict = verifiedTarget(RECEIVER_KEY);
    const record = observationRecord({
      parse_result: "UNVERIFIED_SIGNATURE",
      relationship: "NOT_APPLICABLE",
      step_1_signature: verdict.transaction.step_1_signature,
    });
    expect(verifyGatewayObservationRecord(record)).toContain("FIELD_F_NONVERIFIED_SHAPE");
  });
});

describe("verdict vocabulary alignment with observation_parse_result", () => {
  it("maps every stage outcome onto a frozen enum member (VERIFIED as VERIFIED_HEAD)", () => {
    const mapped = [...TRANSACTION_VERIFY_OUTCOMES].map((outcome) =>
      outcome === "VERIFIED" ? "VERIFIED_HEAD" : outcome,
    );
    for (const member of mapped) {
      expect(OBSERVATION_PARSE_RESULTS).toContain(member);
    }
  });
});
