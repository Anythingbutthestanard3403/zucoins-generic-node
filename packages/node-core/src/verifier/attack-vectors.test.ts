// the adversarial driving suite for the two production stages.
// It feeds the frozen attack vectors committed under
// packages/generic-node-contracts/src/receive-golden/attack-vectors/ (single-mutation
// derivatives of the frozen A.8.1 golden, see that directory's manifest.json) through the
// real pipeline seam — envelope parser (gateway-envelope.ts) then
// transaction verifier (transaction-verify.ts) — and asserts each one fails closed with the
// exact typed rejection from the production taxonomy, at the correct stage. This is a pure
// test slice: no production logic is added, no live submit or live-chain path is touched, and
// every input is offline committed bytes. The byte freeze that proves each fixture is exactly
// the golden plus its one documented mutation lives in the contracts package
// (receive-golden/attack-vectors.freeze.test.ts); this file only drives behavior.
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import type { ScalarFailureReason, ScalarKind } from "../protocol/scalars.js";
import {
  parseGatewayEnvelope,
  type EnvelopeRejectionReason,
  type ParsedSettledTransaction,
} from "./gateway-envelope.js";
import { verifySettledTransaction, type TransactionVerifyVerdict } from "./transaction-verify.js";

const ATTACK_DIR = new URL(
  "../../../generic-node-contracts/src/receive-golden/attack-vectors/",
  import.meta.url,
);
const GEN_DIR = new URL("../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function attackBytes(file: string): Uint8Array {
  return readFileSync(fileURLToPath(new URL(file, ATTACK_DIR)));
}
function attackText(file: string): string {
  return Buffer.from(attackBytes(file)).toString("utf8");
}
function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

type EnvelopeExpected = {
  readonly classification: "MALFORMED_ENVELOPE";
  readonly reason: EnvelopeRejectionReason;
};
type MalformedExpected = {
  readonly verdict: "MALFORMED_TRANSACTION";
  readonly rejection_reason: "unexpected_inner_shape" | "invalid_scalar";
  readonly scalar_kind?: ScalarKind;
  readonly scalar_reason?: ScalarFailureReason;
};
type UnverifiedExpected = {
  readonly verdict: "UNVERIFIED_SIGNATURE";
  readonly failed_step: 1 | 2;
};
type RoleExpected = {
  readonly verdict: "WALLET_ROLE_INVALID";
};
type VerifierExpected = MalformedExpected | UnverifiedExpected | RoleExpected;

interface AttackVector {
  readonly name: string;
  readonly file: string;
  readonly stage: "envelope" | "verifier";
  readonly checklist_item: string;
  readonly expected: EnvelopeExpected | VerifierExpected;
  readonly sha256: string;
  readonly query_key_seed?: string;
  readonly fails_before?: string;
}
interface AttackManifest {
  readonly schema_version: number;
  readonly baseline_settled_sha256: string;
  readonly role_rejection_detail: string;
  readonly public_keys: Readonly<Record<string, string>>;
  readonly vectors: readonly AttackVector[];
}

const MANIFEST = JSON.parse(attackText("manifest.json")) as AttackManifest;
const SENDER_KEY = MANIFEST.public_keys.seed_02;
const RECEIVER_KEY = MANIFEST.public_keys.seed_03;
const ABSENT_KEY = MANIFEST.public_keys.seed_05;
const KEY_BY_SEED: Readonly<Record<string, string>> = {
  "02": SENDER_KEY,
  "03": RECEIVER_KEY,
  "05": ABSENT_KEY,
};

const GOLDEN_SETTLED_TEXT = readFileSync(
  fileURLToPath(new URL("target.settled.json", GEN_DIR)),
  "utf8",
);

// Wraps settled-transaction bytes in a success envelope by raw text splice — the fixture
// bytes ride through verbatim (never re-serialized), exactly as the live gateway wraps them.
function headEnvelopeBytes(txText: string): Uint8Array {
  return new TextEncoder().encode(`{"status":true,"code":"success","message":"","data":[${txText}]}`);
}

function headParsedFrom(txText: string): ParsedSettledTransaction {
  const verdict = parseGatewayEnvelope(headEnvelopeBytes(txText));
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope verdict");
  return verdict.parsed;
}

// Verifier-stage fixtures ride through the envelope stage as HEAD, so the rejection below is
// the verifier stage's own typed verdict.
function verifyAttack(vector: AttackVector): TransactionVerifyVerdict {
  const queryKey = KEY_BY_SEED[vector.query_key_seed ?? "03"];
  if (queryKey === undefined) throw new Error(`unknown query key seed for ${vector.name}`);
  return verifySettledTransaction(headParsedFrom(attackText(vector.file)), queryKey);
}

const envelopeVectors = MANIFEST.vectors.filter((vector) => vector.stage === "envelope");
const verifierVectors = MANIFEST.vectors.filter((vector) => vector.stage === "verifier");
const malformedVectors = verifierVectors.filter(
  (vector) => (vector.expected as VerifierExpected).verdict === "MALFORMED_TRANSACTION",
);
const unverifiedVectors = verifierVectors.filter(
  (vector) => (vector.expected as VerifierExpected).verdict === "UNVERIFIED_SIGNATURE",
);
const roleVectors = verifierVectors.filter(
  (vector) => (vector.expected as VerifierExpected).verdict === "WALLET_ROLE_INVALID",
);

describe("frozen attack vectors — manifest provenance", () => {
  it("drives the full frozen vector census from committed bytes whose digests match the manifest", () => {
    expect(MANIFEST.schema_version).toBe(1);
    expect(envelopeVectors).toHaveLength(6);
    expect(verifierVectors).toHaveLength(11);
    for (const vector of MANIFEST.vectors) {
      expect(sha256Hex(attackBytes(vector.file))).toBe(vector.sha256);
    }
    expect(sha256Hex(new TextEncoder().encode(GOLDEN_SETTLED_TEXT))).toBe(
      MANIFEST.baseline_settled_sha256,
    );
  });

  it("positive control: the wallet-compatible golden verifies cleanly for the receiver", () => {
    const verdict = verifySettledTransaction(headParsedFrom(GOLDEN_SETTLED_TEXT), RECEIVER_KEY);
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;
    expect(verdict.completedTransactionSha256).toBe(MANIFEST.baseline_settled_sha256);
    expect(verdict.projection.role).toBe("receiver");
  });
});

describe("envelope-stage vectors fail closed at the envelope, before any verifier stage", () => {
  it.each(envelopeVectors)("$name: $checklist_item", (vector) => {
    const expected = vector.expected as EnvelopeExpected;
    const verdict = parseGatewayEnvelope(attackBytes(vector.file));
    expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
    if (verdict.classification !== "MALFORMED_ENVELOPE") return;
    expect(verdict.reason).toBe(expected.reason);
    // No parsed payload ever escapes the envelope stage, so nothing reaches the verifier.
    expect(verdict.parsed).toBeNull();
    // The digest is taken over the exact captured bytes, before any decode.
    expect(verdict.rawSha256).toBe(sha256Hex(attackBytes(vector.file)));
  });
});

describe("pre-signature vectors fail closed at the shape/scalar stage", () => {
  it.each(malformedVectors)("$name: $checklist_item rejects before any signature byte is read", (vector) => {
    const expected = vector.expected as MalformedExpected;
    const verdict = verifyAttack(vector);
    // A MALFORMED_TRANSACTION verdict is by construction produced before the signature stage;
    // the shape/scalar kind (not UNVERIFIED_SIGNATURE) is the assertion that it failed early.
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection.reason).toBe(expected.rejection_reason);
    if (verdict.rejection.reason === "invalid_scalar") {
      expect(verdict.rejection.scalarKind).toBe(expected.scalar_kind);
      expect(verdict.rejection.scalarReason).toBe(expected.scalar_reason);
    }
  });
});

describe("signature-boundary vectors fail closed at the Ed25519 stage", () => {
  it.each(unverifiedVectors)("$name: $checklist_item", (vector) => {
    const expected = vector.expected as UnverifiedExpected;
    const verdict = verifyAttack(vector);
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
    if (verdict.verdict !== "UNVERIFIED_SIGNATURE") return;
    expect(verdict.failedStep).toBe(expected.failed_step);
  });

  it("whitespace-preimage: the signature is genuine over the transmitted bytes, yet the compact reconstruction refuses it", () => {
    const vector = verifierVectors.find((candidate) => candidate.name === "whitespace-preimage");
    if (!vector) throw new Error("whitespace-preimage vector missing");
    // The committed entry's inner parses to the same field set as the golden — the whitespace
    // lives only in the serialized bytes, so the defect is purely the byte-exactness rule.
    const entry = JSON.parse(attackText(vector.file)) as { inner: Record<string, unknown> };
    expect(Object.keys(entry.inner)).toEqual(Object.keys(headParsedFrom(GOLDEN_SETTLED_TEXT).inner));
    const verdict = verifyAttack(vector);
    expect(verdict.verdict).toBe("UNVERIFIED_SIGNATURE");
  });
});

describe("role-boundary vectors fail closed at the role stage, after both signatures pass", () => {
  it.each(roleVectors)("$name: $checklist_item", (vector) => {
    const verdict = verifyAttack(vector);
    expect(verdict.verdict).toBe("WALLET_ROLE_INVALID");
    if (verdict.verdict !== "WALLET_ROLE_INVALID") return;
    expect(verdict.detail).toBe(MANIFEST.role_rejection_detail);
  });

  it("self-transfer passes both signature checks and is rejected only by role determination", () => {
    const vector = verifierVectors.find((candidate) => candidate.name === "self-transfer");
    if (!vector) throw new Error("self-transfer vector missing");
    // Queried with the duplicated key: both step positions match, so role is ambiguous.
    expect(vector.query_key_seed).toBe("02");
    const verdict = verifyAttack(vector);
    expect(verdict.verdict).toBe("WALLET_ROLE_INVALID");
  });

  it("absent-wallet drives the unmodified golden bytes with a key in neither step position", () => {
    const vector = verifierVectors.find((candidate) => candidate.name === "absent-wallet");
    if (!vector) throw new Error("absent-wallet vector missing");
    expect(vector.file).toBe("../gen/target.settled.json");
    expect(sha256Hex(attackBytes(vector.file))).toBe(MANIFEST.baseline_settled_sha256);
    const verdict = verifySettledTransaction(headParsedFrom(attackText(vector.file)), ABSENT_KEY);
    expect(verdict.verdict).toBe("WALLET_ROLE_INVALID");
  });
});

describe("envelope noise outside the signed preimage is verification-neutral", () => {
  it("yields the identical VERIFIED verdict under a perturbed wrapper and surrounding whitespace", () => {
    const plain = parseGatewayEnvelope(headEnvelopeBytes(GOLDEN_SETTLED_TEXT));
    const noisy = parseGatewayEnvelope(
      new TextEncoder().encode(
        `  {"status":true,"code":"success","message":"perturbed wrapper text","data":[ ${GOLDEN_SETTLED_TEXT} ]}\n`,
      ),
    );
    if (plain.classification !== "HEAD" || noisy.classification !== "HEAD") {
      throw new Error("expected HEAD envelope verdicts");
    }
    const first = verifySettledTransaction(plain.parsed, RECEIVER_KEY);
    const second = verifySettledTransaction(noisy.parsed, RECEIVER_KEY);
    expect(first.verdict).toBe("VERIFIED");
    expect(second).toEqual(first);
    if (second.verdict !== "VERIFIED") return;
    expect(second.completedTransactionSha256).toBe(MANIFEST.baseline_settled_sha256);
  });
});
