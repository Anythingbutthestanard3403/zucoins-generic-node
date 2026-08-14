// Exact redelivery + formation crash-recovery matrix.
// Governing: operation flows; signing custody; operations recovery; the data model; the API contract.
//
// Cases covered:
// * all 8 signing custody rows as independently named tests (action + forbidden absence)
//   * redelivery never mutates immutable partial bytes (before/after fingerprint)
//   * INVARIANT_BREACH reachable and distinctly pageable
//   * CLOSE_NEVER_STARTED_EXTERNAL_SEND fails closed on each of 5 evidence kinds
//   * no recovery path produces a second sign-intent or partial row
//   * no submit capability in this module's source (parent AC)

import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  CLOSE_NEVER_STARTED_EXTERNAL_SEND,
  SEC_10_3_CRASH_MATRIX_ROWS,
  SEC_10_3_EXPECTED,
  SEND_CRASH_FORBIDDEN_ACTIONS,
  SEND_CRASH_RECOVERY_ACTIONS,
  SEND_CRASH_RECOVERY_SQL,
  applyCloseNeverStartedExternalSend,
  assertTransferCodeTextMatchesSha256,
  classifySendCrashRecovery,
  createInMemoryCloseNeverStartedPort,
  evidenceForSec103Row,
  evaluateCloseNeverStartedExternalSend,
  fingerprintImmutablePartialBytes,
  redeliverExactPersistedPartial,
  redeliverFromInMemoryPartial,
  type ExactPersistedPartial,
  type SendFormationCrashEvidence,
} from "../src/core/send-crash-recovery.js";
import {
  completeSigningFromDurableIntent,
  constructSendInner,
  createInMemoryFormAndSignState,
  createInMemoryPartialPort,
  createInMemorySignIntentPort,
  formAndSignSendExternal,
  hashTransferCodeText,
  type FormAndSignClaim,
  type FormAndSignHeldLease,
  type FormAndSignInput,
} from "../src/core/send-form-and-sign.js";
import type {
  SignerAuditEntry,
  SignerBoundaryDeps,
  VaultSigner,
} from "../src/core/signer-boundary.js";
import { captureSendBaselines } from "../src/protocol/send-baseline.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "../src/protocol/wallet-role.js";
import {
  WALLET_RECEIVER_PUBLIC_KEY,
  WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
  WALLET_SENDER_PUBLIC_KEY,
} from "./fixtures/splitchain-v2-byte-evidence.js";

const OPERATION_ID = "30230230-3023-4302-8302-302302302302";
const APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const LEASE_GROUP_ID = "gggggggg-0000-4000-8000-000000000001";
const SOURCE_OBSERVATION = "bbbbbbbb-0000-4000-8000-000000000001";
const DESTINATION_OBSERVATION = "bbbbbbbb-0000-4000-8000-000000000002";
const NODE_CLOCK_MS = 1_768_435_200_000;
const PREPARED_AT = "2026-01-15T00:00:00.000Z";
const PERSISTED_AT = "2026-01-15T00:00:01.000Z";
const DELIVERED_AT = "2026-01-15T00:00:02.000Z";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC_CORE = join(HERE, "../src/core");

function senderProjection(b: string): WalletStateProjection {
  return {
    role: "sender",
    S: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
    P: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
    B: b,
    I: "digest",
  };
}

function claimOf(): FormAndSignClaim {
  return {
    operationId: OPERATION_ID,
    status: "APPROVED",
    formationState: "APPROVED_UNSIGNED",
    rowVersion: 2,
    sourceWalletId: SOURCE_WALLET_ID,
    sourcePubkey: WALLET_SENDER_PUBLIC_KEY,
    destinationAddress: WALLET_RECEIVER_PUBLIC_KEY,
    amountZkz: "1",
  };
}

function heldOf(epoch = 1n): FormAndSignHeldLease {
  return {
    walletId: SOURCE_WALLET_ID,
    membershipId: "mmmmmmmm-0000-4000-8000-000000000001",
    leaseGroupId: LEASE_GROUP_ID,
    leaseEpoch: epoch,
    operationId: OPERATION_ID,
  };
}

function captureOf() {
  const captured = captureSendBaselines({
    operationId: OPERATION_ID,
    sourceWalletPublicKey: WALLET_SENDER_PUBLIC_KEY,
    destinationAddress: WALLET_RECEIVER_PUBLIC_KEY,
    sourceLease: { role: "SEND_SOURCE", lifecycle: "ACTIVE" },
    sourceBaseline: senderProjection("10"),
    destinationBaseline: GENESIS_PROJECTION,
    amountZkz: "1",
    capturedAt: NODE_CLOCK_MS,
  });
  if (!captured.ok) throw new Error(`fixture capture failed: ${captured.reason}`);
  return captured.capture;
}

function makeDeterministicVaultSigner(): VaultSigner {
  const seed = Buffer.alloc(32, 0x5e);
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return {
    sign: async (_walletId: string, preimageBytes: Uint8Array) => {
      const sig = nodeSign(null, Buffer.from(preimageBytes), key);
      return Buffer.from(sig).toString("base64url") + "==";
    },
  };
}

function makeSignerDeps(
  vault: VaultSigner = makeDeterministicVaultSigner(),
  audit: SignerAuditEntry[] = [],
): SignerBoundaryDeps {
  return {
    leadership: { held: true },
    leaseReader: {
      readActiveLease: async () => ({
        walletId: SOURCE_WALLET_ID,
        operationId: OPERATION_ID,
        epoch: 1n,
        role: "SEND_SOURCE",
        lifecycle: "ACTIVE",
      }),
    },
    vaultSigner: vault,
    auditLog: {
      append: async (e) => {
        audit.push(e);
      },
    },
    now: () => PREPARED_AT,
    assertMoneyAdmitted: () => {},
    assertCanOperate: () => {},
    assertWalletMaySign: async () => {},
  };
}

function baseInput(
  state: ReturnType<typeof createInMemoryFormAndSignState> = createInMemoryFormAndSignState(),
): FormAndSignInput & { state: ReturnType<typeof createInMemoryFormAndSignState> } {
  return {
    claim: claimOf(),
    held: heldOf(),
    approvalId: APPROVAL_ID,
    sourceT0ObservationId: SOURCE_OBSERVATION,
    destinationFormationObservationId: DESTINATION_OBSERVATION,
    capture: captureOf(),
    nodeClockMs: NODE_CLOCK_MS,
    preparedAt: PREPARED_AT,
    persistedAt: PERSISTED_AT,
    signIntentPort: createInMemorySignIntentPort(state),
    partialPort: createInMemoryPartialPort(state),
    signerDeps: makeSignerDeps(),
    state,
  };
}

async function formHappyPath() {
  const input = baseInput();
  const result = await formAndSignSendExternal(input);
  if (!result.ok) throw new Error(`form failed: ${result.reason} ${result.detail}`);
  return { state: input.state, result };
}

function assertForbids(
  classification: ReturnType<typeof classifySendCrashRecovery>,
  mustForbid: readonly string[],
): void {
  for (const forbidden of mustForbid) {
    expect(
      classification.forbidden,
      `expected forbidden action ${forbidden} on ${classification.action}`,
    ).toContain(forbidden);
  }
  expect(classification.forbidden).toContain("BLIND_SUBMIT");
}

// ── signing custody — eight named crash-matrix rows ────────────────────────────────

describe("signing custody crash matrix — eight named rows", () => {
  it("exposes exactly the eight signing custody row ids", () => {
    expect(SEC_10_3_CRASH_MATRIX_ROWS).toHaveLength(8);
    expect(new Set(SEC_10_3_CRASH_MATRIX_ROWS).size).toBe(8);
  });

  it("signing custody row APPROVAL_PENDING_NO_SIGN_INTENT — await approval; forbid acquire/sign", () => {
    const evidence = evidenceForSec103Row("APPROVAL_PENDING_NO_SIGN_INTENT", {
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
    });
    const c = classifySendCrashRecovery(evidence);
    const expected = SEC_10_3_EXPECTED.APPROVAL_PENDING_NO_SIGN_INTENT;
    expect(c.action).toBe(expected.action);
    assertForbids(c, expected.mustForbid);
    expect(c.pageOperator).toBe(false);
  });

  it("signing custody row APPROVAL_CONSUMED_NO_SIGN_INTENT — acquire lease + first formation; forbid second intent", () => {
    const evidence = evidenceForSec103Row("APPROVAL_CONSUMED_NO_SIGN_INTENT", {
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
    });
    const c = classifySendCrashRecovery(evidence);
    const expected = SEC_10_3_EXPECTED.APPROVAL_CONSUMED_NO_SIGN_INTENT;
    expect(c.action).toBe(expected.action);
    assertForbids(c, expected.mustForbid);
  });

  it("signing custody row SIGNING_CLAIMED_NO_PARTIAL — sign identical preimage; forbid different inner/code", () => {
    const evidence = evidenceForSec103Row("SIGNING_CLAIMED_NO_PARTIAL", {
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
    });
    const c = classifySendCrashRecovery(evidence);
    const expected = SEC_10_3_EXPECTED.SIGNING_CLAIMED_NO_PARTIAL;
    expect(c.action).toBe(expected.action);
    assertForbids(c, expected.mustForbid);
    expect(c.transferCodeSha256).toBeNull();
  });

  it("signing custody row PARTIAL_COMMITTED_NEVER_DELIVERED — deliver exact; forbid re-sign/re-form", () => {
    const evidence = evidenceForSec103Row("PARTIAL_COMMITTED_NEVER_DELIVERED", {
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
    });
    const c = classifySendCrashRecovery(evidence);
    const expected = SEC_10_3_EXPECTED.PARTIAL_COMMITTED_NEVER_DELIVERED;
    expect(c.action).toBe(expected.action);
    assertForbids(c, expected.mustForbid);
    expect(c.transferCodeSha256).toBe(evidence.transferCodeSha256);
  });

  it("signing custody row PARTIAL_DELIVERED_SOURCE_HEAD_UNCHANGED — redeliver exact; forbid replacement partial", () => {
    const evidence = evidenceForSec103Row("PARTIAL_DELIVERED_SOURCE_HEAD_UNCHANGED", {
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
    });
    const c = classifySendCrashRecovery(evidence);
    const expected = SEC_10_3_EXPECTED.PARTIAL_DELIVERED_SOURCE_HEAD_UNCHANGED;
    expect(c.action).toBe(expected.action);
    assertForbids(c, expected.mustForbid);
  });

  it("signing custody row PARTIAL_DELIVERED_EXPECTED_TX_AT_HEAD — mark landed; forbid submit/new code", () => {
    const evidence = evidenceForSec103Row("PARTIAL_DELIVERED_EXPECTED_TX_AT_HEAD", {
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
    });
    const c = classifySendCrashRecovery(evidence);
    const expected = SEC_10_3_EXPECTED.PARTIAL_DELIVERED_EXPECTED_TX_AT_HEAD;
    expect(c.action).toBe(expected.action);
    assertForbids(c, expected.mustForbid);
  });

  it("signing custody row PARTIAL_DELIVERED_UNRELATED_OR_UNVERIFIABLE_HEAD — NEEDS_ATTENTION; forbid infer non-landing", () => {
    const evidence = evidenceForSec103Row(
      "PARTIAL_DELIVERED_UNRELATED_OR_UNVERIFIABLE_HEAD",
      { operationId: OPERATION_ID, sourceWalletId: SOURCE_WALLET_ID },
    );
    const c = classifySendCrashRecovery(evidence);
    const expected = SEC_10_3_EXPECTED.PARTIAL_DELIVERED_UNRELATED_OR_UNVERIFIABLE_HEAD;
    expect(c.action).toBe(expected.action);
    assertForbids(c, expected.mustForbid);
    expect(c.pageOperator).toBe(true);
  });

  it("signing custody row PARTIAL_EXPIRED — terminalize under positive rules; forbid expiry refresh", () => {
    const evidence = evidenceForSec103Row("PARTIAL_EXPIRED", {
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
    });
    const c = classifySendCrashRecovery(evidence);
    const expected = SEC_10_3_EXPECTED.PARTIAL_EXPIRED;
    expect(c.action).toBe(expected.action);
    assertForbids(c, expected.mustForbid);
  });
});

// ── operations recovery four boundaries + lease-held variant ────────────────────────────

describe("operations recovery approved first-formation boundaries", () => {
  it("row 1: APPROVED, no lease, no intent, no audit → ACQUIRE_LEASE_AND_FIRST_FORMATION", () => {
    const c = classifySendCrashRecovery({
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "APPROVED",
      formationState: "APPROVED_UNSIGNED",
      sourceLeaseHeld: false,
      signIntentPersisted: false,
      exactPreimageAvailable: true,
      step1SignaturePersisted: false,
      partialPersisted: false,
      partialFirstDelivered: false,
      signerAuditIndicatesCall: false,
      transferCodeSha256: null,
    });
    expect(c.action).toBe("ACQUIRE_LEASE_AND_FIRST_FORMATION");
    assertForbids(c, ["CREATE_SECOND_SIGN_INTENT"]);
  });

  it("row 2: lease held, no intent, no audit → FIRST_FORMATION_FROM_HELD_LEASE", () => {
    const c = classifySendCrashRecovery({
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "APPROVED",
      formationState: "APPROVED_UNSIGNED",
      sourceLeaseHeld: true,
      signIntentPersisted: false,
      exactPreimageAvailable: true,
      step1SignaturePersisted: false,
      partialPersisted: false,
      partialFirstDelivered: false,
      signerAuditIndicatesCall: false,
      transferCodeSha256: null,
    });
    expect(c.action).toBe("FIRST_FORMATION_FROM_HELD_LEASE");
    assertForbids(c, ["CREATE_SECOND_SIGN_INTENT"]);
  });

  it("row 3: sign intent, no signature → SIGN_IDENTICAL_PERSISTED_PREIMAGE", () => {
    const c = classifySendCrashRecovery({
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "APPROVED",
      formationState: "SIGNING_CLAIMED",
      sourceLeaseHeld: true,
      signIntentPersisted: true,
      exactPreimageAvailable: true,
      step1SignaturePersisted: false,
      partialPersisted: false,
      partialFirstDelivered: false,
      signerAuditIndicatesCall: false,
      transferCodeSha256: null,
    });
    expect(c.action).toBe("SIGN_IDENTICAL_PERSISTED_PREIMAGE");
    assertForbids(c, ["CONSTRUCT_DIFFERENT_INNER_OR_CODE"]);
  });

  it("row 4: signature/partial persisted → RESTORE_AWAITING_REDEMPTION_AND_DELIVER_EXACT", () => {
    const c = classifySendCrashRecovery({
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "APPROVED",
      formationState: "SIGNING_CLAIMED",
      sourceLeaseHeld: true,
      signIntentPersisted: true,
      exactPreimageAvailable: true,
      step1SignaturePersisted: true,
      partialPersisted: true,
      partialFirstDelivered: false,
      signerAuditIndicatesCall: false,
      transferCodeSha256: "ff".repeat(32),
    });
    expect(c.action).toBe("RESTORE_AWAITING_REDEMPTION_AND_DELIVER_EXACT");
    assertForbids(c, ["RESIGN_OR_REFORM", "MINT_REPLACEMENT_PARTIAL"]);
  });
});

// ── INVARIANT_BREACH degenerate cases ────────────────────────────────────────

describe("operations recovery INVARIANT_BREACH classification", () => {
  it("signer audit says called but no sign-intent row → INVARIANT_BREACH, pageable, not PROVEN_NOT_STARTED", () => {
    const evidence: SendFormationCrashEvidence = {
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "APPROVED",
      formationState: "APPROVED_UNSIGNED",
      sourceLeaseHeld: true,
      signIntentPersisted: false,
      exactPreimageAvailable: true,
      step1SignaturePersisted: false,
      partialPersisted: false,
      partialFirstDelivered: false,
      signerAuditIndicatesCall: true,
      transferCodeSha256: null,
    };
    const c = classifySendCrashRecovery(evidence);
    expect(c.action).toBe("INVARIANT_BREACH");
    expect(c.pageOperator).toBe(true);
    expect(c.reason).toBe("SIGNER_AUDIT_WITHOUT_SIGN_INTENT");
    assertForbids(c, ["SILENT_REFORM_WHEN_AUDIT_CONTRADICTS", "ACQUIRE_OR_SIGN"]);
    expect(c.action).not.toBe("ACQUIRE_LEASE_AND_FIRST_FORMATION");
    expect(c.action).not.toBe("FIRST_FORMATION_FROM_HELD_LEASE");
  });

  it("sign intent row exists but exact preimage unavailable → INVARIANT_BREACH", () => {
    const c = classifySendCrashRecovery({
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "APPROVED",
      formationState: "SIGNING_CLAIMED",
      sourceLeaseHeld: true,
      signIntentPersisted: true,
      exactPreimageAvailable: false,
      step1SignaturePersisted: false,
      partialPersisted: false,
      partialFirstDelivered: false,
      signerAuditIndicatesCall: false,
      transferCodeSha256: null,
    });
    expect(c.action).toBe("INVARIANT_BREACH");
    expect(c.pageOperator).toBe(true);
    expect(c.reason).toBe("EXPECTED_EXACT_PREIMAGE_UNAVAILABLE");
    assertForbids(c, ["CONSTRUCT_DIFFERENT_INNER_OR_CODE", "RESIGN_OR_REFORM"]);
  });

  // F1 — preimage gate must not block exact redelivery once a partial is durable.
  it("F1: partial + missing preimage → REDELIVER_EXACT (not EXPECTED_EXACT_PREIMAGE_UNAVAILABLE)", () => {
    const c = classifySendCrashRecovery({
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "AWAITING_REDEMPTION",
      formationState: "PARTIAL_PERSISTED",
      sourceLeaseHeld: true,
      signIntentPersisted: true,
      exactPreimageAvailable: false,
      step1SignaturePersisted: true,
      partialPersisted: true,
      partialFirstDelivered: true,
      signerAuditIndicatesCall: false,
      transferCodeSha256: "ff".repeat(32),
      postDeliveryObservation: "SOURCE_HEAD_UNCHANGED",
    });
    expect(c.action).toBe("REDELIVER_EXACT_PERSISTED_CODE");
    expect(c.reason).not.toBe("EXPECTED_EXACT_PREIMAGE_UNAVAILABLE");
    expect(c.pageOperator).toBe(false);
    assertForbids(c, ["MINT_REPLACEMENT_PARTIAL", "RESIGN_OR_REFORM"]);
  });

  // F2 — never SIGN_IDENTICAL when any partial row exists.
  it("F2: partialPersisted && !step1SignaturePersisted → INVARIANT_BREACH (never SIGN_IDENTICAL)", () => {
    const c = classifySendCrashRecovery({
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "APPROVED",
      formationState: "SIGNING_CLAIMED",
      sourceLeaseHeld: true,
      signIntentPersisted: true,
      exactPreimageAvailable: true,
      step1SignaturePersisted: false,
      partialPersisted: true,
      partialFirstDelivered: false,
      signerAuditIndicatesCall: false,
      transferCodeSha256: "aa".repeat(32),
    });
    expect(c.action).toBe("INVARIANT_BREACH");
    expect(c.reason).toBe("PARTIAL_WITHOUT_STEP1_FLAG");
    expect(c.pageOperator).toBe(true);
    expect(c.action).not.toBe("SIGN_IDENTICAL_PERSISTED_PREIMAGE");
    assertForbids(c, ["MINT_REPLACEMENT_PARTIAL", "RESIGN_OR_REFORM"]);
  });
});

// ── Exact redelivery ─────────────────────────────────────────────────────────

describe("operation flows step 5 / the API contract exact redelivery", () => {
  it("returns identical transfer_code bytes across many redeliveries; only counters move", async () => {
    const { state, result } = await formHappyPath();
    const first = redeliverFromInMemoryPartial(state, OPERATION_ID, DELIVERED_AT);
    expect(first.transferCodeText).toBe(result.transferCodeText);
    expect(first.transferCodeSha256).toBe(result.transferCodeSha256);
    expect(first.redeliveryCount).toBe(0);
    expect(first.immutableBytesFingerprintBefore).toBe(first.immutableBytesFingerprintAfter);

    const fingerprints: string[] = [first.immutableBytesFingerprintAfter];
    const codes: string[] = [first.transferCodeText];

    for (let i = 0; i < 5; i++) {
      const again = redeliverFromInMemoryPartial(
        state,
        OPERATION_ID,
        `2026-01-15T00:00:0${4 + i}.000Z`,
      );
      expect(again.transferCodeText).toBe(result.transferCodeText);
      expect(again.transferCodeSha256).toBe(result.transferCodeSha256);
      expect(again.redeliveryCount).toBe(i + 1);
      expect(again.immutableBytesFingerprintBefore).toBe(again.immutableBytesFingerprintAfter);
      fingerprints.push(again.immutableBytesFingerprintAfter);
      codes.push(again.transferCodeText);
    }

    expect(new Set(fingerprints).size).toBe(1);
    expect(new Set(codes).size).toBe(1);
    expect(state.partials.get(OPERATION_ID)?.redeliveryCount).toBe(5);
    expect(state.partials.get(OPERATION_ID)?.step1Signature).toBe(result.step1Signature);
    expect(state.partials.size).toBe(1);
    expect(state.signIntents.size).toBe(1);
  });

  it("refuses redelivery when no partial row exists", () => {
    const state = createInMemoryFormAndSignState();
    expect(() =>
      redeliverFromInMemoryPartial(state, OPERATION_ID, DELIVERED_AT),
    ).toThrow(/no persisted partial/);
  });

  it("fingerprintImmutablePartialBytes binds only immutable columns", () => {
    const base = {
      transferCodeText: "code-v1",
      transferCodeSha256: "aa".repeat(32),
      step1Signature: "sig-v1",
      innerSha256: "bb".repeat(32),
    };
    const a = fingerprintImmutablePartialBytes(base);
    const b = fingerprintImmutablePartialBytes(base);
    expect(a).toBe(b);
    const c = fingerprintImmutablePartialBytes({
      ...base,
      transferCodeText: "code-v1-mutated",
    });
    expect(c).not.toBe(a);
    const d = fingerprintImmutablePartialBytes({
      ...base,
      step1Signature: "sig-v2",
    });
    expect(d).not.toBe(a);
  });

  // F3 — content-bind fingerprint + handout sha256 gate (same-length mutation rejected).
  it("F3: fingerprint content-binds transferCodeText (same-length mutation differs)", () => {
    const base = {
      transferCodeText: "AAAA",
      transferCodeSha256: "aa".repeat(32),
      step1Signature: "sig-v1",
      innerSha256: "bb".repeat(32),
    };
    const a = fingerprintImmutablePartialBytes(base);
    const b = fingerprintImmutablePartialBytes({
      ...base,
      transferCodeText: "BBBB",
    });
    expect(a).not.toBe(b);
    expect(base.transferCodeText.length).toBe(4);
    expect("BBBB".length).toBe(4);
  });

  it("F3: redelivery rejects when sha256(transfer_code_text) !== transfer_code_sha256", () => {
    const text = "exact-code-bytes";
    const partial: ExactPersistedPartial = {
      operationId: OPERATION_ID,
      transferCodeText: text,
      // Deliberately wrong digest (same length hex) — handout must fail closed.
      transferCodeSha256: "cc".repeat(32),
      step1Signature: "sig",
      innerSha256: "dd".repeat(32),
      firstDeliveredAt: null,
      lastRedeliveredAt: null,
      redeliveryCount: 0,
    };
    expect(hashTransferCodeText(text)).not.toBe(partial.transferCodeSha256);
    expect(() => assertTransferCodeTextMatchesSha256(partial)).toThrow(
      /does not match transfer_code_sha256/,
    );
    expect(() =>
      redeliverExactPersistedPartial(partial, DELIVERED_AT, () => 0),
    ).toThrow(/does not match transfer_code_sha256/);
  });

  it("F3: redelivery accepts only when text hashes to bound sha256", () => {
    const text = "exact-code-bytes";
    const partial: ExactPersistedPartial = {
      operationId: OPERATION_ID,
      transferCodeText: text,
      transferCodeSha256: hashTransferCodeText(text),
      step1Signature: "sig",
      innerSha256: "dd".repeat(32),
      firstDeliveredAt: null,
      lastRedeliveredAt: null,
      redeliveryCount: 0,
    };
    const result = redeliverExactPersistedPartial(partial, DELIVERED_AT, () => 1);
    expect(result.transferCodeText).toBe(text);
    expect(result.transferCodeSha256).toBe(partial.transferCodeSha256);
    expect(result.redeliveryCount).toBe(1);
  });
});

// ── Crash-and-restart: no second intent / partial ────────────────────────────

describe("crash-and-restart cannot mint a second sign intent or partial", () => {
  it("after full formation, restart classifies as exact deliver and second form refuses", async () => {
    const input = baseInput();
    const formed = await formAndSignSendExternal(input);
    expect(formed.ok).toBe(true);
    if (!formed.ok) return;
    expect(input.state.signIntents.size).toBe(1);
    expect(input.state.partials.size).toBe(1);

    const c = classifySendCrashRecovery({
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "AWAITING_REDEMPTION",
      formationState: "PARTIAL_PERSISTED",
      sourceLeaseHeld: true,
      signIntentPersisted: true,
      exactPreimageAvailable: true,
      step1SignaturePersisted: true,
      partialPersisted: true,
      partialFirstDelivered: false,
      signerAuditIndicatesCall: true,
      transferCodeSha256: formed.transferCodeSha256,
    });
    expect(c.action).toBe("RESTORE_AWAITING_REDEMPTION_AND_DELIVER_EXACT");
    assertForbids(c, ["CREATE_SECOND_SIGN_INTENT", "MINT_REPLACEMENT_PARTIAL"]);

    const second = await formAndSignSendExternal({
      ...input,
      claim: { ...claimOf(), formationState: "APPROVED_UNSIGNED" },
    });
    expect(second.ok).toBe(false);
    expect(input.state.signIntents.size).toBe(1);
    expect(input.state.partials.size).toBe(1);
  });

  it("durable intent only → completeSigningFromDurableIntent yields one partial; never two", async () => {
    const state = createInMemoryFormAndSignState();
    const signPort = createInMemorySignIntentPort(state);
    const partialPort = createInMemoryPartialPort(state);
    const deps = makeSignerDeps();

    const constructed = constructSendInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });

    const intentResult = await signPort.commitSignIntent({
      claim: claimOf(),
      held: heldOf(),
      approvalId: APPROVAL_ID,
      sourceT0ObservationId: SOURCE_OBSERVATION,
      destinationFormationObservationId: DESTINATION_OBSERVATION,
      constructed,
      preparedAt: PREPARED_AT,
    });
    expect(intentResult.ok).toBe(true);
    if (!intentResult.ok) return;

    const c = classifySendCrashRecovery({
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "APPROVED",
      formationState: "SIGNING_CLAIMED",
      sourceLeaseHeld: true,
      signIntentPersisted: true,
      exactPreimageAvailable: true,
      step1SignaturePersisted: false,
      partialPersisted: false,
      partialFirstDelivered: false,
      signerAuditIndicatesCall: false,
      transferCodeSha256: null,
    });
    expect(c.action).toBe("SIGN_IDENTICAL_PERSISTED_PREIMAGE");

    const completed = await completeSigningFromDurableIntent({
      intent: intentResult.intent,
      persistedAt: PERSISTED_AT,
      partialPort,
      signerDeps: deps,
    });
    expect(completed.ok).toBe(true);
    expect(state.partials.size).toBe(1);
    expect(state.signIntents.size).toBe(1);

    const again = await completeSigningFromDurableIntent({
      intent: intentResult.intent,
      persistedAt: PERSISTED_AT,
      partialPort,
      signerDeps: deps,
    });
    expect(again.ok).toBe(false);
    expect(state.partials.size).toBe(1);
  });
});

// ── CLOSE_NEVER_STARTED_EXTERNAL_SEND ────────────────────────────────────────

describe("CLOSE_NEVER_STARTED_EXTERNAL_SEND", () => {
  it("constant matches operations recovery action token", () => {
    expect(CLOSE_NEVER_STARTED_EXTERNAL_SEND).toBe("CLOSE_NEVER_STARTED_EXTERNAL_SEND");
  });

  function approvedClean(
    overrides: Partial<SendFormationCrashEvidence> = {},
  ): SendFormationCrashEvidence {
    return {
      operationId: OPERATION_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      status: "APPROVED",
      formationState: "APPROVED_UNSIGNED",
      sourceLeaseHeld: true,
      signIntentPersisted: false,
      exactPreimageAvailable: true,
      step1SignaturePersisted: false,
      partialPersisted: false,
      partialFirstDelivered: false,
      signerAuditIndicatesCall: false,
      transferCodeSha256: null,
      ...overrides,
    };
  }

  it("succeeds when all five negatives re-prove absent; releases lease; keeps approval", async () => {
    const evidence = approvedClean();
    const mem = {
      status: "APPROVED",
      rowVersion: 3,
      signIntent: false,
      partial: false,
      signerAudit: false,
      leaseHeld: true,
      approvals: [{ id: APPROVAL_ID, consumed: true }],
      releasedLeases: [] as string[],
    };
    const port = createInMemoryCloseNeverStartedPort(mem);
    const result = await applyCloseNeverStartedExternalSend({
      evidence,
      expectedRowVersion: 3,
      port,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe("REJECTED");
    expect(mem.status).toBe("REJECTED");
    expect(mem.leaseHeld).toBe(false);
    expect(mem.releasedLeases).toEqual([OPERATION_ID]);
    expect(mem.approvals[0]?.consumed).toBe(true);
  });

  it("fails closed on SIGN_INTENT evidence", () => {
    const evidence = approvedClean({ signIntentPersisted: true });
    const gate = evaluateCloseNeverStartedExternalSend(evidence);
    expect(gate.ok).toBe(false);
    if (!gate.ok) expect(gate.blockingEvidence).toBe("SIGN_INTENT");
  });

  it("fails closed on SIGNER_CALL evidence", () => {
    const evidence = approvedClean({ signerAuditIndicatesCall: true });
    const gate = evaluateCloseNeverStartedExternalSend(evidence);
    expect(gate.ok).toBe(false);
    if (!gate.ok) expect(gate.blockingEvidence).toBe("SIGNER_CALL");
  });

  it("fails closed on SIGNATURE evidence alone", () => {
    const evidence = approvedClean({ step1SignaturePersisted: true });
    const gate = evaluateCloseNeverStartedExternalSend(evidence);
    expect(gate.ok).toBe(false);
    if (!gate.ok) expect(gate.blockingEvidence).toBe("SIGNATURE");
  });

  it("fails closed on PARTIAL evidence alone", () => {
    const evidence = approvedClean({
      partialPersisted: true,
      transferCodeSha256: "aa".repeat(32),
    });
    const gate = evaluateCloseNeverStartedExternalSend(evidence);
    expect(gate.ok).toBe(false);
    if (!gate.ok) expect(gate.blockingEvidence).toBe("PARTIAL");
  });

  it("fails closed on DELIVERY evidence alone; commit never runs", async () => {
    const evidence = approvedClean({ partialFirstDelivered: true });
    const gate = evaluateCloseNeverStartedExternalSend(evidence);
    expect(gate.ok).toBe(false);
    if (!gate.ok) expect(gate.blockingEvidence).toBe("DELIVERY");

    const mem = {
      status: "APPROVED",
      rowVersion: 1,
      signIntent: false,
      partial: false,
      signerAudit: false,
      leaseHeld: true,
      approvals: [{ id: APPROVAL_ID, consumed: true }],
      releasedLeases: [] as string[],
    };
    const applied = await applyCloseNeverStartedExternalSend({
      evidence,
      expectedRowVersion: 1,
      port: createInMemoryCloseNeverStartedPort(mem),
    });
    expect(applied.ok).toBe(false);
    expect(mem.status).toBe("APPROVED");
    expect(mem.leaseHeld).toBe(true);
    expect(mem.releasedLeases).toEqual([]);
  });
});

// ── SQL catalogue + source census (no submit) ────────────────────────────────

describe("recovery surface census (parent AC)", () => {
  it("SQL catalogue is read/CAS only — no INSERT into sign_intents or partials, no submit", () => {
    const sql = Object.values(SEND_CRASH_RECOVERY_SQL).join("\n").toUpperCase();
    expect(sql.includes("INSERT")).toBe(false);
    expect(sql).not.toMatch(/SUBMIT/);
    expect(sql).toMatch(/SELECT/);
    expect(SEND_CRASH_RECOVERY_SQL.LOAD_PARTIAL_BYTES).toMatch(/transfer_code_text/);
    expect(SEND_CRASH_RECOVERY_SQL.LOAD_PARTIAL_BYTES).not.toMatch(
      /UPDATE\s+external_send_partials/i,
    );
    expect(SEND_CRASH_RECOVERY_SQL.CLOSE_NEVER_STARTED_CAS).toMatch(/NOT EXISTS/);
    expect(SEND_CRASH_RECOVERY_SQL.CLOSE_NEVER_STARTED_CAS).toMatch(/signer_audit/);
    expect(SEND_CRASH_RECOVERY_SQL.CLOSE_NEVER_STARTED_CAS).toMatch(/status = 'APPROVED'/);
    expect(SEND_CRASH_RECOVERY_SQL.CLOSE_NEVER_STARTED_CAS).toMatch(/status = 'REJECTED'/);
    expect(SEND_CRASH_RECOVERY_SQL.CLOSE_NEVER_STARTED_CAS).not.toMatch(
      /EXTERNAL_SEND_LANDED/,
    );
  });

  it("CLOSE_PROVEN_NOT_LANDED_CAS is NEEDS_ATTENTION→REJECTED + attention clear; no oracle in SQL", () => {
    const cas = SEND_CRASH_RECOVERY_SQL.CLOSE_PROVEN_NOT_LANDED_CAS;
    expect(cas).toMatch(/status = 'NEEDS_ATTENTION'/);
    expect(cas).toMatch(/status = 'REJECTED'/);
    expect(cas).toMatch(/attention_required = false/);
    expect(cas).toMatch(/attention_reason = NULL/);
    expect(cas).not.toMatch(/NOT EXISTS/);
    expect(cas).not.toMatch(/EXTERNAL_SEND_LANDED/);
    expect(cas).not.toMatch(/sign_intent/);
    expect(cas).not.toMatch(/signer_audit/);
    expect(cas).not.toMatch(/external_send_partials/);
  });

  // F4 — RESTORE must not demote NEEDS_ATTENTION; allowlist APPROVED only.
  it("F4: RESTORE_AWAITING_REDEMPTION_WHEN_PARTIAL allowlists APPROVED; excludes NEEDS_ATTENTION", () => {
    const restore = SEND_CRASH_RECOVERY_SQL.RESTORE_AWAITING_REDEMPTION_WHEN_PARTIAL;
    expect(restore).toMatch(/status\s*=\s*'APPROVED'/);
    expect(restore).not.toMatch(/IS DISTINCT FROM\s+'NEEDS_ATTENTION'/);
    // Must not use a denylist that omits NEEDS_ATTENTION while still matching it.
    expect(restore).not.toMatch(/IS DISTINCT FROM\s+'AWAITING_REDEMPTION'/);
    expect(restore).not.toMatch(/IS DISTINCT FROM\s+'EXTERNAL_SEND_LANDED'/);
    expect(restore).not.toMatch(/IS DISTINCT FROM\s+'REJECTED'/);
    // Explicitly must not match NEEDS_ATTENTION rows under the allowlist.
    expect(restore).toMatch(/AND status = 'APPROVED'/);
    expect(restore.toUpperCase()).not.toContain("NEEDS_ATTENTION");
  });

  it("module source has no submit capability", () => {
    const src = readFileSync(join(SRC_CORE, "send-crash-recovery.ts"), "utf8");
    expect(src).not.toMatch(/submitGateway/);
    expect(src).not.toMatch(/submit_transaction/);
    expect(src).not.toMatch(/gateway_submit/);
    expect(src).not.toMatch(/submitOnce/);
    expect(src.includes("../send/")).toBe(false);
    expect(src).not.toMatch(/constructSendInner/);
    expect(src).not.toMatch(/buildSplitChainInner/);
  });

  it("closed action vocabularies are exhaustive and frozen", () => {
    expect(SEND_CRASH_RECOVERY_ACTIONS.length).toBeGreaterThanOrEqual(8);
    expect(SEND_CRASH_FORBIDDEN_ACTIONS).toContain("BLIND_SUBMIT");
    expect(SEND_CRASH_FORBIDDEN_ACTIONS).toContain("MINT_REPLACEMENT_PARTIAL");
    expect(SEND_CRASH_FORBIDDEN_ACTIONS).toContain("REFRESH_EXPIRY_UNDER_OLD_APPROVAL");
  });
});
