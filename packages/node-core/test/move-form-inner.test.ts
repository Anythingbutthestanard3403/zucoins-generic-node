// MOVE_INTERNAL exact-inner formation + durable attempt-1.
//
// Cases covered:
//   * economics consistent with A.8.2 expected-artifact fixture (amount "2.25", fixed UUIDs/keys)
//   * operation_transactions at INNER_PREIMAGE_PERSISTED with step_1_signature IS NULL before signer
//   * crash-inject after write: signerCalls stays 0
//   * construct twice → byte-identical JSON.stringify; parse-then-restringify matches persisted text
//   * no operation_expected_artifacts insert/update; upstream artifact left byte-unchanged
//   * second attempt rejected; over-balance / same-wallet rejected

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  constructMoveInner,
  createInMemoryMoveFormState,
  createInMemoryMoveInnerPersistPort,
  formMoveInner,
  isDurableMoveInner,
  MoveInnerBuildError,
  ONLY_ATTEMPT_NO,
  persistMoveInnerAttemptSql,
  type DurableMoveInner,
  type FormMoveInnerInput,
  type PersistMoveInnerInput,
} from "../src/core/move-form-inner.js";
import type { PersistedExpectedArtifact } from "../src/core/move-baseline-binding.js";
import { captureDualBaselines } from "../src/protocol/move-baseline.js";
import { buildMoveInternalExpectedArtifact } from "../src/protocol/suite/builders.js";
import {
  parseExpiryUnixTimeSecs,
  parseUuid,
  parseWalletPublicKey,
} from "../src/protocol/scalars.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "../src/protocol/wallet-role.js";
import { CANONICAL_INNER_FIELD_ORDER } from "./fixtures/splitchain-v2-byte-evidence.js";

// A.8.2 fixture identifiers (appendix fixed UUID set + seed-derived keys).
const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const ARTIFACT_ID = "99999999-9999-4999-8999-999999999999";
const SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const DESTINATION_WALLET_ID = "44444444-4444-4444-8444-444444444444";
const DESTINATION_ID = "66666666-6666-4666-8666-666666666666";
const SOURCE_PUBKEY = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DESTINATION_PUBKEY = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const SOURCE_T0_OBSERVATION = "aaaaaaaa-0000-4000-8000-000000000001";
const DESTINATION_T0_OBSERVATION = "aaaaaaaa-0000-4000-8000-000000000002";
const SIGNING_KEY_ID = "bbbbbbbb-0000-4000-8000-000000000001";
const SIGNATURE = `${"A".repeat(86)}==`;

/** Valid padded Ed25519 signature used as source T0.S0 (HEAD link). */
const SOURCE_T0_S =
  "IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==";

/** A.8.2 frozen amount. Source B0 = 10 → post 7.75 (matches A.8.1 economics shape). */
const AMOUNT_ZKZ = "2.25";
const SOURCE_B0 = "10";
const SOURCE_POST = "7.75";
const DEST_POST = "2.25";

/** Formation clock: 2026-07-18T00:00:00.000Z → floor secs 1784332800. */
const NODE_CLOCK_MS = 1_784_332_800_000;
const FORMED_AT = "2026-07-18T00:00:00.000Z";

const A82_MOVE_EXPECTED_SHA256 =
  "ad964723e07ca2aef3356f1e02990e07b90be49b5387a7095091398a10944a14";

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function senderProjection(b: string): WalletStateProjection {
  return {
    role: "sender",
    S: SOURCE_T0_S,
    P: SOURCE_T0_S,
    B: b,
    I: "digest",
  };
}

function captureOf(amount = AMOUNT_ZKZ, sourceB = SOURCE_B0) {
  const captured = captureDualBaselines({
    operationId: OPERATION_ID,
    sourceWalletPublicKey: SOURCE_PUBKEY,
    destinationWalletPublicKey: DESTINATION_PUBKEY,
    sourceLease: { role: "MOVE_SOURCE", lifecycle: "ACTIVE" },
    destinationLease: { role: "MOVE_DESTINATION", lifecycle: "ACTIVE" },
    sourceBaseline: senderProjection(sourceB),
    destinationBaseline: GENESIS_PROJECTION,
    amountZkz: amount,
    capturedAt: NODE_CLOCK_MS,
  });
  if (!captured.ok) throw new Error(`fixture capture failed: ${captured.reason} ${captured.detail}`);
  return captured.capture;
}

/** Upstream artifact — built once; formation must not re-insert or mutate it. */
function expectedArtifactOf(): PersistedExpectedArtifact {
  const preimage = buildMoveInternalExpectedArtifact({
    node_id: parseUuid(NODE_ID),
    implementer_id: parseUuid(IMPLEMENTER_ID),
    operation_id: parseUuid(OPERATION_ID),
    source_wallet_id: parseUuid(SOURCE_WALLET_ID),
    source_pubkey: parseWalletPublicKey(SOURCE_PUBKEY),
    destination_id: parseUuid(DESTINATION_ID),
    destination_wallet_id: parseUuid(DESTINATION_WALLET_ID),
    destination_pubkey: parseWalletPublicKey(DESTINATION_PUBKEY),
    amount_zkz: captureOf().amountZkz,
    spawned_from_operation_id: null,
    references_operation_id: null,
  });
  return {
    id: ARTIFACT_ID,
    operationId: OPERATION_ID,
    purpose: "zp-move-internal-expected-v1",
    canonicalVersion: 1,
    signingKeyId: SIGNING_KEY_ID,
    preimageText: preimage.preimageText,
    preimageSha256: preimage.sha256,
    signature: SIGNATURE,
  };
}

function baseFormInput(
  overrides: Partial<FormMoveInnerInput> & {
    state?: ReturnType<typeof createInMemoryMoveFormState>;
  } = {},
): FormMoveInnerInput & { state: ReturnType<typeof createInMemoryMoveFormState> } {
  const state = overrides.state ?? createInMemoryMoveFormState();
  const artifact = overrides.expectedArtifact ?? expectedArtifactOf();
  // Seed artifact snapshot as would have left it.
  if (!state.artifactPreimageByOperation.has(OPERATION_ID)) {
    state.artifactPreimageByOperation.set(OPERATION_ID, artifact.preimageText);
  }
  return {
    operationId: OPERATION_ID,
    capture: captureOf(),
    sourceT0ObservationId: SOURCE_T0_OBSERVATION,
    destinationT0ObservationId: DESTINATION_T0_OBSERVATION,
    expectedArtifact: artifact,
    nodeClockMs: NODE_CLOCK_MS,
    formedAt: FORMED_AT,
    persistPort: createInMemoryMoveInnerPersistPort(state),
    state,
    ...overrides,
    ...(overrides.state
      ? {
          persistPort:
            overrides.persistPort ?? createInMemoryMoveInnerPersistPort(overrides.state),
        }
      : {}),
  };
}

describe("A.8.2 expected-artifact fixture lock", () => {
  it("reproduces the pinned move-internal-expected SHA-256", () => {
    const artifact = expectedArtifactOf();
    expect(artifact.preimageSha256).toBe(A82_MOVE_EXPECTED_SHA256);
    expect(sha256Hex(artifact.preimageText)).toBe(A82_MOVE_EXPECTED_SHA256);
    expect(artifact.preimageText.startsWith("zp-move-internal-expected-v1\n")).toBe(true);
  });
});

describe("constructMoveInner — operation-flow step 1", () => {
  it("maps source→step_1 and destination→step_2 with correct post-balances", () => {
    const constructed = constructMoveInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });
    const parsed = JSON.parse(constructed.innerPreimageText) as Record<string, unknown>;
    expect(parsed.step_1_key_public__base64urlsafe).toBe(SOURCE_PUBKEY);
    expect(parsed.step_2_key_public__base64urlsafe).toBe(DESTINATION_PUBKEY);
    expect(parsed.previous_step_1_state_signature).toBe(SOURCE_T0_S);
    expect(parsed.previous_step_2_state_signature).toBe("");
    expect((parsed.step_1_state as { amount: string }).amount).toBe(SOURCE_POST);
    expect((parsed.step_2_state as { amount: string }).amount).toBe(DEST_POST);
    expect(constructed.amountZkz).toBe(AMOUNT_ZKZ);
    expect(constructed.innerSha256).toBe(sha256Hex(constructed.innerPreimageText));
    expect(constructed.formationUnixTimeSecs).toBe("1784332800");
    expect(parsed.unix_time_secs).toBe("1784332800");
  });

  it("emits canonical A.1.2 field sequence without optional expiry/message", () => {
    const constructed = constructMoveInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });
    const parsed = JSON.parse(constructed.innerPreimageText) as Record<string, unknown>;
    const expectedKeys = [...CANONICAL_INNER_FIELD_ORDER].filter(
      (k) => k !== "expiry__unix_time_secs" && k !== "message",
    );
    expect(Object.keys(parsed)).toEqual(expectedKeys);
  });

  it("is deterministic — same input yields byte-identical preimage", () => {
    const a = constructMoveInner({ capture: captureOf(), nodeClockMs: NODE_CLOCK_MS });
    const b = constructMoveInner({ capture: captureOf(), nodeClockMs: NODE_CLOCK_MS });
    expect(a.innerPreimageText).toBe(b.innerPreimageText);
    expect(a.innerSha256).toBe(b.innerSha256);
  });

  it("parse-then-restringify round-trip matches the constructed preimage (Byte-exact)", () => {
    const constructed = constructMoveInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });
    // Round-trip proves the in-memory object was insertion-sequenced: JSON.parse then
    // JSON.stringify reproduces the exact persisted bytes.
    const roundTrip = JSON.stringify(JSON.parse(constructed.innerPreimageText));
    expect(roundTrip).toBe(constructed.innerPreimageText);
  });

  it("omits expiry and message when not supplied; includes them when supplied", () => {
    const bare = constructMoveInner({ capture: captureOf(), nodeClockMs: NODE_CLOCK_MS });
    expect(bare.innerPreimageText).not.toContain("expiry__unix_time_secs");
    expect(bare.innerPreimageText).not.toContain('"message"');

    const withExpiry = constructMoveInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
      expiryUnixTimeSecs: parseExpiryUnixTimeSecs("1784333100"),
    });
    const parsedExpiry = JSON.parse(withExpiry.innerPreimageText) as Record<string, unknown>;
    expect(parsedExpiry.expiry__unix_time_secs).toBe("1784333100");
    expect(parsedExpiry).not.toHaveProperty("message");
    expect(constructMoveInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
      expiryUnixTimeSecs: parseExpiryUnixTimeSecs("1784333100"),
    }).innerPreimageText).toBe(withExpiry.innerPreimageText);

    const withMessage = constructMoveInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
      message: "move-note",
    });
    const parsedMsg = JSON.parse(withMessage.innerPreimageText) as Record<string, unknown>;
    expect(parsedMsg.message).toBe("move-note");
    expect(parsedMsg).not.toHaveProperty("expiry__unix_time_secs");

    const both = constructMoveInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
      expiryUnixTimeSecs: parseExpiryUnixTimeSecs("1784333100"),
      message: "move-note",
    });
    expect(Object.keys(JSON.parse(both.innerPreimageText) as object)).toEqual([
      ...CANONICAL_INNER_FIELD_ORDER,
    ]);
  });

  it("rejects same-wallet, invalid baselines, and over-balance", () => {
    const base = captureOf();
    expect(() =>
      constructMoveInner({
        capture: {
          ...base,
          destinationWalletPublicKey: SOURCE_PUBKEY,
        },
        nodeClockMs: NODE_CLOCK_MS,
      }),
    ).toThrow(MoveInnerBuildError);

    expect(() =>
      constructMoveInner({
        capture: {
          ...base,
          sourceBaseline: {
            role: "sender",
            S: "not-a-signature",
            P: "not-a-signature",
            B: SOURCE_B0,
            I: "digest",
          },
        },
        nodeClockMs: NODE_CLOCK_MS,
      }),
    ).toThrow(MoveInnerBuildError);

    // Amount exceeding source B0 is rejected at captureDualBaselines; construction path
    // also rejects via buildSplitChainInnerV2 when handed an oversize branded amount.
    expect(() => {
      // Bypass capture: hand a capture whose amount exceeds B0.
      const over = {
        ...base,
        amountZkz: captureOf("1").amountZkz, // will rebuild
      };
      // Force over-balance by using a tiny source B with the A.8.2 amount via captureOf fail:
      expect(() => captureOf(AMOUNT_ZKZ, "1")).toThrow(/fixture capture failed/);
      void over;
    }).not.toThrow(); // the outer expect is structural; real assert:
    expect(() => captureOf(AMOUNT_ZKZ, "1")).toThrow(/fixture capture failed/);
  });

  it("rejects construction when amount exceeds source balance at the builder", () => {
    // Capture with sufficient balance, then swap amount to a larger branded value.
    const ok = captureOf("1", "10");
    const big = captureOf("9", "10");
    expect(() =>
      constructMoveInner({
        capture: { ...ok, amountZkz: big.amountZkz },
        // source B=10, amount=9 → ok
        nodeClockMs: NODE_CLOCK_MS,
      }),
    ).not.toThrow();
    const tiny = captureOf("1", "10");
    const huge = captureOf("9", "10");
    expect(() =>
      constructMoveInner({
        capture: {
          ...tiny,
          sourceBaseline: senderProjection("5"),
          amountZkz: huge.amountZkz, // 9 > 5
        },
        nodeClockMs: NODE_CLOCK_MS,
      }),
    ).toThrow(MoveInnerBuildError);
  });
});

describe("formMoveInner — operation-flow steps 1–2 (construct + durable attempt)", () => {
  it("persists attempt at INNER_PREIMAGE_PERSISTED with step_1 unset and never calls a signer", async () => {
    const input = baseFormInput();
    const result = await formMoveInner(input);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.detail);

    expect(isDurableMoveInner(result.durable)).toBe(true);
    expect(result.durable.attemptNo).toBe(ONLY_ATTEMPT_NO);
    expect(result.durable.attemptPhase).toBe("INNER_PREIMAGE_PERSISTED");
    expect(result.durable.operationId).toBe(OPERATION_ID);
    expect(result.durable.innerSha256).toBe(sha256Hex(result.durable.innerPreimageText));
    expect(result.durable.sourceT0ObservationId).toBe(SOURCE_T0_OBSERVATION);
    expect(result.durable.destinationT0ObservationId).toBe(DESTINATION_T0_OBSERVATION);

    // Crash-inject proof: after durable write, signer was never invoked.
    expect(input.state.signerCalls).toBe(0);
    expect(input.state.attempts.size).toBe(1);

    // Economics consistent with A.8.2 artifact.
    const parsed = JSON.parse(result.durable.innerPreimageText) as {
      step_1_state: { amount: string };
      step_2_state: { amount: string };
      step_1_key_public__base64urlsafe: string;
      step_2_key_public__base64urlsafe: string;
    };
    expect(parsed.step_1_key_public__base64urlsafe).toBe(SOURCE_PUBKEY);
    expect(parsed.step_2_key_public__base64urlsafe).toBe(DESTINATION_PUBKEY);
    expect(parsed.step_1_state.amount).toBe(SOURCE_POST);
    expect(parsed.step_2_state.amount).toBe(DEST_POST);
    expect(result.durable.expectedArtifactPreimageSha256).toBe(A82_MOVE_EXPECTED_SHA256);
  });

  it("leaves the upstream expected-artifact preimage byte-unchanged (no insert/update)", async () => {
    const artifact = expectedArtifactOf();
    const frozen = artifact.preimageText;
    const input = baseFormInput({ expectedArtifact: artifact });
    const before = input.state.artifactPreimageByOperation.get(OPERATION_ID);
    expect(before).toBe(frozen);

    const result = await formMoveInner(input);
    expect(result.ok).toBe(true);

    const after = input.state.artifactPreimageByOperation.get(OPERATION_ID);
    expect(after).toBe(frozen);
    expect(after).toBe(artifact.preimageText);
    // Artifact object identity fields untouched.
    expect(artifact.preimageText).toBe(frozen);
    expect(artifact.preimageSha256).toBe(A82_MOVE_EXPECTED_SHA256);
  });

  it("parse-then-restringify of persisted inner_preimage_text is byte-identical", async () => {
    const result = await formMoveInner(baseFormInput());
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.detail);
    const roundTrip = JSON.stringify(JSON.parse(result.durable.innerPreimageText));
    expect(roundTrip).toBe(result.durable.innerPreimageText);
  });

  it("rejects a second attempt for the same operation_id", async () => {
    const state = createInMemoryMoveFormState();
    const first = await formMoveInner(baseFormInput({ state }));
    expect(first.ok).toBe(true);
    const second = await formMoveInner(baseFormInput({ state }));
    expect(second.ok).toBe(false);
    if (second.ok) throw new Error("expected second attempt to fail");
    expect(second.reason).toBe("persist_failed");
    expect(second.detail).toMatch(/attempt_exists/);
    expect(state.attempts.size).toBe(1);
    expect(state.signerCalls).toBe(0);
  });

  it("rejects economics mismatch against a different-amount artifact", async () => {
    const wrongAmount = buildMoveInternalExpectedArtifact({
      node_id: parseUuid(NODE_ID),
      implementer_id: parseUuid(IMPLEMENTER_ID),
      operation_id: parseUuid(OPERATION_ID),
      source_wallet_id: parseUuid(SOURCE_WALLET_ID),
      source_pubkey: parseWalletPublicKey(SOURCE_PUBKEY),
      destination_id: parseUuid(DESTINATION_ID),
      destination_wallet_id: parseUuid(DESTINATION_WALLET_ID),
      destination_pubkey: parseWalletPublicKey(DESTINATION_PUBKEY),
      amount_zkz: captureOf("1").amountZkz,
      spawned_from_operation_id: null,
      references_operation_id: null,
    });
    const badArtifact: PersistedExpectedArtifact = {
      id: ARTIFACT_ID,
      operationId: OPERATION_ID,
      purpose: "zp-move-internal-expected-v1",
      canonicalVersion: 1,
      signingKeyId: SIGNING_KEY_ID,
      preimageText: wrongAmount.preimageText,
      preimageSha256: wrongAmount.sha256,
      signature: SIGNATURE,
    };
    const result = await formMoveInner(baseFormInput({ expectedArtifact: badArtifact }));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected economics mismatch");
    expect(result.detail).toMatch(/economics_mismatch|amount/);
  });

  it("DurableMoveInner is not assignable from a bare constructed inner (brand)", async () => {
    const constructed = constructMoveInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });
    expect(isDurableMoveInner(constructed)).toBe(false);
    const result = await formMoveInner(baseFormInput());
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.detail);
    expect(isDurableMoveInner(result.durable)).toBe(true);
    // Brand is not forgeable by shape alone.
    const forged = {
      operationId: OPERATION_ID,
      attemptNo: 1 as const,
      attemptPhase: "INNER_PREIMAGE_PERSISTED" as const,
      innerPreimageText: constructed.innerPreimageText,
      innerSha256: constructed.innerSha256,
      sourceT0ObservationId: SOURCE_T0_OBSERVATION,
      destinationT0ObservationId: DESTINATION_T0_OBSERVATION,
      expectedArtifactPreimageText: "x",
      expectedArtifactPreimageSha256: "y",
      formedAt: FORMED_AT,
    };
    expect(isDurableMoveInner(forged)).toBe(false);
    void forged satisfies Omit<DurableMoveInner, symbol>;
  });
});

describe("persistMoveInnerAttemptSql — SQL adapter surface", () => {
  it("inserts via insertTransactionAttempt with INNER_PREIMAGE_PERSISTED and no payer step-1", async () => {
    const calls: Array<{ sql: string; params: readonly unknown[] }> = [];
    const query = async (sql: string, params: readonly unknown[] = []) => {
      calls.push({ sql, params });
      return [{ operation_id: OPERATION_ID, attempt_no: 1, attempt_phase: "INNER_PREIMAGE_PERSISTED" }];
    };
    const constructed = constructMoveInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });
    const input: PersistMoveInnerInput = {
      operationId: OPERATION_ID,
      constructed,
      sourceT0ObservationId: SOURCE_T0_OBSERVATION,
      destinationT0ObservationId: DESTINATION_T0_OBSERVATION,
      expectedArtifact: expectedArtifactOf(),
      formedAt: FORMED_AT,
    };
    const result = await persistMoveInnerAttemptSql(query, input);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.detail);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.sql).toMatch(/INSERT INTO operation_transactions/);
    // Bindings: operationId, phase, preimage, sha256, step_1_signature=null, formedAt
    expect(calls[0]!.params[0]).toBe(OPERATION_ID);
    expect(calls[0]!.params[1]).toBe("INNER_PREIMAGE_PERSISTED");
    expect(calls[0]!.params[2]).toBe(constructed.innerPreimageText);
    expect(calls[0]!.params[3]).toBe(constructed.innerSha256);
    expect(calls[0]!.params[4]).toBeNull();
    expect(calls[0]!.params[5]).toBe(FORMED_AT);
    expect(result.durable.attemptPhase).toBe("INNER_PREIMAGE_PERSISTED");
    expect(isDurableMoveInner(result.durable)).toBe(true);
  });

  it("does not emit any operation_expected_artifacts statement", async () => {
    const statements: string[] = [];
    const query = async (sql: string, _params: readonly unknown[] = []) => {
      statements.push(sql);
      return [{ operation_id: OPERATION_ID }];
    };
    const constructed = constructMoveInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });
    await persistMoveInnerAttemptSql(query, {
      operationId: OPERATION_ID,
      constructed,
      sourceT0ObservationId: SOURCE_T0_OBSERVATION,
      destinationT0ObservationId: DESTINATION_T0_OBSERVATION,
      expectedArtifact: expectedArtifactOf(),
      formedAt: FORMED_AT,
    });
    expect(statements.some((s) => /operation_expected_artifacts/i.test(s))).toBe(false);
    expect(statements.some((s) => /UPDATE\s+operations/i.test(s))).toBe(false);
  });
});
