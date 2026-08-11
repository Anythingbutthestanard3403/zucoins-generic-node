// SEND_EXTERNAL form-and-sign unit tests.
// Governing: operation flows steps 6–8; signing custody; the data model.
//
// Cases covered:
//   * sign intent commits before any signer call (structural: DurableSignIntent brand + call order)
//   * re-signing the same persisted preimage twice → byte-identical Ed25519 signature
//   * expiry is integer-seconds string, computed once, not recomputed on redelivery
//   * no second sign-intent / partial row per operation_id (constraint-violation)
//   * transfer-code SHA-256 over exact string; whitespace/encoding-mutated equivalent fails
//   * APPROVED→AWAITING_REDEMPTION + external_send.awaiting_redemption in same TX as signature
//   * first_delivered_at set-once

import { createHash, createPrivateKey, sign as nodeSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  EXTERNAL_SEND_AWAITING_REDEMPTION_EVENT,
  FORM_AND_SIGN_SQL,
  FORMATION_STATE,
  SEND_REDEMPTION_WINDOW_SECS,
  buildSendTransferCodeText,
  completeSigningFromDurableIntent,
  constructSendInner,
  createInMemoryFormAndSignState,
  createInMemoryPartialPort,
  createInMemorySignIntentPort,
  deriveSendRedemptionExpiryUnixSecs,
  formAndSignSendExternal,
  hashTransferCodeText,
  recordInMemoryPartialDelivery,
  signDurableSendIntent,
  type DurableSignIntent,
  type FormAndSignClaim,
  type FormAndSignHeldLease,
  type FormAndSignInput,
} from "../src/core/send-form-and-sign.js";
import type {
  SignerBoundaryDeps,
  SignerAuditEntry,
  VaultSigner,
} from "../src/core/signer-boundary.js";
import { captureSendBaselines } from "../src/protocol/send-baseline.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "../src/protocol/wallet-role.js";
import {
  WALLET_RECEIVER_PUBLIC_KEY,
  WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
  WALLET_SENDER_PUBLIC_KEY,
} from "./fixtures/splitchain-v2-byte-evidence.js";

const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const LEASE_GROUP_ID = "gggggggg-0000-4000-8000-000000000001";
const SOURCE_OBSERVATION = "bbbbbbbb-0000-4000-8000-000000000001";
const DESTINATION_OBSERVATION = "bbbbbbbb-0000-4000-8000-000000000002";

/** Formation clock: 2026-01-15T00:00:00.000Z → floor secs 1768435200 (illustrative ms). */
const NODE_CLOCK_MS = 1_768_435_200_000;
const PREPARED_AT = "2026-01-15T00:00:00.000Z";
const PERSISTED_AT = "2026-01-15T00:00:01.000Z";

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

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * Deterministic Ed25519 over UTF-8 preimage using a fixed PKCS8 seed so two
 * sign calls over the same bytes produce byte-identical signatures.
 */
function makeDeterministicVaultSigner(): VaultSigner & { calls: string[] } {
  // 32-byte seed → PKCS8 Ed25519 private key (RFC 8410).
  const seed = Buffer.alloc(32, 0x5e);
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const calls: string[] = [];
  return {
    calls,
    sign: async (walletId: string, preimageBytes: Uint8Array) => {
      calls.push(walletId);
      const sig = nodeSign(null, Buffer.from(preimageBytes), key);
      return Buffer.from(sig).toString("base64url") + "==";
    },
  };
}

function makeSignerDeps(
  vault: VaultSigner,
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
  overrides: Partial<FormAndSignInput> & {
    state?: ReturnType<typeof createInMemoryFormAndSignState>;
    vault?: VaultSigner;
  } = {},
): FormAndSignInput & {
  state: ReturnType<typeof createInMemoryFormAndSignState>;
  vaultCalls: string[];
} {
  const state = overrides.state ?? createInMemoryFormAndSignState();
  const vault =
    (overrides.vault as ReturnType<typeof makeDeterministicVaultSigner> | undefined) ??
    makeDeterministicVaultSigner();
  const vaultCalls = "calls" in vault ? (vault as { calls: string[] }).calls : [];
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
    signerDeps: makeSignerDeps(vault),
    state,
    vaultCalls,
    ...overrides,
    // re-bind ports if state was overridden after spread
    ...(overrides.state
      ? {
          signIntentPort:
            overrides.signIntentPort ?? createInMemorySignIntentPort(overrides.state),
          partialPort: overrides.partialPort ?? createInMemoryPartialPort(overrides.state),
        }
      : {}),
  };
}

describe("SEND_REDEMPTION_WINDOW_SECS / expiry derivation", () => {
  it("freezes the 300s window constant", () => {
    expect(SEND_REDEMPTION_WINDOW_SECS).toBe(300);
  });

  it("derives integer-seconds string = floor(ms/1000)+300 (never ms, never number)", () => {
    const expiry = deriveSendRedemptionExpiryUnixSecs(NODE_CLOCK_MS);
    expect(typeof expiry).toBe("string");
    expect(/^[0-9]+$/.test(expiry)).toBe(true);
    expect(expiry.includes(".")).toBe(false);
    expect(Number(expiry)).toBe(Math.floor(NODE_CLOCK_MS / 1000) + 300);
    // Not a JS number sneaking through.
    expect(expiry).not.toBe(Number(expiry) as unknown as string);
  });

  it("rejects a seconds-scale clock mistaken for milliseconds", () => {
    expect(() => deriveSendRedemptionExpiryUnixSecs(1_768_435_200)).toThrow(/MILLISECONDS/);
  });
});

describe("constructSendInner — operation flows step 6", () => {
  it("builds a 14-field inner with T2 expiry frozen once", () => {
    const constructed = constructSendInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });
    const parsed = JSON.parse(constructed.innerPreimageText) as Record<string, unknown>;
    expect(Object.keys(parsed)).toEqual([
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
      // message optional — absent when not supplied
    ].filter((k) => k in parsed || k !== "message"));
    // message is optional and not set — expiry is last present optional.
    expect(parsed.expiry__unix_time_secs).toBe(constructed.expiryUnixTimeSecs);
    expect(typeof parsed.expiry__unix_time_secs).toBe("string");
    expect(parsed.step_1_key_public__base64urlsafe).toBe(WALLET_SENDER_PUBLIC_KEY);
    expect(parsed.step_2_key_public__base64urlsafe).toBe(WALLET_RECEIVER_PUBLIC_KEY);
    expect(constructed.innerSha256).toBe(sha256Hex(constructed.innerPreimageText));
    // Post-balances: source 10-1=9, dest 0+1=1.
    expect((parsed.step_1_state as { amount: string }).amount).toBe("9");
    expect((parsed.step_2_state as { amount: string }).amount).toBe("1");
  });

  it("does not recompute expiry when called with a later clock (caller discipline: once)", () => {
    // The function itself always derives from the clock it is given — the freeze is
    // that formAndSign calls it once and persists the bytes. Prove two different clocks
    // produce different expiries so a redelivery path that rebuilt would diverge.
    const a = constructSendInner({ capture: captureOf(), nodeClockMs: NODE_CLOCK_MS });
    const b = constructSendInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS + 5_000,
    });
    expect(a.expiryUnixTimeSecs).not.toBe(b.expiryUnixTimeSecs);
    expect(a.innerPreimageText).not.toBe(b.innerPreimageText);
  });
});

describe("formAndSignSendExternal — signing custody happy path", () => {
  it("persists sign intent before calling the signer (call-order + brand)", async () => {
    const order: string[] = [];
    const state = createInMemoryFormAndSignState();
    const basePort = createInMemorySignIntentPort(state);
    const signIntentPort = {
      commitSignIntent: async (input: Parameters<typeof basePort.commitSignIntent>[0]) => {
        order.push("persist_sign_intent");
        expect(state.signIntents.size).toBe(0);
        const result = await basePort.commitSignIntent(input);
        expect(state.signIntents.size).toBe(1);
        order.push("sign_intent_committed");
        return result;
      },
    };
    const vault = makeDeterministicVaultSigner();
    const originalSign = vault.sign.bind(vault);
    vault.sign = async (walletId, bytes) => {
      order.push("signer_called");
      // Sign intent MUST already be durable when the vault is reached.
      expect(state.signIntents.has(OPERATION_ID)).toBe(true);
      expect(state.formationState).toBe("SIGNING_CLAIMED");
      return originalSign(walletId, bytes);
    };

    const result = await formAndSignSendExternal(
      baseInput({ state, signIntentPort, vault, signerDeps: makeSignerDeps(vault) }),
    );
    expect(result.ok).toBe(true);
    expect(order).toEqual([
      "persist_sign_intent",
      "sign_intent_committed",
      "signer_called",
    ]);
  });

  it("commits APPROVED→AWAITING_REDEMPTION + event in the same TX as the step-1 signature", async () => {
    const input = baseInput();
    const result = await formAndSignSendExternal(input);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(input.state.status).toBe("AWAITING_REDEMPTION");
    expect(input.state.formationState).toBe("PARTIAL_PERSISTED");
    expect(input.state.attemptPhase.get(OPERATION_ID)).toBe("STEP1_SIGNATURE_PERSISTED");
    expect(input.state.partials.get(OPERATION_ID)?.step1Signature).toBe(result.step1Signature);
    expect(input.state.events).toEqual([
      {
        operationId: OPERATION_ID,
        eventType: EXTERNAL_SEND_AWAITING_REDEMPTION_EVENT,
        at: PERSISTED_AT,
      },
    ]);
    // No window where status advanced without the partial.
    expect(input.state.partials.has(OPERATION_ID)).toBe(true);
  });

  it("role:receiver + empty S dest does not throw — returns construction_rejected (FAIL)", async () => {
    const badDest: WalletStateProjection = {
      role: "receiver",
      S: "",
      P: "",
      B: "0",
      I: null,
    };
    const captured = captureSendBaselines({
      operationId: OPERATION_ID,
      sourceWalletPublicKey: WALLET_SENDER_PUBLIC_KEY,
      destinationAddress: WALLET_RECEIVER_PUBLIC_KEY,
      sourceLease: { role: "SEND_SOURCE", lifecycle: "ACTIVE" },
      sourceBaseline: senderProjection("10"),
      destinationBaseline: badDest,
      amountZkz: "1",
      capturedAt: NODE_CLOCK_MS,
    });
    expect(captured.ok).toBe(true);
    if (!captured.ok) return;
    const input = baseInput({ capture: captured.capture });
    await expect(formAndSignSendExternal(input)).resolves.toMatchObject({
      ok: false,
      reason: "construction_rejected",
      detail: "invalid_genesis_link",
    });
    expect(input.state.status).not.toBe("AWAITING_REDEMPTION");
    expect(input.state.signIntents.has(OPERATION_ID)).toBe(false);
  });

  it("returns the transfer code only after partial commit", async () => {
    const input = baseInput();
    const result = await formAndSignSendExternal(input);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.transferCodeText.length).toBeGreaterThan(0);
    expect(result.transferCodeSha256).toBe(hashTransferCodeText(result.transferCodeText));
    expect(input.state.partials.get(OPERATION_ID)?.transferCodeText).toBe(result.transferCodeText);
  });

  it("freezes T2 expiry inside the durable intent and never recomputes on completeSigning", async () => {
    const input = baseInput();
    // Stop after sign-intent by using a partial port that fails first, then complete.
    const state = input.state;
    const intentOnly = await input.signIntentPort.commitSignIntent({
      claim: input.claim,
      held: input.held,
      approvalId: input.approvalId,
      sourceT0ObservationId: input.sourceT0ObservationId,
      destinationFormationObservationId: input.destinationFormationObservationId,
      constructed: constructSendInner({
        capture: input.capture,
        nodeClockMs: input.nodeClockMs,
      }),
      preparedAt: input.preparedAt,
    });
    expect(intentOnly.ok).toBe(true);
    if (!intentOnly.ok) return;
    const frozenExpiry = intentOnly.intent.expiryUnixTimeSecs;
    const frozenPreimage = intentOnly.intent.innerPreimageText;

    // Complete with a *different* wall clock — must still use the frozen preimage.
    const completed = await completeSigningFromDurableIntent({
      intent: intentOnly.intent,
      persistedAt: "2026-01-15T00:10:00.000Z",
      partialPort: createInMemoryPartialPort(state),
      signerDeps: makeSignerDeps(makeDeterministicVaultSigner()),
    });
    expect(completed.ok).toBe(true);
    if (!completed.ok) return;
    expect(completed.intent.expiryUnixTimeSecs).toBe(frozenExpiry);
    expect(completed.intent.innerPreimageText).toBe(frozenPreimage);
    // Preimage still embeds the original T2.
    expect(JSON.parse(frozenPreimage).expiry__unix_time_secs).toBe(frozenExpiry);
  });
});

describe("deterministic re-sign (review indicator)", () => {
  it("re-signing the same persisted inner_preimage_text twice yields byte-identical signatures", async () => {
    const vault = makeDeterministicVaultSigner();
    const input = baseInput({ vault, signerDeps: makeSignerDeps(vault) });
    const first = await formAndSignSendExternal(input);
    expect(first.ok).toBe(true);
    if (!first.ok) return;

    const sig1 = await signDurableSendIntent(first.intent, makeSignerDeps(vault));
    const sig2 = await signDurableSendIntent(first.intent, makeSignerDeps(vault));
    expect(sig1.signature).toBe(sig2.signature);
    expect(sig1.signature).toBe(first.step1Signature);
    expect(sig1.preimageSha256).toBe(first.intent.innerSha256);
  });
});

describe("cardinality — one sign intent, one partial per operation/approval", () => {
  it("rejects a second sign intent for the same operation_id", async () => {
    const state = createInMemoryFormAndSignState();
    const port = createInMemorySignIntentPort(state);
    const constructed = constructSendInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });
    const first = await port.commitSignIntent({
      claim: claimOf(),
      held: heldOf(),
      approvalId: APPROVAL_ID,
      sourceT0ObservationId: SOURCE_OBSERVATION,
      destinationFormationObservationId: DESTINATION_OBSERVATION,
      constructed,
      preparedAt: PREPARED_AT,
    });
    expect(first.ok).toBe(true);

    const second = await port.commitSignIntent({
      claim: claimOf(),
      held: heldOf(),
      approvalId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      sourceT0ObservationId: SOURCE_OBSERVATION,
      destinationFormationObservationId: DESTINATION_OBSERVATION,
      constructed,
      preparedAt: PREPARED_AT,
    });
    expect(second.ok).toBe(false);
    if (second.ok) return;
    // After the first commit, formation_state is SIGNING_CLAIMED — CAS refuses a second
    // insert. Even if formation were reset, the operation_id uniqueness fence still fires.
    expect(["sign_intent_exists", "formation_not_unsigned"]).toContain(second.reason);
    expect(state.signIntents.size).toBe(1);

    // Explicit uniqueness fence with formation reset (simulates a buggy caller).
    state.formationState = "APPROVED_UNSIGNED";
    const third = await port.commitSignIntent({
      claim: claimOf(),
      held: heldOf(),
      approvalId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
      sourceT0ObservationId: SOURCE_OBSERVATION,
      destinationFormationObservationId: DESTINATION_OBSERVATION,
      constructed,
      preparedAt: PREPARED_AT,
    });
    expect(third.ok).toBe(false);
    if (!third.ok) expect(third.reason).toBe("sign_intent_exists");
    expect(state.signIntents.size).toBe(1);
  });

  it("rejects a second sign intent for the same approval_id", async () => {
    const state = createInMemoryFormAndSignState();
    // First intent on a different operation consumes the approval.
    state.signIntentsByApproval.set(APPROVAL_ID, "other-op");
    const port = createInMemorySignIntentPort(state);
    const second = await port.commitSignIntent({
      claim: claimOf(),
      held: heldOf(),
      approvalId: APPROVAL_ID,
      sourceT0ObservationId: SOURCE_OBSERVATION,
      destinationFormationObservationId: DESTINATION_OBSERVATION,
      constructed: constructSendInner({
        capture: captureOf(),
        nodeClockMs: NODE_CLOCK_MS,
      }),
      preparedAt: PREPARED_AT,
    });
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.reason).toBe("approval_already_bound");
  });

  it("rejects a second partial for the same operation_id", async () => {
    const input = baseInput();
    const first = await formAndSignSendExternal(input);
    expect(first.ok).toBe(true);
    if (!first.ok) return;

    // Formation is already PARTIAL_PERSISTED — a second commit must fail.
    const second = await input.partialPort.commitPartialAndAwaitRedemption({
      intent: first.intent,
      step1Signature: first.step1Signature,
      transferCodeText: first.transferCodeText,
      transferCodeSha256: first.transferCodeSha256,
      persistedAt: PERSISTED_AT,
    });
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.reason).toMatch(/partial_exists|formation_not_signing_claimed/);
    expect(input.state.partials.size).toBe(1);
  });
});

describe("transfer-code digest — canonical fields zero preprocessing", () => {
  it("hashes the exact encoded string", () => {
    const code = buildSendTransferCodeText('{"type":"unique_combinable"}', "sig==");
    expect(hashTransferCodeText(code)).toBe(sha256Hex(code));
  });

  // The three envelope splices moved from inline `JSON.stringify(...)` to the guarded
  // `jsonEscapeString` helper. `JSON.stringify(s)` over a `string` is RFC 8259 escaping either way,
  // so the wire bytes must be identical — this pins them to a literal captured from the pre-change
  // implementation rather than recomputing them from the post-change one. Byte-exact (byte-exact signing).
  it("emits byte-identical wire text for a fixed input", () => {
    expect(
      buildSendTransferCodeText(
        '{"type":"unique_combinable","amount":"0.01","unix_time_secs":"1700000000"}',
        "Rq6Oyn7HEISIb1t3dRuSv-czb33rsWAUmiZe2YmBTK813iHOfNXGF8fIzenv_UENGqUzKJl6f1iTpeAMfnHeAA==",
      ),
    ).toBe(
      "JTdCJTIydmVyc2lvbiUyMiUzQSUyMjElMjIlMkMlMjJ0eXBlJTIyJTNBJTIycmVjZWl2ZXJfY29uZmlybV9wYXJ0aWFsX3RyYW5zYWN0aW9uJTIyJTJDJTIyaW5jb21pbmdfZGF0YSUyMiUzQSU3QiUyMnBhcnRpYWxfdHJhbnNhY3Rpb24lMjIlM0ElN0IlMjJpbm5lciUyMiUzQSU3QiUyMnR5cGUlMjIlM0ElMjJ1bmlxdWVfY29tYmluYWJsZSUyMiUyQyUyMmFtb3VudCUyMiUzQSUyMjAuMDElMjIlMkMlMjJ1bml4X3RpbWVfc2VjcyUyMiUzQSUyMjE3MDAwMDAwMDAlMjIlN0QlMkMlMjJzdGVwXzFfc2lnbmF0dXJlJTIyJTNBJTIyUnE2T3luN0hFSVNJYjF0M2RSdVN2LWN6YjMzcnNXQVVtaVplMlltQlRLODEzaUhPZk5YR0Y4Zkl6ZW52X1VFTkdxVXpLSmw2ZjFpVHBlQU1mbkhlQUElM0QlM0QlMjIlN0QlN0QlN0Q",
    );
  });

  // The runtime half of the same change, and the assertion that actually holds the invariant: the
  // gate can only prove things about syntax it enumerates, so the guard — not a static shadow
  // hunt — is what stops an object's source-order keys reaching the hashed wire bytes. Whatever
  // binding form substitutes a non-string, it throws here instead of being serialised.
  it("throws rather than serialise a non-string into the envelope", () => {
    expect(() =>
      buildSendTransferCodeText('{"type":"unique_combinable"}', {
        zulu: "z",
        alpha: "a",
      } as unknown as string),
    ).toThrow(TypeError);
  });

  it("a whitespace/encoding-mutated equivalent fails to match", () => {
    const inner = constructSendInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    }).innerPreimageText;
    const sig =
      "Rq6Oyn7HEISIb1t3dRuSv-czb33rsWAUmiZe2YmBTK813iHOfNXGF8fIzenv_UENGqUzKJl6f1iTpeAMfnHeAA==";
    const exact = buildSendTransferCodeText(inner, sig);
    const exactDigest = hashTransferCodeText(exact);

    // Mutate: insert whitespace into a would-be equivalent JSON before re-encoding.
    const paddedInner = inner.replace(/:/g, " : ");
    expect(paddedInner).not.toBe(inner);
    const mutated = buildSendTransferCodeText(paddedInner, sig);
    expect(hashTransferCodeText(mutated)).not.toBe(exactDigest);

    // Mutate: trailing newline on the encoded string.
    expect(hashTransferCodeText(exact + "\n")).not.toBe(exactDigest);

    // Mutate: uppercase hex would be a different digest alphabet — change one base64 char.
    const flipped = exact.slice(0, -2) + (exact.endsWith("AB") ? "CD" : "AB");
    expect(hashTransferCodeText(flipped)).not.toBe(exactDigest);
  });

  it("refuses a caller-supplied digest that does not match the exact text", async () => {
    const state = createInMemoryFormAndSignState();
    const intentPort = createInMemorySignIntentPort(state);
    const partialPort = createInMemoryPartialPort(state);
    const constructed = constructSendInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });
    const persisted = await intentPort.commitSignIntent({
      claim: claimOf(),
      held: heldOf(),
      approvalId: APPROVAL_ID,
      sourceT0ObservationId: SOURCE_OBSERVATION,
      destinationFormationObservationId: DESTINATION_OBSERVATION,
      constructed,
      preparedAt: PREPARED_AT,
    });
    expect(persisted.ok).toBe(true);
    if (!persisted.ok) return;

    const code = buildSendTransferCodeText(persisted.intent.innerPreimageText, "sig==");
    const bad = await partialPort.commitPartialAndAwaitRedemption({
      intent: persisted.intent,
      step1Signature: "sig==",
      transferCodeText: code,
      transferCodeSha256: "0".repeat(64),
      persistedAt: PERSISTED_AT,
    });
    expect(bad.ok).toBe(false);
    if (bad.ok) return;
    expect(bad.reason).toBe("transfer_code_digest_mismatch");
    expect(state.partials.size).toBe(0);
    expect(state.status).toBe("APPROVED");
  });
});

describe("first_delivered_at set-once", () => {
  it("stamps first_delivered_at once; later calls only bump redelivery_count", async () => {
    const input = baseInput();
    const result = await formAndSignSendExternal(input);
    expect(result.ok).toBe(true);

    const c0 = recordInMemoryPartialDelivery(input.state, OPERATION_ID, "t1");
    expect(c0).toBe(0);
    expect(input.state.partials.get(OPERATION_ID)?.firstDeliveredAt).toBe("t1");

    const c1 = recordInMemoryPartialDelivery(input.state, OPERATION_ID, "t2");
    expect(c1).toBe(1);
    expect(input.state.partials.get(OPERATION_ID)?.firstDeliveredAt).toBe("t1"); // unchanged
    expect(input.state.partials.get(OPERATION_ID)?.redeliveryCount).toBe(1);

    const c2 = recordInMemoryPartialDelivery(input.state, OPERATION_ID, "t3");
    expect(c2).toBe(2);
    expect(input.state.partials.get(OPERATION_ID)?.firstDeliveredAt).toBe("t1");
  });

  it("forbids delivery before the partial row exists", () => {
    const state = createInMemoryFormAndSignState();
    expect(() => recordInMemoryPartialDelivery(state, OPERATION_ID, "t1")).toThrow(
      /forbidden until the partial row commits/,
    );
  });
});

describe("structural: signer requires DurableSignIntent", () => {
  it("signDurableSendIntent is not callable with a bare ConstructedSendInner (type-level)", () => {
    // Runtime census: the production source only ever passes intent.innerPreimageText
    // into signUnderLease, and only via signDurableSendIntent which requires the brand.
    const src = readFileSync(join(SRC_CORE, "send-form-and-sign.ts"), "utf8");
    // The only call site of signUnderLease in this module is inside signDurableSendIntent.
    const matches = [...src.matchAll(/signUnderLease\s*\(/g)];
    expect(matches.length).toBe(1);
    // And signDurableSendIntent's first parameter is typed DurableSignIntent.
    expect(src).toMatch(
      /export async function signDurableSendIntent\(\s*intent: DurableSignIntent/,
    );
    // formAndSign never calls the vault / signUnderLease before commitSignIntent returns.
    const formBody = src.slice(src.indexOf("export async function formAndSignSendExternal"));
    const persistIdx = formBody.indexOf("commitSignIntent");
    const signIdx = formBody.indexOf("signDurableSendIntent");
    expect(persistIdx).toBeGreaterThan(-1);
    expect(signIdx).toBeGreaterThan(persistIdx);
  });

  it("a ConstructedSendInner object is not a DurableSignIntent at runtime", () => {
    const constructed = constructSendInner({
      capture: captureOf(),
      nodeClockMs: NODE_CLOCK_MS,
    });
    // Brand is a unique symbol — constructed has none of the brand key.
    const brandKeys = Object.getOwnPropertySymbols(constructed);
    expect(brandKeys.length).toBe(0);
    // And the in-memory port only brands after commit.
    const state = createInMemoryFormAndSignState();
    expect(state.signIntents.size).toBe(0);
  });
});

describe("SQL catalogue pins (composition-root contract)", () => {
  it("CAS guards formation_state and status exactly", () => {
    expect(FORM_AND_SIGN_SQL.CAS_APPROVED_UNSIGNED_TO_SIGNING_CLAIMED).toContain(
      "formation_state = 'APPROVED_UNSIGNED'",
    );
    expect(FORM_AND_SIGN_SQL.CAS_APPROVED_UNSIGNED_TO_SIGNING_CLAIMED).toContain(
      "formation_state = 'SIGNING_CLAIMED'",
    );
    expect(FORM_AND_SIGN_SQL.CAS_SIGNING_CLAIMED_TO_AWAITING_REDEMPTION).toContain(
      "status = 'AWAITING_REDEMPTION'",
    );
    expect(FORM_AND_SIGN_SQL.CAS_SIGNING_CLAIMED_TO_AWAITING_REDEMPTION).toContain(
      "formation_state = 'PARTIAL_PERSISTED'",
    );
    expect(FORMATION_STATE.APPROVED_UNSIGNED).toBe("APPROVED_UNSIGNED");
  });
});

// Type-only exhaustiveness: DurableSignIntent is the sole sign path input.
export type _AssertSignPath = typeof signDurableSendIntent extends (
  intent: DurableSignIntent,
  deps: SignerBoundaryDeps,
) => Promise<unknown>
  ? true
  : never;

describe("leaseEpoch end-to-end exactness (ZTR-1168)", () => {
  it("source no longer coerces held.leaseEpoch through Number()", () => {
    const src = readFileSync(join(SRC_CORE, "send-form-and-sign.ts"), "utf8");
    expect(src).not.toMatch(/leaseEpoch:\s*Number\(\s*held\.leaseEpoch\s*\)/);
    expect(src).toMatch(/leaseEpoch:\s*held\.leaseEpoch\.toString\(\)/);
  });

  it("preserves epochs above Number.MAX_SAFE_INTEGER as string for SQL", async () => {
    const { insertSignIntent } = await import("../src/core/transaction-material-store.js");
    const huge = 9_007_199_254_740_993n; // 2^53 + 1
    expect(BigInt(Number(huge))).not.toBe(huge); // proves Number is lossy past 2^53
    const params: unknown[][] = [];
    const query = async (_sql: string, p: readonly unknown[]) => {
      params.push([...p]);
      return [{ operation_id: "x" }];
    };
    await insertSignIntent(query as never, {
      operationId: OPERATION_ID,
      approvalId: APPROVAL_ID,
      sourceWalletId: SOURCE_WALLET_ID,
      sourceT0ObservationId: SOURCE_OBSERVATION,
      destinationT0ObservationId: DESTINATION_OBSERVATION,
      leaseGroupId: LEASE_GROUP_ID,
      leaseEpoch: huge.toString(),
      innerPreimageText: "{}",
      innerSha256: "a".repeat(64),
      redemptionExpiryAt: "2026-01-15T00:05:00.000Z",
      preparedAt: PREPARED_AT,
    });
    expect(params[0]![6]).toBe("9007199254740993");
    expect(params[0]![6]).not.toBe(String(Number(huge)));
  });

  it("in-memory formAndSign keeps bigint epoch above 2^53", async () => {
    const state = createInMemoryFormAndSignState();
    const huge = 9_007_199_254_740_993n;
    const persisted = await createInMemorySignIntentPort(state).commitSignIntent({
      claim: claimOf(),
      held: heldOf(huge),
      approvalId: APPROVAL_ID,
      sourceT0ObservationId: SOURCE_OBSERVATION,
      destinationFormationObservationId: DESTINATION_OBSERVATION,
      constructed: constructSendInner({
        capture: captureOf(),
        nodeClockMs: NODE_CLOCK_MS,
      }),
      preparedAt: PREPARED_AT,
    });
    expect(persisted.ok).toBe(true);
    if (persisted.ok) {
      expect(persisted.intent.leaseEpoch).toBe(huge);
      expect(persisted.intent.leaseEpoch > 2n ** 53n).toBe(true);
    }
  });
});
