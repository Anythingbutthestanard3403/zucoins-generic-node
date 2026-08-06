// Offline APPROVED → AWAITING_REDEMPTION post-approve formation + privilege.
import { createHash, createPrivateKey, sign as nodeSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  GENESIS_PROJECTION,
  RECEIVE_T0_OBSERVATION_ROLE,
  buildExternalSendResponse,
  createInMemoryFormAndSignState,
  createInMemoryPartialPort,
  createInMemorySignIntentPort,
  hashTransferCodeText,
  readExternalSend,
  runSendPostApproveFormation,
  type ApprovedSendClaimPort,
  type ExternalSendPartialLoader,
  type FormAndSignClaim,
  type HeldSourceLease,
  type ReceiveT0Observer,
  type SendCreateStore,
  type SendFormationObserver,
  type SendOperation,
  type SignerBoundaryDeps,
  type SourceLeasePort,
  type StoredSendOperation,
  type VaultSigner,
  captureSendBaselines,
} from "@zucoins/node-core";
import {
  WALLET_RECEIVER_PUBLIC_KEY,
  WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
  WALLET_SENDER_PUBLIC_KEY,
} from "../../../packages/node-core/test/fixtures/splitchain-v2-byte-evidence.js";
import { createSendFormationObserverFromReceiveT0 } from "../src/money-workers/send-formation-observer.js";

const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const SOURCE_OBS = "bbbbbbbb-0000-4000-8000-000000000001";
const DEST_OBS = "bbbbbbbb-0000-4000-8000-000000000002";
const HERE = dirname(fileURLToPath(import.meta.url));

/** Privilege scan only — kept out of production send/ so census half-2 stays clean. */
const POST_APPROVE_FORBIDDEN_MARKERS = [
  "submit_transaction",
  "submit_transaction__v1",
  "makeSubmitDecisionClaimStore",
  "makeSubmitAttemptRecorder",
  "gateway_submit_attempts",
  "submit_decisions",
  "NODE_SUBMIT_EXTERNAL_SEND",
] as const;

function makeVault(): VaultSigner {
  const seed = Buffer.alloc(32, 0x5e);
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return {
    sign: async (_w, preimageBytes) => {
      const sig = nodeSign(null, Buffer.from(preimageBytes), key);
      return Buffer.from(sig).toString("base64url") + "==";
    },
  };
}

function signerDeps(): SignerBoundaryDeps {
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
    vaultSigner: makeVault(),
    auditLog: { append: async () => {} },
    assertMoneyAdmitted: () => {},
    assertCanOperate: () => {},
    assertWalletMaySign: async () => {},
  };
}

function held(): HeldSourceLease {
  return {
    walletId: SOURCE_WALLET_ID,
    membershipId: "mmmmmmmm-0000-4000-8000-000000000001",
    leaseGroupId: "gggggggg-0000-4000-8000-000000000001",
    leaseEpoch: 1n,
    operationId: OPERATION_ID,
    lease: { role: "SEND_SOURCE", lifecycle: "ACTIVE" },
  };
}

describe("SEND post-approve formation (offline)", () => {
  it("APPROVED → AWAITING_REDEMPTION with transfer_code fingerprint set", async () => {
    const state = createInMemoryFormAndSignState();
    const claimPort: ApprovedSendClaimPort = {
      claimApproved: async () => ({
        outcome: "CLAIMED",
        claim: {
          operationId: OPERATION_ID,
          status: "APPROVED",
          formationState: "APPROVED_UNSIGNED",
          rowVersion: 2,
          sourceWalletId: SOURCE_WALLET_ID,
          sourcePubkey: WALLET_SENDER_PUBLIC_KEY,
          destinationAddress: WALLET_RECEIVER_PUBLIC_KEY,
          amountZkz: "0.01",
        },
      }),
    };
    const leasePort: SourceLeasePort = {
      tryAcquireSourceLease: async () => ({ outcome: "ACQUIRED", held: held() }),
    };
    const observer: SendFormationObserver = {
      observeSource: async () => ({
        kind: "VERIFIED",
        observationId: SOURCE_OBS,
        projection: {
          role: "sender",
          S: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
          P: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
          B: "10",
          I: "digest",
        },
      }),
      observeDestination: async () => ({
        kind: "VERIFIED",
        observationId: DEST_OBS,
        projection: GENESIS_PROJECTION,
      }),
    };

    const result = await runSendPostApproveFormation({
      operationId: OPERATION_ID,
      ownerInstanceId: "owner-1",
      capturedAt: 1_768_435_200_000,
      nodeClockMs: 1_768_435_200_000,
      preparedAt: "2026-01-15T00:00:00.000Z",
      persistedAt: "2026-01-15T00:00:01.000Z",
      claimPort,
      leasePort,
      observer,
      approvalIds: { loadConsumedApprovalId: async () => APPROVAL_ID },
      signIntentPort: createInMemorySignIntentPort(state),
      partialPort: createInMemoryPartialPort(state),
      signerDeps: signerDeps(),
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe("AWAITING_REDEMPTION");
    expect(state.status).toBe("AWAITING_REDEMPTION");
    expect(state.formationState).toBe("PARTIAL_PERSISTED");
    expect(result.transferCodeSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(hashTransferCodeText(result.transferCodeText)).toBe(result.transferCodeSha256);
    expect(result.transferCodeText.length).toBeGreaterThan(32);
  });

  it("GET read at AWAITING_REDEMPTION surfaces transfer_code_sha256 fingerprint", async () => {
    const partialSha = createHash("sha256").update("code-bytes").digest("hex");
    const partials: ExternalSendPartialLoader = {
      loadPartial: async () => ({
        transferCodeText: "code-bytes",
        transferCodeSha256: partialSha,
        availableUntil: "2026-01-15T00:05:00.000Z",
      }),
    };
    const op: StoredSendOperation = {
      operationId: OPERATION_ID,
      implementerId: "11111111-1111-4111-8111-111111111111",
      nodeId: "22222222-2222-4222-8222-222222222222",
      kind: "SEND_EXTERNAL",
      status: "AWAITING_REDEMPTION",
      rowVersion: 3,
      attentionRequired: false,
      formationState: "PARTIAL_PERSISTED",
      httpMethod: "POST",
      route: "/v1/external-sends",
      idempotencyKey: "idem-key-at-least-16",
      requestSha256: "a".repeat(64),
      sourceWalletId: SOURCE_WALLET_ID,
      destinationAddress: WALLET_RECEIVER_PUBLIC_KEY,
      amountZkz: "0.01",
      referencesOperationId: null,
      clientReference: null,
      description: null,
      createdAt: Date.parse("2026-01-15T00:00:00.000Z"),
      responseStatus: null,
      responseBody: null,
    };
    const store = {
      findByOperationId: async () => ({
        operation: op,
        artifact: {
          artifactId: "art",
          operationId: OPERATION_ID,
          purpose: "zp-send-external-expected-v1",
          canonicalVersion: 1,
          keyId: "key",
          preimageText: "{}",
          preimageSha256: "b".repeat(64),
          signature: "c".repeat(86) + "==",
        },
      }),
    } as unknown as SendCreateStore;

    const read = await readExternalSend(store, OPERATION_ID, partials);
    expect(read.outcome).toBe("FOUND");
    if (read.outcome !== "FOUND") return;
    expect(read.response.operation.state).toBe("AWAITING_REDEMPTION");
    expect(read.response.transfer_code).toBe("code-bytes");
    expect(read.response.transfer_code_sha256).toBe(partialSha);
    expect(read.response.approval_status).toBe("CONSUMED");
  });

  it("buildExternalSendResponse create-time still freezes null code fields", () => {
    const claim: FormAndSignClaim = {
      operationId: OPERATION_ID,
      status: "APPROVED",
      formationState: "APPROVED_UNSIGNED",
      rowVersion: 1,
      sourceWalletId: SOURCE_WALLET_ID,
      sourcePubkey: WALLET_SENDER_PUBLIC_KEY,
      destinationAddress: WALLET_RECEIVER_PUBLIC_KEY,
      amountZkz: "1",
    };
    void claim;
    const op = {
      operationId: OPERATION_ID,
      status: "CREATED",
      amountZkz: "1",
      rowVersion: 1,
      attentionRequired: false,
      sourceWalletId: SOURCE_WALLET_ID,
      destinationAddress: WALLET_RECEIVER_PUBLIC_KEY,
      referencesOperationId: null,
      createdAt: Date.now(),
    } as unknown as SendOperation;
    const body = buildExternalSendResponse(op, {
      artifactId: "a",
      operationId: OPERATION_ID,
      purpose: "zp-send-external-expected-v1",
      canonicalVersion: 1,
      keyId: "k",
      preimageText: "{}",
      preimageSha256: "d".repeat(64),
      signature: "e".repeat(86) + "==",
    });
    expect(body.transfer_code).toBeNull();
    expect(body.transfer_code_sha256).toBeNull();
    expect(body.approval_status).toBe("PENDING");
  });

  it("post-approve module and money-worker SEND paths never carry submit markers", () => {
    const roots = [
      join(HERE, "../../../packages/node-core/src/send/post-approve.ts"),
      join(HERE, "../src/money-workers/send-sql-ports.ts"),
      join(HERE, "../src/money-workers/send-completion-tick.ts"),
      join(HERE, "../src/money-workers/send-formation-observer.ts"),
      join(HERE, "../src/money-workers/send-vault-signer.ts"),
      join(HERE, "../src/money-workers/start-money-workers.ts"),
    ];
    for (const path of roots) {
      let src = readFileSync(path, "utf8");
      // Drop comments so docstrings naming the prohibition do not active-fail.
      src = src
        .split("\n")
        .filter((line) => !/^\s*\/\//.test(line) && !/^\s*\*/.test(line))
        .join("\n");
      for (const marker of POST_APPROVE_FORBIDDEN_MARKERS) {
        expect(src, `${path} must not contain ${marker}`).not.toContain(marker);
      }
    }
  });

  it("composition pins: startMoneyWorkers invokes post-approve + completion stub", () => {
    const workers = readFileSync(join(HERE, "../src/money-workers/start-money-workers.ts"), "utf8");
    expect(workers).toMatch(/runSendPostApproveFormation/);
    expect(workers).toMatch(/mirrorSendOperationsToOperations/);
    expect(workers).toMatch(/tickSendCompletionLander/);
    expect(workers).toMatch(/loadApprovedUnsignedSendIds/);
    expect(workers).toMatch(/AWAITING_REDEMPTION/);
    expect(workers).not.toMatch(/submit_transaction/);
    const main = readFileSync(join(HERE, "../src/main.ts"), "utf8");
    expect(main).toMatch(/signerLeadership:\s*shutdownRegistry\.authority/);
    expect(main).toMatch(/createSqlSendPartialLoader/);
  });

  it("baseline capture remains pure (sanity)", () => {
    const captured = captureSendBaselines({
      operationId: OPERATION_ID,
      sourceWalletPublicKey: WALLET_SENDER_PUBLIC_KEY,
      destinationAddress: WALLET_RECEIVER_PUBLIC_KEY,
      sourceLease: { role: "SEND_SOURCE", lifecycle: "ACTIVE" },
      sourceBaseline: {
        role: "sender",
        S: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
        P: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
        B: "10",
        I: "d",
      },
      destinationBaseline: GENESIS_PROJECTION,
      amountZkz: "0.01",
      capturedAt: 1,
    });
    expect(captured.ok).toBe(true);
  });

  it("default dest OBSERVE uses gated T0 stream — preserves role:genesis, never invents receiver+empty S", async () => {
    const observedKeys: string[] = [];
    const t0: ReceiveT0Observer = {
      async observe(walletPublicKey, role) {
        expect(role).toBe(RECEIVE_T0_OBSERVATION_ROLE);
        observedKeys.push(walletPublicKey);
        if (walletPublicKey === WALLET_SENDER_PUBLIC_KEY) {
          return {
            kind: "VERIFIED",
            observationId: SOURCE_OBS,
            projection: {
              role: "sender",
              S: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
              P: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
              B: "10",
              I: "digest",
            },
          };
        }
        // Gated genesis stub / gateway GENESIS only return role:genesis with empty S.
        return {
          kind: "VERIFIED",
          observationId: DEST_OBS,
          projection: GENESIS_PROJECTION,
        };
      },
    };
    const composed = createSendFormationObserverFromReceiveT0(t0);
    const dest = await composed.observeDestination(WALLET_RECEIVER_PUBLIC_KEY);
    expect(dest).toEqual({
      kind: "VERIFIED",
      observationId: DEST_OBS,
      projection: GENESIS_PROJECTION,
    });
    expect(dest.kind === "VERIFIED" && dest.projection.role).toBe("genesis");
    expect(dest.kind === "VERIFIED" && dest.projection.S).toBe("");
    // Must not invent VERIFIED without calling the durable T0 path.
    expect(observedKeys).toContain(WALLET_RECEIVER_PUBLIC_KEY);

    const src = await composed.observeSource(WALLET_SENDER_PUBLIC_KEY);
    expect(src.kind).toBe("VERIFIED");
    if (src.kind !== "VERIFIED") return;
    expect(src.projection.role).toBe("sender");
    expect(src.projection.S).toBe(WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE);

    // Full post-approve path with real genesis dest reaches AWAITING_REDEMPTION.
    const state = createInMemoryFormAndSignState();
    const result = await runSendPostApproveFormation({
      operationId: OPERATION_ID,
      ownerInstanceId: "owner-1",
      capturedAt: 1_768_435_200_000,
      nodeClockMs: 1_768_435_200_000,
      preparedAt: "2026-01-15T00:00:00.000Z",
      persistedAt: "2026-01-15T00:00:01.000Z",
      claimPort: {
        claimApproved: async () => ({
          outcome: "CLAIMED",
          claim: {
            operationId: OPERATION_ID,
            status: "APPROVED",
            formationState: "APPROVED_UNSIGNED",
            rowVersion: 2,
            sourceWalletId: SOURCE_WALLET_ID,
            sourcePubkey: WALLET_SENDER_PUBLIC_KEY,
            destinationAddress: WALLET_RECEIVER_PUBLIC_KEY,
            amountZkz: "0.01",
          },
        }),
      },
      leasePort: {
        tryAcquireSourceLease: async () => ({ outcome: "ACQUIRED", held: held() }),
      },
      observer: composed,
      approvalIds: { loadConsumedApprovalId: async () => APPROVAL_ID },
      signIntentPort: createInMemorySignIntentPort(state),
      partialPort: createInMemoryPartialPort(state),
      signerDeps: signerDeps(),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe("AWAITING_REDEMPTION");
  });

  it("default dest OBSERVE never fabricates VERIFIED without T0 (INDETERMINATE passthrough)", async () => {
    const t0: ReceiveT0Observer = {
      async observe() {
        return { kind: "INDETERMINATE", detail: "no gateway" };
      },
    };
    const dest = await createSendFormationObserverFromReceiveT0(t0).observeDestination(
      WALLET_RECEIVER_PUBLIC_KEY,
    );
    expect(dest).toEqual({ kind: "INDETERMINATE", detail: "no gateway" });
  });

  it("receiver+empty S observer cannot throw tick — post-approve returns form_and_sign_rejected", async () => {
    const observer: SendFormationObserver = {
      observeSource: async () => ({
        kind: "VERIFIED",
        observationId: SOURCE_OBS,
        projection: {
          role: "sender",
          S: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
          P: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
          B: "10",
          I: "digest",
        },
      }),
      observeDestination: async () => ({
        kind: "VERIFIED",
        observationId: DEST_OBS,
        projection: { role: "receiver", S: "", P: "", B: "0", I: null },
      }),
    };
    const state = createInMemoryFormAndSignState();
    const result = await runSendPostApproveFormation({
      operationId: OPERATION_ID,
      ownerInstanceId: "owner-1",
      capturedAt: 1_768_435_200_000,
      nodeClockMs: 1_768_435_200_000,
      preparedAt: "2026-01-15T00:00:00.000Z",
      persistedAt: "2026-01-15T00:00:01.000Z",
      claimPort: {
        claimApproved: async () => ({
          outcome: "CLAIMED",
          claim: {
            operationId: OPERATION_ID,
            status: "APPROVED",
            formationState: "APPROVED_UNSIGNED",
            rowVersion: 2,
            sourceWalletId: SOURCE_WALLET_ID,
            sourcePubkey: WALLET_SENDER_PUBLIC_KEY,
            destinationAddress: WALLET_RECEIVER_PUBLIC_KEY,
            amountZkz: "0.01",
          },
        }),
      },
      leasePort: {
        tryAcquireSourceLease: async () => ({ outcome: "ACQUIRED", held: held() }),
      },
      observer,
      approvalIds: { loadConsumedApprovalId: async () => APPROVAL_ID },
      signIntentPort: createInMemorySignIntentPort(state),
      partialPort: createInMemoryPartialPort(state),
      signerDeps: signerDeps(),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("form_and_sign_rejected");
    expect(result.detail).toMatch(/construction_rejected|invalid_genesis_link/);
    expect(state.status).not.toBe("AWAITING_REDEMPTION");
  });
});
