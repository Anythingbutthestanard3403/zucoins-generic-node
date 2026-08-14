// ZTR-1301 — admission engines accept verification_mode behind fail-closed policy.
import { describe, expect, it } from "vitest";

import {
  admitReceiveExternal,
  canonicalRequestSha256 as canonicalReceiveRequestSha256,
  type ReceiveAdmissionStore,
  type ReceiveInsertOutcome,
  type ReceiveOperation,
  type ReceiveQueuedInsertOutcome,
  type StoredReceiveOperation,
} from "../src/receive/admission.js";
import {
  createInternalMove,
  canonicalMoveRequestSha256,
  type MoveAdmitInsert,
  type MoveCreateStore,
  type MoveInsertOutcome,
  type StoredMoveOperation,
} from "../src/move/create.js";
import {
  createExternalSend,
  canonicalRequestSha256 as canonicalSendRequestSha256,
  type SendArtifactSigner,
  type SendCreateStore,
  type SendExpectedArtifact,
  type SendInsertOutcome,
  type SendOperation,
  type StoredSendOperation,
} from "../src/send/create.js";
import {
  InMemoryAllowNodeVerifiedPolicy,
  refuseAllNodeVerifiedPolicy,
} from "../src/verification/allow-node-verified-policy.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const DEST_WALLET_ID = "66666666-6666-4666-8666-666666666666";
const DESTINATION_ID = "77777777-7777-4777-8777-777777777777";
const SOURCE_PUBKEY = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DEST_PUBKEY = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const OTHER_ADDRESS = `${"A".repeat(43)}=`;
const IDEMP = "idem-key-verification-mode-01";

const signer: SendArtifactSigner = {
  signingKeyId: "66666666-6666-4666-8666-666666666666",
  sign: (bytes) => bytes.slice(0, 64),
};

function receiveStore(): {
  store: ReceiveAdmissionStore;
  ops: Map<string, StoredReceiveOperation>;
} {
  const ops = new Map<string, StoredReceiveOperation>();
  const byIdem = new Map<string, StoredReceiveOperation>();
  const store: ReceiveAdmissionStore = {
    findDestination: async () => null,
    insertInProgress: async (operation) => {
      const stored: StoredReceiveOperation = {
        ...operation,
        responseStatus: null,
        responseBody: null,
      };
      ops.set(operation.operationId, stored);
      byIdem.set(operation.idempotencyKey, stored);
      return { kind: "INSERTED", subscriptionHandlePlaintext: "sh_test" };
    },
    insertQueuedIfCapAllows: async (operation, _cap) => {
      const key = operation.idempotencyKey;
      const existing = byIdem.get(key);
      if (existing !== undefined) return { kind: "IDEMPOTENCY_CONFLICT" };
      const stored: StoredReceiveOperation = {
        ...operation,
        responseStatus: null,
        responseBody: null,
      };
      ops.set(operation.operationId, stored);
      byIdem.set(key, stored);
      return { kind: "INSERTED", subscriptionHandlePlaintext: "sh_test" };
    },
    findByIdempotency: async (_i, _m, _r, key) => byIdem.get(key) ?? null,
    completeOperation: async (id, status, body) => {
      const row = ops.get(id);
      if (row === undefined || row.responseBody !== null) return false;
      const next = { ...row, responseStatus: status, responseBody: body };
      ops.set(id, next);
      byIdem.set(row.idempotencyKey, next);
      return true;
    },
    findByOperationId: async (id) => ops.get(id) ?? null,
    countQueuedReceives: async () => ops.size,
  };
  return { store, ops };
}

function moveStore(): {
  store: MoveCreateStore;
  ops: Map<string, StoredMoveOperation>;
} {
  const ops = new Map<string, StoredMoveOperation>();
  const store: MoveCreateStore = {
    findSourceWallet: async (id) =>
      id === SOURCE_WALLET_ID
        ? {
            walletId: SOURCE_WALLET_ID,
            nodeId: NODE_ID,
            publicKey: SOURCE_PUBKEY,
            keyOrigin: "node_generated",
            state: "AVAILABLE",
            allowInternalMove: true,
          }
        : null,
    findDestination: async (id) =>
      id === DESTINATION_ID
        ? {
            destinationId: DESTINATION_ID,
            nodeId: NODE_ID,
            walletId: DEST_WALLET_ID,
            publicKey: DEST_PUBKEY,
            keyOrigin: "node_generated",
            walletState: "AVAILABLE",
            destinationState: "BLESSED",
            recoveryVerifiedAt: "2026-01-01T00:00:00.000Z",
            allowInternalMove: true,
          }
        : null,
    hasActiveLease: async () => false,
    insertAdmitted: async (input: MoveAdmitInsert): Promise<MoveInsertOutcome> => {
      for (const row of ops.values()) {
        if (
          row.implementerId === input.operation.implementerId &&
          row.idempotencyKey === input.operation.idempotencyKey
        ) {
          return { kind: "IDEMPOTENCY_CONFLICT" };
        }
      }
      const stored: StoredMoveOperation = {
        ...input.operation,
        status: "CREATED",
        rowVersion: 1,
        attentionRequired: false,
        leaseGroupId: input.operation.leaseGroupId,
        updatedAt: input.operation.createdAt,
      };
      ops.set(stored.operationId, stored);
      return { kind: "INSERTED", leaseGroupId: stored.leaseGroupId as string };
    },
    findByIdempotency: async (implementerId, _kind, key) => {
      for (const row of ops.values()) {
        if (row.implementerId === implementerId && row.idempotencyKey === key) return row;
      }
      return null;
    },
    findByOperationId: async (id) => ops.get(id) ?? null,
    loadReadProjection: async () => ({
      attentionReason: null,
      terminalAt: null,
      verificationMaterialAvailableUntil: null,
      activeLeaseCount: 0,
      expectedArtifact: null,
      executionFacts: {
        operationKind: "MOVE_INTERNAL",
        attemptPhase: null,
        signIntentPersisted: false,
        partialPersisted: false,
        partialFirstDelivered: false,
        submitStarted: false,
        submitReturned: false,
        verificationAccepted: false,
        terminalObservationsPresent: false,
      },
      sourceTerminalObservationId: null,
      destinationTerminalObservationId: null,
    }),
  };
  return { store, ops };
}

function sendStore(): {
  store: SendCreateStore;
  ops: Map<string, StoredSendOperation>;
} {
  const ops = new Map<string, StoredSendOperation>();
  const artifacts = new Map<string, SendExpectedArtifact>();
  const store: SendCreateStore = {
    findSourceWallet: async (id) =>
      id === SOURCE_WALLET_ID
        ? {
            walletId: SOURCE_WALLET_ID,
            nodeId: NODE_ID,
            publicKey: SOURCE_PUBKEY,
            keyOrigin: "node_generated",
            state: "AVAILABLE",
            allowExternalSend: true,
          }
        : null,
    isBlessedInternalAddress: async () => false,
    insertCreated: async (
      operation: SendOperation,
      artifact: SendExpectedArtifact,
    ): Promise<SendInsertOutcome> => {
      for (const row of ops.values()) {
        if (
          row.implementerId === operation.implementerId &&
          row.idempotencyKey === operation.idempotencyKey
        ) {
          return { kind: "IDEMPOTENCY_CONFLICT" };
        }
      }
      const stored: StoredSendOperation = {
        ...operation,
        status: operation.status,
        rowVersion: operation.rowVersion,
        attentionRequired: operation.attentionRequired,
        formationState: operation.formationState,
        responseStatus: null,
        responseBody: null,
      };
      ops.set(operation.operationId, stored);
      artifacts.set(operation.operationId, artifact);
      return { kind: "INSERTED" };
    },
    findByIdempotency: async (implementerId, _m, _r, key) => {
      for (const row of ops.values()) {
        if (row.implementerId === implementerId && row.idempotencyKey === key) return row;
      }
      return null;
    },
    findByOperationId: async (id) => {
      const operation = ops.get(id);
      const artifact = artifacts.get(id);
      if (operation === undefined || artifact === undefined) return null;
      return { operation, artifact };
    },
    completeOperation: async () => true,
  };
  return { store, ops };
}

describe("verification_mode admission (ZTR-1301)", () => {
  describe("receive", () => {
    it("omitted mode admits as INDEPENDENT (AC2)", async () => {
      const { store, ops } = receiveStore();
      const outcome = await admitReceiveExternal(
        store,
        {
          implementerId: IMPLEMENTER_ID,
          nodeId: NODE_ID,
          amountZkz: "1",
          anchor: "ord_01",
          ttlMs: 60_000,
          afterLanding: { kind: "HOLD", destinationId: null },
          idempotencyKey: IDEMP,
        },
        { queueCap: 10 },
      );
      expect(outcome.outcome).toBe("ADMITTED");
      if (outcome.outcome !== "ADMITTED") return;
      expect(outcome.operation.verificationMode).toBe("INDEPENDENT");
      expect([...ops.values()][0]?.verificationMode).toBe("INDEPENDENT");
    });

    it("NODE_VERIFIED without policy → verification_mode_not_allowed (AC1)", async () => {
      const { store } = receiveStore();
      const outcome = await admitReceiveExternal(
        store,
        {
          implementerId: IMPLEMENTER_ID,
          nodeId: NODE_ID,
          amountZkz: "1",
          anchor: "ord_01",
          ttlMs: 60_000,
          afterLanding: { kind: "HOLD", destinationId: null },
          idempotencyKey: IDEMP,
          verificationMode: "NODE_VERIFIED",
        },
        { queueCap: 10, allowNodeVerifiedPolicy: refuseAllNodeVerifiedPolicy() },
      );
      expect(outcome).toEqual({
        outcome: "REJECTED",
        code: "verification_mode_not_allowed",
      });
    });

    it("NODE_VERIFIED with policy persists mode (AC1)", async () => {
      const { store, ops } = receiveStore();
      const policy = new InMemoryAllowNodeVerifiedPolicy();
      policy.allowImplementer(IMPLEMENTER_ID);
      const outcome = await admitReceiveExternal(
        store,
        {
          implementerId: IMPLEMENTER_ID,
          nodeId: NODE_ID,
          amountZkz: "1",
          anchor: "ord_01",
          ttlMs: 60_000,
          afterLanding: { kind: "HOLD", destinationId: null },
          idempotencyKey: IDEMP,
          verificationMode: "NODE_VERIFIED",
        },
        { queueCap: 10, allowNodeVerifiedPolicy: policy },
      );
      expect(outcome.outcome).toBe("ADMITTED");
      if (outcome.outcome !== "ADMITTED") return;
      expect(outcome.operation.verificationMode).toBe("NODE_VERIFIED");
      expect([...ops.values()][0]?.verificationMode).toBe("NODE_VERIFIED");
    });

    it("idempotency replay with different mode → conflict (AC3)", async () => {
      const { store } = receiveStore();
      const policy = new InMemoryAllowNodeVerifiedPolicy();
      policy.allowImplementer(IMPLEMENTER_ID);
      const base = {
        implementerId: IMPLEMENTER_ID,
        nodeId: NODE_ID,
        amountZkz: "1",
        anchor: "ord_01",
        ttlMs: 60_000,
        afterLanding: { kind: "HOLD" as const, destinationId: null },
        idempotencyKey: IDEMP,
      };
      const first = await admitReceiveExternal(store, base, {
        queueCap: 10,
        allowNodeVerifiedPolicy: policy,
      });
      expect(first.outcome).toBe("ADMITTED");
      if (first.outcome !== "ADMITTED") return;
      await store.completeOperation(
        first.operation.operationId,
        202,
        JSON.stringify({ ok: true }),
      );

      const second = await admitReceiveExternal(
        store,
        { ...base, verificationMode: "NODE_VERIFIED" },
        { queueCap: 10, allowNodeVerifiedPolicy: policy },
      );
      expect(second).toEqual({ outcome: "REJECTED", code: "idempotency_key_reused" });

      // Fingerprints differ when mode changes.
      expect(canonicalReceiveRequestSha256(base)).not.toBe(
        canonicalReceiveRequestSha256({ ...base, verificationMode: "NODE_VERIFIED" }),
      );
    });
  });

  describe("move", () => {
    it("NODE_VERIFIED without policy → not allowed", async () => {
      const { store } = moveStore();
      const outcome = await createInternalMove(
        store,
        {
          implementerId: IMPLEMENTER_ID,
          nodeId: NODE_ID,
          sourceWalletId: SOURCE_WALLET_ID,
          destinationId: DESTINATION_ID,
          amountZkz: "1",
          idempotencyKey: IDEMP,
          verificationMode: "NODE_VERIFIED",
        },
        { allowNodeVerifiedPolicy: refuseAllNodeVerifiedPolicy() },
      );
      expect(outcome).toEqual({
        outcome: "REJECTED",
        code: "verification_mode_not_allowed",
      });
    });

    it("NODE_VERIFIED with policy persists + GET body echoes mode", async () => {
      const { store, ops } = moveStore();
      const policy = new InMemoryAllowNodeVerifiedPolicy();
      policy.allowImplementer(IMPLEMENTER_ID);
      const outcome = await createInternalMove(
        store,
        {
          implementerId: IMPLEMENTER_ID,
          nodeId: NODE_ID,
          sourceWalletId: SOURCE_WALLET_ID,
          destinationId: DESTINATION_ID,
          amountZkz: "1",
          idempotencyKey: IDEMP,
          verificationMode: "NODE_VERIFIED",
        },
        { allowNodeVerifiedPolicy: policy },
      );
      expect(outcome.outcome).toBe("CREATED");
      if (outcome.outcome !== "CREATED") return;
      expect(outcome.operation.verificationMode).toBe("NODE_VERIFIED");
      expect([...ops.values()][0]?.verificationMode).toBe("NODE_VERIFIED");
      const body = JSON.parse(
        JSON.stringify(
          (
            await import("../src/move/create.js")
          ).buildInternalMoveResponse(outcome.operation),
        ),
      ) as { operation: { verification_mode: string } };
      expect(body.operation.verification_mode).toBe("NODE_VERIFIED");
    });

    it("different mode is a distinct fingerprint", () => {
      const base = {
        implementerId: IMPLEMENTER_ID,
        nodeId: NODE_ID,
        sourceWalletId: SOURCE_WALLET_ID,
        destinationId: DESTINATION_ID,
        amountZkz: "1",
        idempotencyKey: IDEMP,
      };
      expect(canonicalMoveRequestSha256(base)).not.toBe(
        canonicalMoveRequestSha256({ ...base, verificationMode: "NODE_VERIFIED" }),
      );
      expect(canonicalMoveRequestSha256(base)).toBe(
        canonicalMoveRequestSha256({ ...base, verificationMode: "INDEPENDENT" }),
      );
    });
  });

  describe("send", () => {
    it("NODE_VERIFIED without policy → not allowed", async () => {
      const { store } = sendStore();
      const outcome = await createExternalSend(
        store,
        signer,
        {
          implementerId: IMPLEMENTER_ID,
          nodeId: NODE_ID,
          sourceWalletId: SOURCE_WALLET_ID,
          destinationAddress: OTHER_ADDRESS,
          amountZkz: "1",
          referencesOperationId: null,
          clientReference: null,
          description: null,
          idempotencyKey: IDEMP,
          verificationMode: "NODE_VERIFIED",
        },
        { allowNodeVerifiedPolicy: refuseAllNodeVerifiedPolicy() },
      );
      expect(outcome).toEqual({
        outcome: "REJECTED",
        code: "verification_mode_not_allowed",
      });
    });

    it("NODE_VERIFIED with policy persists mode on row + response", async () => {
      const { store, ops } = sendStore();
      const policy = new InMemoryAllowNodeVerifiedPolicy();
      policy.allowImplementer(IMPLEMENTER_ID);
      const outcome = await createExternalSend(
        store,
        signer,
        {
          implementerId: IMPLEMENTER_ID,
          nodeId: NODE_ID,
          sourceWalletId: SOURCE_WALLET_ID,
          destinationAddress: OTHER_ADDRESS,
          amountZkz: "1",
          referencesOperationId: null,
          clientReference: null,
          description: null,
          idempotencyKey: IDEMP,
          verificationMode: "NODE_VERIFIED",
        },
        { allowNodeVerifiedPolicy: policy },
      );
      expect(outcome.outcome).toBe("CREATED");
      if (outcome.outcome !== "CREATED") return;
      expect(outcome.operation.verificationMode).toBe("NODE_VERIFIED");
      expect([...ops.values()][0]?.verificationMode).toBe("NODE_VERIFIED");
      const { buildExternalSendResponse } = await import("../src/send/create.js");
      const body = buildExternalSendResponse(outcome.operation, outcome.artifact);
      expect(body.operation.verification_mode).toBe("NODE_VERIFIED");
    });

    it("different mode is a distinct fingerprint", () => {
      const base = {
        implementerId: IMPLEMENTER_ID,
        nodeId: NODE_ID,
        sourceWalletId: SOURCE_WALLET_ID,
        destinationAddress: OTHER_ADDRESS,
        amountZkz: "1",
        referencesOperationId: null,
        clientReference: null,
        description: null,
        idempotencyKey: IDEMP,
      };
      expect(canonicalSendRequestSha256(base)).not.toBe(
        canonicalSendRequestSha256({ ...base, verificationMode: "NODE_VERIFIED" }),
      );
    });
  });
});
