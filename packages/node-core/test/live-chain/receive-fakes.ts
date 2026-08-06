// In-memory fakes for RECEIVE_EXTERNAL preflight tests. No network, no filesystem, no keys,
// no lease acquisition, no transfer-code formation, no submit.

import {
  type ActiveLeaseRow,
  type ReceiveBuildVersionConfig,
  type ReceiveExternalPayerFacts,
  type ReceiveOperationRowSnapshot,
  type ReceivePreflightProbe,
  type ReceiveReceiverFacts,
  RECEIVE_EXPECTED_FIELD_ORDER,
} from "./receive-preflight.js";
import { type DualControlAuthorization } from "./types.js";

export interface FakeReceiveState {
  receivers: Map<string, ReceiveReceiverFacts>;
  payers: Map<string, ReceiveExternalPayerFacts>;
  leases: Map<string, ActiveLeaseRow[]>;
  operations: Map<string, ReceiveOperationRowSnapshot>;
  /** Freshest vault backup timestamp, or null when none. */
  vaultBackupCapturedAt: string | null;
  buildVersion: ReceiveBuildVersionConfig | null;
}

export function emptyReceiveState(): FakeReceiveState {
  return {
    receivers: new Map(),
    payers: new Map(),
    leases: new Map(),
    operations: new Map(),
    vaultBackupCapturedAt: null,
    buildVersion: null,
  };
}

export function fakeReceiveProbe(state: FakeReceiveState): ReceivePreflightProbe {
  return {
    loadReceiver: async (walletId) => state.receivers.get(walletId) ?? null,
    loadExternalPayer: async (payerAddress) => state.payers.get(payerAddress) ?? null,
    activeLeases: async (walletId) => state.leases.get(walletId) ?? [],
    loadOperation: async (operationId) => state.operations.get(operationId) ?? null,
    freshVaultBackup: async (notBeforeIso) => {
      const capturedAt = state.vaultBackupCapturedAt;
      if (capturedAt === null) return { present: false, capturedAt: null };
      // Lexicographic ISO-8601 compare is chronological for the fixed ms format.
      const fresh = capturedAt >= notBeforeIso;
      return { present: fresh, capturedAt };
    },
    loadBuildVersion: async () => state.buildVersion,
  };
}

export function sampleReceiveAuth(
  attemptId = "attempt-receive-1",
  overrides: Partial<DualControlAuthorization> = {},
): DualControlAuthorization {
  return {
    attemptId,
    attestationId: "dual-control-attestation-receive-1",
    recordedAt: "2026-07-27T00:00:00.000Z",
    ...overrides,
  };
}

/** Receiver wallet UUID (node pool). */
export const SAMPLE_RECEIVE_RECEIVER_ID = "55555555-5555-4555-8555-555555555555";
/** Operation under preflight (optional). */
export const SAMPLE_RECEIVE_OPERATION_ID = "33333333-3333-4333-8333-333333333333";
/** Receiver pubkey (A.8 fixture style). */
export const SAMPLE_RECEIVE_RECEIVER_PUBKEY =
  "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
/**
 * Disposable external payer (step_1 signer). Independently held — NOT a node
 * treasury wallet.
 */
export const SAMPLE_RECEIVE_PAYER_ADDRESS =
  "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
/** Independent external keyholder id (distinct from node treasury holder). */
export const SAMPLE_PAYER_KEYHOLDER = "external-payer-disposable-1";

export const SAMPLE_RECEIVE_BUILD: ReceiveBuildVersionConfig = {
  commitSha: "cbcedc8b4a7e7a4033b672abc440a11a",
  imageTag: "local-dev-fixture",
  gatewayEndpoint: "https://gateway.test.example/v1",
  configFingerprint: "cfg-fingerprint-receive-preflight-1",
};

export function eligibleReceiveReceiver(
  walletId = SAMPLE_RECEIVE_RECEIVER_ID,
  overrides: Partial<ReceiveReceiverFacts> = {},
): ReceiveReceiverFacts {
  return {
    walletId,
    pubkey: SAMPLE_RECEIVE_RECEIVER_PUBKEY,
    keyOrigin: "node_generated",
    walletState: "AVAILABLE",
    recoveryVerifiedAt: "2026-07-20T12:00:00.000Z",
    nodeControlled: true,
    backupPresent: true,
    backupCapturedAt: "2026-07-27T00:00:00.000Z",
    ...overrides,
  };
}

export function eligibleExternalPayer(
  payerAddress = SAMPLE_RECEIVE_PAYER_ADDRESS,
  overrides: Partial<ReceiveExternalPayerFacts> = {},
): ReceiveExternalPayerFacts {
  return {
    payerAddress,
    resolvesToNodeBlessedSet: false,
    isNodeControlledWallet: false,
    keyholderId: SAMPLE_PAYER_KEYHOLDER,
    independentControlNote:
      "disposable external payer wallet; private key held offline by external-payer-disposable-1; never the node treasury; funds <= 0.01 ZKZ test capital",
    ...overrides,
  };
}

export function sampleReceiveOperationRow(
  operationId = SAMPLE_RECEIVE_OPERATION_ID,
  overrides: Partial<ReceiveOperationRowSnapshot> = {},
): ReceiveOperationRowSnapshot {
  // CREATED-stage defaults only — READY/leased/code-released is past preflight.
  return {
    operationId,
    status: "CREATED",
    receiverWalletId: SAMPLE_RECEIVE_RECEIVER_ID,
    amountZkz: "0.000001",
    expectedArtifactPresent: true,
    expectedArtifactFieldOrder: [...RECEIVE_EXPECTED_FIELD_ORDER],
    receiverLeaseHeld: false,
    step2SubmitAttempted: false,
    transferCodeReleased: false,
    ...overrides,
  };
}

/** Chain state where every RECEIVE_EXTERNAL preflight check can pass (clean start). */
export function readyReceiveState(attemptId = "attempt-receive-1"): FakeReceiveState {
  void attemptId;
  const state = emptyReceiveState();
  state.receivers.set(SAMPLE_RECEIVE_RECEIVER_ID, eligibleReceiveReceiver());
  state.payers.set(SAMPLE_RECEIVE_PAYER_ADDRESS, eligibleExternalPayer());
  state.vaultBackupCapturedAt = "2026-07-27T00:00:00.000Z";
  state.buildVersion = { ...SAMPLE_RECEIVE_BUILD };
  return state;
}

/** Ready state with an admitted CREATED operation row (A.3.1 artifact, pre-lease). */
export function readyReceiveStateWithOperation(
  attemptId = "attempt-receive-1",
): FakeReceiveState {
  const state = readyReceiveState(attemptId);
  state.operations.set(SAMPLE_RECEIVE_OPERATION_ID, sampleReceiveOperationRow());
  return state;
}
