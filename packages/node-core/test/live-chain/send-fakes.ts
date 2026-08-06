// In-memory fakes for SEND_EXTERNAL preflight tests. No network, no filesystem, no keys,
// no TOTP, no lease acquisition.

import {
  type ActiveLeaseRow,
  type SendApprovalChallenge,
  type SendExternalRecipientFacts,
  type SendOperationRowSnapshot,
  type SendPreflightProbe,
  type SendSourceFacts,
  SEND_APPROVAL_FIELD_ORDER,
  SEND_APPROVAL_PURPOSE,
  SEND_EXPECTED_FIELD_ORDER,
} from "./send-preflight.js";
import { type Amount, type DualControlAuthorization } from "./types.js";

export interface FakeSendState {
  sources: Map<string, SendSourceFacts>;
  recipients: Map<string, SendExternalRecipientFacts>;
  leases: Map<string, ActiveLeaseRow[]>;
  balances: Map<string, Amount>;
  operations: Map<string, SendOperationRowSnapshot>;
  challenges: Map<string, SendApprovalChallenge>;
  /** Freshest vault backup timestamp, or null when none. */
  vaultBackupCapturedAt: string | null;
  /** Balance reads that should throw (simulates gateway failure). */
  balanceErrors: Map<string, string>;
}

export function emptySendState(): FakeSendState {
  return {
    sources: new Map(),
    recipients: new Map(),
    leases: new Map(),
    balances: new Map(),
    operations: new Map(),
    challenges: new Map(),
    vaultBackupCapturedAt: null,
    balanceErrors: new Map(),
  };
}

export function fakeSendProbe(state: FakeSendState): SendPreflightProbe {
  return {
    loadSource: async (walletId) => state.sources.get(walletId) ?? null,
    loadRecipient: async (destinationAddress) =>
      state.recipients.get(destinationAddress) ?? null,
    activeLeases: async (walletId) => state.leases.get(walletId) ?? [],
    freshGatewayBalance: async (walletId) => {
      const err = state.balanceErrors.get(walletId);
      if (err !== undefined) throw new Error(err);
      return state.balances.get(walletId) ?? "0";
    },
    loadOperation: async (operationId) => state.operations.get(operationId) ?? null,
    loadApprovalChallenge: async (operationId) =>
      state.challenges.get(operationId) ?? null,
    freshVaultBackup: async (notBeforeIso) => {
      const capturedAt = state.vaultBackupCapturedAt;
      if (capturedAt === null) return { present: false, capturedAt: null };
      // Lexicographic ISO-8601 compare is chronological for the fixed ms format.
      const fresh = capturedAt >= notBeforeIso;
      return { present: fresh, capturedAt };
    },
  };
}

export function sampleSendAuth(
  attemptId = "attempt-send-1",
  overrides: Partial<DualControlAuthorization> = {},
): DualControlAuthorization {
  return {
    attemptId,
    attestationId: "dual-control-attestation-send-1",
    recordedAt: "2026-07-27T00:00:00.000Z",
    ...overrides,
  };
}

/** Source wallet UUID (node treasury). */
export const SAMPLE_SEND_SOURCE_ID = "55555555-5555-4555-8555-555555555555";
/** Operation under preflight. */
export const SAMPLE_SEND_OPERATION_ID = "33333333-3333-4333-8333-333333333333";
/** Node id (A.8 fixture). */
export const SAMPLE_SEND_NODE_ID = "11111111-1111-4111-8111-111111111111";
/** Source pubkey (A.8 fixture). */
export const SAMPLE_SEND_SOURCE_PUBKEY =
  "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
/**
 * Disposable external destination (A.8 fixture). Independently held — NOT a node
 * treasury wallet.
 */
export const SAMPLE_SEND_DEST_ADDRESS =
  "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
/** Independent external keyholder id (distinct from node treasury holder). */
export const SAMPLE_EXTERNAL_KEYHOLDER = "external-keyholder-disposable-1";

export function eligibleSendSource(
  walletId = SAMPLE_SEND_SOURCE_ID,
  overrides: Partial<SendSourceFacts> = {},
): SendSourceFacts {
  return {
    walletId,
    pubkey: SAMPLE_SEND_SOURCE_PUBKEY,
    keyOrigin: "node_generated",
    walletState: "AVAILABLE",
    nodeControlled: true,
    backupPresent: true,
    backupCapturedAt: "2026-07-27T00:00:00.000Z",
    ...overrides,
  };
}

export function eligibleExternalRecipient(
  destinationAddress = SAMPLE_SEND_DEST_ADDRESS,
  overrides: Partial<SendExternalRecipientFacts> = {},
): SendExternalRecipientFacts {
  return {
    destinationAddress,
    resolvesToNodeBlessedSet: false,
    isNodeControlledWallet: false,
    keyholderId: SAMPLE_EXTERNAL_KEYHOLDER,
    independentControlNote:
      "disposable external wallet; private key held offline by external-keyholder-disposable-1; never the node treasury",
    ...overrides,
  };
}

export function sampleApprovalChallenge(
  operationId = SAMPLE_SEND_OPERATION_ID,
  overrides: Partial<SendApprovalChallenge> = {},
): SendApprovalChallenge {
  return {
    purpose: SEND_APPROVAL_PURPOSE,
    canonicalVersion: 1,
    nodeId: SAMPLE_SEND_NODE_ID,
    operationId,
    sourceSelector: { kind: "WALLET_ID", wallet_id: SAMPLE_SEND_SOURCE_ID },
    sourcePubkey: SAMPLE_SEND_SOURCE_PUBKEY,
    destinationAddress: SAMPLE_SEND_DEST_ADDRESS,
    amountZkz: "0.000001",
    referencesOperationId: null,
    nonce: "99999999-9999-4999-8999-999999999999",
    issuedAt: "2026-07-27T00:00:00.000Z",
    expiresAt: "2026-07-27T00:05:00.000Z",
    fieldOrder: [...SEND_APPROVAL_FIELD_ORDER],
    carriesSplitInnerSha256: false,
    consumed: false,
    ...overrides,
  };
}

export function sampleOperationRow(
  operationId = SAMPLE_SEND_OPERATION_ID,
  overrides: Partial<SendOperationRowSnapshot> = {},
): SendOperationRowSnapshot {
  return {
    operationId,
    status: "CREATED",
    sourceWalletId: SAMPLE_SEND_SOURCE_ID,
    sourcePubkey: SAMPLE_SEND_SOURCE_PUBKEY,
    destinationAddress: SAMPLE_SEND_DEST_ADDRESS,
    amountZkz: "0.000001",
    referencesOperationId: null,
    expectedArtifactPresent: true,
    expectedArtifactFieldOrder: [...SEND_EXPECTED_FIELD_ORDER],
    sourceLeaseHeld: false,
    splitChainPreimageExists: false,
    approvalConsumed: false,
    ...overrides,
  };
}

/** Chain state where every SEND_EXTERNAL preflight check can pass. */
export function readySendState(attemptId = "attempt-send-1"): FakeSendState {
  void attemptId;
  const state = emptySendState();
  state.sources.set(SAMPLE_SEND_SOURCE_ID, eligibleSendSource());
  state.recipients.set(SAMPLE_SEND_DEST_ADDRESS, eligibleExternalRecipient());
  state.balances.set(SAMPLE_SEND_SOURCE_ID, "1");
  state.operations.set(SAMPLE_SEND_OPERATION_ID, sampleOperationRow());
  state.challenges.set(SAMPLE_SEND_OPERATION_ID, sampleApprovalChallenge());
  state.vaultBackupCapturedAt = "2026-07-27T00:00:00.000Z";
  return state;
}
