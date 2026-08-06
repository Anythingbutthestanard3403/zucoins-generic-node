// In-memory fakes for MOVE_INTERNAL preflight tests. No network, no filesystem, no keys.

import {
  type ActiveLeaseRow,
  type MovePreflightProbe,
  type MoveWalletFacts,
} from "./move-preflight.js";
import { type Amount, type DualControlAuthorization } from "./types.js";

export interface FakeMoveState {
  wallets: Map<string, MoveWalletFacts>;
  leases: Map<string, ActiveLeaseRow[]>;
  balances: Map<string, Amount>;
  /** attemptIds for which T0 capture is declared fresh. */
  freshT0Attempts: Set<string>;
}

export function emptyMoveState(): FakeMoveState {
  return {
    wallets: new Map(),
    leases: new Map(),
    balances: new Map(),
    freshT0Attempts: new Set(),
  };
}

export function fakeMoveProbe(state: FakeMoveState): MovePreflightProbe {
  return {
    loadWallet: async (walletId) => state.wallets.get(walletId) ?? null,
    activeLeases: async (walletId) => state.leases.get(walletId) ?? [],
    availableBalance: async (walletId) => state.balances.get(walletId) ?? "0",
    t0CaptureWillBeFresh: async (attemptId) => state.freshT0Attempts.has(attemptId),
  };
}

export function sampleAuth(
  attemptId = "attempt-move-1",
  overrides: Partial<DualControlAuthorization> = {},
): DualControlAuthorization {
  return {
    attemptId,
    attestationId: "dual-control-attestation-1",
    recordedAt: "2026-07-27T00:00:00.000Z",
    ...overrides,
  };
}

/** Two distinct UUIDs with known sort order (a < b). */
export const SAMPLE_SOURCE_ID = "11111111-1111-4111-8111-111111111111";
export const SAMPLE_DEST_ID = "22222222-2222-4222-8222-222222222222";

export function eligibleSource(
  walletId = SAMPLE_SOURCE_ID,
  overrides: Partial<MoveWalletFacts> = {},
): MoveWalletFacts {
  return {
    walletId,
    keyOrigin: "node_generated",
    walletState: "AVAILABLE",
    // Source need not be blessed or recovery-verified.
    destinationState: null,
    recoveryVerifiedAt: null,
    nodeControlled: true,
    backupPresent: true,
    ...overrides,
  };
}

export function eligibleDestination(
  walletId = SAMPLE_DEST_ID,
  overrides: Partial<MoveWalletFacts> = {},
): MoveWalletFacts {
  return {
    walletId,
    keyOrigin: "node_generated",
    walletState: "AVAILABLE",
    destinationState: "BLESSED",
    recoveryVerifiedAt: "2026-07-01T12:00:00.000Z",
    nodeControlled: true,
    backupPresent: true,
    ...overrides,
  };
}

/** Chain state where every preflight check can pass. */
export function readyMoveState(attemptId = "attempt-move-1"): FakeMoveState {
  const state = emptyMoveState();
  state.wallets.set(SAMPLE_SOURCE_ID, eligibleSource());
  state.wallets.set(SAMPLE_DEST_ID, eligibleDestination());
  state.balances.set(SAMPLE_SOURCE_ID, "1");
  state.balances.set(SAMPLE_DEST_ID, "0");
  state.freshT0Attempts.add(attemptId);
  return state;
}
