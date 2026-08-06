import { type ReconcileClassificationKind } from "../protocol/reconcile/index.js";

export interface WorkerClaim {
  readonly claimId: string;
  readonly workerId: string;
  readonly walletId: string;
  readonly acquiredAt: number;
  readonly expiresAt: number;
  readonly heartbeatAt: number;
  readonly generation: number;
}

export type ClaimAcquireResult =
  | { readonly outcome: "ACQUIRED"; readonly claim: WorkerClaim }
  | { readonly outcome: "HELD_BY_OTHER"; readonly holder: string; readonly expiresAt: number }
  | { readonly outcome: "CAS_CONFLICT" };

export type ClaimStealResult =
  | { readonly outcome: "STOLEN"; readonly claim: WorkerClaim }
  | { readonly outcome: "NOT_EXPIRED"; readonly expiresAt: number }
  | { readonly outcome: "CAS_CONFLICT" };

export interface SchedulerCursor {
  readonly walletId: string;
  readonly streamKind: StreamKind;
  readonly position: number;
  readonly updatedAt: number;
}

export const STREAM_KINDS = [
  "SUBMITTED",
  "AWAITING",
  "ATTENTION",
  "RECOVERY",
] as const;
export type StreamKind = (typeof STREAM_KINDS)[number];

export interface ReconcileVerdict {
  readonly operationId: string;
  readonly walletId: string;
  readonly classification: ReconcileClassificationKind;
  readonly expectedRowVersion: number;
  readonly appliedAt: number | null;
}

export type VerdictApplyResult =
  | { readonly outcome: "APPLIED"; readonly newRowVersion: number }
  | { readonly outcome: "ALREADY_APPLIED" }
  | { readonly outcome: "CAS_CONFLICT"; readonly actualRowVersion: number };

export interface AdmissionEntry {
  readonly operationId: string;
  readonly walletId: string | null;
  readonly createdAt: number;
  readonly status: "QUEUED" | "PROMOTED" | "EXPIRED";
}

export type AdmissionPromoteResult =
  | { readonly outcome: "PROMOTED"; readonly operationId: string; readonly walletId: string }
  | { readonly outcome: "NO_CAPACITY" }
  | { readonly outcome: "QUEUE_EMPTY" };

export type AdmissionExpireResult =
  | { readonly outcome: "EXPIRED"; readonly operationId: string }
  | { readonly outcome: "NOT_EXPIRED"; readonly remainingMs: number }
  | { readonly outcome: "ALREADY_TERMINAL" };

export interface DeliveryRecord {
  readonly seq: number;
  readonly eventId: string;
  readonly operationId: string;
  readonly dispatchedAt: number | null;
}

export type DeliveryDispatchResult =
  | { readonly outcome: "DISPATCHED"; readonly seq: number }
  | { readonly outcome: "ALREADY_DISPATCHED"; readonly seq: number }
  | { readonly outcome: "GAP_DETECTED"; readonly expectedSeq: number; readonly actualSeq: number };

export interface WorkerPoolConfig {
  readonly claimTtlMs: number;
  readonly heartbeatIntervalMs: number;
  readonly stealGraceMs: number;
  readonly receiveQueueCap: number;
  readonly receiveQueueMaxWaitMs: number;
  readonly poolCapTotal: number;
  readonly poolTargetAvailable: number;
  readonly mintBatchLimit: number;
}

export const DEFAULT_POOL_CONFIG: WorkerPoolConfig = {
  claimTtlMs: 30_000,
  heartbeatIntervalMs: 10_000,
  stealGraceMs: 5_000,
  receiveQueueCap: 100,
  receiveQueueMaxWaitMs: 300_000,
  poolCapTotal: 500,
  poolTargetAvailable: 50,
  mintBatchLimit: 10,
};
