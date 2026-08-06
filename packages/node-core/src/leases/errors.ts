// Typed failures for the persisted lease foundation. Throwing inside a caller
// transaction triggers ROLLBACK so partial acquisition/release never commits.

export type LeaseErrorReason =
  | "WALLET_NOT_FOUND"
  | "WALLET_NOT_ELIGIBLE"
  | "ALREADY_LEASED"
  | "NO_ACTIVE_LEASE"
  | "DUPLICATE_WALLET_ID"
  | "NON_OPERATION_ROLE"
  | "LEASE_OWNER_MISMATCH"
  | "LEASE_OPERATION_MISMATCH"
  | "LEASE_MEMBERSHIP_MISMATCH"
  | "LEASE_GROUP_MISMATCH"
  | "LEASE_EPOCH_MISMATCH"
  | "PROOF_NOT_FOUND"
  | "PROOF_FOREIGN"
  | "PROOF_ALREADY_CONSUMED"
  | "PROOF_UNTRUSTED"
  | "DELETE_NOT_EXACT"
  | "SCHEMA_NOT_READY"
  | "LEGACY_POPULATED"
  | "SIGN_CAPABILITY_MISMATCH"
  | "BATCH_ROLLED_BACK"
  | "GROUP_NOT_TERMINAL"
  | "GROUP_OPERATION_MISSING"
  | "GROUP_ALREADY_RELEASED"
  | "GROUP_OWNERSHIP_MISSING"
  | "TRANSFER_ROLE_INVALID"
  | "TRANSFER_TARGET_NOT_JOINED";

export class LeaseError extends Error {
  readonly reason: LeaseErrorReason;
  readonly walletId: string | undefined;

  constructor(reason: LeaseErrorReason, detail: string, walletId?: string) {
    super(`LeaseError[${reason}]${walletId ? ` wallet=${walletId}` : ""}: ${detail}`);
    this.name = "LeaseError";
    this.reason = reason;
    this.walletId = walletId;
  }
}
