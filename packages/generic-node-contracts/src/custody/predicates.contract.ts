/**
 * These values freeze custody classification policy only; callers
 * provide authoritative wallet/destination facts, never precomputed eligibility booleans.
 */

export const WALLET_KEY_ORIGINS = ["node_generated", "imported"] as const;
export type WalletKeyOrigin = (typeof WALLET_KEY_ORIGINS)[number];

export const DESTINATION_STATES = ["PENDING", "BLESSED", "RETIRED", "WORKER"] as const;
export type DestinationState = (typeof DESTINATION_STATES)[number];

export const WALLET_STATES = ["AVAILABLE", "PINNED", "QUARANTINED", "RETIRED"] as const;
export type WalletState = (typeof WALLET_STATES)[number];

export const INTERNAL_CUSTODY_CONJUNCTS = {
  keyOrigin: "node_generated",
  destinationState: "BLESSED",
} as const;

export const AUTOMATIC_SINK_CONJUNCTS = {
  requiresInternalCustody: true,
  requiresValidRecoveryVerifiedAt: true,
  allowedWalletStates: ["AVAILABLE", "PINNED"],
} as const;

/** Node-owned send-worker sink (scaler mint). Not internal custody; no blessing, no recovery. */
export const WORKER_SINK_CONJUNCTS = {
  keyOrigin: "node_generated",
  destinationState: "WORKER",
  requiresValidRecoveryVerifiedAt: false,
  allowedWalletStates: ["AVAILABLE", "PINNED"],
} as const;

/** Composition top-up may land on an automatic sink or a worker sink. */
export const COMPOSITION_SINK_STATES = ["BLESSED", "WORKER"] as const;

/** Evidence requirements are facts that ceremonies must establish, not caller switches. */
export const CUSTODY_EVIDENCE_REQUIREMENTS = {
  origin: "IMMUTABLE_WALLETS_KEY_ORIGIN",
  blessing:
    "DESTINATION_BLESSING_ARTIFACT_BINDS_PUBLIC_KEY_WALLET_ID_NODE_ID_NONCE_ISSUED_AT_EXPIRES_AT",
  recovery:
    "AUDITED_EXPORT_MATCHES_WALLET_PUBLIC_KEY_AND_RECORDS_EXACT_EXPORT_DIGEST",
} as const;

/** Binding obligations describe structural enforcement independently of evidence. */
export const CUSTODY_BINDING_OBLIGATIONS = {
  immutableWalletFields: ["key_origin", "node_id", "public_key"],
  importedDestinationInsert: "REJECT",
  recoveryFields: "SET_TOGETHER_AFTER_SUCCESSFUL_AUDITED_EXPORT_AND_NEVER_CLEAR",
  selectionRecheck: "RECHECK_ALL_CONJUNCTS_AT_EXECUTION_TIME",
  failClosedUnknownMalformedOrFutureValues: true,
  recoveryNeverUpgradesOrigin: true,
} as const;

export const CUSTODY_DENIAL_REASONS = [
  "INVALID_KEY_ORIGIN",
  "KEY_ORIGIN_NOT_NODE_GENERATED",
  "INVALID_DESTINATION_STATE",
  "DESTINATION_NOT_BLESSED",
  "DESTINATION_NOT_WORKER",
  "INVALID_RECOVERY_VERIFIED_AT",
  "INVALID_WALLET_STATE",
  "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE",
] as const;

export type CustodyDenialReason = (typeof CUSTODY_DENIAL_REASONS)[number];
