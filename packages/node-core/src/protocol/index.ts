export interface GatewayRequest {
  readonly rpc: string;
  readonly bodyBytes: Uint8Array;
}

export interface GatewayResponse {
  readonly statusCode: number;
  readonly bodyBytes: Uint8Array;
}

// concern barrel — role-relative wallet projection and operation economic
// predicates. Not the package root src/index.ts; this is protocol/'s own export
// sequence, matching the concern-barrel convention already used by
// packages/generic-node-contracts/src/*/index.ts.
export {
  type SplitChainStateV2,
  type SplitChainInnerV2,
  type SettledSplitChainTransaction,
  computeInnerDigest,
} from "./inner.js";
export {
  type WalletStateProjection,
  type WalletRoleRejectionReason,
  type WalletRoleProjectionResult,
  GENESIS_PROJECTION,
  projectRoleRelativeState,
  isWalletObservationRole,
} from "./wallet-role.js";
export {
  type DeltaRejectionReason,
  type DeltaEvaluation,
  type ReceiveDeltaInput,
  type MoveLegInput,
  type MoveDeltaInput,
  type SendDeltaInput,
  evaluateReceiveDelta,
  evaluateInternalMoveDelta,
  evaluateExternalSendDelta,
} from "./economic-predicates.js";
export {
  type DualBaselineRejectionReason,
  type DualBaselineCaptureResult,
  type DualBaselineCapture,
  type DualBaselineInput,
  captureDualBaselines,
} from "./move-baseline.js";
export {
  type SendBaselineRejectionReason,
  type SendBaselineCaptureResult,
  type SendBaselineCapture,
  type SendBaselineInput,
  captureSendBaselines,
} from "./send-baseline.js";
export {
  type BaselineOperationNoun,
  type SourceBalancePredicateReason,
  type SourceBalancePredicateResult,
  type PositiveAmountPredicateResult,
  type LeaseRoleSide,
  type ActiveLeaseRolePredicateResult,
  evaluateSourceBalanceAgainstAmount,
  evaluatePositiveOperationAmount,
  evaluateActiveLeaseRole,
} from "./baseline-validation.js";
export {
  SEND_REDEMPTION_WINDOW_SECS,
  deriveSendRedemptionExpiryUnixSecs,
  redemptionExpiryAtFromSecs,
} from "./send-redemption.js";
export {
  constructSendInner,
  type ConstructedSendInner,
  type ConstructSendInnerInput,
} from "./send-inner.js";
export {
  constructMoveInner,
  MoveInnerBuildError,
  type ConstructedMoveInner,
  type ConstructMoveInnerInput,
  type MoveInnerBuildFailureReason,
} from "./move-inner.js";
export {
  buildSendTransferCodeText,
  hashTransferCodeText,
  SEND_TRANSFER_CODE_TYPE,
  SEND_TRANSFER_CODE_WIRE_VERSION,
} from "./send-transfer-code.js";
export {
  RECEIVE_MESSAGE_PREFIX,
  RECEIVE_TRANSFER_CODE_TYPE,
  RECEIVE_TRANSFER_CODE_WIRE_VERSION,
  ReceiveTransferCodeError,
  buildReceiveMessage,
  buildReceiveTransferCode,
  hashTransferCodeText as hashReceiveTransferCodeText,
  type BuildReceiveTransferCodeInput,
  type ReceiveTransferCode,
} from "./receive-transfer-code.js";
export {
  AmountOverflowError,
  AmountUnderflowError,
  addZkz,
  compareZkz,
  formatZkz,
  inspectForeignSignedAmount,
  parseObservedZkzBalance,
  parsePositiveZkzAmount,
  parseZkzBalance,
  reemitObservedZkzCanonical,
  subtractZkz,
  type CanonicalZkz,
  type ForeignAmountAnomaly,
  type ForeignSignedAmountInspection,
  type ObservedZkzBalance,
  type PositiveZkzAmount,
  type ZkzBalance,
} from "./amounts.js";
export {
  SPLITCHAIN_FUTURE_TIME_CEILING_SECS,
  assertReceiveTtlBounds,
  clampReceiveTtlSecs,
  deriveExpiryUnixTimeSecs,
  type ReceiveTtlBounds,
} from "./receive-ttl.js";
export {
  SPLIT_CHAIN_INNER_OPTIONAL_FIELDS,
  SPLIT_CHAIN_INNER_REQUIRED_FIELDS,
  narrowSplitChainInner,
  type InnerShapeNarrowing,
  type InnerShapeRejection,
  type SplitChainInnerParseInput,
} from "./inner-shape.js";
export * from "./scalars.js";
export { ed25519PublicKeyObject, verifyRawEd25519 } from "./ed25519-verify.js";
export * from "./suite/index.js";
export * from "./implementer-events/index.js";
export {
  TransactionConstructionError,
  buildSettledSplitChainTransactionV2,
  buildSplitChainInnerV2,
  buildSplitChainPartialV2,
  type BuildSplitChainInnerV2Input,
  type SettledSplitChainTransactionV2,
  type SettledSplitChainTransactionV2Projection,
  type SplitChainInnerV2Capability,
  type SplitChainInnerV2Projection,
  type SplitChainPartialV2Capability,
  type SplitChainPartialV2Projection,
  type SplitChainStateV2Projection,
  type TransactionConstructionFailureReason,
  type WalletBaselineV2Capability,
} from "./transactions.js";

