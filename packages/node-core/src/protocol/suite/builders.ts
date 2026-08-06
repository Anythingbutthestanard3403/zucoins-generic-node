// Typed builders for every Appendix – suite-tuple purpose. Each
// builder is a thin, purpose-specific facade over the one canonical constructor mandated by spec
// (`serializeSuiteTuple`): it takes a TS-checked input (every field except
// the `purpose`/`canonical_version` header, which the builder supplies), and returns exactly the
// `{preimageText, preimageBytes, sha256}` triple requires — never an intermediate object a
// caller could re-stringify. Field validation, field sequencing, and byte assembly all happen inside
// `serializeSuiteTuple`; this module adds nothing to that trust boundary, only a typed name per
// purpose so call sites cannot pass the wrong fields to the wrong tuple.
//
// "Proof manifest" tuples are intentionally absent from this module: Appendix, – and
// this module's scope ("builders, parsers, and verifiers for artifacts,
// approvals, blessings, device enrollment, reporting requests, events, and fingerprints") do not
// define one. The only "proof manifest" reference in the backlog is title ("Implement
// generic operation verification and proof manifests"), later work that depends on — not
// a purpose this module is scoped to build.

import type { ObservedZkzBalance, PositiveZkzAmount, ZkzBalance } from "../amounts.js";
import type {
  Ed25519Signature,
  ExpiryUnixTimeSecs,
  PreviousStateSignature,
  Sha256Hex,
  Uuid,
  WalletPublicKey,
} from "../scalars.js";
import type { AfterLanding, NodeEventType, SourceSelector, WalletStateKind } from "./composites.js";
import { serializeSuiteTuple, type SuiteTuplePreimage } from "./serialize.js";

export interface ReceiveExpectedInput {
  readonly node_id: Uuid;
  readonly implementer_id: Uuid;
  readonly operation_id: Uuid;
  readonly receiver_wallet_id: Uuid;
  readonly receiver_pubkey: WalletPublicKey;
  readonly amount_zkz: PositiveZkzAmount;
  readonly discriminator: Uuid;
  readonly anchor: string;
  readonly receiver_t0_fingerprint: Sha256Hex;
  readonly expiry_unix_time_secs: ExpiryUnixTimeSecs | null;
  readonly after_landing: AfterLanding;
  readonly transfer_code_sha256: Sha256Hex;
}

export function buildReceiveExpectedArtifact(input: ReceiveExpectedInput): SuiteTuplePreimage {
  return serializeSuiteTuple("zp-receive-expected-v1", { purpose: "zp-receive-expected-v1", canonical_version: 1, ...input });
}

export interface MoveInternalExpectedInput {
  readonly node_id: Uuid;
  readonly implementer_id: Uuid;
  readonly operation_id: Uuid;
  readonly source_wallet_id: Uuid;
  readonly source_pubkey: WalletPublicKey;
  readonly destination_id: Uuid;
  readonly destination_wallet_id: Uuid;
  readonly destination_pubkey: WalletPublicKey;
  readonly amount_zkz: PositiveZkzAmount;
  readonly spawned_from_operation_id: Uuid | null;
  readonly references_operation_id: Uuid | null;
}

export function buildMoveInternalExpectedArtifact(input: MoveInternalExpectedInput): SuiteTuplePreimage {
  return serializeSuiteTuple("zp-move-internal-expected-v1", { purpose: "zp-move-internal-expected-v1", canonical_version: 1, ...input });
}

export interface SendExternalExpectedInput {
  readonly node_id: Uuid;
  readonly implementer_id: Uuid;
  readonly operation_id: Uuid;
  readonly source_selector: SourceSelector;
  readonly source_pubkey: WalletPublicKey;
  readonly destination_address: WalletPublicKey;
  readonly amount_zkz: PositiveZkzAmount;
  readonly references_operation_id: Uuid | null;
}

export function buildSendExternalExpectedArtifact(input: SendExternalExpectedInput): SuiteTuplePreimage {
  return serializeSuiteTuple("zp-send-external-expected-v1", { purpose: "zp-send-external-expected-v1", canonical_version: 1, ...input });
}

export interface SendExternalApprovalInput {
  readonly node_id: Uuid;
  readonly operation_id: Uuid;
  readonly source_selector: SourceSelector;
  readonly source_pubkey: WalletPublicKey;
  readonly destination_address: WalletPublicKey;
  readonly amount_zkz: PositiveZkzAmount;
  readonly references_operation_id: Uuid | null;
  readonly nonce: Uuid;
  readonly issued_at: string;
  readonly expires_at: string;
}

export function buildSendExternalApproval(input: SendExternalApprovalInput): SuiteTuplePreimage {
  return serializeSuiteTuple("zp-send-external-approval-v1", { purpose: "zp-send-external-approval-v1", canonical_version: 1, ...input });
}

export interface DestinationBlessInput {
  readonly node_id: Uuid;
  readonly destination_id: Uuid;
  readonly wallet_id: Uuid;
  readonly wallet_pubkey: WalletPublicKey;
  readonly nonce: Uuid;
  readonly issued_at: string;
  readonly expires_at: string;
}

export function buildDestinationBless(input: DestinationBlessInput): SuiteTuplePreimage {
  return serializeSuiteTuple("zp-destination-bless-v1", { purpose: "zp-destination-bless-v1", canonical_version: 1, ...input });
}

export interface DeviceEnrolInput {
  readonly node_id: Uuid;
  readonly new_device_key_id: Uuid;
  readonly new_device_public_key: WalletPublicKey;
  readonly label: string;
  readonly nonce: Uuid;
  readonly issued_at: string;
  readonly expires_at: string;
}

export function buildDeviceEnrol(input: DeviceEnrolInput): SuiteTuplePreimage {
  return serializeSuiteTuple("zp-device-enrol-v1", { purpose: "zp-device-enrol-v1", canonical_version: 1, ...input });
}

export interface ReportRequestInput {
  readonly node_id: Uuid;
  readonly implementer_id: Uuid;
  readonly method: string;
  readonly path: string;
  readonly body_sha256: Sha256Hex;
  readonly nonce: Uuid;
  readonly issued_at: string;
  readonly expires_at: string;
}

export function buildReportRequest(input: ReportRequestInput): SuiteTuplePreimage {
  return serializeSuiteTuple("zp-report-request-v1", { purpose: "zp-report-request-v1", canonical_version: 1, ...input });
}

export interface ReportingRegisterInput {
  readonly node_id: Uuid;
  readonly implementer_id: Uuid;
  readonly new_reporting_key_id: Uuid;
  readonly new_reporting_public_key: WalletPublicKey;
  readonly supersedes_key_id: Uuid | null;
  readonly nonce: Uuid;
  readonly issued_at: string;
  readonly expires_at: string;
}

export function buildReportingRegister(input: ReportingRegisterInput): SuiteTuplePreimage {
  return serializeSuiteTuple("zp-reporting-register-v1", { purpose: "zp-reporting-register-v1", canonical_version: 1, ...input });
}

export interface NodeEventInput {
  readonly node_id: Uuid;
  readonly event_id: Uuid;
  readonly seq: string;
  readonly operation_id: Uuid | null;
  readonly wallet_id: Uuid | null;
  readonly event_type: NodeEventType;
  readonly data_sha256: Sha256Hex;
  readonly previous_event_hash: Sha256Hex | null;
  readonly created_at: string;
}

export function buildNodeEvent(input: NodeEventInput): SuiteTuplePreimage {
  return serializeSuiteTuple("zp-node-event-v1", { purpose: "zp-node-event-v1", canonical_version: 1, ...input });
}

export interface WalletHeadFingerprintInput {
  readonly wallet_public_key: WalletPublicKey;
  readonly state_kind: WalletStateKind;
  readonly s_signature: PreviousStateSignature;
  readonly p_signature: PreviousStateSignature;
  // Observed foreign-preserving balance (A.7 / Byte-exact). Canonical ZkzBalance is a
  // subset (shortest form still grammar-valid); non-canonical heads keep exact text.
  readonly b_amount: ObservedZkzBalance | ZkzBalance;
  readonly inner_sha256: Sha256Hex | null;
  readonly step_1_signature: Ed25519Signature | null;
  readonly step_2_signature: Ed25519Signature | null;
}

export function buildWalletHeadFingerprint(input: WalletHeadFingerprintInput): SuiteTuplePreimage {
  return serializeSuiteTuple("zp-wallet-head-fingerprint-v1", { purpose: "zp-wallet-head-fingerprint-v1", canonical_version: 1, ...input });
}
