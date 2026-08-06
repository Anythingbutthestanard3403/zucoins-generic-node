// Co-sign preimage and completed body persistence for receives.
//
// Covers receive steps 7–11 (external sender partial intake → co-sign → submit) under the
// exact-byte rules. The byte-exact signing rule: the persisted bytes are never reformatted, resequenced,
// or re-serialized after capture.

export const COSIGN_PHASES = [
  "STEP2_PREIMAGE_PERSISTED",
  "STEP2_SIGNATURE_PERSISTED",
] as const;

export type CosignPhase = (typeof COSIGN_PHASES)[number];

// The step-2 preimage: the exact JSON.stringify({inner, step_1_signature}) bytes
// constructed in fixed insertion sequence from the parsed inner and persisted payer
// step-1 signature (step 8–9). These are the exact bytes
// the receiver signer will sign.
export interface CosignPreimage {
  readonly preimage_id: string;
  readonly operation_id: string;
  readonly tenant_id: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly preimage_octets: number;
  readonly inner_preimage_text: string;
  readonly inner_sha256: string;
  readonly step_1_signature: string;
  readonly persisted_at: string;
}

// The completed co-signed body: the full transaction text with both signatures
// (payer step-1 + node step-2), persisted after the receiver signer produces its
// signature over the persisted preimage (step 11).
export interface CosignCompletedBody {
  readonly completed_id: string;
  readonly preimage_id: string;
  readonly operation_id: string;
  readonly tenant_id: string;
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
  readonly completed_transaction_octets: number;
  readonly step_2_signature: string;
  readonly persisted_at: string;
}

export interface CosignPreimageStore {
  insertPreimage(row: CosignPreimage): Promise<void>;
  findPreimageById(preimageId: string): Promise<CosignPreimage | null>;
  findPreimageByOperation(operationId: string): Promise<CosignPreimage | null>;
  insertCompletedBody(row: CosignCompletedBody): Promise<void>;
  findCompletedBodyByPreimageId(preimageId: string): Promise<CosignCompletedBody | null>;
  findCompletedBodyByOperation(operationId: string): Promise<CosignCompletedBody | null>;
}

export type PersistCosignPreimageRequest = {
  readonly preimage_id: string;
  readonly operation_id: string;
  readonly tenant_id: string;
  readonly preimage_text: string;
  readonly inner_preimage_text: string;
  readonly inner_sha256: string;
  readonly step_1_signature: string;
};

export type PersistCosignPreimageResult =
  | { readonly persisted: true; readonly preimage_sha256: string }
  | { readonly persisted: false; readonly reason: CosignPersistRejectionReason; readonly detail: string };

export type PersistCosignCompletedBodyRequest = {
  readonly completed_id: string;
  readonly preimage_id: string;
  readonly operation_id: string;
  readonly tenant_id: string;
  readonly completed_transaction_text: string;
  readonly step_2_signature: string;
};

export type PersistCosignCompletedBodyResult =
  | { readonly persisted: true; readonly completed_transaction_sha256: string }
  | { readonly persisted: false; readonly reason: CosignPersistRejectionReason; readonly detail: string };

export const COSIGN_PERSIST_REJECTION_REASONS = [
  "PREIMAGE_ALREADY_EXISTS",
  "COMPLETED_BODY_ALREADY_EXISTS",
  "PREIMAGE_NOT_FOUND",
] as const;

export type CosignPersistRejectionReason = (typeof COSIGN_PERSIST_REJECTION_REASONS)[number];
