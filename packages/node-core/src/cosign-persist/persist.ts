import { createHash } from "node:crypto";
import type {
  CosignCompletedBody,
  CosignPersistRejectionReason,
  CosignPreimage,
  CosignPreimageStore,
  PersistCosignCompletedBodyRequest,
  PersistCosignCompletedBodyResult,
  PersistCosignPreimageRequest,
  PersistCosignPreimageResult,
} from "./types.js";

// Insert-only co-sign persistence for receives (steps 9–11).
// The byte-exact signing rule: preimage_text and completed_transaction_text are stored byte-exact as
// received; they are never reformatted, resequenced, or re-serialized after capture.

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function byteLength(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

export async function persistCosignPreimage(
  store: CosignPreimageStore,
  request: PersistCosignPreimageRequest,
): Promise<PersistCosignPreimageResult> {
  const existing = await store.findPreimageByOperation(request.operation_id);
  if (existing !== null) {
    return {
      persisted: false,
      reason: "PREIMAGE_ALREADY_EXISTS" satisfies CosignPersistRejectionReason,
      detail: `operation ${request.operation_id} already has a persisted co-sign preimage`,
    };
  }

  const preimage_sha256 = sha256Hex(request.preimage_text);

  const row: CosignPreimage = {
    preimage_id: request.preimage_id,
    operation_id: request.operation_id,
    tenant_id: request.tenant_id,
    preimage_text: request.preimage_text,
    preimage_sha256,
    preimage_octets: byteLength(request.preimage_text),
    inner_preimage_text: request.inner_preimage_text,
    inner_sha256: request.inner_sha256,
    step_1_signature: request.step_1_signature,
    persisted_at: new Date().toISOString(),
  };

  await store.insertPreimage(row);
  return { persisted: true, preimage_sha256 };
}

export async function persistCosignCompletedBody(
  store: CosignPreimageStore,
  request: PersistCosignCompletedBodyRequest,
): Promise<PersistCosignCompletedBodyResult> {
  const preimage = await store.findPreimageById(request.preimage_id);
  if (preimage === null) {
    return {
      persisted: false,
      reason: "PREIMAGE_NOT_FOUND" satisfies CosignPersistRejectionReason,
      detail: `preimage ${request.preimage_id} not found; cannot persist completed body without a linked preimage`,
    };
  }

  const existingCompleted = await store.findCompletedBodyByPreimageId(request.preimage_id);
  if (existingCompleted !== null) {
    return {
      persisted: false,
      reason: "COMPLETED_BODY_ALREADY_EXISTS" satisfies CosignPersistRejectionReason,
      detail: `preimage ${request.preimage_id} already has a persisted completed body`,
    };
  }

  const completed_transaction_sha256 = sha256Hex(request.completed_transaction_text);

  const row: CosignCompletedBody = {
    completed_id: request.completed_id,
    preimage_id: request.preimage_id,
    operation_id: request.operation_id,
    tenant_id: request.tenant_id,
    completed_transaction_text: request.completed_transaction_text,
    completed_transaction_sha256,
    completed_transaction_octets: byteLength(request.completed_transaction_text),
    step_2_signature: request.step_2_signature,
    persisted_at: new Date().toISOString(),
  };

  await store.insertCompletedBody(row);
  return { persisted: true, completed_transaction_sha256 };
}
