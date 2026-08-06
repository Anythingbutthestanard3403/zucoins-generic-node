import { z } from "zod";

import { ATTENTION_REASONS } from "../operations/events.contract.ts";
import {
  MOVE_INTERNAL_STATES,
  RECEIVE_EXTERNAL_STATES,
  SEND_EXTERNAL_STATES,
} from "../operations/states.contract.ts";
import {
  Ed25519SignatureSchema,
  PositiveZkzAmountSchema,
  PreviousStateSignatureSchema,
  Rfc3339MsSchema,
  Sha256HexSchema,
  UuidSchema,
  ZkzBalanceSchema,
} from "./scalars.ts";

const CommonOperationFields = {
  operation_id: UuidSchema,
  amount_zkz: PositiveZkzAmountSchema,
  row_version: z.number().int().positive(),
  attention_required: z.boolean(),
  attention_reason: z.enum(ATTENTION_REASONS).nullable(),
  created_at: Rfc3339MsSchema,
  updated_at: Rfc3339MsSchema,
  terminal_at: Rfc3339MsSchema.nullable(),
  verification_material_available_until: Rfc3339MsSchema.nullable(),
} as const;

export const ReceiveExternalOperationSchema = z
  .object({
    operation_id: CommonOperationFields.operation_id,
    operation_type: z.literal("RECEIVE_EXTERNAL"),
    state: z.enum(RECEIVE_EXTERNAL_STATES),
    amount_zkz: CommonOperationFields.amount_zkz,
    row_version: CommonOperationFields.row_version,
    attention_required: CommonOperationFields.attention_required,
    attention_reason: CommonOperationFields.attention_reason,
    created_at: CommonOperationFields.created_at,
    updated_at: CommonOperationFields.updated_at,
    terminal_at: CommonOperationFields.terminal_at,
    verification_material_available_until:
      CommonOperationFields.verification_material_available_until,
  })
  .strict();

export const MoveInternalOperationSchema = z
  .object({
    operation_id: CommonOperationFields.operation_id,
    operation_type: z.literal("MOVE_INTERNAL"),
    state: z.enum(MOVE_INTERNAL_STATES),
    amount_zkz: CommonOperationFields.amount_zkz,
    row_version: CommonOperationFields.row_version,
    attention_required: CommonOperationFields.attention_required,
    attention_reason: CommonOperationFields.attention_reason,
    created_at: CommonOperationFields.created_at,
    updated_at: CommonOperationFields.updated_at,
    terminal_at: CommonOperationFields.terminal_at,
    verification_material_available_until:
      CommonOperationFields.verification_material_available_until,
  })
  .strict();

export const SendExternalOperationSchema = z
  .object({
    operation_id: CommonOperationFields.operation_id,
    operation_type: z.literal("SEND_EXTERNAL"),
    state: z.enum(SEND_EXTERNAL_STATES),
    amount_zkz: CommonOperationFields.amount_zkz,
    row_version: CommonOperationFields.row_version,
    attention_required: CommonOperationFields.attention_required,
    attention_reason: CommonOperationFields.attention_reason,
    created_at: CommonOperationFields.created_at,
    updated_at: CommonOperationFields.updated_at,
    terminal_at: CommonOperationFields.terminal_at,
    verification_material_available_until:
      CommonOperationFields.verification_material_available_until,
  })
  .strict();

export const ExpectedArtifactSchema = z
  .object({
    key_id: UuidSchema,
    preimage_text: z.string().min(1),
    preimage_sha256: Sha256HexSchema,
    signature: Ed25519SignatureSchema,
  })
  .strict();

export const T0EvidenceSchema = z
  .object({
    observation_id: UuidSchema,
    projection: z
      .object({
        s: PreviousStateSignatureSchema,
        p: PreviousStateSignatureSchema,
        b_zkz: ZkzBalanceSchema,
      })
      .strict(),
  })
  .strict();
