import { z } from "zod";

import {
  ExpectedArtifactSchema,
  MoveInternalOperationSchema,
} from "./common-operation.ts";
import { ClientReferenceSchema, PositiveZkzAmountSchema, UuidSchema } from "./scalars.ts";
import {
  DEFAULT_VERIFICATION_MODE,
  VERIFICATION_MODES,
} from "../operations/verification-mode.contract.ts";

export const MoveInternalRequestSchema = z
  .object({
    source_wallet_id: UuidSchema,
    destination_id: UuidSchema,
    amount_zkz: PositiveZkzAmountSchema,
    client_reference: ClientReferenceSchema.optional(),
    /** Optional; defaults to INDEPENDENT when omitted. */
    verification_mode: z.enum(VERIFICATION_MODES).default(DEFAULT_VERIFICATION_MODE),
  })
  .strict();

export const MoveLeaseStatusSchema = z.enum([
  "WAITING",
  "HELD",
  "RELEASED",
  "PINNED_FOR_ATTENTION",
]);

export const ExecutionPhaseSchema = z.enum([
  "NOT_STARTED",
  "PREIMAGE_PERSISTED",
  "SIGNED_PERSISTED",
  "DELIVERED",
  "SUBMIT_STARTED",
  "SUBMIT_RETURNED",
  "LANDED_VERIFIED",
]);

export const MoveInternalResponseSchema = z
  .object({
    operation: MoveInternalOperationSchema,
    source_wallet_id: UuidSchema,
    destination_id: UuidSchema,
    spawned_from_operation_id: UuidSchema.nullable(),
    lease_status: MoveLeaseStatusSchema,
    execution_phase: ExecutionPhaseSchema,
    expected_artifact: ExpectedArtifactSchema.nullable(),
    source_terminal_observation_id: UuidSchema.nullable(),
    destination_terminal_observation_id: UuidSchema.nullable(),
  })
  .strict();

export type MoveInternalRequest = z.infer<typeof MoveInternalRequestSchema>;
export type MoveInternalResponse = z.infer<typeof MoveInternalResponseSchema>;
