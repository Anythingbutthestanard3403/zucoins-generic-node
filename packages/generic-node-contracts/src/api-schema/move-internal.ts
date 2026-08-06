import { z } from "zod";

import {
  ExpectedArtifactSchema,
  MoveInternalOperationSchema,
} from "./common-operation.ts";
import { PositiveZkzAmountSchema, UuidSchema } from "./scalars.ts";

export const MoveInternalRequestSchema = z
  .object({
    source_wallet_id: UuidSchema,
    destination_id: UuidSchema,
    amount_zkz: PositiveZkzAmountSchema,
  })
  .strict();

const MoveInternalCreatedOperationSchema = MoveInternalOperationSchema.extend({
  state: z.literal("CREATED"),
}).strict();

export const MoveInternalResponseSchema = z
  .object({
    operation: MoveInternalCreatedOperationSchema,
    source_wallet_id: UuidSchema,
    destination_id: UuidSchema,
    spawned_from_operation_id: z.null(),
    lease_status: z.literal("WAITING"),
    expected_artifact: ExpectedArtifactSchema,
  })
  .strict();

export type MoveInternalRequest = z.infer<typeof MoveInternalRequestSchema>;
export type MoveInternalResponse = z.infer<typeof MoveInternalResponseSchema>;
