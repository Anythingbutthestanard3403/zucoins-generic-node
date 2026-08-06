import { z } from "zod";

import {
  ExpectedArtifactSchema,
  SendExternalOperationSchema,
} from "./common-operation.ts";
import {
  ClientReferenceSchema,
  DescriptionSchema,
  PositiveZkzAmountSchema,
  UuidSchema,
  WalletPublicKeySchema,
} from "./scalars.ts";

export const SendExternalRequestSchema = z
  .object({
    source_wallet_id: UuidSchema,
    destination_address: WalletPublicKeySchema,
    amount_zkz: PositiveZkzAmountSchema,
    references_operation_id: UuidSchema.optional(),
    client_reference: ClientReferenceSchema.optional(),
    description: DescriptionSchema.optional(),
  })
  .strict();

const SendExternalCreatedOperationSchema = SendExternalOperationSchema.extend({
  state: z.literal("CREATED"),
}).strict();

export const SendExternalResponseSchema = z
  .object({
    operation: SendExternalCreatedOperationSchema,
    source_wallet_id: UuidSchema,
    destination_address: WalletPublicKeySchema,
    references_operation_id: UuidSchema.optional(),
    approval_status: z.literal("PENDING"),
    transfer_code: z.null(),
    transfer_code_sha256: z.null(),
    available_until: z.null(),
    expected_artifact: ExpectedArtifactSchema,
  })
  .strict();

export type SendExternalRequest = z.infer<typeof SendExternalRequestSchema>;
export type SendExternalResponse = z.infer<typeof SendExternalResponseSchema>;
