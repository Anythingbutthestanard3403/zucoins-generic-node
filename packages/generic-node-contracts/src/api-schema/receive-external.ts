import { z } from "zod";

import {
  ExpectedArtifactSchema,
  ReceiveExternalOperationSchema,
  T0EvidenceSchema,
} from "./common-operation.ts";
import {
  AnchorSchema,
  PositiveZkzAmountSchema,
  Rfc3339MsSchema,
  UuidSchema,
  WalletPublicKeySchema,
} from "./scalars.ts";

const HoldAfterLandingSchema = z
  .object({
    kind: z.literal("HOLD"),
    destination_id: z.null(),
  })
  .strict();

const InternalMoveAfterLandingSchema = z
  .object({
    kind: z.literal("INTERNAL_MOVE"),
    destination_id: UuidSchema,
  })
  .strict();

export const AfterLandingSchema = z.discriminatedUnion("kind", [
  HoldAfterLandingSchema,
  InternalMoveAfterLandingSchema,
]);

export const ReceiveExternalRequestSchema = z
  .object({
    amount_zkz: PositiveZkzAmountSchema,
    anchor: AnchorSchema,
    expires_in_seconds: z.number().int().positive().safe().optional(),
    after_landing: AfterLandingSchema,
  })
  .strict();

const ReceiveReadyOperationSchema = ReceiveExternalOperationSchema.extend({
  state: z.literal("READY"),
}).strict();

const ReceiveCreatedOperationSchema = ReceiveExternalOperationSchema.extend({
  state: z.literal("CREATED"),
}).strict();

export const ReceiveExternalReadyResponseSchema = z
  .object({
    operation: ReceiveReadyOperationSchema,
    receiver_pubkey: WalletPublicKeySchema,
    discriminator: UuidSchema,
    expires_at: Rfc3339MsSchema,
    after_landing: AfterLandingSchema,
    code_status: z.literal("AWAITING_ARM"),
    transfer_code: z.null(),
    expected_artifact: ExpectedArtifactSchema,
    t0: T0EvidenceSchema,
    subscription_handle: z.string().min(1),
  })
  .strict();

export const ReceiveExternalQueuedResponseSchema = z
  .object({
    operation: ReceiveCreatedOperationSchema,
    receiver_pubkey: z.null(),
    discriminator: UuidSchema,
    expires_at: z.null(),
    after_landing: AfterLandingSchema,
    code_status: z.literal("NOT_CREATED"),
    transfer_code: z.null(),
    expected_artifact: z.null(),
    t0: z.null(),
    subscription_handle: z.string().min(1),
  })
  .strict();

export const ReceiveExternalResponseSchema = z.union([
  ReceiveExternalReadyResponseSchema,
  ReceiveExternalQueuedResponseSchema,
]);

export type ReceiveExternalRequest = z.infer<typeof ReceiveExternalRequestSchema>;
export type ReceiveExternalResponse = z.infer<typeof ReceiveExternalResponseSchema>;
