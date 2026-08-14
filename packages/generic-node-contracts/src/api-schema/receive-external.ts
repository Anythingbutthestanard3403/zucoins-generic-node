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
import {
  DEFAULT_VERIFICATION_MODE,
  VERIFICATION_MODES,
} from "../operations/verification-mode.contract.ts";

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
    /** Optional; defaults to INDEPENDENT when omitted. */
    verification_mode: z.enum(VERIFICATION_MODES).default(DEFAULT_VERIFICATION_MODE),
  })
  .strict();

const ReceiveReadyOperationSchema = ReceiveExternalOperationSchema.extend({
  state: z.literal("READY"),
}).strict();

const ReceiveCreatedOperationSchema = ReceiveExternalOperationSchema.extend({
  state: z.literal("CREATED"),
}).strict();

const ReceiveReadyCommonFields = {
  operation: ReceiveReadyOperationSchema,
  receiver_pubkey: WalletPublicKeySchema,
  discriminator: UuidSchema,
  expires_at: Rfc3339MsSchema,
  after_landing: AfterLandingSchema,
  expected_artifact: ExpectedArtifactSchema,
  t0: T0EvidenceSchema,
  subscription_handle: z.string().min(1),
} as const;

/** INDEPENDENT ready: code withheld until arm. */
const ReceiveExternalReadyAwaitingArmSchema = z
  .object({
    ...ReceiveReadyCommonFields,
    code_status: z.literal("AWAITING_ARM"),
    transfer_code: z.null(),
  })
  .strict();

/**
 * NODE_VERIFIED ready (ZTR-1302): code auto-released at ready-commit.
 * Same READY operation state; transfer_code plaintext is present.
 * Also covers post-arm INDEPENDENT GET overlays that surface RELEASED.
 */
const ReceiveExternalReadyReleasedSchema = z
  .object({
    ...ReceiveReadyCommonFields,
    code_status: z.literal("RELEASED"),
    transfer_code: z.string().min(1),
  })
  .strict();

export const ReceiveExternalReadyResponseSchema = z.discriminatedUnion("code_status", [
  ReceiveExternalReadyAwaitingArmSchema,
  ReceiveExternalReadyReleasedSchema,
]);

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
