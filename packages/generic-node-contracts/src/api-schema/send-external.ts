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
import {
  DEFAULT_VERIFICATION_MODE,
  VERIFICATION_MODES,
} from "../operations/verification-mode.contract.ts";

export const SendExternalRequestSchema = z
  .object({
    /**
     * Optional send-capable source. When omitted, the node assigns a free worker
     * (and may MOVE_INTERNAL top-up from an INTERNAL_ONLY hub) before binding the
     * expected artifact — ZTR-1271 / ZTR-1270. Response always echoes the resolved id.
     */
    source_wallet_id: UuidSchema.optional(),
    destination_address: WalletPublicKeySchema,
    amount_zkz: PositiveZkzAmountSchema,
    references_operation_id: UuidSchema.optional(),
    client_reference: ClientReferenceSchema.optional(),
    description: DescriptionSchema.optional(),
    /** Optional; defaults to INDEPENDENT when omitted. */
    verification_mode: z.enum(VERIFICATION_MODES).default(DEFAULT_VERIFICATION_MODE),
  })
  .strict();

/** Wire `approval_status` for create + GET. Create-time is always PENDING. */
export const EXTERNAL_SEND_APPROVAL_STATUSES = [
  "PENDING",
  "APPROVED",
  "CONSUMED",
] as const;

export type ExternalSendApprovalStatus =
  (typeof EXTERNAL_SEND_APPROVAL_STATUSES)[number];

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
