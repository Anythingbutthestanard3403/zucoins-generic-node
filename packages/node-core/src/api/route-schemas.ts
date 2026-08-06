// Per-route request/response Zod schemas derived from the frozen
// ROUTE_POLICIES manifest and. Each POST body schema
// uses.strict to reject unknown fields ("Unknown request properties are
// rejected with 400 unknown_field"). GET query schemas validate query params.
//
// Canonical: phantom 403 collapsed to 401 (no 403), canonical ZKZ amount contract (PositiveZkzAmount < 100000000).

import { z } from "zod";
import { SPLITCHAIN_FUTURE_TIME_CEILING_SECS } from "../protocol/receive-ttl.js";
import {
  UuidSchema,
  PositiveZkzAmountSchema,
  WalletPublicKeySchema,
  AnchorSchema,
  Sha256HexSchema,
  DecimalSeqStringSchema,
} from "./scalars.js";
import { NeedsAttentionQuerySchema } from "./recovery-inspection.js";
import { OPERATOR_RECOVERY_ACTIONS } from "../operator/recovery-inspection.js";

// --- RECEIVE_EXTERNAL --

const AfterLandingHold = z.object({
  kind: z.literal("HOLD"),
  destination_id: z.null(),
}).strict();

const AfterLandingInternalMove = z.object({
  kind: z.literal("INTERNAL_MOVE"),
  destination_id: UuidSchema,
}).strict();

const AfterLanding = z.discriminatedUnion("kind", [
  AfterLandingHold,
  AfterLandingInternalMove,
]);

// `expires_in_seconds` is CLAMPED by node policy, not rejected, so this
// boundary schema must not impose a policy ceiling of its own — it bounds only what
// no policy could ever honour (the SplitChain future-time ceiling). The
// in-policy clamp is protocol/receive-ttl.ts `clampReceiveTtlSecs`, applied downstream.
export const CreateReceiveBody = z.object({
  amount_zkz: PositiveZkzAmountSchema,
  anchor: AnchorSchema,
  expires_in_seconds: z
    .number()
    .int()
    .min(1)
    .max(SPLITCHAIN_FUTURE_TIME_CEILING_SECS)
    .optional(),
  after_landing: AfterLanding,
}).strict();

// --- MOVE_INTERNAL --

export const CreateInternalMoveBody = z.object({
  source_wallet_id: UuidSchema,
  destination_id: UuidSchema,
  amount_zkz: PositiveZkzAmountSchema,
}).strict();

// --- SEND_EXTERNAL --

export const CreateExternalSendBody = z.object({
  source_wallet_id: UuidSchema,
  destination_address: WalletPublicKeySchema,
  amount_zkz: PositiveZkzAmountSchema,
  references_operation_id: UuidSchema.optional(),
  client_reference: z.string().max(256).optional(),
  description: z.string().max(512).optional(),
}).strict();

// --- Destinations --

export const CreateDestinationBody = z.object({
  label: z.string().min(1).max(256),
}).strict();

export const ListDestinationsQuery = z.object({
  state: z.enum(["PENDING", "BLESSED", "RETIRED"]).optional(),
  after: UuidSchema.optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
}).strict();

// --- Events, snapshot --

export const ListEventsQuery = z.object({
  after_implementer_seq: DecimalSeqStringSchema.optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
  wait_seconds: z.coerce.number().int().min(0).max(30).optional(),
}).strict();

export const EventStreamQuery = z.object({
  after_implementer_seq: DecimalSeqStringSchema.optional(),
}).strict();

// --- Arm and verification barriers --

const T0Projection = z.object({
  s: z.string(),
  p: z.string(),
  b_zkz: z.string(),
}).strict();

const T0Evidence = z.object({
  observation_id: UuidSchema,
  projection: T0Projection,
}).strict();

export const ArmBody = z.object({
  expected_row_version: z.number().int().min(1),
  t0: T0Evidence,
  opened_cursor: DecimalSeqStringSchema,
}).strict();

const LandingProof = z.object({
  classification: z.enum(["EXPECTED_AT_HEAD", "EXPECTED_ANCESTOR"]),
  fresh_head_step_2_signature: z.string(),
  fresh_head_transaction_sha256: Sha256HexSchema,
  path_manifest_sha256: Sha256HexSchema,
}).strict();

const WalletEvidence = z.object({
  wallet_id: UuidSchema,
  role: z.enum(["RECEIVER", "SOURCE", "DESTINATION"]),
  t0: T0Evidence,
  terminal: T0Evidence,
  landing_proof: LandingProof,
}).strict();

export const VerificationCompleteBody = z.object({
  expected_row_version: z.number().int().min(1),
  consumed_cursor: DecimalSeqStringSchema,
  verdict: z.enum(["VERIFIED", "REJECTED", "INDETERMINATE"]),
  wallet_evidence: z.array(WalletEvidence).min(1),
}).strict();

// --- Operator endpoints --

export const ApproveBody = z.object({
  challenge_nonce: UuidSchema,
  expected_row_version: z.number().int().min(1),
  preimage_sha256: Sha256HexSchema,
  device_key_id: UuidSchema.nullable(),
  device_signature: z.string().nullable(),
}).strict();

export const RejectBody = z.object({
  expected_row_version: z.number().int().min(1),
  reason: z.string().max(512),
}).strict();

// closed action enum — free strings and tokens fail at parse (400).
// recovery_nonce is required on the wire (body); prior optional was a freeze stub.
export const RecoveryActionsBody = z
  .object({
    action: z.enum(OPERATOR_RECOVERY_ACTIONS),
    expected_row_version: z.number().int().min(1),
    recovery_nonce: z.string().uuid(),
    proof_id: z.string().uuid().nullable().optional(),
    operator_note: z.string().max(1024).optional(),
  })
  .strict();

export type RecoveryActionsBodyInput = z.infer<typeof RecoveryActionsBody>;

// --- Route schema registry --
// Maps route method+path to its body schema (POST) or query schema (GET).

export interface RouteSchema {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly bodySchema?: z.ZodType;
  readonly querySchema?: z.ZodType;
  readonly requiresIdempotencyKey: boolean;
}

export const ROUTE_SCHEMAS: readonly RouteSchema[] = [
  { method: "POST", path: "/v1/receives", bodySchema: CreateReceiveBody, requiresIdempotencyKey: true },
  { method: "GET", path: "/v1/receives/:operation_id", requiresIdempotencyKey: false },
  { method: "POST", path: "/v1/internal-moves", bodySchema: CreateInternalMoveBody, requiresIdempotencyKey: true },
  { method: "GET", path: "/v1/internal-moves/:operation_id", requiresIdempotencyKey: false },
  { method: "POST", path: "/v1/external-sends", bodySchema: CreateExternalSendBody, requiresIdempotencyKey: true },
  { method: "GET", path: "/v1/external-sends/:operation_id", requiresIdempotencyKey: false },
  { method: "POST", path: "/v1/destinations", bodySchema: CreateDestinationBody, requiresIdempotencyKey: true },
  { method: "GET", path: "/v1/destinations", querySchema: ListDestinationsQuery, requiresIdempotencyKey: false },
  { method: "GET", path: "/v1/events", querySchema: ListEventsQuery, requiresIdempotencyKey: false },
  { method: "GET", path: "/v1/events/stream", querySchema: EventStreamQuery, requiresIdempotencyKey: false },
  { method: "GET", path: "/v1/state/snapshot", requiresIdempotencyKey: false },
  { method: "GET", path: "/v1/operations/:operation_id/subscribe", requiresIdempotencyKey: false },
  { method: "POST", path: "/v1/operations/:operation_id/armed", bodySchema: ArmBody, requiresIdempotencyKey: true },
  { method: "POST", path: "/v1/operations/:operation_id/verification-complete", bodySchema: VerificationCompleteBody, requiresIdempotencyKey: true },
  { method: "GET", path: "/v1/operations/:operation_id/verification-material", requiresIdempotencyKey: false },
  { method: "GET", path: "/admin/v1/external-sends/:operation_id/approval-challenge", requiresIdempotencyKey: false },
  { method: "POST", path: "/admin/v1/external-sends/:operation_id/approve", bodySchema: ApproveBody, requiresIdempotencyKey: true },
  { method: "POST", path: "/admin/v1/external-sends/:operation_id/reject", bodySchema: RejectBody, requiresIdempotencyKey: true },
  { method: "POST", path: "/admin/v1/destinations/:destination_id/bless", requiresIdempotencyKey: true },
  { method: "POST", path: "/admin/v1/destinations/:destination_id/retire", requiresIdempotencyKey: true },
  { method: "GET", path: "/admin/v1/operations/needs-attention", querySchema: NeedsAttentionQuerySchema, requiresIdempotencyKey: false },
  { method: "GET", path: "/admin/v1/operations/:operation_id/recovery", requiresIdempotencyKey: false },
  { method: "POST", path: "/admin/v1/operations/:operation_id/recovery-actions", bodySchema: RecoveryActionsBody, requiresIdempotencyKey: true },
  { method: "GET", path: "/.well-known/zupay-node", requiresIdempotencyKey: false },
  { method: "GET", path: "/health", requiresIdempotencyKey: false },
] as const;

export function findRouteSchema(method: string, path: string): RouteSchema | undefined {
  return ROUTE_SCHEMAS.find((route) => route.method === method && route.path === path);
}
