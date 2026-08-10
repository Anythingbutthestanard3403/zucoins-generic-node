// OpenAPI request-body / query field inventories.
//
// Scalar patterns and bounds are imported from `../scalars.ts` and
// `protocol/receive-ttl.ts` so the freeze document cannot invent looser money
// or identity contracts than the runtime Zod boundary (canonical ZKZ amount contract; receive TTL policy; pre-formed sender transfer code).
// Property sets mirror `route-schemas.ts` Zod shapes; freeze tests assert
// BODY_BY_ROUTE / QUERY_BY_ROUTE property names equal the Zod keys.
//
// Canonical ZKZ amount contract; reporting-key enrolment ceremony (no callback_url on receives)

import { OPERATION_KINDS } from "@zucoins/generic-node-contracts/operations";

import { SPLITCHAIN_FUTURE_TIME_CEILING_SECS } from "../../protocol/receive-ttl.js";
import {
  ANCHOR_PATTERN,
  DECIMAL_SEQ_PATTERN,
  ED25519_SIG_PATTERN,
  POSITIVE_ZKZ_OPENAPI_PATTERN,
  SHA256_HEX_PATTERN,
  UUID_PATTERN,
  WALLET_PUBKEY_PATTERN,
} from "../scalars.js";

export type JsonSchema = {
  readonly type?: string | readonly string[];
  readonly description?: string;
  readonly enum?: readonly string[];
  readonly const?: string | number | boolean | null;
  readonly format?: string;
  readonly pattern?: string;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly minItems?: number;
  readonly maxItems?: number;
  readonly items?: JsonSchema;
  readonly properties?: Readonly<Record<string, JsonSchema>>;
  readonly required?: readonly string[];
  readonly additionalProperties?: boolean | JsonSchema;
  readonly oneOf?: readonly JsonSchema[];
  readonly nullable?: boolean;
  readonly $ref?: string;
};

const uuid: JsonSchema = {
  type: "string",
  pattern: UUID_PATTERN,
  description: "Lowercase canonical UUID (RFC 4122 hex form).",
};

const sha256Hex: JsonSchema = {
  type: "string",
  pattern: SHA256_HEX_PATTERN,
  description: "Lowercase hex SHA-256 digest.",
};

/** Operation amount — canonical ZKZ amount contract grammar + structural non-zero (see POSITIVE_ZKZ_OPENAPI_PATTERN). */
export const positiveZkz: JsonSchema = {
  type: "string",
  pattern: POSITIVE_ZKZ_OPENAPI_PATTERN,
  description:
    "Positive ZKZ decimal string: canonical grammar ^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$ with exclusive upper bound < 1e8, ≤32 dp, and numerically > 0 (zeros rejected).",
};

const walletPubkey: JsonSchema = {
  type: "string",
  pattern: WALLET_PUBKEY_PATTERN,
  description: "SplitChain wallet public key — padded base64url, 44 chars (43 body + '=').",
};

const anchor: JsonSchema = {
  type: "string",
  pattern: ANCHOR_PATTERN,
  description: "Opaque implementer anchor bound into the expected artifact.",
};

const decimalSeq: JsonSchema = {
  type: "string",
  pattern: DECIMAL_SEQ_PATTERN,
  description: "Non-negative integer decimal string (implementer_seq / cursor).",
};

const t0Projection: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["s", "p", "b_zkz"],
  properties: {
    s: { type: "string" },
    p: { type: "string" },
    b_zkz: { type: "string" },
  },
};

const t0Evidence: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["observation_id", "projection"],
  properties: {
    observation_id: uuid,
    projection: t0Projection,
  },
};

const landingProof: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: [
    "classification",
    "fresh_head_step_2_signature",
    "fresh_head_transaction_sha256",
    "path_manifest_sha256",
  ],
  properties: {
    classification: {
      type: "string",
      enum: ["EXPECTED_AT_HEAD", "EXPECTED_ANCESTOR"],
    },
    fresh_head_step_2_signature: { type: "string" },
    fresh_head_transaction_sha256: sha256Hex,
    path_manifest_sha256: sha256Hex,
  },
};

const walletEvidence: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["wallet_id", "role", "t0", "terminal", "landing_proof"],
  properties: {
    wallet_id: uuid,
    role: { type: "string", enum: ["RECEIVER", "SOURCE", "DESTINATION"] },
    t0: t0Evidence,
    terminal: t0Evidence,
    landing_proof: landingProof,
  },
};

/** POST /v1/receives — CreateReceiveBody. No callback_url (reporting-key enrolment ceremony). */
export const CREATE_RECEIVE_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["amount_zkz", "anchor", "after_landing"],
  properties: {
    amount_zkz: positiveZkz,
    anchor,
    expires_in_seconds: {
      type: "integer",
      minimum: 1,
      maximum: SPLITCHAIN_FUTURE_TIME_CEILING_SECS,
      description:
        "Optional TTL hint; node-clamped to RECEIVE_TTL_MIN/MAX. Hard ceiling is SPLITCHAIN_FUTURE_TIME_CEILING_SECS — matches CreateReceiveBody Zod max.",
    },
    after_landing: {
      oneOf: [
        {
          type: "object",
          additionalProperties: false,
          required: ["kind", "destination_id"],
          properties: {
            kind: { type: "string", const: "HOLD" },
            destination_id: { type: "null" },
          },
        },
        {
          type: "object",
          additionalProperties: false,
          required: ["kind", "destination_id"],
          properties: {
            kind: { type: "string", const: "INTERNAL_MOVE" },
            destination_id: uuid,
          },
        },
      ],
    },
  },
};

export const CREATE_INTERNAL_MOVE_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["source_wallet_id", "destination_id", "amount_zkz"],
  properties: {
    source_wallet_id: uuid,
    destination_id: uuid,
    amount_zkz: positiveZkz,
  },
};

export const CREATE_EXTERNAL_SEND_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["source_wallet_id", "destination_address", "amount_zkz"],
  properties: {
    source_wallet_id: uuid,
    destination_address: walletPubkey,
    amount_zkz: positiveZkz,
    references_operation_id: uuid,
    client_reference: { type: "string", maxLength: 256 },
    description: { type: "string", maxLength: 512 },
  },
};

export const CREATE_DESTINATION_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["label"],
  properties: {
    label: { type: "string", minLength: 1, maxLength: 256 },
  },
};

export const ARM_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["expected_row_version", "t0", "opened_cursor"],
  properties: {
    expected_row_version: { type: "integer", minimum: 1 },
    t0: t0Evidence,
    opened_cursor: decimalSeq,
  },
};

export const VERIFICATION_COMPLETE_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["expected_row_version", "consumed_cursor", "verdict", "wallet_evidence"],
  properties: {
    expected_row_version: { type: "integer", minimum: 1 },
    consumed_cursor: decimalSeq,
    verdict: { type: "string", enum: ["VERIFIED", "REJECTED", "INDETERMINATE"] },
    wallet_evidence: {
      type: "array",
      minItems: 1,
      items: walletEvidence,
    },
  },
};

export const APPROVE_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: [
    "challenge_nonce",
    "expected_row_version",
    "preimage_sha256",
    "device_key_id",
    "device_signature",
  ],
  properties: {
    challenge_nonce: uuid,
    expected_row_version: { type: "integer", minimum: 1 },
    preimage_sha256: sha256Hex,
    device_key_id: { ...uuid, nullable: true },
    device_signature: { type: "string", nullable: true },
  },
};

export const REJECT_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["expected_row_version", "reason"],
  properties: {
    expected_row_version: { type: "integer", minimum: 1 },
    reason: { type: "string", maxLength: 512 },
  },
};

export const RECOVERY_ACTIONS_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["action", "expected_row_version", "recovery_nonce"],
  properties: {
    action: {
      type: "string",
      enum: [
        "RETRY_OBSERVATION",
        "REDELIVER_EXACT_PARTIAL",
        "CONTINUE_EXTERNAL_WAIT",
        "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
        "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
        "REBUILD_INTERNAL_MOVE",
        "RELEASE_EXPIRED_RECEIVE",
        "QUARANTINE_WALLETS",
        "ACKNOWLEDGE_KEEP_PINNED",
      ],
    },
    expected_row_version: { type: "integer", minimum: 1 },
    recovery_nonce: uuid,
    proof_id: { ...uuid, nullable: true },
    operator_note: { type: "string", maxLength: 1024 },
  },
};

export const LIST_DESTINATIONS_QUERY: Readonly<Record<string, JsonSchema>> = {
  state: { type: "string", enum: ["PENDING", "BLESSED", "RETIRED"] },
  after: uuid,
  limit: { type: "integer", minimum: 1, maximum: 100 },
};

export const LIST_EVENTS_QUERY: Readonly<Record<string, JsonSchema>> = {
  after_implementer_seq: decimalSeq,
  limit: { type: "integer", minimum: 1, maximum: 500 },
  wait_seconds: { type: "integer", minimum: 0, maximum: 30 },
};

export const EVENT_STREAM_QUERY: Readonly<Record<string, JsonSchema>> = {
  after_implementer_seq: decimalSeq,
};

export const NEEDS_ATTENTION_QUERY: Readonly<Record<string, JsonSchema>> = {
  classification: {
    type: "string",
    enum: [
      "LANDED_VERIFIED",
      "PROVEN_NOT_STARTED",
      "PROVEN_NOT_LANDED",
      "WAITING",
      "INDETERMINATE",
      "INVARIANT_BREACH",
    ],
  },
  kind: {
    type: "string",
    enum: [...OPERATION_KINDS],
  },
  limit: { type: "integer", minimum: 1, maximum: 200 },
};

const ed25519Sig: JsonSchema = {
  type: "string",
  pattern: ED25519_SIG_PATTERN,
  description: "Ed25519 signature — padded base64url, 88 chars (86 body + '==').",
};

const rfc3339Ms: JsonSchema = {
  type: "string",
  pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$",
  description: "Canonical RFC 3339 UTC timestamp with exactly three fractional digits.",
};

export const BLESS_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["nonce", "issued_at", "expires_at", "device_signature", "device_key_id"],
  properties: {
    nonce: uuid,
    issued_at: rfc3339Ms,
    expires_at: rfc3339Ms,
    device_signature: ed25519Sig,
    device_key_id: uuid,
  },
};

/** Empty body for destination retire — no properties; unknown keys rejected. */
export const RETIRE_BODY: JsonSchema = {
  type: "object",
  additionalProperties: false,
  required: [],
  properties: {},
};

/** Body schema by method+path for routes that accept a JSON body. */
export const BODY_BY_ROUTE: ReadonlyMap<string, JsonSchema> = new Map([
  ["POST /v1/receives", CREATE_RECEIVE_BODY],
  ["POST /v1/internal-moves", CREATE_INTERNAL_MOVE_BODY],
  ["POST /v1/external-sends", CREATE_EXTERNAL_SEND_BODY],
  ["POST /v1/destinations", CREATE_DESTINATION_BODY],
  ["POST /v1/operations/:operation_id/armed", ARM_BODY],
  ["POST /v1/operations/:operation_id/verification-complete", VERIFICATION_COMPLETE_BODY],
  ["POST /admin/v1/external-sends/:operation_id/approve", APPROVE_BODY],
  ["POST /admin/v1/external-sends/:operation_id/reject", REJECT_BODY],
  ["POST /admin/v1/destinations/:destination_id/bless", BLESS_BODY],
  ["POST /admin/v1/destinations/:destination_id/retire", RETIRE_BODY],
  ["POST /admin/v1/operations/:operation_id/recovery-actions", RECOVERY_ACTIONS_BODY],
]);

/** Query parameter schemas by method+path. */
export const QUERY_BY_ROUTE: ReadonlyMap<string, Readonly<Record<string, JsonSchema>>> = new Map([
  ["GET /v1/destinations", LIST_DESTINATIONS_QUERY],
  ["GET /v1/events", LIST_EVENTS_QUERY],
  ["GET /v1/events/stream", EVENT_STREAM_QUERY],
  ["GET /admin/v1/operations/needs-attention", NEEDS_ATTENTION_QUERY],
]);

/** Property names of CreateReceiveBody — freeze asserts callback_url is absent. */
export const CREATE_RECEIVE_PROPERTY_NAMES: readonly string[] = Object.freeze(
  Object.keys(CREATE_RECEIVE_BODY.properties ?? {}),
);

/**
 * Critical scalar constraints frozen for inventory↔Zod parity tests.
 * Values are the live constants imported above — mutating them fails the freeze.
 */
export const OPENAPI_SCALAR_CONSTRAINTS = Object.freeze({
  amount_zkz_pattern: POSITIVE_ZKZ_OPENAPI_PATTERN,
  uuid_pattern: UUID_PATTERN,
  wallet_pubkey_pattern: WALLET_PUBKEY_PATTERN,
  expires_in_seconds_maximum: SPLITCHAIN_FUTURE_TIME_CEILING_SECS,
});
