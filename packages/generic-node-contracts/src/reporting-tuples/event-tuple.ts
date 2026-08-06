// the reporting node-event purpose — The frozen `zp-node-event-v1` neutral node-event tuple (the
// canonical-fields and state-event references). Signed by the node event key registered under the reporting-auth register tuple. Events are hash-chained:
// `event_hash = SHA256(preimage_bytes || signature_bytes)` becomes the next `previous_event_hash`.
//
// Governing: the canonical serializer, the node-event field/hash rules and goldens, the closed
// event set, and the pull-cursor authority rule (per-node gapless pre-signed seq). Byte-exactness is the byte-exact signing rule.

export const NODE_EVENT_PURPOSE = "zp-node-event-v1" as const;
export const NODE_EVENT_CANONICAL_VERSION = 1 as const;

export const NODE_EVENT_FIELD_ORDER = [
  "purpose",
  "canonical_version",
  "node_id",
  "event_id",
  "seq",
  "operation_id",
  "wallet_id",
  "event_type",
  "data_sha256",
  "previous_event_hash",
  "created_at",
] as const;

// The event set is closed at nine values (the state-event reference).
export const NEUTRAL_EVENT_TYPES = [
  "receive.ready",
  "receive.landed",
  "internal_move.created",
  "internal_move.landed",
  "external_send.created",
  "external_send.awaiting_redemption",
  "external_send.landed",
  "operation.needs_attention",
  "operation.expired",
] as const;

export interface NodeEventPayload {
  readonly purpose: typeof NODE_EVENT_PURPOSE;
  readonly canonical_version: typeof NODE_EVENT_CANONICAL_VERSION;
  readonly node_id: string;
  readonly event_id: string;
  readonly seq: string;
  readonly operation_id: string | null;
  readonly wallet_id: string | null;
  readonly event_type: string;
  readonly data_sha256: string;
  readonly previous_event_hash: string | null;
  readonly created_at: string;
}

// Build the byte-exact preimage per A.1.1 (the byte-exact signing rule). Nullable fields are always PRESENT and
// serialized as JSON null (never omitted) — `data` is stored/served separately and is never nested.
export function buildNodeEventPreimage(p: NodeEventPayload): string {
  const payload = {
    purpose: p.purpose,
    canonical_version: p.canonical_version,
    node_id: p.node_id,
    event_id: p.event_id,
    seq: p.seq,
    operation_id: p.operation_id,
    wallet_id: p.wallet_id,
    event_type: p.event_type,
    data_sha256: p.data_sha256,
    previous_event_hash: p.previous_event_hash,
    created_at: p.created_at,
  };
  return `${NODE_EVENT_PURPOSE}\n${JSON.stringify(payload)}`;
}

// Sequence source (the pull-cursor authority rule): a dedicated, transactionally-serialized, per-node gapless counter
// allocated pre-sign; ONE counter per node (fragmenting per-tenant would break the hash chain).
// Tenant-filtered consumers see a legitimately sparse subset — a skipped seq is another tenant's
// event, NOT a gap. It is never sourced from an identity/bigserial column.
export const SEQUENCE_MODEL = {
  source: "per_node_gapless_counter_allocated_pre_sign",
  countersPerNode: 1,
  skippedSeqMeaning: "another_tenants_event_not_a_gap",
  forbiddenSource: "identity_or_bigserial",
} as const;

// A.8 golden A: first event (previous_event_hash null), operation + wallet present.
export const NODE_EVENT_GOLDEN_A: NodeEventPayload = {
  purpose: NODE_EVENT_PURPOSE,
  canonical_version: NODE_EVENT_CANONICAL_VERSION,
  node_id: "11111111-1111-4111-8111-111111111111",
  event_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  seq: "1",
  operation_id: "33333333-3333-4333-8333-333333333333",
  wallet_id: "55555555-5555-4555-8555-555555555555",
  event_type: "receive.ready",
  data_sha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
  previous_event_hash: null,
  created_at: "2026-07-18T00:00:00.000Z",
};

// Golden B: null-field case (wallet_id null, serialized as JSON null per the tuple field rules) chained off A — its previous_event_hash is
// A's event_hash, exercising gapless hash-chain linkage across a rotation-safe stream.
export const NODE_EVENT_GOLDEN_B: NodeEventPayload = {
  purpose: NODE_EVENT_PURPOSE,
  canonical_version: NODE_EVENT_CANONICAL_VERSION,
  node_id: "11111111-1111-4111-8111-111111111111",
  event_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
  seq: "2",
  operation_id: "33333333-3333-4333-8333-333333333333",
  wallet_id: null,
  event_type: "operation.needs_attention",
  data_sha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
  previous_event_hash: "1f0ec14dd26b58d3ce4200a18125080951b0e391c6ec081f71b8c49d44b8f4be",
  created_at: "2026-07-18T00:00:01.000Z",
};

export const NODE_EVENT_GOLDEN_A_PREIMAGE = buildNodeEventPreimage(NODE_EVENT_GOLDEN_A);
export const NODE_EVENT_GOLDEN_B_PREIMAGE = buildNodeEventPreimage(NODE_EVENT_GOLDEN_B);
