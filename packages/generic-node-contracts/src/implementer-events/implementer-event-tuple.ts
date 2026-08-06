// The frozen `zp-implementer-event-v1` tenant-facing implementer-scoped event tuple.
// TEST-ONLY: A.8 seed keys are TEST-ONLY and MUST never be used with live ZKZ.
//
// Covers A.1.1 (serializer), A.6 (architecture), A.8 (golden); the closed event
// set; dual continuity and implementer_seq encoding. Byte-exactness is
// the byte-exact signing rule. Signed with the node's existing EVENT_SIGNING key (seed byte 00) — no new
// custody surface (the key-custody rule).

export const IMPLEMENTER_EVENT_PURPOSE = "zp-implementer-event-v1" as const;
export const IMPLEMENTER_EVENT_CANONICAL_VERSION = 1 as const;

export const IMPLEMENTER_EVENT_FIELD_ORDER = [
  "purpose",
  "canonical_version",
  "node_id",
  "implementer_id",
  "event_id",
  "implementer_seq",
  "operation_id",
  "wallet_id",
  "event_type",
  "data_sha256",
  "node_event_hash",
  "implementer_previous_event_hash",
  "created_at",
] as const;

export interface ImplementerEventPayload {
  readonly purpose: typeof IMPLEMENTER_EVENT_PURPOSE;
  readonly canonical_version: typeof IMPLEMENTER_EVENT_CANONICAL_VERSION;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly event_id: string;
  readonly implementer_seq: string;
  readonly operation_id: string | null;
  readonly wallet_id: string | null;
  readonly event_type: string;
  readonly data_sha256: string;
  readonly node_event_hash: string;
  readonly implementer_previous_event_hash: string | null;
  readonly created_at: string;
}

// Build the byte-exact preimage per A.1.1 (the byte-exact signing rule). Nullable fields are always PRESENT
// and serialized as JSON null (never omitted).
export function buildImplementerEventPreimage(p: ImplementerEventPayload): string {
  const payload = {
    purpose: p.purpose,
    canonical_version: p.canonical_version,
    node_id: p.node_id,
    implementer_id: p.implementer_id,
    event_id: p.event_id,
    implementer_seq: p.implementer_seq,
    operation_id: p.operation_id,
    wallet_id: p.wallet_id,
    event_type: p.event_type,
    data_sha256: p.data_sha256,
    node_event_hash: p.node_event_hash,
    implementer_previous_event_hash: p.implementer_previous_event_hash,
    created_at: p.created_at,
  };
  return `${IMPLEMENTER_EVENT_PURPOSE}\n${JSON.stringify(payload)}`;
}

// implementer_seq model: a per-(node_id, implementer_id) gapless
// counter allocated pre-sign from a locked-head counter — NOT IDENTITY. Allocation is atomic
// with the global counter (binding condition C2). Fixed lock sequence: global-head then
// implementer-head. An unfillable gap is a fail-closed operator INVARIANT.
export const IMPLEMENTER_SEQ_MODEL = {
  source: "per_node_implementer_gapless_counter_allocated_pre_sign",
  scope: "per_(node_id,implementer_id)",
  forbiddenSource: "identity_or_bigserial",
  allocationAtomicWithGlobal: true,
  lockOrder: "global_head_then_implementer_head",
  unfillableGap: "FAIL_CLOSED_OPERATOR_INVARIANT",
} as const;

// Non-invertibility: node_event_hash = SHA256(preimage_bytes || signature_bytes) of the
// corresponding zp-node-event-v1 row. The tenant sees only this hash and cannot recover the
// global seq or node_events.previous_event_hash.
export const NODE_EVENT_HASH_RULE = "SHA256(preimage_bytes || signature_bytes)" as const;
export const NODE_EVENT_HASH_INVERTIBILITY = "NON_INVERTIBLE" as const;

// A.8 golden A: first implementer event (implementer_previous_event_hash null), mirrors
// zp-node-event-v1 golden A's event_id and data_sha256.
export const IMPLEMENTER_EVENT_GOLDEN_A: ImplementerEventPayload = {
  purpose: IMPLEMENTER_EVENT_PURPOSE,
  canonical_version: IMPLEMENTER_EVENT_CANONICAL_VERSION,
  node_id: "11111111-1111-4111-8111-111111111111",
  implementer_id: "22222222-2222-4222-8222-222222222222",
  event_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  implementer_seq: "1",
  operation_id: "33333333-3333-4333-8333-333333333333",
  wallet_id: "55555555-5555-4555-8555-555555555555",
  event_type: "receive.ready",
  data_sha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
  node_event_hash: "1f0ec14dd26b58d3ce4200a18125080951b0e391c6ec081f71b8c49d44b8f4be",
  implementer_previous_event_hash: null,
  created_at: "2026-07-18T00:00:00.000Z",
};

// Golden B: null wallet_id, chained off A (implementer_previous_event_hash == A's event_hash).
export const IMPLEMENTER_EVENT_GOLDEN_B: ImplementerEventPayload = {
  purpose: IMPLEMENTER_EVENT_PURPOSE,
  canonical_version: IMPLEMENTER_EVENT_CANONICAL_VERSION,
  node_id: "11111111-1111-4111-8111-111111111111",
  implementer_id: "22222222-2222-4222-8222-222222222222",
  event_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
  implementer_seq: "2",
  operation_id: "33333333-3333-4333-8333-333333333333",
  wallet_id: null,
  event_type: "operation.needs_attention",
  data_sha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
  node_event_hash: "ff6f8bbadf5e50f8d0476802341eec50b8ffff4268d41591537b04e3d255ecd5",
  implementer_previous_event_hash: "f55d6203df0445655cc79ac971a864795f2293cf96c316d3931d298a6f460160",
  created_at: "2026-07-18T00:00:01.000Z",
};

export const IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE = buildImplementerEventPreimage(IMPLEMENTER_EVENT_GOLDEN_A);
export const IMPLEMENTER_EVENT_GOLDEN_B_PREIMAGE = buildImplementerEventPreimage(IMPLEMENTER_EVENT_GOLDEN_B);
