// The frozen `zp-implementer-checkpoint-v1` anti-rollback checkpoint tuple.
// TEST-ONLY: A.8 seed keys are TEST-ONLY and MUST never be used with live ZKZ.
//
// Covers A.1.1 (serializer), A.6 (architecture), A.8 (golden); binding condition C3
// of the dual-continuity data model. Byte-exactness is the byte-exact signing rule. Signed with the node's existing
// EVENT_SIGNING key (seed byte 00) — no new custody surface (the key-custody rule).

export const IMPLEMENTER_CHECKPOINT_PURPOSE = "zp-implementer-checkpoint-v1" as const;
export const IMPLEMENTER_CHECKPOINT_CANONICAL_VERSION = 1 as const;

export const IMPLEMENTER_CHECKPOINT_FIELD_ORDER = [
  "purpose",
  "canonical_version",
  "node_id",
  "implementer_id",
  "checkpoint_epoch",
  "implementer_seq_head",
  "implementer_event_hash",
  "signing_key_id",
  "created_at",
] as const;

export interface ImplementerCheckpointPayload {
  readonly purpose: typeof IMPLEMENTER_CHECKPOINT_PURPOSE;
  readonly canonical_version: typeof IMPLEMENTER_CHECKPOINT_CANONICAL_VERSION;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly checkpoint_epoch: string;
  readonly implementer_seq_head: string;
  readonly implementer_event_hash: string;
  readonly signing_key_id: string;
  readonly created_at: string;
}

// Build the byte-exact preimage per A.1.1 (the byte-exact signing rule).
export function buildImplementerCheckpointPreimage(p: ImplementerCheckpointPayload): string {
  const payload = {
    purpose: p.purpose,
    canonical_version: p.canonical_version,
    node_id: p.node_id,
    implementer_id: p.implementer_id,
    checkpoint_epoch: p.checkpoint_epoch,
    implementer_seq_head: p.implementer_seq_head,
    implementer_event_hash: p.implementer_event_hash,
    signing_key_id: p.signing_key_id,
    created_at: p.created_at,
  };
  return `${IMPLEMENTER_CHECKPOINT_PURPOSE}\n${JSON.stringify(payload)}`;
}

// Anti-rollback contract (binding condition C3): persist the highest checkpoint epoch/head seen
// and REFUSE any lower value. Conflicting equal-epoch heads = INVARIANT_BREACH (alarm, never
// pick one). Validates the signing key against the seq-canonical key via node-identity directory.
export const CHECKPOINT_ANTI_ROLLBACK = {
  persistsHighestEpochHead: true,
  refusesLower: true,
  conflictingEqualEpochHeads: "INVARIANT_BREACH",
  validatesSigningKeyAgainst: "seq_canonical_key_via_node_identity_directory",
} as const;

// Launch delivery channel (/ UP-07). Signed checkpoint proofs are tenant-facing companions
// to zp-implementer-event-v1 (CONTRACT.md) and ride GET /v1/events as `checkpoints[]`
// opaque proof representations next to `events[]`. SSE and snapshot remain event-scoped; quiet-tail
// mint appends into the durable checkpoint table the events route reads.
export const CHECKPOINT_DELIVERY_CHANNEL = {
  status: "ACTIVE",
  method: "GET",
  path: "/v1/events",
  responseField: "checkpoints",
  proofPurpose: IMPLEMENTER_CHECKPOINT_PURPOSE,
  authMode: "signed_reporting_credential",
} as const;

// Evaluates whether a new checkpoint is acceptable given the current highest.
export function evaluateCheckpoint(
  currentEpoch: bigint,
  currentHead: bigint,
  newEpoch: bigint,
  newHead: bigint,
): "ACCEPT" | "REFUSE_ROLLBACK" | "INVARIANT_BREACH" {
  if (newEpoch < currentEpoch) return "REFUSE_ROLLBACK";
  if (newEpoch === currentEpoch && newHead !== currentHead) return "INVARIANT_BREACH";
  if (newEpoch === currentEpoch && newHead < currentHead) return "REFUSE_ROLLBACK";
  return "ACCEPT";
}

// A.8 golden: checkpoint at epoch 1, head at implementer_seq 2, chained off golden B's event_hash.
export const IMPLEMENTER_CHECKPOINT_GOLDEN: ImplementerCheckpointPayload = {
  purpose: IMPLEMENTER_CHECKPOINT_PURPOSE,
  canonical_version: IMPLEMENTER_CHECKPOINT_CANONICAL_VERSION,
  node_id: "11111111-1111-4111-8111-111111111111",
  implementer_id: "22222222-2222-4222-8222-222222222222",
  checkpoint_epoch: "1",
  implementer_seq_head: "2",
  implementer_event_hash: "5d30760469db67c76d98aa99f68616ef564db7e2c088f6559337d4789af17391",
  signing_key_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
  created_at: "2026-07-18T00:00:02.000Z",
};

export const IMPLEMENTER_CHECKPOINT_GOLDEN_PREIMAGE =
  buildImplementerCheckpointPreimage(IMPLEMENTER_CHECKPOINT_GOLDEN);
