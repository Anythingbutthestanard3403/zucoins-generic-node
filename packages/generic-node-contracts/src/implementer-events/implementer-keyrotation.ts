// The frozen `zp-implementer-keyrotation-v1` retirement/rotation attestation tuple.
// TEST-ONLY: A.8 seed keys are TEST-ONLY and MUST never be used with live ZKZ.
//
// Covers A.1.1 (serializer), A.6 (architecture), A.8 (golden); dual-continuity data
// model. Byte-exactness is the byte-exact signing rule. Signed with the node's existing EVENT_SIGNING key
// (seed byte 00) — no new custody surface (the key-custody rule).
//
// OPEN QUESTION: the exact co-signing parties for key rotation are NOT decided by
// this freeze. This tuple is signed with the node event key only. A future decision may add
// co-signature fields (additive-only, new canonical_version, or new purpose literal).

export const IMPLEMENTER_KEYROTATION_PURPOSE = "zp-implementer-keyrotation-v1" as const;
export const IMPLEMENTER_KEYROTATION_CANONICAL_VERSION = 1 as const;

export const IMPLEMENTER_KEYROTATION_FIELD_ORDER = [
  "purpose",
  "canonical_version",
  "node_id",
  "implementer_id",
  "implementer_seq",
  "retired_key_id",
  "new_key_id",
  "new_public_key",
  "supersedes_key_id",
  "implementer_previous_event_hash",
  "created_at",
] as const;

export interface ImplementerKeyRotationPayload {
  readonly purpose: typeof IMPLEMENTER_KEYROTATION_PURPOSE;
  readonly canonical_version: typeof IMPLEMENTER_KEYROTATION_CANONICAL_VERSION;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly implementer_seq: string;
  readonly retired_key_id: string;
  readonly new_key_id: string;
  readonly new_public_key: string;
  readonly supersedes_key_id: string | null;
  readonly implementer_previous_event_hash: string | null;
  readonly created_at: string;
}

// Build the byte-exact preimage per A.1.1 (the byte-exact signing rule). Nullable fields are always PRESENT
// and serialized as JSON null (never omitted).
export function buildImplementerKeyRotationPreimage(p: ImplementerKeyRotationPayload): string {
  const payload = {
    purpose: p.purpose,
    canonical_version: p.canonical_version,
    node_id: p.node_id,
    implementer_id: p.implementer_id,
    implementer_seq: p.implementer_seq,
    retired_key_id: p.retired_key_id,
    new_key_id: p.new_key_id,
    new_public_key: p.new_public_key,
    supersedes_key_id: p.supersedes_key_id,
    implementer_previous_event_hash: p.implementer_previous_event_hash,
    created_at: p.created_at,
  };
  return `${IMPLEMENTER_KEYROTATION_PURPOSE}\n${JSON.stringify(payload)}`;
}

// Key rotation is keyed on the implementer's own implementer_seq cursor, NEVER the node-global
// cursor (preserves NC2 — the tenant's gapless stream is unaffected by global resequencing).
export const KEYROTATION_CURSOR_MODEL = {
  cursor: "implementer_seq",
  neverGlobalCursor: true,
  preservesNC2: true,
} as const;

// Co-signing parties: OPEN QUESTION. Not decided by this freeze.
export const KEYROTATION_COSIGN_STATUS = "OPEN_QUESTION" as const;

// A.8 golden: rotation at implementer_seq 3, chained off golden B's event_hash.
export const IMPLEMENTER_KEYROTATION_GOLDEN: ImplementerKeyRotationPayload = {
  purpose: IMPLEMENTER_KEYROTATION_PURPOSE,
  canonical_version: IMPLEMENTER_KEYROTATION_CANONICAL_VERSION,
  node_id: "11111111-1111-4111-8111-111111111111",
  implementer_id: "22222222-2222-4222-8222-222222222222",
  implementer_seq: "3",
  retired_key_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  new_key_id: "ffffffff-ffff-4fff-8fff-ffffffffffff",
  new_public_key: "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=",
  supersedes_key_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  implementer_previous_event_hash: "5d30760469db67c76d98aa99f68616ef564db7e2c088f6559337d4789af17391",
  created_at: "2026-07-18T00:00:03.000Z",
};

export const IMPLEMENTER_KEYROTATION_GOLDEN_PREIMAGE =
  buildImplementerKeyRotationPreimage(IMPLEMENTER_KEYROTATION_GOLDEN);
