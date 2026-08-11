// The durable PROOF_CHANNEL proof-body intake store: candidate bodies, the idempotency
// ledger, and the bounded sighting counters. The byte-exact signing rule (byte-exact bodies).
//
// Frozen inventory of the structural invariants carried by proof-body-store.sql
// the durable PROOF_CHANNEL proof-body intake store that backs the
// ProofBodyStore port. The census test binds every entry here to the literal SQL
// text, so the inventory and the schema contract cannot drift apart. Execution against a
// live database belongs to the schema-apply phase, recorded below as obligations rather
// than silently omitted.
//
// Deferral resolution: observation-ledger.sql defers lineage_path_bodies to "the
// observation-verification and landing-path oracle landing-oracle lanes". THIS file resolves that
// deferral for the PROOF_CHANNEL intake path only -- it materializes the
// lineage_path_bodies body-column shape for caller-supplied candidate bodies. The
// verifier's FK-bound lineage_path_bodies assembly table stays in the landing
// lane and is intentionally not transcribed here (see proof-body-store.sql header).

export const PROOF_BODY_STORE_SCHEMA_FILE = "proof-body-store.sql" as const;

export interface ProofBodyStoreInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const PROOF_BODY_STORE_INVARIANTS: readonly ProofBodyStoreInvariant[] = [
  {
    id: "CANDIDATE_SLOT_PRIMARY_KEY",
    sqlAnchor: "PRIMARY KEY (path_proof_id, path_index),",
    rule: "the candidate body slot is (path_proof_id, path_index), the lineage_path_bodies PK components: a second body at an occupied slot is a unique_violation, which persist.ts maps to DIGEST_COLLISION on the TOCTOU race.",
  },
  {
    id: "CANDIDATE_SOURCE_KIND_PROOF_CHANNEL_ONLY",
    sqlAnchor: "source_kind text NOT NULL CHECK (source_kind = 'PROOF_CHANNEL'),",
    rule: "the only representable provenance is PROOF_CHANNEL (source_kind is restricted to the single caller-supplied value): source_kind records provenance only and grants no authority, and the other three source_kind values are node-derived and never arrive through intake.",
  },
  {
    id: "CANDIDATE_IDEMPOTENCY_FULL_TRIPLE_UNIQUE",
    sqlAnchor:
      "CONSTRAINT proof_channel_candidate_bodies_tenant_op_idem_key\n    UNIQUE (tenant_id, operation_id, idempotency_key),",
    rule: "the durable idempotency ledger keys on the FULL (tenant_id, operation_id, idempotency_key) tuple, never key-only: cross-tenant isolation is structural -- the same idempotency_key from two tenants can never collide.",
  },
  {
    id: "CANDIDATE_BYTE_OCTET_CHECK",
    sqlAnchor:
      "CHECK (octet_length(completed_transaction_text) = completed_transaction_octets),",
    rule: "the persisted octet count equals the actual byte length of the completed transaction text: the stored bytes are the authoritative record and their declared length cannot drift from them (the byte-exact signing rule).",
  },
  {
    id: "CANDIDATE_INNER_PREIMAGE_NONEMPTY",
    sqlAnchor: "CHECK (octet_length(inner_preimage_text) > 0)",
    rule: "the inner preimage text is non-empty: a candidate body always carries the exact inner preimage the verifier re-derives against.",
  },
  {
    id: "CANDIDATE_RAW_DIGEST_PRESENT",
    sqlAnchor: "raw_bytes_sha256 sha256_hex NOT NULL,",
    rule: "the SHA-256 of the exact raw intake bytes is persisted with every candidate (capture-before-parse evidence): raw_bytes_sha256 is the dedup / idempotency-content key persist.ts compares, not a projection.",
  },
  {
    id: "CANDIDATE_SIGNATURE_DOMAINS",
    sqlAnchor: "s_signature padded_base64url_signature NOT NULL,",
    rule: "signature columns use the padded_base64url_signature reference domain (88 chars, 86 base64url + '=='): the candidate carries exact signature bytes, structurally shaped, never reformatted (the byte-exact signing rule).",
  },
  {
    id: "CANDIDATE_P_SIGNATURE_GENESIS_OR_PADDED",
    sqlAnchor: "(p_signature = '' OR p_signature ~ '^[A-Za-z0-9_-]{86}==$'),",
    rule: "the predecessor signature is empty (genesis) or a padded base64url signature: mirrors the frozen lineage_path_bodies p_signature CHECK verbatim.",
  },
  {
    id: "CANDIDATE_APPEND_ONLY_UPDATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER proof_channel_candidate_bodies_no_update\n  BEFORE UPDATE ON proof_channel_candidate_bodies\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "captured candidate bytes cannot be rewritten by ANY connection: the engine, not the application, refuses UPDATE. This is the anti-forensics permanence guarantee, which insert-only application discipline alone does not provide.",
  },
  {
    id: "CANDIDATE_APPEND_ONLY_DELETE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER proof_channel_candidate_bodies_no_delete\n  BEFORE DELETE ON proof_channel_candidate_bodies\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "captured candidate bytes cannot be removed (retention: complete-path bodies, manifests and adjudications are permanent, and retention jobs revoke proof access without deleting any permanent row): proof-access expiry closes ONE endpoint's window and never reaches these rows.",
  },
  {
    id: "CANDIDATE_APPEND_ONLY_TRUNCATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER proof_channel_candidate_bodies_no_truncate\n  BEFORE TRUNCATE ON proof_channel_candidate_bodies\n  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "TRUNCATE does not fire row-level DELETE triggers, so a statement-level BEFORE TRUNCATE guard is required or the whole evidence table stays removable in one statement -- append-only would hold row by row and fail table-wide.",
  },
  {
    id: "APPEND_ONLY_REJECTOR_IS_THE_DOC_FUNCTION",
    sqlAnchor:
      "CREATE FUNCTION reporting_reject_immutable_change()\nRETURNS trigger LANGUAGE plpgsql\nAS $$\nBEGIN\n  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP\n    USING ERRCODE = '55000';\nEND\n$$;",
    rule: "the rejector is 04's reporting_reject_immutable_change transcribed VERBATIM, ERRCODE '55000' included: the canonical append-only rejector is consumed, never re-invented under a second name (a parallel definition of an existing schema concept is the defect class this anchor exists to prevent).",
  },
  {
    id: "SLOT_SIGHTING_BOUNDED_COUNTER",
    sqlAnchor:
      "CREATE TABLE proof_body_slot_sighting_counters (\n  path_proof_id uuid NOT NULL,\n  path_index bigint NOT NULL CHECK (path_index >= 0),\n  sighting_count bigint NOT NULL DEFAULT 0 CHECK (sighting_count >= 0),\n  PRIMARY KEY (path_proof_id, path_index)\n);",
    rule: "per-slot sightings are a bounded COUNTER keyed by slot, not an append-ledger (a sighting appends once and increments the counter, mirroring the consecutive_repeat_count model): one row per slot, incremented by UPSERT, so storage cannot be driven to unbounded growth by fresh-key resubmits -- the denial-of-service closure. Backs countSightingsBySlot and the MAX_SIGHTINGS_PER_BODY cap.",
  },
  {
    id: "TENANT_SIGHTING_BOUNDED_COUNTER",
    sqlAnchor:
      "CREATE TABLE proof_body_tenant_sighting_counters (\n  tenant_id text NOT NULL,\n  sighting_count bigint NOT NULL DEFAULT 0 CHECK (sighting_count >= 0),\n  PRIMARY KEY (tenant_id)\n);",
    rule: "per-tenant sightings are a bounded COUNTER keyed by tenant (the same counter model): one row per tenant, incremented by UPSERT, closing the role-conflict fresh-slot spray the per-slot cap misses and containing the cross-tenant blast radius. Backs countSightingsByTenant and the MAX_SIGHTINGS_PER_TENANT cap.",
  },
] as const;

// non-authority: the store persists candidate evidence ONLY. No table carries any of
// these authority/verdict/landing/lease tokens; the census asserts their literal absence.
export const PROOF_BODY_STORE_FORBIDDEN_AUTHORITY_TOKENS = [
  "verdict",
  "landed",
  "landing",
  "lease",
  "verified_at",
  "promote",
  "authorize",
  "release",
] as const;

// Mutability regime: candidate bodies are insert-only evidence; the sighting counters are
// the only mutable rows ("cursor counters are mutable operational indexes, not
// evidence"), and their only sanctioned mutation is the +1 UPSERT increment.
export const PROOF_BODY_STORE_MUTABILITY_REGIMES = [
  {
    table: "proof_channel_candidate_bodies",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "append-only candidate evidence: no column is updatable or deletable; captured bytes are frozen at insert.",
  },
  {
    table: "proof_body_slot_sighting_counters",
    regime: "counter_upsert_only",
    updatableColumns: ["sighting_count"] as readonly string[],
    rule: "operational counter: the only mutation is the monotonic +1 UPSERT increment; the count is not evidence.",
  },
  {
    table: "proof_body_tenant_sighting_counters",
    regime: "counter_upsert_only",
    updatableColumns: ["sighting_count"] as readonly string[],
    rule: "operational counter: the only mutation is the monotonic +1 UPSERT increment; the count is not evidence.",
  },
] as const;

// Live-database proofs: the live engine's enforcement, not the store's logic, so the
// faithful-executor suite in test/proof-body-persist-sql-store.test.ts cannot reach them.
//
// These were originally recorded as schema-apply obligations because no database harness
// existed in node-core. That is no longer true: established the
// psql-as-child-process pattern (test/node-implementer-registry.pg.test.ts), which runs a
// real PostgreSQL WITHOUT opening an in-process socket and therefore keeps the
// network-containment guard intact. test/proof-body-store.pg.test.ts uses it to discharge
// the append-only guards and the byte-for-byte round trip here (D4/D5); each entry
// below that is discharged says so inline. The rest still belong to the schema-apply phase.
export const SCHEMA_PROOF_BODY_STORE_OBLIGATIONS = [
  "execution sequence: create the zkz_balance_text / sha256_hex / padded_base64url_signature domains before this file's tables; no other frozen table is referenced (the candidate table intentionally omits the lineage_path_proofs FK carried by the verifier lineage_path_bodies, so this file applies additively onto the existing schema with no destructive change).",
  "negative: a second candidate row at the same (path_proof_id, path_index) is rejected with unique_violation (23505) -- the slot PK; persist.ts maps this to DIGEST_COLLISION on the concurrent-insert race.",
  "negative: a second candidate row with the same (tenant_id, operation_id, idempotency_key) is rejected with unique_violation (23505) even with different bytes -- the durable idempotency ledger; persist.ts pre-checks it via findByIdempotencyKey and only a TOCTOU race reaches the constraint.",
  "positive: the same idempotency_key under a DIFFERENT tenant_id (or operation_id) inserts cleanly -- the full-tuple key gives cross-tenant isolation; prove two tenants sharing key 'K' both persist.",
  "negative: source_kind other than 'PROOF_CHANNEL', a malformed sha256_hex / zkz_balance_text / padded_base64url_signature, completed_transaction_octets not equal to octet_length(completed_transaction_text), or an empty inner_preimage_text is rejected by the column/table CHECKs and domains.",
  "concurrency: the slot and tenant counter UPSERTs increment atomically under concurrent sightings (no lost update); the +1 is evaluated inside the ON CONFLICT DO UPDATE, so N concurrent sightings yield count N.",
  "cross-call atomicity: the frozen ProofBodyStore port exposes no transaction boundary. SqlProofBodyStore (with a composition-root SqlTransactionRunner) opens one transaction per persistProofBody and takes the per-path_proof_id advisory lock pg_advisory_xact_lock(hashtextextended(path_proof_id::text, 0)) as the first statement inside that transaction (lockPathProofId), serializing the per-path_proof_id cap-read / insert / increment sequence. That closes the per-slot MAX_SIGHTINGS_PER_BODY overshoot under concurrent same-path_proof_id persists. A separate lock scoped to the idempotency tuple (tenant_id, operation_id, idempotency_key) and a per-tenant-cap lock are NOT taken here; see residuals.",
  "residual (NOT closed by a per-path_proof_id lock alone): the idempotency UNIQUE is tenant-scoped (tenant_id, operation_id, idempotency_key), a granularity NARROWER than path_proof_id -- two concurrent same-key requests submitted at different path_proof_id values take different locks and both reach the constraint; the per-tenant sighting cap (countSightingsByTenant / MAX_SIGHTINGS_PER_TENANT) reads a tenant-wide counter that a per-path_proof_id lock never serializes, so two concurrent same-tenant requests at different slots can both read cap-1 and both increment, overshooting the cap by up to the concurrency factor. The per-tenant cap is therefore a soft DoS bound, not a claim that the caps 'cannot be raced past' under a per-path_proof_id lock alone. Intentional relaxation at this layer (ZTR-1211 took the documented path_proof_id lock; tenant/idempotency-tuple locks remain open).",
  "error taxonomy under the residual above: the frozen persist.ts isUniqueViolation maps ANY Postgres 23505 at store.insert() to DIGEST_COLLISION, so a concurrent idempotency-key race that passes the step-1 findByIdempotencyKey pre-check and then collides on the tenant_op_idem_key UNIQUE surfaces as DIGEST_COLLISION, never IDEMPOTENCY_CONFLICT, even though the underlying cause is an idempotency-key race, not a slot race. Downstream callers MUST treat both reasons as terminal / non-retryable (the never-blind-retry rule -- never blind-retry a submit); neither reason authorizes a resubmit with the same idempotency_key.",
  "open dependency: the upstream discipline for assigning path_proof_id per submission (one deterministic path_proof_id per logical slot vs. a fresh path_proof_id per request) is UNRESOLVED at this layer and determines how severe the residual above is in practice; the composition root wiring this store MUST pin that discipline and re-derive whether the per-idempotency-tuple lock alone suffices or whether the per-tenant cap residual also needs closing.",
  "guards (DISCHARGED): the BEFORE UPDATE / DELETE / TRUNCATE triggers making proof_channel_candidate_bodies append-only now ship in proof-body-store.sql and are executed against a live PostgreSQL by test/proof-body-store.pg.test.ts; the counters remain unguarded and permit only the monotonic +1 UPSERT, which the same suite proves still works.",
  "non-authority: prove no column, trigger, or default in this file promotes a candidate, sets a verdict, records a landing, or releases a lease; a candidate row is inert until the landing oracle accepts the entire path.",
] as const;

// Counter information-loss tradeoff (the consecutive_repeat_count model):
// the bounded sighting counters intentionally persist ONLY the totals
// (proof_body_slot_sighting_counters.sighting_count / proof_body_tenant_sighting_counters
// .sighting_count) -- the only fields the caps logic (sightingCapViolation,
// MAX_SIGHTINGS_PER_BODY, MAX_SIGHTINGS_PER_TENANT) ever reads. They do NOT durably persist
// the frozen ProofBodySighting's is_duplicate / is_conflict booleans from persist.ts: the
// per-occurrence DIGEST_COLLISION / ROLE_CONFLICT reason is still surfaced synchronously,
// at decision time, in persistProofBody's return value -- it is simply not retained for
// later durable forensics. Durable per-kind collision/conflict forensics, if needs
// it, is a NAMED FOLLOW-UP against this schema, not a silently dropped requirement.

export const PROOF_BODY_STORE_SOURCE =
  "data-model: proof-channel candidate bodies and sighting counters; the byte-exact signing rule" as const;
