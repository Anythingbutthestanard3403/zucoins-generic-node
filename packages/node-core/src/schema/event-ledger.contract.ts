// Durable neutral event stream: the reference scalar checks, the neutral node event
// tuple, and the closed nine-value durable public event set. The per-node event counter
// is gapless; the reporting cursor tracks the dedicated seq while the node-global hash
// chain is the gap/tamper detector; PRIMARY KEY (node_id, seq) gives one chain per node.
//
// Frozen inventory of the structural neutral-event invariants carried by event-ledger.sql
// the node_event_seq_counters counter and the node_events append-only signed
// ledger. The census test binds every entry here to the literal SQL text, so the inventory
// and the schema contract cannot drift apart. Execution against a live database belongs to
// the schema-apply phase, recorded below as obligations rather than silently omitted.
//
// Scope: only the two tables of the neutral event stream. The implementer-scoped
// continuity artifacts (zp-implementer-event-v1 / -checkpoint-v1 / -keyrotation-v1) are
// deferred to the sibling byte-freeze slice and are not a byte contract yet, so nothing
// about them is inventoried here.

export const EVENT_LEDGER_SCHEMA_FILE = "event-ledger.sql" as const;

export interface EventLedgerInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const EVENT_LEDGER_INVARIANTS: readonly EventLedgerInvariant[] = [
  {
    id: "SEQ_FROM_DEDICATED_COUNTER_TABLE",
    sqlAnchor:
      "CREATE TABLE node_event_seq_counters (\n  node_id uuid PRIMARY KEY REFERENCES nodes(id),\n  next_seq bigint NOT NULL DEFAULT 1 CHECK (next_seq > 0)\n);",
    rule: "seq is allocated from a dedicated single-row-per-node counter table, never a GENERATED ALWAYS AS IDENTITY / bigserial column: an identity value is allocated at insert and a rolled-back transaction burns it permanently, gapping the reporting cursor. The counter increment shares the event insert's transaction, so a rollback un-does it and the sequence stays contiguous and gapless.",
  },
  {
    id: "COUNTER_NEXT_SEQ_MONOTONIC_POSITIVE",
    sqlAnchor: "next_seq bigint NOT NULL DEFAULT 1 CHECK (next_seq > 0)",
    rule: "the counter starts at 1 and is constrained positive: the writer locks the node's counter row, takes the current next_seq as the event's seq, and increments next_seq in the same transaction. The counter is monotonic and durable-before-visible — a consumer never sees a seq that could still roll back, and on restart it resumes from the durable high-water without reset or reuse.",
  },
  {
    id: "EVENT_SEQ_IS_PRIMARY_KEY_NOT_IDENTITY",
    sqlAnchor: "  PRIMARY KEY (node_id, seq)",
    rule: "events are sequenced per node by (node_id, seq); seq is a plain bigint populated from the dedicated per-node counter — never an identity/serial column. The composite PRIMARY KEY lets equal seq values coexist across nodes on a shared database. The reporting cursor tracks this dedicated per-node sequence, not audit_log.id.",
  },
  {
    id: "EVENT_ID_UNIQUE",
    sqlAnchor: "  event_id uuid NOT NULL UNIQUE,",
    rule: "event_id is UNIQUE: a redelivered or duplicate insert collides here, so a duplicate committed event is impossible at the schema layer.",
  },
  {
    id: "EVENT_PURPOSE_FROZEN",
    sqlAnchor: "CHECK (purpose = 'zp-node-event-v1')",
    rule: "purpose is frozen to 'zp-node-event-v1', the neutral node-event artifact. Per the dual-continuity scope note this stream is operator/auditor-only: it is never served to, and never used as a cursor for, any tenant-facing signed reporting credential.",
  },
  {
    id: "EVENT_CANONICAL_VERSION_FROZEN",
    sqlAnchor: "CHECK (canonical_version = 1)",
    rule: "canonical_version is frozen at 1.",
  },
  {
    id: "EVENT_TYPE_CLOSED_NINE_VALUE_SET",
    sqlAnchor: "event_type text NOT NULL CHECK (event_type IN (",
    rule: "event_type is the closed nine-value durable public event set ('the event set is closed at nine values'). Dual continuity adds a second signed cursor over the same events, never new event types. The literals are cross-bound to DURABLE_EVENTS in the census test.",
  },
  {
    id: "EVENT_DATA_TEXT_AND_DIGEST",
    sqlAnchor: "data_text text NOT NULL,\n  data_sha256 sha256_hex NOT NULL,",
    rule: "data_text is the exact separately stored event-data JSON text and data_sha256 is its SHA-256. Authoritative bytes are stored as text plus digest, never JSONB; the writer recomputes the digest in the same serialized transaction.",
  },
  {
    id: "EVENT_PREIMAGE_AND_DIGEST",
    sqlAnchor: "preimage_text text NOT NULL,\n  preimage_sha256 sha256_hex NOT NULL,",
    rule: "preimage_text stores every A SS A.6 field — purpose, canonical version, node id, event id, decimal-string sequence, nullable operation/wallet ids, event type, data digest, nullable previous hash, and canonical creation timestamp — and preimage_sha256 is its digest; the signature is formed over this exact preimage (the byte-exact signing rule, byte-exact).",
  },
  {
    id: "EVENT_SIGNED_BY_NODE_SIGNING_KEY",
    sqlAnchor:
      "signing_key_id uuid NOT NULL REFERENCES node_signing_keys(id),\n  signature padded_base64url_signature NOT NULL,",
    rule: "each event is signed by a node signing key (the EVENT_SIGNING key); signing_key_id is exposed on the wire only as key_id. Signing reuses the node's existing key — no new custody surface is introduced (the key-custody rule).",
  },
  {
    id: "EVENT_HASH_LINKED_CHAIN",
    sqlAnchor: "previous_event_hash sha256_hex,\n  event_hash sha256_hex NOT NULL UNIQUE,",
    rule: "events are hash-linked into a node-global chain: previous_event_hash links the prior event's event_hash, and event_hash is UNIQUE. This chain is the sole authoritative gap/tamper detector; event_hash uniqueness makes a duplicate committed event impossible. previous_event_hash is nullable for the genesis event.",
  },
  {
    id: "EVENT_NODE_SCOPED",
    sqlAnchor: "  node_id uuid NOT NULL REFERENCES nodes(id),",
    rule: "every event is scoped to a node: the counter and the hash chain are node-global, never fragmented per tenant.",
  },
  {
    id: "EVENTS_APPEND_ONLY_UPDATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER node_events_no_update\n  BEFORE UPDATE ON node_events\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "a committed event's signed bytes cannot be rewritten by ANY connection (retention: signed node event, permanent, append-only): the engine, not the application, refuses UPDATE. An UPDATE-able data_text or event_hash would let a writer rewrite the very chain that is the gap/tamper detector.",
  },
  {
    id: "EVENTS_APPEND_ONLY_DELETE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER node_events_no_delete\n  BEFORE DELETE ON node_events\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "a committed event cannot be removed (events are never edited or deleted): deleting one link would silently break the node-global hash chain, so the engine refuses DELETE.",
  },
  {
    id: "EVENTS_APPEND_ONLY_TRUNCATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER node_events_no_truncate\n  BEFORE TRUNCATE ON node_events\n  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "TRUNCATE does not fire row-level DELETE triggers, so a statement-level BEFORE TRUNCATE guard is required or the whole ledger stays removable in one statement -- append-only would hold row by row and fail table-wide.",
  },
  {
    id: "EVENTS_APPEND_ONLY_REJECTOR_IS_THE_DOC_FUNCTION",
    sqlAnchor:
      "CREATE FUNCTION reporting_reject_immutable_change()\nRETURNS trigger LANGUAGE plpgsql\nAS $$\nBEGIN\n  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP\n    USING ERRCODE = '55000';\nEND\n$$;",
    rule: "the rejector is 04's reporting_reject_immutable_change transcribed VERBATIM, ERRCODE '55000' included: the canonical append-only rejector is consumed, never re-invented under a second name (a parallel definition of an existing schema concept is the defect class this anchor exists to prevent).",
  },
] as const;

// Live-database proofs this package cannot run (no database harness lands in this package). The schema-apply phase MUST discharge each of these against a real
// Postgres before the schema contract is considered enforced.
export const SCHEMA_EVENT_LEDGER_OBLIGATIONS = [
  "execution sequence: create the reference scalar domains and the nodes, operations, wallets, and node_signing_keys tables before this file's tables — node_event_seq_counters targets nodes(id), and node_events targets nodes(id), operations(id), wallets(id), and node_signing_keys(id).",
  "atomic allocation: the writer MUST lock the node's node_event_seq_counters row (e.g. SELECT ... FOR UPDATE), take its current next_seq as the event's seq, increment next_seq, and insert the event row — all in ONE transaction with the triggering operation status transition. A rollback un-does the increment so the sequence stays gapless; seq is never allocated from an identity/serial column.",
  "guards (DISCHARGED): the BEFORE UPDATE / DELETE / TRUNCATE triggers making node_events append-only forever (retention: signed node event / audit log — permanent, append-only; events are never edited or deleted) now ship in event-ledger.sql and are executed against a live PostgreSQL by test/evidence-append-only.pg.test.ts, so a committed event's signed bytes are immutable after insertion. node_event_seq_counters stays deliberately unguarded — it is the mutable allocation counter and may only advance next_seq forward (monotonic), never rewind.",
  "negative: a duplicate event_id insert is rejected with unique_violation (23505).",
  "negative: a duplicate event_hash insert is rejected with unique_violation (23505).",
  "negative: an event_type outside the closed nine-value set, a purpose other than 'zp-node-event-v1', or a canonical_version other than 1 is rejected by its CHECK.",
  "negative: malformed sha256_hex (data_sha256, preimage_sha256, previous_event_hash, event_hash) and padded_base64url_signature (signature) values are rejected by their domains.",
  "negative: a second node_event_seq_counters row for the same node is rejected by the primary key, and next_seq <= 0 is rejected by the CHECK.",
] as const;

export const EVENT_LEDGER_SOURCE =
  "data-model: durable neutral event stream" as const;
