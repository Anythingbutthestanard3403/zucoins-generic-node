// Independent raw observation ledger: raw capture before decode, bounded/jittered read
// retry for transport ambiguity only, and the reference domains and enums it uses.
// Transport acknowledgement is receipt-only.
//
// Frozen inventory of the structural raw-observation invariants carried by
// observation-ledger.sql: the observers and gateway_observations
// tables every bounded read lands evidence in. The census test binds every entry here
// to the literal SQL text, so the inventory and the schema contract cannot drift
// apart. Execution against a live database belongs to the schema-apply phase, recorded
// below as obligations rather than silently omitted.
//
// The naming conflict this note used to report is closed: the ledger is
// transcribed verbatim, so gateway_observations targets wallets(id), and
// custody-eligibility.sql now declares wallets(id) to match. What remains is execution
// sequence, not naming — wallets must exist before this file's tables.

export const OBSERVATION_LEDGER_SCHEMA_FILE = "observation-ledger.sql" as const;

export interface ObservationLedgerInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const OBSERVATION_LEDGER_INVARIANTS: readonly ObservationLedgerInvariant[] = [
  {
    id: "OBSERVER_ENDPOINT_FINGERPRINT",
    sqlAnchor: "gateway_endpoint_fingerprint sha256_hex NOT NULL,",
    rule: "every observer is bound to the sha256_hex fingerprint of its configured gateway endpoint: the fingerprint identifies the actual endpoint selected for reads.",
  },
  {
    id: "OBSERVER_UNIQUE_DOMAIN_OWNER",
    sqlAnchor: "UNIQUE (domain, owner_id)",
    rule: "at most one observer per (domain, owner): the node database and platform database each instantiate this logical schema without sharing rows.",
  },
  {
    id: "OBSERVATION_ENDPOINT_FINGERPRINT_COPIED",
    sqlAnchor: "observer_id uuid NOT NULL REFERENCES observers(id),\n  endpoint_fingerprint sha256_hex NOT NULL,",
    rule: "the fingerprint of the endpoint actually used for the read is copied into every observation row: later observer reconfiguration cannot rewrite the provenance of existing evidence.",
  },
  {
    id: "OBSERVATION_RAW_BYTES_BEFORE_PARSE",
    sqlAnchor: "raw_response_bytes bytea NOT NULL,",
    rule: "the complete HTTP response body is captured as raw bytes BEFORE any decode or parse: it is evidence, not a signed blob, and an invalid UTF-8 response is still evidence.",
  },
  {
    id: "OBSERVATION_RAW_DIGEST",
    sqlAnchor: "raw_response_sha256 sha256_hex NOT NULL,",
    rule: "the SHA-256 of the exact raw response bytes is persisted with them: exact raw-byte equality is the consecutive dedup key, and digest indexes are never equality authority.",
  },
  {
    id: "OBSERVATION_HTTP_STATUS_NULLABLE",
    sqlAnchor: "http_status integer,",
    rule: "the HTTP status is nullable: a transport-error observation carries no status, matching the transport layer's ambiguous-capture rows.",
  },
  {
    id: "OBSERVATION_TRANSPORT_ERROR_IS_PERMANENT_RESULT",
    sqlAnchor: "'TRANSPORT_ERROR',",
    rule: "TRANSPORT_ERROR is a first-class parse_result: every non-verified result inserts a permanent observation row — an ambiguous read attempt is evidence, never dropped.",
  },
  {
    id: "OBSERVATION_UNIQUE_CURSOR_TRIPLE",
    sqlAnchor: "UNIQUE (observer_id, wallet_public_key, wallet_seq),",
    rule: "at most one observation per (observer, wallet public key, wallet sequence): the recorded sequence position is unique per observer, structurally.",
  },
  {
    id: "OBSERVATION_SELF_REFERENCE",
    sqlAnchor: "previous_recorded_observation_id uuid REFERENCES gateway_observations(id),",
    rule: "each observation may link its immediately prior recorded observation: regression and repeat classification chain through actual foreign keys.",
  },
  {
    id: "VERIFIED_IFF_SEMANTIC_FINGERPRINT",
    sqlAnchor: "(parse_result IN ('VERIFIED_GENESIS','VERIFIED_HEAD')) =\n    (semantic_fingerprint IS NOT NULL)",
    rule: "the semantic fingerprint exists exactly for verified results: it is computed only after complete verification and is never an insertion-eligibility key.",
  },
  {
    id: "VERIFIED_HEAD_MATERIAL_COMPLETE",
    sqlAnchor: "(parse_result = 'VERIFIED_HEAD') =\n    (inner_preimage_text IS NOT NULL AND step_1_signature IS NOT NULL",
    rule: "a verified head carries the complete signed material — inner preimage, both step signatures, completed transaction text and digest — or is not a verified head.",
  },
  {
    id: "NON_VERIFIED_ROWS_CARRY_NO_MATERIAL",
    sqlAnchor: "parse_result IN ('VERIFIED_GENESIS','VERIFIED_HEAD')\n    OR (\n      relationship = 'NOT_APPLICABLE' AND wallet_role IS NULL",
    rule: "every non-verified observation (transport error, malformed envelope, unverified signature, ...) carries no wallet role and no signature material: raw bytes plus classification, nothing derived.",
  },
  {
    id: "GATEWAY_OBSERVATIONS_APPEND_ONLY_UPDATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER gateway_observations_no_update\n  BEFORE UPDATE ON gateway_observations\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "a committed observation's raw bytes, classification, and endpoint fingerprint cannot be rewritten by ANY connection (observation rows are append-only forever; mandatory database test 15): the engine, not the application, refuses UPDATE.",
  },
  {
    id: "GATEWAY_OBSERVATIONS_APPEND_ONLY_DELETE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER gateway_observations_no_delete\n  BEFORE DELETE ON gateway_observations\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "a committed observation cannot be removed: deleting evidence would silently defeat consecutive-dedup authority and the anti-phantom-settle evidence floor.",
  },
  {
    id: "GATEWAY_OBSERVATIONS_APPEND_ONLY_TRUNCATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER gateway_observations_no_truncate\n  BEFORE TRUNCATE ON gateway_observations\n  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "TRUNCATE does not fire row-level DELETE triggers, so a statement-level BEFORE TRUNCATE guard is required or the whole ledger stays removable in one statement.",
  },
  {
    id: "OBSERVERS_APPEND_ONLY_UPDATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER observers_no_update\n  BEFORE UPDATE ON observers\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "observer endpoint provenance is immutable after insertion: rewriting gateway_endpoint_fingerprint would re-attribute historical observation rows.",
  },
  {
    id: "OBSERVERS_APPEND_ONLY_DELETE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER observers_no_delete\n  BEFORE DELETE ON observers\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "an observer row cannot be removed while its observation ledger depends on it.",
  },
  {
    id: "OBSERVATION_APPEND_ONLY_REJECTOR_IS_THE_DOC_FUNCTION",
    sqlAnchor:
      "CREATE FUNCTION reporting_reject_immutable_change()\nRETURNS trigger LANGUAGE plpgsql\nAS $$\nBEGIN\n  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP\n    USING ERRCODE = '55000';\nEND\n$$;",
    rule: "the rejector is 04's reporting_reject_immutable_change transcribed VERBATIM, ERRCODE '55000' included: the canonical append-only rejector is consumed, never re-invented under a second name.",
  },
] as const;

// Live-database proofs this package cannot run (no database harness lands in this package). The schema-apply phase MUST discharge each of these against a
// real Postgres before the schema contract is considered enforced.
export const SCHEMA_OBSERVATION_LEDGER_OBLIGATIONS = [
  "execution sequence: create the reference scalar domains, the observer_domain / observation_parse_result / observation_relationship enums, and wallets before this file's tables; the wallets(id) target matches custody-eligibility.sql, so only the execution sequence below remains to be honoured.",
  "reconciliation: a transport-ambiguous capture carries no bytes, but raw_response_bytes is NOT NULL — the schema-apply phase must persist the no-bytes case (e.g. empty bytea) with parse_result TRANSPORT_ERROR and its accompanying observation_anomalies row: every non-verified result and every relationship anomaly inserts a permanent observation row plus a permanent anomaly row, and the anomaly foreign key requires the observation row to exist.",
  "guards (DISCHARGED): the BEFORE UPDATE / DELETE / TRUNCATE triggers making gateway_observations and observers append-only forever (all observation and anomaly rows are append-only forever; mandatory database test 15) now ship in observation-ledger.sql and are executed against a live PostgreSQL by test/observation-migration-integrity.test.ts.",
  "negative: a duplicate (observer_id, wallet_public_key, wallet_seq) insert is rejected with unique_violation (23505).",
  "negative: a duplicate (domain, owner_id) observers insert is rejected with unique_violation.",
  "negative: malformed sha256_hex, padded_base64url_pubkey, and zkz_balance_text values are rejected by their domains; b_amount takes the balance domain, so '0' is accepted and a value >= 1e8 is rejected.",
  "negative: a non-verified observation row carrying wallet_role or signature material is rejected by the final table CHECK.",
] as const;

export const OBSERVATION_LEDGER_SOURCE =
  "data-model: independent raw observation ledger" as const;
