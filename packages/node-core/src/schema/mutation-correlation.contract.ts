/**
 * Contract for mutation-correlation.sql — the deferred parent/child correlation guard that
 * makes `reporting_mutation_idempotency.child_record_id` trustworthy.
 *
 * data-model: operation verification and acknowledgements (§12). The five objects below are
 * frozen contract text in verification-proofs.sql; that file is contract-only and excluded
 * from the pack, so this slice is the shipping copy. The two bodies are byte-identical.
 *
 * `child_record_id` is NOT NULL UNIQUE with no FOREIGN KEY because the child table varies by
 * route. The constraint triggers are the polymorphic equivalent: at COMMIT they resolve the
 * child in the table the declared route selects and require every correlated field to agree.
 */

export const MUTATION_CORRELATION_SCHEMA_FILE = "mutation-correlation.sql" as const;

/** The two functions and three constraint triggers this slice must materialise. */
export const MUTATION_CORRELATION_FUNCTIONS = [
  "reporting_assert_completed_mutation",
  "reporting_validate_mutation_deferred",
] as const;

export const MUTATION_CORRELATION_TRIGGERS = [
  "reporting_completed_parent_has_child",
  "reporting_arm_has_completed_parent",
  "reporting_ack_has_completed_parent",
] as const;

/** Route → child relation the correlation function resolves against. */
export const MUTATION_CORRELATION_CHILD_RELATIONS = {
  operation_armed: "receive_arms",
  verification_complete: "verification_acknowledgements",
} as const;

export interface MutationCorrelationInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const MUTATION_CORRELATION_INVARIANTS: readonly MutationCorrelationInvariant[] = [
  {
    id: "COMPLETED_PARENT_HAS_CHILD",
    sqlAnchor: "CREATE CONSTRAINT TRIGGER reporting_completed_parent_has_child",
    rule: "a completed reporting_mutation_idempotency row whose child_record_id names no matching child row is refused at COMMIT — the parent→child direction the composite FKs never covered.",
  },
  {
    id: "ARM_HAS_COMPLETED_PARENT",
    sqlAnchor: "CREATE CONSTRAINT TRIGGER reporting_arm_has_completed_parent",
    rule: "a receive_arms row whose completion parent does not correlate back to it is refused at COMMIT.",
  },
  {
    id: "ACK_HAS_COMPLETED_PARENT",
    sqlAnchor: "CREATE CONSTRAINT TRIGGER reporting_ack_has_completed_parent",
    rule: "a verification_acknowledgements row whose completion parent does not correlate back to it is refused at COMMIT.",
  },
  {
    id: "DEFERRED_BOTH_DIRECTIONS",
    sqlAnchor: "DEFERRABLE INITIALLY DEFERRED",
    rule: "all three attachments defer to COMMIT, matching the child→parent composite FKs, so parent and child may be written in either sequence inside one transaction.",
  },
  {
    id: "ROUTE_SELECTS_THE_CHILD_RELATION",
    sqlAnchor: "WHEN 'operation_armed' THEN",
    rule: "the child relation is selected by route_id, so a child_record_id belonging to the other route's table resolves to zero matches and is refused.",
  },
  {
    id: "NONCE_AND_FINGERPRINT_MUST_AGREE",
    sqlAnchor: "AND a.reporting_nonce_id = p.reporting_nonce_id",
    rule: "parent and child must share reporting_nonce_id, tenant, route_id, method, raw_target, body sha256 and logical fingerprint — an existing-but-unrelated child is not correlation.",
  },
  {
    id: "UNKNOWN_ROUTE_FAILS_CLOSED",
    sqlAnchor: "RAISE EXCEPTION 'unsupported completed reporting mutation route %'",
    rule: "a route_id with no known child relation raises 23514 rather than passing unchecked.",
  },
] as const;

export const MUTATION_CORRELATION_EXECUTION_OBLIGATIONS: readonly string[] = [
  "mutation-correlation.sql applies after reporting_mutation_idempotency (reporting drizzle 0000), receive-arms.sql and verification-acknowledgements.sql; applied alone it fails on reporting_mutation_idempotency.",
  "It creates no table and no index: two functions and three constraint triggers only.",
  "Both live mutation routes already write child and completion parent on one transaction, so the deferred guard costs them nothing; any writer that cannot is refused at COMMIT by design.",
] as const;

export const MUTATION_CORRELATION_SCHEMA_SOURCE =
  "data-model: operation verification and acknowledgements (deferred mutation correlation)" as const;
