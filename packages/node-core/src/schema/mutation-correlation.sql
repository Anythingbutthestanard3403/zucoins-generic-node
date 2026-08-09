-- Deferred parent/child correlation for completed reporting mutations.
--
-- `reporting_mutation_idempotency.child_record_id` is NOT NULL UNIQUE but cannot carry a
-- real FOREIGN KEY: the child table varies by route (`receive_arms` for `operation_armed`,
-- `verification_acknowledgements` for `verification_complete`). These deferred constraint
-- triggers ARE the polymorphic equivalent — they assert, at COMMIT, that the named child
-- exists in the table the declared route selects and that every correlated field agrees.
-- Without them the column is decorative and a replay can return a cached 200 for a mutation
-- whose child row never landed.
--
-- The definitions below are byte-identical to the frozen contract text in
-- verification-proofs.sql (data-model §12); that file is contract-only and excluded from the
-- pack (MONEY_SCHEMA_PACK_EXCLUDED_AFTER_REPORTING), so this slice is what actually ships.
--
-- DEFERRABLE INITIALLY DEFERRED on all three attachments matches the child→parent composite
-- FKs in receive-arms.sql / verification-acknowledgements.sql, so parent and child may be
-- inserted in either sequence within one transaction. Both live routes already write the
-- child and the completion parent on a single transaction (arm-live.ts writes the parent on
-- the held wallet-lock TX; verification-complete-route.ts freezes the response on the ack TX).
--
-- Prerequisite slices (must exist EARLIER in the apply sequence):
--   reporting-persistence.sql / drizzle 0000 — reporting_mutation_idempotency
--   receive-arms.sql                         — receive_arms
--   verification-acknowledgements.sql        — verification_acknowledgements
-- Applied alone this slice fails on reporting_mutation_idempotency, like every other
-- prerequisite-bound pack slice. Appended slice — never renumber prior slices.

CREATE FUNCTION reporting_assert_completed_mutation(p_idempotency_id uuid)
RETURNS void LANGUAGE plpgsql
AS $$
DECLARE
  p reporting_mutation_idempotency%ROWTYPE;
  matching_children integer;
BEGIN
  SELECT * INTO STRICT p
    FROM reporting_mutation_idempotency
    WHERE id = p_idempotency_id;

  CASE p.route_id
    WHEN 'operation_armed' THEN
      SELECT count(*) INTO matching_children
      FROM receive_arms a
      WHERE a.id = p.child_record_id
        AND a.mutation_idempotency_id = p.id
        AND a.reporting_nonce_id = p.reporting_nonce_id
        AND a.node_id = p.node_id
        AND a.implementer_id = p.implementer_id
        AND a.route_id = p.route_id
        AND a.method = p.method
        AND a.raw_target = p.raw_target
        AND a.request_body_sha256 = p.body_sha256
        AND a.logical_fingerprint = p.logical_fingerprint;
    WHEN 'verification_complete' THEN
      SELECT count(*) INTO matching_children
      FROM verification_acknowledgements a
      WHERE a.id = p.child_record_id
        AND a.mutation_idempotency_id = p.id
        AND a.reporting_nonce_id = p.reporting_nonce_id
        AND a.node_id = p.node_id
        AND a.implementer_id = p.implementer_id
        AND a.route_id = p.route_id
        AND a.method = p.method
        AND a.raw_target = p.raw_target
        AND a.request_body_sha256 = p.body_sha256
        AND a.logical_fingerprint = p.logical_fingerprint;
    ELSE
      RAISE EXCEPTION 'unsupported completed reporting mutation route %', p.route_id
        USING ERRCODE = '23514';
  END CASE;

  IF matching_children <> 1 THEN
    RAISE EXCEPTION 'completed idempotency/child correlation is incomplete'
      USING ERRCODE = '23514';
  END IF;
END
$$;

CREATE FUNCTION reporting_validate_mutation_deferred()
RETURNS trigger LANGUAGE plpgsql
AS $$
DECLARE
  parent_id uuid;
BEGIN
  -- A branch, never a CASE expression: plpgsql resolves EVERY column reference in one
  -- expression against NEW's actual row type, so the unused arm's
  -- `NEW.mutation_idempotency_id` raises 42703 on reporting_mutation_idempotency, which
  -- has no such column. IF arms are planned only when taken.
  IF TG_TABLE_NAME = 'reporting_mutation_idempotency' THEN
    parent_id := NEW.id;
  ELSE
    parent_id := NEW.mutation_idempotency_id;
  END IF;
  PERFORM reporting_assert_completed_mutation(parent_id);
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER reporting_completed_parent_has_child
  AFTER INSERT ON reporting_mutation_idempotency
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_mutation_deferred();
CREATE CONSTRAINT TRIGGER reporting_arm_has_completed_parent
  AFTER INSERT ON receive_arms
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_mutation_deferred();
CREATE CONSTRAINT TRIGGER reporting_ack_has_completed_parent
  AFTER INSERT ON verification_acknowledgements
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_mutation_deferred();
