-- Submit attempts and retry authority: a single submit per attempt, the reference scalar
-- checks, and the receipt-only acknowledgement posture (status:true is receipt-only;
-- landing is adjudicated by the landing oracle);
-- the never-blind-retry rule (never blind-retry a submit).
-- Frozen schema contract. This file is contract text: it is
-- executed only by the schema-apply phase against a live database; nothing in this
-- package runs it. Every invariant below is inventoried in submit-attempts.contract.ts
-- and censused by test/submit-attempts.census.test.ts.

-- Reference scalar check (verbatim; the only domain these relations use):

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

-- Submit attempts and retry authority (verbatim):

CREATE TABLE submit_decisions (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  transaction_attempt_no integer NOT NULL CHECK (transaction_attempt_no = 1),
  decision text NOT NULL CHECK (decision = 'INITIAL_SINGLE_SHOT'),
  decided_at timestamptz NOT NULL,
  details text NOT NULL,
  UNIQUE (id, operation_id, transaction_attempt_no),
  UNIQUE (operation_id, transaction_attempt_no),
  FOREIGN KEY (operation_id, transaction_attempt_no)
    REFERENCES operation_transactions(operation_id, attempt_no)
);

CREATE TABLE gateway_submit_attempts (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  attempt_no integer NOT NULL CHECK (attempt_no > 0),
  transaction_attempt_no integer NOT NULL CHECK (transaction_attempt_no > 0),
  decision_id uuid NOT NULL UNIQUE,
  request_body bytea NOT NULL,
  request_sha256 sha256_hex NOT NULL,
  response_body bytea,
  response_sha256 sha256_hex,
  transport_outcome text NOT NULL CHECK (transport_outcome IN
    ('ACK','REJECT','INDETERMINATE')),
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  UNIQUE (operation_id, attempt_no),
  UNIQUE (operation_id, transaction_attempt_no),
  FOREIGN KEY (decision_id, operation_id, transaction_attempt_no)
    REFERENCES submit_decisions(id, operation_id, transaction_attempt_no),
  FOREIGN KEY (operation_id, transaction_attempt_no)
    REFERENCES operation_transactions(operation_id, attempt_no),
  CHECK ((response_body IS NULL) = (response_sha256 IS NULL))
);
