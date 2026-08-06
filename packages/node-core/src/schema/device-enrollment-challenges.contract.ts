// Device enrollment challenges for zp-device-enrol-v1.
//
// Frozen inventory of the structural enrollment-challenge invariants carried by
// device-enrollment-challenges.sql. There is no separately frozen shape for a dedicated
// table, so the slice mirrors approval_challenges (status enum, unique nonce,
// issued/expires CHECK, superseded_by) rather than inventing a new pattern. The census
// binds every entry here to the literal SQL text. Execution against a live database
// belongs to the schema-apply phase.
//
// Note: this contract file was missing when device-enrollment-challenges.sql landed on
// main (inventory red). Added so SCHEMA_FILES registration stays exact
// while reporting-persistence.sql is registered alongside.

export const DEVICE_ENROLLMENT_CHALLENGES_SCHEMA_FILE =
  "device-enrollment-challenges.sql" as const;

export interface DeviceEnrollmentChallengeInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const DEVICE_ENROLLMENT_CHALLENGES_INVARIANTS: readonly DeviceEnrollmentChallengeInvariant[] =
  [
    {
      id: "CHALLENGE_NODE_SCOPED",
      sqlAnchor: "node_id uuid NOT NULL REFERENCES nodes(id),",
      rule: "every enrollment challenge is bound to one node: a challenge issued on one node confers no enrollment right on another.",
    },
    {
      id: "CHALLENGE_PURPOSE_CLOSED",
      sqlAnchor: "purpose text NOT NULL CHECK (purpose = 'zp-device-enrol-v1'),",
      rule: "the only representable purpose is zp-device-enrol-v1 (A.4.3): no other enrollment purpose is admissible on this table.",
    },
    {
      id: "CHALLENGE_NONCE_UNIQUE",
      sqlAnchor: "nonce uuid NOT NULL UNIQUE,",
      rule: "each challenge nonce is globally unique (mirrors approval_challenges): a second insert of the same nonce is a unique_violation, never a silent reuse.",
    },
    {
      id: "CHALLENGE_ONE_ISSUED_PER_NODE",
      sqlAnchor:
        "CREATE UNIQUE INDEX device_enrollment_challenges_one_issued_per_node\n  ON device_enrollment_challenges(node_id)\n  WHERE status = 'ISSUED';",
      rule: "at most one ISSUED challenge per node (partial unique index): a second concurrent issue is rejected by the database, not by a caller's memory.",
    },
    {
      id: "CHALLENGE_EXPIRES_AFTER_ISSUED",
      sqlAnchor: "CHECK (expires_at > issued_at),",
      rule: "expires_at is strictly after issued_at: a zero- or negative-duration challenge is not representable.",
    },
    {
      id: "CHALLENGE_SUPERSEDED_CONSISTENT",
      sqlAnchor:
        "CHECK ((status = 'SUPERSEDED') = (superseded_by IS NOT NULL))",
      rule: "SUPERSEDED status and superseded_by are co-present: a superseded row always points at its successor, and a non-superseded row never does.",
    },
  ] as const;
