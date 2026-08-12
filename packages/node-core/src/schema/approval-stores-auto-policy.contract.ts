// approval-stores AUTO_POLICY amendment (ZTR-1233): fix-forward for DBs that
// already applied the pre-AUTO_POLICY approval-stores body.
//
// Greenfield shape lives in approval-stores.sql + base-enums-domains.sql.
// This file only inventories the appended ALTER slice.

export const APPROVAL_STORES_AUTO_POLICY_SCHEMA_FILE =
  "approval-stores-auto-policy.sql" as const;

export interface ApprovalStoresAutoPolicyInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const APPROVAL_STORES_AUTO_POLICY_INVARIANTS: readonly ApprovalStoresAutoPolicyInvariant[] =
  [
    {
      id: "DROP_CHALLENGE_NOT_NULL",
      sqlAnchor: "ALTER COLUMN challenge_id DROP NOT NULL",
      rule: "challenge_id becomes nullable so AUTO_POLICY rows carry no fabricated challenge id.",
    },
    {
      id: "DROP_TOTP_NOT_NULL",
      sqlAnchor: "ALTER COLUMN totp_timestep DROP NOT NULL",
      rule: "totp_timestep becomes nullable so AUTO_POLICY rows do not burn the TOTP single-use space.",
    },
    {
      id: "THREE_ARM_CHECK",
      sqlAnchor: "operation_approvals_method_arms_check",
      rule: "replaces the two-arm device biconditional with TOTP_AND_DEVICE / TOTP_ONLY / AUTO_POLICY factor arms.",
    },
    {
      id: "PARTIAL_TOTP_INDEX",
      sqlAnchor:
        "CREATE UNIQUE INDEX IF NOT EXISTS operation_approvals_totp_single_use\n  ON operation_approvals (node_id, totp_timestep)\n  WHERE totp_timestep IS NOT NULL;",
      rule: "TOTP single-use uniqueness applies only when totp_timestep is non-null.",
    },
  ] as const;

export const APPROVAL_STORES_AUTO_POLICY_EXECUTION_OBLIGATIONS: readonly string[] =
  [
    "approval-stores-auto-policy.sql applies after approval-stores.sql and approval-method-auto-policy-enum.sql so operation_approvals exists and AUTO_POLICY is already committed.",
    "Idempotent on greenfield: DROP NOT NULL is a no-op when already nullable; CHECK recreate is gated on AUTO_POLICY presence; index recreate is IF NOT EXISTS after DROP.",
    "Composite FK to approval_challenges is retained (MATCH SIMPLE): NULL challenge_id vacuously passes.",
    "purpose, canonical_version, preimage_text, preimage_sha256, and consumed_at stay NOT NULL for every method.",
  ] as const;

export const APPROVAL_STORES_AUTO_POLICY_SOURCE =
  "data-model: approval_method AUTO_POLICY; ZTR-1233" as const;
