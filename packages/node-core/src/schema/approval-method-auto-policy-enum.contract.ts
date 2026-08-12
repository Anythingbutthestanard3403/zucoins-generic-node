// approval_method += AUTO_POLICY (ZTR-1233). Enum-only fix-forward slice.

export const APPROVAL_METHOD_AUTO_POLICY_ENUM_SCHEMA_FILE =
  "approval-method-auto-policy-enum.sql" as const;

export interface ApprovalMethodAutoPolicyEnumInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const APPROVAL_METHOD_AUTO_POLICY_ENUM_INVARIANTS: readonly ApprovalMethodAutoPolicyEnumInvariant[] =
  [
    {
      id: "ADD_AUTO_POLICY_ENUM",
      sqlAnchor: "ALTER TYPE approval_method ADD VALUE 'AUTO_POLICY'",
      rule: "idempotently admits AUTO_POLICY on already-applied approval_method enums; own slice so the ADD VALUE transaction commits before later CHECKs reference the label.",
    },
  ] as const;

export const APPROVAL_METHOD_AUTO_POLICY_ENUM_EXECUTION_OBLIGATIONS: readonly string[] =
  [
    "Must pack sequence before approval-stores-auto-policy so ADD VALUE is committed before the three-arm CHECK references AUTO_POLICY.",
    "Idempotent: no-op when base-enums-domains already created the 3-value enum (greenfield).",
  ] as const;

export const APPROVAL_METHOD_AUTO_POLICY_ENUM_SOURCE =
  "data-model: approval_method AUTO_POLICY; ZTR-1233" as const;
