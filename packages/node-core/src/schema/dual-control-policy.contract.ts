/**
 * Dual-control policy durable home (migration-pack ownership). ZTR-1214.
 *
 * Mode value lives in node_settings (ops.dual_control_mode); changes journal
 * to audit_log. This slice pins pack ordering after those tables exist.
 */

export const DUAL_CONTROL_POLICY_SCHEMA_FILE = "dual-control-policy.sql" as const;

export interface DualControlPolicyInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const DUAL_CONTROL_POLICY_INVARIANTS: readonly DualControlPolicyInvariant[] = [
  {
    id: "REQUIRES_NODE_SETTINGS",
    sqlAnchor: "dual-control-policy requires node_settings (operational-stores)",
    rule:
      "Pack apply fails closed if node_settings is missing — the durable dual-control row cannot exist without the operational KV store.",
  },
  {
    id: "REQUIRES_AUDIT_LOG",
    sqlAnchor: "dual-control-policy requires audit_log",
    rule:
      "Pack apply fails closed if audit_log is missing — policy mutations must be able to journal ops.dual_control_mode_changed.",
  },
  {
    id: "NO_DEFAULT_SEED",
    sqlAnchor: "This slice does NOT seed a default value",
    rule:
      "No INSERT of ops.dual_control_mode: boot-validated DUAL_CONTROL_MODE remains pre-mutation truth so cold apply cannot silently weaken two_human.",
  },
] as const;

export const DUAL_CONTROL_POLICY_EXECUTION_OBLIGATIONS: readonly string[] = [
  "dual-control-policy.sql applies after operational-stores.sql (node_settings) and audit-log.sql.",
  "Runtime createSqlDualControlPolicy writes setting_key=ops.dual_control_mode and audit action ops.dual_control_mode_changed inside the admin mutation TX (SERIALIZABLE).",
] as const;

export const DUAL_CONTROL_POLICY_SOURCE =
  "doc 01 §4.2 dual-control; ZTR-1214 / deferred ZTR-1148 criterion" as const;
