/**
 * Per-operation verification_mode column + RELEASED_NODE_VERIFIED release-status
 * widening + ops.allow_node_verified policy home (ZTR-1300 / epic ZTR-1298).
 *
 * Vocabulary is owned by generic-node-contracts verification-mode.contract.ts —
 * this slice inventories the durable SQL surface only.
 */
import {
  ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION,
  ALLOW_NODE_VERIFIED_SETTING_KEY,
  DEFAULT_VERIFICATION_MODE,
  RELEASED_NODE_VERIFIED,
  VERIFICATION_MODES,
} from "@zucoins/generic-node-contracts/operations";

export const VERIFICATION_MODE_SCHEMA_FILE = "verification-mode.sql" as const;

export const VERIFICATION_MODE_EXTENDS = [
  "operations.sql",
  "receive-admission.sql",
  "send-external-create.sql",
  "receive-expiry-release.sql",
  "operator-accepted-risk-release.sql",
  "operational-stores.sql",
  "audit-log.sql",
] as const;

/** Re-export frozen labels so schema consumers import one table. */
export {
  ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION,
  ALLOW_NODE_VERIFIED_SETTING_KEY,
  DEFAULT_VERIFICATION_MODE,
  RELEASED_NODE_VERIFIED,
  VERIFICATION_MODES,
};

export interface VerificationModeSchemaInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const VERIFICATION_MODE_SCHEMA_INVARIANTS: readonly VerificationModeSchemaInvariant[] = [
  {
    id: "REQUIRES_OPERATIONS",
    sqlAnchor: "verification-mode requires operations",
    rule: "Pack apply fails closed if operations is missing — the universal mirror is the primary mode carrier.",
  },
  {
    id: "REQUIRES_RECEIVE_OPERATIONS",
    sqlAnchor: "verification-mode requires receive_operations",
    rule: "Pack apply fails closed if receive_operations is missing — RECEIVE_EXTERNAL projection carries mode at admission.",
  },
  {
    id: "REQUIRES_SEND_OPERATIONS",
    sqlAnchor: "verification-mode requires send_operations",
    rule: "Pack apply fails closed if send_operations is missing — SEND_EXTERNAL projection carries mode at admission.",
  },
  {
    id: "REQUIRES_NODE_SETTINGS",
    sqlAnchor: "verification-mode requires node_settings (operational-stores)",
    rule: "Pack apply fails closed if node_settings is missing — ops.allow_node_verified cannot exist without the KV store.",
  },
  {
    id: "REQUIRES_AUDIT_LOG",
    sqlAnchor: "verification-mode requires audit_log",
    rule: "Pack apply fails closed if audit_log is missing — policy mutations must journal ops.allow_node_verified_changed.",
  },
  {
    id: "OPERATIONS_MODE_DEFAULT_INDEPENDENT",
    sqlAnchor:
      "ADD COLUMN IF NOT EXISTS verification_mode text NOT NULL DEFAULT 'INDEPENDENT'",
    rule: "operations.verification_mode defaults INDEPENDENT so existing rows and omitted inserts are independent by definition.",
  },
  {
    id: "OPERATIONS_MODE_CLOSED",
    sqlAnchor: "chk_operations_verification_mode",
    rule: "operations.verification_mode admits only INDEPENDENT | NODE_VERIFIED.",
  },
  {
    id: "RECEIVE_MODE_CLOSED",
    sqlAnchor: "chk_receive_verification_mode",
    rule: "receive_operations.verification_mode admits only INDEPENDENT | NODE_VERIFIED.",
  },
  {
    id: "SEND_MODE_CLOSED",
    sqlAnchor: "chk_send_verification_mode",
    rule: "send_operations.verification_mode admits only INDEPENDENT | NODE_VERIFIED.",
  },
  // Note: OPERATIONS_MODE_CLOSED / RECEIVE_MODE_CLOSED / SEND_MODE_CLOSED anchors are
  // distinct strings; mutation negatives must target one full conname at a time.
  {
    id: "MODE_CHECK_LABELS",
    sqlAnchor: "CHECK (verification_mode IN ('INDEPENDENT', 'NODE_VERIFIED'))",
    rule: "CHECK predicate text matches VERIFICATION_MODES from contracts; third labels are structural rejects (23514).",
  },
  {
    id: "MODE_IMMUTABLE_FUNCTION",
    sqlAnchor: "VERIFICATION_MODE_IMMUTABLE",
    rule: "BEFORE UPDATE trigger rejects any change to verification_mode after insert (admission-time freeze).",
  },
  {
    id: "RELEASE_STATUS_NODE_VERIFIED",
    sqlAnchor: "RELEASED_NODE_VERIFIED",
    rule: "operations.receive_release_status admits RELEASED_NODE_VERIFIED so node-verified custody close is never misread as expiry or operator-risk release.",
  },
  {
    id: "NO_POLICY_SEED",
    sqlAnchor: "This slice does NOT seed a row",
    rule: "No INSERT of ops.allow_node_verified: absent document remains fail-closed refuse of NODE_VERIFIED at admission.",
  },
] as const;

export const VERIFICATION_MODE_SCHEMA_EXECUTION_OBLIGATIONS: readonly string[] = [
  "verification-mode.sql applies after operations, receive-admission, send-external-create, receive-expiry-release, operator-accepted-risk-release, operational-stores (node_settings), and audit-log.",
  "DEFAULT 'INDEPENDENT' is the backfill: every pre-existing row is independent by definition; no explicit UPDATE required.",
  "MOVE_INTERNAL has no projection table — mode lives only on operations for moves.",
  "Runtime policy writers (ZTR-1301+) use node_settings key ops.allow_node_verified and audit action ops.allow_node_verified_changed; this slice only pins pack sequence.",
  "CHECK violation on a third mode label is proven by verification-mode.pg.test.ts (SQLSTATE 23514).",
] as const;

export const VERIFICATION_MODE_SCHEMA_SOURCE =
  "ZTR-1300 schema slice; epic ZTR-1298; contracts verification-mode.contract.ts (ZTR-1299)" as const;

/** Compile-time pin: schema DEFAULT matches contracts DEFAULT. */
const _defaultPin: typeof DEFAULT_VERIFICATION_MODE = "INDEPENDENT";
void _defaultPin;

/** Compile-time pin: schema CHECK labels match contracts VERIFICATION_MODES. */
const _modesPin: readonly ["INDEPENDENT", "NODE_VERIFIED"] = VERIFICATION_MODES;
void _modesPin;

/** Compile-time pin: release token matches contracts. */
const _releasePin: typeof RELEASED_NODE_VERIFIED = "RELEASED_NODE_VERIFIED";
void _releasePin;

/** Compile-time pin: policy key / audit action match contracts. */
const _policyKeyPin: typeof ALLOW_NODE_VERIFIED_SETTING_KEY = "ops.allow_node_verified";
void _policyKeyPin;
const _policyActionPin: typeof ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION =
  "ops.allow_node_verified_changed";
void _policyActionPin;
