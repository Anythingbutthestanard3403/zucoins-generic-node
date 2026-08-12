// Home readiness checklist aggregation.
//
// Secret-free operator funnel: each row is status + plain-language detail + deep-link.
// Never includes password/secret/token/private/KEK/ik_ material. Governing product
// rules: the recovery-verification gate, three money ops only, node-origin operator UI.

import { OPERATION_KINDS, type OperationKind } from "@zucoins/generic-node-contracts/operations";

export type ReadinessStatus = "ok" | "blocked" | "optional" | "unknown" | "amber";

export type ReadinessRowId =
  | "node_healthy"
  | "totp_enrolled"
  | "device_enrolled"
  | "recovery_verified_wallet"
  | "reporting_key_active"
  | "implementer_key"
  | "backup_health";

/** Canonical checklist row sequence on Home. */
export const READINESS_ROW_IDS: readonly ReadinessRowId[] = [
  "node_healthy",
  "totp_enrolled",
  "device_enrolled",
  "recovery_verified_wallet",
  "reporting_key_active",
  "implementer_key",
  "backup_health",
] as const;

export type MoneyOpKind = OperationKind;

export interface ReadinessRow {
  readonly id: ReadinessRowId;
  readonly status: ReadinessStatus;
  readonly title: string;
  readonly detail: string;
  readonly href: string;
  readonly blocks_ops?: readonly MoneyOpKind[];
}

export interface ReadinessChecklist {
  readonly object: "readiness_checklist";
  readonly generated_at: string;
  readonly rows: readonly ReadinessRow[];
}

/** Probe inputs — never secrets. Absent signal → unknown (never fake green). */
export interface ReadinessSignals {
  /** /health/ready style verdict when known. */
  readonly nodeStatus?: "ready" | "degraded" | "not_ready" | null;
  /** Active TOTP factor (or usable lab bind) for the session operator. */
  readonly totpEnrolled?: boolean | null;
  /** ≥1 active device key on this node. */
  readonly deviceEnrolled?: boolean | null;
  /** Break-glass authority present (satisfies device dual-control path). */
  readonly breakGlassActive?: boolean | null;
  /**
   * Count of receive-eligible wallets
   * (node_generated ∧ recovery_verified ∧ AVAILABLE when known).
   * null = inventory unavailable.
   */
  readonly recoveryVerifiedEligibleCount?: number | null;
  /**
   * Latest recovery_verified_at among eligible wallets (ISO), when known.
   * Used only for "last pack prove" display — never invents green without stamps.
   */
  readonly lastRecoveryVerifiedAt?: string | null;
  /** ≥1 ACTIVE reporting credential. null = service not wired / list failed. */
  readonly reportingKeyActive?: boolean | null;
  /** ≥1 non-revoked implementer API key, or implementer registered for later issue. */
  readonly implementerKeyPresent?: boolean | null;
  /**
   * Backup schedule health. null = not wired (unknown is OK).
   * amber when schedule on but RPO breached / stale success; blocked only if
   * explicitly failing closed (rare).
   */
  readonly backup?: {
    readonly enabled: boolean;
    /** owner | standby | disabled — standby is not an RPO failure (ZTR-1183). */
    readonly ownership?: "owner" | "standby" | "disabled";
    readonly rpoBreached: boolean;
    readonly lastSuccessAt: string | null;
    readonly consecutiveFailures: number;
  } | null;
}

const ALL_OPS: readonly MoneyOpKind[] = OPERATION_KINDS;

const MONEY_MUTATION_OPS: readonly MoneyOpKind[] = [
  "MOVE_INTERNAL",
  "SEND_EXTERNAL",
];

/** Key/path substrings that must never appear in checklist JSON (case-insensitive). */
export const READINESS_FORBIDDEN_KEY_FRAGMENTS: readonly string[] = [
  "password",
  "secret",
  "token",
  "private",
  "kek",
  "master_key",
  "masterkey",
  "raw_key",
  "raw_private",
  "ik_",
  "sh_",
  "totp_secret",
  "csrf",
  "authorization",
  "cookie",
  "seed",
];

/**
 * Walk a JSON-like value and collect object keys + string leaves that look
 * secret-shaped. Used by the automated leak test and as a last-line assert
 * before the router serializes the body.
 */
export function collectSecretShapedLeaks(value: unknown, path = "$"): string[] {
  const hits: string[] = [];
  if (value === null || value === undefined) return hits;
  if (typeof value === "string") {
    const lower = value.toLowerCase();
    // Bare secret prefixes that must not leak as checklist content.
    if (/(?:^|[^a-z])ik_[a-z0-9_-]{8,}/i.test(value)) {
      hits.push(`${path}=ik_prefix`);
    }
    if (/(?:^|[^a-z])sh_[a-z0-9_-]{8,}/i.test(value)) {
      hits.push(`${path}=sh_prefix`);
    }
    if (lower.includes("begin private") || lower.includes("private key material")) {
      hits.push(`${path}=private_material`);
    }
    return hits;
  }
  if (typeof value !== "object") return hits;
  if (Array.isArray(value)) {
    value.forEach((item, i) => hits.push(...collectSecretShapedLeaks(item, `${path}[${i}]`)));
    return hits;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const keyLower = key.toLowerCase();
    for (const frag of READINESS_FORBIDDEN_KEY_FRAGMENTS) {
      if (keyLower.includes(frag)) {
        hits.push(`${path}.${key}`);
        break;
      }
    }
    hits.push(...collectSecretShapedLeaks(child, `${path}.${key}`));
  }
  return hits;
}

export function assertReadinessSecretFree(body: unknown): void {
  const leaks = collectSecretShapedLeaks(body);
  if (leaks.length > 0) {
    throw new Error(`readiness checklist leaked secret-shaped fields: ${leaks.join(", ")}`);
  }
}

function row(
  id: ReadinessRowId,
  status: ReadinessStatus,
  title: string,
  detail: string,
  href: string,
  blocks_ops?: readonly MoneyOpKind[],
): ReadinessRow {
  return blocks_ops === undefined
    ? { id, status, title, detail, href }
    : { id, status, title, detail, href, blocks_ops };
}

/**
 * Pure truth-table builder. Every canonical id is always present.
 * Missing signals → status "unknown" with honest "not wired yet" detail.
 */
export function buildReadinessChecklist(
  signals: ReadinessSignals,
  nowIso: string = new Date().toISOString(),
): ReadinessChecklist {
  const rows: ReadinessRow[] = [
    buildNodeHealthy(signals),
    buildTotp(signals),
    buildDevice(signals),
    buildRecoveryWallet(signals),
    buildReportingKey(signals),
    buildImplementerKey(signals),
    buildBackup(signals),
  ];

  const checklist: ReadinessChecklist = {
    object: "readiness_checklist",
    generated_at: nowIso,
    rows,
  };
  assertReadinessSecretFree(checklist);
  return checklist;
}

function buildNodeHealthy(s: ReadinessSignals): ReadinessRow {
  const href = "/";
  if (s.nodeStatus === undefined || s.nodeStatus === null) {
    return row(
      "node_healthy",
      "unknown",
      "Node health",
      "Health probe not wired yet — check /health/ready on the node host.",
      href,
    );
  }
  if (s.nodeStatus === "ready") {
    return row("node_healthy", "ok", "Node health", "Ready probe reports ready.", href);
  }
  if (s.nodeStatus === "degraded") {
    return row(
      "node_healthy",
      "amber",
      "Node health",
      "Ready probe reports degraded — some non-gating checks failed.",
      href,
      ALL_OPS,
    );
  }
  return row(
    "node_healthy",
    "blocked",
    "Node health",
    "Ready probe reports not ready — money paths will not admit work.",
    href,
    ALL_OPS,
  );
}

function buildTotp(s: ReadinessSignals): ReadinessRow {
  const href = "/";
  if (s.totpEnrolled === undefined || s.totpEnrolled === null) {
    return row(
      "totp_enrolled",
      "unknown",
      "Operator TOTP",
      "TOTP enrolment status not wired yet.",
      href,
    );
  }
  if (s.totpEnrolled) {
    return row(
      "totp_enrolled",
      "ok",
      "Operator TOTP",
      "Active TOTP factor enrolled for this operator.",
      href,
    );
  }
  return row(
    "totp_enrolled",
    "blocked",
    "Operator TOTP",
    "Enrol and confirm TOTP before money mutations.",
    href,
    MONEY_MUTATION_OPS,
  );
}

function buildDevice(s: ReadinessSignals): ReadinessRow {
  // Manage/second device lives under Devices (not destinations — destinations are day-2 money).
  const href = "/devices";
  const device = s.deviceEnrolled;
  const bg = s.breakGlassActive;

  if (device === undefined && bg === undefined) {
    return row(
      "device_enrolled",
      "unknown",
      "Approval device enrolled",
      "Device / break-glass status not wired yet.",
      href,
    );
  }

  const deviceOk = device === true;
  const bgOk = bg === true;
  if (deviceOk || bgOk) {
    return row(
      "device_enrolled",
      "ok",
      "Approval device enrolled",
      deviceOk
        ? "At least one approval device is enrolled. Manage or add a second device under Devices."
        : "Break-glass authority is active (device path satisfied). Enrol a real device under Devices when you can.",
      href,
    );
  }

  // Known false on both (or device false and bg unknown/false).
  if (device === false || bg === false) {
    return row(
      "device_enrolled",
      "blocked",
      "Approval device enrolled",
      "No active approval device or break-glass authority — bless and hardened approve stay blocked. Enrol under Devices.",
      href,
      ["SEND_EXTERNAL"],
    );
  }

  return row(
    "device_enrolled",
    "unknown",
    "Device enrolment",
    "Device / break-glass status not wired yet.",
    href,
  );
}

function buildRecoveryWallet(s: ReadinessSignals): ReadinessRow {
  // Happy path CTA: pack prove UI (same page as advanced Mode A break-glass).
  const href = "/recovery-ceremony";
  if (s.recoveryVerifiedEligibleCount === undefined || s.recoveryVerifiedEligibleCount === null) {
    return row(
      "recovery_verified_wallet",
      "unknown",
      "Recovery verified",
      "Wallet inventory not available — cannot confirm recovery stamps (never fake green).",
      href,
    );
  }
  // Honesty: recovery OK only when live stamps exist (count > 0). Zero never ok.
  if (s.recoveryVerifiedEligibleCount > 0) {
    const last =
      s.lastRecoveryVerifiedAt != null && s.lastRecoveryVerifiedAt !== ""
        ? ` Last pack prove: ${s.lastRecoveryVerifiedAt}.`
        : "";
    return row(
      "recovery_verified_wallet",
      "ok",
      "Recovery verified",
      `${s.recoveryVerifiedEligibleCount} wallet(s) recovery-verified (stamped).${last} CTA: Verify backup again.`,
      href,
    );
  }
  return row(
    "recovery_verified_wallet",
    "blocked",
    "Recovery verified",
    "No recovery stamps yet — Test backup (pack create + prove). Incoming stays blocked until recovery_verified_at is stamped. Mode A ceremony is advanced/disaster only.",
    href,
    ["RECEIVE_EXTERNAL"],
  );
}

function buildReportingKey(s: ReadinessSignals): ReadinessRow {
  const href = "/reporting-keys";
  if (s.reportingKeyActive === undefined || s.reportingKeyActive === null) {
    return row(
      "reporting_key_active",
      "unknown",
      "Reporting key",
      "Reporting credential inventory not wired yet.",
      href,
    );
  }
  if (s.reportingKeyActive) {
    return row(
      "reporting_key_active",
      "ok",
      "Reporting key",
      "An ACTIVE reporting credential is registered for ARM / transfer_code paths.",
      href,
    );
  }
  return row(
    "reporting_key_active",
    "blocked",
    "Reporting key",
    "No ACTIVE reporting key — issue one before ARM / transfer_code flows.",
    href,
    ["RECEIVE_EXTERNAL", "SEND_EXTERNAL"],
  );
}

function buildImplementerKey(s: ReadinessSignals): ReadinessRow {
  const href = "/api-keys";
  if (s.implementerKeyPresent === undefined || s.implementerKeyPresent === null) {
    return row(
      "implementer_key",
      "unknown",
      "Server API key",
      "Implementer API key inventory not wired yet.",
      href,
    );
  }
  if (s.implementerKeyPresent) {
    return row(
      "implementer_key",
      "ok",
      "Server API key",
      "An implementer API key exists (or the implementer is registered to issue one).",
      href,
    );
  }
  return row(
    "implementer_key",
    "blocked",
    "Server API key",
    "No implementer API key yet — issue a server API key before create calls.",
    href,
    ALL_OPS,
  );
}

function buildBackup(s: ReadinessSignals): ReadinessRow {
  // Primary deep-link: Backup page. Stale/missing also point operators at Recovery
  // verify (recovery verification is separate — never claim backup success = recovery_verified).
  const href = "/recovery-ceremony";
  if (s.backup === undefined || s.backup === null) {
    return row(
      "backup_health",
      "unknown",
      "Backup health",
      "Backup schedule markers unavailable — honest unknown, not fake green. Encrypted backup ≠ recovery verification (see Recovery).",
      href,
    );
  }
  const { enabled, ownership, rpoBreached, lastSuccessAt, consecutiveFailures } = s.backup;
  // Standby replica: schedule is on cluster-wide but this process is not the owner.
  // Distinct from "backups failing" / RPO breach (ZTR-1183).
  if (ownership === "standby") {
    return row(
      "backup_health",
      "optional",
      "Backup health",
      "This replica is not the backup owner (signer leadership not held). Scheduled dumps run only on the leadership holder — local RPO status is not authoritative here.",
      href,
    );
  }
  if (!enabled || ownership === "disabled") {
    return row(
      "backup_health",
      "optional",
      "Backup health",
      "Scheduled backup is off — run encrypted backup via CLI when you need a DR archive. This does not complete recovery verification. Test backup / Verify backup again: /recovery-ceremony",
      href,
    );
  }
  // Never succeeded while schedule is on → red (blocked-style nag), not ok.
  if (lastSuccessAt === null || lastSuccessAt === "") {
    return row(
      "backup_health",
      "amber",
      "Backup health",
      "Schedule on but no successful backup recorded yet. Open Backup for CLI/schedule, then Test backup to verify wallets (encrypted backup ≠ recovery verification).",
      href,
    );
  }
  if (rpoBreached || consecutiveFailures > 0) {
    const age = ` Last success: ${lastSuccessAt}.`;
    const fail =
      consecutiveFailures > 0 ? ` ${consecutiveFailures} consecutive failure(s).` : "";
    return row(
      "backup_health",
      "amber",
      "Backup health",
      `Backup schedule stale or failing.${age}${fail} CTA: Backup page + Verify backup again (/recovery-ceremony). Encrypted backup ≠ recovery verification.`,
      href,
    );
  }
  return row(
    "backup_health",
    "ok",
    "Backup health",
    `Schedule healthy. Last success: ${lastSuccessAt}. (Backup success ≠ recovery_verified.)`,
    href,
  );
}
