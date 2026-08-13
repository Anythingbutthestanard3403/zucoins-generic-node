/**
 * Single-source plain-language maps for the operator SPA.
 * Wire enums / API / DB values are NEVER renamed — these labels are display-only.
 * Census tests pin coverage against @zucoins/generic-node-contracts enums.
 */

/** Protocol three-ops → primary UI label. */
export const OPERATION_KIND_LABELS = {
  RECEIVE_EXTERNAL: "Incoming",
  MOVE_INTERNAL: "Internal transfer",
  SEND_EXTERNAL: "Outgoing (needs approval)",
} as const;

/**
 * Per-wallet money capability presets (ZTR-1269) — short chip + help copy.
 * Drift-safe wording: hub / internal-only / float — not forbidden stems.
 */
export const MONEY_MODE_LABELS = {
  RECEIVE_ONLY: {
    short: "Receive only",
    help: "Accepts external incoming funds and internal transfers. Cannot be a source for external outgoing.",
  },
  SEND_ONLY: {
    short: "Send only",
    help: "Can source external outgoing and internal transfers. Does not accept external incoming assign.",
  },
  INTERNAL_ONLY: {
    short: "Internal only",
    help: "Hub float: internal transfers only. Never external send or receive. Multiple internal-only wallets are allowed.",
  },
  FULL: {
    short: "Full",
    help: "Unrestricted: external receive, external send, and internal transfers (default).",
  },
} as const;

export type MoneyModeKey = keyof typeof MONEY_MODE_LABELS;

export function moneyModeLabel(mode: string | null | undefined): string {
  if (mode == null || mode === "") return "Unknown";
  const key = mode.trim().toUpperCase() as MoneyModeKey;
  return MONEY_MODE_LABELS[key]?.short ?? mode;
}

export function moneyModeHelp(mode: string | null | undefined): string {
  if (mode == null || mode === "") return "Mode unknown.";
  const key = mode.trim().toUpperCase() as MoneyModeKey;
  return MONEY_MODE_LABELS[key]?.help ?? "Unrecognised money mode.";
}

export type OperationKindKey = keyof typeof OPERATION_KIND_LABELS;

/** Status / formation / attention / inventory codes → operator text. */
export const STATUS_LABELS: Readonly<Record<string, string>> = {
  // Operation status (OPERATION_STATUS)
  CREATED: "Created",
  READY: "Ready",
  RECEIVE_LANDED: "Receive landed",
  INTERNAL_MOVE_LANDED: "Internal transfer landed",
  APPROVED: "Approved — recipient must finish; observe-land is separate",
  AWAITING_REDEMPTION: "Waiting for recipient to finish",
  EXTERNAL_SEND_LANDED: "Outgoing landed",
  EXPIRED: "Expired",
  REJECTED: "Rejected",
  NEEDS_ATTENTION: "Needs attention",

  // Recovery classification
  LANDED_VERIFIED: "Landed and verified",
  PROVEN_NOT_STARTED: "Proven not started",
  PROVEN_NOT_LANDED: "Proven not landed",
  WAITING: "Waiting",
  INDETERMINATE: "Indeterminate",
  INVARIANT_BREACH: "Invariant breach",

  // Wallet / destination / generic inventory
  AVAILABLE: "Available",
  PINNED: "Pinned",
  QUARANTINED: "Quarantined",
  RETIRED: "Retired",
  BLOCKED: "Blocked",
  VERIFIED: "Verified",
  PENDING: "Pending",
  BLESSED: "Blessed",
  ACTIVE: "Active",
  REVOKED: "Revoked",
  LOST: "Marked lost",
  DISABLED: "Disabled",
  ENABLED: "Enabled",

  // Formation (NO_ELIGIBLE + EXTERNAL_FORMATION_STATE)
  NO_ELIGIBLE_WALLET: "Wallets not recovery-verified — continue setup",
  NOT_REQUIRED: "Formation not required",
  APPROVAL_PENDING: "Approval pending",
  APPROVED_UNSIGNED: "Approved — signature not yet applied",
  SIGNING_CLAIMED: "Signing in progress",
  PARTIAL_PERSISTED: "Partial formation persisted",
  PARTIAL_DELIVERED: "Partial formation delivered",

  // After-landing policy
  HOLD: "Hold in receive wallet",
  INTERNAL_MOVE: "Move to blessed sink after landing",

  // Attention reasons (ATTENTION_REASONS — 15)
  GATEWAY_RESPONSE_INVALID: "Gateway response invalid",
  GATEWAY_UNAVAILABLE_BEYOND_BUDGET: "Gateway unavailable beyond budget",
  UNEXPECTED_HEAD_CHANGE: "Unexpected head change",
  LINEAGE_GAP: "Lineage gap",
  SUBMIT_OUTCOME_AMBIGUOUS: "Submit outcome ambiguous",
  SIGNING_OUTCOME_AMBIGUOUS: "Signing outcome ambiguous",
  DESTINATION_NO_LONGER_BLESSED: "Destination no longer blessed",
  T0_RELEASE_MISMATCH: "T0 release mismatch",
  VERIFICATION_REJECTED: "Verification rejected",
  VERIFICATION_INDETERMINATE: "Verification indeterminate",
  VERIFICATION_RESOURCE_EXHAUSTED: "Verification resource exhausted",
  LEASE_INVARIANT_VIOLATION: "Lease invariant violation",
  EXACT_BYTES_UNAVAILABLE: "Exact bytes unavailable",
  OPERATOR_PARKED: "Operator parked",
  POST_EXPIRY_RECONCILING: "Post-expiry reconciling",

  // Challenge / approval method
  ISSUED: "Issued",
  CONSUMED: "Consumed",
  SUPERSEDED: "Superseded",
  TOTP_ONLY: "TOTP only",
  TOTP_AND_DEVICE: "TOTP and device",
  AUTO_POLICY: "Auto-policy",

  // Audit actor kinds (common)
  operator: "Operator",
  OPERATOR: "Operator",
  system: "System",
  SYSTEM: "System",
  implementer: "Integration",
  IMPLEMENTER: "Integration",
  service: "Service",
  SERVICE: "Service",
};

/** Severity codes from needs-attention rows. */
export const SEVERITY_LABELS: Readonly<Record<string, string>> = {
  P0: "P0 — act now",
  P1: "P1 — act this shift",
  P2: "P2 — plan soon",
};

/** Humanize unknown SCREAMING_SNAKE / mixed tokens without claiming product meaning. */
export function humanizeWire(code: string): string {
  return code
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Primary label for an operation kind. Unknown kinds fall back to a
 * humanized form of the raw enum (never invents a fourth money verb).
 */
export function operationKindLabel(kind: string | null | undefined): string {
  if (kind == null || kind === "") return "—";
  const key = kind.trim().toUpperCase();
  if (key in OPERATION_KIND_LABELS) {
    return OPERATION_KIND_LABELS[key as OperationKindKey];
  }
  return kind.replace(/_/g, " ");
}

/** Wire enum kept as secondary mono text for support. */
export function operationKindWire(kind: string | null | undefined): string {
  if (kind == null || kind === "") return "";
  return kind.trim().toUpperCase();
}

/** Combined "Incoming · RECEIVE_EXTERNAL" for dense rows. */
export function operationKindDisplay(kind: string | null | undefined): string {
  const primary = operationKindLabel(kind);
  const wire = operationKindWire(kind);
  if (!wire || primary === wire || primary === "—") return primary;
  // Only append wire when we mapped a known three-op.
  if (wire in OPERATION_KIND_LABELS) return `${primary}`;
  return primary;
}

/**
 * Operator-facing status / enum text. Unknown codes keep a light humanize
 * (underscores → spaces) without claiming settlement/"paid".
 */
export function statusLabel(status: string | null | undefined): string {
  if (status == null || status === "") return "—";
  const key = status.trim();
  const upper = key.toUpperCase();
  if (upper in STATUS_LABELS) return STATUS_LABELS[upper]!;
  if (key in STATUS_LABELS) return STATUS_LABELS[key]!;
  return humanizeWire(key);
}

/**
 * Primary label + optional wire secondary for deliberate pairing
 * ("Waiting for recipient · AWAITING_REDEMPTION").
 */
export function statusLabelWithWire(status: string | null | undefined): {
  readonly primary: string;
  readonly wire: string;
} {
  if (status == null || status === "") return { primary: "—", wire: "" };
  const wire = status.trim();
  const primary = statusLabel(wire);
  return { primary, wire: primary === wire || primary === humanizeWire(wire) ? "" : wire };
}

/** Severity badge text — always carries meaning. */
export function severityLabel(severity: string | null | undefined): string {
  if (severity == null || severity === "") return "—";
  const key = severity.trim().toUpperCase();
  return SEVERITY_LABELS[key] ?? severityLabelFallback(key);
}

function severityLabelFallback(key: string): string {
  if (key.startsWith("P") && key.length <= 3) return `${key} — review priority`;
  return humanizeWire(key);
}

/** Short severity for compact type-ic chips (still meaningful). */
export function severityShort(severity: string | null | undefined): string {
  if (severity == null || severity === "") return "—";
  const key = severity.trim().toUpperCase();
  if (key === "P0") return "P0 now";
  if (key === "P1") return "P1 shift";
  if (key === "P2") return "P2 plan";
  return key;
}

/**
 * Secret-prefix family labels (display beside truncated prefixes only —
 * never invent or echo full secrets).
 */
export function credentialPrefixKind(prefix: string | null | undefined): string {
  if (prefix == null || prefix === "") return "Credential";
  if (prefix.startsWith("ik_")) return "Server API key";
  if (prefix.startsWith("sh_")) return "Status subscription secret";
  return "Credential";
}

/** True when a raw code is the NO_ELIGIBLE_WALLET formation/attention class. */
export function isNoEligibleWallet(code: string | null | undefined): boolean {
  if (code == null) return false;
  return code.toUpperCase().includes("NO_ELIGIBLE_WALLET");
}

/** Approve/success banners must never say "paid". */
export const APPROVE_SUCCESS_NOTE =
  "Approval alone is not settlement — recipient must finish; observe-land is separate.";

/** Resolve integration/implementer id → display name; UUID remains title for hover. */
export function implementerDisplayName(
  id: string | null | undefined,
  rows: readonly { readonly id: string; readonly name: string }[] | undefined,
): string {
  if (id == null || id === "") return "—";
  const hit = rows?.find((r) => r.id === id);
  if (hit?.name) return hit.name;
  if (id.length > 12) return `${id.slice(0, 8)}…`;
  return id;
}
