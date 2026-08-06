/**
 * Single-source plain-language maps for the operator SPA.
 * Wire enums / API / DB values are NEVER renamed — these labels are display-only.
 */

/** Protocol three-ops → primary UI label. */
export const OPERATION_KIND_LABELS = {
  RECEIVE_EXTERNAL: "Incoming",
  MOVE_INTERNAL: "Internal transfer",
  SEND_EXTERNAL: "Outgoing (needs approval)",
} as const;

export type OperationKindKey = keyof typeof OPERATION_KIND_LABELS;

/** Status / formation / attention codes → operator text. */
export const STATUS_LABELS: Readonly<Record<string, string>> = {
  NO_ELIGIBLE_WALLET: "Wallets not recovery-verified — continue setup",
  AWAITING_REDEMPTION: "Waiting for recipient to finish",
  APPROVED: "Approved — recipient must finish; observe-land is separate",
  LANDED_VERIFIED: "Landed and verified",
  PROVEN_NOT_STARTED: "Proven not started",
  PROVEN_NOT_LANDED: "Proven not landed",
  WAITING: "Waiting",
  INDETERMINATE: "Indeterminate",
  INVARIANT_BREACH: "Invariant breach",
  CREATED: "Created",
  REJECTED: "Rejected",
  NEEDS_ATTENTION: "Needs attention",
  AVAILABLE: "Available",
  BLOCKED: "Blocked",
  VERIFIED: "Verified",
};

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
 * Operator-facing status text. Unknown codes keep a light humanize
 * (underscores → spaces) without claiming settlement/"paid".
 */
export function statusLabel(status: string | null | undefined): string {
  if (status == null || status === "") return "—";
  const key = status.trim();
  const upper = key.toUpperCase();
  if (upper in STATUS_LABELS) return STATUS_LABELS[upper]!;
  if (key in STATUS_LABELS) return STATUS_LABELS[key]!;
  return key.replace(/_/g, " ");
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
