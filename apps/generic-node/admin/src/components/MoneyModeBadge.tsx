import { moneyModeLabel } from "../lib/labels.js";

const SEVERITY: Readonly<Record<string, string>> = {
  full: "ok",
  receive_only: "warn",
  send_only: "warn",
  internal_only: "muted",
};

/**
 * Compact money-mode chip for wallet list / detail headers.
 * Wire enum stays in data-mode; label is plain language only.
 */
export function MoneyModeBadge({ mode }: { readonly mode: string | null | undefined }) {
  const raw = typeof mode === "string" && mode.length > 0 ? mode : "unknown";
  const key = raw.toLowerCase().replace(/\s+/g, "_");
  const cls = SEVERITY[key] ?? "muted";
  return (
    <span
      className={`tag ${cls}`}
      data-testid={`money-mode-badge-${key}`}
      data-mode={raw}
      data-severity={cls}
      title={raw}
    >
      {moneyModeLabel(raw)}
    </span>
  );
}
