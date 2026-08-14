import { verificationModeLabel } from "../lib/labels.js";

const SEVERITY: Readonly<Record<string, string>> = {
  independent: "muted",
  node_verified: "warn",
};

/**
 * Compact verification-mode chip for operation detail / attention rows (ZTR-1305).
 * Wire enum stays in data-mode; label is plain language only.
 */
export function VerificationModeBadge({
  mode,
}: {
  readonly mode: string | null | undefined;
}) {
  const raw = typeof mode === "string" && mode.length > 0 ? mode : "INDEPENDENT";
  const key = raw.toLowerCase().replace(/\s+/g, "_");
  const cls = SEVERITY[key] ?? "muted";
  return (
    <span
      className={`tag ${cls}`}
      data-testid={`verification-mode-badge-${key}`}
      data-mode={raw}
      data-severity={cls}
      title={raw}
    >
      {verificationModeLabel(raw)}
    </span>
  );
}
