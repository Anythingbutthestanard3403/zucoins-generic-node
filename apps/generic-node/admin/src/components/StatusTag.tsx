const MAP: Record<string, string> = {
  // Success / healthy terminals
  settled: "ok",
  done: "ok",
  available: "ok",
  clear: "ok",
  approved: "ok",
  blessed: "ok",
  landed_verified: "ok",
  verified: "ok",
  receive_landed: "ok",
  send_landed: "ok",
  move_landed: "ok",
  ready: "ok",
  released: "ok",
  active: "ok",

  // In-flight / waiting
  awaiting: "warn",
  parked: "warn",
  awaiting_release: "warn",
  awaiting_arm: "warn",
  allocated: "warn",
  consolidating: "warn",
  created: "warn",
  pending: "warn",
  waiting: "warn",
  indeterminate: "warn",
  leased: "warn",
  pinned: "warn",
  hold: "warn",

  // Failures / custody alarms — never mute QUARANTINED (ZTR-1255)
  quarantined: "danger",
  blocked: "danger",
  exhausted: "danger",
  failed: "danger",
  rejected: "danger",
  invariant_breach: "danger",
  proven_not_started: "danger",
  proven_not_landed: "danger",

  // Neutral terminals
  expired: "muted",
  retired: "muted",
  cancelled: "muted",
};

export function StatusTag({ status }: { status: string }) {
  const raw = typeof status === "string" && status.length > 0 ? status : "unknown";
  const key = raw.toLowerCase().replace(/\s+/g, "_");
  const cls = MAP[key] ?? "muted";
  const label = raw.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  return (
    <span className={`tag ${cls}`} data-testid={`status-tag-${key}`} data-severity={cls}>
      {label}
    </span>
  );
}
