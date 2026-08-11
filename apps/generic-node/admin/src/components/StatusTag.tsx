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
  sweeping: "warn",
  created: "warn",
  pending: "warn",
  waiting: "warn",
  indeterminate: "warn",
  busy: "warn",
  leased: "warn",
  pinned: "warn",
  hold: "warn",

  // Failures
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
  const key = status.toLowerCase().replace(/\s+/g, "_");
  const cls = MAP[key] ?? "muted";
  const label = status.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  return <span className={`tag ${cls}`}>{label}</span>;
}
