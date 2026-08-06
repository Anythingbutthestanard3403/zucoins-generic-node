import type { NodeHealthUiState } from "../lib/health.js";

export type OfflineBannerProps = {
  healthState: NodeHealthUiState;
  /** Design-preview mode already has its own honesty banner — skip offline claim there. */
  demoMode?: boolean;
};

const COPY: Partial<Record<NodeHealthUiState, string>> = {
  offline:
    "Node unreachable — balances and approvals are unavailable. Showing shell only; never treat offline UI as live money state.",
  degraded:
    "Node degraded — some checks failed. Do not treat balances or approvals as fully verified until the node reports ready.",
};

/**
 * Shell-level honesty banner when the node is offline or degraded.
 * Never invents demo balances as live; never claims healthy without a probe.
 */
export function OfflineBanner({ healthState, demoMode = false }: OfflineBannerProps) {
  if (demoMode) return null;
  const text = COPY[healthState];
  if (!text) return null;
  return (
    <div
      className={`banner banner-offline ${healthState === "offline" ? "banner-error" : "banner-warn"}`}
      role="status"
      aria-live="polite"
      data-testid="offline-honesty-banner"
    >
      {text}
    </div>
  );
}
