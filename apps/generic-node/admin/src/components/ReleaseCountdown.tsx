import { useEffect, useState } from "react";
import {
  deriveReleaseCountdown,
  type ReleaseCountdownState,
} from "../lib/release-countdown.js";

export interface ReleaseCountdownProps {
  readonly expiryUnixTimeSecs: string | null | undefined;
  readonly status: string;
  readonly terminalAt: string | null | undefined;
  readonly attentionRequired?: boolean;
  /** Compact single-line chip for tables. */
  readonly compact?: boolean;
}

export function ReleaseCountdown(props: ReleaseCountdownProps) {
  const [nowMs, setNowMs] = useState(() => Date.now());
  const state = deriveReleaseCountdown({ ...props, nowMs });

  useEffect(() => {
    if (state.kind !== "pre_release") return;
    const id = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [state.kind]);

  if (state.kind === "none") return null;

  return (
    <span
      className={props.compact ? "release-countdown release-countdown-compact" : "release-countdown"}
      data-state={state.kind}
      title={titleFor(state)}
    >
      {state.label}
    </span>
  );
}

function titleFor(state: ReleaseCountdownState): string {
  if (state.kind === "none") return "";
  if (state.kind === "pre_release") {
    return `Release eligible at ${new Date(state.releaseAtMs).toISOString()} (expiry + 30s safety margin)`;
  }
  return state.label;
}
