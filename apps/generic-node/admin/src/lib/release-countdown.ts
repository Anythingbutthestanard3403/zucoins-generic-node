/**
 * Operator-facing release countdown (ZTR-1253).
 *
 * Backend expiry is `operations.expiry_unix_time_secs` (unix seconds, text).
 * Receive expiry-release only fires after expiry + RECEIVE_EXPIRY_SAFETY_MARGIN_SECS
 * (30s) — the countdown targets that fire time so it matches when the wallet
 * can actually return, not the raw arm deadline.
 */

/** Mirrors packages/node-core receive expiry-release safety margin. */
export const RELEASE_SAFETY_MARGIN_SECS = 30 as const;

export type ReleaseCountdownState =
  | { kind: "none" }
  | { kind: "terminal"; label: string }
  | { kind: "pre_release"; remainingMs: number; releaseAtMs: number; label: string }
  | { kind: "awaiting_release_proof"; label: string }
  | { kind: "awaiting_verification"; label: string };

const LANDED = /^(RECEIVE_LANDED|INTERNAL_MOVE_LANDED|EXTERNAL_SEND_LANDED)$/;
const TERMINAL = /^(RECEIVE_LANDED|INTERNAL_MOVE_LANDED|EXTERNAL_SEND_LANDED|EXPIRED|REJECTED)$/;

export function parseExpiryUnixSecs(raw: string | null | undefined): number | null {
  if (raw == null || raw === "") return null;
  // Integer unix seconds only — never Number() (amounts-admin/no-float-amount).
  if (!/^[0-9]+$/.test(raw)) return null;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return null;
  return n;
}

export function formatRemaining(ms: number): string {
  const totalSec = Math.max(0, Math.ceil(ms / 1000));
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) {
    return `${h}h ${String(m).padStart(2, "0")}m ${String(s).padStart(2, "0")}s`;
  }
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

/**
 * Derive countdown copy from inventory fields.
 * @param nowMs wall clock for tests
 */
export function deriveReleaseCountdown(input: {
  readonly expiryUnixTimeSecs: string | null | undefined;
  readonly status: string;
  readonly terminalAt: string | null | undefined;
  readonly attentionRequired?: boolean;
  readonly nowMs?: number;
  readonly safetyMarginSecs?: number;
}): ReleaseCountdownState {
  const status = input.status ?? "";
  if (input.terminalAt != null || TERMINAL.test(status)) {
    if (LANDED.test(status)) {
      return {
        kind: "awaiting_verification",
        label: "awaiting implementer verification-complete",
      };
    }
    return { kind: "terminal", label: statusLabel(status) };
  }

  const expirySecs = parseExpiryUnixSecs(input.expiryUnixTimeSecs);
  if (expirySecs === null) return { kind: "none" };

  const margin = input.safetyMarginSecs ?? RELEASE_SAFETY_MARGIN_SECS;
  const releaseAtMs = (expirySecs + margin) * 1000;
  const now = input.nowMs ?? Date.now();
  const remainingMs = releaseAtMs - now;

  if (remainingMs > 0) {
    return {
      kind: "pre_release",
      remainingMs,
      releaseAtMs,
      label: `auto-releases in ${formatRemaining(remainingMs)}`,
    };
  }

  if (input.attentionRequired) {
    return {
      kind: "awaiting_release_proof",
      label: "awaiting release proof — check attention",
    };
  }

  return {
    kind: "awaiting_release_proof",
    label: "awaiting release proof — check attention",
  };
}

function statusLabel(status: string): string {
  return status.replace(/_/g, " ").toLowerCase();
}
