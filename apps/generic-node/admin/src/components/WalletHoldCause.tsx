import { Link } from "react-router";
import type { WalletInventoryItem } from "../lib/money.js";
import { operationKindLabel, statusLabel } from "../lib/labels.js";
import { ReleaseCountdown } from "./ReleaseCountdown.js";

/**
 * Operator-facing hold cause for a wallet inventory row (ZTR-1255).
 * Lease projection is sole authority for "why held"; quarantine_reason is
 * the custody-alarm text when state is QUARANTINED. Never collapses distinct
 * states into a bare "busy" pill.
 */
export function walletHoldCauseText(w: WalletInventoryItem): string | null {
  const state = (w.state ?? "").toUpperCase();
  if (state === "QUARANTINED") {
    const reason = w.quarantine_reason?.trim();
    return reason ? `QUARANTINED: ${reason}` : "QUARANTINED";
  }
  if (state === "RETIRED") return "Retired";
  if (w.holding_operation_id) {
    const kind =
      w.holding_operation_type != null && w.holding_operation_type !== ""
        ? operationKindLabel(w.holding_operation_type)
        : w.holding_lease_role != null && w.holding_lease_role !== ""
          ? w.holding_lease_role.replace(/_/g, " ").toLowerCase()
          : "operation";
    const shortId =
      w.holding_operation_id.length > 12
        ? w.holding_operation_id.slice(0, 8)
        : w.holding_operation_id;
    const statusBit =
      w.holding_operation_status != null && w.holding_operation_status !== ""
        ? ` · ${statusLabel(w.holding_operation_status)}`
        : "";
    return `Held by ${kind} ${shortId}${statusBit}`;
  }
  if (state === "PINNED") return "Pinned (no active lease projection)";
  if (state === "AVAILABLE") return null;
  return null;
}

export function WalletHoldCause({
  wallet,
  compact = false,
}: {
  readonly wallet: WalletInventoryItem;
  readonly compact?: boolean;
}) {
  const text = walletHoldCauseText(wallet);
  if (!text && !wallet.holding_operation_id) return null;

  return (
    <span
      className={compact ? "wallet-hold-cause wallet-hold-cause-compact" : "wallet-hold-cause"}
      data-testid="wallet-hold-cause"
      data-state={(wallet.state ?? "").toUpperCase()}
    >
      {text ? <span className="wallet-hold-cause-text">{text}</span> : null}
      {wallet.holding_operation_id ? (
        <>
          {" "}
          <Link
            to={`/operations/${wallet.holding_operation_id}`}
            className="linkish"
            data-testid="wallet-hold-op-link"
          >
            {compact ? "op" : wallet.holding_operation_id}
          </Link>
          {compact ? (
            <>
              {" "}
              <ReleaseCountdown
                compact
                expiryUnixTimeSecs={wallet.holding_operation_expiry_unix_time_secs}
                status={wallet.holding_operation_status ?? wallet.state}
                terminalAt={wallet.holding_operation_terminal_at}
                attentionRequired={wallet.holding_operation_attention_required}
              />
            </>
          ) : null}
        </>
      ) : null}
    </span>
  );
}
