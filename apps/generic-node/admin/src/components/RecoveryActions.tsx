/**
 * Shared recovery-action button strip (ZTR-1261).
 * Partitions permitted_actions into live vs unavailable once; used by Approve,
 * Operations quick-recovery, and Transfer detail.
 */

import {
  partitionRecoveryActions,
  recoveryActionLabel,
} from "../lib/money.js";

export interface RecoveryActionsProps {
  readonly permittedActions: readonly string[];
  readonly disabled?: boolean;
  readonly onAction: (action: string) => void;
  /** Button class for live actions (default mini-btn). */
  readonly liveClassName?: string;
  readonly emptyMessage?: string;
  readonly testIdPrefix?: string;
}

export function RecoveryActions({
  permittedActions,
  disabled = false,
  onAction,
  liveClassName = "mini-btn",
  emptyMessage = "No live recovery actions available on this row.",
  testIdPrefix = "recovery-actions",
}: RecoveryActionsProps) {
  if (permittedActions.length === 0) {
    return (
      <p className="muted" style={{ marginTop: 8, fontSize: 12.5 }} data-testid={`${testIdPrefix}-empty`}>
        No permitted recovery actions.
      </p>
    );
  }

  const { live, unavailable } = partitionRecoveryActions(permittedActions);

  return (
    <div data-testid={testIdPrefix} style={{ marginTop: 12 }}>
      {live.length > 0 ? (
        <div className="form-actions" style={{ flexWrap: "wrap" }} data-testid={`${testIdPrefix}-live`}>
          {live.map((action) => (
            <button
              key={action}
              type="button"
              className={liveClassName}
              disabled={disabled}
              onClick={() => onAction(action)}
            >
              {recoveryActionLabel(action)}
            </button>
          ))}
        </div>
      ) : (
        <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
          {emptyMessage}
        </p>
      )}
      {unavailable.length > 0 ? (
        <div
          style={{ marginTop: 6 }}
          data-testid={
            testIdPrefix === "approve-recovery"
              ? "approve-recovery-unimplemented"
              : `${testIdPrefix}-unavailable`
          }
        >
          {unavailable.map(({ action, reason }) => (
            <p
              key={action}
              className="muted"
              style={{ fontSize: 12.5, margin: "4px 0" }}
              data-testid={`${testIdPrefix}-unavailable-item`}
            >
              <button type="button" className="mini-btn" disabled aria-disabled="true">
                {recoveryActionLabel(action)}
              </button>
              {" — "}
              {reason}
            </p>
          ))}
        </div>
      ) : null}
    </div>
  );
}
