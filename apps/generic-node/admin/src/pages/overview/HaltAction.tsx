// SPA Emergency Halt control — GET/POST /admin/v1/halt (frozen halt contract).
// Confirm + checkbox gate, then fresh single-use TOTP via useTotpGatedMutation.
// Engage and disengage share the same posture (re-enabling money is never cheaper).

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ApiError } from "../../lib/api.js";
import {
  formatMoneyError,
  isCancelled,
  postHaltToggle,
  type HaltState,
} from "../../lib/money.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

const ENGAGE_WARNING =
  "This immediately halts new automated Outgoing (SEND_EXTERNAL) and Internal transfer (MOVE_INTERNAL) admissions. In-flight items finish; inbound Incoming (RECEIVE_EXTERNAL) continues.";
const DISENGAGE_WARNING = "This re-enables new automated money movement.";

export function HaltAction({
  state,
  loading,
  unavailable = null,
  authorityQueryKey,
}: {
  state: HaltState | undefined;
  loading: boolean;
  unavailable?: string | null;
  authorityQueryKey?: readonly unknown[];
}) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [understood, setUnderstood] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  const toggle = useTotpGatedMutation<HaltState, boolean>(
    async (target, totp) =>
      postHaltToggle(reason.trim() ? { engaged: target, reason: reason.trim() } : { engaged: target }, totp),
    {
      title: "Confirm emergency halt",
      detail: (target) =>
        target
          ? "Enter a fresh TOTP to enlist the kill-switch."
          : "Enter a fresh TOTP to resume money engines.",
      isValid: (target) => {
        if (!authorityQueryKey) {
          return !loading && !unavailable && state?.engaged === !target;
        }
        const authority = queryClient.getQueryState<HaltState>(authorityQueryKey);
        return (
          authority?.status === "success" &&
          authority.fetchStatus === "idle" &&
          authority.data?.engaged === !target
        );
      },
      onSuccess: () => {
        setError(null);
        setConfirming(false);
        setUnderstood(false);
        setReason("");
        void queryClient.invalidateQueries({ queryKey: ["overview", "halt-state"] });
      },
      onError: (err: unknown) => {
        if (isCancelled(err)) return;
        setError(formatMoneyError(err, err instanceof ApiError ? err.message : "Halt toggle failed."));
      },
    },
  );

  const authorityGeneration =
    loading || unavailable || typeof state?.engaged !== "boolean"
      ? "indeterminate"
      : state.engaged
        ? "engaged"
        : "clear";

  useEffect(() => {
    toggle.cancel();
    setConfirming(false);
    setUnderstood(false);
    setReason("");
    setError(null);
    return toggle.cancel;
  }, [authorityGeneration, toggle.cancel]);

  if (unavailable) {
    return (
      <div className="card" data-testid="halt-action">
        <h2>Emergency halt</h2>
        <span className="tag danger" data-testid="halt-badge">UNKNOWN / UNAVAILABLE</span>
        <div className="banner banner-error" role="alert" style={{ marginTop: 12 }}>
          {unavailable}
        </div>
        <p className="muted">
          Retry the halt-state request. Do not assume money rails are open or mutate the halt control
          until the node reports an explicit state.
        </p>
      </div>
    );
  }

  if (loading || !state) {
    return (
      <div className="card" data-testid="halt-action">
        <h2>Emergency halt</h2>
        <p className="muted">Loading…</p>
      </div>
    );
  }

  const engaged = state.engaged;
  const target = !engaged;
  const warning = target ? ENGAGE_WARNING : DISENGAGE_WARNING;

  if (!confirming) {
    return (
      <div className="card" data-testid="halt-action">
        <h2>Emergency halt</h2>
        <span className={`tag ${engaged ? "danger" : "ok"}`} data-testid="halt-badge">
          {engaged ? "Halted" : "Running"}
        </span>
        {engaged && state.reason ? <p className="muted">Reason: {state.reason}</p> : null}
        <div className="pill-row" style={{ marginTop: 12 }}>
          <button
            type="button"
            className="pill danger"
            onClick={() => {
              setError(null);
              setUnderstood(false);
              setConfirming(true);
            }}
          >
            {engaged ? "Resume engines" : "Halt engines"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="card" data-testid="halt-action">
      <h2>Emergency halt</h2>
      <div className="banner banner-error" role="alert">
        {warning}
      </div>
      <label style={{ display: "block", marginTop: 12 }}>
        <input
          type="checkbox"
          checked={understood}
          onChange={(e) => setUnderstood(e.target.checked)}
        />{" "}
        I understand the consequences described above.
      </label>
      <label style={{ display: "block", marginTop: 8 }}>
        Reason (optional)
        <input
          aria-label="Reason (optional)"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          maxLength={500}
          style={{ display: "block", width: "100%", marginTop: 4 }}
        />
      </label>
      {error ? (
        <div className="err" role="alert" style={{ marginTop: 8 }}>
          {error}
        </div>
      ) : null}
      <div className="pill-row" style={{ marginTop: 12 }}>
        <button
          type="button"
          className="pill danger"
          disabled={!understood || toggle.isPending}
          onClick={() => toggle.mutate(target)}
        >
          {toggle.isPending ? "Submitting…" : target ? "Confirm halt" : "Confirm resume"}
        </button>
        <button
          type="button"
          className="pill"
          onClick={() => {
            setConfirming(false);
            setUnderstood(false);
          }}
          disabled={toggle.isPending}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
