import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { StatusTag } from "../../components/StatusTag.js";
import {
  formatMoneyError,
  getRecovery,
  isCancelled,
  listOperationsInventory,
  operationDetailPath,
  partitionRecoveryActions,
  postRecoveryAction,
  recoveryActionLabel,
  type OperationListItem,
  type RecoveryDetail,
} from "../../lib/money.js";
import { apiSoftRead } from "../../lib/api.js";
import { relativeTime } from "../../lib/format.js";
import { EMPTY_NEEDS_ATTENTION, type NeedsAttentionResponse } from "../../lib/ops.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";
import { operationKindLabel, statusLabel } from "../../lib/labels.js";

type Tab = "attention" | "history";

export function OperationsPage() {
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("attention");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detail, setDetail] = useState<RecoveryDetail | null>(null);
  const [detailErr, setDetailErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const attentionQ = useQuery({
    queryKey: ["needs-attention"],
    queryFn: async () =>
      apiSoftRead<NeedsAttentionResponse>("/operations/needs-attention", EMPTY_NEEDS_ATTENTION),
    refetchInterval: 15_000,
  });

  const historyQ = useQuery({
    queryKey: ["operations-history"],
    queryFn: () => listOperationsInventory(),
    enabled: tab === "history",
    refetchInterval: 30_000,
  });

  const live = attentionQ.data?.live ?? false;
  const loading = attentionQ.isLoading;
  const payload = attentionQ.data?.data ?? EMPTY_NEEDS_ATTENTION;
  const ops = payload.operations;
  const summary = payload.summary;

  const historyLive = historyQ.data?.live === true;
  const historyRows: readonly OperationListItem[] = historyLive ? (historyQ.data?.data ?? []) : [];

  const historyCounts = useMemo(() => {
    let landed = 0;
    let open = 0;
    let expired = 0;
    for (const o of historyRows) {
      if (o.terminal_at) {
        if (/EXPIRED/i.test(o.status)) expired += 1;
        else landed += 1;
      } else {
        open += 1;
      }
    }
    return { landed, open, expired, total: historyRows.length };
  }, [historyRows]);

  async function openRecovery(operationId: string) {
    setDetailErr(null);
    setMsg(null);
    setErr(null);
    
    setExpanded(operationId);
    try {
      const d = await getRecovery(operationId);
      setDetail(d);
    } catch (e) {
      setDetail(null);
      setDetailErr(formatMoneyError(e, "Recovery load failed"));
    }
  }

  const act = useTotpGatedMutation(
    async (action: string, totp: string) => {
      if (!detail) throw new Error("No recovery detail");
      const fresh = await getRecovery(detail.operation_id);
      return postRecoveryAction(
        detail.operation_id,
        {
          action,
          expected_row_version: fresh.row_version,
          recovery_nonce: fresh.recovery_nonce,
        },
        totp,
      );
    },
    {
      title: "Confirm recovery action",
      detail: (a) => String(a),
      onSuccess: async () => {
        setErr(null);
        setMsg("Recovery action accepted.");
        if (detail) {
          try {
            setDetail(await getRecovery(detail.operation_id));
          } catch {
            /* keep prior */
          }
        }
        void qc.invalidateQueries({ queryKey: ["needs-attention"] });
        void qc.invalidateQueries({ queryKey: ["operations-history"] });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Recovery action failed"));
      },
    },
  );

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Operations</h1>
        <span className="muted" style={{ fontSize: 12.5 }}>
          {loading
              ? "Loading…"
              : attentionQ.isFetching
                ? "Refreshing…"
                : live && !attentionQ.isError
                  ? "Live"
                  : "Unavailable"}
        </span>
      </div>

      <div className="tabs" style={{ marginBottom: 4 }}>
        <button
          type="button"
          className={`tab ${tab === "attention" ? "on" : ""}`}
          onClick={() => setTab("attention")}
        >
          Needs attention{" "}
          <span className={`n ${live && summary.total > 0 ? "warn" : ""}`}>
            {live ? summary.total : "—"}
          </span>
        </button>
        <button
          type="button"
          className={`tab ${tab === "history" ? "on" : ""}`}
          onClick={() => setTab("history")}
        >
          History{" "}
          <span className="n">{historyLive ? historyCounts.total : "…"}</span>
        </button>
      </div>

      {tab === "attention" ? (
        <>
          <div className="stats" style={{ marginBottom: 16 }}>
            <div className="stat">
              <div className="k">Parked</div>
              <div className="v">{live ? summary.total : "—"}</div>
            </div>
            <div className="stat">
              <div className="k">P0 breach</div>
              <div className="v">{live ? summary.p0_invariant_breach : "—"}</div>
            </div>
          </div>
          <div className="panel">
            {loading ? (
              <p className="muted" style={{ padding: 16, margin: 0 }}>Loading…</p>
            ) : ops.length === 0 ? (
              <>
                <p className="muted" style={{ padding: 16, margin: 0 }}>
                  {attentionQ.isError
                    ? "Could not load attention queue (auth may have expired)."
                    : live
                      ? "No operations need attention."
                      : "Attention queue unavailable — not implying an empty queue."}
                </p>
                {!live ? <ApiErrorNote error={attentionQ.data?.error} /> : null}
                {live ? (
                  <p className="muted" style={{ padding: "0 16px 16px", margin: 0, fontSize: 12.5 }}>
                    Healthy lands do not appear here. Open the{" "}
                    <button type="button" className="linkish" onClick={() => setTab("history")}>
                      History
                    </button>{" "}
                    tab for every operation.
                  </p>
                ) : null}
              </>
            ) : (
              ops.map((a) => (
                <div key={a.operation_id}>
                  <div className="attn">
                    <div className={`type-ic ${a.severity === "P0" ? "danger" : ""}`}>{a.severity}</div>
                    <div className="body-t">
                      <div className="t">
                        {operationKindLabel(a.operation_type)} · {statusLabel(a.status)} <StatusTag status={a.classification} />
                      </div>
                      <div className="d">
                        <code>{a.operation_id}</code>
                        {a.attention_reason ? ` · ${statusLabel(a.attention_reason)}` : ""}
                        {a.attention_since ? ` · ${relativeTime(a.attention_since)}` : ""}
                      </div>
                      {a.classification_rationale ? (
                        <div className="d" style={{ marginTop: 4 }}>
                          {a.classification_rationale}
                        </div>
                      ) : null}
                      <div className="form-actions" style={{ marginTop: 8 }}>
                        <Link
                          className="mini-btn primary"
                          to={operationDetailPath(a.operation_id, a.operation_type)}
                        >
                          Open detail
                        </Link>
                        <button
                          type="button"
                          className="mini-btn"
                          onClick={() => void openRecovery(a.operation_id)}
                        >
                          Quick recovery
                        </button>
                      </div>
                    </div>
                  </div>
                  {expanded === a.operation_id ? (
                    <div className="card form-card" style={{ margin: "0 12px 12px" }}>
                      {detailErr ? <p className="err">{detailErr}</p> : null}
                      {detail ? (
                        <>
                          <p className="muted" style={{ fontSize: 12.5 }}>
                            Nonce issued {detail.recovery_nonce_issued_at} · expires{" "}
                            {detail.recovery_nonce_expires_at} · row {detail.row_version}
                          </p>
                          <p style={{ marginTop: 8, fontSize: 13 }}>
                            {detail.classification}: {detail.classification_rationale}
                          </p>
                          {detail.permitted_actions.length === 0 ? (
                            <p className="muted" style={{ marginTop: 8 }}>
                              No permitted actions
                            </p>
                          ) : (
                            (() => {
                              const { live, unavailable } = partitionRecoveryActions(
                                detail.permitted_actions,
                              );
                              return (
                                <div style={{ marginTop: 12 }}>
                                  {live.length > 0 ? (
                                    <div className="form-actions" style={{ flexWrap: "wrap" }}>
                                      {live.map((action) => (
                                        <button
                                          key={action}
                                          type="button"
                                          className="mini-btn primary"
                                          disabled={act.isPending }
                                          onClick={() => {
                                            setErr(null);
                                            setMsg(null);
                                            act.mutate(action);
                                          }}
                                        >
                                          {recoveryActionLabel(action)}
                                        </button>
                                      ))}
                                    </div>
                                  ) : null}
                                  {unavailable.map(({ action, reason }) => (
                                    <p
                                      key={action}
                                      className="muted"
                                      style={{ fontSize: 12.5, margin: "4px 0" }}
                                    >
                                      <button
                                        type="button"
                                        className="mini-btn"
                                        disabled
                                        aria-disabled="true"
                                      >
                                        {recoveryActionLabel(action)}
                                      </button>
                                      {" — "}
                                      {reason}
                                    </p>
                                  ))}
                                </div>
                              );
                            })()
                          )}
                        </>
                      ) : !detailErr ? (
                        <p className="muted">Loading recovery…</p>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              ))
            )}
          </div>
        </>
      ) : (
        <>
          <div className="stats" style={{ marginBottom: 16 }}>
            <div className="stat">
              <div className="k">Total</div>
              <div className="v">{historyLive ? historyCounts.total : "—"}</div>
            </div>
            <div className="stat">
              <div className="k">Landed / terminal</div>
              <div className="v">{historyLive ? historyCounts.landed : "—"}</div>
            </div>
            <div className="stat">
              <div className="k">In flight</div>
              <div className="v">{historyLive ? historyCounts.open : "—"}</div>
            </div>
            <div className="stat">
              <div className="k">Expired</div>
              <div className="v">{historyLive ? historyCounts.expired : "—"}</div>
            </div>
          </div>
          <div className="table-wrap">
            {historyQ.isLoading ? (
              <p className="muted" style={{ padding: 16, margin: 0 }}>Loading…</p>
            ) : !historyLive ? (
              <>
                <p className="muted" style={{ padding: 16, margin: 0 }}>
                  Operation history unavailable — not implying an empty ledger.
                </p>
                <ApiErrorNote error={historyQ.data?.error} />
              </>
            ) : historyRows.length === 0 ? (
              <p className="muted" style={{ padding: 16, margin: 0 }}>No operations yet.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Reference</th>
                    <th>Amount</th>
                    <th>Status</th>
                    <th>When</th>
                    <th>
                      <span className="visually-hidden">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {historyRows.map((o) => (
                    <tr key={o.operation_id}>
                      <td>{operationKindLabel(o.operation_type)} <span className="quiet mono" style={{ fontSize: 11 }}>{o.operation_type}</span></td>
                      <td className="mono">
                        <Link
                          className="linkish"
                          to={operationDetailPath(o.operation_id, o.operation_type)}
                        >
                          {o.operation_id}
                        </Link>
                      </td>
                      <td className="money">{o.amount_zkz}</td>
                      <td>
                        <StatusTag status={o.status} />
                        {o.attention_required ? (
                          <span className="tag danger" style={{ marginLeft: 6 }}>
                            Attention
                          </span>
                        ) : null}
                      </td>
                      <td className="quiet">{o.updated_at ?? o.created_at}</td>
                      <td>
                        <Link
                          className="linkish"
                          to={operationDetailPath(o.operation_id, o.operation_type)}
                        >
                          View
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {msg ? <div className="banner" style={{ marginTop: 12 }}>{msg}</div> : null}
      {err ? <div className="banner banner-error" style={{ marginTop: 12 }}>{err}</div> : null}
      <p className="muted" style={{ fontSize: 12.5 }}>
        Attention: <code className="mono">GET /admin/v1/operations/needs-attention</code>
        {" · "}
        History: <code className="mono">GET /admin/v1/operations</code>
        {" · "}
        Detail: <code className="mono">GET …/operations/{"{id}"}</code> + recovery
      </p>
    </div>
  );
}
