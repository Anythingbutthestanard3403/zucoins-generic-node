import { useQuery } from "@tanstack/react-query";
import { useMemo, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { listAuditInventory } from "../../lib/money.js";
import { statusLabel } from "../../lib/labels.js";

export function AuditPage() {
  const [params, setParams] = useSearchParams();
  const actorKind = params.get("actor_kind") ?? "";
  const action = params.get("action") ?? "";
  const operationId = params.get("operation_id") ?? "";
  const [actorDraft, setActorDraft] = useState(actorKind);
  const [actionDraft, setActionDraft] = useState(action);
  const [opDraft, setOpDraft] = useState(operationId);

  const q = useQuery({
    queryKey: ["audit-inventory", actorKind, action],
    queryFn: () =>
      listAuditInventory({
        ...(actorKind ? { actor_kind: actorKind } : {}),
        ...(action ? { action } : {}),
      }),
  });

  const live = q.data?.live === true;
  const allRows = live ? (q.data?.data ?? []) : [];
  const rows = useMemo(() => {
    if (!operationId.trim()) return allRows;
    const needle = operationId.trim().toLowerCase();
    return allRows.filter((r) => (r.operation_id ?? "").toLowerCase().includes(needle));
  }, [allRows, operationId]);

  function applyFilters(e: FormEvent) {
    e.preventDefault();
    const next = new URLSearchParams();
    if (actorDraft.trim()) next.set("actor_kind", actorDraft.trim());
    if (actionDraft.trim()) next.set("action", actionDraft.trim());
    if (opDraft.trim()) next.set("operation_id", opDraft.trim());
    setParams(next);
  }

  if (q.isLoading) {
    return (
      <div className="page">
        <div className="page-title-row">
          <h1>Audit log</h1>
        </div>
        <p className="muted">Loading…</p>
      </div>
    );
  }

  return (
    <div className="page" data-testid="audit-page">
      <div className="page-title-row">
        <h1>Audit log</h1>
      </div>
      <form
        className="card form-card"
        style={{ marginBottom: 16 }}
        onSubmit={applyFilters}
        data-testid="audit-filters"
      >
        <div className="row gap" style={{ flexWrap: "wrap", alignItems: "flex-end" }}>
          <div className="field">
            <label htmlFor="audit-actor">Actor kind</label>
            <input
              id="audit-actor"
              value={actorDraft}
              onChange={(e) => setActorDraft(e.target.value)}
              placeholder="operator"
            />
          </div>
          <div className="field">
            <label htmlFor="audit-action">Action</label>
            <input
              id="audit-action"
              value={actionDraft}
              onChange={(e) => setActionDraft(e.target.value)}
              placeholder="filter action"
            />
          </div>
          <div className="field">
            <label htmlFor="audit-op">Operation id</label>
            <input
              id="audit-op"
              className="mono"
              value={opDraft}
              onChange={(e) => setOpDraft(e.target.value)}
              placeholder="uuid (client filter)"
            />
          </div>
          <button type="submit" className="mini-btn primary">
            Apply filters
          </button>
          <button
            type="button"
            className="mini-btn"
            onClick={() => {
              setActorDraft("");
              setActionDraft("");
              setOpDraft("");
              setParams(new URLSearchParams());
            }}
          >
            Clear
          </button>
        </div>
      </form>
      {!live ? (
        <>
          <p className="muted">Audit inventory unavailable — no audit events are being implied.</p>
          <ApiErrorNote error={q.data?.error} />
        </>
      ) : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={4} className="muted">
                  {live ? "No audit events" : "Audit inventory unavailable"}
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr key={row.id}>
                  <td>{row.created_at}</td>
                  <td title={row.actor_kind}>
                    {statusLabel(row.actor_kind)}
                    {row.actor_id ? ` · ${row.actor_id}` : ""}
                  </td>
                  <td title={row.action}>{statusLabel(row.action)}</td>
                  <td className="mono">
                    {row.operation_id ? (
                      <Link className="linkish" to={`/operations/${row.operation_id}`}>
                        {row.operation_id}
                      </Link>
                    ) : (
                      (row.wallet_id ?? "—")
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
