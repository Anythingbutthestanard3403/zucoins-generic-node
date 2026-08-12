import { useQuery } from "@tanstack/react-query";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { listAuditInventory } from "../../lib/money.js";
import { statusLabel } from "../../lib/labels.js";

export function AuditPage() {
  const q = useQuery({
    queryKey: ["audit-inventory"],
    queryFn: listAuditInventory,
    
  });

  if (q.isLoading) {
    return (
      <div className="page">
        <div className="page-title-row"><h1>Audit log</h1></div>
        <p className="muted">Loading…</p>
      </div>
    );
  }

  const live = q.data?.live === true;
  const rows = live ? (q.data?.data ?? []) : [];
  return (
    <div className="page">
      <div className="page-title-row"><h1>Audit log</h1></div>
      {!live ? (
        <>
          <p className="muted">Audit inventory unavailable — no audit events are being implied.</p>
          <ApiErrorNote error={q.data?.error} />
        </>
      ) : null}
      <div className="table-wrap">
        <table>
          <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th></tr></thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
                  {live ? "No audit events" : "Audit inventory unavailable"}
                </td>
              </tr>
            ) : rows.map((row) => (
              <tr key={row.id}>
                <td>{row.created_at}</td>
                <td title={row.actor_kind}>{statusLabel(row.actor_kind)}{row.actor_id ? ` · ${row.actor_id}` : ""}</td>
                <td title={row.action}>{statusLabel(row.action)}</td>
                <td className="mono">{row.operation_id ?? row.wallet_id ?? "—"}</td>
                <td className="mono">—</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
