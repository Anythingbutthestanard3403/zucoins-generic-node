import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { StatusTag } from "../../components/StatusTag.js";
import { listSendOperationsInventory } from "../../lib/money.js";
import { isPackEnabled, loadEnabledPacks } from "../../lib/packs.js";

export function TransfersPage() {
  const q = useQuery({
    queryKey: ["transfers-inventory"],
    queryFn: async () => {
      
      const r = await listSendOperationsInventory();
      return {
        live: r.live,
        error: r.error,
        data: r.data.map((o) => ({
          operation_id: o.operation_id,
          from: "—",
          to: o.destination_address ?? "—",
          amount_zkz: o.amount_zkz,
          status: o.status,
        })),
      };
    },
  });

  const rows = q.data?.data ?? [];
  const live = q.data?.live ?? false;
  const loading = q.isLoading;

  const packP = isPackEnabled(loadEnabledPacks(), "P");

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Transfers</h1>
        <div className="toolbar">
          <span className="muted" style={{ fontSize: 12.5 }}>
            {loading
                ? "Loading…"
                : live
                  ? "Live inventory"
                  : "No inventory — open by id"}
          </span>
          <span className="muted" style={{ fontSize: 12.5 }}>
            Sends are created via implementer{" "}
            <code className="mono">POST /v1/external-sends</code> — approve/reject below
          </span>
        </div>
      </div>
      {packP ? (
        <div
          className="banner"
          role="note"
          data-testid="pack-p-dual-control"
          style={{ marginBottom: 16 }}
        >
          <strong>Pack P — External sends.</strong> Someone requests SEND via implementer API
          (server-side). Approver uses this inbox with TOTP + device sign. The node does{" "}
          <em>not</em> chain-submit SEND. After approve, status may be waiting for recipient to
          finish — approve alone is not paid. Observe-land is separate.
        </div>
      ) : null}

      {!loading && !live ? (
        <>
          <p className="muted" style={{ marginBottom: 12, fontSize: 12.5 }}>
            Outgoing send inventory unavailable.
            Paste a CREATED operation id into the URL{" "}
            <code className="mono">{"/transfers/{operation_id}"}</code> to approve/reject.
          </p>
          <ApiErrorNote error={q.data?.error} />
        </>
      ) : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>From</th>
              <th>To</th>
              <th>Amount</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
                  {loading
                      ? "Loading…"
                      : live
                        ? "No transfers"
                        : "Transfers unavailable"}
                </td>
              </tr>
            ) : (
              rows.map((t) => (
                <tr key={t.operation_id}>
                  <td className="mono">
                    <Link className="linkish" to={`/transfers/${t.operation_id}`}>
                      {t.operation_id}
                    </Link>
                  </td>
                  <td>{t.from}</td>
                  <td className="mono">{t.to}</td>
                  <td className="money">{t.amount_zkz}</td>
                  <td>
                    <StatusTag status={t.status} />
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
