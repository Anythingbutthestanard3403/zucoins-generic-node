import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { CopyButton } from "../../components/CopyButton.js";
import { ReleaseCountdown } from "../../components/ReleaseCountdown.js";
import { StatusTag } from "../../components/StatusTag.js";
import { truncatePubkey } from "../../lib/format.js";
import { listWalletsInventory } from "../../lib/money.js";

export function WalletsPage() {
  const q = useQuery({
    queryKey: ["wallets-inventory"],
    queryFn: listWalletsInventory,
    refetchInterval: 30_000,
  });
  const live = q.data?.live === true;
  const loading = q.isLoading;
  const rows = live ? (q.data?.data ?? []) : [];
  const verifiedCount = rows.filter((w) => w.recovery_verified).length;
  const blockedCount = rows.filter((w) => !w.recovery_verified).length;
  const zeroEligible = live && !loading && (rows.length === 0 || verifiedCount === 0);

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Wallets</h1>
        <div className="toolbar">
          <span className="filter-btn" style={{ pointerEvents: "none" }}>
            {loading
                ? "Loading…"
                : live
                  ? `Live inventory · ${rows.length}`
                  : "Inventory unavailable"}
          </span>
          <button type="button" className="filter-btn" onClick={() => void q.refetch()}>
            Refresh
          </button>
        </div>
      </div>
      {!loading && !live ? (
        <>
          <p className="muted">Wallet inventory API did not answer — refusing to show demo equity.</p>
          <ApiErrorNote error={q.data?.error} />
        </>
      ) : null}
      {zeroEligible ? (
        <div
          className="banner banner-error"
          role="alert"
          data-testid="wallets-recovery-cta"
          style={{ marginBottom: 16 }}
        >
          <strong>Wallets not recovery-verified — continue setup.</strong>
          {" "}
          Incoming has no eligible pool wallet until at least one node-generated wallet is
          stamped by the recovery-verification ceremony
          {rows.length === 0
            ? " (custody DB has no wallets yet — mint under signer leadership, then verify)."
            : ` (${blockedCount} blocked · ${verifiedCount} verified).`}
          <div className="form-actions" style={{ marginTop: 10 }}>
            <Link to="/recovery-ceremony" className="mini-btn primary">
              Continue recovery verification
            </Link>
            <Link to="/" className="mini-btn">
              Home checklist
            </Link>
          </div>
        </div>
      ) : null}
      {live && rows.length === 0 ? (
        <p className="muted">
          No wallets in custody DB yet. After signer leadership, the receive-pool mint creates
          node-generated keys; observed balances fill when the gateway has reported heads.
          Backup alone does not verify recovery.
        </p>
      ) : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Pubkey</th>
              <th>Origin</th>
              <th>State</th>
              <th>Recovery</th>
              <th>Observed ZKZ</th>
              <th><span className="visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={6} className="muted">
                  {loading
                      ? "Loading…"
                      : live
                        ? "No wallets"
                        : "Wallets unavailable"}
                </td>
              </tr>
            ) : (
              rows.map((w) => (
                <tr key={w.wallet_id + w.public_key}>
                  <td className="mono">
                    <Link to={`/wallets/${encodeURIComponent(w.public_key)}`} className="linkish">
                      {truncatePubkey(w.public_key, 12, 6)}
                    </Link>
                  </td>
                  <td>{w.key_origin}</td>
                  <td>
                    <StatusTag status={w.state} />
                  </td>
                  <td>
                    {w.holding_operation_id ? (
                      <ReleaseCountdown
                        compact
                        expiryUnixTimeSecs={w.holding_operation_expiry_unix_time_secs}
                        status={w.holding_operation_status ?? w.state}
                        terminalAt={w.holding_operation_terminal_at}
                        attentionRequired={w.holding_operation_attention_required}
                      />
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>
                    {w.recovery_verified ? (
                      <StatusTag status="VERIFIED" />
                    ) : (
                      <StatusTag status="BLOCKED" />
                    )}
                  </td>
                  <td className="money">{w.observed_balance_zkz ?? "—"}</td>
                  <td>
                    <CopyButton value={w.public_key} />
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
