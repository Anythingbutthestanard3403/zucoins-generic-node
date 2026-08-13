import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { CopyButton } from "../../components/CopyButton.js";
import { MoneyModeBadge } from "../../components/MoneyModeBadge.js";
import { StatusTag } from "../../components/StatusTag.js";
import { WalletHoldCause } from "../../components/WalletHoldCause.js";
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
  const sendCapable = rows.filter((w) => w.allow_external_send).length;
  const receiveCapable = rows.filter((w) => w.allow_external_receive).length;

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
      {live && rows.length > 0 && (sendCapable === 0 || receiveCapable === 0) ? (
        <div
          className="banner banner-warn"
          role="status"
          data-testid="wallets-capability-fleet-warning"
          style={{ marginBottom: 16 }}
        >
          {sendCapable === 0 ? (
            <p style={{ margin: 0 }}>
              No send-capable wallet remains (none allow external send). Outgoing may stall until a
              FULL or SEND_ONLY wallet is restored.
            </p>
          ) : null}
          {receiveCapable === 0 ? (
            <p style={{ margin: sendCapable === 0 ? "8px 0 0" : 0 }}>
              No receive-capable wallet remains (none allow external receive). Incoming assign may
              stall until a FULL or RECEIVE_ONLY wallet is restored.
            </p>
          ) : null}
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
              <th>Money mode</th>
              <th>Hold cause</th>
              <th>Recovery</th>
              <th>Observed ZKZ</th>
              <th><span className="visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={8} className="muted">
                  {loading
                      ? "Loading…"
                      : live
                        ? "No wallets"
                        : "Wallets unavailable"}
                </td>
              </tr>
            ) : (
              rows.map((w) => (
                <tr key={w.wallet_id + w.public_key} data-wallet-state={w.state}>
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
                    <MoneyModeBadge mode={w.money_mode} />
                  </td>
                  <td>
                    <WalletHoldCause wallet={w} compact />
                    {!w.holding_operation_id && (w.state ?? "").toUpperCase() === "AVAILABLE" ? (
                      <span className="muted">—</span>
                    ) : null}
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
