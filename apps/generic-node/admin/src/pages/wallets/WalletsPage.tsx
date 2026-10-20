import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { CopyButton } from "../../components/CopyButton.js";
import { MoneyModeBadge } from "../../components/MoneyModeBadge.js";
import { StatusTag } from "../../components/StatusTag.js";
import { WalletHoldCause } from "../../components/WalletHoldCause.js";
import { api, ApiError } from "../../lib/api.js";
import { truncatePubkey } from "../../lib/format.js";
import { listWalletsInventory } from "../../lib/money.js";

function makeIdempotencyKey(prefix: string): string {
  const rand = Math.random().toString(36).slice(2, 12);
  return `${prefix}-${Date.now()}-${rand}`;
}

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

  // Reserve-First UX state (GN-404)
  const [showNewReserveModal, setShowNewReserveModal] = useState(false);
  const [newReserveName, setNewReserveName] = useState("");
  const [newReserveTotp, setNewReserveTotp] = useState("");
  const [newReserveBusy, setNewReserveBusy] = useState(false);
  const [newReserveError, setNewReserveError] = useState<string | null>(null);
  const [workerPoolExpanded, setWorkerPoolExpanded] = useState(false);

  const reserveWallets = rows.filter((w) => w.money_mode === "INTERNAL_ONLY");
  const receiveWorkers = rows.filter((w) => w.money_mode === "RECEIVE_ONLY");
  const sendWorkers = rows.filter((w) => w.money_mode === "SEND_ONLY");

  async function handleCreateReserveWallet(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (!newReserveName.trim() || !newReserveTotp.trim()) return;
    setNewReserveBusy(true);
    setNewReserveError(null);
    try {
      await api("/reserve-wallets", {
        method: "POST",
        totp: newReserveTotp.trim(),
        idempotencyKey: makeIdempotencyKey("reserve-mint"),
        body: JSON.stringify({
          label: newReserveName.trim(),
          display_name: newReserveName.trim(),
          totp_code: newReserveTotp.trim(),
        }),
      });
      setShowNewReserveModal(false);
      setNewReserveName("");
      setNewReserveTotp("");
      await q.refetch();
    } catch (err) {
      if (err instanceof ApiError) {
        setNewReserveError(err.message);
      } else {
        setNewReserveError("Could not create reserve wallet");
      }
    } finally {
      setNewReserveBusy(false);
    }
  }

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Wallets</h1>
        <div className="toolbar">
          <button
            type="button"
            className="mini-btn primary"
            data-testid="new-reserve-wallet-btn"
            onClick={() => {
              setNewReserveError(null);
              setShowNewReserveModal(true);
            }}
          >
            + New Reserve Wallet
          </button>
          <Link to="/destinations" className="filter-btn" data-testid="wallets-link-destinations">
            Blessed Destinations
          </Link>
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

      {/* Primary Section: Reserve Wallets (GN-404) */}
      <section className="card" data-testid="reserve-wallets-section" style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <div>
            <h2 style={{ margin: 0, fontSize: "1rem" }}>Reserve Wallets</h2>
            <p className="muted" style={{ margin: 0, fontSize: "0.85rem" }}>
              Long-lived internal vaults holding consolidated funds (INTERNAL_ONLY).
            </p>
          </div>
          <span className="mono" data-testid="reserve-wallets-count">
            {reserveWallets.length} reserve{reserveWallets.length === 1 ? "" : "s"}
          </span>
        </div>
        {reserveWallets.length > 0 ? (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))",
              gap: 12,
            }}
          >
            {reserveWallets.map((rw, idx) => {
              const rawLabel = (rw as { display_label?: string | null }).display_label;
              const label =
                rawLabel && rawLabel.trim().length > 0
                  ? rawLabel
                  : idx === 0
                    ? "Main Reserve"
                    : `Reserve Wallet #${idx + 1}`;
              return (
                <div
                  key={rw.wallet_id}
                  className="card"
                  data-testid={`reserve-wallet-card-${rw.wallet_id}`}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong>{label}</strong>
                    <span className="mono">{rw.state}</span>
                  </div>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginTop: 6,
                      gap: 8,
                    }}
                  >
                    <Link
                      to={`/wallets/${encodeURIComponent(rw.public_key)}`}
                      className="linkish mono"
                      style={{ fontSize: "0.8rem" }}
                    >
                      {truncatePubkey(rw.public_key, 12, 6)}
                    </Link>
                    <CopyButton value={rw.public_key} />
                  </div>
                  <div className="mono muted" style={{ fontSize: "0.75rem", marginTop: 4 }}>
                    ID: {rw.wallet_id}
                  </div>
                  <div style={{ marginTop: 8, display: "flex", justifyContent: "space-between" }}>
                    <span className="muted">Balance</span>
                    <span className="money">{rw.observed_balance_zkz ?? "0"} ZKZ</span>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="muted" data-testid="reserve-wallets-empty" style={{ margin: 0 }}>
            Provision named Reserve Wallets to segregate funds across connectors or departments.
          </p>
        )}
      </section>

      {/* Collapsible Secondary Drawer: Internal Worker Pool & Consolidation (GN-404) */}
      <section className="card" data-testid="worker-pool-drawer" style={{ marginBottom: 16 }}>
        <button
          type="button"
          className="filter-btn"
          data-testid="worker-pool-toggle"
          aria-expanded={workerPoolExpanded}
          onClick={() => setWorkerPoolExpanded((prev) => !prev)}
          style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center" }}
        >
          <span>Advanced: Internal Worker Pool &amp; Consolidation</span>
          <span className="mono">
            Receive Workers ({receiveWorkers.length}) · Send Workers ({sendWorkers.length})
          </span>
        </button>
        {workerPoolExpanded ? (
          <div data-testid="worker-pool-details" style={{ marginTop: 10 }}>
            <p className="muted" style={{ margin: "0 0 8px" }}>
              Single-use RECEIVE_ONLY and SEND_ONLY worker wallets are automatically managed and consolidated into Reserve Wallets.
            </p>
            <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
              <div>
                <strong>Receive Worker Pool:</strong> {receiveWorkers.length} total
              </div>
              <div>
                <strong>Send Worker Pool:</strong> {sendWorkers.length} total
              </div>
            </div>
          </div>
        ) : null}
      </section>

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

      {showNewReserveModal ? (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-label="New Reserve Wallet"
          data-testid="new-reserve-wallet-modal"
        >
          <div className="card" style={{ maxWidth: 440, margin: "10vh auto" }}>
            <h2 style={{ marginTop: 0 }}>Create New Reserve Wallet</h2>
            <p className="muted">
              Mints a new node-generated INTERNAL_ONLY reserve wallet and blesses its internal consolidation address.
            </p>
            {newReserveError ? (
              <div className="banner banner-error" role="alert" style={{ marginBottom: 12 }}>
                {newReserveError}
              </div>
            ) : null}
            <form onSubmit={(e) => void handleCreateReserveWallet(e)}>
              <div style={{ marginBottom: 12 }}>
                <label htmlFor="reserve-wallet-name">Display Name</label>
                <input
                  id="reserve-wallet-name"
                  data-testid="reserve-wallet-name-input"
                  value={newReserveName}
                  onChange={(e) => setNewReserveName(e.target.value)}
                  placeholder="e.g. Savings Vault"
                  required
                />
              </div>
              <div style={{ marginBottom: 12 }}>
                <label htmlFor="reserve-wallet-totp">Authenticator 6-Digit Code</label>
                <input
                  id="reserve-wallet-totp"
                  className="mono"
                  data-testid="reserve-wallet-totp-input"
                  value={newReserveTotp}
                  onChange={(e) => setNewReserveTotp(e.target.value)}
                  placeholder="123456"
                  maxLength={6}
                  required
                />
              </div>
              <div className="form-actions" style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                <button
                  type="button"
                  className="mini-btn"
                  onClick={() => setShowNewReserveModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="mini-btn primary"
                  data-testid="reserve-wallet-submit-btn"
                  disabled={newReserveBusy || !newReserveName.trim() || !newReserveTotp.trim()}
                >
                  {newReserveBusy ? "Minting…" : "Create Reserve Wallet"}
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}
    </div>
  );
}
