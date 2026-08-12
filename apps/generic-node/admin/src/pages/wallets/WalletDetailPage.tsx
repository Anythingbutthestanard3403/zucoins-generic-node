import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { CopyButton } from "../../components/CopyButton.js";
import { ReleaseCountdown } from "../../components/ReleaseCountdown.js";
import { StatusTag } from "../../components/StatusTag.js";
import { toApiFailureDetail } from "../../lib/api.js";
import { getWalletInventory } from "../../lib/money.js";

export function WalletDetailPage() {
  const { pubkey = "" } = useParams();
  const q = useQuery({
    queryKey: ["wallet-detail", pubkey],
    queryFn: () => getWalletInventory(pubkey),
    enabled: pubkey.length > 0,
  });
  const w = q.data ?? undefined;

  

  if (q.isLoading) {
    return (
      <div className="page">
        <Link to="/wallets" className="linkish">← Wallets</Link>
        <p className="muted">Loading…</p>
      </div>
    );
  }

  if (!w) {
    return (
      <div className="page">
        <Link to="/wallets" className="linkish">← Wallets</Link>
        <div className="page-title-row"><h1>Wallet</h1></div>
        <p className="muted">
          {q.isError ? "Wallet inventory unavailable — balance not invented." : "Wallet not found."}
        </p>
        {q.isError ? <ApiErrorNote error={toApiFailureDetail(q.error)} /> : null}
        <div className="card form-card detail-grid">
          <div className="detail-item">
            <div className="k">Pubkey</div>
            <div className="v mono">{pubkey || "—"}</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <Link to="/wallets" className="linkish">← Wallets</Link>
      <div className="page-title-row">
        <h1>Wallet</h1>
        <CopyButton value={w.public_key} label="Copy pubkey" />
      </div>
      <div className="card form-card detail-grid">
        <div className="detail-item"><div className="k">Pubkey</div><div className="v mono">{w.public_key}</div></div>
        <div className="detail-item"><div className="k">Origin</div><div className="v">{w.key_origin}</div></div>
        <div className="detail-item"><div className="k">State</div><div className="v"><StatusTag status={w.state} /></div></div>
        <div className="detail-item">
          <div className="k">Observed balance</div>
          <div className="v money">{w.observed_balance_zkz ?? "—"} ZKZ</div>
        </div>
        <div className="detail-item">
          <div className="k">Recovery verified</div>
          <div className="v">
            {w.recovery_verified ? (
              <StatusTag status="VERIFIED" />
            ) : (
              <>
                <StatusTag status="BLOCKED" />
                <Link to="/recovery-ceremony" className="linkish" style={{ marginLeft: 8, fontSize: 12 }}>
                  Continue recovery verification
                </Link>
              </>
            )}
          </div>

        {w.holding_operation_id ? (
          <>
            <div className="detail-item">
              <div className="k">Holding operation</div>
              <div className="v mono">
                <Link to={`/operations/${w.holding_operation_id}`} className="linkish">
                  {w.holding_operation_id}
                </Link>
              </div>
            </div>
            <div className="detail-item">
              <div className="k">Wallet release</div>
              <div className="v">
                <ReleaseCountdown
                  expiryUnixTimeSecs={w.holding_operation_expiry_unix_time_secs}
                  status={w.holding_operation_status ?? w.state}
                  terminalAt={w.holding_operation_terminal_at}
                  attentionRequired={w.holding_operation_attention_required}
                />
              </div>
            </div>
          </>
        ) : null}
        </div>
      </div>
    </div>
  );
}
