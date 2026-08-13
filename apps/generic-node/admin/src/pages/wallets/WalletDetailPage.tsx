import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { CopyButton } from "../../components/CopyButton.js";
import { MoneyModeBadge } from "../../components/MoneyModeBadge.js";
import { ReleaseCountdown } from "../../components/ReleaseCountdown.js";
import { StatusTag } from "../../components/StatusTag.js";
import { WalletHoldCause } from "../../components/WalletHoldCause.js";
import { toApiFailureDetail } from "../../lib/api.js";
import { MONEY_MODE_LABELS, moneyModeHelp, moneyModeLabel } from "../../lib/labels.js";
import {
  formatMoneyError,
  getWalletInventory,
  isCancelled,
  listWalletsInventory,
  patchWalletMoneyCapability,
  type WalletMoneyMode,
} from "../../lib/money.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

const MODES = Object.keys(MONEY_MODE_LABELS) as WalletMoneyMode[];

export function WalletDetailPage() {
  const { pubkey = "" } = useParams();
  const queryClient = useQueryClient();
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [selectedMode, setSelectedMode] = useState<WalletMoneyMode | "">("");
  const [fleetWarning, setFleetWarning] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["wallet-detail", pubkey],
    queryFn: () => getWalletInventory(pubkey),
    enabled: pubkey.length > 0,
  });
  const w = q.data ?? undefined;

  const fleetQ = useQuery({
    queryKey: ["wallets-inventory"],
    queryFn: listWalletsInventory,
    enabled: w !== undefined,
    staleTime: 15_000,
  });

  const currentMode = (w?.money_mode ?? "FULL") as WalletMoneyMode;
  const effectiveSelected = selectedMode || currentMode;

  const confirmHint = useMemo(() => {
    if (!w) return null;
    if (effectiveSelected === currentMode) return null;
    const strippingSend =
      w.allow_external_send &&
      (effectiveSelected === "RECEIVE_ONLY" || effectiveSelected === "INTERNAL_ONLY");
    const fundedInternal =
      effectiveSelected === "INTERNAL_ONLY" &&
      w.observed_balance_zkz != null &&
      w.observed_balance_zkz !== "" &&
      w.observed_balance_zkz !== "0" &&
      w.observed_balance_zkz !== "0.0000";
    if (strippingSend && fundedInternal) {
      return "This wallet holds a non-zero observed balance and will lose external send. Internal-only hubs are allowed in multiples.";
    }
    if (strippingSend) {
      return "This change removes external send from this wallet.";
    }
    if (fundedInternal) {
      return "Marking a funded wallet internal-only — it will not send or receive externally. Multiple internal-only wallets are allowed.";
    }
    return null;
  }, [w, effectiveSelected, currentMode]);

  const setMode = useTotpGatedMutation<
    Awaited<ReturnType<typeof patchWalletMoneyCapability>>,
    WalletMoneyMode
  >(
    (mode, totp) => {
      if (!w) throw new Error("wallet not loaded");
      return patchWalletMoneyCapability(
        w.wallet_id,
        { mode, expected_row_version: w.row_version },
        totp,
      );
    },
    {
      title: "Set wallet money mode",
      detail: "Enter a fresh TOTP to change this wallet's money capability. The change is audited.",
      onSuccess: (result) => {
        setErr(null);
        setSelectedMode("");
        setMsg(`Money mode set to ${moneyModeLabel(result.money_mode)}.`);
        const warns: string[] = [];
        if (result.warnings.zero_send_capable) {
          warns.push("No send-capable wallet remains on this node.");
        }
        if (result.warnings.zero_receive_capable) {
          warns.push("No receive-capable wallet remains on this node.");
        }
        setFleetWarning(warns.length > 0 ? warns.join(" ") : null);
        void queryClient.invalidateQueries({ queryKey: ["wallet-detail", pubkey] });
        void queryClient.invalidateQueries({ queryKey: ["wallets-inventory"] });
      },
      onError: (e: unknown) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setFleetWarning(null);
        setErr(formatMoneyError(e, "Could not set money mode"));
      },
    },
  );

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

  const fleetLive = fleetQ.data?.live === true;
  const fleetRows = fleetLive ? (fleetQ.data?.data ?? []) : [];
  const fleetSend = fleetRows.filter((row) => row.allow_external_send).length;
  const fleetReceive = fleetRows.filter((row) => row.allow_external_receive).length;

  return (
    <div className="page">
      <Link to="/wallets" className="linkish">← Wallets</Link>
      <div className="page-title-row">
        <h1>Wallet</h1>
        <CopyButton value={w.public_key} label="Copy pubkey" />
      </div>
      {err ? (
        <p className="err" role="alert" data-testid="wallet-money-mode-error">
          {err}
        </p>
      ) : null}
      {msg ? (
        <p className="ok" data-testid="wallet-money-mode-msg">
          {msg}
        </p>
      ) : null}
      {fleetWarning ? (
        <div className="banner banner-warn" role="status" data-testid="wallet-money-mode-fleet-warning">
          {fleetWarning}
        </div>
      ) : null}
      <div className="card form-card detail-grid">
        <div className="detail-item"><div className="k">Pubkey</div><div className="v mono">{w.public_key}</div></div>
        <div className="detail-item"><div className="k">Origin</div><div className="v">{w.key_origin}</div></div>
        <div className="detail-item">
          <div className="k">State</div>
          <div className="v"><StatusTag status={w.state} /></div>
        </div>
        <div className="detail-item">
          <div className="k">Money mode</div>
          <div className="v" data-testid="wallet-money-mode-current">
            <MoneyModeBadge mode={w.money_mode} />
            <span className="muted" style={{ marginLeft: 8 }}>
              ({w.money_mode})
            </span>
          </div>
        </div>
        <div className="detail-item">
          <div className="k">Hold cause</div>
          <div className="v">
            <WalletHoldCause wallet={w} />
            {!w.holding_operation_id && (w.state ?? "").toUpperCase() === "AVAILABLE" ? (
              <span className="muted">None</span>
            ) : null}
          </div>
        </div>
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
            {w.holding_lease_role ? (
              <div className="detail-item">
                <div className="k">Lease role</div>
                <div className="v mono">{w.holding_lease_role}</div>
              </div>
            ) : null}
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
        {w.quarantine_reason ? (
          <div className="detail-item">
            <div className="k">Quarantine reason</div>
            <div className="v" data-testid="wallet-quarantine-reason">{w.quarantine_reason}</div>
          </div>
        ) : null}
      </div>

      <section className="card form-card" data-testid="wallet-money-mode-editor" style={{ marginTop: 16 }}>
        <h2>Money capability</h2>
        <p className="muted">
          Operator custody policy for this wallet. Changing mode requires a fresh TOTP and is
          audited with before and after values. Multiple internal-only wallets are allowed —
          there is no single-hub constraint.
        </p>
        {fleetLive && fleetRows.length > 0 && (fleetSend === 0 || fleetReceive === 0) ? (
          <div className="banner banner-warn" role="status" style={{ marginBottom: 12 }}>
            {fleetSend === 0
              ? "Fleet currently has zero send-capable wallets. "
              : null}
            {fleetReceive === 0
              ? "Fleet currently has zero receive-capable wallets."
              : null}
          </div>
        ) : null}
        <label htmlFor="wallet-money-mode-select" className="k">
          Mode
        </label>
        <select
          id="wallet-money-mode-select"
          data-testid="wallet-money-mode-select"
          value={effectiveSelected}
          disabled={setMode.isPending}
          onChange={(e) => setSelectedMode(e.target.value as WalletMoneyMode)}
          aria-describedby="wallet-money-mode-help"
          style={{ display: "block", marginTop: 6, minWidth: 220 }}
        >
          {MODES.map((mode) => (
            <option key={mode} value={mode}>
              {moneyModeLabel(mode)} ({mode})
            </option>
          ))}
        </select>
        <p id="wallet-money-mode-help" className="muted" data-testid="wallet-money-mode-help">
          {moneyModeHelp(effectiveSelected)}
        </p>
        <ul className="muted" data-testid="wallet-money-mode-help-all">
          {MODES.map((mode) => (
            <li key={mode}>
              <strong>{moneyModeLabel(mode)}</strong> — {moneyModeHelp(mode)}
            </li>
          ))}
        </ul>
        {confirmHint ? (
          <p className="muted" role="status" data-testid="wallet-money-mode-confirm-hint">
            {confirmHint}
          </p>
        ) : null}
        <div className="form-actions" style={{ marginTop: 12 }}>
          <button
            type="button"
            className="btn primary"
            data-testid="wallet-money-mode-save"
            disabled={setMode.isPending || effectiveSelected === currentMode}
            onClick={() => setMode.mutate(effectiveSelected)}
          >
            {setMode.isPending ? "Saving…" : "Save money mode"}
          </button>
        </div>
        <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>
          row_version {w.row_version} · flags receive={String(w.allow_external_receive)} send=
          {String(w.allow_external_send)} move={String(w.allow_internal_move)}
        </p>
      </section>
    </div>
  );
}
