import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { StatusTag } from "../../components/StatusTag.js";
import { WalletHoldCause } from "../../components/WalletHoldCause.js";
import {
  IconArrow, IconHalt, IconMark, IconRefresh,
} from "../../icons.js";
import { apiSoftRead } from "../../lib/api.js";
import { truncatePubkey } from "../../lib/format.js";
import { deriveNodeHealthUiState, fetchNodeReadiness, type NodeHealthUiState } from "../../lib/health.js";
import {
  fetchHaltState,
  fetchReadinessChecklist,
  formatMoneyError,
  listOperationsInventory,
  listWalletsInventory,
  operationDetailPath,
  sumObservedEquityZkz,
  type HaltState,
  type OperationListItem,
  type ReadinessChecklist,
  type ReadinessRow,
  type WalletInventoryItem,
} from "../../lib/money.js";
import { operationKindLabel, statusLabel } from "../../lib/labels.js";
import {
  EMPTY_NEEDS_ATTENTION,
  type NeedsAttentionListItem,
  type NeedsAttentionResponse,
} from "../../lib/ops.js";
import {
  loadEnabledPacks,
  packChecklistRowsForEnabled,
  type PackChecklistRow,
} from "../../lib/packs.js";
import { HaltAction } from "./HaltAction.js";

/** Honest per-state labels for the overview page header.
 * "Node is healthy" is rendered only when /health/ready genuinely reports ready;
 * every other state (checking / degraded / offline) renders its true condition. */
const OVERVIEW_HEALTH_LABEL: Record<NodeHealthUiState, string> = {
  checking: "Checking node health\u2026",
  healthy: "Node is healthy",
  degraded: "Node is degraded",
  offline: "Node is offline",
};

function countByKind(
  ops: readonly OperationListItem[],
  kind: string,
): { open: number; landed_today: number } {
  const today = new Date().toISOString().slice(0, 10);
  let open = 0;
  let landed_today = 0;
  for (const o of ops) {
    if (o.operation_type !== kind) continue;
    const terminal = o.terminal_at != null && o.terminal_at !== "";
    if (terminal) {
      if ((o.terminal_at ?? "").startsWith(today) || (o.updated_at ?? "").startsWith(today)) {
        landed_today += 1;
      }
    } else {
      open += 1;
    }
  }
  return { open, landed_today };
}

function isTerminal(o: OperationListItem): boolean {
  return o.terminal_at != null && o.terminal_at !== "";
}

type ActivityTab = "attention" | "in-flight" | "settled" | "all";

type ActivityRow = NeedsAttentionListItem | OperationListItem;

/** Counterparty column: sends show destination; receives show type + amount context
 * (list inventory has no receiver pubkey). Join miss reads as "unavailable". */
function rowTarget(
  row: ActivityRow,
  opsByOpId: ReadonlyMap<string, OperationListItem>,
): string {
  const matched = "severity" in row ? opsByOpId.get(row.operation_id) : row;
  if (!matched && "severity" in row) return "unavailable";
  const op = matched ?? ("severity" in row ? undefined : row);
  if (!op) return "unavailable";
  if (op.destination_address) return op.destination_address;
  const kind = op.operation_type.toUpperCase();
  if (kind.includes("RECEIVE")) return "receive pool wallet";
  if (kind.includes("MOVE")) return "internal move";
  return "—";
}

function rowMoney(
  row: ActivityRow,
  opsByOpId: ReadonlyMap<string, OperationListItem>,
): { target: string; amount: string } {
  if ("severity" in row) {
    const matched = opsByOpId.get(row.operation_id);
    return matched
      ? { target: rowTarget(row, opsByOpId), amount: matched.amount_zkz }
      : { target: "unavailable", amount: "unavailable" };
  }
  return { target: rowTarget(row, opsByOpId), amount: row.amount_zkz };
}

function rowWhen(row: ActivityRow): string {
  return "severity" in row ? (row.attention_since ?? "—") : (row.updated_at ?? row.created_at);
}

// OWASP CSV injection: a leading =/+/-/@ opens as a formula in Excel/Sheets.
// Operation strings (destination_address) are counterparty-supplied — neutralize before quoting.
const CSV_FORMULA_LEAD = /^[=+\-@]/;

function csvField(value: string): string {
  const safe = CSV_FORMULA_LEAD.test(value) ? `'${value}` : value;
  return `"${safe.replace(/"/g, '""')}"`;
}

/** a real export of the rows currently on screen — no server route
 * exists for this yet (route-policy has no audit-of-export endpoint), so this
 * stays a client-side download rather than inventing one. */
function exportActivityCsv(
  rows: readonly ActivityRow[],
  opsByOpId: ReadonlyMap<string, OperationListItem>,
): void {
  const header = ["Type", "Reference", "Target", "Amount", "Status", "When"].map(csvField).join(",");
  const lines = rows.map((row) => {
    const { target, amount } = rowMoney(row, opsByOpId);
    return [row.operation_type, row.operation_id, target, amount, row.status, rowWhen(row)]
      .map(csvField)
      .join(",");
  });
  const blob = new Blob([[header, ...lines].join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `overview-activity-${new Date().toISOString().slice(0, 19).replace(/:/g, "-")}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function OverviewPage() {
  const [tab, setTab] = useState<ActivityTab>("attention");
  const attentionQ = useQuery({
    queryKey: ["needs-attention-overview"],
    queryFn: async () =>
      apiSoftRead<NeedsAttentionResponse>("/operations/needs-attention", EMPTY_NEEDS_ATTENTION),
    refetchInterval: 30_000,
  });
  const walletsQ = useQuery({
    queryKey: ["overview-wallets"],
    queryFn: listWalletsInventory,
    refetchInterval: 30_000,
  });
  const opsQ = useQuery({
    queryKey: ["overview-operations"],
    queryFn: () => listOperationsInventory(),
    refetchInterval: 30_000,
  });
  const haltQueryKey = ["overview", "halt-state"] as const;
  const haltQ = useQuery({
    queryKey: haltQueryKey,
    queryFn: async (): Promise<HaltState> => {
      
      return fetchHaltState();
    },
    refetchInterval: 15_000,
  });

  // Real /health/ready probe.
  const healthQ = useQuery({
    queryKey: ["overview", "node-health"],
    queryFn: fetchNodeReadiness,
    refetchInterval: 15_000,
    
    retry: false,
  });
  const healthState = deriveNodeHealthUiState(healthQ);

  const readinessQ = useQuery({
    queryKey: ["overview", "readiness-checklist"],
    queryFn: fetchReadinessChecklist,
    refetchInterval: 30_000,
    
    retry: false,
  });
  const readiness: ReadinessChecklist | null =
    readinessQ.data ? readinessQ.data : null;
  const readinessRows = readiness?.rows ?? [];
  const blockedRows = readinessRows.filter((r) => r.status === "blocked" || r.status === "amber");
  /** Day-0 is done when nothing is blocked/amber — hide the full list by default. */
  const readinessNeedsAttention = blockedRows.length > 0;
  const [readinessExpanded, setReadinessExpanded] = useState(false);
  const showReadinessDetails =
    readinessNeedsAttention || readinessExpanded || readinessQ.isPending || readinessQ.isError;
  const packRows = packChecklistRowsForEnabled(loadEnabledPacks());

  const liveAttn = attentionQ.data?.live === true ? attentionQ.data.data : null;
  const attentionCount = liveAttn?.summary.total ?? 0;
  const attentionLive = liveAttn?.operations ?? [];
  const haltErrored = haltQ.isError;
  const haltEngaged = !haltErrored && haltQ.data?.engaged === true;
  const haltClear = !haltErrored && haltQ.data?.engaged === false;
  const haltLoading = haltQ.isFetching ;
  const haltUnknown = !haltLoading && (haltErrored || (!haltEngaged && !haltClear));
  const haltErrorDetail = haltQ.error
    ? formatMoneyError(haltQ.error, "Halt state unavailable.")
    : "Halt API returned an indeterminate state.";
  const walletsLive = walletsQ.data?.live === true;
  const wallets: readonly WalletInventoryItem[] = walletsLive ? (walletsQ.data?.data ?? []) : [];
  const equity = walletsLive ? sumObservedEquityZkz(wallets) : "—";
  const walletCount = wallets.length;
  const walletPreview = wallets.slice(0, 6).map((w, i) => ({
    id: `W${i + 1}`,
    pubkey: w.public_key,
    balance: w.observed_balance_zkz ?? "—",
    state: w.state,
    role: w.key_origin,
    wallet: w,
  }));
  const opsLive = opsQ.data?.live === true;
  const opsRows = opsLive ? (opsQ.data?.data ?? []) : [];
  const recv = countByKind(opsRows, "RECEIVE_EXTERNAL");
  const move = countByKind(opsRows, "MOVE_INTERNAL");
  const send = countByKind(opsRows, "SEND_EXTERNAL");
  const inFlightOps = opsRows.filter((o) => !isTerminal(o));
  const settledOps = opsRows.filter(isTerminal);
  const opsByOpId = new Map(opsRows.map((o) => [o.operation_id, o]));
  const activityRows = tab === "attention"
    ? attentionLive
    : tab === "in-flight"
      ? inFlightOps
      : tab === "settled"
        ? settledOps
        : opsRows;
  const activityLive = tab === "attention" ? liveAttn !== null : opsLive;
  const activityError = tab === "attention" ? attentionQ.data?.error : opsQ.data?.error;


  // Persistent banner when operator used typed break-glass without a device.
  const setupBreakGlassQ = useQuery({
    queryKey: ["overview", "setup-device-break-glass"],
    queryFn: async (): Promise<boolean> => {
      const res = await fetch("/admin/v1/setup-state", { credentials: "include" });
      if (!res.ok) return false;
      const body = (await res.json()) as { device_break_glass_active?: boolean };
      return body.device_break_glass_active === true;
    },
    refetchInterval: 60_000,
    
  });
  const deviceBreakGlassActive = setupBreakGlassQ.data === true;


  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p>
            {(
                <>
                  {OVERVIEW_HEALTH_LABEL[healthState]}
                  {" · "}<em>{attentionCount} items</em> need attention
                  {liveAttn ? " · live" : " · attention API empty/unavailable"}
                  {haltEngaged ? " · money halt engaged" : ""}
                  {haltUnknown ? " · halt state UNKNOWN" : ""}
                </>
              )}
          </p>
        </div>
        <div className="pill-row">
          <Link to="/transfers" className="pill primary"><IconArrow /> Send</Link>
          <button type="button" className="pill" onClick={() => void attentionQ.refetch()}>
            <IconRefresh /> Refresh
          </button>
          <button
            type="button"
            className={`pill ${haltEngaged || haltUnknown ? "danger" : ""}`}
            disabled={haltLoading || haltUnknown}
            onClick={() => {
              document.getElementById("halt-control")?.scrollIntoView({ behavior: "smooth" });
            }}
          >
            <IconHalt /> {haltEngaged ? "Halt on" : haltUnknown ? "Halt unavailable" : "Halt"}
          </button>
        </div>
      </div>
      {deviceBreakGlassActive ? (
        <div
          className="banner banner-error"
          role="alert"
          data-testid="device-break-glass-banner"
          style={{ marginBottom: 16 }}
        >
          Device signatures unavailable — setup used typed break-glass without an approval
          device. Enrol a device under Devices before dual-control bless/approve will work.
        </div>
      ) : null}


      <section
          className="card"
          data-testid="readiness-checklist"
          aria-label="Node readiness"
          data-collapsed={showReadinessDetails ? "false" : "true"}
          style={{ marginBottom: 20 }}
        >
          <div className="hd" style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12 }}>
            <h2 style={{ margin: 0, fontSize: 15 }}>Node readiness</h2>
            <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
              {!readinessNeedsAttention && !readinessQ.isPending && !readinessQ.isError ? (
                <button
                  type="button"
                  className="linkish"
                  data-testid="readiness-toggle-details"
                  aria-expanded={showReadinessDetails}
                  onClick={() => setReadinessExpanded((v) => !v)}
                >
                  {showReadinessDetails ? "Hide details" : "Show details"}
                </button>
              ) : null}
              <button
                type="button"
                className="linkish"
                onClick={() => void readinessQ.refetch()}
                disabled={readinessQ.isFetching}
              >
                {readinessQ.isFetching ? "Refreshing…" : "Refresh"}
              </button>
            </div>
          </div>
          {readinessQ.isPending ? (
            <p className="muted" style={{ padding: 12, margin: 0 }}>Loading checklist…</p>
          ) : readinessQ.isError || readiness === null ? (
            <p className="muted" style={{ padding: 12, margin: 0 }} role="status">
              Readiness checklist unavailable — not implying setup is complete.
            </p>
          ) : readinessNeedsAttention ? (
            <>
              <div className="banner banner-error" role="alert" style={{ margin: "8px 0 12px" }}>
                {blockedRows.length} item{blockedRows.length === 1 ? "" : "s"} still block money ops —
                fix the red rows below first.
              </div>
              <ul className="readiness-list" style={{ listStyle: "none", margin: 0, padding: 0 }}>
                {readinessRows.map((row) => (
                  <ReadinessRowItem key={row.id} row={row} />
                ))}
              </ul>
            </>
          ) : (
            <>
              <div
                className="banner banner-ok"
                role="status"
                data-testid="readiness-all-clear"
                style={{ margin: "8px 0 12px" }}
              >
                All readiness checks clear — day-0 setup is done. This panel stays out of the way
                until something needs attention again.
              </div>
              {showReadinessDetails ? (
                <ul className="readiness-list" style={{ listStyle: "none", margin: 0, padding: 0 }}>
                  {readinessRows.map((row) => (
                    <ReadinessRowItem key={row.id} row={row} />
                  ))}
                </ul>
              ) : null}
            </>
          )}
        </section>

      {packRows.length > 0 ? (
        <section
          className="card"
          data-testid="pack-checklist"
          aria-label="Enabled pack checklists"
          style={{ marginBottom: 20 }}
        >
          <div className="hd">
            <h2 style={{ margin: 0, fontSize: 15 }}>Pack checklists</h2>
            <p className="muted" style={{ margin: "6px 0 0", fontSize: 12.5 }}>
              From Connect enablement — compositions of Incoming, Internal transfer, and
              Outgoing only.{" "}
              <Link to="/integration" className="linkish">Manage packs</Link>
            </p>
          </div>
          <ul className="readiness-list" style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {packRows.map((row) => (
              <PackChecklistRowItem key={row.id} row={row} />
            ))}
          </ul>
        </section>
      ) : null}

      <div className="grid-hero">
        <div className="card balance-card">
          <div className="row-top">
            <div className="label">
              <span className="mark"><IconMark /></span>
              Custody equity
            </div>
            <span className="period" style={{ pointerEvents: "none" }}>Observed</span>
          </div>
          <div className="amount">
            {equity}
            <span className="unit">ZKZ</span>
          </div>
          <div className="delta">
            {walletsLive ? (
              <>
                <strong>Observed on gateway</strong>
                {" · "}
                {walletCount} wallet{walletCount === 1 ? "" : "s"}
                {walletCount === 0
                  ? " · pool will mint after leadership; balances appear after gateway observe"
                  : " · null balance = not yet observed"}
              </>
            ) : (
              <>Wallet inventory unavailable — equity not invented</>
            )}
          </div>
          {!walletsLive ? <ApiErrorNote error={walletsQ.data?.error} /> : null}
          <div className="chart" aria-hidden>
            <svg viewBox="0 0 600 72" preserveAspectRatio="none">
              <defs>
                <linearGradient id="eq" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--accent)" stopOpacity=".35" />
                  <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
                </linearGradient>
              </defs>
              <path d="M0 58 C40 56, 70 52, 100 48 C140 42, 160 44, 200 36 C240 28, 280 40, 320 30 C360 20, 400 24, 440 18 C480 12, 520 22, 560 14 L600 10 L600 72 L0 72 Z" fill="url(#eq)" />
              <path d="M0 58 C40 56, 70 52, 100 48 C140 42, 160 44, 200 36 C240 28, 280 40, 320 30 C360 20, 400 24, 440 18 C480 12, 520 22, 560 14 L600 10" fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </div>
          <div className="mini-actions">
            <Link to="/lab/receive" className="mini-btn">Lab receive</Link>
            <Link to="/transfers" className="mini-btn primary">Send transfer</Link>
            <Link to="/wallets" className="mini-btn">View wallets</Link>
            <button type="button" className="mini-btn" onClick={() => void walletsQ.refetch()}>
              Resync balances
            </button>
          </div>
        </div>

        <div className="card side-card">
          <div className="hd">
            <h2>Wallets</h2>
            <Link to="/wallets" className="link">All</Link>
          </div>
          {walletPreview.length === 0 ? (
            <div className="acct">
              <div className="meta">
                <div className="name">No wallets yet</div>
                <div className="sub">
                  {walletsLive
                      ? "Live inventory empty — receive-pool mint runs under signer leadership"
                      : "Waiting for live inventory"}
                </div>
              </div>
              <div className="bal">—</div>
            </div>
          ) : (
            walletPreview.map((t) => (
              <div className="acct" key={t.id + t.pubkey} data-wallet-state={t.state}>
                <div className={`orb ${t.id.toLowerCase()}`}>{t.id}</div>
                <div className="meta">
                  <div className="name">
                    {t.role}{" "}
                    <StatusTag status={t.state} />
                  </div>
                  <div className="sub">
                    {truncatePubkey(t.pubkey)}
                    <WalletHoldCause wallet={t.wallet} compact />
                  </div>
                </div>
                <div className="bal">{t.balance}</div>
              </div>
            ))
          )}
          <div className="acct-foot">
            <Link to="/wallets" className="linkish">Manage wallets →</Link>
          </div>
        </div>
      </div>

      <div className="stats" data-testid="three-ops-stats">
        <div className="stat">
          <div className="k">{operationKindLabel("RECEIVE_EXTERNAL")}</div>
          <div className="h mono" style={{ fontSize: 11 }}>RECEIVE_EXTERNAL</div>
          <div className="v">{opsLive ? recv.open : "—"}</div>
          <div className="h">{opsLive ? `${recv.landed_today} landed today` : "—"}</div>
        </div>
        <div className="stat">
          <div className="k">{operationKindLabel("MOVE_INTERNAL")}</div>
          <div className="h mono" style={{ fontSize: 11 }}>MOVE_INTERNAL</div>
          <div className="v">{opsLive ? move.open : "—"}</div>
          <div className="h">{opsLive ? `${move.landed_today} landed today` : "—"}</div>
        </div>
        <div className="stat">
          <div className="k">{operationKindLabel("SEND_EXTERNAL")}</div>
          <div className="h mono" style={{ fontSize: 11 }}>SEND_EXTERNAL</div>
          <div className="v">{opsLive ? send.open : "—"}</div>
          <div className="h">{opsLive ? `${send.landed_today} landed today` : "—"}</div>
        </div>
        <div className="stat" data-testid="halt-stat">
          <div className="k">Halt</div>
          <div
            className={`v ${haltClear ? "ok" : ""}`}
            style={{
              fontSize: 16,
              paddingTop: 6,
              color: haltEngaged || haltUnknown ? "var(--danger)" : undefined,
            }}
          >
            {haltLoading ? "Checking…" : haltEngaged ? "Engaged" : haltClear ? "Clear" : "UNKNOWN"}
          </div>
          <div className="h" role={haltUnknown ? "alert" : undefined}>
            {haltLoading
              ? "Confirming halt state"
              : haltEngaged
                ? "Money rails blocked"
                : haltClear
                  ? "Money rails open"
                  : "Halt state unavailable — treat money rails as unknown"}
          </div>
        </div>
      </div>

      <div id="halt-control" style={{ marginBottom: 24 }}>
        <HaltAction
          state={haltEngaged || haltClear ? haltQ.data : undefined}
          loading={haltLoading}
          unavailable={haltUnknown ? haltErrorDetail : null}
          authorityQueryKey={haltQueryKey}
        />
      </div>

      <div className="split">
        <div className="panel">
          <div className="panel-hd">
            <h2>Needs attention</h2>
            <Link to="/operations" className="link">View all</Link>
          </div>
          {liveAttn ? (
            attentionLive.length === 0 ? (
              <p className="muted" style={{ padding: 12, margin: 0 }}>No parked operations.</p>
            ) : (
              attentionLive.slice(0, 5).map((a) => (
                <div className="attn" key={a.operation_id}>
                  <div className={`type-ic ${a.severity === "P0" ? "danger" : ""}`}>{a.severity}</div>
                  <DivBody
                    title={`${operationKindLabel(a.operation_type)} · ${statusLabel(a.status)}`}
                    detail={`${a.operation_id}${a.attention_reason ? ` · ${statusLabel(a.attention_reason)}` : ""} · ${a.operation_type}`}
                  />
                  <Link
                    to={operationDetailPath(a.operation_id, a.operation_type)}
                    className="go pri"
                  >
                    Open
                  </Link>
                </div>
              ))
            )
          ) : (
            <>
              <p className="muted" style={{ padding: 12, margin: 0 }}>
                {"Attention inventory unavailable"}
              </p>
            </>
          )}
        </div>
        <div className="panel">
          <div className="panel-hd">
            <h2>Wallet pool</h2>
            <Link to="/wallets" className="link">See all</Link>
          </div>
          {wallets.length === 0 ? (
            <>
              <p className="muted" style={{ padding: 12, margin: 0 }}>
                {walletsLive
                    ? "Pool empty"
                    : "Wallet inventory unavailable"}
              </p>
              {!walletsLive ? <ApiErrorNote error={walletsQ.data?.error} /> : null}
            </>
          ) : (
            wallets.slice(0, 8).map((w) => (
              <Link
                key={w.wallet_id + w.public_key}
                to={`/wallets/${encodeURIComponent(w.public_key)}`}
                className="sess-row"
                data-wallet-state={w.state}
              >
                <span className="id">{truncatePubkey(w.public_key)}</span>
                <span className="amt">{w.observed_balance_zkz ?? "—"}</span>
                <StatusTag status={w.state} />
                <span className="when">
                  {w.key_origin}
                  <WalletHoldCause wallet={w} compact />
                </span>
              </Link>
            ))
          )}
        </div>
      </div>

      <div className="table-wrap">
        <div className="table-toolbar">
          <div className="tabs">
            <button
              type="button"
              className={`tab ${tab === "attention" ? "on" : ""}`}
              onClick={() => setTab("attention")}
            >
              Attention <span className="n warn">{attentionCount}</span>
            </button>
            <button
              type="button"
              className={`tab ${tab === "in-flight" ? "on" : ""}`}
              onClick={() => setTab("in-flight")}
            >
              In-flight <span className="n">{inFlightOps.length}</span>
            </button>
            <button
              type="button"
              className={`tab ${tab === "settled" ? "on" : ""}`}
              onClick={() => setTab("settled")}
            >
              Settled
            </button>
            <button
              type="button"
              className={`tab ${tab === "all" ? "on" : ""}`}
              onClick={() => setTab("all")}
            >
              All
            </button>
          </div>
          <div className="filters">
            <button
              type="button"
              className="filter-btn"
              disabled={activityRows.length === 0}
              onClick={() => exportActivityCsv(activityRows, opsByOpId)}
            >
              Export
            </button>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Type</th><th>Reference</th><th>Target</th><th>Amount</th><th>Status</th><th>When</th><th><span className="visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {activityRows.length === 0 ? (
              <tr>
                <td colSpan={7} className="muted">
                  {activityLive
                      ? "No activity yet"
                      : (
                        <>
                          Activity unavailable — not implying an empty queue
                          {activityError ? ` (${activityError.code} · request ${activityError.requestId ?? "n/a"})` : ""}
                        </>
                      )}
                </td>
              </tr>
            ) : (
              activityRows.slice(0, 10).map((row) => {
                const { target, amount } = rowMoney(row, opsByOpId);
                const detailTo = operationDetailPath(row.operation_id, row.operation_type);
                if ("severity" in row) {
                  return (
                    <tr key={row.operation_id}>
                      <td>
                        <span className="cell-type">
                          <span className="ti xfer"><IconArrow /></span>
                          {operationKindLabel(row.operation_type)}
                          <span className="quiet mono" style={{ marginLeft: 6, fontSize: 11 }}>{row.operation_type}</span>
                        </span>
                      </td>
                      <td className="mono">
                        <Link className="linkish" to={detailTo}>{row.operation_id}</Link>
                      </td>
                      <td className="mono">{target}</td>
                      <td className="money">{amount}</td>
                      <td><StatusTag status={row.status} /></td>
                      <td className="quiet">{row.attention_since ?? "—"}</td>
                      <td><Link to={detailTo} className="linkish">Open</Link></td>
                    </tr>
                  );
                }
                return (
                  <tr key={row.operation_id}>
                    <td>
                      <span className="cell-type">
                        <span className="ti xfer"><IconArrow /></span>
                        {operationKindLabel(row.operation_type)}
                        <span className="quiet mono" style={{ marginLeft: 6, fontSize: 11 }}>{row.operation_type}</span>
                      </span>
                    </td>
                    <td className="mono">
                      <Link className="linkish" to={detailTo}>{row.operation_id}</Link>
                    </td>
                    <td className="mono">{target}</td>
                    <td className="money">{amount}</td>
                    <td><StatusTag status={row.status} /></td>
                    <td className="quiet">{row.updated_at ?? row.created_at}</td>
                    <td>
                      <Link to={detailTo} className="linkish">
                        View
                      </Link>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DivBody({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="body-t">
      <div className="t">{title}</div>
      <div className="d">{detail}</div>
    </div>
  );
}

function PackChecklistRowItem({ row }: { row: PackChecklistRow }) {
  return (
    <li
      className="attn"
      data-testid={`pack-checklist-row-${row.id}`}
      data-pack={row.pack}
      style={{ alignItems: "flex-start" }}
    >
      <div className="type-ic" aria-hidden>
        {row.pack}
      </div>
      <div className="body-t">
        <div className="t">
          {row.title}{" "}
          <span className="tag muted" style={{ marginLeft: 6 }}>
            Pack {row.pack}
          </span>
        </div>
        <div className="d">{row.detail}</div>
      </div>
      <Link to={row.href} className="go pri">
        Open
      </Link>
    </li>
  );
}

function readinessTone(status: ReadinessRow["status"]): string {
  if (status === "ok") return "ok";
  if (status === "blocked") return "danger";
  if (status === "amber") return "warn";
  if (status === "optional") return "muted";
  return "muted";
}

function ReadinessRowItem({ row }: { row: ReadinessRow }) {
  const tone = readinessTone(row.status);
  const needsFix = row.status === "blocked" || row.status === "amber";
  const backupStale = row.id === "backup_health" && needsFix;
  return (
    <li
      className="attn"
      data-testid={`readiness-row-${row.id}`}
      data-status={row.status}
      style={{ alignItems: "flex-start" }}
    >
      <div className={`type-ic ${tone === "danger" ? "danger" : ""}`} aria-hidden>
        {row.status === "ok" ? "✓" : row.status === "blocked" ? "!" : "·"}
      </div>
      <div className="body-t">
        <div className="t">
          {row.title}{" "}
          <span className={`tag ${tone}`} style={{ marginLeft: 6 }}>{row.status}</span>
        </div>
        <div className="d">{row.detail}</div>
        {row.blocks_ops && row.blocks_ops.length > 0 ? (
          <div className="d" style={{ marginTop: 4 }}>
            Blocks: {row.blocks_ops.map((op) => operationKindLabel(op)).join(", ")}
          </div>
        ) : null}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6, alignItems: "flex-end" }}>
        <Link to={row.href} className={`go ${needsFix ? "pri" : ""}`}>
          {needsFix
            ? backupStale
              ? "Backup"
              : row.id === "recovery_verified_wallet"
                ? "Test backup"
                : "Fix"
            : row.id === "recovery_verified_wallet"
              ? "Verify backup again"
              : "Open"}
        </Link>
        {backupStale ? (
          <Link to="/recovery-ceremony" className="go" data-testid="backup-recovery-cta">
            Verify backup again
          </Link>
        ) : null}
      </div>
    </li>
  );
}

