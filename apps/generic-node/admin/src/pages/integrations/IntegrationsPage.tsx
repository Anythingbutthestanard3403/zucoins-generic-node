// SPA Integrations — named integration identities (create / list / retire)
// plus per-integration funding wallet pin (reserve/proof — not send/source).
// Retirement is an issuance gate only: existing keys keep authenticating until
// revoked. Operators issue keys under an integration from the Keys page.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { truncatePubkey } from "../../lib/format.js";
import {
  fetchDefaultFundingWallet,
  formatMoneyError,
  isCancelled,
  listImplementers,
  listWalletsInventory,
  postCreateImplementer,
  postRetireImplementer,
  postSetImplementerFundingWallet,
  putDefaultFundingWallet,
  type FundingWalletSetMode,
  type ImplementerListing,
} from "../../lib/money.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

const QUERY_KEY = ["implementers"] as const;
const DEFAULT_FUNDING_KEY = ["default-funding-wallet"] as const;
const WALLETS_KEY = ["wallets-for-funding"] as const;

function fundingLabel(row: ImplementerListing): string {
  if (row.funding_wallet_id !== null && row.funding_wallet_public_key !== null) {
    return `${truncatePubkey(row.funding_wallet_public_key, 8, 6)}`;
  }
  if (row.funding_wallet_id !== null) {
    return row.funding_wallet_id.slice(0, 8) + "…";
  }
  return "Node default";
}

export function IntegrationsPage() {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [retireId, setRetireId] = useState<string | null>(null);
  const [retireError, setRetireError] = useState<string | null>(null);
  const [created, setCreated] = useState<ImplementerListing | null>(null);

  const [fundingTarget, setFundingTarget] = useState<ImplementerListing | null>(null);
  const [fundingMode, setFundingMode] = useState<FundingWalletSetMode>("DEFAULT");
  const [fundingWalletId, setFundingWalletId] = useState("");
  const [fundingError, setFundingError] = useState<string | null>(null);

  const [defaultWalletPick, setDefaultWalletPick] = useState("");
  const [defaultError, setDefaultError] = useState<string | null>(null);

  const list = useQuery({
    queryKey: [...QUERY_KEY],
    queryFn: listImplementers,
  });

  const defaultFunding = useQuery({
    queryKey: [...DEFAULT_FUNDING_KEY],
    queryFn: fetchDefaultFundingWallet,
    retry: false,
  });

  const wallets = useQuery({
    queryKey: [...WALLETS_KEY],
    queryFn: () => listWalletsInventory(),
    enabled: fundingTarget !== null || true,
  });

  const create = useTotpGatedMutation<ImplementerListing, void>(
    (_v, totp) => postCreateImplementer(name.trim(), totp),
    {
      title: "Create integration",
      detail: "Enter a fresh TOTP to register a named integration identity.",
      onSuccess: (result) => {
        setCreated(result);
        setName("");
        setCreateError(null);
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (err: unknown) => {
        if (isCancelled(err)) return;
        setCreateError(formatMoneyError(err, "Create failed."));
      },
    },
  );

  const retire = useTotpGatedMutation<ImplementerListing, string>(
    (id, totp) => postRetireImplementer(id, totp),
    {
      title: "Retire integration",
      detail: () =>
        "Enter a fresh TOTP. New keys cannot be issued under this integration; existing keys keep working until revoked.",
      onSuccess: () => {
        setRetireId(null);
        setRetireError(null);
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (err: unknown) => {
        if (isCancelled(err)) return;
        setRetireError(formatMoneyError(err, "Retire failed."));
      },
    },
  );

  const setFunding = useTotpGatedMutation<
    ImplementerListing,
    { readonly id: string; readonly mode: FundingWalletSetMode; readonly wallet_id?: string }
  >(
    (vars, totp) =>
      postSetImplementerFundingWallet(
        vars.id,
        { mode: vars.mode, wallet_id: vars.wallet_id },
        totp,
      ),
    {
      title: "Set funding wallet",
      detail:
        "Enter a fresh TOTP. This pins the SplitChain reserve/proof wallet for the integration — not the send/source wallet used for transfers.",
      onSuccess: () => {
        setFundingTarget(null);
        setFundingError(null);
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (err: unknown) => {
        if (isCancelled(err)) return;
        setFundingError(formatMoneyError(err, "Set funding wallet failed."));
      },
    },
  );

  const setDefault = useTotpGatedMutation<
    Awaited<ReturnType<typeof putDefaultFundingWallet>>,
    { readonly wallet_id: string | null; readonly expected_row_version: number }
  >((vars, totp) => putDefaultFundingWallet(vars, totp), {
    title: "Set default funding wallet",
    detail:
      "Enter a fresh TOTP. Integrations using “Node default” share this reserve/proof wallet. This is not a send/source pin.",
    onSuccess: () => {
      setDefaultError(null);
      void qc.invalidateQueries({ queryKey: DEFAULT_FUNDING_KEY });
    },
    onError: (err: unknown) => {
      if (isCancelled(err)) return;
      setDefaultError(formatMoneyError(err, "Set default funding wallet failed."));
    },
  });

  const rows = list.data?.implementers ?? [];
  const live = list.data?.live === true;
  const unavailable = !live;
  const canCreate = name.trim().length > 0 && name.trim().length <= 128;
  const walletItems = wallets.data?.data ?? [];
  const activeWallets = walletItems.filter((w) => w.retired_at === null && w.state !== "RETIRED");

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Integrations</h1>
      </div>

      <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }}>
        Each integration is a named identity keys and auto-approve rules bind to.
        Issue bearer keys on the <Link to="/api-keys">Keys</Link> page after create.
        Retiring stops new key issuance only — revoke keys separately to disable auth.
      </p>

      <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }} data-testid="funding-copy">
        <strong>Funding wallet</strong> is the SplitChain reserve/proof address Zukaz
        balance-checks — not the worker wallet that signs hunter transfers (sends stay
        omit-source). Integrations may share the node default or pin their own wallet.
      </p>

      {list.isPending ? <p className="muted">Loading…</p> : null}

      {list.isError || (list.isSuccess && unavailable) ? (
        <div className="banner banner-error" role="alert">
          Integration registry is not available.
        </div>
      ) : null}

      {list.isSuccess && !unavailable ? (
        <>
          <div className="card" style={{ marginBottom: 16 }} data-testid="default-funding-card">
            <h2>Default funding wallet (node-wide)</h2>
            <p className="muted" style={{ fontSize: 12.5 }}>
              Shared reserve/proof wallet used when an integration has no explicit pin.
              Reusable across integrations. Not a send/source pin.
            </p>
            {defaultFunding.isSuccess ? (
              <p style={{ fontSize: 13 }}>
                Current:{" "}
                {defaultFunding.data.wallet_id ? (
                  <>
                    <code>{defaultFunding.data.wallet_id}</code>
                    {defaultFunding.data.public_key ? (
                      <>
                        {" "}
                        · fingerprint{" "}
                        <code>{truncatePubkey(defaultFunding.data.public_key, 8, 6)}</code>
                      </>
                    ) : (
                      <span className="muted"> · pubkey unresolved</span>
                    )}
                  </>
                ) : (
                  <span className="muted">not set</span>
                )}
                <span className="muted"> · row_version {defaultFunding.data.row_version}</span>
              </p>
            ) : defaultFunding.isError ? (
              <p className="muted" style={{ fontSize: 12.5 }}>
                Default funding setting unavailable.
              </p>
            ) : (
              <p className="muted">Loading default…</p>
            )}
            <label style={{ display: "block", marginTop: 8, fontSize: 13 }}>
              <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                Set default to wallet
              </span>
              <select
                aria-label="Default funding wallet"
                value={defaultWalletPick}
                onChange={(e) => setDefaultWalletPick(e.target.value)}
                style={{ minWidth: 280 }}
              >
                <option value="">— clear default —</option>
                {activeWallets.map((w) => (
                  <option key={w.wallet_id} value={w.wallet_id}>
                    {truncatePubkey(w.public_key, 8, 6)} · {w.wallet_id.slice(0, 8)}…
                  </option>
                ))}
              </select>
            </label>
            <div className="pill-row" style={{ marginTop: 10 }}>
              <button
                type="button"
                className="pill primary"
                disabled={defaultFunding.isPending || setDefault.isPending || !defaultFunding.isSuccess}
                onClick={() => {
                  if (!defaultFunding.data) return;
                  setDefaultError(null);
                  setDefault.mutate({
                    wallet_id: defaultWalletPick === "" ? null : defaultWalletPick,
                    expected_row_version: defaultFunding.data.row_version,
                  });
                }}
              >
                {setDefault.isPending ? "Saving…" : "Save default funding wallet"}
              </button>
            </div>
            {defaultError ? (
              <div className="err" role="alert" style={{ marginTop: 8 }}>
                {defaultError}
              </div>
            ) : null}
          </div>

          <div className="card" style={{ marginBottom: 16 }}>
            <h2>Create integration</h2>
            <label style={{ display: "block", marginTop: 8, fontSize: 13 }}>
              <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                Name
              </span>
              <input
                type="text"
                aria-label="Integration name"
                value={name}
                maxLength={128}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. payroll-run"
                style={{ minWidth: 240 }}
              />
            </label>
            <div className="pill-row" style={{ marginTop: 10 }}>
              <button
                type="button"
                className="pill primary"
                disabled={!canCreate || create.isPending}
                onClick={() => {
                  setCreateError(null);
                  setCreated(null);
                  create.mutate();
                }}
              >
                {create.isPending ? "Creating…" : "Create"}
              </button>
            </div>
            {createError ? (
              <div className="err" role="alert" style={{ marginTop: 8 }}>
                {createError}
              </div>
            ) : null}
            {created ? (
              <p className="ok" style={{ marginTop: 8 }} data-testid="implementer-created">
                Created <strong>{created.name}</strong> (
                <code>{created.id}</code>).{" "}
                <Link to="/api-keys">Issue a key</Link> under it.
              </p>
            ) : null}
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Id</th>
                  <th>Funding wallet</th>
                  <th>Created</th>
                  <th>Status</th>
                  <th>
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="muted">
                      No integrations yet
                    </td>
                  </tr>
                ) : (
                  rows.map((row) => {
                    const retired = row.retired_at !== null;
                    return (
                      <tr key={row.id}>
                        <td>{row.name}</td>
                        <td>
                          <code style={{ fontSize: 12 }}>{row.id}</code>
                        </td>
                        <td data-testid={`funding-cell-${row.id}`}>
                          <span className="mono" style={{ fontSize: 12 }}>
                            {fundingLabel(row)}
                          </span>
                          {row.funding_wallet_id ? (
                            <div className="muted" style={{ fontSize: 11 }}>
                              <code>{row.funding_wallet_id.slice(0, 8)}…</code>
                            </div>
                          ) : null}
                        </td>
                        <td>{row.created_at}</td>
                        <td>
                          <span className={`tag ${retired ? "muted" : "ok"}`}>
                            {retired ? "RETIRED" : "ACTIVE"}
                          </span>
                        </td>
                        <td>
                          {!retired ? (
                            <span className="pill-row">
                              <button
                                type="button"
                                className="pill"
                                onClick={() => {
                                  setFundingError(null);
                                  setFundingTarget(row);
                                  setFundingMode(
                                    row.funding_wallet_id === null ? "DEFAULT" : "WALLET_ID",
                                  );
                                  setFundingWalletId(row.funding_wallet_id ?? "");
                                }}
                              >
                                Set funding
                              </button>{" "}
                              {retireId === row.id ? (
                                <span>
                                  <button
                                    type="button"
                                    className="pill danger"
                                    disabled={retire.isPending}
                                    onClick={() => retire.mutate(row.id)}
                                  >
                                    {retire.isPending ? "Retiring…" : "Confirm retire"}
                                  </button>{" "}
                                  <button
                                    type="button"
                                    className="pill"
                                    disabled={retire.isPending}
                                    onClick={() => {
                                      setRetireId(null);
                                      setRetireError(null);
                                    }}
                                  >
                                    Cancel
                                  </button>
                                </span>
                              ) : (
                                <button
                                  type="button"
                                  className="pill"
                                  onClick={() => {
                                    setRetireError(null);
                                    setRetireId(row.id);
                                  }}
                                >
                                  Retire
                                </button>
                              )}
                            </span>
                          ) : null}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          {retireError ? (
            <div className="err" role="alert" style={{ marginTop: 8 }}>
              {retireError}
            </div>
          ) : null}

          {fundingTarget ? (
            <div
              className="card"
              style={{ marginTop: 16 }}
              data-testid="funding-dialog"
              role="dialog"
              aria-label="Set funding wallet"
            >
              <h2>Set funding wallet — {fundingTarget.name}</h2>
              <p className="muted" style={{ fontSize: 12.5 }}>
                Reserve/proof pin only. Does not force the send/source wallet for
                transfers (omit-source stays).
              </p>
              <fieldset style={{ border: "none", padding: 0, marginTop: 8 }}>
                <legend className="visually-hidden">Funding mode</legend>
                <label style={{ display: "block", fontSize: 13, marginBottom: 6 }}>
                  <input
                    type="radio"
                    name="funding-mode"
                    checked={fundingMode === "DEFAULT"}
                    onChange={() => setFundingMode("DEFAULT")}
                  />{" "}
                  Use shared node default
                </label>
                <label style={{ display: "block", fontSize: 13, marginBottom: 6 }}>
                  <input
                    type="radio"
                    name="funding-mode"
                    checked={fundingMode === "WALLET_ID"}
                    onChange={() => setFundingMode("WALLET_ID")}
                  />{" "}
                  Select existing wallet
                </label>
                <label style={{ display: "block", fontSize: 13, marginBottom: 6 }}>
                  <input
                    type="radio"
                    name="funding-mode"
                    checked={fundingMode === "CREATE"}
                    onChange={() => setFundingMode("CREATE")}
                  />{" "}
                  Create new wallet and attach
                </label>
              </fieldset>
              {fundingMode === "WALLET_ID" ? (
                <label style={{ display: "block", marginTop: 8, fontSize: 13 }}>
                  <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                    Wallet
                  </span>
                  <select
                    aria-label="Funding wallet id"
                    value={fundingWalletId}
                    onChange={(e) => setFundingWalletId(e.target.value)}
                    style={{ minWidth: 280 }}
                  >
                    <option value="">— pick wallet —</option>
                    {activeWallets.map((w) => (
                      <option key={w.wallet_id} value={w.wallet_id}>
                        {truncatePubkey(w.public_key, 8, 6)} · {w.wallet_id.slice(0, 8)}…
                      </option>
                    ))}
                  </select>
                </label>
              ) : null}
              <div className="pill-row" style={{ marginTop: 10 }}>
                <button
                  type="button"
                  className="pill primary"
                  disabled={
                    setFunding.isPending ||
                    (fundingMode === "WALLET_ID" && fundingWalletId.length === 0)
                  }
                  onClick={() => {
                    setFundingError(null);
                    setFunding.mutate({
                      id: fundingTarget.id,
                      mode: fundingMode,
                      wallet_id:
                        fundingMode === "WALLET_ID" ? fundingWalletId : undefined,
                    });
                  }}
                >
                  {setFunding.isPending ? "Saving…" : "Save funding wallet"}
                </button>
                <button
                  type="button"
                  className="pill"
                  disabled={setFunding.isPending}
                  onClick={() => {
                    setFundingTarget(null);
                    setFundingError(null);
                  }}
                >
                  Cancel
                </button>
              </div>
              {fundingError ? (
                <div className="err" role="alert" style={{ marginTop: 8 }}>
                  {fundingError}
                </div>
              ) : null}
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
