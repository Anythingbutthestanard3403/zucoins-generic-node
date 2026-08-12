// SPA Keys — live implementer API key management with integration picker.
// Issue returns the raw key exactly once (shown + copyable, never re-fetched); list
// never includes the secret or hash; revoke takes effect on the next bearer auth.
// Demo sessions never show fixture keys as real (error-honesty rule).

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import { stageIssuedIntegrationKey } from "../../lib/integration-handoff.js";
import {
  formatMoneyError,
  isCancelled,
  listApiKeys,
  listImplementers,
  postIssueApiKey,
  postRevokeApiKey,
  type ApiKeyIssueResult,
} from "../../lib/money.js";
import { credentialPrefixKind, statusLabel } from "../../lib/labels.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

const QUERY_KEY = ["api-keys"] as const;
const IMPLEMENTERS_KEY = ["implementers"] as const;

export function ApiKeysPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [issued, setIssued] = useState<ApiKeyIssueResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [revokeError, setRevokeError] = useState<string | null>(null);
  /** Empty string = genesis default (server resolves). */
  const [selectedImplementerId, setSelectedImplementerId] = useState("");

  const implementersQ = useQuery({
    queryKey: [...IMPLEMENTERS_KEY],
    queryFn: listImplementers,
  });

  const list = useQuery({
    queryKey: [...QUERY_KEY, selectedImplementerId],
    queryFn: () =>
      listApiKeys(
        selectedImplementerId.length > 0
          ? { implementerId: selectedImplementerId }
          : undefined,
      ),
  });

  const activeImplementers = useMemo(
    () => (implementersQ.data?.implementers ?? []).filter((i) => i.retired_at === null),
    [implementersQ.data],
  );

  const implementerNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const row of implementersQ.data?.implementers ?? []) {
      map.set(row.id, row.name);
    }
    return map;
  }, [implementersQ.data]);

  const issue = useTotpGatedMutation<ApiKeyIssueResult, void>(
    (_v, totp) =>
      postIssueApiKey(
        selectedImplementerId.length > 0
          ? { implementerId: selectedImplementerId }
          : undefined,
        totp,
      ),
    {
      title: "Issue API key",
      detail: "Enter a fresh TOTP to mint a new implementer bearer key.",
      onSuccess: (result) => {
        setIssued(result);
        setCopied(false);
        setIssueError(null);
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (err: unknown) => {
        if (isCancelled(err)) return;
        setIssueError(formatMoneyError(err, "Issue failed."));
      },
    },
  );

  const revoke = useTotpGatedMutation<{ id: string; revoked: boolean }, string>(
    (credentialId, totp) => postRevokeApiKey(credentialId, totp),
    {
      title: "Revoke API key",
      detail: () => "Enter a fresh TOTP. The key stops working on the next request.",
      onSuccess: () => {
        setRevokeId(null);
        setRevokeError(null);
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (err: unknown) => {
        if (isCancelled(err)) return;
        setRevokeError(formatMoneyError(err, "Revoke failed."));
      },
    },
  );

  const keys = list.data?.keys ?? [];
  const live = list.data?.live === true;
  const unavailable = !live;

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Keys</h1>
        {list.isSuccess && !unavailable ? (
          <button
            type="button"
            className="pill primary"
            disabled={issue.isPending}
            onClick={() => {
              setIssueError(null);
              issue.mutate();
            }}
          >
            {issue.isPending ? "Issuing…" : "Issue key"}
          </button>
        ) : null}
      </div>

      <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }}>
        Integrations: <Link to="/integrations">Manage integrations</Link>
        {" · "}
        Operator device keys: <Link to="/devices">Devices</Link>
        {" · "}
        Dual-control &amp; operator push: <Link to="/operator-security">Operator security</Link>
      </p>

      <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }}>
        This list shows prefixes only — the full <code>ik_…</code> secret is returned once when
        you issue a key. Pick an integration to scope issue/list, or leave the default to use
        the genesis integration. A key already present after first boot was seeded at genesis;
        if you never copied a raw secret, issue a new key and store that secret in your
        integration backend.
      </p>

      {implementersQ.isSuccess && implementersQ.data?.live === true && activeImplementers.length > 0 ? (
        <label style={{ display: "block", marginBottom: 12, fontSize: 13 }}>
          <span className="muted" style={{ display: "block", marginBottom: 4 }}>
            Integration
          </span>
          <select
            aria-label="Integration"
            value={selectedImplementerId}
            onChange={(e) => setSelectedImplementerId(e.target.value)}
            style={{ minWidth: 220 }}
          >
            <option value="">Genesis default</option>
            {activeImplementers.map((row) => (
              <option key={row.id} value={row.id}>
                {row.name}
              </option>
            ))}
          </select>
        </label>
      ) : null}

      {list.isPending ? <p className="muted">Loading…</p> : null}

      {list.isError ? (
        <div className="banner banner-error" role="alert">
          API key inventory and issuing are not available. No keys can be shown or issued until
          the live node responds.
        </div>
      ) : null}

      {list.isSuccess && unavailable ? (
        <p className="muted">API key inventory and issuing are not available.</p>
      ) : null}

      {issueError ? (
        <div className="err" role="alert" style={{ marginTop: 8 }}>
          {issueError}
        </div>
      ) : null}

      {issued ? (
        <div className="card" data-testid="api-key-once" style={{ marginTop: 12 }}>
          <h2>New API key — copy it now</h2>
          <p className="muted">
            This is shown once and never stored in plaintext. Paste it into your integration
            website backend env — never customer browser JS.
          </p>
          <code
            data-testid="api-key-raw"
            style={{ display: "block", wordBreak: "break-all", marginTop: 8 }}
          >
            {issued.raw_key}
          </code>
          <div className="pill-row" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="pill"
              onClick={() => {
                void navigator.clipboard.writeText(issued.raw_key).then(
                  () => setCopied(true),
                  () => setCopied(false),
                );
              }}
            >
              {copied ? "Copied" : "Copy"}
            </button>
            <button
              type="button"
              className="pill primary"
              onClick={() => {
                stageIssuedIntegrationKey(issued.raw_key);
                void navigate("/connect");
              }}
            >
              Build Connect kit
            </button>
            <button type="button" className="pill" onClick={() => setIssued(null)}>
              Done
            </button>
          </div>
        </div>
      ) : null}

      {list.isSuccess && !unavailable ? (
        <div className="table-wrap" style={{ marginTop: 12 }}>
          <table>
            <thead>
              <tr>
                <th>Prefix</th>
                <th>Integration</th>
                <th>Status</th>
                <th>Scopes</th>
                <th>Created</th>
                <th>
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {keys.length === 0 ? (
                <tr>
                  <td colSpan={6} className="muted">
                    No API keys listed
                  </td>
                </tr>
              ) : (
                keys.map((k) => (
                  <tr key={k.id}>
                    <td>
                      <span className="muted" style={{ marginRight: 6 }}>
                        {credentialPrefixKind(k.prefix)}
                      </span>
                      <code>{k.prefix}…</code>
                    </td>
                    <td>
                      {implementerNameById.get(k.implementer_id) ?? (
                        <code className="muted">{k.implementer_id.slice(0, 8)}…</code>
                      )}
                    </td>
                    <td>
                      <span className={`tag ${k.status === "ACTIVE" ? "ok" : "muted"}`}>
                        {statusLabel(k.status)}
                      </span>
                    </td>
                    <td>{k.scopes.join(", ")}</td>
                    <td>{k.issued_at}</td>
                    <td>
                      {k.status === "ACTIVE" ? (
                        revokeId === k.id ? (
                          <span>
                            <button
                              type="button"
                              className="pill danger"
                              disabled={revoke.isPending}
                              onClick={() => revoke.mutate(k.id)}
                            >
                              {revoke.isPending ? "Revoking…" : "Confirm revoke"}
                            </button>{" "}
                            <button
                              type="button"
                              className="pill"
                              disabled={revoke.isPending}
                              onClick={() => {
                                setRevokeId(null);
                                setRevokeError(null);
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
                              setRevokeError(null);
                              setRevokeId(k.id);
                            }}
                          >
                            Revoke
                          </button>
                        )
                      ) : null}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : null}
      {revokeError ? (
        <div className="err" role="alert" style={{ marginTop: 8 }}>
          {revokeError}
        </div>
      ) : null}
    </div>
  );
}
