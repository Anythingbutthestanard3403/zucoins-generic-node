// SPA Integrations — named integration identities (create / list / retire).
// Retirement is an issuance gate only: existing keys keep authenticating until
// revoked. Operators issue keys under an integration from the Keys page.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import {
  formatMoneyError,
  isCancelled,
  listImplementers,
  postCreateImplementer,
  postRetireImplementer,
  type ImplementerListing,
} from "../../lib/money.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

const QUERY_KEY = ["implementers"] as const;

export function IntegrationsPage() {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [retireId, setRetireId] = useState<string | null>(null);
  const [retireError, setRetireError] = useState<string | null>(null);
  const [created, setCreated] = useState<ImplementerListing | null>(null);

  const list = useQuery({
    queryKey: [...QUERY_KEY],
    queryFn: listImplementers,
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

  const rows = list.data?.implementers ?? [];
  const live = list.data?.live === true;
  const unavailable = !live;
  const canCreate = name.trim().length > 0 && name.trim().length <= 128;

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

      {list.isPending ? <p className="muted">Loading…</p> : null}

      {list.isError || (list.isSuccess && unavailable) ? (
        <div className="banner banner-error" role="alert">
          Integration registry is not available.
        </div>
      ) : null}

      {list.isSuccess && !unavailable ? (
        <>
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
                    <td colSpan={5} className="muted">
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
                        <td>{row.created_at}</td>
                        <td>
                          <span className={`tag ${retired ? "muted" : "ok"}`}>
                            {retired ? "RETIRED" : "ACTIVE"}
                          </span>
                        </td>
                        <td>
                          {!retired ? (
                            retireId === row.id ? (
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
                            )
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
        </>
      ) : null}
    </div>
  );
}
