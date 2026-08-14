// Allow NODE_VERIFIED policy — operator-only whole-document editor (ZTR-1305).
// Per-implementer toggle for ops.allow_node_verified. Fail-closed display when
// the stored document is absent/corrupt/off. Fresh TOTP on save.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import {
  fetchAllowNodeVerifiedPolicy,
  formatMoneyError,
  isCancelled,
  listImplementers,
  postAllowNodeVerifiedPolicy,
  type AllowNodeVerifiedPolicyResponse,
  type AllowNodeVerifiedPolicyWriteBody,
  type ImplementerListing,
} from "../../lib/money.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

const QUERY_KEY = ["allow-node-verified-policy"] as const;
const IMPLEMENTERS_KEY = ["implementers"] as const;

type DraftEntry = {
  implementer_id: string;
  enabled: boolean;
};

function emptyDraft(): DraftEntry {
  return { implementer_id: "", enabled: true };
}

function draftsToBody(
  enabled: boolean,
  drafts: readonly DraftEntry[],
): AllowNodeVerifiedPolicyWriteBody {
  return {
    enabled,
    implementers: drafts.map((d) => ({
      implementer_id: d.implementer_id.trim(),
      enabled: d.enabled,
    })),
  };
}

function failClosedCopy(policy: AllowNodeVerifiedPolicyResponse | undefined): string | null {
  if (!policy || policy.status === "enabled") return null;
  switch (policy.disabledReason) {
    case "absent":
      return "Node-verified mode is OFF — no policy stored yet. NODE_VERIFIED create requests get 422.";
    case "unreadable":
      return "Node-verified mode is OFF — policy store unreadable.";
    case "invalid":
      return "Node-verified mode is OFF — stored policy invalid.";
    case "off":
      return "Node-verified mode is OFF — policy parked (enabled: false).";
    default:
      return "Node-verified mode is OFF.";
  }
}

function integrationName(
  id: string,
  rows: readonly ImplementerListing[] | undefined,
): string {
  const hit = rows?.find((r) => r.id === id);
  return hit?.name ?? id.slice(0, 8) + "…";
}

export function AllowNodeVerifiedPolicyPage() {
  const qc = useQueryClient();
  const [drafts, setDrafts] = useState<DraftEntry[]>([]);
  const [policyEnabled, setPolicyEnabled] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [hydrated, setHydrated] = useState(false);

  const policyQ = useQuery({
    queryKey: [...QUERY_KEY],
    queryFn: fetchAllowNodeVerifiedPolicy,
  });

  const implementersQ = useQuery({
    queryKey: [...IMPLEMENTERS_KEY],
    queryFn: listImplementers,
  });

  useEffect(() => {
    if (!policyQ.data || hydrated) return;
    const p = policyQ.data;
    setPolicyEnabled(p.status === "enabled");
    setDrafts(p.implementers.map((e) => ({ implementer_id: e.implementer_id, enabled: e.enabled })));
    setHydrated(true);
  }, [policyQ.data, hydrated]);

  const save = useTotpGatedMutation<AllowNodeVerifiedPolicyResponse, void>(
    (_v, totp) => postAllowNodeVerifiedPolicy(draftsToBody(policyEnabled, drafts), totp),
    {
      title: "Save node-verified policy",
      detail: "Enter a fresh TOTP to replace the whole policy document.",
      onSuccess: (result) => {
        setSaveError(null);
        setSaveMsg("Policy saved.");
        setPolicyEnabled(result.status === "enabled");
        setDrafts(
          result.implementers.map((e) => ({
            implementer_id: e.implementer_id,
            enabled: e.enabled,
          })),
        );
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (err: unknown) => {
        if (isCancelled(err)) return;
        setSaveMsg(null);
        setSaveError(formatMoneyError(err, "Save failed."));
      },
    },
  );

  const implementers = implementersQ.data?.implementers ?? [];
  const activeImplementers = useMemo(
    () => implementers.filter((i) => i.retired_at === null),
    [implementers],
  );

  const failClosed = failClosedCopy(policyQ.data);
  const liveEntries = policyQ.data?.implementers ?? [];

  function updateDraft(index: number, patch: Partial<DraftEntry>) {
    setDrafts((prev) => prev.map((d, i) => (i === index ? { ...d, ...patch } : d)));
  }

  function removeDraft(index: number) {
    setDrafts((prev) => prev.filter((_, i) => i !== index));
  }

  function addDraft() {
    setDrafts((prev) => [...prev, emptyDraft()]);
  }

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Node-verified policy</h1>
      </div>

      <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }}>
        Operator-only gate for <code>NODE_VERIFIED</code> admission. When enabled for an{" "}
        <Link to="/integrations">integration</Link>, that implementer may create receive /
        move / send operations in node-verified mode. Disabled ⇒ create returns 422
        immediately (fail-closed; no cache beyond one policy read). See{" "}
        <code>docs/operations/verification-modes.md</code>.
      </p>

      {policyQ.isPending ? <p className="muted">Loading…</p> : null}

      {policyQ.isError ? (
        <div className="banner banner-error" role="alert">
          Node-verified policy endpoint unavailable.
        </div>
      ) : null}

      {failClosed ? (
        <div
          className="banner banner-warn"
          role="status"
          data-testid="allow-node-verified-fail-closed"
        >
          {failClosed}
        </div>
      ) : null}

      {policyQ.isSuccess ? (
        <>
          <section
            className="card"
            style={{ marginBottom: 16 }}
            data-testid="allow-node-verified-entries"
          >
            <h2>Current implementers</h2>
            {liveEntries.length === 0 ? (
              <p className="muted" data-testid="allow-node-verified-empty">
                No implementer entries in the stored document.
              </p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Integration</th>
                      <th scope="col">Enabled</th>
                    </tr>
                  </thead>
                  <tbody>
                    {liveEntries.map((e) => (
                      <tr
                        key={e.implementer_id}
                        data-testid={`allow-node-verified-entry-${e.implementer_id}`}
                      >
                        <td>{integrationName(e.implementer_id, implementers)}</td>
                        <td>{e.enabled ? "yes" : "no"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {policyQ.data?.server_time ? (
              <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
                Server time: {policyQ.data.server_time}
              </p>
            ) : null}
          </section>

          <section className="card" data-testid="allow-node-verified-editor">
            <h2>Edit policy</h2>
            <p className="muted" style={{ fontSize: 12.5 }}>
              Whole-document replace. Invalid documents are rejected (nothing stored).
              Saving requires a fresh single-use TOTP. Residual risk (gateway eclipse) is
              documented in ops — enable only when you accept the node&apos;s chain view as
              custody authority for that implementer.
            </p>

            <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 12 }}>
              <input
                type="checkbox"
                checked={policyEnabled}
                onChange={(e) => setPolicyEnabled(e.target.checked)}
                data-testid="allow-node-verified-enabled"
              />
              <span>Policy enabled (NODE_VERIFIED admission for listed implementers)</span>
            </label>

            {drafts.map((d, i) => (
              <fieldset
                key={i}
                style={{
                  border: "1px solid var(--border, #333)",
                  borderRadius: 8,
                  padding: 12,
                  marginTop: 12,
                }}
                data-testid={`allow-node-verified-draft-${i}`}
              >
                <legend>Implementer {i + 1}</legend>
                <label style={{ display: "block", marginTop: 8, fontSize: 13 }}>
                  <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                    Integration
                  </span>
                  <select
                    value={d.implementer_id}
                    onChange={(e) => updateDraft(i, { implementer_id: e.target.value })}
                    aria-label={`Implementer ${i + 1} integration`}
                    style={{ width: "100%" }}
                  >
                    <option value="">Select integration…</option>
                    {activeImplementers.map((imp) => (
                      <option key={imp.id} value={imp.id}>
                        {imp.name}
                      </option>
                    ))}
                    {d.implementer_id &&
                    !activeImplementers.some((imp) => imp.id === d.implementer_id) ? (
                      <option value={d.implementer_id}>
                        {integrationName(d.implementer_id, implementers)} (current)
                      </option>
                    ) : null}
                  </select>
                </label>
                <label
                  style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10 }}
                >
                  <input
                    type="checkbox"
                    checked={d.enabled}
                    onChange={(e) => updateDraft(i, { enabled: e.target.checked })}
                    aria-label={`Implementer ${i + 1} enabled`}
                  />
                  <span>Allow NODE_VERIFIED for this implementer</span>
                </label>
                <button
                  type="button"
                  className="pill"
                  style={{ marginTop: 10 }}
                  onClick={() => removeDraft(i)}
                >
                  Remove
                </button>
              </fieldset>
            ))}

            <div style={{ display: "flex", gap: 8, marginTop: 16, flexWrap: "wrap" }}>
              <button type="button" className="pill" onClick={addDraft}>
                Add implementer
              </button>
              <button
                type="button"
                className="btn"
                disabled={save.isPending}
                onClick={() => {
                  setSaveError(null);
                  setSaveMsg(null);
                  save.mutate();
                }}
                data-testid="allow-node-verified-save"
              >
                {save.isPending ? "Saving…" : "Save policy"}
              </button>
            </div>

            {saveError ? (
              <p className="err" role="alert" data-testid="allow-node-verified-save-error">
                {saveError}
              </p>
            ) : null}
            {saveMsg ? (
              <p className="ok" data-testid="allow-node-verified-save-ok">
                {saveMsg}
              </p>
            ) : null}
          </section>
        </>
      ) : null}
    </div>
  );
}
