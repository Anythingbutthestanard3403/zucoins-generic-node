// Auto-approve policy — operator-only whole-document editor (ZTR-1237).
// Rules bind to named integrations. Fail-closed display when the stored
// document is absent/corrupt/off. Wording stays inside the forbidden-
// vocabulary scanner (no banned product terms).

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import {
  fetchAutoApprovePolicy,
  formatMoneyError,
  isCancelled,
  listImplementers,
  postAutoApprovePolicy,
  type AutoApprovePolicyResponse,
  type AutoApprovePolicyWriteBody,
  type AutoApproveRuleView,
  type ImplementerListing,
} from "../../lib/money.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

const QUERY_KEY = ["auto-approve-policy"] as const;
const IMPLEMENTERS_KEY = ["implementers"] as const;

type DraftRule = {
  rule_id: string;
  implementer_id: string;
  per_send_max_zkz: string;
  per_send_min_zkz: string;
  window_hours: string;
  window_cap_zkz: string;
  expires_at: string;
  enabled: boolean;
};

function emptyDraft(): DraftRule {
  return {
    rule_id: "",
    implementer_id: "",
    per_send_max_zkz: "",
    per_send_min_zkz: "",
    window_hours: "24",
    window_cap_zkz: "",
    expires_at: "",
    enabled: true,
  };
}

function ruleToDraft(r: AutoApproveRuleView): DraftRule {
  return {
    rule_id: r.rule_id,
    implementer_id: r.implementer_id,
    per_send_max_zkz: r.per_send_max_zkz,
    per_send_min_zkz: r.per_send_min_zkz ?? "",
    window_hours: String(r.window_hours),
    window_cap_zkz: r.window_cap_zkz,
    expires_at: r.expires_at ?? "",
    enabled: r.enabled,
  };
}

function draftsToBody(enabled: boolean, drafts: readonly DraftRule[]): AutoApprovePolicyWriteBody {
  return {
    enabled,
    rules: drafts.map((d) => ({
      rule_id: d.rule_id.trim(),
      implementer_id: d.implementer_id.trim(),
      per_send_max_zkz: d.per_send_max_zkz.trim(),
      per_send_min_zkz: d.per_send_min_zkz.trim() === "" ? null : d.per_send_min_zkz.trim(),
      window_hours: Number.parseInt(d.window_hours, 10),
      window_cap_zkz: d.window_cap_zkz.trim(),
      expires_at: d.expires_at.trim() === "" ? null : d.expires_at.trim(),
      enabled: d.enabled,
    })),
  };
}

function failClosedCopy(policy: AutoApprovePolicyResponse | undefined): string | null {
  if (!policy || policy.status === "enabled") return null;
  switch (policy.disabledReason) {
    case "absent":
      return "Automatic approval of external sends is OFF — no policy stored yet.";
    case "unreadable":
      return "Automatic approval of external sends is OFF — policy store unreadable.";
    case "invalid":
      return "Automatic approval of external sends is OFF — stored policy invalid.";
    case "off":
      return "Automatic approval of external sends is OFF — policy parked (enabled: false).";
    default:
      return "Automatic approval of external sends is OFF.";
  }
}

function integrationName(
  id: string,
  rows: readonly ImplementerListing[] | undefined,
): string {
  const hit = rows?.find((r) => r.id === id);
  return hit?.name ?? id.slice(0, 8) + "…";
}

export function AutoApprovePolicyPage() {
  const qc = useQueryClient();
  const [drafts, setDrafts] = useState<DraftRule[]>([]);
  const [policyEnabled, setPolicyEnabled] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [hydrated, setHydrated] = useState(false);

  const policyQ = useQuery({
    queryKey: [...QUERY_KEY],
    queryFn: fetchAutoApprovePolicy,
  });

  const implementersQ = useQuery({
    queryKey: [...IMPLEMENTERS_KEY],
    queryFn: listImplementers,
  });

  useEffect(() => {
    if (!policyQ.data || hydrated) return;
    const p = policyQ.data;
    setPolicyEnabled(p.status === "enabled");
    setDrafts(p.rules.map(ruleToDraft));
    setHydrated(true);
  }, [policyQ.data, hydrated]);

  // Re-hydrate drafts after a successful save (fresh spend + server_time).
  useEffect(() => {
    if (!policyQ.data || !hydrated) return;
    // Only sync when query refetched after our invalidate and local saveMsg is set.
  }, [policyQ.data, hydrated]);

  const save = useTotpGatedMutation<AutoApprovePolicyResponse, void>(
    (_v, totp) => postAutoApprovePolicy(draftsToBody(policyEnabled, drafts), totp),
    {
      title: "Save auto-approve policy",
      detail: "Enter a fresh TOTP to replace the whole policy document.",
      onSuccess: (result) => {
        setSaveError(null);
        setSaveMsg("Policy saved.");
        setPolicyEnabled(result.status === "enabled");
        setDrafts(result.rules.map(ruleToDraft));
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
  const liveRules = policyQ.data?.rules ?? [];

  function updateDraft(index: number, patch: Partial<DraftRule>) {
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
        <h1>Auto-approve</h1>
      </div>

      <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }}>
        Operator-only rules for automatic approval of external sends. Each rule
        binds to one{" "}
        <Link to="/integrations">integration</Link> and caps spending allowance
        per send and rolling window. An API key can never set or widen its own
        caps — only this page writes the policy.
      </p>

      {policyQ.isPending ? <p className="muted">Loading…</p> : null}

      {policyQ.isError ? (
        <div className="banner banner-error" role="alert">
          Auto-approve policy endpoint unavailable.
        </div>
      ) : null}

      {failClosed ? (
        <div className="banner banner-warn" role="status" data-testid="auto-approve-fail-closed">
          {failClosed}
        </div>
      ) : null}

      {policyQ.isSuccess ? (
        <>
          <section className="card" style={{ marginBottom: 16 }} data-testid="auto-approve-rules">
            <h2>Current rules</h2>
            {liveRules.length === 0 ? (
              <p className="muted" data-testid="auto-approve-empty">
                No rules in the stored document.
              </p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Rule</th>
                      <th scope="col">Integration</th>
                      <th scope="col">Per-send max</th>
                      <th scope="col">Window</th>
                      <th scope="col">Spend vs cap</th>
                      <th scope="col">Expires</th>
                      <th scope="col">Enabled</th>
                    </tr>
                  </thead>
                  <tbody>
                    {liveRules.map((r) => (
                      <tr key={r.rule_id} data-testid={`auto-approve-rule-${r.rule_id}`}>
                        <td>
                          <code>{r.rule_id}</code>
                        </td>
                        <td>{integrationName(r.implementer_id, implementers)}</td>
                        <td>
                          <code>{r.per_send_max_zkz}</code>
                          {r.per_send_min_zkz ? (
                            <span className="muted"> (min {r.per_send_min_zkz})</span>
                          ) : null}
                        </td>
                        <td>{r.window_hours}h</td>
                        <td data-testid={`spend-${r.rule_id}`}>
                          <code>
                            {r.current_window_spend_zkz} of {r.window_cap_zkz}
                          </code>
                        </td>
                        <td>{r.expires_at ?? "—"}</td>
                        <td>{r.enabled ? "yes" : "no"}</td>
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

          <section className="card" data-testid="auto-approve-editor">
            <h2>Edit policy</h2>
            <p className="muted" style={{ fontSize: 12.5 }}>
              Whole-document replace. Invalid documents are rejected (nothing
              stored). Saving requires a fresh single-use TOTP.
            </p>

            <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 12 }}>
              <input
                type="checkbox"
                checked={policyEnabled}
                onChange={(e) => setPolicyEnabled(e.target.checked)}
                data-testid="auto-approve-enabled"
              />
              <span>Policy enabled (automatic approval of external sends)</span>
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
                data-testid={`auto-approve-draft-${i}`}
              >
                <legend>Rule {i + 1}</legend>
                <label style={{ display: "block", marginTop: 8, fontSize: 13 }}>
                  <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                    Rule id
                  </span>
                  <input
                    type="text"
                    value={d.rule_id}
                    onChange={(e) => updateDraft(i, { rule_id: e.target.value })}
                    aria-label={`Rule ${i + 1} id`}
                    style={{ width: "100%" }}
                  />
                </label>
                <label style={{ display: "block", marginTop: 8, fontSize: 13 }}>
                  <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                    Integration
                  </span>
                  <select
                    value={d.implementer_id}
                    onChange={(e) => updateDraft(i, { implementer_id: e.target.value })}
                    aria-label={`Rule ${i + 1} integration`}
                    style={{ width: "100%" }}
                  >
                    <option value="">Select integration…</option>
                    {activeImplementers.map((imp) => (
                      <option key={imp.id} value={imp.id}>
                        {imp.name}
                      </option>
                    ))}
                    {/* Keep current id selectable even if retired/missing from list */}
                    {d.implementer_id &&
                    !activeImplementers.some((imp) => imp.id === d.implementer_id) ? (
                      <option value={d.implementer_id}>
                        {integrationName(d.implementer_id, implementers)} (current)
                      </option>
                    ) : null}
                  </select>
                </label>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: 8,
                    marginTop: 8,
                  }}
                >
                  <label style={{ fontSize: 13 }}>
                    <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                      Per-send max (ZKZ)
                    </span>
                    <input
                      type="text"
                      inputMode="decimal"
                      value={d.per_send_max_zkz}
                      onChange={(e) => updateDraft(i, { per_send_max_zkz: e.target.value })}
                      aria-label={`Rule ${i + 1} per-send max`}
                      style={{ width: "100%" }}
                    />
                  </label>
                  <label style={{ fontSize: 13 }}>
                    <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                      Per-send min (optional)
                    </span>
                    <input
                      type="text"
                      inputMode="decimal"
                      value={d.per_send_min_zkz}
                      onChange={(e) => updateDraft(i, { per_send_min_zkz: e.target.value })}
                      aria-label={`Rule ${i + 1} per-send min`}
                      style={{ width: "100%" }}
                    />
                  </label>
                  <label style={{ fontSize: 13 }}>
                    <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                      Window hours
                    </span>
                    <input
                      type="number"
                      min={1}
                      value={d.window_hours}
                      onChange={(e) => updateDraft(i, { window_hours: e.target.value })}
                      aria-label={`Rule ${i + 1} window hours`}
                      style={{ width: "100%" }}
                    />
                  </label>
                  <label style={{ fontSize: 13 }}>
                    <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                      Window cap (ZKZ)
                    </span>
                    <input
                      type="text"
                      inputMode="decimal"
                      value={d.window_cap_zkz}
                      onChange={(e) => updateDraft(i, { window_cap_zkz: e.target.value })}
                      aria-label={`Rule ${i + 1} window cap`}
                      style={{ width: "100%" }}
                    />
                  </label>
                  <label style={{ fontSize: 13, gridColumn: "1 / -1" }}>
                    <span className="muted" style={{ display: "block", marginBottom: 4 }}>
                      Expires at (RFC3339 Z, optional)
                    </span>
                    <input
                      type="text"
                      value={d.expires_at}
                      onChange={(e) => updateDraft(i, { expires_at: e.target.value })}
                      aria-label={`Rule ${i + 1} expires at`}
                      placeholder="2026-12-31T00:00:00Z"
                      style={{ width: "100%" }}
                    />
                  </label>
                </div>
                <label
                  style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10 }}
                >
                  <input
                    type="checkbox"
                    checked={d.enabled}
                    onChange={(e) => updateDraft(i, { enabled: e.target.checked })}
                    aria-label={`Rule ${i + 1} enabled`}
                  />
                  <span>Rule enabled</span>
                </label>
                <button
                  type="button"
                  className="pill"
                  style={{ marginTop: 10 }}
                  onClick={() => removeDraft(i)}
                >
                  Remove rule
                </button>
              </fieldset>
            ))}

            <div style={{ display: "flex", gap: 8, marginTop: 16, flexWrap: "wrap" }}>
              <button type="button" className="pill" onClick={addDraft}>
                Add rule
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
                data-testid="auto-approve-save"
              >
                {save.isPending ? "Saving…" : "Save policy"}
              </button>
            </div>

            {saveError ? (
              <p className="err" role="alert" data-testid="auto-approve-save-error">
                {saveError}
              </p>
            ) : null}
            {saveMsg ? (
              <p className="ok" data-testid="auto-approve-save-ok">
                {saveMsg}
              </p>
            ) : null}
          </section>
        </>
      ) : null}
    </div>
  );
}
