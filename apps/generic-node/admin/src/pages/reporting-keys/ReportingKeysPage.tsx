// SPA Reporting — live reporting-credential management.
// Issue node-mints the reporting credential and returns the raw private seed exactly once.
// Lost-seed recovery is a first-class TOTP-gated action (not an env-var reset): retires the
// bricked implementer and returns a new reporting seed + implementer ik_ once.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  formatMoneyError,
  isCancelled,
  listReportingKeys,
  postIssueReportingKey,
  postRecoverLostReportingKey,
  type ReportingKeyIssueResult,
  type ReportingKeyRecoverResult,
} from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

const QUERY_KEY = ["reporting-keys"] as const;

type OnceShown =
  | { readonly kind: "issue"; readonly result: ReportingKeyIssueResult }
  | { readonly kind: "recover"; readonly result: ReportingKeyRecoverResult };

export function ReportingKeysPage() {
  const demoMode = useAuth((s) => s.demoMode);
  const qc = useQueryClient();
  const [issued, setIssued] = useState<OnceShown | null>(null);
  const [copiedSeed, setCopiedSeed] = useState(false);
  const [copiedIk, setCopiedIk] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [recoverConfirm, setRecoverConfirm] = useState(false);

  const list = useQuery({
    queryKey: [...QUERY_KEY, demoMode],
    queryFn: listReportingKeys,
    enabled: !demoMode,
  });

  const issue = useTotpGatedMutation<ReportingKeyIssueResult, void>(
    (_v, totp) => postIssueReportingKey(totp),
    {
      title: "Issue reporting credential",
      detail: "Enter a fresh TOTP to mint the node's reporting credential.",
      onSuccess: (result) => {
        setIssued({ kind: "issue", result });
        setCopiedSeed(false);
        setCopiedIk(false);
        setIssueError(null);
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (err: unknown) => {
        if (isCancelled(err)) return;
        setIssueError(formatMoneyError(err, "Issue failed."));
      },
    },
  );

  const recover = useTotpGatedMutation<ReportingKeyRecoverResult, string>(
    (lostKeyId, totp) => postRecoverLostReportingKey(lostKeyId, totp),
    {
      title: "Recover lost reporting key",
      detail:
        "This retires the old reporting identity and mints a new seed. Enter a fresh TOTP.",
      onSuccess: (result) => {
        setIssued({ kind: "recover", result });
        setCopiedSeed(false);
        setCopiedIk(false);
        setIssueError(null);
        setRecoverConfirm(false);
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (err: unknown) => {
        if (isCancelled(err)) return;
        setIssueError(formatMoneyError(err, "Recovery failed."));
      },
    },
  );

  const keys = list.data?.keys ?? [];
  const live = list.data?.live === true;
  const unavailable = !demoMode && !live;
  const activeKey = keys.find((k) => k.status === "ACTIVE") ?? null;
  const canIssue = !demoMode && list.isSuccess && !unavailable && activeKey === null;
  const canRecover = !demoMode && list.isSuccess && !unavailable && activeKey !== null;

  const seedText =
    issued === null
      ? ""
      : issued.kind === "issue"
        ? issued.result.raw_private_key
        : issued.result.raw_private_key;
  const keyIdText =
    issued === null
      ? ""
      : issued.kind === "issue"
        ? issued.result.key_id
        : issued.result.key_id;

  function downloadSecrets() {
    if (issued === null) return;
    const lines =
      issued.kind === "issue"
        ? [
            "Zu Node reporting credential — SAVE THIS FILE",
            `key_id=${issued.result.key_id}`,
            `public_key=${issued.result.public_key}`,
            `raw_private_key=${issued.result.raw_private_key}`,
            "",
            "Shown once. Never commit. Not in the recovery pack.",
          ]
        : [
            "Zu Node reporting + implementer recovery — SAVE THIS FILE",
            `superseded_key_id=${issued.result.superseded_key_id}`,
            `reporting_key_id=${issued.result.key_id}`,
            `reporting_public_key=${issued.result.public_key}`,
            `reporting_raw_private_key=${issued.result.raw_private_key}`,
            `implementer_id=${issued.result.implementer_id}`,
            `implementer_key_prefix=${issued.result.implementer_key_prefix}`,
            `implementer_raw_key=${issued.result.implementer_raw_key}`,
            "",
            "Shown once. Never commit. Recovery pack does NOT contain these.",
          ];
    const blob = new Blob([lines.join("\n") + "\n"], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download =
      issued.kind === "issue"
        ? `zu-reporting-key-${issued.result.key_id.slice(0, 8)}.txt`
        : `zu-reporting-recovery-${issued.result.key_id.slice(0, 8)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    setCopiedSeed(true);
  }

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Reporting</h1>
        {canIssue ? (
          <button
            type="button"
            className="pill primary"
            disabled={issue.isPending}
            onClick={() => {
              setIssueError(null);
              issue.mutate();
            }}
          >
            {issue.isPending ? "Issuing…" : "Issue reporting credential"}
          </button>
        ) : null}
      </div>

      <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }}>
        The reporting private seed is shown <strong>once</strong> and is never stored on the
        node. It is <strong>not</strong> inside your recovery pack (that pack is vault master
        only). Save it to a password manager immediately.
      </p>

      {demoMode ? (
        <p className="muted">
          No fixtures — log in for a live session to manage reporting credentials.
        </p>
      ) : null}

      {!demoMode && list.isPending ? <p className="muted">Loading…</p> : null}

      {!demoMode && list.isError ? (
        <div className="banner banner-error" role="alert">
          Reporting credential inventory and issuing are not available. No credentials can be
          shown or issued until the live node responds.
        </div>
      ) : null}

      {list.isSuccess && unavailable ? (
        <p className="muted">Reporting credential inventory and issuing are not available.</p>
      ) : null}

      {issueError ? (
        <div className="err" role="alert" style={{ marginTop: 8 }}>
          {issueError}
        </div>
      ) : null}

      {canRecover && !issued ? (
        <div className="card" data-testid="reporting-recover-panel" style={{ marginTop: 12 }}>
          <h2 style={{ marginTop: 0, fontSize: 15 }}>Lost the private seed?</h2>
          <p className="muted" style={{ fontSize: 13 }}>
            If you never saved the seed (or lost the password-manager entry), you cannot get the
            old one back — the node never stored it. You <strong>can</strong> mint a replacement
            here with TOTP. This retires the old reporting identity and issues a new seed plus a
            new implementer API key (old <code>ik_…</code> stops working).
          </p>
          {!recoverConfirm ? (
            <button
              type="button"
              className="pill"
              data-testid="reporting-recover-start"
              onClick={() => setRecoverConfirm(true)}
            >
              I lost this key — get a new one
            </button>
          ) : (
            <div data-testid="reporting-recover-confirm">
              <div className="banner banner-error" role="alert" style={{ marginBottom: 12 }}>
                Confirm: the current ACTIVE reporting key will be retired. You must save the new
                seed and the new implementer key when they appear. This cannot be undone.
              </div>
              <div className="pill-row">
                <button
                  type="button"
                  className="pill primary"
                  disabled={recover.isPending || activeKey === null}
                  data-testid="reporting-recover-confirm-btn"
                  onClick={() => {
                    if (activeKey === null) return;
                    setIssueError(null);
                    recover.mutate(activeKey.id);
                  }}
                >
                  {recover.isPending ? "Recovering…" : "Yes, mint replacement (TOTP)"}
                </button>
                <button
                  type="button"
                  className="pill"
                  disabled={recover.isPending}
                  onClick={() => setRecoverConfirm(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      ) : null}

      {issued ? (
        <div className="card" data-testid="reporting-key-once" style={{ marginTop: 12 }}>
          <h3>
            {issued.kind === "recover"
              ? "Replacement secrets — copy or download now"
              : "New reporting credential — copy it now"}
          </h3>
          <p className="muted">
            Shown once and never stored. Not in the recovery pack. Paste into your password
            manager and server secret store — never customer browser JS.
          </p>
          <p className="muted" style={{ fontSize: 12 }}>
            Key id: <code data-testid="reporting-key-id">{keyIdText}</code>
          </p>
          <code
            data-testid="reporting-key-raw"
            style={{ display: "block", wordBreak: "break-all", marginTop: 8 }}
          >
            {seedText}
          </code>
          {issued.kind === "recover" ? (
            <>
              <h4 style={{ marginTop: 16, fontSize: 14 }}>New implementer API key</h4>
              <p className="muted" style={{ fontSize: 12 }}>
                Prefix <code>{issued.result.implementer_key_prefix}</code> — old ik_ keys for the
                retired implementer no longer work.
              </p>
              <code
                data-testid="implementer-key-raw"
                style={{ display: "block", wordBreak: "break-all", marginTop: 8 }}
              >
                {issued.result.implementer_raw_key}
              </code>
            </>
          ) : null}
          <div className="pill-row" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="pill primary"
              data-testid="reporting-download-secrets"
              onClick={() => downloadSecrets()}
            >
              Download secrets file
            </button>
            <button
              type="button"
              className="pill"
              onClick={() => {
                void navigator.clipboard.writeText(seedText).then(
                  () => setCopiedSeed(true),
                  () => setCopiedSeed(false),
                );
              }}
            >
              {copiedSeed ? "Seed copied" : "Copy reporting seed"}
            </button>
            {issued.kind === "recover" ? (
              <button
                type="button"
                className="pill"
                onClick={() => {
                  void navigator.clipboard.writeText(issued.result.implementer_raw_key).then(
                    () => setCopiedIk(true),
                    () => setCopiedIk(false),
                  );
                }}
              >
                {copiedIk ? "API key copied" : "Copy implementer key"}
              </button>
            ) : null}
            <button
              type="button"
              className="pill"
              data-testid="reporting-once-done"
              disabled={!copiedSeed && issued.kind === "issue"}
              title={
                !copiedSeed && issued.kind === "issue"
                  ? "Copy or download the seed before dismissing"
                  : undefined
              }
              onClick={() => {
                if (issued.kind === "issue" && !copiedSeed) return;
                if (issued.kind === "recover" && !copiedSeed && !copiedIk) {
                  // still allow dismiss after download (download sets copiedSeed)
                  if (!copiedSeed) return;
                }
                setIssued(null);
                setCopiedSeed(false);
                setCopiedIk(false);
              }}
            >
              Done
            </button>
          </div>
          {issued.kind === "issue" && !copiedSeed ? (
            <p className="muted" style={{ fontSize: 12, marginTop: 8 }} role="status">
              Copy or download before Done — this screen will not show the seed again.
            </p>
          ) : null}
          {issued.kind === "recover" && !copiedSeed ? (
            <p className="muted" style={{ fontSize: 12, marginTop: 8 }} role="status">
              Download or copy the reporting seed (and implementer key) before Done.
            </p>
          ) : null}
        </div>
      ) : null}

      {demoMode || (list.isSuccess && !unavailable) ? (
        <div className="table-wrap" style={{ marginTop: 12 }}>
          <table>
            <thead>
              <tr>
                <th>Id</th>
                <th>Public key</th>
                <th>Status</th>
                <th>Registered</th>
              </tr>
            </thead>
            <tbody>
              {demoMode || keys.length === 0 ? (
                <tr>
                  <td colSpan={4} className="muted">
                    No reporting credentials listed
                  </td>
                </tr>
              ) : (
                keys.map((k) => (
                  <tr key={k.id}>
                    <td>
                      <code style={{ fontSize: 11 }}>{k.id}</code>
                    </td>
                    <td>
                      <code>{k.public_key}</code>
                    </td>
                    <td>
                      <span className={`tag ${k.status === "ACTIVE" ? "ok" : "muted"}`}>
                        {k.status}
                      </span>
                    </td>
                    <td>{k.registered_at}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
