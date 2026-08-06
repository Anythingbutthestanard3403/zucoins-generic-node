// Lab receive tool — operator-only capped RECEIVE + code display.
// Real chain rules; wake ≠ proof; no false paid; no gate bypass.

import { useMutation, useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { TotpQrCode } from "../../components/TotpQrCode.js";
import { ApiError, api } from "../../lib/api.js";
import { fetchReadinessChecklist, type ReadinessChecklist } from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";

const LAB_CAP = "0.01";

export interface LabReceiveSuccess {
  readonly object: "lab_receive";
  readonly lab: true;
  readonly non_production_label: string;
  readonly amount_zkz: string;
  readonly operation_id: string;
  readonly state: string;
  readonly code_status: string;
  readonly transfer_code: string;
  readonly transfer_code_sha256: string;
  readonly expires_at: string | null;
  readonly receiver_pubkey: string | null;
  readonly discriminator: string | null;
  readonly reminders: {
    readonly wake_is_not_proof: true;
    readonly independent_verify_required: true;
    readonly verification_complete_required: true;
    readonly no_false_paid: true;
  };
}

export interface LabGateLink {
  readonly id: string;
  readonly href: string;
  readonly title: string;
  readonly detail: string;
  readonly status: string;
}

async function postLabReceive(input: {
  amount_zkz: string;
  reporting_key_id: string;
  reporting_private_seed_hex: string;
  totp: string;
}): Promise<LabReceiveSuccess> {
  return api<LabReceiveSuccess>("/lab/receive", {
    method: "POST",
    totp: input.totp,
    body: JSON.stringify({
      amount_zkz: input.amount_zkz,
      reporting_key_id: input.reporting_key_id,
      reporting_private_seed_hex: input.reporting_private_seed_hex,
    }),
  });
}

export function LabReceivePage() {
  const demo = useAuth((s) => s.demoMode);
  const [amount, setAmount] = useState(LAB_CAP);
  const [keyId, setKeyId] = useState("");
  const [seed, setSeed] = useState("");
  const [totp, setTotp] = useState("");
  const [result, setResult] = useState<LabReceiveSuccess | null>(null);
  const [gateLinks, setGateLinks] = useState<readonly LabGateLink[] | null>(null);

  const readinessQ = useQuery({
    queryKey: ["lab-readiness", demo],
    queryFn: fetchReadinessChecklist,
    enabled: !demo,
    refetchInterval: demo ? false : 30_000,
    retry: false,
  });
  const checklist: ReadinessChecklist | null = readinessQ.data ?? null;
  const receiveBlocked =
    checklist?.rows.some(
      (r) =>
        (r.status === "blocked" || r.status === "amber") &&
        (r.blocks_ops?.includes("RECEIVE_EXTERNAL") ||
          r.id === "recovery_verified_wallet" ||
          r.id === "reporting_key_active" ||
          r.id === "implementer_key" ||
          r.id === "node_healthy"),
    ) ?? false;

  const mut = useMutation({
    mutationFn: postLabReceive,
    onSuccess: (body) => {
      setResult(body);
      setGateLinks(null);
      setSeed(""); // drop seed from React state after use
    },
    onError: (err: unknown) => {
      setResult(null);
      if (err instanceof ApiError && Array.isArray(err.extras?.checklist_links)) {
        setGateLinks(err.extras.checklist_links as readonly LabGateLink[]);
      }
    },
  });

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (demo) return;
    mut.mutate({
      amount_zkz: amount.trim(),
      reporting_key_id: keyId.trim(),
      reporting_private_seed_hex: seed.trim(),
      totp: totp.trim(),
    });
  }

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Lab receive</h1>
      </div>

      <div className="banner" role="status" data-testid="lab-banner" style={{ marginBottom: 16 }}>
        <strong>Lab / non-production tool.</strong> Creates a real{" "}
        <code className="mono">RECEIVE_EXTERNAL</code> capped at ≤ {LAB_CAP} ZKZ. Chain rules
        still apply. <strong>Wake ≠ proof</strong> — node status is not settlement. Never treat
        this screen as &quot;paid&quot;. You must still run independent verify and{" "}
        <code className="mono">verification-complete</code> or the pool wallet stays pinned.
      </div>

      {demo ? (
        <p className="muted">Design preview — log in for a live lab session.</p>
      ) : null}

      {!demo && receiveBlocked ? (
        <div className="banner banner-error" role="alert" style={{ marginBottom: 16 }}>
          Checklist is not green for Incoming. Lab will not bypass recovery_verified or reporting
          gates.{" "}
          <Link to="/" className="linkish">
            Open Home checklist →
          </Link>
          {checklist?.rows
            .filter((r) => r.status === "blocked" || r.status === "amber")
            .slice(0, 6)
            .map((r) => (
              <div key={r.id} style={{ marginTop: 8 }}>
                <Link to={r.href} className="linkish">
                  {r.title}
                </Link>
                <span className="muted"> — {r.detail}</span>
              </div>
            ))}
        </div>
      ) : null}

      {gateLinks && gateLinks.length > 0 ? (
        <div className="banner banner-error" role="alert" style={{ marginBottom: 16 }}>
          Server refused lab receive — fix checklist items:
          <ul style={{ margin: "8px 0 0", paddingLeft: 18 }}>
            {gateLinks.map((l) => (
              <li key={l.id}>
                <Link to={l.href} className="linkish">
                  {l.title}
                </Link>
                <span className="muted"> — {l.detail}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {!result ? (
        <form className="card form-card" onSubmit={onSubmit} data-testid="lab-receive-form">
          <label className="field">
            <span>Amount (ZKZ) — max {LAB_CAP}</span>
            <input
              className="mono"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              inputMode="decimal"
              required
              aria-label="Lab receive amount ZKZ"
            />
          </label>
          <label className="field">
            <span>Reporting key id (UUID from Reporting page)</span>
            <input
              className="mono"
              value={keyId}
              onChange={(e) => setKeyId(e.target.value)}
              required
              autoComplete="off"
              aria-label="Reporting key id"
            />
          </label>
          <label className="field">
            <span>
              Reporting private seed (hex, once) — used only for ARM; never stored or logged
            </span>
            <input
              className="mono"
              type="password"
              value={seed}
              onChange={(e) => setSeed(e.target.value)}
              required
              autoComplete="off"
              aria-label="Reporting private seed hex"
            />
          </label>
          <label className="field">
            <span>Operator TOTP</span>
            <input
              className="mono"
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
              inputMode="numeric"
              pattern="\d{6}"
              maxLength={6}
              required
              autoComplete="one-time-code"
              aria-label="TOTP code"
            />
          </label>
          <div className="form-actions">
            <button
              type="submit"
              className="mini-btn primary"
              disabled={mut.isPending || demo}
            >
              {mut.isPending ? "Creating + ARM…" : "Create lab receive + ARM"}
            </button>
            <Link to="/reporting-keys" className="mini-btn">
              Reporting keys
            </Link>
            <Link to="/" className="mini-btn">
              Checklist
            </Link>
          </div>
          {mut.isError ? <ApiErrorNote error={mut.error instanceof ApiError ? { code: mut.error.code, message: mut.error.message, status: mut.error.status, requestId: mut.error.requestId } : { code: "error", message: String(mut.error), status: 0 }} /> : null}
          <p className="muted" style={{ fontSize: 12.5, marginTop: 12 }}>
            Cap is enforced server-side. Prefer the Integration kit for production consumer flows.
            After ARM, remind the sender path to verify independently — this UI never claims paid.
          </p>
        </form>
      ) : (
        <div className="card form-card" data-testid="lab-receive-result">
          <div className="banner" role="status" style={{ marginBottom: 12 }}>
            Lab code released — <strong>not paid</strong>. Wake ≠ proof. Complete independent verify
            then <code className="mono">verification-complete</code>.
          </div>
          <p className="muted" style={{ fontSize: 12.5 }}>
            operation_id: <code className="mono">{result.operation_id}</code>
            <br />
            amount: <strong className="money">{result.amount_zkz}</strong> ZKZ · status:{" "}
            {result.code_status} / {result.state}
          </p>
          {result.receiver_pubkey ? (
            <p className="muted" style={{ fontSize: 12.5 }}>
              receiver: <code className="mono">{result.receiver_pubkey}</code>
            </p>
          ) : null}
          <h2 style={{ fontSize: 14, margin: "12px 0 8px" }}>transfer_code</h2>
          <pre className="mono" style={{ fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {result.transfer_code}
          </pre>
          <div style={{ margin: "16px 0" }} data-testid="lab-transfer-qr">
            <TotpQrCode value={result.transfer_code} />
          </div>
          {result.expires_at ? (
            <p className="muted" style={{ fontSize: 12.5 }}>
              expires_at: {result.expires_at}
            </p>
          ) : null}
          <div className="form-actions">
            <button
              type="button"
              className="mini-btn"
              onClick={() => {
                setResult(null);
                setTotp("");
              }}
            >
              New lab receive
            </button>
            <Link to={`/operations/${result.operation_id}`} className="mini-btn primary">
              Open operation
            </Link>
            <Link to="/integration" className="mini-btn">
              Integration kit
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
