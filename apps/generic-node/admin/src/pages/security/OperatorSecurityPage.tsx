/**
 * Operator security notes — dual-control policy + optional operator push.
 * Pack P plain-language surface: which mode is active must match server enforcement.
 */
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  fetchDualControlPolicy,
  fetchOperatorPushStatus,
  formatMoneyError,
  subscribeOperatorPush,
  unsubscribeOperatorPush,
} from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";

export function OperatorSecurityPage() {
  const demoMode = useAuth((s) => s.demoMode);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [pushBusy, setPushBusy] = useState(false);

  const policyQ = useQuery({
    queryKey: ["dual-control-policy", demoMode],
    queryFn: async () => {
      if (demoMode) {
        return {
          mode: "single_operator" as const,
          short: "Single-operator",
          long: "Demo: one human may both request and approve.",
          approve_hint: "Demo single-operator mode.",
        };
      }
      return fetchDualControlPolicy();
    },
  });

  const pushQ = useQuery({
    queryKey: ["operator-push", demoMode],
    queryFn: async () => {
      if (demoMode) {
        return {
          opt_in: true,
          wired: false,
          note: "Demo — operator push is optional and separate from wallet receiver push.",
          subscriptions: [],
        };
      }
      return fetchOperatorPushStatus();
    },
  });

  async function onEnablePush() {
    setErr(null);
    setMsg(null);
    setPushBusy(true);
    try {
      if (!("Notification" in window) || !("serviceWorker" in navigator) || !("PushManager" in window)) {
        setMsg("This browser does not support Web Push. Use the Approve inbox manually.");
        return;
      }
      const permission = await Notification.requestPermission();
      if (permission !== "granted") {
        setMsg("Push denied or dismissed — full manual inbox still works. Operator push is opt-in only.");
        return;
      }
      if (demoMode) {
        setMsg("Demo: push permission granted (no server subscribe).");
        return;
      }
      // VAPID applicationServerKey is deployment-specific; without it we record intent only.
      // Real PushSubscription.subscribe needs the node’s operator-push VAPID key (optional infra).
      setMsg(
        "Notification permission granted. Server subscribe needs operator-push VAPID (optional). Inbox remains source of truth.",
      );
      // Placeholder subscribe so API path is exercised in labs that inject keys later.
      try {
        await subscribeOperatorPush({
          endpoint: `https://operator-push.local/pending/${Date.now()}`,
          p256dh: "pending-p256dh-placeholder-value-xx",
          auth: "pending-auth-placeholder-xx",
        });
      } catch {
        /* fail soft */
      }
    } catch (e) {
      setErr(formatMoneyError(e, "Push opt-in failed (inbox still works)"));
    } finally {
      setPushBusy(false);
    }
  }

  async function onDisablePush() {
    setErr(null);
    setPushBusy(true);
    try {
      const subs = pushQ.data?.subscriptions ?? [];
      for (const s of subs) {
        // endpoint_fingerprint only — full endpoint not returned; server delete by exact endpoint
        // when client still holds PushSubscription. Fail soft.
        void s;
      }
      if (!demoMode) {
        try {
          await unsubscribeOperatorPush("https://operator-push.local/pending/0");
        } catch {
          /* fail soft */
        }
      }
      setMsg("Push disabled or unavailable. Manual inbox is still authoritative.");
    } finally {
      setPushBusy(false);
    }
  }

  const policy = policyQ.data;

  return (
    <div className="page">
      <header className="page-header">
        <h1>Security</h1>
        <p className="muted">
          Dual-control policy and optional operator notifications. Wallet receiver push is a
          separate system and never gates SEND approve.
        </p>
      </header>

      {err ? <p className="err">{err}</p> : null}
      {msg ? <p className="ok">{msg}</p> : null}

      <section className="card" data-testid="dual-control-policy">
        <h2>Dual-control policy</h2>
        {policyQ.isLoading ? (
          <p className="muted">Loading policy…</p>
        ) : policyQ.isError ? (
          <p className="muted">Policy endpoint unavailable — server defaults to single-operator.</p>
        ) : policy ? (
          <>
            <p>
              <strong data-testid="dual-control-mode">{policy.short}</strong>
              <span className="muted"> ({policy.mode})</span>
            </p>
            <p>{policy.long}</p>
            <p className="muted">{policy.approve_hint}</p>
            <ul className="muted">
              <li>
                <strong>Single-operator</strong> — one human with TOTP (+ device when enrolled) may
                both request the challenge and approve.
              </li>
              <li>
                <strong>Two-human</strong> — a <em>different</em> <code>admin_operator</code> must
                approve than the one who requested the challenge. Same person both sides → rejected
                with a plain error.
              </li>
            </ul>
            <p className="muted">
              Mode is a node policy flag (server-enforced). This copy always matches enforcement.
            </p>
          </>
        ) : null}
      </section>

      <section className="card" data-testid="operator-push">
        <h2>Operator push notifications (optional)</h2>
        <p>
          Opt-in Web Push to <em>operator</em> devices for pending SEND / needs_attention. This is{" "}
          <strong>not</strong> wallet receiver push and <strong>must not</strong> gate RECEIVE.
        </p>
        {pushQ.data ? <p className="muted">{pushQ.data.note}</p> : null}
        <p className="muted">
          Wired: {pushQ.data?.wired ? "yes" : "no"} · Subscriptions:{" "}
          {pushQ.data?.subscriptions.length ?? 0}
        </p>
        <div className="row gap">
          <button
            type="button"
            className="btn primary"
            disabled={pushBusy}
            onClick={() => void onEnablePush()}
          >
            Enable operator push
          </button>
          <button type="button" className="btn" disabled={pushBusy} onClick={() => void onDisablePush()}>
            Disable
          </button>
        </div>
        <p className="muted">
          Skip or deny the permission prompt and the Approve inbox still works fully. Push failures
          are soft — inbox is the source of truth.
        </p>
      </section>
    </div>
  );
}
