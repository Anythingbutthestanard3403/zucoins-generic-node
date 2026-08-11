/**
 * Operator security notes — dual-control policy + optional operator push.
 * Pack P plain-language surface: which mode is active must match server enforcement.
 *
 * Operator push Enable requires a genuine browser PushManager.subscribe() with a real
 * VAPID applicationServerKey. No fabricated subscription is ever POSTed (ZTR-1168).
 */
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  fetchDualControlPolicy,
  fetchOperatorPushStatus,
  formatMoneyError,
  subscribeOperatorPush,
  unsubscribeOperatorPush,
} from "../../lib/money.js";

function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function bufferToBase64Url(buf: ArrayBuffer | null): string | null {
  if (!buf) return null;
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function OperatorSecurityPage() {
  const queryClient = useQueryClient();
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [pushBusy, setPushBusy] = useState(false);

  const policyQ = useQuery({
    queryKey: ["dual-control-policy"],
    queryFn: async () => {
      
      return fetchDualControlPolicy();
    },
  });

  const pushQ = useQuery({
    queryKey: ["operator-push"],
    queryFn: async () => {
      
      return fetchOperatorPushStatus();
    },
  });

  const browserPushOk =
    typeof window !== "undefined" &&
    "Notification" in window &&
    "serviceWorker" in navigator &&
    "PushManager" in window;

  const vapidKey = pushQ.data?.vapid_public_key ?? null;
  const pushWired = Boolean(pushQ.data?.wired);
  const enableUnavailableReason = !browserPushOk
    ? "This browser does not support Web Push. Use the Approve inbox manually."
    : !pushWired
        ? "Operator push is not wired on this node (optional). Inbox remains source of truth."
        : !vapidKey
          ? "No VAPID application-server key is configured on this node, so a real PushManager.subscribe() cannot run. Inbox remains source of truth."
          : null;

  async function onEnablePush() {
    setErr(null);
    setMsg(null);
    setPushBusy(true);
    try {
      if (!browserPushOk) {
        setMsg("This browser does not support Web Push. Use the Approve inbox manually.");
        return;
      }
      const permission = await Notification.requestPermission();
      if (permission !== "granted") {
        setMsg("Push denied or dismissed — full manual inbox still works. Operator push is opt-in only.");
        return;
      }
      
      if (enableUnavailableReason) {
        setMsg(enableUnavailableReason);
        return;
      }
      if (!vapidKey) {
        setMsg("VAPID key unavailable — no subscription request sent.");
        return;
      }

      const reg = await navigator.serviceWorker.ready;
      const sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(vapidKey) as BufferSource,
      });
      const json = sub.toJSON();
      const endpoint = json.endpoint ?? sub.endpoint;
      const p256dh = json.keys?.p256dh ?? bufferToBase64Url(sub.getKey("p256dh"));
      const auth = json.keys?.auth ?? bufferToBase64Url(sub.getKey("auth"));
      if (!endpoint || !p256dh || !auth) {
        setErr("Browser returned an incomplete PushSubscription — nothing was sent to the server.");
        return;
      }
      await subscribeOperatorPush({ endpoint, p256dh, auth });
      setMsg("Operator push enabled for this browser.");
      await queryClient.invalidateQueries({ queryKey: ["operator-push"] });
    } catch (e) {
      setErr(formatMoneyError(e, "Push opt-in failed (inbox still works)"));
    } finally {
      setPushBusy(false);
    }
  }

  async function onDisablePush() {
    setErr(null);
    setMsg(null);
    setPushBusy(true);
    try {
      
      const subs = pushQ.data?.subscriptions ?? [];
      if (subs.length === 0) {
        try {
          if (browserPushOk) {
            const reg = await navigator.serviceWorker.ready;
            const existing = await reg.pushManager.getSubscription();
            if (existing) await existing.unsubscribe();
          }
        } catch {
          /* browser unsubscribe is best-effort */
        }
        setMsg("No server subscriptions to remove. Manual inbox is still authoritative.");
        return;
      }

      let removed = 0;
      const failures: string[] = [];
      for (const s of subs) {
        try {
          const res = (await unsubscribeOperatorPush({
            endpoint_fingerprint: s.endpoint_fingerprint,
          })) as { removed?: boolean };
          if (res?.removed) removed += 1;
          else failures.push(s.endpoint_fingerprint);
        } catch (e) {
          failures.push(formatMoneyError(e, s.endpoint_fingerprint));
        }
      }

      try {
        if (browserPushOk) {
          const reg = await navigator.serviceWorker.ready;
          const existing = await reg.pushManager.getSubscription();
          if (existing) await existing.unsubscribe();
        }
      } catch {
        /* browser unsubscribe is best-effort */
      }

      await queryClient.invalidateQueries({ queryKey: ["operator-push"] });

      if (failures.length === 0 && removed > 0) {
        setMsg(`Removed ${removed} operator push subscription(s). Manual inbox is still authoritative.`);
      } else if (removed > 0) {
        setMsg(
          `Removed ${removed} subscription(s); ${failures.length} could not be removed. Manual inbox is still authoritative.`,
        );
        setErr(failures.join("; "));
      } else {
        setErr(
          failures.length > 0
            ? `Could not remove subscriptions: ${failures.join("; ")}`
            : "Server reported no subscriptions removed.",
        );
        setMsg(null);
      }
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
          {vapidKey ? " · VAPID: configured" : " · VAPID: not configured"}
        </p>
        {enableUnavailableReason  ? (
          <p className="muted" data-testid="operator-push-unavailable">
            Enable unavailable: {enableUnavailableReason}
          </p>
        ) : null}
        <div className="row gap">
          <button
            type="button"
            className="btn primary"
            disabled={pushBusy || Boolean(enableUnavailableReason )}
            title={enableUnavailableReason ?? undefined}
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
