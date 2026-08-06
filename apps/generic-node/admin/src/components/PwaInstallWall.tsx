import { useCallback, useEffect, useRef, useState } from "react";
import { TotpQrCode } from "./TotpQrCode.js";
import {
  getDeferredInstallPrompt,
  isStandaloneDisplay,
  nodeOriginInstallUrl,
  observePwaInstallEvidence,
  reportPwaInstalled,
  subscribeDeferredInstallPrompt,
  type BeforeInstallPromptEvent,
  type PwaInstallEvidenceKind,
} from "../lib/pwa.js";

export type PwaInstallWallProps = {
  csrf: string;
  /** Lab ALLOW_BROWSER_TAB_SETUP — only then is Skip shown. */
  allowBrowserTabSetup: boolean;
  onInstalled: () => void;
  onLabSkip?: () => void;
};

/**
 * Full-screen mandatory Operator PWA install wall.
 * QR payload = node HTTPS origin only. Durable flag only after real evidence.
 */
export function PwaInstallWall({
  csrf,
  allowBrowserTabSetup,
  onInstalled,
  onLabSkip,
}: PwaInstallWallProps) {
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [deferred, setDeferred] = useState<BeforeInstallPromptEvent | null>(() =>
    getDeferredInstallPrompt(),
  );
  const [installUrl] = useState(() => nodeOriginInstallUrl());
  const postedRef = useRef(false);
  const appInstalledSeen = useRef(false);

  const postEvidence = useCallback(
    async (evidence: PwaInstallEvidenceKind) => {
      if (postedRef.current) return;
      postedRef.current = true;
      setBusy(true);
      setErr(null);
      try {
        await reportPwaInstalled(evidence, csrf);
        onInstalled();
      } catch (ex) {
        postedRef.current = false;
        setErr(ex instanceof Error ? ex.message : "Failed to record install");
      } finally {
        setBusy(false);
      }
    },
    [csrf, onInstalled],
  );

  // If already running as installed PWA, record and continue.
  useEffect(() => {
    const ev = observePwaInstallEvidence();
    if (ev) void postEvidence(ev);
  }, [postEvidence]);

  useEffect(() => subscribeDeferredInstallPrompt(setDeferred), []);

  // appinstalled → wait for standalone confirmation on later observation, or post after event + recheck.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const onAppInstalled = () => {
      appInstalledSeen.current = true;
      const now = observePwaInstallEvidence();
      if (now) {
        void postEvidence(now);
        return;
      }
      // Chromium may fire appinstalled before display-mode flips; accept enum after event
      // once we re-check standalone, else post appinstalled when still not in tab-only mode
      // after a short settle (appinstalled is an accepted evidence kind).
      window.setTimeout(() => {
        const again = observePwaInstallEvidence();
        if (again) void postEvidence(again);
        else if (appInstalledSeen.current) void postEvidence("appinstalled");
      }, 400);
    };
    window.addEventListener("appinstalled", onAppInstalled);
    return () => window.removeEventListener("appinstalled", onAppInstalled);
  }, [postEvidence]);

  // Poll display-mode while wall is open (operator returns from home-screen launch).
  useEffect(() => {
    if (isStandaloneDisplay()) return;
    const id = window.setInterval(() => {
      const ev = observePwaInstallEvidence();
      if (ev) void postEvidence(ev);
    }, 1500);
    return () => window.clearInterval(id);
  }, [postEvidence]);

  const onNativeInstall = useCallback(async () => {
    if (!deferred) return;
    setBusy(true);
    setErr(null);
    try {
      await deferred.prompt();
      await deferred.userChoice;
    } catch {
      /* user dismissed */
    } finally {
      setBusy(false);
    }
  }, [deferred]);

  const onIAlreadyInstalled = useCallback(() => {
    const ev = observePwaInstallEvidence();
    if (!ev) {
      setErr(
        "This browser tab is not running as an installed app yet. Open the home-screen icon, or use Install below.",
      );
      return;
    }
    void postEvidence(ev);
  }, [postEvidence]);

  return (
    <div className="auth-wrap" data-testid="pwa-install-wall">
      <div className="auth-card" style={{ maxWidth: 420 }}>
        <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
          Required · Operator PWA
        </p>
        <h1>Install Zu Node</h1>
        <p className="lead">
          You must install the Operator app on this device before continuing. Scan the QR with
          your phone or use Install below. The code is this node&apos;s address only — no secrets.
        </p>

        <div
          style={{ display: "flex", justifyContent: "center", margin: "16px 0" }}
          data-testid="pwa-install-qr"
          data-install-url={installUrl}
        >
          <TotpQrCode value={installUrl} />
        </div>
        <p
          className="muted"
          style={{ fontSize: 12.5, wordBreak: "break-all", textAlign: "center" }}
          data-testid="pwa-install-url"
        >
          {installUrl}
        </p>

        <ul className="muted" style={{ fontSize: 13, marginTop: 12, paddingLeft: 18 }}>
          <li>
            <strong>iPhone / iPad:</strong> Share → Add to Home Screen, then open the icon.
          </li>
          <li>
            <strong>Android:</strong> browser menu → Install app / Add to Home screen, then open it.
          </li>
        </ul>

        {err ? <p className="err">{err}</p> : null}

        <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 16 }}>
          {deferred ? (
            <button
              type="button"
              className="btn-block"
              disabled={busy}
              onClick={() => void onNativeInstall()}
              aria-label="Install Zu Node on this device"
            >
              {busy ? "Installing…" : "Install app"}
            </button>
          ) : null}
          <button
            type="button"
            className="btn-block"
            disabled={busy}
            onClick={onIAlreadyInstalled}
            aria-label="Continue after opening installed app"
            style={
              deferred
                ? { background: "transparent", border: "1px solid var(--line)" }
                : undefined
            }
          >
            {busy ? "Checking…" : "I opened the installed app — continue"}
          </button>
          {allowBrowserTabSetup ? (
            <button
              type="button"
              className="btn-block"
              data-testid="pwa-lab-skip"
              disabled={busy}
              style={{ background: "transparent", border: "1px solid var(--line)" }}
              onClick={() => onLabSkip?.()}
              aria-label="Lab skip — browser tab setup allowed"
            >
              Skip (lab ALLOW_BROWSER_TAB_SETUP)
            </button>
          ) : null}
        </div>
        <p className="muted" style={{ fontSize: 12, marginTop: 12 }}>
          Setup continues only after this session reports real install evidence
          (standalone / fullscreen / appinstalled).
        </p>
      </div>
    </div>
  );
}
