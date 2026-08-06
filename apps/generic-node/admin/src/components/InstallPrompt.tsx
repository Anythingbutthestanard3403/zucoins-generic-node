import { useCallback, useEffect, useState } from "react";
import {
  clearInstallDismiss,
  dismissInstall,
  isStandaloneDisplay,
  wasInstallDismissed,
  type BeforeInstallPromptEvent,
} from "../lib/pwa.js";

export type InstallPromptProps = {
  /** When true, surface the post-TOTP install card (skippable). */
  open: boolean;
  onClose: () => void;
  /** Optional deferred event from beforeinstallprompt (Chromium). */
  deferredPrompt?: BeforeInstallPromptEvent | null;
  onPromptConsumed?: () => void;
};

/**
 * Skippable "Install Zu Node" affordance shown after TOTP enrol completes.
 * a11y: dialog role, labelled title, Install + Not now actions.
 * Does not force install — skip records dismiss so Home can re-offer later.
 */
export function InstallPrompt({
  open,
  onClose,
  deferredPrompt = null,
  onPromptConsumed,
}: InstallPromptProps) {
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) setBusy(false);
  }, [open]);

  const onSkip = useCallback(() => {
    dismissInstall();
    onClose();
  }, [onClose]);

  const onInstall = useCallback(async () => {
    if (deferredPrompt) {
      setBusy(true);
      try {
        await deferredPrompt.prompt();
        await deferredPrompt.userChoice;
      } catch {
        /* user dismissed native sheet */
      } finally {
        onPromptConsumed?.();
        setBusy(false);
        clearInstallDismiss();
        onClose();
      }
      return;
    }
    // Safari / no beforeinstallprompt: close and leave iOS Add-to-Home copy visible via toast path.
    clearInstallDismiss();
    onClose();
  }, [deferredPrompt, onClose, onPromptConsumed]);

  if (!open || isStandaloneDisplay()) return null;

  const hasNative = deferredPrompt != null;

  return (
    <div className="totp-overlay" role="presentation">
      <div
        className="totp-card install-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="install-pwa-title"
        aria-describedby="install-pwa-desc"
      >
        <h2 id="install-pwa-title">Install Zu Node</h2>
        <p id="install-pwa-desc" className="lead" style={{ marginTop: 8 }}>
          {hasNative
            ? "Add the operator console to your home screen for one-tap access on this device. Same origin as the node — no third-party host."
            : "Add this page to your Home Screen from the browser share menu for one-tap access. Same origin as the node — no third-party host."}
        </p>
        <div style={{ display: "flex", gap: 8, marginTop: 16, flexWrap: "wrap" }}>
          <button
            type="button"
            className="btn-block"
            style={{ flex: "1 1 140px" }}
            onClick={() => void onInstall()}
            disabled={busy}
            aria-label={hasNative ? "Install Zu Node on this device" : "Got it — use browser Add to Home Screen"}
          >
            {busy ? "Installing…" : hasNative ? "Install" : "Got it"}
          </button>
          <button
            type="button"
            className="btn-block"
            style={{ flex: "1 1 140px", background: "transparent", border: "1px solid var(--line)" }}
            onClick={onSkip}
            aria-label="Not now — skip installing Zu Node"
          >
            Not now
          </button>
        </div>
        <p className="muted" style={{ fontSize: 12.5, marginTop: 12 }}>
          You can install later from Overview. Skip is always available.
        </p>
      </div>
    </div>
  );
}

export type InstallHomeNudgeProps = {
  deferredPrompt?: BeforeInstallPromptEvent | null;
  onPromptConsumed?: () => void;
};

/**
 * Quiet Home/Overview re-offer after the operator skipped the post-TOTP prompt.
 * Hidden when already installed, never dismissed skip, or no install path.
 */
export function InstallHomeNudge({
  deferredPrompt = null,
  onPromptConsumed,
}: InstallHomeNudgeProps) {
  const [visible, setVisible] = useState(() => wasInstallDismissed() && !isStandaloneDisplay());
  const [busy, setBusy] = useState(false);

  if (!visible || isStandaloneDisplay()) return null;

  return (
    <div className="banner banner-install" role="region" aria-label="Install Zu Node">
      <span>
        Install Zu Node on this device for faster operator access. Optional — balances still
        require a live node connection.
      </span>
      <span style={{ display: "inline-flex", gap: 8, flexWrap: "wrap" }}>
        <button
          type="button"
          className="pill primary"
          aria-label="Install Zu Node on this device"
          disabled={busy}
          onClick={() => {
            if (!deferredPrompt) {
              clearInstallDismiss();
              setVisible(false);
              return;
            }
            setBusy(true);
            void deferredPrompt
              .prompt()
              .then(() => deferredPrompt.userChoice)
              .finally(() => {
                onPromptConsumed?.();
                clearInstallDismiss();
                setBusy(false);
                setVisible(false);
              });
          }}
        >
          {busy ? "Installing…" : deferredPrompt ? "Install" : "How to install"}
        </button>
        <button
          type="button"
          className="pill"
          aria-label="Dismiss install Zu Node reminder"
          onClick={() => {
            dismissInstall();
            setVisible(false);
          }}
        >
          Dismiss
        </button>
      </span>
    </div>
  );
}
