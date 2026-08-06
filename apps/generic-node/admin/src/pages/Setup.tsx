import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useAuth } from "../store/auth.js";
import { TotpQrCode } from "../components/TotpQrCode.js";
import { PwaInstallWall } from "../components/PwaInstallWall.js";
import { runGenesisDeviceEnrol } from "../lib/genesis-device-enrol.js";
import { formatMoneyError, isCancelled } from "../lib/money.js";
import { TotpPromptProvider } from "../totp/TotpPromptProvider.js";
import { useTotpGatedMutation } from "../totp/useTotpGatedMutation.js";
import {
  hasPackCreateMarker,
  isDay0Step,
  pathForNextStep,
  refineNextStep,
  type Day0Step,
} from "../funnel/day0.js";

/**
 * Setup wizard W0–W12 + vault master show-once at W5.
 * W3 PWA wall. W4 Device #1 genesis enrol + typed BREAK GLASS.
 * Day-0 funnel routes `/start/*` reuse this page for install/device/vault.
 * Extends password+TOTP (W1/W2). Secret-free server flags; master key only in
 * component state until offline ack — never localStorage/console.
 */

/** Exact phrase — must match server DEVICE_BREAK_GLASS_PHRASE. */
const BREAK_GLASS_PHRASE = "BREAK GLASS";

const setupQueryClient = new QueryClient({
  defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
});

type TotpPhase = "idle" | "pending";

type SetupStepId =
  | "W0"
  | "W1"
  | "W2"
  | "W3"
  | "W4"
  | "W5"
  | "W6"
  | "W7"
  | "W8"
  | "W9"
  | "W10"
  | "W11"
  | "W12";

interface SetupStateView {
  object: "setup_state";
  current_step: SetupStepId;
  complete: boolean;
  ceremony_master_key_blocked: boolean;
  pwa_installed?: boolean;
  allow_browser_tab_setup?: boolean;
  device_break_glass_active?: boolean;
  password_ok?: boolean;
  totp_ok?: boolean;
  device_enrolled?: boolean;
  recovery_proven?: boolean;
  vault_ready?: boolean;
  next_step?: Day0Step | string;
  flags: Record<string, boolean | string | null>;
  steps: readonly {
    id: SetupStepId;
    required: boolean;
    status: string;
    title: string;
    detail: string;
  }[];
}

interface VaultMasterStatus {
  phase: string;
  can_generate: boolean;
  plaintext_pending_ack: boolean;
  offline_backup_acked: boolean;
}

function isSecureContextClient(): boolean {
  if (typeof window === "undefined") return false;
  if (window.isSecureContext) return true;
  const h = window.location.hostname;
  return h === "localhost" || h === "127.0.0.1" || h === "[::1]";
}

async function apiJson<T>(
  path: string,
  init: RequestInit & { csrf?: string } = {},
): Promise<T> {
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string> | undefined),
  };
  if (init.csrf) headers["X-CSRF-Token"] = init.csrf;
  if (init.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(path, { ...init, credentials: "include", headers });
  if (!res.ok) {
    let msg = `${res.status}`;
    try {
      const b = (await res.json()) as { error?: { message?: string } };
      msg = b.error?.message ?? msg;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  return (await res.json()) as T;
}

export function SetupPage() {
  return (
    <QueryClientProvider client={setupQueryClient}>
      <TotpPromptProvider>
        <SetupPageInner />
      </TotpPromptProvider>
    </QueryClientProvider>
  );
}

function SetupPageInner() {

  const user = useAuth((s) => s.user);
  const changePassword = useAuth((s) => s.changePassword);
  const enrolTotp = useAuth((s) => s.enrolTotp);
  const confirmTotp = useAuth((s) => s.confirmTotp);
  const demoMode = useAuth((s) => s.demoMode);
  const nav = useNavigate();
  const location = useLocation();

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [enrolPassword, setEnrolPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const [otpauthUrl, setOtpauthUrl] = useState<string | null>(null);
  const [totpPhase, setTotpPhase] = useState<TotpPhase>("idle");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [setup, setSetup] = useState<SetupStateView | null>(null);
  const [vaultStatus, setVaultStatus] = useState<VaultMasterStatus | null>(null);
  /** Ephemeral — component state only until ack. */
  const [shownMasterKey, setShownMasterKey] = useState<string | null>(null);
  const [offlineAckChecked, setOfflineAckChecked] = useState(false);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [deviceLabel, setDeviceLabel] = useState("Operator phone");
  const [breakGlassPhrase, setBreakGlassPhrase] = useState("");
  const [showBreakGlass, setShowBreakGlass] = useState(false);

  const csrf = user?.csrfToken ?? "";

  /** After auth, bounce /setup → /start/* for the server next_step. */
  const maybeRedirectFunnel = useCallback(
    (view: SetupStateView) => {
      if (view.complete === true || view.next_step === "home") {
        nav("/", { replace: true });
        return;
      }
      // Older mocks / nodes without next_step: stay on Setup (current_step UI).
      if (!isDay0Step(view.next_step)) return;
      const refined = refineNextStep(view.next_step, {
        packCreatedLocally: hasPackCreateMarker(),
      });
      // Password/TOTP stay on /setup.
      if (refined === "password" || refined === "totp") return;
      const target = pathForNextStep(refined);
      // Pack create/prove have dedicated pages — leave Setup.
      if (refined === "backup" || refined === "prove") {
        if (location.pathname !== target) nav(target, { replace: true });
        return;
      }
      // install/device/vault: Setup content is reused under /start/*; leave bare /setup.
      if (location.pathname === "/setup" && target !== "/setup") {
        nav(target, { replace: true });
      }
    },
    [nav, location.pathname],
  );

  const refreshSetup = useCallback(async () => {
    if (demoMode) {
      // Demo: synthesize complete-after-auth posture.
      setSetup({
        object: "setup_state",
        current_step: "W12",
        complete: true,
        ceremony_master_key_blocked: true,
        next_step: "home",
        password_ok: true,
        totp_ok: true,
        pwa_installed: true,
        device_enrolled: true,
        vault_ready: true,
        recovery_proven: true,
        flags: {},
        steps: [],
      });
      return;
    }
    const view = await apiJson<SetupStateView>("/admin/v1/setup-state");
    setSetup(view);
    maybeRedirectFunnel(view);
  }, [demoMode, maybeRedirectFunnel]);

  const refreshVault = useCallback(async () => {
    if (demoMode) return;
    const st = await apiJson<VaultMasterStatus>("/admin/v1/vault-master");
    setVaultStatus(st);
  }, [demoMode]);

  const deviceEnrol = useTotpGatedMutation(
    async (_: void, totp: string) => runGenesisDeviceEnrol({ label: deviceLabel, totp }),
    {
      title: "Register this phone",
      detail: "Fresh TOTP required. Private key stays in this browser (IndexedDB).",
      onSuccess: () => {
        setErr(null);
        void refreshSetup();
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setErr(formatMoneyError(e, "Device enrol failed"));
      },
    },
  );

  async function onTypedBreakGlass() {
    if (breakGlassPhrase !== BREAK_GLASS_PHRASE) {
      setErr(`Type exactly ${BREAK_GLASS_PHRASE} (case-sensitive) to continue without a device.`);
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      if (demoMode) {
        setBusy(false);
        return;
      }
      const view = await apiJson<SetupStateView>("/admin/v1/setup-state/device-break-glass", {
        method: "POST",
        csrf,
        body: JSON.stringify({ phrase: breakGlassPhrase }),
      });
      setSetup(view);
      maybeRedirectFunnel(view);
      setBusy(false);
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Break-glass failed");
      setBusy(false);
    }
  }

  // Boot: secure-context ack + load durable state.
  useEffect(() => {
    if (!user) return;
    let cancelled = false;
    (async () => {
      try {
        if (!demoMode && isSecureContextClient()) {
          await apiJson("/admin/v1/setup-state", {
            method: "PATCH",
            csrf,
            body: JSON.stringify({ w0_secure_context_ok: true }),
          });
        }
        if (!cancelled) {
          await refreshSetup();
          await refreshVault();
        }
      } catch (ex) {
        if (!cancelled) {
          setLoadErr(ex instanceof Error ? ex.message : "Failed to load setup state");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [user, demoMode, csrf, refreshSetup, refreshVault]);

  // Re-probe vault status whenever the wizard lands on W5.
  useEffect(() => {
    if (setup?.current_step === "W5" && !demoMode) {
      void refreshVault();
    }
  }, [setup?.current_step, demoMode, refreshVault]);

  if (!user) return <Navigate to="/login" replace />;

  // Auth posture still drives W1/W2 UI even before setup-state loads.
  const mustPw = user.mustChangePassword;
  const mustTotp = user.mustEnrolTotp;

  async function onPasswordSubmit(e: FormEvent) {
    e.preventDefault();
    if (next !== confirm) {
      setErr("New passwords do not match");
      return;
    }
    if (demoMode) {
      useAuth.setState({
        user: user
          ? { ...user, mustChangePassword: false, mustEnrolTotp: false }
          : null,
      });
      nav("/");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await changePassword(current, next);
      setEnrolPassword(next);
      setCurrent("");
      setNext("");
      setConfirm("");
      await refreshSetup();
      if (!useAuth.getState().user?.mustEnrolTotp) {
        setBusy(false);
        return;
      }
      setBusy(false);
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Password change failed");
      setBusy(false);
    }
  }

  async function onEnrolSubmit(e: FormEvent) {
    e.preventDefault();
    if (demoMode) {
      useAuth.setState({
        user: user ? { ...user, mustEnrolTotp: false } : null,
      });
      nav("/");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const r = await enrolTotp(enrolPassword);
      setSecret(r.secret);
      setOtpauthUrl(r.otpauthUrl);
      setTotpPhase("pending");
      setEnrolPassword("");
      setBusy(false);
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "TOTP enrol failed");
      setBusy(false);
    }
  }

  async function onConfirmSubmit(e: FormEvent) {
    e.preventDefault();
    if (demoMode) {
      useAuth.setState({
        user: user ? { ...user, mustEnrolTotp: false } : null,
      });
      nav("/");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await confirmTotp(totpCode);
      setSecret(null);
      setOtpauthUrl(null);
      setTotpCode("");
      await refreshSetup();
      setBusy(false);
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "TOTP confirm failed");
      setBusy(false);
    }
  }

  async function patchFlags(body: Record<string, boolean>) {
    setBusy(true);
    setErr(null);
    try {
      if (demoMode) {
        setBusy(false);
        return;
      }
      const view = await apiJson<SetupStateView>("/admin/v1/setup-state", {
        method: "PATCH",
        csrf,
        body: JSON.stringify(body),
      });
      setSetup(view);
      maybeRedirectFunnel(view);
      setBusy(false);
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Update failed");
      setBusy(false);
    }
  }

  async function onGenerateMaster() {
    setBusy(true);
    setErr(null);
    try {
      const r = await apiJson<{ master_key: string }>("/admin/v1/vault-master/generate", {
        method: "POST",
        csrf,
        body: "{}",
      });
      // Memory only — never localStorage.
      setShownMasterKey(r.master_key);
      await refreshVault();
      setBusy(false);
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Generate failed");
      setBusy(false);
    }
  }

  async function onAckOffline() {
    if (!offlineAckChecked) {
      setErr("Confirm you stored the key offline before continuing");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await apiJson("/admin/v1/vault-master/ack-offline", {
        method: "POST",
        csrf,
        body: JSON.stringify({ offline_backup_ack: true }),
      });
      setShownMasterKey(null);
      setOfflineAckChecked(false);
      await refreshVault();
      await refreshSetup();
      setBusy(false);
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Ack failed");
      setBusy(false);
    }
  }

  const showPassword = mustPw;
  const showEnrol = !mustPw && mustTotp && totpPhase === "idle";
  const showConfirm = !mustPw && mustTotp && totpPhase === "pending";
  const authDone = !mustPw && !mustTotp;

  const step = setup?.current_step;
  const showWizard = authDone && setup !== null && !setup.complete;

  return (
    <div className="auth-shell">
      {loadErr ? (
        <div className="auth-card">
          <h1>Setup</h1>
          <p className="err">{loadErr}</p>
        </div>
      ) : null}

      {showPassword ? (
        <form className="auth-card" onSubmit={(e) => void onPasswordSubmit(e)}>
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
            Step W1 · Change bootstrap password
          </p>
          <h1>Finish setup</h1>
          <p className="lead">
            Change the bootstrap password before operating the node.
            {user.mustEnrolTotp
              ? " Authenticator enrolment follows password change."
              : ""}
          </p>
          <div className="field">
            <label htmlFor="cur">Current password</label>
            <input
              id="cur"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              required={!demoMode}
            />
          </div>
          <div className="field">
            <label htmlFor="np">New password</label>
            <input
              id="np"
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              required
              minLength={12}
            />
          </div>
          <div className="field">
            <label htmlFor="np2">Confirm new password</label>
            <input
              id="np2"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
              minLength={12}
            />
          </div>
          {err ? <p className="err">{err}</p> : null}
          <button className="btn-block" type="submit" disabled={busy}>
            {busy ? "Saving…" : "Update password"}
          </button>
          <p className="muted" style={{ fontSize: 12.5, marginTop: 10 }}>
            Live path: <code className="mono">POST /admin/v1/password</code> with{" "}
            <code className="mono">X-CSRF-Token</code>.
          </p>
        </form>
      ) : null}

      {showEnrol ? (
        <form className="auth-card" onSubmit={(e) => void onEnrolSubmit(e)}>
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
            Step W2 · Enrol authenticator
          </p>
          <h1>Enrol authenticator</h1>
          <p className="lead">
            Re-enter your password to mint a one-time authenticator secret. The secret
            is shown once and never logged.
          </p>
          <div className="field">
            <label htmlFor="enrol-pw">Password</label>
            <input
              id="enrol-pw"
              type="password"
              autoComplete="current-password"
              value={enrolPassword}
              onChange={(e) => setEnrolPassword(e.target.value)}
              required={!demoMode}
            />
          </div>
          {err ? <p className="err">{err}</p> : null}
          <button className="btn-block" type="submit" disabled={busy}>
            {busy ? "Minting…" : "Generate authenticator secret"}
          </button>
          <p className="muted" style={{ fontSize: 12.5, marginTop: 10 }}>
            Live path: <code className="mono">POST /admin/v1/enrol-totp</code>.
          </p>
        </form>
      ) : null}

      {showConfirm ? (
        <form className="auth-card" onSubmit={(e) => void onConfirmSubmit(e)}>
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
            Step W2 · Confirm authenticator
          </p>
          <h1>Confirm authenticator</h1>
          <p className="lead">
            Scan this QR code with your authenticator app, then enter the current
            6-digit code. Confirm burns this step so the same code cannot approve money.
          </p>
          {otpauthUrl ? (
            <div className="field" style={{ display: "flex", justifyContent: "center" }}>
              <TotpQrCode value={otpauthUrl} />
            </div>
          ) : null}
          {secret ? (
            <div className="field">
              <label htmlFor="totp-secret">Can&rsquo;t scan? Enter this secret manually (shown once)</label>
              <input
                id="totp-secret"
                className="mono"
                readOnly
                value={secret}
                onFocus={(e) => e.currentTarget.select()}
              />
            </div>
          ) : null}
          {otpauthUrl ? (
            <div className="field">
              <label htmlFor="totp-otpauth">otpauth URL</label>
              <textarea
                id="totp-otpauth"
                className="mono"
                readOnly
                rows={3}
                value={otpauthUrl}
                style={{ width: "100%", resize: "vertical", fontSize: 12 }}
                onFocus={(e) => e.currentTarget.select()}
              />
            </div>
          ) : null}
          <div className="field">
            <label htmlFor="totp-code">6-digit code</label>
            <input
              id="totp-code"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="\d{6}"
              maxLength={6}
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              required
            />
          </div>
          {err ? <p className="err">{err}</p> : null}
          <button className="btn-block" type="submit" disabled={busy || totpCode.length !== 6}>
            {busy ? "Confirming…" : "Confirm and continue"}
          </button>
          <p className="muted" style={{ fontSize: 12.5, marginTop: 10 }}>
            Live path: <code className="mono">POST /admin/v1/confirm-totp</code>. Clears{" "}
            <code className="mono">mustEnrolTotp</code>.
          </p>
        </form>
      ) : null}

      {showWizard && step === "W0" ? (
        <div className="auth-card" data-testid="setup-step-w0">
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Step W0</p>
          <h1>Secure context required</h1>
          <p className="lead">
            Open the Operator UI over HTTPS or loopback (localhost). This page did not
            detect a secure context.
          </p>
          {err ? <p className="err">{err}</p> : null}
          <button
            className="btn-block"
            type="button"
            disabled={busy}
            onClick={() => void patchFlags({ w0_secure_context_ok: isSecureContextClient() })}
          >
            Re-check secure context
          </button>
        </div>
      ) : null}

      {showWizard && step === "W3" ? (
        <div data-testid="setup-step-w3">
          <PwaInstallWall
            csrf={csrf}
            allowBrowserTabSetup={setup?.allow_browser_tab_setup === true}
            onInstalled={() => {
              void refreshSetup();
            }}
            onLabSkip={() => {
              // Lab only: wall skip control is gated server-side via allow_browser_tab_setup.
              // Local flag still does not invent durable evidence; refresh may advance if env on.
              void refreshSetup();
            }}
          />
        </div>
      ) : null}

      {showWizard && step === "W4" ? (
        <div className="auth-card" data-testid="setup-step-w4">
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Step W4 · Device #1</p>
          <h1>Register this phone as your approval device</h1>
          <p className="lead">
            This PWA session enrols a WebCrypto approval key before Home. Fresh TOTP is
            required. The private key stays non-extractable in this browser — never sent to
            the platform. Destinations are day-2 and not part of enrol. Quiet break-glass
            checkboxes do not count.
          </p>
          <div className="field">
            <label htmlFor="setup-device-label">Device label</label>
            <input
              id="setup-device-label"
              value={deviceLabel}
              onChange={(e) => setDeviceLabel(e.target.value)}
              maxLength={80}
              required
              data-testid="setup-device-label"
            />
          </div>
          {err ? <p className="err">{err}</p> : null}
          <button
            className="btn-block"
            type="button"
            disabled={busy || deviceEnrol.isPending || deviceLabel.trim().length === 0}
            data-testid="setup-device-enrol"
            onClick={() => {
              setErr(null);
              deviceEnrol.mutate();
            }}
          >
            {deviceEnrol.isPending ? "Enrolling…" : "Generate key & enrol with TOTP"}
          </button>
          <button
            className="btn-block"
            type="button"
            disabled={busy}
            style={{ marginTop: 8 }}
            data-testid="setup-device-refresh"
            onClick={() => void refreshSetup()}
          >
            Refresh status
          </button>
          <p className="muted" style={{ fontSize: 12.5, marginTop: 16 }}>
            Cannot enrol this phone? Break-glass is audited and leaves device signatures
            unavailable on Home — not a quiet skip.
          </p>
          {!showBreakGlass ? (
            <button
              className="btn-block"
              type="button"
              disabled={busy}
              style={{ marginTop: 8 }}
              data-testid="setup-break-glass-reveal"
              onClick={() => setShowBreakGlass(true)}
            >
              Show break-glass path
            </button>
          ) : (
            <div style={{ marginTop: 12 }} data-testid="setup-break-glass-panel">
              <div className="field">
                <label htmlFor="setup-break-glass-phrase">
                  Type exactly <code className="mono">{BREAK_GLASS_PHRASE}</code>
                </label>
                <input
                  id="setup-break-glass-phrase"
                  value={breakGlassPhrase}
                  onChange={(e) => setBreakGlassPhrase(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                  data-testid="setup-break-glass-phrase"
                />
              </div>
              <button
                className="btn-block"
                type="button"
                disabled={busy || breakGlassPhrase !== BREAK_GLASS_PHRASE}
                data-testid="setup-break-glass-submit"
                onClick={() => void onTypedBreakGlass()}
              >
                {busy ? "Recording…" : "Continue without device (audited)"}
              </button>
            </div>
          )}
        </div>
      ) : null}

      {showWizard && step === "W5" ? (
        <div className="auth-card" data-testid="setup-step-w5">
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Step W5 · Vault master</p>
          <h1>Vault ready</h1>
          <p className="lead">
            First-boot: generate a vault master key with CSPRNG entropy, store it{" "}
            <strong>offline</strong> (paper / offline password manager), then continue.
            The key is shown <strong>once</strong> and is never emailed or re-fetched.
            It is <strong>not</strong> the backup KEK (<code className="mono">BACKUP_MASTER_KEY</code>).
          </p>
          {vaultStatus?.phase === "configured" ? (
            <p className="muted" style={{ fontSize: 13 }}>
              Vault already configured from the environment. Confirm you hold the offline
              copy of the master key.
            </p>
          ) : null}
          {!shownMasterKey && vaultStatus?.can_generate ? (
            <button
              className="btn-block"
              type="button"
              disabled={busy}
              onClick={() => void onGenerateMaster()}
            >
              {busy ? "Generating…" : "Generate vault master key"}
            </button>
          ) : null}
          {shownMasterKey ? (
            <div className="field" style={{ marginTop: 12 }}>
              <label htmlFor="vault-master-once">Vault master key (shown once)</label>
              <textarea
                id="vault-master-once"
                className="mono"
                readOnly
                rows={3}
                value={shownMasterKey}
                data-testid="vault-master-once"
                style={{ width: "100%", resize: "vertical", fontSize: 12 }}
                onFocus={(e) => e.currentTarget.select()}
              />
              <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
                Store offline now. Closing this step clears it from the browser.
              </p>
            </div>
          ) : null}
          {(shownMasterKey ||
            vaultStatus?.plaintext_pending_ack ||
            vaultStatus?.phase === "configured") &&
          !vaultStatus?.offline_backup_acked ? (
            <div className="field" style={{ marginTop: 12 }}>
              <label style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                <input
                  type="checkbox"
                  checked={offlineAckChecked}
                  onChange={(e) => setOfflineAckChecked(e.target.checked)}
                  data-testid="vault-offline-ack"
                />
                <span>I stored this vault master key offline (not in browser storage or email).</span>
              </label>
              <button
                className="btn-block"
                type="button"
                style={{ marginTop: 12 }}
                disabled={busy || !offlineAckChecked}
                onClick={() => void onAckOffline()}
              >
                {busy ? "Saving…" : "Continue"}
              </button>
            </div>
          ) : null}
          {err ? <p className="err">{err}</p> : null}
        </div>
      ) : null}

      {showWizard && step === "W6" ? (
        <div className="auth-card" data-testid="setup-step-w6">
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Step W6 · Recovery pack</p>
          <h1>Recovery pack create + prove</h1>
          <p className="lead">
            Day-0 happy path is encrypted recovery-pack download + prove.
            Only a real <code className="mono">recovery_verified_at</code> stamp completes
            setup — no checkbox. Mode A / CLI remain break-glass under Recovery ceremony.
          </p>
          {err ? <p className="err">{err}</p> : null}
          <button
            className="btn-block"
            type="button"
            data-testid="setup-go-backup"
            onClick={() => nav("/start/backup", { replace: true })}
          >
            Create recovery pack
          </button>
          <button
            className="btn-block"
            type="button"
            style={{ marginTop: 8 }}
            data-testid="setup-go-prove"
            onClick={() => nav("/start/prove", { replace: true })}
          >
            Prove recovery pack
          </button>
          <button
            className="btn-block"
            type="button"
            style={{ marginTop: 8 }}
            disabled={busy}
            onClick={() => void refreshSetup()}
          >
            Refresh status
          </button>
        </div>
      ) : null}

      {showWizard && step === "W7" ? (
        <div className="auth-card" data-testid="setup-step-w7">
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Step W7</p>
          <h1>Recovery-verified wallet</h1>
          <p className="lead">
            Need ≥1 <code className="mono">node_generated</code> wallet with{" "}
            <code className="mono">recovery_verified_at</code>. Complete pack prove or
            break-glass ceremony, then refresh. Client acks cannot stamp verification.
          </p>
          {err ? <p className="err">{err}</p> : null}
          <button
            className="btn-block"
            type="button"
            disabled={busy}
            onClick={() => void refreshSetup()}
          >
            Refresh status
          </button>
        </div>
      ) : null}

      {showWizard && step === "W8" ? (
        <div className="auth-card" data-testid="setup-step-w8">
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Step W8 · Optional</p>
          <h1>Implementer key</h1>
          <p className="lead">
            Optional: capture the implementer API key when issued (shown once on issue).
            Skip if you will issue later from API keys.
          </p>
          {err ? <p className="err">{err}</p> : null}
          <button
            className="btn-block"
            type="button"
            disabled={busy}
            onClick={() => void patchFlags({ w8_implementer_key_ack: true })}
          >
            I captured the implementer key
          </button>
          <button
            className="btn-block"
            type="button"
            style={{ marginTop: 8 }}
            disabled={busy}
            onClick={() => void patchFlags({ w8_implementer_skipped: true })}
          >
            Skip for now
          </button>
        </div>
      ) : null}

      {showWizard && step === "W9" ? (
        <div className="auth-card" data-testid="setup-step-w9">
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Step W9</p>
          <h1>Reporting key</h1>
          <p className="lead">
            Required for the RECEIVE pack (ARM). Issue a reporting key from Reporting keys,
            then continue.
          </p>
          {err ? <p className="err">{err}</p> : null}
          <button
            className="btn-block"
            type="button"
            disabled={busy}
            onClick={() => void patchFlags({ w9_reporting_key_ok: true })}
          >
            Reporting key is active
          </button>
        </div>
      ) : null}

      {showWizard && step === "W10" ? (
        <div className="auth-card" data-testid="setup-step-w10">
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Step W10 · Optional</p>
          <h1>Packs</h1>
          <p className="lead">Optional pack selection. Skip to finish setup.</p>
          {err ? <p className="err">{err}</p> : null}
          <button
            className="btn-block"
            type="button"
            disabled={busy}
            onClick={() => void patchFlags({ w10_packs_ack: true })}
          >
            Packs configured
          </button>
          <button
            className="btn-block"
            type="button"
            style={{ marginTop: 8 }}
            disabled={busy}
            onClick={() => void patchFlags({ w10_packs_skipped: true })}
          >
            Skip for now
          </button>
        </div>
      ) : null}

      {showWizard && step === "W11" ? (
        <div className="auth-card" data-testid="setup-step-w11">
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Step W11 · Optional</p>
          <h1>Mini-steps</h1>
          <p className="lead">Optional remaining integration mini-steps.</p>
          {err ? <p className="err">{err}</p> : null}
          <button
            className="btn-block"
            type="button"
            disabled={busy}
            onClick={() => void patchFlags({ w11_mini_steps_ack: true })}
          >
            Done with mini-steps
          </button>
          <button
            className="btn-block"
            type="button"
            style={{ marginTop: 8 }}
            disabled={busy}
            onClick={() => void patchFlags({ w11_mini_steps_skipped: true })}
          >
            Skip for now
          </button>
        </div>
      ) : null}

      {showWizard && step === "W12" ? (
        <div className="auth-card" data-testid="setup-step-w12">
          <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Step W12</p>
          <h1>Setup complete</h1>
          <p className="lead">
            Continue to Home — Node readiness stays collapsed when clear and only expands if
            something blocks money ops again.
          </p>
          <button className="btn-block" type="button" onClick={() => nav("/", { replace: true })}>
            Go to Home
          </button>
        </div>
      ) : null}

      {authDone && setup === null && !loadErr ? (
        <div className="auth-card">
          <p className="muted">Loading setup…</p>
        </div>
      ) : null}
    </div>
  );
}
