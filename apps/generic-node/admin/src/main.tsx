import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, StrictMode, Suspense, useEffect, useState, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router";
import { App } from "./App.js";
import { ErrorBoundary } from "./components/ErrorBoundary.js";
import { LoginPage } from "./pages/Login.js";
import { useAuth } from "./store/auth.js";
import { TotpPromptProvider } from "./totp/TotpPromptProvider.js";
import {
  bindBeforeInstallPromptListener,
  registerShellServiceWorker,
} from "./lib/pwa.js";
import {
  hasPackCreateMarker,
  isDay0Step,
  isMoneyOrAppPath,
  pathForNextStep,
  redirectForFunnelPath,
  refineNextStep,
  type Day0Step,
  type SetupStateDay0,
} from "./funnel/day0.js";
import { decideSetupStateHttp } from "./funnel/setup-state-gate.js";
import { bindSessionQueryClient } from "./lib/session-reset.js";
import "./styles.css";

// Capture Chromium install prompt early (must preventDefault before first paint settles).
bindBeforeInstallPromptListener();
// Shell-only SW — never caches admin/API JSON as money truth.
void registerShellServiceWorker();

const SetupPage = lazy(() => import("./pages/Setup.js").then((m) => ({ default: m.SetupPage })));
const StartSetupStepPage = lazy(() =>
  import("./pages/start/StartFunnelPages.js").then((m) => ({ default: m.StartSetupStepPage })),
);
const StartBackupPage = lazy(() =>
  import("./pages/start/StartFunnelPages.js").then((m) => ({ default: m.StartBackupPage })),
);
const StartProvePage = lazy(() =>
  import("./pages/start/StartFunnelPages.js").then((m) => ({ default: m.StartProvePage })),
);
const OverviewPage = lazy(() => import("./pages/overview/OverviewPage.js").then((m) => ({ default: m.OverviewPage })));
const ApproveInboxPage = lazy(() =>
  import("./pages/approve/ApproveInboxPage.js").then((m) => ({ default: m.ApproveInboxPage })),
);
const OperationsPage = lazy(() => import("./pages/operations/OperationsPage.js").then((m) => ({ default: m.OperationsPage })));
const OperationDetailPage = lazy(() =>
  import("./pages/operations/OperationDetailPage.js").then((m) => ({ default: m.OperationDetailPage })),
);
const WalletsPage = lazy(() => import("./pages/wallets/WalletsPage.js").then((m) => ({ default: m.WalletsPage })));
const WalletDetailPage = lazy(() => import("./pages/wallets/WalletDetailPage.js").then((m) => ({ default: m.WalletDetailPage })));
const TransfersPage = lazy(() => import("./pages/transfers/TransfersPage.js").then((m) => ({ default: m.TransfersPage })));
const TransferDetailPage = lazy(() => import("./pages/transfers/TransferDetailPage.js").then((m) => ({ default: m.TransferDetailPage })));
const AuditPage = lazy(() => import("./pages/audit/AuditPage.js").then((m) => ({ default: m.AuditPage })));
const BackupPage = lazy(() => import("./pages/backup/BackupPage.js").then((m) => ({ default: m.BackupPage })));
const ApiKeysPage = lazy(() => import("./pages/api-keys/ApiKeysPage.js").then((m) => ({ default: m.ApiKeysPage })));
const IntegrationsPage = lazy(() =>
  import("./pages/integrations/IntegrationsPage.js").then((m) => ({ default: m.IntegrationsPage })),
);
const AutoApprovePolicyPage = lazy(() =>
  import("./pages/auto-approve/AutoApprovePolicyPage.js").then((m) => ({
    default: m.AutoApprovePolicyPage,
  })),
);
const ReportingKeysPage = lazy(() => import("./pages/reporting-keys/ReportingKeysPage.js").then((m) => ({ default: m.ReportingKeysPage })));
const LabReceivePage = lazy(() => import("./pages/lab/LabReceivePage.js").then((m) => ({ default: m.LabReceivePage })));
const IntegrationPage = lazy(() => import("./pages/integration/IntegrationPage.js").then((m) => ({ default: m.IntegrationPage })));
const DestinationsPage = lazy(() => import("./pages/destinations/DestinationsPage.js").then((m) => ({ default: m.DestinationsPage })));
const DevicesPage = lazy(() => import("./pages/devices/DevicesPage.js").then((m) => ({ default: m.DevicesPage })));
const RecoveryCeremonyPage = lazy(() => import("./pages/ceremony/RecoveryCeremonyPage.js").then((m) => ({ default: m.RecoveryCeremonyPage })));
const SettingsPage = lazy(() => import("./pages/settings/SettingsPage.js").then((m) => ({ default: m.SettingsPage })));
const OperatorSecurityPage = lazy(() =>
  import("./pages/security/OperatorSecurityPage.js").then((m) => ({ default: m.OperatorSecurityPage })),
);

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 0 } },
});
bindSessionQueryClient(queryClient);

function AuthGate({ children }: { children: ReactNode }) {
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    void useAuth.getState().me().finally(() => setHydrated(true));
  }, []);
  if (!hydrated) return null;
  return <>{children}</>;
}

const FALLBACK = <p className="muted">Loading…</p>;

/**
 * Session + day-0 setup gate. Incomplete operators cannot open
 * money/app routes — redirect to pathForNextStep(next_step).
 */
function RequireAuth({ children }: { children: ReactNode }) {
  const user = useAuth((s) => s.user);
  const location = useLocation();
  const [gate, setGate] = useState<
    | { readonly kind: "loading" }
    | { readonly kind: "ok" }
    | { readonly kind: "funnel"; readonly next: Day0Step }
  >({ kind: "loading" });

  useEffect(() => {
    if (!user) return;
    if (user.mustChangePassword) {
      setGate({ kind: "funnel", next: "password" });
      return;
    }
    if (user.mustEnrolTotp) {
      setGate({ kind: "funnel", next: "totp" });
      return;
    }
    
    let cancelled = false;
    void fetch("/admin/v1/setup-state", { credentials: "include" })
      .then(async (res) => {
        if (cancelled) return;
        const decision = decideSetupStateHttp(res);
        if (decision.kind === "open_legacy") {
          // Genuine 404 only — older nodes without setup-state. Password/TOTP still gated above.
          setGate({ kind: "ok" });
          return;
        }
        if (decision.kind === "closed") {
          // 5xx / other errors: fail closed into the earliest funnel step.
          setGate({ kind: "funnel", next: "install" });
          return;
        }
        const body = (await res.json()) as SetupStateDay0;
        if (body.complete === true || body.next_step === "home") {
          setGate({ kind: "ok" });
          return;
        }
        const serverNext: Day0Step = isDay0Step(body.next_step)
          ? body.next_step
          : body.pwa_installed !== true && body.allow_browser_tab_setup !== true
            ? "install"
            : "install";
        const next = refineNextStep(serverNext, {
          packCreatedLocally: hasPackCreateMarker(),
        });
        setGate({ kind: "funnel", next });
      })
      .catch(() => {
        // Network rejection — fail closed (ZTR-1168).
        if (!cancelled) setGate({ kind: "funnel", next: "install" });
      });
    return () => {
      cancelled = true;
    };
  }, [user, location.pathname]);

  if (!user) return <Navigate to="/login" replace />;
  if (user.mustChangePassword || user.mustEnrolTotp) {
    return <Navigate to="/setup" replace />;
  }
  if (gate.kind === "loading") return null;
  if (gate.kind === "funnel") {
    // Money/app routes always bounce to current funnel step.
    if (isMoneyOrAppPath(location.pathname)) {
      return <Navigate to={pathForNextStep(gate.next)} replace />;
    }
  }
  return <>{children}</>;
}

/**
 * Funnel step routes: require auth, enforce sequence via server next_step.
 * Not wrapped in App shell (no money nav until Home).
 */
function RequireFunnel({ children }: { children: ReactNode }) {
  const user = useAuth((s) => s.user);
  const location = useLocation();
  const [next, setNext] = useState<Day0Step | "loading" | "home">("loading");

  useEffect(() => {
    if (!user) return;
    if (user.mustChangePassword) {
      setNext("password");
      return;
    }
    if (user.mustEnrolTotp) {
      setNext("totp");
      return;
    }
    
    let cancelled = false;
    void fetch("/admin/v1/setup-state", { credentials: "include" })
      .then(async (res) => {
        if (cancelled) return;
        const decision = decideSetupStateHttp(res);
        if (decision.kind === "open_legacy") {
          // 404: no setup-state API — treat funnel as complete for older nodes.
          setNext("home");
          return;
        }
        if (decision.kind === "closed") {
          setNext("install");
          return;
        }
        const body = (await res.json()) as SetupStateDay0;
        if (body.complete === true) {
          setNext("home");
          return;
        }
        const serverNext: Day0Step = isDay0Step(body.next_step) ? body.next_step : "install";
        setNext(
          refineNextStep(serverNext, { packCreatedLocally: hasPackCreateMarker() }),
        );
      })
      .catch(() => {
        if (!cancelled) setNext("install");
      });
    return () => {
      cancelled = true;
    };
  }, [user, location.pathname]);

  if (!user) return <Navigate to="/login" replace />;
  if (user.mustChangePassword || user.mustEnrolTotp) {
    return <Navigate to="/setup" replace />;
  }
  if (next === "loading") return null;
  if (next === "home") return <Navigate to="/" replace />;
  const bounce = redirectForFunnelPath(location.pathname, next);
  if (bounce) return <Navigate to={bounce} replace />;
  return <>{children}</>;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ErrorBoundary variant="page">
      <QueryClientProvider client={queryClient}>
        <TotpPromptProvider>
          <BrowserRouter>
            <AuthGate>
              <Routes>
                <Route path="/login" element={<LoginPage />} />
                <Route
                  path="/setup"
                  element={
                    <Suspense fallback={FALLBACK}>
                      <SetupPage />
                    </Suspense>
                  }
                />
                <Route
                  path="/start/install"
                  element={
                    <RequireFunnel>
                      <Suspense fallback={FALLBACK}>
                        <StartSetupStepPage />
                      </Suspense>
                    </RequireFunnel>
                  }
                />
                <Route
                  path="/start/device"
                  element={
                    <RequireFunnel>
                      <Suspense fallback={FALLBACK}>
                        <StartSetupStepPage />
                      </Suspense>
                    </RequireFunnel>
                  }
                />
                <Route
                  path="/start/vault"
                  element={
                    <RequireFunnel>
                      <Suspense fallback={FALLBACK}>
                        <StartSetupStepPage />
                      </Suspense>
                    </RequireFunnel>
                  }
                />
                <Route
                  path="/start/backup"
                  element={
                    <RequireFunnel>
                      <Suspense fallback={FALLBACK}>
                        <StartBackupPage />
                      </Suspense>
                    </RequireFunnel>
                  }
                />
                <Route
                  path="/start/prove"
                  element={
                    <RequireFunnel>
                      <Suspense fallback={FALLBACK}>
                        <StartProvePage />
                      </Suspense>
                    </RequireFunnel>
                  }
                />
                <Route element={<RequireAuth><App /></RequireAuth>}>
                  <Route path="/" element={<OverviewPage />} />
                  <Route path="/approve" element={<ApproveInboxPage />} />
                  <Route path="/operations" element={<OperationsPage />} />
                  <Route path="/operations/:id" element={<OperationDetailPage />} />
                  <Route path="/wallets" element={<WalletsPage />} />
                  <Route path="/wallets/:pubkey" element={<WalletDetailPage />} />
                  <Route path="/transfers" element={<TransfersPage />} />
                  <Route path="/transfers/:id" element={<TransferDetailPage />} />
                  <Route path="/audit" element={<AuditPage />} />
                  <Route path="/backup" element={<BackupPage />} />
                  <Route path="/recovery-ceremony" element={<RecoveryCeremonyPage />} />
                  <Route path="/api-keys" element={<ApiKeysPage />} />
                  <Route path="/integrations" element={<IntegrationsPage />} />
                  <Route path="/auto-approve" element={<AutoApprovePolicyPage />} />
                  <Route path="/devices" element={<DevicesPage />} />
                  <Route path="/devices/enrol" element={<DevicesPage />} />
                  <Route path="/reporting-keys" element={<ReportingKeysPage />} />
                  <Route path="/integration" element={<IntegrationPage />} />
                  <Route path="/connect" element={<IntegrationPage />} />
                  <Route path="/lab/receive" element={<LabReceivePage />} />
                  <Route path="/destinations" element={<DestinationsPage />} />
                  <Route path="/settings" element={<SettingsPage />} />
                  <Route path="/operator-security" element={<OperatorSecurityPage />} />
                </Route>
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </AuthGate>
          </BrowserRouter>
        </TotpPromptProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  </StrictMode>,
);
