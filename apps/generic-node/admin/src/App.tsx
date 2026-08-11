import { Suspense, useEffect, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { ErrorBoundary } from "./components/ErrorBoundary.js";
import {
  IconAlert, IconArrow, IconClipboard, IconFile, IconGrid,
  IconKey, IconLock, IconLogo, IconLogout, IconMoon, IconPin,
  IconTarget, IconWallet, IconBell, IconSettings,
} from "./icons.js";
import { apiOrDemo } from "./lib/api.js";
import { fetchEffectiveConfig } from "./pages/settings/SettingsPage.js";
import { deriveNodeHealthUiState, fetchNodeReadiness, type NodeHealthUiState } from "./lib/health.js";
import { EMPTY_NEEDS_ATTENTION, type NeedsAttentionResponse } from "./lib/ops.js";
import { useAuth } from "./store/auth.js";
import { OfflineBanner } from "./components/OfflineBanner.js";
import { InstallHomeNudge } from "./components/InstallPrompt.js";
import {
  consumeDeferredInstallPrompt,
  getDeferredInstallPrompt,
  subscribeDeferredInstallPrompt,
  type BeforeInstallPromptEvent,
} from "./lib/pwa.js";

type NavItem = { to: string; label: string; icon: ReactNode; end?: boolean; badge?: number; badgeHot?: boolean };
type NavSec = { title: string; items: NavItem[] };

const PIN_KEY = "zu-node-ui-sidebar-pinned";
const THEME_KEY = "zu-node-ui-theme";

const HEALTH_LABEL: Record<NodeHealthUiState, string> = {
  checking: "Checking…",
  healthy: "Healthy",
  degraded: "Degraded",
  offline: "Offline",
};
const HEALTH_DOT_CLASS: Record<NodeHealthUiState, string> = {
  checking: "",
  healthy: "",
  degraded: "warn",
  offline: "danger",
};
const HEALTH_TEXT_CLASS: Record<NodeHealthUiState, string> = {
  checking: "muted",
  healthy: "ok",
  degraded: "warn",
  offline: "danger",
};

/** Production shell sections — Approve inbox / Operations / money rails / vault. */
export function buildSections(attentionBadge: number | undefined): NavSec[] {
  return [
    {
      title: "Command",
      items: [
        { to: "/", label: "Overview", icon: <IconGrid />, end: true },
        {
          to: "/approve",
          label: "Approve",
          icon: <IconClipboard />,
          badge: attentionBadge && attentionBadge > 0 ? attentionBadge : undefined,
          badgeHot: attentionBadge !== undefined && attentionBadge > 0,
        },
        {
          to: "/operations",
          label: "Operations",
          icon: <IconAlert />,
        },
      ],
    },
    {
      title: "Custody",
      items: [
        { to: "/wallets", label: "Wallets", icon: <IconWallet /> },
        { to: "/transfers", label: "Transfers", icon: <IconArrow /> },
        { to: "/destinations", label: "Destinations", icon: <IconTarget /> },
      ],
    },
    {
      title: "Vault",
      items: [
        { to: "/backup", label: "Backup", icon: <IconLock /> },
        { to: "/recovery-ceremony", label: "Recovery", icon: <IconKey /> },
        { to: "/api-keys", label: "Keys", icon: <IconKey /> },
        { to: "/devices", label: "Devices", icon: <IconLock /> },
        { to: "/reporting-keys", label: "Reporting", icon: <IconBell /> },
        { to: "/integration", label: "Connect", icon: <IconFile /> },
        { to: "/audit", label: "Audit", icon: <IconFile /> },
        { to: "/settings", label: "Settings", icon: <IconSettings /> },
      ],
    },
  ];
}

/** Flat label census of production nav (used by boundary tests). */
export function productionNavLabels(attentionBadge?: number): string[] {
  return buildSections(attentionBadge).flatMap((s) => s.items.map(({ label }) => label));
}

export function App() {
  const logout = useAuth((s) => s.logout);
  const user = useAuth((s) => s.user);
  const demoMode = useAuth((s) => s.demoMode);
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [pinned, setPinned] = useState(() => localStorage.getItem(PIN_KEY) === "1");
  const [theme, setTheme] = useState<"dark" | "light">(() =>
    (localStorage.getItem(THEME_KEY) as "dark" | "light") || "dark",
  );
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(
    () => getDeferredInstallPrompt(),
  );

  useEffect(() => subscribeDeferredInstallPrompt(setDeferredPrompt), []);

  const attentionQ = useQuery({
    queryKey: ["needs-attention-nav", demoMode],
    queryFn: async () =>
      apiOrDemo<NeedsAttentionResponse>("/operations/needs-attention", EMPTY_NEEDS_ATTENTION),
    refetchInterval: demoMode ? false : 30_000,
    enabled: Boolean(user) && !demoMode,
  });
  const attentionBadge = attentionQ.data?.live
    ? attentionQ.data.data.summary.total
    : demoMode
      ? 3
      : undefined;
  const sections = buildSections(attentionBadge);

  // Real /health/ready probe — never enabled in demo mode, where
  // the shell shows fixture data and never claims a live probe result.
  const healthQ = useQuery({
    queryKey: ["node-health"],
    queryFn: fetchNodeReadiness,
    refetchInterval: demoMode ? false : 15_000,
    enabled: !demoMode,
    retry: false,
  });
  const healthState = deriveNodeHealthUiState(demoMode, healthQ);

  const settingsQ = useQuery({
    queryKey: ["effective-config-shell", demoMode],
    queryFn: fetchEffectiveConfig,
    staleTime: 60_000,
    enabled: Boolean(user),
    retry: false,
  });
  const settings = settingsQ.data?.data;
  const networkLabel = (() => {
    if (!settings) return "Node";
    const host = settings.gateway_hosts[0];
    if (host) {
      const short = host.replace(/^https?:\/\//, "").split("/")[0] ?? host;
      return short.length > 28 ? `${short.slice(0, 26)}…` : short;
    }
    if (settings.public_base_url) {
      try {
        return new URL(settings.public_base_url).host || "Node";
      } catch {
        return "Node";
      }
    }
    return "Node";
  })();
  const versionLabel = settings?.version ? ` · ${settings.version}` : "";
  const displayName = user?.username?.trim() || null;
  const initials = (() => {
    if (!displayName) return null;
    const parts = displayName.split(/[\s._@-]+/).filter(Boolean);
    if (parts.length >= 2) {
      return `${parts[0]![0] ?? ""}${parts[1]![0] ?? ""}`.toUpperCase();
    }
    return displayName.slice(0, 2).toUpperCase();
  })();

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem(PIN_KEY, pinned ? "1" : "0");
  }, [pinned]);

  return (
    <div className={pinned ? "app pinned" : "app"}>
      <a className="skip-link" href="#main-content">Skip to content</a>
      <aside className="side" aria-label="Primary">
        <div className="brand">
          <div className="logo" aria-hidden><IconLogo /></div>
          <div className="brand-name">Zu <span>Node</span></div>
        </div>
        {sections.map((sec) => (
          <div key={sec.title}>
            <div className="sec">{sec.title}</div>
            {sec.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => (isActive ? "nav active" : "nav")}
              >
                <span className="ic">{item.icon}</span>
                <span className="lbl">{item.label}</span>
                {item.badge ? (
                  <span className={`count ${item.badgeHot ? "danger" : "warn"}`}>{item.badge}</span>
                ) : null}
                {item.badge ? <span className={`dot ${item.badgeHot ? "danger" : ""}`} /> : null}
              </NavLink>
            ))}
          </div>
        ))}
        <div className="side-foot">
          <button type="button" className="pin" onClick={() => setPinned((p) => !p)}>
            <span className="ic"><IconPin /></span>
            <span className="lbl">{pinned ? "Collapse sidebar" : "Pin sidebar"}</span>
          </button>
          <button
            type="button"
            className="nav"
            style={{ width: "calc(100% - 16px)", border: 0, background: "transparent", cursor: "pointer" }}
            onClick={() => void logout()}
          >
            <span className="ic"><IconLogout /></span>
            <span className="lbl">Log out</span>
          </button>
        </div>
      </aside>

      <div className="main">
        <header className="top">
          <span className="meta-chip" data-testid="network-label">
            {networkLabel}{versionLabel}
          </span>
          <span className="meta-chip">
            <span className={`live ${HEALTH_DOT_CLASS[healthState]}`} /> {HEALTH_LABEL[healthState]}
          </span>
          <div style={{ flex: 1 }} />
          <button type="button" className="icon-btn" title="Toggle theme" onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}>
            <IconMoon />
          </button>
          <button
            type="button"
            className="icon-btn"
            title={attentionBadge && attentionBadge > 0 ? `${attentionBadge} item(s) need attention` : "Approve inbox"}
            onClick={() => navigate("/approve")}
          >
            <IconBell />
          </button>
          <div className="who">
            {initials ? <div className="av" aria-hidden>{initials}</div> : null}
            {displayName ? <span>{displayName}</span> : <span className="muted">Signed in</span>}
          </div>
        </header>

        <div className="body" id="main-content" tabIndex={-1}>
          {demoMode ? (
            <div className="banner-demo" role="status">
              Design preview — fixture data. Sign in against this node for live attention and dual-control flows.
            </div>
          ) : null}
          <OfflineBanner healthState={healthState} demoMode={demoMode} />
          {pathname === "/" ? (
            <InstallHomeNudge
              deferredPrompt={deferredPrompt}
              onPromptConsumed={consumeDeferredInstallPrompt}
            />
          ) : null}
          <ErrorBoundary variant="inline" key={pathname}>
            <Suspense fallback={<p className="muted">Loading…</p>}>
              <Outlet />
            </Suspense>
          </ErrorBoundary>
        </div>
        <footer className="foot">
          <span>Node <b className={HEALTH_TEXT_CLASS[healthState]}>{HEALTH_LABEL[healthState].toLowerCase()}</b></span>
          <span className="sep">·</span>
          <span>
            Attention{" "}
            <b className={attentionBadge && attentionBadge > 0 ? "warn" : "ok"}>
              {attentionBadge ?? "—"}
            </b>
          </span>
          <span className="sep">·</span>
          <span>Session <b className="ok">{demoMode ? "demo" : "live"}</b></span>
          <span className="sep">·</span>
          <span style={{ marginLeft: "auto" }}>generic-node-ui</span>
        </footer>
      </div>
    </div>
  );
}
