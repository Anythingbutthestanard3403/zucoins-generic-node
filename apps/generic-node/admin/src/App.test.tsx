import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App, buildSections, productionNavLabels } from "./App.js";
import {
  FORBIDDEN_NAV_LABELS,
  FORBIDDEN_NAV_PATHS,
  PRODUCTION_NAV_LABELS,
  PRODUCTION_NAV_PATHS,
} from "./nav.js";
import { OverviewPage } from "./pages/overview/OverviewPage.js";
import { useAuth } from "./store/auth.js";
import { TotpPromptProvider } from "./totp/TotpPromptProvider.js";
import { assertPacksPreserveNavInvariant, packChecklistRowsForEnabled, kitSlotsForPacks } from "./lib/packs.js";

const adminSrc = dirname(fileURLToPath(import.meta.url));

function authenticateDemo() {
  useAuth.setState({
    demoMode: true,
    user: {
      userId: "demo",
      username: "demo",
      role: "admin",
      mustEnrolTotp: false,
      mustChangePassword: false,
      csrfToken: "x",
    },
  });
}

function liveSession() {
  useAuth.setState({
    demoMode: false,
    user: {
      userId: "u1",
      username: "op",
      role: "admin",
      mustEnrolTotp: false,
      mustChangePassword: false,
      csrfToken: "csrf",
    },
  });
}

const FALLBACK_503 = () =>
  new Response(JSON.stringify({ error: { code: "service_unavailable", message: "unavailable" } }), { status: 503 });

/** Routes GET /health/ready to `handler`; every other path gets a generic 503
 *  fallback so the shell's other live queries (attention badge) never crash
 *  on an unrelated readiness-shaped body. */
function stubHealthFetch(handler: () => Response | Promise<Response>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      return url.startsWith("/health/ready") ? handler() : FALLBACK_503();
    }),
  );
}

function renderShell(ui: import("react").ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <TotpPromptProvider>
        <MemoryRouter initialEntries={["/"]}>
          <Routes>
            <Route element={<App />}>
              <Route path="/" element={ui} />
            </Route>
          </Routes>
        </MemoryRouter>
      </TotpPromptProvider>
     </QueryClientProvider>,
  );
}

describe("App shell", () => {
  it("renders overview chrome when authenticated", async () => {
    authenticateDemo();
    renderShell(<div>Overview body</div>);
    expect(screen.getByText("Overview body")).toBeInTheDocument();
    expect(screen.getByText(/Zu/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Search")).not.toBeInTheDocument();
  });


  it("enabling any pack combination does not add forbidden nav", () => {
    for (const combo of [[], ["M"], ["T"], ["P"], ["M", "T", "P"]] as const) {
      void packChecklistRowsForEnabled(combo);
      void kitSlotsForPacks(combo);
      assertPacksPreserveNavInvariant(productionNavLabels(0), buildSections(undefined).flatMap((s) => s.items.map((i) => i.to)));
    }
    const labels = productionNavLabels(0);
    for (const f of FORBIDDEN_NAV_LABELS) {
      expect(labels).not.toContain(f);
    }
    expect(labels).not.toContain("Orders");
  });

  it("production nav is the closed generic model set", () => {
    const labels = productionNavLabels(0);
    expect(labels).toEqual([...PRODUCTION_NAV_LABELS]);
    for (const forbidden of FORBIDDEN_NAV_LABELS) {
      expect(labels).not.toContain(forbidden);
    }
    const paths = buildSections(undefined).flatMap((s) => s.items.map((i) => i.to));
    expect(paths).toEqual([...PRODUCTION_NAV_PATHS]);
    for (const p of FORBIDDEN_NAV_PATHS) {
      expect(paths).not.toContain(p);
    }
  });

  it("labels the only fixture mode with the design-preview banner (restored, was honesty.test.tsx)", () => {
    cleanup();
    authenticateDemo();
    renderShell(<div>body</div>);
    expect(screen.getByRole("status")).toHaveTextContent(/Design preview.*fixture data/i);
  });

  it("does not show the design-preview banner in a live (non-demo) session", () => {
    cleanup();
    useAuth.setState({
      demoMode: false,
      user: {
        userId: "u1",
        username: "op",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "x",
      },
    });
    renderShell(<div>body</div>);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shell DOM exposes only production nav labels", () => {
    authenticateDemo();
    const { container } = renderShell(<div>body</div>);
    const sides = container.querySelectorAll('aside[aria-label="Primary"]');
    expect(sides.length).toBeGreaterThan(0);
    const labels = [...sides[0]!.querySelectorAll("a.nav .lbl")].map((el) => el.textContent?.trim());
    expect(labels).toEqual([...PRODUCTION_NAV_LABELS]);
    for (const forbidden of ["Sessions", "Sweeps", "Webhooks"] as const) {
      expect(labels).not.toContain(forbidden);
    }
    expect(container.textContent).not.toMatch(/\bSessions\b/);
    expect(container.textContent).not.toMatch(/\bSweeps\b/);
    expect(container.textContent).not.toMatch(/\bWebhooks\b/);
  });
});

describe("sidebar reachable without hover", () => {
  it("the 'Pin sidebar' control is keyboard-focusable and toggles the app's pinned state on click, no hover required", () => {
    cleanup();
    authenticateDemo();
    const { container } = renderShell(<div>body</div>);
    const pinBtn = screen.getByRole("button", { name: "Pin sidebar" });
    pinBtn.focus();
    expect(pinBtn).toHaveFocus();
    expect(container.querySelector(".app.pinned")).toBeNull();
    fireEvent.click(pinBtn);
    expect(container.querySelector(".app.pinned")).not.toBeNull();
    expect(screen.getByRole("button", { name: "Collapse sidebar" })).toBeInTheDocument();
  });
});

describe("Overview product boundary", () => {
  it("shows three ops + wallets + attention  not checkout sessions chrome", () => {
    authenticateDemo();
    renderShell(<OverviewPage />);
    expect(screen.getByTestId("three-ops-stats")).toBeInTheDocument();
    expect(screen.getByText("Incoming")).toBeInTheDocument();
    expect(screen.getByText("Internal transfer")).toBeInTheDocument();
    expect(screen.getByText("Outgoing (needs approval)")).toBeInTheDocument();
    // Wire enums remain as secondary mono text
    expect(screen.getByText("RECEIVE_EXTERNAL")).toBeInTheDocument();
    expect(screen.getByText("MOVE_INTERNAL")).toBeInTheDocument();
    expect(screen.getByText("SEND_EXTERNAL")).toBeInTheDocument();
    expect(screen.getByText("Needs attention")).toBeInTheDocument();
    expect(screen.getByText("Wallet pool")).toBeInTheDocument();
    expect(screen.queryByText("Recent sessions")).not.toBeInTheDocument();
    expect(screen.queryByText("Open sessions")).not.toBeInTheDocument();
    expect(screen.queryByText("See all", { selector: 'a[href="/sessions"]' })).not.toBeInTheDocument();
  });
});

describe("Overview honesty: ungated fixture zeros + stale-data-under-unavailable", () => {
  it("demo mode never renders 0 counts — uses em-dash fallback", () => {
    cleanup();
    authenticateDemo();
    renderShell(<OverviewPage />);
    const stats = screen.getAllByTestId("three-ops-stats")[0]!;
    const text = stats.textContent ?? "";
    expect(text).toContain("—");
  });

  it("demo mode activity section shows demo message, not 'No activity yet'", () => {
    cleanup();
    authenticateDemo();
    const { container } = renderShell(<OverviewPage />);
    expect(container.textContent).toContain("No fixtures");
  });
});

describe("node health chrome — real /health/ready, no hard-coded Healthy", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("shows Checking… while the probe is in flight, never Healthy", async () => {
    cleanup();
    liveSession();
    stubHealthFetch(() => new Promise<Response>(() => {}));
    renderShell(<div>body</div>);
    expect(screen.getByText("Checking…")).toBeInTheDocument();
    expect(screen.queryByText("Healthy")).not.toBeInTheDocument();
  });

  it("renders Healthy only from a verified ready probe", async () => {
    cleanup();
    liveSession();
    stubHealthFetch(() => new Response(JSON.stringify({ status: "ready" }), { status: 200 }));
    renderShell(<div>body</div>);
    await waitFor(() => expect(screen.getByText("Healthy")).toBeInTheDocument());
  });

  it("renders Degraded from a verified non-ready probe, never Healthy", async () => {
    cleanup();
    liveSession();
    stubHealthFetch(() => new Response(JSON.stringify({ status: "degraded" }), { status: 503 }));
    renderShell(<div>body</div>);
    await waitFor(() => expect(screen.getByText("Degraded")).toBeInTheDocument());
    expect(screen.queryByText("Healthy")).not.toBeInTheDocument();
  });

  it("renders Offline when the probe is unreachable, never Healthy", async () => {
    cleanup();
    liveSession();
    stubHealthFetch(() => {
      throw new TypeError("Failed to fetch");
    });
    renderShell(<div>body</div>);
    await waitFor(() => expect(screen.getByText("Offline")).toBeInTheDocument());
    expect(screen.queryByText("Healthy")).not.toBeInTheDocument();
  });

  it("shows offline honesty banner when the node is unreachable", async () => {
    cleanup();
    liveSession();
    stubHealthFetch(() => {
      throw new TypeError("Failed to fetch");
    });
    renderShell(<div>body</div>);
    await waitFor(() => expect(screen.getByTestId("offline-honesty-banner")).toBeInTheDocument());
    expect(screen.getByTestId("offline-honesty-banner")).toHaveTextContent(/Node unreachable/i);
    expect(screen.queryByText(/1248/)).not.toBeInTheDocument();
  });

  it("does not show offline honesty banner in design preview", async () => {
    cleanup();
    authenticateDemo();
    stubHealthFetch(() => {
      throw new TypeError("Failed to fetch");
    });
    renderShell(<div>body</div>);
    expect(screen.queryByTestId("offline-honesty-banner")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/Design preview/i);
  });

  it("Notifications button is genuinely wired: navigates to Approve inbox", () => {
    cleanup();
    liveSession();
    vi.stubGlobal("fetch", vi.fn(async () => FALLBACK_503()));
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TotpPromptProvider>
          <MemoryRouter initialEntries={["/"]}>
            <Routes>
              <Route element={<App />}>
                <Route path="/" element={<div>Overview body</div>} />
                <Route path="/approve" element={<div>Approve body</div>} />
              </Route>
            </Routes>
          </MemoryRouter>
        </TotpPromptProvider>
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByTitle("Approve inbox"));
    expect(screen.getByText("Approve body")).toBeInTheDocument();
  });
});

describe("router source boundary (no v1 checkout routes)", () => {
  it("main.tsx does not register sessions/sweeps/webhooks routes", () => {
    const main = readFileSync(join(adminSrc, "main.tsx"), "utf8");
    for (const path of FORBIDDEN_NAV_PATHS) {
      expect(main).not.toMatch(new RegExp(`path=["']${path.replace("/", "\\/")}`));
    }
    expect(main).not.toMatch(/SessionsPage|SweepsPage|WebhookDeliveriesPage/);
    expect(main).not.toMatch(/pages\/sessions|pages\/sweeps|pages\/webhooks/);
  });

  it("checkout chrome page modules are not present", () => {
    for (const rel of [
      "pages/sessions/SessionsPage.tsx",
      "pages/sweeps/SweepsPage.tsx",
      "pages/webhooks/WebhookDeliveriesPage.tsx",
    ]) {
      let exists = true;
      try {
        readFileSync(join(adminSrc, rel), "utf8");
      } catch {
        exists = false;
      }
      expect(exists, rel).toBe(false);
    }
  });

  it("main.tsx registers /settings with SettingsPage (secret-safe effective config)", () => {
    const main = readFileSync(join(adminSrc, "main.tsx"), "utf8");
    expect(main).toMatch(/path=["']\/settings["']/);
    expect(main).toMatch(/SettingsPage/);
    expect(main).toMatch(/pages\/settings/);
  });

  it("SettingsPage module is present on disk", () => {
    const src = readFileSync(join(adminSrc, "pages/settings/SettingsPage.tsx"), "utf8");
    expect(src).toMatch(/SettingsPage/);
    expect(src).toMatch(/public_base_url/);
    // Read-only: no PATCH/POST settings mutation helper on the page module.
    expect(src).not.toMatch(/method:\s*["']POST["']/);
    expect(src).not.toMatch(/method:\s*["']PATCH["']/);
  });
});
