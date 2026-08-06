// axe-core smoke test over admin key operator-workflow screens.
// WCAG label/keyboard/reflow/name-role-value is the binding standard here.
//
// This runs the actual axe-core engine against rendered output, so a real
// regression (missing accessible name, duplicate id, invalid ARIA usage)
// fails the suite even if the hand-written per-page a11y assertions elsewhere
// in this package don't happen to probe it.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, cleanup, act, fireEvent } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router";

import { App } from "./App.js";
import { useAuth } from "./store/auth.js";
import { TotpPromptProvider } from "./totp/TotpPromptProvider.js";
import { OverviewPage } from "./pages/overview/OverviewPage.js";
import { DestinationsPage } from "./pages/destinations/DestinationsPage.js";
import { WalletsPage } from "./pages/wallets/WalletsPage.js";
import { ApiKeysPage } from "./pages/api-keys/ApiKeysPage.js";
import { BackupPage } from "./pages/backup/BackupPage.js";
import { ApproveInboxPage } from "./pages/approve/ApproveInboxPage.js";
import { SettingsPage } from "./pages/settings/SettingsPage.js";
import { OperationsPage } from "./pages/operations/OperationsPage.js";
import { OperationDetailPage } from "./pages/operations/OperationDetailPage.js";
import { TransfersPage } from "./pages/transfers/TransfersPage.js";
import { AuditPage } from "./pages/audit/AuditPage.js";
import { WalletDetailPage } from "./pages/wallets/WalletDetailPage.js";
import { TransferDetailPage } from "./pages/transfers/TransferDetailPage.js";
import { LoginPage } from "./pages/Login.js";
import { SetupPage } from "./pages/Setup.js";
import { axeViolations, formatViolations } from "./test-a11y.js";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// axe.run() spans several microtask ticks; screens with pending react-query
// fetches can flush a setState during that window. Wrapping the run in act()
// keeps that flush inside the test instead of leaking an "update not wrapped
// in act" warning after assertions.
async function expectNoAxeViolations(container: Element) {
  let violations: Awaited<ReturnType<typeof axeViolations>> = [];
  await act(async () => {
    violations = await axeViolations(container);
  });
  expect(violations, formatViolations(violations)).toHaveLength(0);
}

function demoSession() {
  useAuth.setState({
    demoMode: true,
    user: { userId: "demo", role: "admin", mustEnrolTotp: false, mustChangePassword: false, csrfToken: "x" },
  });
}

function liveSession() {
  useAuth.setState({
    demoMode: false,
    user: { userId: "u1", role: "admin", mustEnrolTotp: false, mustChangePassword: false, csrfToken: "csrf" },
  });
}

function renderShell(ui: import("react").ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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

function renderPage(ui: import("react").ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TotpPromptProvider>
        <MemoryRouter>{ui}</MemoryRouter>
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

function renderRoutedPage(
  ui: import("react").ReactElement,
  path: string,
  routePath: string,
) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TotpPromptProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes><Route path={routePath} element={ui} /></Routes>
        </MemoryRouter>
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

describe("axe smoke — App shell (Overview)", () => {
  it("has no axe violations", async () => {
    demoSession();
    const { container } = renderShell(<OverviewPage />);
    await screen.findByRole("complementary", { name: "Primary" });
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — forms + table (DestinationsPage)", () => {
  beforeEach(() => liveSession());

  it("has no axe violations with a live row and the bless form open", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            object: "list",
            data: [
              {
                destination_id: "d1",
                wallet_id: "w1",
                wallet_public_key: "zkz1qdestlive0000000000",
                state: "BLESSED",
                label: "Exchange hot wallet",
                blessed_at: "2026-07-30T00:00:00.000Z",
                retired_at: null,
              },
            ],
            has_more: false,
            next_cursor: null,
          }),
          { status: 200 },
        ),
      ),
    );
    const { container } = renderPage(<DestinationsPage />);
    await screen.findByText("Exchange hot wallet");
    fireEvent.click(screen.getByRole("button", { name: "Bless destination" }));
    await screen.findByLabelText("Destination id");
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — tables (WalletsPage)", () => {
  beforeEach(() => liveSession());

  it("has no axe violations with a live row", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            object: "list",
            data: [
              {
                wallet_id: "w1",
                public_key: "zkz1qwalletlive",
                state: "ACTIVE",
                key_origin: "NODE_GENERATED",
                recovery_verified: true,
                observed_balance_zkz: "1.5000",
              },
            ],
            has_more: false,
            next_cursor: null,
          }),
          { status: 200 },
        ),
      ),
    );
    const { container } = renderPage(<WalletsPage />);
    await screen.findByText("1.5000");
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Operations workflow", () => {
  it("has no axe violations", async () => {
    demoSession();
    const { container } = renderPage(<OperationsPage />);
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Approve inbox", () => {
  it("has no axe violations (demo empty)", async () => {
    demoSession();
    const { container } = renderPage(<ApproveInboxPage />);
    await expectNoAxeViolations(container);
  });

  it("has no axe violations with one pending SEND", async () => {
    liveSession();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("needs-attention")) {
          return new Response(
            JSON.stringify({
              operations: [],
              summary: { total: 0, by_classification: {}, p0_invariant_breach: 0 },
            }),
            { status: 200 },
          );
        }
        if (url.includes("/operations")) {
          return new Response(
            JSON.stringify({
              object: "list",
              data: [
                {
                  operation_id: "op-axe-send-1",
                  operation_type: "SEND_EXTERNAL",
                  status: "CREATED",
                  amount_zkz: "0.0100",
                  row_version: 1,
                  attention_required: false,
                  attention_reason: null,
                  created_at: "2026-08-02T00:00:00.000Z",
                  destination_address: "zkz1qaxe0001",
                },
              ],
              has_more: false,
              next_cursor: null,
            }),
            { status: 200 },
          );
        }
        return new Response(
          JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
          { status: 200 },
        );
      }),
    );
    const { container } = renderPage(<ApproveInboxPage />);
    await screen.findByTestId("approve-send-card");
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Transfers workflow (list)", () => {
  it("has no axe violations", async () => {
    demoSession();
    const { container } = renderPage(<TransfersPage />);
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Audit workflow", () => {
  it("has no axe violations", async () => {
    demoSession();
    const { container } = renderPage(<AuditPage />);
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Backup workflow", () => {
  it("has no axe violations", async () => {
    demoSession();
    const { container } = renderPage(<BackupPage />);
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Settings workflow", () => {
  it("has no axe violations", async () => {
    demoSession();
    const { container } = renderPage(<SettingsPage />);
    await expectNoAxeViolations(container);
  });
});

// ApiKeysPage was previously excluded from axe coverage
// because rendering it crashed on a missing TotpPromptProvider — but renderPage() here
// (like ApiKeysPage.test.tsx) already supplies the real provider, so that was never a
// genuine blocker, only a gap in this file. Covers both the demo-mode empty state and a
// live row with the revoke control, so the action-column <th> and the issue/revoke pills
// are exercised, not just the page shell.
describe("axe smoke — Keys workflow (ApiKeysPage, demo)", () => {
  it("has no axe violations", async () => {
    demoSession();
    const { container } = renderPage(<ApiKeysPage />);
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Keys workflow (ApiKeysPage, live row)", () => {
  beforeEach(() => liveSession());

  it("has no axe violations with a live key row", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            keys: [
              {
                id: "k1",
                prefix: "ik_abcdef12",
                scopes: ["receive:create", "receive:read"],
                status: "ACTIVE",
                key_version: 1,
                issued_at: "2026-07-30T00:00:00Z",
                expires_at: null,
                revoked_at: null,
                last_used_at: null,
              },
            ],
          }),
          { status: 200 },
        ),
      ),
    );
    const { container } = renderPage(<ApiKeysPage />);
    await screen.findByText("ik_abcdef12…");
    await expectNoAxeViolations(container);
  });
});

// Detail/auth routes are operator workflows too. Keep these explicit so adding a route to
// main.tsx without axe coverage remains visible in the workflow census.
describe("axe smoke — Wallet detail workflow", () => {
  it("has no axe violations", async () => {
    demoSession();
    const { container } = renderRoutedPage(
      <WalletDetailPage />,
      "/wallets/zkz1qe2e",
      "/wallets/:pubkey",
    );
    await screen.findByRole("heading", { name: "Wallet" });
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Transfer detail workflow", () => {
  it("has no axe violations", async () => {
    demoSession();
    const { container } = renderRoutedPage(
      <TransferDetailPage />,
      "/transfers/op-e2e",
      "/transfers/:id",
    );
    await screen.findByRole("heading", { name: /Transfer op-e2e/ });
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Operation detail workflow", () => {
  it("has no axe violations", async () => {
    demoSession();
    const { container } = renderRoutedPage(
      <OperationDetailPage />,
      "/operations/op-e2e",
      "/operations/:id",
    );
    await screen.findByRole("heading", { name: /Operation op-e2e/ });
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Login workflow", () => {
  it("has no axe violations", async () => {
    useAuth.setState({ demoMode: false, user: null });
    const { container } = renderRoutedPage(<LoginPage />, "/login", "/login");
    await screen.findByRole("heading", { name: "Zu Node" });
    await expectNoAxeViolations(container);
  });
});

describe("axe smoke — Setup workflow", () => {
  it("has no axe violations", async () => {
    useAuth.setState({
      demoMode: false,
      user: {
        userId: "u1",
        role: "admin",
        mustEnrolTotp: true,
        mustChangePassword: true,
        csrfToken: "csrf",
      },
    });
    const { container } = renderRoutedPage(<SetupPage />, "/setup", "/setup");
    await screen.findByRole("heading", { name: "Finish setup" });
    await expectNoAxeViolations(container);
  });
});

// Sanity check that the helper itself actually catches a real violation —
// otherwise a broken wiring (e.g. rules disabled too broadly) would make
// every test above pass vacuously.
describe("axe smoke — helper sanity", () => {
  it("flags an element with no accessible name", async () => {
    const { container } = render(
      <div>
        {/* Intentional violation for the sanity check — no jsx-a11y lint rule is
            configured (a11y is enforced at runtime by axe, below), so no directive
            is needed here. The button-interactivity lint rule is likewise
            deliberately violated by this fixture. */}
        {/* eslint-disable-next-line admin-ui/button-must-be-interactive-or-inert -- intentional violation fixture for the axe sanity check */}
        <button />
      </div>,
    );
    const violations = await axeViolations(container);
    expect(violations.length).toBeGreaterThan(0);
  });
});
