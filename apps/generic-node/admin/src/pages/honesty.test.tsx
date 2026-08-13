import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditPage } from "./audit/AuditPage.js";
import { ReportingKeysPage } from "./reporting-keys/ReportingKeysPage.js";
import { WalletDetailPage } from "./wallets/WalletDetailPage.js";
import { useAuth } from "../store/auth.js";
import { TotpPromptProvider } from "../totp/index.js";

function liveSession() {
  useAuth.setState({
    user: { userId: "u1", role: "admin", mustEnrolTotp: false, mustChangePassword: false, csrfToken: "csrf" },
  });
}

function renderPage(page: ReactElement, path = "/") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes><Route path="*" element={page} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

let fetchMock: ReturnType<typeof vi.fn>;

describe("admin SPA honesty", () => {
  beforeEach(() => {
    liveSession();
    fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: { code: "service_unavailable", message: "unavailable" } }), { status: 503 }));
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("does not paint a 503 audit inventory request as a successful empty audit", async () => {
    renderPage(<AuditPage />);
    await waitFor(() => expect(screen.getAllByText(/Audit inventory unavailable/).length).toBeGreaterThan(0));
    expect(screen.queryByText("No audit events")).not.toBeInTheDocument();
  });

  it("does not paint a pending audit fetch as unavailable before it settles", async () => {
    renderPage(<AuditPage />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
    expect(screen.queryByText(/Audit inventory unavailable/)).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByText(/Audit inventory unavailable/).length).toBeGreaterThan(0));
  });


  it("renders an audit row only from the live inventory GET", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      object: "list",
      data: [{
        id: "audit-1",
        actor_kind: "operator",
        actor_id: "admin-1",
        action: "wallet.inspected",
        operation_id: null,
        wallet_id: "wallet-1",
        created_at: "2026-07-30T00:00:00.000Z",
      }],
      has_more: false,
      next_cursor: null,
    }), { status: 200 })));
    renderPage(<AuditPage />);
    // Action is humanized in the cell; wire code remains on title for operators.
    expect(await screen.findByTitle("wallet.inspected")).toBeInTheDocument();
    expect(screen.getByText("wallet-1")).toBeInTheDocument();
  });

  it("does not substitute a fixture balance when wallet inventory is unavailable", async () => {
    // Real :pubkey route (not the generic "*" catch-all) so useParams() actually
    // populates pubkey and the query is enabled — proving the unavailable text
    // comes from a real fetch attempt, not a shortcut from an empty param.
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/wallets/wallet-live"]}>
          <Routes><Route path="/wallets/:pubkey" element={<WalletDetailPage />} /></Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByText(/Wallet inventory unavailable/)).toBeInTheDocument());
    expect(screen.queryByText(/1248\.4200/)).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(1);
  });

  it("marks unavailable reporting credentials without implying an empty inventory", async () => {
    render(
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <TotpPromptProvider>
          <MemoryRouter>
            <ReportingKeysPage />
          </MemoryRouter>
        </TotpPromptProvider>
      </QueryClientProvider>,
    );
    expect(
      await screen.findByText(/Reporting credential inventory and issuing are not available/),
    ).toBeInTheDocument();
    expect(screen.queryByText("No reporting credentials listed")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /issue reporting credential/i }),
    ).not.toBeInTheDocument();
  });

});
