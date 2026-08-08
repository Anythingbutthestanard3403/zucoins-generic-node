import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TransfersPage } from "./TransfersPage.js";
import { useAuth } from "../../store/auth.js";
import { saveEnabledPacks } from "../../lib/packs.js";

function liveSession() {
  useAuth.setState({
    demoMode: false,
    user: { userId: "u1", role: "admin", mustEnrolTotp: false, mustChangePassword: false, csrfToken: "csrf" },
  });
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <TransfersPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("TransfersPage honesty", () => {
  beforeEach(() => {
    liveSession();
    localStorage.clear();
  });
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("never paints a pending fetch as unavailable or empty", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    renderPage();
    expect(screen.getAllByText("Loading…").length).toBeGreaterThan(0);
    expect(screen.queryByText("Transfers unavailable")).not.toBeInTheDocument();
    expect(screen.queryByText("No transfers")).not.toBeInTheDocument();
  });

  it("does not claim 'No transfers' when a 503 makes inventory unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: { code: "service_unavailable", message: "down" } }), { status: 503 })),
    );
    renderPage();
    await waitFor(() => expect(screen.getByText("Transfers unavailable")).toBeInTheDocument());
    expect(screen.queryByText("No transfers")).not.toBeInTheDocument();
  });

  it("shows 'No transfers' only after a live 200 with an empty page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }), { status: 200 })),
    );
    renderPage();
    await waitFor(() => expect(screen.getByText("No transfers")).toBeInTheDocument());
  });

  it("distinguishes demo preview from a live-fetch unavailable state", () => {
    useAuth.setState({ demoMode: true });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(screen.getAllByText("No fixtures — log in for live").length).toBeGreaterThan(0);
    expect(screen.queryByText("Transfers unavailable")).not.toBeInTheDocument();
    expect(screen.queryByText("No transfers")).not.toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("renders a live transfer row from a real 200", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({
        object: "list",
        data: [{
          operation_id: "op-live-1",
          operation_type: "SEND_EXTERNAL",
          status: "CREATED",
          amount_zkz: "0.0100",
          row_version: 1,
          attention_required: false,
          attention_reason: null,
          created_at: "2026-07-30T00:00:00.000Z",
          destination_address: "zkz1qdest",
        }],
        has_more: false,
        next_cursor: null,
      }), { status: 200 })),
    );
    renderPage();
    expect(await screen.findByText("op-live-1")).toBeInTheDocument();
    // "To" renders the destination the summary row carries. It read `—` on every row in
    // production while the list projection omitted the field the SPA type declared.
    expect(screen.getByText("zkz1qdest")).toBeInTheDocument();
    expect(screen.queryByText("No transfers")).not.toBeInTheDocument();
  });

  it("shows Pack P dual-control teaching when P enabled", async () => {
    saveEnabledPacks(["P"]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
          { status: 200 },
        ),
      ),
    );
    renderPage();
    const banner = await screen.findByTestId("pack-p-dual-control");
    expect(banner).toHaveTextContent(/does/i);
    expect(banner).toHaveTextContent(/not/i);
    expect(banner).toHaveTextContent(/chain-submit SEND|not paid/i);
    expect(banner).toHaveTextContent(/not paid/i);
  });

});
