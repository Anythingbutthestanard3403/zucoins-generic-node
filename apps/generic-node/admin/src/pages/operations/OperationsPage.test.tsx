import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OperationsPage } from "./OperationsPage.js";
import { TotpPromptProvider } from "../../totp/TotpPromptProvider.js";
import { useAuth } from "../../store/auth.js";

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
      <TotpPromptProvider>
        <MemoryRouter>
          <OperationsPage />
        </MemoryRouter>
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

describe("OperationsPage honesty", () => {
  beforeEach(() => liveSession());
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("never paints a pending fetch as unavailable or empty", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    renderPage();
    expect(screen.getAllByText("Loading…").length).toBeGreaterThan(0);
    expect(screen.queryByText(/Attention queue unavailable/)).not.toBeInTheDocument();
    expect(screen.queryByText("No operations need attention.")).not.toBeInTheDocument();
  });

  it("does not claim an empty attention queue when a 503 makes it unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: { code: "service_unavailable", message: "down" } }), { status: 503 })),
    );
    const { container } = renderPage();
    await waitFor(() => expect(screen.getByText(/Attention queue unavailable/)).toBeInTheDocument());
    expect(screen.queryByText("No operations need attention.")).not.toBeInTheDocument();
    const statValues = Array.from(container.querySelectorAll(".stat .v")).map((el) => el.textContent);
    expect(statValues).toEqual(["—", "—"]);
  });

  it("shows 'No operations need attention' only after a live 200 with an empty queue", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({
        operations: [],
        summary: { total: 0, by_classification: {}, p0_invariant_breach: 0 },
      }), { status: 200 })),
    );
    renderPage();
    await waitFor(() => expect(screen.getByText("No operations need attention.")).toBeInTheDocument());
  });

  it("distinguishes demo preview from a live-fetch unavailable state", () => {
    useAuth.setState({ demoMode: true });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(screen.getByText(/No fixtures — log in for a live session to view the attention queue\./)).toBeInTheDocument();
    expect(screen.queryByText(/Attention queue unavailable/)).not.toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("renders a live attention row from a real 200", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({
        operations: [{
          operation_id: "op-1",
          operation_type: "SEND_EXTERNAL",
          status: "PARKED",
          attention_required: true,
          attention_reason: "stuck",
          classification: "WAITING",
          classification_rationale: "awaiting formation",
          severity: "P1",
          permitted_actions: [],
          row_version: 1,
          lease_epoch: null,
          attention_since: "2026-07-30T00:00:00.000Z",
          wallet_ids: [],
        }],
        summary: { total: 1, by_classification: { WAITING: 1 }, p0_invariant_breach: 0 },
      }), { status: 200 })),
    );
    renderPage();
    expect(await screen.findByText(/op-1/)).toBeInTheDocument();
    expect(screen.queryByText("No operations need attention.")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open detail/i })).toHaveAttribute(
      "href",
      "/operations/op-1",
    );
  });

  it("history tab lists inventory ops with receive detail links", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
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
                operation_id: "recv-1",
                operation_type: "RECEIVE_EXTERNAL",
                status: "RECEIVE_LANDED",
                amount_zkz: "0.01",
                row_version: 4,
                attention_required: false,
                attention_reason: null,
                created_at: "2026-08-02T15:46:53.940Z",
                updated_at: "2026-08-02T15:46:59.685Z",
                terminal_at: "2026-08-02T15:46:59.685Z",
              },
            ],
            has_more: false,
            next_cursor: null,
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ error: { code: "not_found", message: url } }), {
        status: 404,
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await screen.findByText("No operations need attention.");
    // Tab button (class "tab") — not the inline "History" linkish control in the empty state.
    const historyTab = screen
      .getAllByRole("button", { name: /History/i })
      .find((el) => el.classList.contains("tab"));
    expect(historyTab).toBeTruthy();
    historyTab!.click();
    expect(await screen.findByText("recv-1")).toBeInTheDocument();
    expect(screen.getByText("0.01")).toBeInTheDocument();
    const links = screen.getAllByRole("link");
    expect(links.some((a) => a.getAttribute("href") === "/operations/recv-1")).toBe(true);
  });
});
