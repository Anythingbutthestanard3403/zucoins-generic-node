import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OperationsPage } from "./OperationsPage.js";
import { TotpPromptProvider } from "../../totp/TotpPromptProvider.js";
import { useAuth } from "../../store/auth.js";

function liveSession() {
  useAuth.setState({
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
        has_more: false,
        next_cursor: null,
      }), { status: 200 })),
    );
    renderPage();
    await waitFor(() => expect(screen.getByText("No operations need attention.")).toBeInTheDocument());
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
        has_more: false,
        next_cursor: null,
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

  it("badge total is server summary.total and load-more walks the cursor (ZTR-1284)", async () => {
    const row = (id: string) => ({
      operation_id: id,
      operation_type: "SEND_EXTERNAL",
      status: "PARKED",
      attention_required: true,
      attention_reason: "stuck",
      classification: "WAITING",
      classification_rationale: "awaiting formation",
      severity: "P1" as const,
      permitted_actions: [] as string[],
      row_version: 1,
      lease_epoch: null,
      attention_since: "2026-07-30T00:00:00.000Z",
      wallet_ids: [] as string[],
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (!url.includes("needs-attention")) {
        return new Response(JSON.stringify({ error: { code: "not_found", message: url } }), {
          status: 404,
        });
      }
      if (url.includes("after=")) {
        return new Response(
          JSON.stringify({
            operations: [row("op-2")],
            summary: { total: 87, by_classification: { WAITING: 87 }, p0_invariant_breach: 0 },
            has_more: false,
            next_cursor: null,
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          operations: [row("op-1")],
          summary: { total: 87, by_classification: { WAITING: 87 }, p0_invariant_breach: 0 },
          has_more: true,
          next_cursor: "00000000-0000-4000-8000-000000000001",
        }),
        { status: 200 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const { container } = renderPage();
    expect(await screen.findByText(/op-1/)).toBeInTheDocument();
    // Tab badge and Parked stat use summary.total (87), not page length (1).
    const warnBadges = Array.from(container.querySelectorAll(".n.warn")).map((el) => el.textContent);
    expect(warnBadges).toContain("87");
    const parked = Array.from(container.querySelectorAll(".stat")).find((el) =>
      el.textContent?.includes("Parked"),
    );
    expect(parked?.querySelector(".v")?.textContent).toBe("87");
    expect(screen.getByText(/Showing 1 of 87/)).toBeInTheDocument();

    screen.getByTestId("needs-attention-load-more").click();
    expect(await screen.findByText(/op-2/)).toBeInTheDocument();
    expect(screen.getByText(/Showing 2 of 87/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.some((c) => String(c[0]).includes("after="))).toBe(true);
  });

  it("surfaces EXPIRED + attention_required receives in the needs-attention inbox (ZTR-1278/1285)", async () => {
    const expiredOp = {
      operation_id: "recv-expired-1",
      operation_type: "RECEIVE_EXTERNAL",
      status: "EXPIRED",
      attention_required: true,
      attention_reason: "T0_RELEASE_MISMATCH",
      classification: "NEEDS_ATTENTION",
      classification_rationale: "fresh head does not match T0",
      severity: "P1",
      permitted_actions: ["QUARANTINE_WALLETS", "RELEASE_EXPIRED_RECEIVE"],
      row_version: 3,
      lease_epoch: 1,
      attention_since: "2026-08-14T00:00:00.000Z",
      wallet_ids: ["wallet-recv-1"],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            operations: [expiredOp],
            summary: {
              total: 1,
              by_classification: { NEEDS_ATTENTION: 1 },
              p0_invariant_breach: 0,
            },
            has_more: false,
            next_cursor: null,
          }),
          { status: 200 },
        ),
      ),
    );
    const { container } = renderPage();
    expect(await screen.findByText(/recv-expired-1/)).toBeInTheDocument();
    // Parked stat mirrors summary.total from the same payload (badge/page parity).
    const statValues = Array.from(container.querySelectorAll(".stat .v")).map(
      (el) => el.textContent,
    );
    expect(statValues[0]).toBe("1");
    expect(screen.getByText(/T0 release mismatch/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open detail/i })).toHaveAttribute(
      "href",
      "/operations/recv-expired-1",
    );
    expect(screen.queryByText("No operations need attention.")).not.toBeInTheDocument();
  });

  it("history tab lists inventory ops with receive detail links", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("needs-attention")) {
        return new Response(
          JSON.stringify({
            operations: [],
            summary: { total: 0, by_classification: {}, p0_invariant_breach: 0 },
            has_more: false,
            next_cursor: null,
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
                expiry_unix_time_secs: null,
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
