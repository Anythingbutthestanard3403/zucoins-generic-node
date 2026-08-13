import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WalletsPage } from "./WalletsPage.js";
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
      <MemoryRouter>
        <WalletsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("WalletsPage honesty", () => {
  beforeEach(() => liveSession());
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("never paints a pending fetch as unavailable or empty", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    renderPage();
    expect(screen.getAllByText("Loading…").length).toBeGreaterThan(0);
    expect(screen.queryByText(/Inventory unavailable/)).not.toBeInTheDocument();
    expect(screen.queryByText("Wallets unavailable")).not.toBeInTheDocument();
    expect(screen.queryByText("No wallets")).not.toBeInTheDocument();
  });

  it("does not claim 'No wallets' when a 503 makes inventory unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: { code: "service_unavailable", message: "down" } }), { status: 503 })),
    );
    renderPage();
    await waitFor(() => expect(screen.getByText("Wallets unavailable")).toBeInTheDocument());
    expect(screen.queryByText("No wallets")).not.toBeInTheDocument();
  });

  it("surfaces the server's code and request id instead of a bare unavailable message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            error: { code: "service_unavailable", message: "gateway down", request_id: "req-wallets-1" },
          }),
          { status: 503 },
        ),
      ),
    );
    renderPage();
    await waitFor(() => expect(screen.getByText(/service_unavailable/)).toBeInTheDocument());
    expect(screen.getByText(/req-wallets-1/)).toBeInTheDocument();
  });

  it("shows 'No wallets' only after a live 200 with an empty page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }), { status: 200 })),
    );
    renderPage();
    await waitFor(() => expect(screen.getByText("No wallets")).toBeInTheDocument());
  });

  it("renders a live wallet row from a real 200", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({
        object: "list",
        data: [{
          wallet_id: "w1",
          public_key: "zkz1qwalletlive",
          state: "ACTIVE",
          key_origin: "NODE_GENERATED",
          recovery_verified: true,
          observed_balance_zkz: "1.5000",
          holding_operation_id: null,
          holding_operation_status: null,
          holding_operation_expiry_unix_time_secs: null,
          holding_operation_attention_required: false,
          holding_operation_terminal_at: null,
          holding_lease_role: null,
          holding_operation_type: null,
          money_mode: "FULL",
          allow_external_receive: true,
          allow_external_send: true,
          allow_internal_move: true,
          row_version: 1,
        }],
        has_more: false,
        next_cursor: null,
      }), { status: 200 })),
    );
    renderPage();
    expect(await screen.findByText("1.5000")).toBeInTheDocument();
    expect(screen.queryByText("No wallets")).not.toBeInTheDocument();
    expect(screen.getByTestId("money-mode-badge-full")).toHaveTextContent("Full");
  });

  it("soft-warns when the live fleet has zero send-capable wallets", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            object: "list",
            data: [
              {
                wallet_id: "w1",
                public_key: "zkz1qhub",
                state: "AVAILABLE",
                key_origin: "node_generated",
                recovery_verified: true,
                observed_balance_zkz: "2.0000",
                holding_operation_id: null,
                holding_operation_status: null,
                holding_operation_expiry_unix_time_secs: null,
                holding_operation_attention_required: false,
                holding_operation_terminal_at: null,
                holding_lease_role: null,
                holding_operation_type: null,
                money_mode: "INTERNAL_ONLY",
                allow_external_receive: false,
                allow_external_send: false,
                allow_internal_move: true,
                row_version: 2,
              },
            ],
            has_more: false,
            next_cursor: null,
          }),
          { status: 200 },
        ),
      ),
    );
    renderPage();
    expect(await screen.findByTestId("money-mode-badge-internal_only")).toBeInTheDocument();
    expect(screen.getByTestId("wallets-capability-fleet-warning")).toHaveTextContent(
      /No send-capable/,
    );
    expect(screen.getByTestId("wallets-capability-fleet-warning")).toHaveTextContent(
      /No receive-capable/,
    );
  });

  it("shows Continue recovery verification CTA when live inventory has zero verified wallets", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            object: "list",
            data: [
              {
                wallet_id: "w1",
                public_key: "zkz1qblockedwallet",
                state: "AVAILABLE",
                key_origin: "node_generated",
                recovery_verified: false,
                observed_balance_zkz: null,
                holding_operation_id: null,
                holding_operation_status: null,
                holding_operation_expiry_unix_time_secs: null,
                holding_operation_attention_required: false,
                holding_operation_terminal_at: null,
                holding_lease_role: null,
                holding_operation_type: null,
                money_mode: "FULL",
                allow_external_receive: true,
                allow_external_send: true,
                allow_internal_move: true,
                row_version: 1,
              },
            ],
            has_more: false,
            next_cursor: null,
          }),
          { status: 200 },
        ),
      ),
    );
    renderPage();
    const cta = await screen.findByTestId("wallets-recovery-cta");
    expect(cta).toHaveTextContent(/Wallets not recovery-verified/i);
    const link = screen.getByRole("link", { name: /Continue recovery verification/i });
    expect(link).toHaveAttribute("href", "/recovery-ceremony");
    expect(screen.queryByText(/use Backup to verify recovery/i)).not.toBeInTheDocument();
  });

  it("shows recovery CTA when inventory is live-empty (no eligible pool)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }), {
          status: 200,
        }),
      ),
    );
    renderPage();
    expect(await screen.findByTestId("wallets-recovery-cta")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Continue recovery verification/i })).toHaveAttribute(
      "href",
      "/recovery-ceremony",
    );
  });

});

  it("renders QUARANTINED with danger tag and cause; AVAILABLE is not busy (ZTR-1255)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            object: "list",
            data: [
              {
                wallet_id: "w-q",
                public_key: "zkz1qquarantinedwallet",
                state: "QUARANTINED",
                key_origin: "node_generated",
                recovery_verified: true,
                quarantine_reason: "REGRESSION",
                observed_balance_zkz: "0",
                holding_operation_id: null,
                holding_operation_status: null,
                holding_operation_expiry_unix_time_secs: null,
                holding_operation_attention_required: false,
                holding_operation_terminal_at: null,
                holding_lease_role: null,
                holding_operation_type: null,
                money_mode: "FULL",
                allow_external_receive: true,
                allow_external_send: true,
                allow_internal_move: true,
                row_version: 1,
              },
              {
                wallet_id: "w-a",
                public_key: "zkz1qavailablewalletxx",
                state: "AVAILABLE",
                key_origin: "node_generated",
                recovery_verified: true,
                quarantine_reason: null,
                observed_balance_zkz: "1",
                holding_operation_id: null,
                holding_operation_status: null,
                holding_operation_expiry_unix_time_secs: null,
                holding_operation_attention_required: false,
                holding_operation_terminal_at: null,
                holding_lease_role: null,
                holding_operation_type: null,
                money_mode: "FULL",
                allow_external_receive: true,
                allow_external_send: true,
                allow_internal_move: true,
                row_version: 1,
              },
              {
                wallet_id: "w-p",
                public_key: "zkz1qpinnedwalletxxxxx",
                state: "PINNED",
                key_origin: "node_generated",
                recovery_verified: true,
                quarantine_reason: null,
                observed_balance_zkz: "2",
                holding_operation_id: "4fc07a73-0000-4000-8000-000000000001",
                holding_operation_status: "AWAITING_REDEMPTION",
                holding_operation_expiry_unix_time_secs: "9999999999",
                holding_operation_attention_required: false,
                holding_operation_terminal_at: null,
                holding_lease_role: "RECEIVE_WINDOW",
                holding_operation_type: "RECEIVE_EXTERNAL",
                money_mode: "FULL",
                allow_external_receive: true,
                allow_external_send: true,
                allow_internal_move: true,
                row_version: 1,
              },
            ],
            has_more: false,
            next_cursor: null,
          }),
          { status: 200 },
        ),
      ),
    );
    renderPage();
    const qTag = await screen.findByTestId("status-tag-quarantined");
    expect(qTag).toHaveAttribute("data-severity", "danger");
    expect(screen.getByText(/QUARANTINED: REGRESSION/)).toBeInTheDocument();
    expect(screen.getByTestId("status-tag-available")).toHaveAttribute("data-severity", "ok");
    expect(screen.queryByText(/^busy$/i)).not.toBeInTheDocument();
    expect(screen.getByTestId("status-tag-pinned")).toHaveAttribute("data-severity", "warn");
    const holdLinks = screen.getAllByTestId("wallet-hold-op-link");
    expect(holdLinks.length).toBeGreaterThan(0);
    expect(holdLinks[0]).toHaveAttribute("href", "/operations/4fc07a73-0000-4000-8000-000000000001");
  });
