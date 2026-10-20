/** @vitest-environment jsdom */
// Unified ConnectorsPage tests (GN-403 / ZTR-1341).

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import * as apiModule from "../../lib/api.js";
import * as money from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { TotpPromptProvider } from "../../totp/index.js";
import {
  ConnectorsPage,
  computeCapProgressPercent,
  type ConnectorView,
} from "./ConnectorsPage.js";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <TotpPromptProvider>
        <MemoryRouter>
          <ConnectorsPage />
        </MemoryRouter>
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

async function enterTotp(digits: string) {
  const input = await screen.findByLabelText("Verification code");
  fireEvent.change(input, { target: { value: digits[0]! } });
  for (let i = 1; i < 6; i += 1) {
    const slot = screen.getByLabelText(`Digit ${i + 1}`);
    fireEvent.change(slot, { target: { value: digits[i]! } });
  }
}

afterEach(cleanup);

describe("ConnectorsPage (GN-403)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuth.getState().setUser({
      userId: "u1",
      username: "admin",
      role: "admin",
      mustEnrolTotp: false,
      mustChangePassword: false,
      csrfToken: "csrf-1",
    });

    vi.spyOn(money, "listWalletsInventory").mockResolvedValue({
      data: [
        {
          wallet_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          node_id: "n1",
          public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          key_origin: "node_generated",
          state: "AVAILABLE",
          created_at: "2026-01-01T00:00:00Z",
          retired_at: null,
          quarantine_reason: null,
          recovery_verified: true,
          recovery_verified_at: "2026-01-01T00:00:00Z",
          recovery_verification: null,
          observed_balance_zkz: "1500.0000",
          holding_operation_id: null,
          holding_operation_status: null,
          holding_operation_expiry_unix_time_secs: null,
          holding_operation_attention_required: false,
          holding_operation_terminal_at: null,
          holding_lease_role: null,
          holding_operation_type: null,
          money_mode: "INTERNAL_ONLY",
          display_label: "Main Reserve",
          allow_external_receive: false,
          allow_external_send: false,
          allow_internal_move: true,
          row_version: 1,
        } as unknown as money.WalletInventoryItem,
      ],
      live: true,
    });
  });

  test("computeCapProgressPercent computes exact integer percentages and clamps at 100%", () => {
    expect(computeCapProgressPercent("250.00000000", "1000.00000000")).toBe(25);
    expect(computeCapProgressPercent("1200", "1000")).toBe(100);
    expect(computeCapProgressPercent("0", "500")).toBe(0);
    expect(computeCapProgressPercent("10", null)).toBe(0);
  });

  test("renders connected platforms, linked reserves, and Spend Rule progress bars (Lifetime & Rolling Window)", async () => {
    const sampleConnector: ConnectorView = {
      implementer_id: "11111111-1111-4111-8111-111111111111",
      display_name: "Promotional Campaign Engine",
      policy_mode: "NODE_VERIFIED",
      scopes: ["receives:write", "sends:write", "wallets:read_linked"],
      linked_reserves: [
        {
          wallet_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          display_name: "Main Reserve",
          is_default: true,
          allow_custom_routing: true,
        },
      ],
      api_keys: [
        {
          key_id: "22222222-2222-4222-8222-222222222222",
          key_prefix: "ik_live_abc",
          created_at: "2026-06-01T00:00:00Z",
          last_used_at: null,
        },
      ],
      spend_rules: [
        {
          rule_id: "spring-promo",
          implementer_id: "11111111-1111-4111-8111-111111111111",
          label: "Spring Promo Cap",
          reserve_wallet_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          total_cap_zkz: "1000",
          per_send_max_zkz: "50",
          per_send_min_zkz: "1",
          window_hours: 24,
          window_cap_zkz: "200",
          expires_at: null,
          enabled: true,
          current_window_spend_zkz: "50",
          cumulative_total_spend_zkz: "400",
        },
      ],
      webhook_url: "https://example.com/hooks/events",
      webhook_enabled: true,
    };

    vi.spyOn(apiModule, "apiSoftRead").mockImplementation(async (path: string) => {
      if (path.startsWith("/connectors")) {
        return { data: { connectors: [sampleConnector] }, live: true };
      }
      return { data: { requests: [], data: [] }, live: true };
    });

    renderPage();

    expect(await screen.findByText("Promotional Campaign Engine")).toBeInTheDocument();
    expect(screen.getByTestId("connector-detail-view")).toBeInTheDocument();
    expect(screen.getByTestId("linked-reserve-pill-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")).toHaveTextContent(
      "Main Reserve (Default)",
    );
    expect(screen.getByTestId("window-spend-text-spring-promo")).toHaveTextContent(
      "50 / 200 ZKZ (25%)",
    );
    expect(screen.getByTestId("lifetime-spend-text-spring-promo")).toHaveTextContent(
      "400 / 1000 ZKZ (40%)",
    );
    expect(
      screen.getByRole("progressbar", { name: "Rolling Window Cap for spring-promo" }),
    ).toHaveAttribute("aria-valuenow", "25");
    expect(
      screen.getByRole("progressbar", { name: "Lifetime Cap for spring-promo" }),
    ).toHaveAttribute("aria-valuenow", "40");
  });

  test("renders pending pairing requests and spend rule requests and supports 1-tap TOTP approval", async () => {
    vi.spyOn(money, "listIntegrationRequests").mockResolvedValue({
      live: true,
      data: [
        {
          id: "33333333-3333-4333-8333-333333333333",
          display_name: "Partner Platform",
          requested_scopes: ["receives:write", "sends:write"],
          proposed_rule_json: JSON.stringify({
            rule_id: "partner-rule",
            per_send_max_zkz: "25",
            window_hours: 24,
            window_cap_zkz: "100",
            enabled: true,
          }),
          approved_rule_json: null,
          status: "PENDING",
          row_version: 1,
          created_at: "2026-06-01T00:00:00Z",
          expires_at: "2026-06-02T00:00:00Z",
          decided_at: null,
          decided_by: null,
          implementer_id: null,
        },
      ],
    });

    vi.spyOn(apiModule, "apiSoftRead").mockImplementation(async (path: string) => {
      if (path.startsWith("/connector-rules/requests")) {
        return {
          data: {
            requests: [
              {
                request_id: "44444444-4444-4444-8444-444444444444",
                implementer_id: "11111111-1111-4111-8111-111111111111",
                rule_id: "bonus-campaign",
                label: "Bonus Campaign",
                reserve_wallet_id: null,
                total_cap_zkz: "500",
                per_send_max_zkz: "20",
                per_send_min_zkz: null,
                window_hours: 24,
                window_cap_zkz: "100",
                expires_at: null,
                status: "PENDING",
                webhook_enabled: true,
                created_at: "2026-06-01T00:00:00Z",
                decided_at: null,
                decided_by: null,
              },
            ],
          },
          live: true,
        };
      }
      return { data: { connectors: [] }, live: true };
    });

    const apiSpy = vi.spyOn(apiModule, "api").mockResolvedValue({ ok: true });

    renderPage();

    expect(await screen.findByTestId("pending-connector-requests-banner")).toBeInTheDocument();
    expect(screen.getByText("Partner Platform")).toBeInTheDocument();
    expect(screen.getByText("Bonus Campaign")).toBeInTheDocument();

    fireEvent.click(
      screen.getByTestId("approve-rule-req-44444444-4444-4444-8444-444444444444"),
    );
    await enterTotp("123456");

    await waitFor(() =>
      expect(apiSpy).toHaveBeenCalledWith(
        "/connector-rules/requests/44444444-4444-4444-8444-444444444444/approve",
        expect.objectContaining({
          method: "POST",
          totp: "123456",
        }),
      ),
    );
  });

  test("creates a new connector via + New Connector modal and displays the one-time API key", async () => {
    vi.spyOn(apiModule, "apiSoftRead").mockResolvedValue({
      data: { connectors: [], requests: [], data: [] },
      live: true,
    });

    const apiSpy = vi.spyOn(apiModule, "api").mockResolvedValue({
      implementer_id: "55555555-5555-4555-8555-555555555555",
      display_name: "Automated Desk",
      policy_mode: "NODE_VERIFIED",
      scopes: ["receives:write", "sends:write", "wallets:read_linked"],
      linked_reserves: [],
      api_keys: [],
      spend_rules: [],
      webhook_url: null,
      webhook_enabled: false,
      api_key: "ik_live_secret_token_once",
    });

    renderPage();

    fireEvent.click(await screen.findByTestId("open-new-connector-modal"));
    expect(await screen.findByTestId("new-connector-modal")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Connector display name"), {
      target: { value: "Automated Desk" },
    });
    fireEvent.click(screen.getByTestId("submit-create-connector"));
    await enterTotp("654321");

    await waitFor(() =>
      expect(apiSpy).toHaveBeenCalledWith(
        "/connectors",
        expect.objectContaining({
          method: "POST",
          totp: "654321",
        }),
      ),
    );

    expect(await screen.findByTestId("minted-raw-key")).toHaveTextContent(
      "ik_live_secret_token_once",
    );
  });
});
