/** @vitest-environment jsdom */
// IntegrationsPage — create/list/retire + funding wallet pin (ZTR-1287).

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import * as money from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { TotpPromptProvider } from "../../totp/index.js";
import { IntegrationsPage } from "./IntegrationsPage.js";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <TotpPromptProvider>
        <MemoryRouter>
          <IntegrationsPage />
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

describe("IntegrationsPage", () => {
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
    vi.spyOn(money, "fetchDefaultFundingWallet").mockResolvedValue({
      wallet_id: null,
      public_key: null,
      row_version: 0,
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
          recovery_verified: false,
          recovery_verified_at: null,
          recovery_verification: null,
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
        } as money.WalletInventoryItem,
      ],
      live: true,
    });
  });

  test("lists active and retired integrations with funding column", async () => {
    vi.spyOn(money, "listImplementers").mockResolvedValue({
      live: true,
      implementers: [
        {
          id: "11111111-1111-4111-8111-111111111111",
          name: "genesis",
          created_at: "2026-01-01T00:00:00Z",
          retired_at: null,
          funding_wallet_id: null,
          funding_wallet_public_key: null,
        },
        {
          id: "22222222-2222-4222-8222-222222222222",
          name: "payroll-run",
          created_at: "2026-02-01T00:00:00Z",
          retired_at: "2026-03-01T00:00:00Z",
          funding_wallet_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          funding_wallet_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        },
      ],
    });
    renderPage();
    expect(await screen.findByText("genesis")).toBeInTheDocument();
    expect(screen.getByText("payroll-run")).toBeInTheDocument();
    expect(screen.getByText("ACTIVE")).toBeInTheDocument();
    expect(screen.getByText("RETIRED")).toBeInTheDocument();
    expect(screen.getByText("Node default")).toBeInTheDocument();
    expect(screen.getByTestId("funding-copy")).toHaveTextContent("not the worker wallet");
  });

  test("create requires TOTP and shows success", async () => {
    vi.spyOn(money, "listImplementers").mockResolvedValue({
      live: true,
      implementers: [],
    });
    const createSpy = vi.spyOn(money, "postCreateImplementer").mockResolvedValue({
      id: "33333333-3333-4333-8333-333333333333",
      name: "zukaz",
      created_at: "2026-04-01T00:00:00Z",
      retired_at: null,
      funding_wallet_id: null,
      funding_wallet_public_key: null,
    });
    renderPage();
    fireEvent.change(await screen.findByLabelText("Integration name"), {
      target: { value: "zukaz" },
    });
    const createBtn = await screen.findByRole("button", { name: "Create" });
    await waitFor(() => expect(createBtn).not.toBeDisabled());
    fireEvent.click(createBtn);
    await enterTotp("123456");
    await waitFor(() => expect(createSpy).toHaveBeenCalledWith("zukaz", "123456"));
    expect(await screen.findByTestId("implementer-created")).toHaveTextContent("zukaz");
  });

  test("retire confirms with TOTP", async () => {
    vi.spyOn(money, "listImplementers").mockResolvedValue({
      live: true,
      implementers: [
        {
          id: "11111111-1111-4111-8111-111111111111",
          name: "active-one",
          created_at: "2026-01-01T00:00:00Z",
          retired_at: null,
          funding_wallet_id: null,
          funding_wallet_public_key: null,
        },
      ],
    });
    const retireSpy = vi.spyOn(money, "postRetireImplementer").mockResolvedValue({
      id: "11111111-1111-4111-8111-111111111111",
      name: "active-one",
      created_at: "2026-01-01T00:00:00Z",
      retired_at: "2026-05-01T00:00:00Z",
      funding_wallet_id: null,
      funding_wallet_public_key: null,
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Retire" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm retire" }));
    await enterTotp("654321");
    await waitFor(() =>
      expect(retireSpy).toHaveBeenCalledWith(
        "11111111-1111-4111-8111-111111111111",
        "654321",
      ),
    );
  });

  test("set funding wallet DEFAULT with TOTP", async () => {
    vi.spyOn(money, "listImplementers").mockResolvedValue({
      live: true,
      implementers: [
        {
          id: "11111111-1111-4111-8111-111111111111",
          name: "active-one",
          created_at: "2026-01-01T00:00:00Z",
          retired_at: null,
          funding_wallet_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          funding_wallet_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        },
      ],
    });
    const setSpy = vi.spyOn(money, "postSetImplementerFundingWallet").mockResolvedValue({
      id: "11111111-1111-4111-8111-111111111111",
      name: "active-one",
      created_at: "2026-01-01T00:00:00Z",
      retired_at: null,
      funding_wallet_id: null,
      funding_wallet_public_key: null,
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Set funding" }));
    expect(await screen.findByTestId("funding-dialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save funding wallet" }));
    await enterTotp("111111");
    await waitFor(() =>
      expect(setSpy).toHaveBeenCalledWith(
        "11111111-1111-4111-8111-111111111111",
        expect.objectContaining({ mode: expect.any(String) }),
        "111111",
      ),
    );
  });
});
