/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../../lib/api.js";
import * as money from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { TotpPromptProvider } from "../../totp/index.js";
import { WalletDetailPage } from "./WalletDetailPage.js";

const WALLET = {
  wallet_id: "wallet-page-two",
  node_id: "n1",
  public_key: "pubkey-page-two",
  state: "AVAILABLE",
  key_origin: "node_generated",
  created_at: "2026-07-30T00:00:00.000Z",
  retired_at: null,
  quarantine_reason: null,
  recovery_verified: true,
  recovery_verified_at: "2026-07-30T00:00:00.000Z",
  recovery_verification: null,
  observed_balance_zkz: "8.25",
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
} as const;

function renderDetail(pubkey: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TotpPromptProvider>
        <MemoryRouter initialEntries={[`/wallets/${encodeURIComponent(pubkey)}`]}>
          <Routes>
            <Route path="/wallets/:pubkey" element={<WalletDetailPage />} />
          </Routes>
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

describe("WalletDetailPage point-read", () => {
  beforeEach(() => {
    useAuth.setState({
      user: {
        userId: "u1",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "csrf",
      },
    });
    vi.restoreAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders a wallet outside list page one without requesting the list", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/wallets?") || url.endsWith("/wallets")) {
        return new Response(
          JSON.stringify({ object: "list", data: [WALLET], has_more: false, next_cursor: null }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify(WALLET), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderDetail("pubkey-page-two");

    expect(await screen.findByText("8.25 ZKZ")).toBeInTheDocument();
    expect(await screen.findByTestId("wallet-money-mode-current")).toHaveTextContent(/Full/i);
    expect(screen.getByTestId("wallet-money-mode-select")).toBeInTheDocument();
    expect(screen.getByTestId("wallet-money-mode-help-all")).toHaveTextContent(/Internal only/i);
  });

  it("saves a new money mode through TOTP-gated PATCH", async () => {
    vi.spyOn(money, "getWalletInventory").mockResolvedValue({ ...WALLET });
    vi.spyOn(money, "listWalletsInventory").mockResolvedValue({
      live: true,
      data: [{ ...WALLET }],
    });
    const patch = vi.spyOn(money, "patchWalletMoneyCapability").mockResolvedValue({
      wallet_id: WALLET.wallet_id,
      money_mode: "INTERNAL_ONLY",
      allow_external_receive: false,
      allow_external_send: false,
      allow_internal_move: true,
      row_version: 2,
      previous_mode: "FULL",
      previous_flags: {
        allow_external_receive: true,
        allow_external_send: true,
        allow_internal_move: true,
      },
      warnings: { zero_send_capable: true, zero_receive_capable: true },
    });

    renderDetail(WALLET.public_key);
    expect(await screen.findByTestId("wallet-money-mode-select")).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("wallet-money-mode-select"), {
      target: { value: "INTERNAL_ONLY" },
    });
    expect(screen.getByTestId("wallet-money-mode-confirm-hint")).toHaveTextContent(
      /internal-only/i,
    );

    fireEvent.click(screen.getByTestId("wallet-money-mode-save"));
    await enterTotp("123456");

    await waitFor(() => expect(patch).toHaveBeenCalled());
    expect(patch).toHaveBeenCalledWith(
      WALLET.wallet_id,
      { mode: "INTERNAL_ONLY", expected_row_version: 1 },
      "123456",
    );
    expect(await screen.findByTestId("wallet-money-mode-msg")).toHaveTextContent(/Internal only/i);
    expect(screen.getByTestId("wallet-money-mode-fleet-warning")).toHaveTextContent(
      /No send-capable/,
    );
  });

  it("surfaces CAS conflict errors", async () => {
    vi.spyOn(money, "getWalletInventory").mockResolvedValue({ ...WALLET });
    vi.spyOn(money, "listWalletsInventory").mockResolvedValue({ live: true, data: [{ ...WALLET }] });
    vi.spyOn(money, "patchWalletMoneyCapability").mockRejectedValue(
      new ApiError(409, {
        error: { code: "conflict", message: "row_version mismatch" },
      }),
    );

    renderDetail(WALLET.public_key);
    await screen.findByTestId("wallet-money-mode-select");
    fireEvent.change(screen.getByTestId("wallet-money-mode-select"), {
      target: { value: "SEND_ONLY" },
    });
    fireEvent.click(screen.getByTestId("wallet-money-mode-save"));
    await enterTotp("654321");

    expect(await screen.findByTestId("wallet-money-mode-error")).toHaveTextContent(
      /row_version mismatch/,
    );
  });
});
