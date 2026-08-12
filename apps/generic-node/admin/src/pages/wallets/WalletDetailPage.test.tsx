import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useAuth } from "../../store/auth.js";
import { WalletDetailPage } from "./WalletDetailPage.js";

function renderDetail(pubkey: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/wallets/${encodeURIComponent(pubkey)}`]}>
        <Routes>
          <Route path="/wallets/:pubkey" element={<WalletDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
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

  it("renders a wallet outside list page one without requesting the list", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          wallet_id: "wallet-page-two",
          public_key: "pubkey-page-two",
          state: "AVAILABLE",
          key_origin: "node_generated",
          recovery_verified: true,
          observed_balance_zkz: "8.25",
          holding_operation_id: null,
          holding_operation_status: null,
          holding_operation_expiry_unix_time_secs: null,
          holding_operation_attention_required: false,
          holding_operation_terminal_at: null,
        }),
        { status: 200 },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    renderDetail("pubkey-page-two");

    expect(await screen.findByText("8.25 ZKZ")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/v1/wallets/pubkey-page-two",
      expect.anything(),
    );
  });
});
