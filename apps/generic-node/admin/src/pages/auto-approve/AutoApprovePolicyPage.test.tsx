/** @vitest-environment jsdom */
// AutoApprovePolicyPage — rules table, fail-closed banner, TOTP save round-trip.

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import * as money from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { TotpPromptProvider } from "../../totp/index.js";
import { AutoApprovePolicyPage } from "./AutoApprovePolicyPage.js";

const IMP_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <TotpPromptProvider>
        <MemoryRouter>
          <AutoApprovePolicyPage />
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

describe("AutoApprovePolicyPage", () => {
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
    vi.spyOn(money, "listImplementers").mockResolvedValue({
      live: true,
      implementers: [
        {
          id: IMP_A,
          name: "rewards-bot",
          created_at: "2026-01-01T00:00:00Z",
          retired_at: null,
        },
      ],
    });
  });

  test("renders rules with spend and integration name", async () => {
    vi.spyOn(money, "fetchAutoApprovePolicy").mockResolvedValue({
      status: "enabled",
      rules: [
        {
          rule_id: "r1",
          implementer_id: IMP_A,
          per_send_max_zkz: "10",
          per_send_min_zkz: null,
          window_hours: 24,
          window_cap_zkz: "100",
          expires_at: null,
          enabled: true,
          current_window_spend_zkz: "37.2",
        },
      ],
      server_time: "2026-08-12T00:00:00.000Z",
    });
    renderPage();
    expect(await screen.findByText("rewards-bot")).toBeInTheDocument();
    expect(screen.getByTestId("spend-r1")).toHaveTextContent("37.2 of 100");
    expect(screen.queryByTestId("auto-approve-fail-closed")).not.toBeInTheDocument();
  });

  test("shows fail-closed banner when policy is invalid", async () => {
    vi.spyOn(money, "fetchAutoApprovePolicy").mockResolvedValue({
      status: "disabled",
      disabledReason: "invalid",
      rules: [],
      server_time: "2026-08-12T00:00:00.000Z",
    });
    renderPage();
    const banner = await screen.findByTestId("auto-approve-fail-closed");
    expect(banner).toHaveTextContent(/stored policy invalid/i);
  });

  test("save round-trip prompts TOTP and posts document", async () => {
    vi.spyOn(money, "fetchAutoApprovePolicy").mockResolvedValue({
      status: "disabled",
      disabledReason: "absent",
      rules: [],
      server_time: "2026-08-12T00:00:00.000Z",
    });
    const postSpy = vi.spyOn(money, "postAutoApprovePolicy").mockResolvedValue({
      status: "enabled",
      rules: [
        {
          rule_id: "r-new",
          implementer_id: IMP_A,
          per_send_max_zkz: "5",
          per_send_min_zkz: null,
          window_hours: 24,
          window_cap_zkz: "50",
          expires_at: null,
          enabled: true,
          current_window_spend_zkz: "0",
        },
      ],
      server_time: "2026-08-12T00:01:00.000Z",
    });
    renderPage();
    await screen.findByTestId("auto-approve-editor");

    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));
    fireEvent.change(screen.getByLabelText("Rule 1 id"), { target: { value: "r-new" } });
    fireEvent.change(screen.getByLabelText("Rule 1 integration"), {
      target: { value: IMP_A },
    });
    fireEvent.change(screen.getByLabelText("Rule 1 per-send max"), { target: { value: "5" } });
    fireEvent.change(screen.getByLabelText("Rule 1 window cap"), { target: { value: "50" } });
    fireEvent.click(screen.getByTestId("auto-approve-enabled"));
    fireEvent.click(screen.getByTestId("auto-approve-save"));
    await enterTotp("123456");

    await waitFor(() => expect(postSpy).toHaveBeenCalled());
    const [body, totp] = postSpy.mock.calls[0]!;
    expect(totp).toBe("123456");
    expect(body.enabled).toBe(true);
    expect(body.rules[0]?.rule_id).toBe("r-new");
    expect(body.rules[0]?.implementer_id).toBe(IMP_A);
    expect(await screen.findByTestId("auto-approve-save-ok")).toHaveTextContent("Policy saved");
  });
});
