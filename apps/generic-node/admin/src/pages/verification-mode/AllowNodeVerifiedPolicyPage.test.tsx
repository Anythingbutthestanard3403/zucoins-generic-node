/** @vitest-environment jsdom */
// AllowNodeVerifiedPolicyPage — fail-closed banner, TOTP save round-trip (ZTR-1305).

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import * as money from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { TotpPromptProvider } from "../../totp/index.js";
import { AllowNodeVerifiedPolicyPage } from "./AllowNodeVerifiedPolicyPage.js";

const IMP_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <TotpPromptProvider>
        <MemoryRouter>
          <AllowNodeVerifiedPolicyPage />
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

describe("AllowNodeVerifiedPolicyPage", () => {
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
          name: "Lab A",
          retired_at: null,
          created_at: "2026-08-01T00:00:00.000Z",
        },
      ],
    } as never);
  });

  test("shows fail-closed banner when policy absent", async () => {
    vi.spyOn(money, "fetchAllowNodeVerifiedPolicy").mockResolvedValue({
      status: "disabled",
      disabledReason: "absent",
      implementers: [],
      server_time: "2026-08-14T00:00:00.000Z",
    });
    renderPage();
    const banner = await screen.findByTestId("allow-node-verified-fail-closed");
    expect(banner).toHaveTextContent(/OFF/);
  });

  test("TOTP-gated save posts whole document", async () => {
    vi.spyOn(money, "fetchAllowNodeVerifiedPolicy").mockResolvedValue({
      status: "disabled",
      disabledReason: "off",
      implementers: [{ implementer_id: IMP_A, enabled: true }],
      server_time: "2026-08-14T00:00:00.000Z",
    });
    const post = vi.spyOn(money, "postAllowNodeVerifiedPolicy").mockResolvedValue({
      status: "enabled",
      implementers: [{ implementer_id: IMP_A, enabled: true }],
      server_time: "2026-08-14T00:01:00.000Z",
    });

    renderPage();
    await screen.findByTestId("allow-node-verified-editor");
    fireEvent.click(screen.getByTestId("allow-node-verified-enabled"));
    fireEvent.click(screen.getByTestId("allow-node-verified-save"));
    await enterTotp("123456");

    await waitFor(() => expect(post).toHaveBeenCalled());
    expect(post.mock.calls[0]![0]).toEqual({
      enabled: true,
      implementers: [{ implementer_id: IMP_A, enabled: true }],
    });
    expect(await screen.findByTestId("allow-node-verified-save-ok")).toHaveTextContent(
      "Policy saved",
    );
  });
});
