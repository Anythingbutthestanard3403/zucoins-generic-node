/** @vitest-environment jsdom */
// IntegrationsPage — create/list/retire named integration identities.

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
  });

  test("lists active and retired integrations", async () => {
    vi.spyOn(money, "listImplementers").mockResolvedValue({
      live: true,
      implementers: [
        {
          id: "11111111-1111-4111-8111-111111111111",
          name: "genesis",
          created_at: "2026-01-01T00:00:00Z",
          retired_at: null,
        },
        {
          id: "22222222-2222-4222-8222-222222222222",
          name: "payroll-run",
          created_at: "2026-02-01T00:00:00Z",
          retired_at: "2026-03-01T00:00:00Z",
        },
      ],
    });
    renderPage();
    expect(await screen.findByText("genesis")).toBeInTheDocument();
    expect(screen.getByText("payroll-run")).toBeInTheDocument();
    expect(screen.getByText("ACTIVE")).toBeInTheDocument();
    expect(screen.getByText("RETIRED")).toBeInTheDocument();
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
        },
      ],
    });
    const retireSpy = vi.spyOn(money, "postRetireImplementer").mockResolvedValue({
      id: "11111111-1111-4111-8111-111111111111",
      name: "active-one",
      created_at: "2026-01-01T00:00:00Z",
      retired_at: "2026-05-01T00:00:00Z",
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
});
