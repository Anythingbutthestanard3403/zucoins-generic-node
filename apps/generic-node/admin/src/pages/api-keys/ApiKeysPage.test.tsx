/** @vitest-environment jsdom */
// ApiKeysPage — live issue/list/revoke; one-time secret copy; demo honest empty.

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider, useLocation } from "react-router";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import * as money from "../../lib/money.js";
import { IntegrationPage } from "../integration/IntegrationPage.js";
import { useAuth } from "../../store/auth.js";
import { TotpPromptProvider } from "../../totp/index.js";
import { ApiKeysPage } from "./ApiKeysPage.js";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const observedLocationStates: unknown[] = [];
  const router = createMemoryRouter(
    [
      { path: "/api-keys", element: <ApiKeysPage /> },
      { path: "/integration", element: <IntegrationStateProbe /> },
    ],
    { initialEntries: ["/api-keys"] },
  );
  router.subscribe((state) => observedLocationStates.push(state.location.state));
  const rendered = render(
    <QueryClientProvider client={queryClient}>
      <TotpPromptProvider>
        <RouterProvider router={router} />
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
  return { ...rendered, observedLocationStates };
}

function IntegrationStateProbe() {
  const location = useLocation();
  return (
    <>
      <div data-testid="integration-state">{location.state === null ? "empty" : "present"}</div>
      <IntegrationPage />
    </>
  );
}

afterEach(cleanup);

describe("ApiKeysPage", () => {
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
    useAuth.getState().setDemoMode(false);
  });

  test("demo session shows the honest empty message and does not call the live API", async () => {
    useAuth.getState().setDemoMode(true);
    const listSpy = vi.spyOn(money, "listApiKeys");
    renderPage();
    expect(screen.getByText(/log in for a live session/i)).toBeInTheDocument();
    expect(screen.getByText("No API keys listed")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Issue key" })).not.toBeInTheDocument();
    await waitFor(() => expect(listSpy).not.toHaveBeenCalled());
  });

  test("live session lists keys without the raw secret and can revoke", async () => {
    const listSpy = vi
      .spyOn(money, "listApiKeys")
      .mockResolvedValue({
        keys: [
          {
            id: "k1",
            prefix: "ik_abcdef12",
            scopes: ["receive:create", "receive:read"],
            status: "ACTIVE",
            key_version: 1,
            issued_at: "2026-07-30T00:00:00Z",
            expires_at: null,
            revoked_at: null,
            last_used_at: null,
          },
        ],
        live: true,
      });
    const revokeSpy = vi
      .spyOn(money, "postRevokeApiKey")
      .mockResolvedValue({ id: "k1", revoked: true });

    renderPage();
    expect(await screen.findByText("ik_abcdef12…")).toBeInTheDocument();
    expect(screen.getByText("receive:create, receive:read")).toBeInTheDocument();
    expect(screen.getByText("ACTIVE")).toBeInTheDocument();
    // The raw key never appears in the list response shape.
    expect(listSpy).toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));

    // TOTP step-up prompt opens; enter a code to authorize the revoke.
    const input = await screen.findByLabelText("Verification code");
    fireEvent.change(input, { target: { value: "1" } });
    for (let i = 1; i < 6; i += 1) {
      const slot = screen.getByLabelText(`Digit ${i + 1}`);
      fireEvent.change(slot, { target: { value: String(i + 1) } });
    }
    await waitFor(() => expect(revokeSpy).toHaveBeenCalledWith("k1", "123456"));
  });

  test("issue returns the raw key once and renders the copy banner", async () => {
    vi.spyOn(money, "listApiKeys").mockResolvedValue({ keys: [], live: true });
    const issueSpy = vi
      .spyOn(money, "postIssueApiKey")
      .mockResolvedValue({
        id: "k2",
        raw_key: "ik_s3cr3tvaluethatmustnotleak",
        prefix: "ik_s3cr3tva",
        scopes: ["receive:create"],
        key_version: 1,
        issued_at: "2026-07-30T00:00:00Z",
        expires_at: null,
      });

    const { observedLocationStates } = renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Issue key" }));

    const input = await screen.findByLabelText("Verification code");
    fireEvent.change(input, { target: { value: "2" } });
    for (let i = 1; i < 6; i += 1) {
      const slot = screen.getByLabelText(`Digit ${i + 1}`);
      fireEvent.change(slot, { target: { value: "2" } });
    }
    await waitFor(() => expect(issueSpy).toHaveBeenCalledWith(undefined, "222222"));
    expect(await screen.findByTestId("api-key-once")).toBeInTheDocument();
    expect(screen.getByTestId("api-key-raw")).toHaveTextContent(
      "ik_s3cr3tvaluethatmustnotleak",
    );
    fireEvent.click(screen.getByRole("button", { name: "Build Connect kit" }));
    expect(screen.getByTestId("integration-state")).toHaveTextContent("empty");
    expect(screen.getByTestId("integration-kit")).toHaveTextContent(
      "ik_s3cr3tvaluethatmustnotleak",
    );
    expect(observedLocationStates).not.toContainEqual({
      issuedKey: "ik_s3cr3tvaluethatmustnotleak",
    });
  });
});