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
      { path: "/connect", element: <IntegrationStateProbe /> },
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
  });


  test("live session lists keys without the raw secret and can revoke", async () => {
    vi.spyOn(money, "listImplementers").mockResolvedValue({
      live: true,
      implementers: [
        {
          id: "11111111-1111-4111-8111-111111111111",
          name: "genesis",
          created_at: "2026-01-01T00:00:00Z",
          retired_at: null,
        },
      ],
    });
    const listSpy = vi
      .spyOn(money, "listApiKeys")
      .mockResolvedValue({
        keys: [
          {
            id: "k1",
            implementer_id: "11111111-1111-4111-8111-111111111111",
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
    expect(screen.getByText("Active")).toBeInTheDocument();
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
    vi.spyOn(money, "listImplementers").mockResolvedValue({
      live: true,
      implementers: [],
    });
    vi.spyOn(money, "listApiKeys").mockResolvedValue({ keys: [], live: true });
    const issueSpy = vi
      .spyOn(money, "postIssueApiKey")
      .mockResolvedValue({
        id: "k2",
        implementer_id: "11111111-1111-4111-8111-111111111111",
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

  test("integration picker scopes issue to the selected implementer", async () => {
    const secondId = "22222222-2222-4222-8222-222222222222";
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
          id: secondId,
          name: "payroll-run",
          created_at: "2026-02-01T00:00:00Z",
          retired_at: null,
        },
      ],
    });
    vi.spyOn(money, "listApiKeys").mockResolvedValue({ keys: [], live: true });
    const issueSpy = vi.spyOn(money, "postIssueApiKey").mockResolvedValue({
      id: "k3",
      implementer_id: secondId,
      raw_key: "ik_secondkeyvaluexxxxxxxx",
      prefix: "ik_secondke",
      scopes: ["receive:create"],
      key_version: 1,
      issued_at: "2026-07-30T00:00:00Z",
      expires_at: null,
    });

    renderPage();
    const select = await screen.findByLabelText("Integration");
    fireEvent.change(select, { target: { value: secondId } });
    // Query key changes with the picker — wait for the list to settle so Issue reappears.
    const issueBtn = await screen.findByRole("button", { name: "Issue key" });
    fireEvent.click(issueBtn);
    const input = await screen.findByLabelText("Verification code");
    fireEvent.change(input, { target: { value: "3" } });
    for (let i = 1; i < 6; i += 1) {
      const slot = screen.getByLabelText(`Digit ${i + 1}`);
      fireEvent.change(slot, { target: { value: "3" } });
    }
    await waitFor(() =>
      expect(issueSpy).toHaveBeenCalledWith({ implementerId: secondId }, "333333"),
    );
  });
});