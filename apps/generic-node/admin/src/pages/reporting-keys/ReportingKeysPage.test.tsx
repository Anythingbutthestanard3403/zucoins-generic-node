/** @vitest-environment jsdom */
// ReportingKeysPage — live issue/list; one-time raw seed reveal; demo honest empty.
// The raw seed is shown exactly once (from POST onSuccess state, never a query key); "Done"
// clears it; the list response type has no private field, so a refetch can never re-show it.

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import * as money from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { TotpPromptProvider } from "../../totp/index.js";
import { ReportingKeysPage } from "./ReportingKeysPage.js";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <TotpPromptProvider>
        <MemoryRouter>
          <ReportingKeysPage />
        </MemoryRouter>
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

afterEach(cleanup);

describe("ReportingKeysPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn(async () => undefined) },
    });
    useAuth.getState().setUser({
      userId: "u1",
      username: "admin",
      role: "admin",
      mustEnrolTotp: false,
      mustChangePassword: false,
      csrfToken: "csrf-1",
    });
  });


  test("issue returns the raw seed once, Done clears it, and a list refetch never re-shows it", async () => {
    const RAW = "51".repeat(32);
    // The server has no credential until issue succeeds; then the list returns it public-only.
    const listKeys: money.ReportingKeyListing[] = [];
    vi.spyOn(money, "listReportingKeys").mockImplementation(async () => ({
      keys: [...listKeys],
      live: true,
    }));
    const issueSpy = vi.spyOn(money, "postIssueReportingKey").mockImplementation(async () => {
      listKeys.push({
        id: "rk1",
        node_id: "n1",
        implementer_id: "i1",
        public_key: "PUBKEYb64url",
        registered_at: "2026-07-30T00:00:00Z",
        status: "ACTIVE",
      });
      return {
        id: "rk1",
        key_id: "rk1",
        raw_private_key: RAW,
        public_key: "PUBKEYb64url",
        registered_at: "2026-07-30T00:00:00Z",
      };
    });

    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Issue reporting credential" }));

    const input = await screen.findByLabelText("Verification code");
    fireEvent.change(input, { target: { value: "2" } });
    for (let i = 1; i < 6; i += 1) {
      const slot = screen.getByLabelText(`Digit ${i + 1}`);
      fireEvent.change(slot, { target: { value: "2" } });
    }
    await waitFor(() => expect(issueSpy).toHaveBeenCalledWith("222222"));

    // Raw seed revealed exactly once — only inside the reveal card, never a list row.
    expect(await screen.findByTestId("reporting-key-once")).toBeInTheDocument();
    expect(screen.getByTestId("reporting-key-raw")).toHaveTextContent(RAW);
    expect(screen.getAllByText(RAW)).toHaveLength(1);

    // The invalidated list refetches and now lists the credential public-only.
    expect(await screen.findByText("PUBKEYb64url")).toBeInTheDocument();

    // Copy (or download) required before Done — prevents dismiss-without-save.
    fireEvent.click(screen.getByRole("button", { name: /Copy reporting seed/i }));
    await waitFor(() => expect(screen.getByRole("button", { name: /Seed copied/i })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() =>
      expect(screen.queryByTestId("reporting-key-once")).not.toBeInTheDocument(),
    );
    expect(screen.queryByText(RAW)).not.toBeInTheDocument();
    expect(screen.getByText("PUBKEYb64url")).toBeInTheDocument();
  });

  test("lost-seed panel offers recover when an ACTIVE key exists", async () => {
    vi.spyOn(money, "listReportingKeys").mockResolvedValue({
      keys: [
        {
          id: "rk-active",
          node_id: "n1",
          implementer_id: "i1",
          public_key: "PUB",
          registered_at: "2026-07-30T00:00:00Z",
          status: "ACTIVE",
        },
      ],
      live: true,
    });
    const recoverSpy = vi.spyOn(money, "postRecoverLostReportingKey").mockResolvedValue({
      object: "reporting_key_recovered",
      id: "rk-new",
      key_id: "rk-new",
      public_key: "PUB2",
      raw_private_key: "aa".repeat(32),
      registered_at: "2026-08-03T00:00:00Z",
      superseded_key_id: "rk-active",
      implementer_id: "i2",
      implementer_raw_key: "ik_newkey_test_xxxxxxxxxxxx",
      implementer_key_prefix: "ik_newkey",
    });

    renderPage();
    expect(await screen.findByTestId("reporting-recover-panel")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("reporting-recover-start"));
    fireEvent.click(screen.getByTestId("reporting-recover-confirm-btn"));

    const input = await screen.findByLabelText("Verification code");
    fireEvent.change(input, { target: { value: "3" } });
    for (let i = 1; i < 6; i += 1) {
      fireEvent.change(screen.getByLabelText(`Digit ${i + 1}`), { target: { value: "3" } });
    }
    await waitFor(() => expect(recoverSpy).toHaveBeenCalledWith("rk-active", "333333"));
    expect(await screen.findByTestId("reporting-key-once")).toBeInTheDocument();
    expect(screen.getByTestId("implementer-key-raw")).toHaveTextContent("ik_newkey");
  });
});
