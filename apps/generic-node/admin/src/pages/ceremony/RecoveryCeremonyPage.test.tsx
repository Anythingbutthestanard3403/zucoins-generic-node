import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router";
import { useAuth } from "../../store/auth.js";
import { TotpPromptProvider } from "../../totp/TotpPromptProvider.js";
import { RecoveryCeremonyPage } from "./RecoveryCeremonyPage.js";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TotpPromptProvider>
        <MemoryRouter>
          <RecoveryCeremonyPage />
        </MemoryRouter>
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

describe("RecoveryCeremonyPage (Mode A)", () => {
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
    // not framed
    Object.defineProperty(window, "top", { value: window, configurable: true });
    Object.defineProperty(window, "self", { value: window, configurable: true });
  });

  afterEach(() => cleanup());

  it("shows the explain step first with pack happy-path copy", () => {
    renderPage();

    expect(screen.getByText("Recovery verification")).toBeInTheDocument();
    expect(screen.getByText(/1\. Understand/)).toBeInTheDocument();
    expect(screen.getByText(/2\. Recovery pack/)).toBeInTheDocument();
    expect(screen.getByText(/3\. Break-glass key/)).toBeInTheDocument();
    expect(screen.getByText(/What this ceremony proves/)).toBeInTheDocument();
    expect(screen.getByText(/download an encrypted recovery pack once/i)).toBeInTheDocument();
    expect(screen.getByText(/Argon2id/i)).toBeInTheDocument();
  });

  it("shows pack create/prove on the pack step", () => {
    renderPage();
    fireEvent.click(screen.getByText(/Continue to recovery pack/i));
    expect(screen.getByTestId("pack-secret-create-hint")).toBeInTheDocument();
    expect(screen.getByTestId("pack-file")).toBeInTheDocument();
  });

  it("is generate-only — no operator-chosen seal secret field", () => {
    renderPage();
    fireEvent.click(screen.getByText(/Continue to recovery pack/i));

    // No digit-passcode or hand-rolled secret field: create is server generate-only.
    expect(screen.queryByTestId("pack-passcode-create")).not.toBeInTheDocument();
    expect(screen.queryByTestId("pack-secret-create")).not.toBeInTheDocument();
    expect(screen.queryByTestId("pack-secret-regenerate")).not.toBeInTheDocument();
    expect(screen.getByTestId("pack-secret-create-hint")).toHaveTextContent(/cannot choose/i);

    // Create stays disabled until the operator confirms they will write the shown secret.
    const create = screen.getByRole("button", { name: /Create & download pack/i });
    expect(create).toBeDisabled();
    fireEvent.click(screen.getByTestId("pack-secret-saved"));
    expect(create).toBeEnabled();
  });

  it("offers the v1 legacy opt-in and the re-issue path for superseded packs", () => {
    renderPage();
    fireEvent.click(screen.getByText(/Continue to recovery pack/i));
    expect(screen.getByTestId("pack-legacy-v1")).toBeInTheDocument();
    expect(screen.getByTestId("pack-from-file")).toBeInTheDocument();
    expect(screen.getByTestId("pack-from-secret")).toBeInTheDocument();
    expect(screen.getByText(/destroy every copy of the old file/i)).toBeInTheDocument();
  });

  it("shows a one-shot master key field on the break-glass run step (Mode A)", () => {
    renderPage();
    fireEvent.click(screen.getByText(/3\. Break-glass key/));

    const input = screen.getByTestId("master-key-input");
    expect(input).toBeInTheDocument();
    expect(input).toHaveAttribute("type", "password");
    expect(input).toHaveAttribute("autocomplete", "off");
    expect(input).toHaveAttribute("data-1p-ignore", "true");
  });

  it("clears the master key field on submit and never persists to SPA storage", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/recovery-ceremony/start")) {
        return new Response(
          JSON.stringify({
            ceremony_id: "c-test",
            status: "running",
            stage: "accepted",
            progress: [],
            summary: null,
            error: null,
            started_at: new Date().toISOString(),
            finished_at: null,
            in_flight: true,
          }),
          { status: 202 },
        );
      }
      if (url.includes("/recovery-ceremony/status")) {
        return new Response(
          JSON.stringify({
            ceremony_id: "c-test",
            status: "complete",
            stage: "complete",
            progress: [{ stage: "complete", detail: null, at: new Date().toISOString() }],
            summary: {
              ok: true,
              ceremony_id: "c-test",
              export_id: "e1",
              archive_sha256: "ab".repeat(32),
              accepted: true,
              stamped: 1,
              failed_closed: 0,
              skipped: 0,
              born_blocked: 0,
              abort_reasons: [],
              instance_destroyed: true,
              recovery_verified_on_live: 1,
            },
            error: null,
            started_at: new Date().toISOString(),
            finished_at: new Date().toISOString(),
            in_flight: false,
          }),
          { status: 200 },
        );
      }
      return new Response("{}", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();
    fireEvent.click(screen.getByText(/3\. Break-glass key/));

    const input = screen.getByTestId("master-key-input") as HTMLInputElement;
    const SECRET = "test-master-key-32chars!!!!!!!!!!!";
    fireEvent.change(input, { target: { value: SECRET } });
    expect(input.value).toBe(SECRET);

    fireEvent.click(screen.getByRole("button", { name: /start ceremony/i }));

    // Field is cleared synchronously on submit (before TOTP resolves).
    await waitFor(() => {
      expect((screen.getByTestId("master-key-input") as HTMLInputElement).value).toBe("");
    });

    // Complete TOTP digits if prompt is open
    const d1 = screen.queryByLabelText("Digit 1");
    if (d1) {
      for (let i = 1; i <= 6; i++) {
        const d = screen.getByLabelText(`Digit ${i}`);
        fireEvent.change(d, { target: { value: String(i) } });
      }
      fireEvent.click(screen.getByRole("button", { name: /^Confirm$/i }));
    }

    // Key never written to durable SPA storage
    expect(localStorage.getItem("vault_master_key")).toBeNull();
    expect(sessionStorage.getItem("vault_master_key")).toBeNull();
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)!;
      expect(localStorage.getItem(k) ?? "").not.toContain("test-master!!!!!!!!!");
    }
    // No fetch URL may carry the key
    for (const call of fetchMock.mock.calls) {
      const url = String(call[0]);
      expect(url).not.toContain(SECRET);
      expect(url).not.toMatch(/vault_master/i);
    }
  });

  it("refuses to run when framed", () => {
    const fakeTop = {} as Window;
    Object.defineProperty(window, "top", { value: fakeTop, configurable: true });
    Object.defineProperty(window, "self", { value: window, configurable: true });

    renderPage();
    expect(screen.getByText(/Cannot run in a frame/i)).toBeInTheDocument();
    expect(screen.queryByTestId("master-key-input")).not.toBeInTheDocument();
  });

  it("navigates to verify and polls wallet inventory for recovery_verified", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/wallets")) {
        return new Response(
          JSON.stringify({
            object: "list",
            data: [
              {
                wallet_id: "w1",
                public_key: "pk1aaaaaaaaaa",
                state: "AVAILABLE",
                key_origin: "node_generated",
                recovery_verified: true,
                observed_balance_zkz: "1.0",
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
              },
              {
                wallet_id: "w2",
                public_key: "pk2bbbbbbbbbb",
                state: "AVAILABLE",
                key_origin: "node_generated",
                recovery_verified: false,
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
              },
            ],
            has_more: false,
            next_cursor: null,
          }),
          { status: 200 },
        );
      }
      return new Response("{}", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();
    fireEvent.click(screen.getByText(/4\. Verify result/));

    // Status appears on the step summary and the result card (strict-mode multi-match).
    expect((await screen.findAllByText("Verified")).length).toBeGreaterThan(0);
    expect(screen.getByText("Born-blocked")).toBeInTheDocument();
    expect(screen.getByText(/≥1 recovery_verified/i)).toBeInTheDocument();
  });

  it("documents CLI break-glass still available", () => {
    renderPage();
    fireEvent.click(screen.getByText(/3\. Break-glass key/));
    expect(screen.getByText(/run-recovery-ceremony/)).toBeInTheDocument();
  });
});
