/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router";
import { TransferDetailPage } from "./TransferDetailPage.js";
import { TotpPromptProvider } from "../../totp/TotpPromptProvider.js";
import { useAuth } from "../../store/auth.js";

const OP_ID = "11111111-1111-4111-8111-111111111111";

const challenge = {
  operation_id: OP_ID,
  row_version: 3,
  purpose: "external_send_approval",
  canonical_version: 1,
  nonce: "22222222-2222-4222-8222-222222222222",
  preimage_text: '{"v":1}',
  preimage_sha256: "a".repeat(64),
  issued_at: "2026-07-29T00:00:00.000Z",
  expires_at: "2026-07-29T00:05:00.000Z",
  source_selector: { kind: "WALLET_ID", wallet_id: "33333333-3333-4333-8333-333333333333" },
  source_pubkey: "zkz1qsource",
  destination_address: "zkz1qdest",
  amount_zkz: "0.0100",
  references_operation_id: null,
};

const approveResponse = {
  operation_id: OP_ID,
  status: "APPROVED",
  row_version: 4,
  approval_id: "44444444-4444-4444-8444-444444444444",
  method: "totp",
  consumed_at: "2026-07-29T00:01:00.000Z",
};

const recoveryApproved = {
  operation_id: OP_ID,
  operation_type: "SEND_EXTERNAL",
  status: "APPROVED",
  attention_required: false,
  attention_reason: null,
  classification: "WAITING",
  classification_rationale: "awaiting formation",
  permitted_actions: [] as string[],
  held_leases: [],
  row_version: 4,
  lease_epoch: null,
  recovery_nonce: "55555555-5555-4555-8555-555555555555",
  recovery_nonce_issued_at: "2026-07-29T00:01:01.000Z",
  recovery_nonce_expires_at: "2026-07-29T00:06:01.000Z",
};

function renderDetail() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TotpPromptProvider>
        <MemoryRouter initialEntries={[`/transfers/${OP_ID}`]}>
          <Routes>
            <Route path="/transfers/:id" element={<TransferDetailPage />} />
          </Routes>
        </MemoryRouter>
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

async function enterTotp(code = "123456") {
  for (let i = 0; i < 6; i++) {
    const input = await screen.findByLabelText(i === 0 ? "Verification code" : `Digit ${i + 1}`);
    fireEvent.change(input, { target: { value: code[i]! } });
  }
}

describe("TransferDetailPage approve happy path", () => {
  beforeEach(() => {
    useAuth.setState({
      demoMode: false,
      user: {
        userId: "u1",
        username: "admin",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "csrf-test",
      },
    });
    vi.restoreAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("GET approval-challenge then POST approve with X-ZP-TOTP + CSRF and polls APPROVED", async () => {
    let approveCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/approval-challenge") && (!init?.method || init.method === "GET")) {
        // Challenge lifecycle independent of terminal money status (404 ≠ APPROVED).
        if (approveCalls > 0) {
          return new Response(
            JSON.stringify({ error: { code: "not_found", message: "gone" } }),
            { status: 404 },
          );
        }
        return new Response(JSON.stringify(challenge), { status: 200 });
      }
      if (url.includes("/approve") && init?.method === "POST") {
        approveCalls += 1;
        const headers = new Headers(init.headers);
        expect(headers.get("X-CSRF-Token")).toBe("csrf-test");
        expect(headers.get("X-ZP-TOTP")).toBe("123456");
        expect(headers.get("Idempotency-Key")).toBeTruthy();
        const body = JSON.parse(String(init.body)) as {
          challenge_nonce: string;
          expected_row_version: number;
          preimage_sha256: string;
        };
        expect(body.challenge_nonce).toBe(challenge.nonce);
        expect(body.expected_row_version).toBe(3);
        expect(body.preimage_sha256).toBe(challenge.preimage_sha256);
        return new Response(JSON.stringify(approveResponse), { status: 200 });
      }
      if (url.includes("/recovery") && !url.includes("recovery-actions")) {
        if (approveCalls > 0) {
          return new Response(JSON.stringify(recoveryApproved), { status: 200 });
        }
        return new Response(
          JSON.stringify({ error: { code: "not_found", message: "n/a" } }),
          { status: 404 },
        );
      }
      return new Response(
        JSON.stringify({ error: { code: "not_found", message: url } }),
        { status: 404 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    renderDetail();

    expect(await screen.findByText(/0\.0100/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /approve \(totp\)/i })).toBeEnabled();
    expect(screen.getByTestId("pack-p-approve-semantics")).toHaveTextContent(/does not chain-submit SEND/i);
    expect(screen.getByTestId("pack-p-approve-semantics")).toHaveTextContent(/not paid/i);

    fireEvent.click(screen.getByRole("button", { name: /approve \(totp\)/i }));
    await enterTotp("123456");

    await waitFor(() => expect(approveCalls).toBe(1));
    expect(await screen.findByText(/Approved\. Polling/)).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.some(
        ([u, i]) => String(u).includes("/approve") && (i as RequestInit | undefined)?.method === "POST",
      ),
    ).toBe(true);
    // Polled status surface (may appear more than once via StatusTag)
    expect(screen.getAllByText("APPROVED").length).toBeGreaterThan(0);
  });

  it("demo mode never POSTs approve", async () => {
    useAuth.setState({
      demoMode: true,
      user: {
        userId: "demo",
        username: "demo",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "demo",
      },
    });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();
    expect((await screen.findAllByText(/no fixtures/i)).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /approve \(totp\)/i })).not.toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
