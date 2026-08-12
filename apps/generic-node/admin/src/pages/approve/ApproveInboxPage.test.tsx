/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TotpPromptProvider } from "../../totp/TotpPromptProvider.js";
import { useAuth } from "../../store/auth.js";
import { isLiveRecoveryAction, LIVE_RECOVERY_ACTIONS } from "../../lib/money.js";
import { ApproveInboxPage } from "./ApproveInboxPage.js";

const OP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

const challenge = {
  operation_id: OP_ID,
  row_version: 2,
  purpose: "external_send_approval",
  canonical_version: 1,
  nonce: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  preimage_text: '{"v":1}',
  preimage_sha256: "c".repeat(64),
  issued_at: "2026-08-02T00:00:00.000Z",
  expires_at: "2026-08-02T00:10:00.000Z",
  source_selector: { kind: "WALLET_ID", wallet_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" },
  source_pubkey: "zkz1qsourceapprove",
  destination_address: "zkz1qdestapprove0001",
  amount_zkz: "0.0100",
  references_operation_id: null,
};

const sendRow = {
  operation_id: OP_ID,
  operation_type: "SEND_EXTERNAL",
  status: "CREATED",
  amount_zkz: "0.0100",
  row_version: 2,
  attention_required: false,
  attention_reason: null,
  created_at: "2026-08-02T00:00:00.000Z",
  destination_address: "zkz1qdestapprove0001",
};

function liveSession() {
  useAuth.setState({
    user: {
      userId: "u1",
      username: "op",
      role: "admin",
      mustEnrolTotp: false,
      mustChangePassword: false,
      csrfToken: "csrf-test",
    },
  });
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TotpPromptProvider>
        <MemoryRouter>
          <ApproveInboxPage />
        </MemoryRouter>
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

function emptyList() {
  return new Response(
    JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
    { status: 200 },
  );
}

function emptyAttention() {
  return new Response(
    JSON.stringify({
      operations: [],
      summary: { total: 0, by_classification: {}, p0_invariant_breach: 0 },
    }),
    { status: 200 },
  );
}

async function enterTotp(code = "123456") {
  for (let i = 0; i < 6; i++) {
    const input = await screen.findByLabelText(i === 0 ? "Verification code" : `Digit ${i + 1}`);
    fireEvent.change(input, { target: { value: code[i]! } });
  }
}

describe("ApproveInboxPage", () => {
  beforeEach(() => {
    liveSession();
    vi.restoreAllMocks();
  });
  afterEach(() => {
    cleanup();
  });

  it("treats the three previously-hidden live kinds as live", () => {
    expect(isLiveRecoveryAction("RETRY_OBSERVATION")).toBe(true);
    expect(isLiveRecoveryAction("REDELIVER_EXACT_PARTIAL")).toBe(true);
    expect(isLiveRecoveryAction("CONTINUE_EXTERNAL_WAIT")).toBe(true);
    expect(isLiveRecoveryAction("CLOSE_NEVER_STARTED_EXTERNAL_SEND")).toBe(true);
    expect(isLiveRecoveryAction("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED")).toBe(true);
    expect(isLiveRecoveryAction("REBUILD_INTERNAL_MOVE")).toBe(false);
    expect(LIVE_RECOVERY_ACTIONS).toHaveLength(8);
  });

  it("never paints pending fetch as clear or unavailable", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    renderPage();
    expect(screen.getByTestId("approve-loading")).toBeInTheDocument();
    expect(screen.queryByTestId("approve-empty-clear")).not.toBeInTheDocument();
    expect(screen.queryByTestId("approve-empty-unavailable")).not.toBeInTheDocument();
  });

  it("empty state is 'inbox clear' only after live empty responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("needs-attention")) return emptyAttention();
        return emptyList();
      }),
    );
    renderPage();
    await waitFor(() => expect(screen.getByTestId("approve-empty-clear")).toBeInTheDocument());
    expect(screen.getByText(/Inbox clear/i)).toBeInTheDocument();
  });

  it("unavailable is not painted as clear", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ error: { code: "service_unavailable", message: "down" } }),
            { status: 503 },
          ),
      ),
    );
    renderPage();
    await waitFor(() =>
      expect(screen.getByTestId("approve-empty-unavailable")).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("approve-empty-clear")).not.toBeInTheDocument();
  });

  it("shows honesty copy that approve ≠ paid and node never submits SEND", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("needs-attention")) return emptyAttention();
        return emptyList();
      }),
    );
    renderPage();
    const honesty = await screen.findByTestId("approve-honesty");
    expect(honesty.textContent).toMatch(/not/i);
    expect(honesty.textContent).toMatch(/paid/i);
    expect(honesty.textContent).toMatch(/never/i);
    expect(honesty.textContent).toMatch(/SEND_EXTERNAL/);
    expect(honesty.textContent).not.toMatch(/\bZUC\b/);
  });

  it("renders a pending SEND card without hunting Activity", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("needs-attention")) return emptyAttention();
        if (url.includes("/operations") && url.includes("SEND_EXTERNAL")) {
          return new Response(
            JSON.stringify({
              object: "list",
              data: [sendRow],
              has_more: false,
              next_cursor: null,
            }),
            { status: 200 },
          );
        }
        if (url.includes("/destinations")) return emptyList();
        return emptyList();
      }),
    );
    renderPage();
    await waitFor(() => expect(screen.getByTestId("approve-send-card")).toBeInTheDocument());
    expect(screen.getAllByText("Outgoing (needs approval)").length).toBeGreaterThan(0);
    expect(screen.getByText("0.0100 ZKZ")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Review & decide/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open detail/i })).toHaveAttribute(
      "href",
      `/operations/${OP_ID}`,
    );
  });

  it("approve path requires TOTP and never claims paid", async () => {
    let approveCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes("needs-attention")) return emptyAttention();
        if (url.includes("/destinations")) return emptyList();
        if (url.includes("/operations") && !url.includes("recovery") && (!init?.method || init.method === "GET")) {
          if (url.includes(OP_ID) && !url.includes("kind=")) {
            return new Response(
              JSON.stringify({ ...sendRow, status: approveCalls > 0 ? "APPROVED" : "CREATED" }),
              { status: 200 },
            );
          }
          return new Response(
            JSON.stringify({
              object: "list",
              data: approveCalls > 0 ? [] : [sendRow],
              has_more: false,
              next_cursor: null,
            }),
            { status: 200 },
          );
        }
        if (url.includes("/approval-challenge")) {
          return new Response(JSON.stringify(challenge), { status: 200 });
        }
        if (url.includes("/approve") && init?.method === "POST") {
          approveCalls += 1;
          const headers = new Headers(init.headers);
          expect(headers.get("X-ZP-TOTP")).toBe("123456");
          expect(headers.get("X-CSRF-Token")).toBe("csrf-test");
          return new Response(
            JSON.stringify({
              operation_id: OP_ID,
              status: "APPROVED",
              row_version: 3,
              approval_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
              method: "totp",
              consumed_at: "2026-08-02T00:01:00.000Z",
            }),
            { status: 200 },
          );
        }
        if (url.includes("/recovery") && !url.includes("recovery-actions")) {
          return new Response(
            JSON.stringify({
              operation_id: OP_ID,
              operation_type: "SEND_EXTERNAL",
              status: "APPROVED",
              attention_required: false,
              attention_reason: null,
              classification: "WAITING",
              classification_rationale: "awaiting recipient",
              permitted_actions: [],
              held_leases: [],
              row_version: 3,
              lease_epoch: null,
              recovery_nonce: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
              recovery_nonce_issued_at: "2026-08-02T00:01:00.000Z",
              recovery_nonce_expires_at: "2026-08-02T00:06:00.000Z",
            }),
            { status: 200 },
          );
        }
        return emptyList();
      }),
    );
    renderPage();
    await waitFor(() => expect(screen.getByTestId("approve-send-card")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Review & decide/i }));
    await waitFor(() => expect(screen.getByTestId("approve-send-actions")).toBeInTheDocument());
    expect(screen.getByTitle("c".repeat(64))).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Approve \(TOTP\)/i }));
    await enterTotp("123456");
    await waitFor(() => expect(approveCalls).toBe(1));
    await waitFor(() => {
      const body = document.body.textContent ?? "";
      expect(body).toMatch(/never submits SEND_EXTERNAL/);
      expect(body).toMatch(/Approve ≠ redeemed ≠ paid|not paid yet/i);
      expect(body).not.toMatch(/order paid/i); // contract-allow:order:negative-copy-assertion
      expect(body).not.toMatch(/payment settled/i); // contract-allow:payment:negative-copy-assertion
    });
  });

  it("renders live recovery actions as clickable and reserved/unknown as disabled with reasons", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("needs-attention")) {
          return new Response(
            JSON.stringify({
              operations: [
                {
                  operation_id: "ffffffff-ffff-4fff-8fff-ffffffffffff",
                  operation_type: "SEND_EXTERNAL",
                  status: "AWAITING_REDEMPTION",
                  attention_required: true,
                  attention_reason: "stuck",
                  classification: "INDETERMINATE",
                  classification_rationale: "needs operator",
                  severity: "P1",
                  permitted_actions: [
                    "RETRY_OBSERVATION",
                    "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
                    "REDELIVER_EXACT_PARTIAL",
                    "CONTINUE_EXTERNAL_WAIT",
                    "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
                    "REBUILD_INTERNAL_MOVE",
                    "FORCE_LANDED",
                  ],
                  row_version: 5,
                  lease_epoch: null,
                  attention_since: "2026-08-02T00:00:00.000Z",
                  wallet_ids: [],
                },
              ],
              summary: { total: 1, by_classification: { INDETERMINATE: 1 }, p0_invariant_breach: 0 },
            }),
            { status: 200 },
          );
        }
        return emptyList();
      }),
    );
    renderPage();
    await waitFor(() => expect(screen.getByTestId("approve-recovery-card")).toBeInTheDocument());
    // Live kinds (including CLOSE under ZTR-1226) are clickable.
    expect(screen.getByRole("button", { name: "Retry observation" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Close never-started send" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Re-send exact transfer code" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Continue waiting for redemption" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Close send (proven not landed)" })).toBeEnabled();
    // Reserved + unknown stay disabled with honest reasons; never POSTable as enabled.
    const unavailable = screen.getByTestId("approve-recovery-unimplemented");
    expect(unavailable.textContent).toMatch(/Rebuild internal transfer/);
    expect(unavailable.textContent).toMatch(/Reserved — REBUILD_INTERNAL_MOVE is not grantable/);
    expect(unavailable.textContent).toMatch(/FORCE_LANDED|Not implemented on this node/);
    expect(screen.getByRole("button", { name: "Rebuild internal transfer" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "FORCE_LANDED" })).toBeDisabled();
  });

  it("renders pending integration request cards with edit-then-approve", async () => {
    const approveCalls: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes("/integration-requests/") && url.includes("/approve") && (init?.method ?? "GET") === "POST") {
          approveCalls.push(JSON.parse(String(init?.body ?? "{}")));
          return new Response(
            JSON.stringify({
              request: { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", status: "APPROVED" },
              implementer: { id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", name: "Platform Alpha" },
              rule: { per_send_max_zkz: "5" },
            }),
            { status: 200 },
          );
        }
        if (url.includes("/integration-requests")) {
          return new Response(
            JSON.stringify({
              object: "list",
              data: [
                {
                  id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                  display_name: "Platform Alpha",
                  requested_scopes: ["send:create", "send:read"],
                  proposed_rule_json: JSON.stringify({
                    rule_id: "r1",
                    per_send_max_zkz: "10",
                    per_send_min_zkz: null,
                    window_hours: 24,
                    window_cap_zkz: "100",
                    expires_at: null,
                    enabled: true,
                  }),
                  approved_rule_json: null,
                  status: "PENDING",
                  row_version: 1,
                  created_at: "2026-08-01T00:00:00.000Z",
                  expires_at: "2026-08-08T00:00:00.000Z",
                  decided_at: null,
                  decided_by: null,
                  implementer_id: null,
                },
              ],
              has_more: false,
              next_cursor: null,
            }),
            { status: 200 },
          );
        }
        if (url.includes("needs-attention")) return emptyAttention();
        return emptyList();
      }),
    );
    renderPage();
    await waitFor(() => expect(screen.getByTestId("approve-integration-card")).toBeInTheDocument());
    expect(screen.getByText("Platform Alpha")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Review & edit/i }));
    await waitFor(() => expect(screen.getByTestId("approve-integration-actions")).toBeInTheDocument());
    const maxInput = screen.getByLabelText(/Per-send max/i);
    fireEvent.change(maxInput, { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: /Approve \(TOTP\)/i }));
    await enterTotp("123456");
    await waitFor(() => expect(approveCalls.length).toBe(1));
    const body = approveCalls[0] as { rule: { per_send_max_zkz: string }; expected_row_version: number };
    expect(body.expected_row_version).toBe(1);
    expect(body.rule.per_send_max_zkz).toBe("5");
  });

});
