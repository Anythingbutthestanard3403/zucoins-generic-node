/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OperationDetailPage } from "./OperationDetailPage.js";
import { TotpPromptProvider } from "../../totp/TotpPromptProvider.js";
import { useAuth } from "../../store/auth.js";

const OP_ID = "f176bb4b-3f70-4450-bc91-954afa3c4196";

const inventory = {
  operation_id: OP_ID,
  operation_type: "RECEIVE_EXTERNAL",
  status: "RECEIVE_LANDED",
  amount_zkz: "0.01",
  row_version: 4,
  attention_required: false,
  attention_reason: null,
  created_at: "2026-08-02T15:46:53.940Z",
  updated_at: "2026-08-02T15:46:59.685Z",
  terminal_at: "2026-08-02T15:46:59.685Z",
  source_wallet_id: null,
  receiver_wallet_id: "47500ddd-fa13-402d-8edc-82c0760c58b5",
  destination_id: null,
  destination_address: null,
  after_landing: "HOLD",
  after_landing_destination_id: null,
  formation_state: "NOT_REQUIRED",
  verification_verdict: "PENDING",
  implementer_id: "28fe27f4-9c65-4279-ac2f-18a36aac2994",
  client_reference: null,
};

const recovery = {
  operation_id: OP_ID,
  operation_type: "RECEIVE_EXTERNAL",
  status: "RECEIVE_LANDED",
  attention_required: false,
  attention_reason: null,
  classification: "LANDED_VERIFIED",
  classification_rationale: "landing_exact",
  permitted_actions: [] as string[],
  held_leases: [
    { wallet_id: "47500ddd-fa13-402d-8edc-82c0760c58b5", lease_epoch: 1, role: "RECEIVE_WINDOW" },
  ],
  evidence_manifest: [
    {
      kind: "receive_landing_proofs",
      id: null,
      role: null,
      digest_sha256: null,
      summary: "landing proof verdict LANDED_EXACT",
    },
    {
      kind: "operation_expected_artifacts",
      id: "a4900387-fde9-41b8-862c-46fd39131b2f",
      role: null,
      digest_sha256: "74834fe50dcda6cdea2eab884c9b0cb86966e59b350bd6f09908a82bf89c534f",
      summary: "expected artifact preimage + signature present",
    },
  ],
  row_version: 4,
  lease_epoch: 1,
  recovery_nonce: "affc7e2e-1dd9-47f7-81aa-1cbb4afb8d8f",
  recovery_nonce_issued_at: "2026-08-02T15:46:40.770Z",
  recovery_nonce_expires_at: "2026-08-02T15:51:40.770Z",
};

function renderDetail(id = OP_ID) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TotpPromptProvider>
        <MemoryRouter initialEntries={[`/operations/${id}`]}>
          <Routes>
            <Route path="/operations/:id" element={<OperationDetailPage />} />
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

describe("OperationDetailPage", () => {
  beforeEach(() => {
    useAuth.setState({
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

  it("merges inventory + recovery so a landed receive shows amount, classification, evidence", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes(`/operations/${OP_ID}/recovery`)) {
        return new Response(JSON.stringify(recovery), { status: 200 });
      }
      if (url.match(new RegExp(`/operations/${OP_ID}$`))) {
        return new Response(JSON.stringify(inventory), { status: 200 });
      }
      return new Response(JSON.stringify({ error: { code: "not_found", message: url } }), {
        status: 404,
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderDetail();

    expect(await screen.findByText(/Money path advanced/i)).toBeInTheDocument();
    expect(screen.getByText("0.01")).toBeInTheDocument();
    expect(screen.getAllByText(/Receive landed/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Landed and verified/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/landing_exact/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(inventory.receiver_wallet_id).length).toBeGreaterThan(0);
    expect(screen.getByText(/landing proof verdict LANDED_EXACT/i)).toBeInTheDocument();
    expect(screen.getByText(/No operator action required/i)).toBeInTheDocument();
    expect(screen.getByText(/Held leases/i)).toBeInTheDocument();
    expect(screen.getByText(/Pending implementer verification/i)).toBeInTheDocument();
  });

  it("still paints inventory when recovery is 503", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/recovery")) {
        return new Response(
          JSON.stringify({ error: { code: "service_unavailable", message: "recovery detail unavailable" } }),
          { status: 503 },
        );
      }
      if (url.includes(`/operations/${OP_ID}`)) {
        return new Response(JSON.stringify(inventory), { status: 200 });
      }
      return new Response(JSON.stringify({ error: { code: "not_found", message: url } }), {
        status: 404,
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderDetail();

    await waitFor(() => expect(screen.getByText("0.01")).toBeInTheDocument());
    expect(screen.getAllByText(inventory.receiver_wallet_id).length).toBeGreaterThan(0);
    expect(screen.getByText(/Recovery detail unavailable/i)).toBeInTheDocument();
  });

  it("renders the Evidence-gap card from structured attention_detail (ZTR-1279/1285)", async () => {
    const detail = JSON.stringify({
      failed_predicates: ["FRESH_VERIFIED_T0_EXACT"],
      predicate_causes: [
        {
          predicate: "FRESH_VERIFIED_T0_EXACT",
          cause:
            "fresh verified head does not match T0 exactly; post-expiry confirm-read was skipped: wallet_row_undefined",
        },
      ],
      fresh_read: {
        kind: "skipped",
        reason: "wallet_row_undefined",
        summary: "skipped:wallet_row_undefined",
      },
    });
    const flagged = {
      ...recovery,
      status: "EXPIRED",
      attention_required: true,
      attention_reason: "T0_RELEASE_MISMATCH",
      classification: "NEEDS_ATTENTION",
      classification_rationale: "expiry release predicates failed",
      attention_detail: detail,
      permitted_actions: ["QUARANTINE_WALLETS"],
    };
    const flaggedInv = {
      ...inventory,
      status: "EXPIRED",
      attention_required: true,
      attention_reason: "T0_RELEASE_MISMATCH",
      terminal_at: "2026-08-14T00:10:00.000Z",
    };
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes(`/operations/${OP_ID}/recovery`)) {
        return new Response(JSON.stringify(flagged), { status: 200 });
      }
      if (url.match(new RegExp(`/operations/${OP_ID}$`))) {
        return new Response(JSON.stringify(flaggedInv), { status: 200 });
      }
      return new Response(JSON.stringify({ error: { code: "not_found", message: url } }), {
        status: 404,
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderDetail();

    expect(await screen.findByTestId("attention-detail-evidence")).toBeInTheDocument();
    expect(screen.getByText("Evidence gap")).toBeInTheDocument();
    expect(screen.getAllByText(/wallet_row_undefined/).length).toBeGreaterThan(0);
    expect(screen.getByTestId("fresh-read-outcome")).toHaveTextContent(
      "skipped:wallet_row_undefined",
    );
    expect(screen.getByText(/Attention required/i)).toBeInTheDocument();
  });


  it("renders lifecycle and honest absent fields for partial inventory", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo) => {
        const url = String(input);
        if (url.includes("/recovery")) {
          return new Response(JSON.stringify(recovery), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (url.includes("/operations/")) {
          return new Response(JSON.stringify(inventory), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response("{}", { status: 404 });
      }),
    );
    renderDetail();
    expect(await screen.findByTestId("operation-lifecycle")).toBeInTheDocument();
    expect(screen.getByText(/Lifecycle/i)).toBeInTheDocument();
    expect(screen.getByText("0.01")).toBeInTheDocument();
  });

  it("SEND detail links to transfer controls without replacing detail route", async () => {
    const sendInv = { ...inventory, operation_type: "SEND_EXTERNAL", status: "CREATED" };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo) => {
        const url = String(input);
        if (url.includes("/recovery")) {
          return new Response(JSON.stringify({ ...recovery, operation_type: "SEND_EXTERNAL" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (url.includes("/operations/")) {
          return new Response(JSON.stringify(sendInv), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response("{}", { status: 404 });
      }),
    );
    renderDetail();
    const link = await screen.findByRole("link", { name: /Open transfer controls/i });
    expect(link).toHaveAttribute("href", `/transfers/${OP_ID}`);
  });

});
  it("offers attention retraction only for LANDED_VERIFIED + attention_required (ZTR-1260)", async () => {
    const flagged = {
      ...recovery,
      attention_required: true,
      attention_reason: "STALE_CLASSIFIER",
      permitted_actions: [] as string[],
    };
    let retracted = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("attention-retraction") && init?.method === "POST") {
        retracted = true;
        const body = JSON.parse(String(init.body));
        expect(body.reason.length).toBeGreaterThan(0);
        expect(body.expected_row_version).toBe(4);
        expect(init.headers instanceof Headers ? init.headers.get("X-ZP-TOTP") : null).toBe("123456");
        return new Response(
          JSON.stringify({
            operation_id: OP_ID,
            row_version: 5,
            retracted_at: "2026-08-12T12:00:00.000Z",
            prior_attention_reason: "STALE_CLASSIFIER",
          }),
          { status: 200 },
        );
      }
      if (url.includes(`/operations/${OP_ID}/recovery`)) {
        return new Response(
          JSON.stringify(
            retracted
              ? { ...flagged, attention_required: false, attention_reason: null, row_version: 5 }
              : flagged,
          ),
          { status: 200 },
        );
      }
      if (url.match(new RegExp(`/operations/${OP_ID}$`))) {
        return new Response(JSON.stringify({ ...inventory, attention_required: !retracted }), {
          status: 200,
        });
      }
      return new Response(JSON.stringify({ error: { code: "not_found", message: url } }), {
        status: 404,
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderDetail();
    expect(await screen.findByTestId("attention-retraction")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Retract attention flag/i }));
    await enterTotp("123456");
    await waitFor(() => {
      expect(retracted).toBe(true);
    });
    await waitFor(() => {
      expect(screen.getByText(/Attention retracted/i)).toBeTruthy();
    });
  });

  it("does not show retract button when attention_required but not LANDED_VERIFIED", async () => {
    const breach = {
      ...recovery,
      classification: "INVARIANT_BREACH",
      attention_required: true,
      attention_reason: "REAL",
      permitted_actions: ["ACKNOWLEDGE_KEEP_PINNED"],
    };
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes(`/operations/${OP_ID}/recovery`)) {
        return new Response(JSON.stringify(breach), { status: 200 });
      }
      if (url.match(new RegExp(`/operations/${OP_ID}$`))) {
        return new Response(JSON.stringify({ ...inventory, attention_required: true }), {
          status: 200,
        });
      }
      return new Response(JSON.stringify({ error: { code: "not_found", message: url } }), {
        status: 404,
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();
    await screen.findByText(/Attention required/i);
    expect(screen.queryByTestId("attention-retraction")).toBeNull();
  });

  it("does not show retract when LANDED_VERIFIED without attention flag", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes(`/operations/${OP_ID}/recovery`)) {
        return new Response(JSON.stringify(recovery), { status: 200 });
      }
      if (url.match(new RegExp(`/operations/${OP_ID}$`))) {
        return new Response(JSON.stringify(inventory), { status: 200 });
      }
      return new Response(JSON.stringify({ error: { code: "not_found", message: url } }), {
        status: 404,
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();
    await screen.findByText(/No operator action required/i);
    expect(screen.queryByTestId("attention-retraction")).toBeNull();
    expect(screen.queryByRole("button", { name: /Retract attention flag/i })).toBeNull();
  });
