/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
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
    expect(screen.getAllByText(/Receive Landed/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Landed Verified/i).length).toBeGreaterThan(0);
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