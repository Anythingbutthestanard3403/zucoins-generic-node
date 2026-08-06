/** @vitest-environment jsdom */

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { ApiError } from "../../lib/api.js";
import * as money from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { TotpPromptProvider } from "../../totp/index.js";
import { OverviewPage } from "./OverviewPage.js";
import { saveEnabledPacks } from "../../lib/packs.js";

const CLEAR: money.HaltState = {
  engaged: false,
  reason: null,
  updated_at: null,
  updated_by: null,
};

const ENGAGED: money.HaltState = {
  engaged: true,
  reason: "incident response",
  updated_at: "2026-07-31T00:00:00Z",
  updated_by: "operator-1",
};

function renderOverview() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const result = render(
    <QueryClientProvider client={client}>
      <TotpPromptProvider>
        <MemoryRouter>
          <OverviewPage />
        </MemoryRouter>
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
  return { ...result, client };
}

function stubUnrelatedInventory() {
  vi.spyOn(money, "listWalletsInventory").mockResolvedValue({ data: [], live: true });
  vi.spyOn(money, "listSendOperationsInventory").mockResolvedValue({ data: [], live: true });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    let body: unknown = { object: "list", data: [], has_more: false, next_cursor: null };
    if (path.endsWith("/operations/needs-attention")) {
      body = {
        operations: [],
        summary: { total: 0, by_classification: {}, p0_invariant_breach: 0 },
      };
    } else if (path.includes("/readiness")) {
      body = {
        object: "readiness_checklist",
        generated_at: "2026-08-03T00:00:00.000Z",
        rows: [
          {
            id: "recovery_verified_wallet",
            status: "blocked",
            title: "Recovery-verified wallet",
            detail: "Wallets not recovery-verified — continue setup",
            href: "/recovery-ceremony",
            blocks_ops: ["RECEIVE_EXTERNAL"],
          },
          {
            id: "node_healthy",
            status: "ok",
            title: "Node health",
            detail: "Ready",
            href: "/",
          },
        ],
      };
    } else if (path.startsWith("/health/ready")) {
      body = { status: "ready", version: "t", timestamp: "2026-08-03T00:00:00.000Z", checks: [] };
    }
    return new Response(JSON.stringify(body), { status: 200 });
  }));
}

async function openTotp(action: string, confirmation: string) {
  fireEvent.click(await screen.findByRole("button", { name: action }));
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: confirmation }));
  return screen.findByRole("dialog", { name: "Confirm emergency halt" });
}

function enterTotp(dialog: HTMLElement, code = "123456") {
  const inputs = within(dialog).getAllByRole("textbox");
  code.split("").forEach((digit, index) => {
    fireEvent.change(inputs[index]!, { target: { value: digit } });
  });
}

function haltFailure(requestId: string) {
  return new ApiError(503, {
    error: {
      code: "service_unavailable",
      message: "halt service unavailable",
      request_id: requestId,
    },
  });
}

describe("OverviewPage halt truthfulness", () => {
  beforeEach(() => {
    useAuth.setState({
      demoMode: false,
      user: {
        userId: "operator-1",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "csrf",
      },
    });
    stubUnrelatedInventory();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  test("renders an API failure as prominent UNKNOWN, preserves request ID and disables halt mutation", async () => {
    vi.spyOn(money, "fetchHaltState").mockRejectedValue(new ApiError(503, {
      error: {
        code: "service_unavailable",
        message: "halt service unavailable",
        request_id: "req-fixture",
      },
    }));

    renderOverview();

    const stat = await screen.findByTestId("halt-stat");
    await waitFor(() => expect(within(stat).getByText("UNKNOWN")).toBeInTheDocument());
    expect(within(stat).getByRole("alert")).toHaveTextContent(/treat money rails as unknown/i);
    expect(screen.getByText(/req-fixture/)).toBeInTheDocument();
    expect(screen.queryByText("Clear")).not.toBeInTheDocument();
    expect(screen.queryByText("Money rails open")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /halt engines|resume engines/i })).not.toBeInTheDocument();
    expect(screen.getByTestId("halt-action")).toHaveTextContent(/unavailable/i);
  });

  test("renders indeterminate halt data as UNKNOWN rather than Clear", async () => {
    vi.spyOn(money, "fetchHaltState").mockResolvedValue({
      reason: null,
      updated_at: null,
      updated_by: null,
    } as unknown as money.HaltState);

    renderOverview();

    const stat = await screen.findByTestId("halt-stat");
    await waitFor(() => expect(within(stat).getByText("UNKNOWN")).toBeInTheDocument());
    expect(within(stat).queryByText("Clear")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /halt engines|resume engines/i })).not.toBeInTheDocument();
  });

  test.each([
    {
      state: CLEAR,
      label: "Clear",
      detail: "Money rails open",
      action: "Halt engines",
      requestId: "req-stale-clear",
    },
    {
      state: ENGAGED,
      label: "Engaged",
      detail: "Money rails blocked",
      action: "Resume engines",
      requestId: "req-stale-engaged",
    },
  ] as const)(
    "renders UNKNOWN after cached $label when a real QueryClient refetch fails",
    async ({ state, label, detail, action, requestId }) => {
      vi.spyOn(money, "fetchHaltState")
        .mockResolvedValueOnce(state)
        .mockRejectedValueOnce(new ApiError(503, {
          error: {
            code: "service_unavailable",
            message: "halt service unavailable",
            request_id: requestId,
          },
        }));

      const { client } = renderOverview();
      const stat = await screen.findByTestId("halt-stat");
      await waitFor(() => expect(within(stat).getByText(label)).toBeInTheDocument());
      expect(within(stat).getByText(detail)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: action })).toBeEnabled();

      await client.refetchQueries({ queryKey: ["overview", "halt-state", false] });

      await waitFor(() => expect(within(stat).getByText("UNKNOWN")).toBeInTheDocument());
      expect(within(stat).getByRole("alert")).toHaveTextContent(/treat money rails as unknown/i);
      expect(screen.getByText(new RegExp(requestId))).toBeInTheDocument();
      expect(within(stat).queryByText(label)).not.toBeInTheDocument();
      expect(within(stat).queryByText(detail)).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /halt engines|resume engines/i })).not.toBeInTheDocument();
      expect(screen.getByTestId("halt-action")).toHaveTextContent(/unavailable/i);
    },
  );

  test.each([
    {
      initial: CLEAR,
      opposite: ENGAGED,
      action: "Halt engines",
      confirmation: "Confirm halt",
      recoveredAction: "Resume engines",
      recoveredConfirmation: "Confirm resume",
      recoveredTarget: false,
    },
    {
      initial: ENGAGED,
      opposite: CLEAR,
      action: "Resume engines",
      confirmation: "Confirm resume",
      recoveredAction: "Halt engines",
      recoveredConfirmation: "Confirm halt",
      recoveredTarget: true,
    },
  ] as const)(
    "cancels an armed $action ceremony across repeated failures and opposite-state recovery",
    async ({
      initial,
      opposite,
      action,
      confirmation,
      recoveredAction,
      recoveredConfirmation,
      recoveredTarget,
    }) => {
      const fetchHaltState = vi.spyOn(money, "fetchHaltState")
        .mockResolvedValue(opposite)
        .mockResolvedValueOnce(initial)
        .mockRejectedValueOnce(haltFailure("req-first-failure"))
        .mockRejectedValueOnce(haltFailure("req-latest-failure"));
      const postHaltToggle = vi.spyOn(money, "postHaltToggle").mockResolvedValue(opposite);
      const { client } = renderOverview();

      await openTotp(action, confirmation);
      fireEvent.change(screen.getByLabelText("Reason (optional)"), {
        target: { value: "stale warning reason" },
      });

      await client.refetchQueries({ queryKey: ["overview", "halt-state", false] });

      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      expect(screen.getByTestId("halt-stat")).toHaveTextContent("UNKNOWN");
      expect(screen.getByText(/req-first-failure/)).toBeInTheDocument();
      expect(screen.getByText(/retry the halt-state request/i)).toBeInTheDocument();
      expect(postHaltToggle).not.toHaveBeenCalled();

      await client.refetchQueries({ queryKey: ["overview", "halt-state", false] });
      await waitFor(() => expect(screen.getByText(/req-latest-failure/)).toBeInTheDocument());
      expect(screen.queryByText(/req-first-failure/)).not.toBeInTheDocument();
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(postHaltToggle).not.toHaveBeenCalled();

      await client.refetchQueries({ queryKey: ["overview", "halt-state", false] });
      const recovered = await screen.findByRole("button", { name: recoveredAction });
      expect(recovered).toBeEnabled();
      expect(screen.queryByRole("button", { name: confirmation })).not.toBeInTheDocument();
      expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
      expect(postHaltToggle).not.toHaveBeenCalled();

      const dismissed = await openTotp(recoveredAction, recoveredConfirmation);
      expect(screen.getByLabelText("Reason (optional)")).toHaveValue("");
      fireEvent.click(within(dismissed).getByRole("button", { name: "Cancel" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      expect(postHaltToggle).not.toHaveBeenCalled();

      const retryConfirmation = await screen.findByRole("button", { name: recoveredConfirmation });
      fireEvent.click(retryConfirmation);
      const fresh = await screen.findByRole("dialog", { name: "Confirm emergency halt" });
      enterTotp(fresh);
      await waitFor(() => expect(postHaltToggle).toHaveBeenCalledTimes(1));
      expect(postHaltToggle).toHaveBeenCalledWith({ engaged: recoveredTarget }, "123456");
      expect(fetchHaltState.mock.calls.length).toBeGreaterThanOrEqual(4);
    },
  );

  test("blocks a prompt that resolves after a refetch has already invalidated halt authority", async () => {
    let rejectRefetch!: (error: unknown) => void;
    const refetchFailure = new Promise<money.HaltState>((_resolve, reject) => {
      rejectRefetch = reject;
    });
    vi.spyOn(money, "fetchHaltState")
      .mockResolvedValue(CLEAR)
      .mockResolvedValueOnce(CLEAR)
      .mockImplementationOnce(() => refetchFailure);
    const postHaltToggle = vi.spyOn(money, "postHaltToggle").mockResolvedValue(ENGAGED);
    const { client } = renderOverview();
    const dialog = await openTotp("Halt engines", "Confirm halt");
    const inputs = within(dialog).getAllByRole("textbox");

    await act(async () => {
      const refetch = client.refetchQueries({ queryKey: ["overview", "halt-state", false] });
      "123456".split("").forEach((digit, index) => {
        fireEvent.change(inputs[index]!, { target: { value: digit } });
      });
      rejectRefetch(haltFailure("req-late-resolution"));
      await refetch;
    });

    await waitFor(() => expect(screen.getByText(/req-late-resolution/)).toBeInTheDocument());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(postHaltToggle).not.toHaveBeenCalled();
  });

  test("preserves the explicit demo-mode clear state without calling the halt API", async () => {
    useAuth.setState({ demoMode: true });
    const fetchHaltState = vi.spyOn(money, "fetchHaltState");

    renderOverview();

    const stat = await screen.findByTestId("halt-stat");
    await waitFor(() => expect(within(stat).getByText("Clear")).toBeInTheDocument());
    expect(within(stat).getByText("Money rails open")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Halt engines" })).toBeEnabled();
    expect(fetchHaltState).not.toHaveBeenCalled();
  });

  test.each([
    [CLEAR, "Clear", "Money rails open", "Halt engines"],
    [ENGAGED, "Engaged", "Money rails blocked", "Resume engines"],
  ] as const)("renders a determinate halt state", async (state, label, detail, action) => {
    vi.spyOn(money, "fetchHaltState").mockResolvedValue(state);

    renderOverview();

    const stat = await screen.findByTestId("halt-stat");
    await waitFor(() => expect(within(stat).getByText(label)).toBeInTheDocument());
    expect(within(stat).getByText(detail)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: action })).toBeEnabled();
    expect(within(stat).queryByText("UNKNOWN")).not.toBeInTheDocument();
  });
});

describe("OverviewPage activity toolbar honesty", () => {
  const ATTENTION_MATCHED = {
    operation_id: "op-attn-matched",
    operation_type: "SEND_EXTERNAL",
    status: "PARKED",
    attention_required: true,
    attention_reason: "fee spike",
    classification: "WAITING",
    classification_rationale: "awaiting fee bump",
    severity: "P0" as const,
    permitted_actions: [],
    row_version: 1,
    lease_epoch: null,
    attention_since: "2026-07-30T10:00:00Z",
    wallet_ids: [],
  };

  const ATTENTION_UNMATCHED = {
    ...ATTENTION_MATCHED,
    operation_id: "op-attn-unmatched",
    attention_reason: "no fixture join",
  };

  const OP_MATCHED = {
    operation_id: "op-attn-matched",
    operation_type: "SEND_EXTERNAL",
    status: "LANDED",
    amount_zkz: "12.5000",
    row_version: 2,
    attention_required: false,
    attention_reason: null,
    created_at: "2026-07-30T09:00:00Z",
    updated_at: "2026-07-30T11:00:00Z",
    terminal_at: "2026-07-30T11:00:00Z",
    destination_address: "zkz1deadbeef",
  };

  const OP_INFLIGHT = {
    operation_id: "op-inflight-1",
    operation_type: "MOVE_INTERNAL",
    status: "PENDING",
    amount_zkz: "3.0000",
    row_version: 1,
    attention_required: false,
    attention_reason: null,
    created_at: "2026-07-30T09:30:00Z",
    updated_at: "2026-07-30T09:30:00Z",
    terminal_at: null,
    destination_address: null,
  };

  function stubActivity(
    attention: readonly Record<string, unknown>[] = [ATTENTION_MATCHED, ATTENTION_UNMATCHED],
    ops: readonly Record<string, unknown>[] = [OP_MATCHED, OP_INFLIGHT],
  ) {
    vi.spyOn(money, "listWalletsInventory").mockResolvedValue({ data: [], live: true });
    vi.spyOn(money, "fetchHaltState").mockResolvedValue(CLEAR);
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/operations/needs-attention")) {
        return new Response(JSON.stringify({
          operations: attention,
          summary: { total: attention.length, by_classification: {}, p0_invariant_breach: 0 },
        }), { status: 200 });
      }
      if (path.endsWith("/operations")) {
        return new Response(
          JSON.stringify({ object: "list", data: ops, has_more: false, next_cursor: null }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
        { status: 200 },
      );
    }));
  }

  beforeEach(() => {
    useAuth.setState({
      demoMode: false,
      user: {
        userId: "operator-1",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "csrf",
      },
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  test("joins the inventory list for a real Target/Amount, and marks a join-miss unavailable rather than a dash or zero", async () => {
    stubActivity();
    renderOverview();

    const matchedRow = (await screen.findByText("op-attn-matched")).closest("tr")!;
    expect(within(matchedRow).getByText("12.5000")).toBeInTheDocument();
    expect(within(matchedRow).getByText("zkz1deadbeef")).toBeInTheDocument();

    const unmatchedRow = screen.getByText("op-attn-unmatched").closest("tr")!;
    expect(within(unmatchedRow).getAllByText("unavailable")).toHaveLength(2);
    expect(within(unmatchedRow).queryByText("—")).not.toBeInTheDocument();
    expect(within(unmatchedRow).queryByText("0")).not.toBeInTheDocument();
  });

  test("tabs filter the table by real operation state and the active tab reflects it", async () => {
    stubActivity();
    renderOverview();
    await screen.findByText("op-attn-matched");

    const inFlightTab = screen.getByRole("button", { name: /In-flight/ });
    fireEvent.click(inFlightTab);
    expect(inFlightTab).toHaveClass("on");
    expect(await screen.findByText("op-inflight-1")).toBeInTheDocument();
    expect(screen.queryByText("op-attn-matched")).not.toBeInTheDocument();

    const settledTab = screen.getByRole("button", { name: "Settled" });
    fireEvent.click(settledTab);
    expect(settledTab).toHaveClass("on");
    expect(await screen.findByText("op-attn-matched")).toBeInTheDocument();
    expect(screen.queryByText("op-inflight-1")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "All" }));
    expect(await screen.findByText("op-attn-matched")).toBeInTheDocument();
    expect(screen.getByText("op-inflight-1")).toBeInTheDocument();
  });

  test("Export produces a real CSV of the rows on screen, not a no-op", async () => {
    stubActivity();
    const createObjectURL = vi.fn(() => "blob:mock-url");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    renderOverview();
    await screen.findByText("op-attn-matched");
    fireEvent.click(screen.getByRole("button", { name: "Export" }));

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(click).toHaveBeenCalledTimes(1);
    const blob = createObjectURL.mock.calls[0]![0] as Blob;
    const csv = await blob.text();
    expect(csv).toContain('"Type","Reference","Target","Amount","Status","When"');
    expect(csv).toContain("op-attn-matched");
    expect(csv).toContain("12.5000");
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:mock-url");
  });

  test("Export is disabled when the active tab has no rows to export", async () => {
    stubActivity([], []);
    renderOverview();
    await waitFor(() => expect(screen.getByText("No activity yet")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Export" })).toBeDisabled();
  });

  test.each(["=SUM(A1:A9)", "+1+1", "-1+1", "@SUM(1+1)"])(
    "Export neutralizes a hostile leading %s in an operation string rather than exporting a live formula",
    async (hostile) => {
      stubActivity([], [{ ...OP_MATCHED, destination_address: hostile }]);
      const createObjectURL = vi.fn(() => "blob:mock-url");
      Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
      Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
      vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

      renderOverview();
      fireEvent.click(screen.getByRole("button", { name: "All" }));
      await screen.findByText("op-attn-matched");
      fireEvent.click(screen.getByRole("button", { name: "Export" }));

      const blob = createObjectURL.mock.calls[0]![0] as Blob;
      const csv = await blob.text();
      expect(csv).toContain(`"'${hostile}"`);
      expect(csv).not.toContain(`"${hostile}"`);
    },
  );

  function stubPaginatedOperations(
    pages: readonly { data: readonly Record<string, unknown>[]; has_more: boolean; next_cursor: string | null }[],
  ) {
    vi.spyOn(money, "listWalletsInventory").mockResolvedValue({ data: [], live: true });
    vi.spyOn(money, "fetchHaltState").mockResolvedValue(CLEAR);
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.includes("/operations/needs-attention")) {
        return new Response(JSON.stringify({
          operations: [],
          summary: { total: 0, by_classification: {}, p0_invariant_breach: 0 },
        }), { status: 200 });
      }
      if (path.includes("/operations")) {
        const after = new URL(path, "http://localhost").searchParams.get("after");
        const page = after === null
          ? pages[0]!
          : pages.find((p, i) => pages[i - 1]?.next_cursor === after)!;
        return new Response(JSON.stringify({ object: "list", ...page }), { status: 200 });
      }
      return new Response(
        JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
        { status: 200 },
      );
    }));
  }

  test("walks every /operations page instead of silently truncating to page one", async () => {
    const pageTwoOp = { ...OP_INFLIGHT, operation_id: "op-page-two" };
    stubPaginatedOperations([
      { data: [OP_MATCHED], has_more: true, next_cursor: "cursor-1" },
      { data: [pageTwoOp], has_more: false, next_cursor: null },
    ]);
    renderOverview();

    fireEvent.click(await screen.findByRole("button", { name: "All" }));
    expect(await screen.findByText("op-attn-matched")).toBeInTheDocument();
    expect(await screen.findByText("op-page-two")).toBeInTheDocument();
  });
});

describe("OverviewPage health honesty", () => {
  function stubInventoryAndHealth(opts: {
    healthStatus?: "ready" | "degraded" | "not_ready";
    healthThrows?: boolean;
    healthHang?: boolean;
  } = {}) {
    const { healthStatus, healthThrows, healthHang } = opts;
    vi.spyOn(money, "listWalletsInventory").mockResolvedValue({ data: [], live: true });
    vi.spyOn(money, "fetchHaltState").mockResolvedValue(CLEAR);
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/health/ready")) {
        if (healthHang) {
          return new Promise<Response>(() => {}); // never resolves → "checking"
        }
        if (healthThrows) {
          throw new Error("network down");
        }
        return new Response(JSON.stringify({
          status: healthStatus ?? "ready",
          version: "0.0.0-test",
          timestamp: new Date().toISOString(),
          checks: [],
        }), { status: healthStatus === "ready" ? 200 : 503 });
      }
      if (path.endsWith("/operations/needs-attention")) {
        return new Response(JSON.stringify({
          operations: [],
          summary: { total: 0, by_classification: {}, p0_invariant_breach: 0 },
        }), { status: 200 });
      }
      return new Response(
        JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
        { status: 200 },
      );
    }));
  }

  beforeEach(() => {
    useAuth.setState({
      demoMode: false,
      user: {
        userId: "operator-1",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "csrf",
      },
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  test("renders 'Node is healthy' only when /health/ready reports status=ready", async () => {
    stubInventoryAndHealth({ healthStatus: "ready" });
    renderOverview();
    await screen.findByText(/Node is healthy/);
    expect(screen.queryByText(/Node is degraded/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Node is offline/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Checking node health/)).not.toBeInTheDocument();
  });

  test("renders 'Node is degraded' and never 'Node is healthy' when /health/ready reports degraded", async () => {
    stubInventoryAndHealth({ healthStatus: "degraded" });
    renderOverview();
    await screen.findByText(/Node is degraded/);
    expect(screen.queryByText(/Node is healthy/)).not.toBeInTheDocument();
  });

  test("renders 'Node is degraded' and never 'Node is healthy' when /health/ready reports not_ready", async () => {
    stubInventoryAndHealth({ healthStatus: "not_ready" });
    renderOverview();
    await screen.findByText(/Node is degraded/);
    expect(screen.queryByText(/Node is healthy/)).not.toBeInTheDocument();
  });

  test("renders 'Node is offline' and never 'Node is healthy' when /health/ready fetch throws", async () => {
    stubInventoryAndHealth({ healthThrows: true });
    renderOverview();
    await screen.findByText(/Node is offline/);
    expect(screen.queryByText(/Node is healthy/)).not.toBeInTheDocument();
  });

  test("renders 'Checking node health' and never 'Node is healthy' while /health/ready is still pending", async () => {
    stubInventoryAndHealth({ healthHang: true });
    renderOverview();
    await screen.findByText(/Checking node health/);
    expect(screen.queryByText(/Node is healthy/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Node is degraded/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Node is offline/)).not.toBeInTheDocument();
  });
});

describe("OverviewPage readiness checklist", () => {
  beforeEach(() => {
    useAuth.setState({
      demoMode: false,
      user: {
        userId: "operator-1",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "csrf",
      },
    });
    stubUnrelatedInventory();
    vi.spyOn(money, "fetchHaltState").mockResolvedValue(CLEAR);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  test("renders checklist with recovery row deep-link", async () => {
    renderOverview();
    expect(await screen.findByTestId("readiness-checklist")).toBeInTheDocument();
    const row = await screen.findByTestId("readiness-row-recovery_verified_wallet");
    expect(row).toHaveAttribute("data-status", "blocked");
    expect(row).toHaveTextContent(/No recovery stamps yet|Test backup/i);
    const fix = within(row).getByRole("link", {
      name: /Test backup|Fix|Open|Verify backup again/i,
    });
    expect(fix).toHaveAttribute("href", "/recovery-ceremony");
  });

  test("collapses row list when nothing is blocked (day-0 complete)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input);
        let body: unknown = { object: "list", data: [], has_more: false, next_cursor: null };
        if (path.endsWith("/operations/needs-attention")) {
          body = {
            operations: [],
            summary: { total: 0, by_classification: {}, p0_invariant_breach: 0 },
          };
        } else if (path.includes("/readiness")) {
          body = {
            object: "readiness_checklist",
            generated_at: "2026-08-03T00:00:00.000Z",
            rows: [
              {
                id: "node_healthy",
                status: "ok",
                title: "Node health",
                detail: "Ready",
                href: "/",
              },
              {
                id: "recovery_verified_wallet",
                status: "ok",
                title: "Recovery verified",
                detail: "3 wallet(s) recovery-verified",
                href: "/recovery-ceremony",
              },
              {
                id: "backup_health",
                status: "unknown",
                title: "Backup health",
                detail: "Schedule markers unavailable",
                href: "/backup",
              },
            ],
          };
        } else if (path.startsWith("/health/ready")) {
          body = { status: "ready", version: "t", timestamp: "2026-08-03T00:00:00.000Z", checks: [] };
        }
        return new Response(JSON.stringify(body), { status: 200 });
      }),
    );
    renderOverview();
    expect(await screen.findByTestId("readiness-all-clear")).toBeInTheDocument();
    const section = screen.getByTestId("readiness-checklist");
    expect(section).toHaveAttribute("data-collapsed", "true");
    expect(screen.queryByTestId("readiness-row-node_healthy")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("readiness-toggle-details"));
    expect(await screen.findByTestId("readiness-row-node_healthy")).toBeInTheDocument();
    expect(section).toHaveAttribute("data-collapsed", "false");
  });
});

describe("OverviewPage pack checklist", () => {
  beforeEach(() => {
    localStorage.clear();
    useAuth.setState({
      demoMode: false,
      user: {
        userId: "u1",
        username: "op",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "csrf",
      },
    });
    stubUnrelatedInventory();
    vi.spyOn(money, "fetchHaltState").mockResolvedValue(CLEAR);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  test("Home gains pack rows when M enabled; none when X-only", async () => {
    renderOverview();
    expect(screen.queryByTestId("pack-checklist")).not.toBeInTheDocument();
    cleanup();
    saveEnabledPacks(["M", "T", "P"]);
    renderOverview();
    const section = await screen.findByTestId("pack-checklist");
    expect(section).toBeInTheDocument();
    expect(screen.getByTestId("pack-checklist-row-pack_m_connect_kit")).toHaveTextContent(
      /verification-complete/i,
    );
    expect(screen.getByTestId("pack-checklist-row-pack_t_blessed_sink")).toHaveTextContent(/Bless/i);
    expect(screen.getByTestId("pack-checklist-row-pack_p_approve_not_paid")).toHaveTextContent(
      /not paid/i,
    );
    expect(section.textContent).not.toMatch(/\bSessions\b/);
    expect(section.textContent).not.toMatch(/\bSweeps\b/);
    expect(section.textContent).not.toMatch(/\bOrders\b/);
  });
});
