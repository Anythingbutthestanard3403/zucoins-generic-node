/** @vitest-environment jsdom */
// HaltAction — confirm + TOTP gate for GET/POST /admin/v1/halt.

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { ApiError } from "../../lib/api.js";
import * as money from "../../lib/money.js";
import { TotpPromptProvider } from "../../totp/index.js";
import { HaltAction } from "./HaltAction.js";
import type { HaltState } from "../../lib/money.js";

function renderAction(state: HaltState | undefined, loading = false) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <TotpPromptProvider>
        <HaltAction state={state} loading={loading} />
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

async function enterCodeAndSubmit(code: string) {
  const input = await screen.findByLabelText("Verification code");
  fireEvent.change(input, { target: { value: code[0]! } });
  // Slot TOTP auto-submits on full 6 digits; spread remaining.
  for (let i = 1; i < 6; i += 1) {
    const slot = screen.getByLabelText(i === 0 ? "Verification code" : `Digit ${i + 1}`);
    fireEvent.change(slot, { target: { value: code[i]! } });
  }
}

const DISENGAGED: HaltState = {
  engaged: false,
  reason: null,
  updated_at: null,
  updated_by: null,
};

const ENGAGED: HaltState = {
  engaged: true,
  reason: "gateway discrepancy under investigation",
  updated_at: "2026-07-17T00:00:00Z",
  updated_by: "user_1",
};

afterEach(cleanup);

describe("HaltAction", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  test("renders the disengaged (running) state", () => {
    renderAction(DISENGAGED);
    expect(screen.getByText("Running")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Halt engines" })).toBeInTheDocument();
  });

  test("renders the engaged (halted) state with its reason", () => {
    renderAction(ENGAGED);
    expect(screen.getByText("Halted")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Resume engines" })).toBeInTheDocument();
    expect(screen.getByText(/gateway discrepancy under investigation/)).toBeInTheDocument();
  });

  test("confirm is disabled until the checkbox is checked, and TOTP is required before the request fires", async () => {
    const spy = vi.spyOn(money, "postHaltToggle").mockResolvedValue(ENGAGED);

    renderAction(DISENGAGED);
    fireEvent.click(screen.getByRole("button", { name: "Halt engines" }));

    expect(await screen.findByText(/halts new automated/i)).toBeInTheDocument();
    const confirmButton = screen.getByRole("button", { name: "Confirm halt" });
    expect(confirmButton).toBeDisabled();

    fireEvent.click(screen.getByRole("checkbox"));
    expect(confirmButton).toBeEnabled();

    fireEvent.click(confirmButton);
    expect(await screen.findByLabelText("Verification code")).toBeInTheDocument();
    expect(spy).not.toHaveBeenCalled();

    await enterCodeAndSubmit("123456");
    await vi.waitFor(() => expect(spy).toHaveBeenCalled());
  });

  test("submits the documented POST body + fresh TOTP on engage", async () => {
    const spy = vi.spyOn(money, "postHaltToggle").mockResolvedValue(ENGAGED);

    renderAction(DISENGAGED);
    fireEvent.click(screen.getByRole("button", { name: "Halt engines" }));
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "incident #42" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirm halt" }));
    await enterCodeAndSubmit("654321");

    await vi.waitFor(() =>
      expect(spy).toHaveBeenCalledWith({ engaged: true, reason: "incident #42" }, "654321"),
    );
  });

  test("submits disengage with the same TOTP gate as engage", async () => {
    const spy = vi.spyOn(money, "postHaltToggle").mockResolvedValue(DISENGAGED);

    renderAction(ENGAGED);
    fireEvent.click(screen.getByRole("button", { name: "Resume engines" }));
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Confirm resume" }));
    await enterCodeAndSubmit("111111");

    await vi.waitFor(() => expect(spy).toHaveBeenCalledWith({ engaged: false }, "111111"));
  });

  test("surfaces ApiError without blind-retrying a non-TOTP failure", async () => {
    const spy = vi
      .spyOn(money, "postHaltToggle")
      .mockRejectedValue(
        new ApiError(503, { error: { code: "service_unavailable", message: "down" } }),
      );

    renderAction(DISENGAGED);
    fireEvent.click(screen.getByRole("button", { name: "Halt engines" }));
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Confirm halt" }));
    await enterCodeAndSubmit("123456");

    await vi.waitFor(() => {
      expect(spy).toHaveBeenCalledTimes(1);
    });
    // Non-TOTP failures surface once on the card (no re-prompt burn loop).
    await vi.waitFor(() => {
      expect(screen.queryByLabelText("Verification code")).not.toBeInTheDocument();
    });
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
