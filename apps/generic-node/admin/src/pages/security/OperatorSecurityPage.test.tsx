/** @vitest-environment jsdom */
// OperatorSecurityPage — honest fail-closed copy + TOTP policy setters (ZTR-1259).

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import * as money from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { TotpPromptProvider } from "../../totp/index.js";
import { OperatorSecurityPage } from "./OperatorSecurityPage.js";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <TotpPromptProvider>
        <OperatorSecurityPage />
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

async function enterTotp(digits: string) {
  const input = await screen.findByLabelText("Verification code");
  fireEvent.change(input, { target: { value: digits[0]! } });
  for (let i = 1; i < 6; i += 1) {
    const slot = screen.getByLabelText(`Digit ${i + 1}`);
    fireEvent.change(slot, { target: { value: digits[i]! } });
  }
}

afterEach(cleanup);

describe("OperatorSecurityPage", () => {
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
    vi.spyOn(money, "fetchOperatorPushStatus").mockResolvedValue({
      wired: false,
      vapid_public_key: null,
      subscriptions: [],
      note: "push optional",
    });
  });

  test("renders live dual-control and device-signature modes", async () => {
    vi.spyOn(money, "fetchDualControlPolicy").mockResolvedValue({
      mode: "two_human",
      short: "Two-human dual control",
      long: "A different admin operator must approve.",
      approve_hint: "Second human required.",
    });
    vi.spyOn(money, "fetchDeviceSignaturePolicy").mockResolvedValue({
      mode: "required",
      requires_device_signature: true,
      short: "Device signature required",
      long: "Approve needs device signature.",
      approve_hint: "TOTP + device.",
    });
    renderPage();
    expect(await screen.findByTestId("dual-control-mode")).toHaveTextContent(/Two-human/i);
    expect(screen.getByTestId("dual-control-long")).toHaveTextContent(/different admin/i);
    expect(screen.getByTestId("device-signature-mode")).toHaveTextContent(/required/i);
    expect(screen.getByTestId("device-signature-required-flag")).toHaveTextContent("yes");
    expect(screen.queryByText(/defaults to single-operator/i)).not.toBeInTheDocument();
  });

  test("unavailable dual-control names fail-closed two_human", async () => {
    vi.spyOn(money, "fetchDualControlPolicy").mockRejectedValue(new Error("network"));
    vi.spyOn(money, "fetchDeviceSignaturePolicy").mockResolvedValue({
      mode: "required",
      requires_device_signature: true,
      short: "Device signature required",
      long: "x",
      approve_hint: "y",
    });
    renderPage();
    const banner = await screen.findByTestId("dual-control-unavailable");
    expect(banner).toHaveTextContent(/fails closed to/i);
    expect(banner).toHaveTextContent(/two_human/i);
    expect(banner).not.toHaveTextContent(/single-operator/i);
  });

  test("unavailable device-signature names fail-closed required", async () => {
    vi.spyOn(money, "fetchDualControlPolicy").mockResolvedValue({
      mode: "two_human",
      short: "Two-human",
      long: "x",
      approve_hint: "y",
    });
    vi.spyOn(money, "fetchDeviceSignaturePolicy").mockRejectedValue(new Error("down"));
    renderPage();
    const banner = await screen.findByTestId("device-signature-unavailable");
    expect(banner).toHaveTextContent(/fails closed to/i);
    expect(banner).toHaveTextContent(/required/i);
  });

  test("set two-human prompts TOTP and posts mode", async () => {
    vi.spyOn(money, "fetchDualControlPolicy").mockResolvedValue({
      mode: "single_operator",
      short: "Single-operator",
      long: "One human.",
      approve_hint: "Same operator ok.",
    });
    vi.spyOn(money, "fetchDeviceSignaturePolicy").mockResolvedValue({
      mode: "optional",
      requires_device_signature: false,
      short: "Device signature optional",
      long: "optional",
      approve_hint: "totp only",
    });
    const postSpy = vi.spyOn(money, "postDualControlPolicy").mockResolvedValue({
      mode: "two_human",
      short: "Two-human dual control",
      long: "Different admin.",
      approve_hint: "Second human.",
    });
    renderPage();
    await screen.findByTestId("dual-control-mode");
    fireEvent.click(screen.getByTestId("dual-control-set-two-human"));
    await enterTotp("654321");
    await waitFor(() => expect(postSpy).toHaveBeenCalled());
    const [body, totp] = postSpy.mock.calls[0]!;
    expect(totp).toBe("654321");
    expect(body.mode).toBe("two_human");
    expect(await screen.findByTestId("security-policy-msg")).toHaveTextContent(/Dual-control set/i);
  });

  test("set device-signature required prompts TOTP and posts mode", async () => {
    vi.spyOn(money, "fetchDualControlPolicy").mockResolvedValue({
      mode: "two_human",
      short: "Two-human",
      long: "x",
      approve_hint: "y",
    });
    vi.spyOn(money, "fetchDeviceSignaturePolicy").mockResolvedValue({
      mode: "optional",
      requires_device_signature: false,
      short: "Device signature optional",
      long: "optional",
      approve_hint: "totp",
    });
    const postSpy = vi.spyOn(money, "postDeviceSignaturePolicy").mockResolvedValue({
      mode: "required",
      requires_device_signature: true,
      short: "Device signature required",
      long: "required",
      approve_hint: "device",
    });
    renderPage();
    await screen.findByTestId("device-signature-mode");
    fireEvent.click(screen.getByTestId("device-signature-set-required"));
    await enterTotp("111222");
    await waitFor(() => expect(postSpy).toHaveBeenCalled());
    const [body, totp] = postSpy.mock.calls[0]!;
    expect(totp).toBe("111222");
    expect(body.mode).toBe("required");
  });
});
