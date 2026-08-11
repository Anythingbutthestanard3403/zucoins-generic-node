/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TotpPromptProvider } from "../../totp/TotpPromptProvider.js";
import { useAuth } from "../../store/auth.js";
import * as money from "../../lib/money.js";
import * as deviceCrypto from "../../lib/device-crypto.js";
import { DevicesPage } from "./DevicesPage.js";

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
          <DevicesPage />
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

describe("DevicesPage", () => {
  beforeEach(() => {
    liveSession();
    vi.restoreAllMocks();
  });
  afterEach(() => {
    cleanup();
  });

  it("lists server inventory and offers revoke", async () => {
    vi.spyOn(money, "listDeviceKeys").mockResolvedValue([
      {
        id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        label: "Phone",
        enrolled_at: "2026-07-01T00:00:00.000Z",
      },
    ]);
    renderPage();
    await waitFor(() => expect(screen.getByText("Phone")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /Revoke/i })).toBeInTheDocument();
    expect(screen.getByText(/Add another device \(QR\)/i)).toBeInTheDocument();
  });

  it("happy-path genesis enrol posts challenge + enrol with TOTP", async () => {
    vi.spyOn(money, "listDeviceKeys").mockResolvedValue([]);
    const challenge = vi.spyOn(money, "postEnrollmentChallenge").mockResolvedValue({
      nonce: "99999999-9999-4999-8999-999999999999",
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:05:00.000Z",
      purpose: "zp-device-enrol-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
    });
    const enrol = vi.spyOn(money, "postGenesisEnrol").mockResolvedValue({
      id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      label: "Operator phone",
      enrolled_at: "2026-07-18T00:00:00.000Z",
    });
    vi.spyOn(deviceCrypto, "generateDeviceKeyPair").mockResolvedValue({
      privateKey: {} as CryptoKey,
      publicKey: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
      publicKeyRaw: new Uint8Array(32),
    });
    vi.spyOn(deviceCrypto, "signPreimage").mockResolvedValue("a".repeat(86) + "==");
    vi.spyOn(deviceCrypto, "putDeviceRecord").mockResolvedValue();
    vi.spyOn(deviceCrypto, "randomUuid").mockReturnValue("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");

    renderPage();
    await waitFor(() => expect(screen.getByText(/Enrol first device/i)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Generate key & enrol with TOTP/i }));
    await enterTotp("123456");
    await waitFor(() => expect(enrol).toHaveBeenCalled());
    expect(challenge).toHaveBeenCalled();
    expect(enrol.mock.calls[0]?.[1]).toBe("123456");
    const body = enrol.mock.calls[0]?.[0];
    expect(body?.new_device_public_key).toBe("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=");
    expect(body?.challenge_nonce).toBe("99999999-9999-4999-8999-999999999999");
  });

  it("bad TOTP path never calls enrol when code invalid", async () => {
    vi.spyOn(money, "listDeviceKeys").mockResolvedValue([]);
    const enrol = vi.spyOn(money, "postGenesisEnrol");
    renderPage();
    await waitFor(() => expect(screen.getByText(/Enrol first device/i)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Generate key & enrol with TOTP/i }));
    // leave TOTP empty / cancel — mutation should not fire enrol without 6 digits
    await waitFor(() => expect(screen.getByLabelText("Verification code")).toBeInTheDocument());
    expect(enrol).not.toHaveBeenCalled();
  });

  it("deep-link challenge_id shows ceremony panel and bind path", async () => {
    vi.spyOn(money, "listDeviceKeys").mockResolvedValue([
      {
        id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        label: "Phone A",
        enrolled_at: "2026-07-01T00:00:00.000Z",
      },
    ]);
    vi.spyOn(money, "peekSecondDeviceEnrol").mockResolvedValue({
      challenge_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      status: "ISSUED",
      issued_at: "2026-08-03T12:00:00.000Z",
      expires_at: "2026-08-03T12:05:00.000Z",
      node_id: "11111111-1111-4111-8111-111111111111",
      nonce: "99999999-9999-4999-8999-999999999999",
      label: null,
      new_device_key_id: null,
      new_device_public_key: null,
      preimage_text: null,
      preimage_sha256: null,
      expired: false,
    });
    const bind = vi.spyOn(money, "bindSecondDeviceEnrol").mockResolvedValue({
      challenge_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      status: "BOUND",
      new_device_key_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      label: "Second phone",
      issued_at: "2026-08-03T12:00:00.000Z",
      expires_at: "2026-08-03T12:05:00.000Z",
      nonce: "99999999-9999-4999-8999-999999999999",
      node_id: "11111111-1111-4111-8111-111111111111",
    });
    vi.spyOn(deviceCrypto, "generateDeviceKeyPair").mockResolvedValue({
      privateKey: {} as CryptoKey,
      publicKey: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
      publicKeyRaw: new Uint8Array(32),
    });
    vi.spyOn(deviceCrypto, "putDeviceRecord").mockResolvedValue();

    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <TotpPromptProvider>
          <MemoryRouter
            initialEntries={["/devices/enrol?challenge_id=cccccccc-cccc-4ccc-8ccc-cccccccccccc"]}
          >
            <Routes>
              <Route path="/devices/enrol" element={<DevicesPage />} />
            </Routes>
          </MemoryRouter>
        </TotpPromptProvider>
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("second-device-ceremony")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("second-device-bind"));
    await waitFor(() => expect(bind).toHaveBeenCalled());
    expect(bind.mock.calls[0]?.[0]).toMatchObject({
      challenge_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      new_device_public_key: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
    });
  });

});
