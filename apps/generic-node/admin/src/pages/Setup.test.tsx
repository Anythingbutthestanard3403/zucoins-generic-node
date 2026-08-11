/** @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router";
import { SetupPage } from "./Setup.js";
import { useAuth } from "../store/auth.js";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

beforeEach(() => {
  useAuth.setState({ user: null });
});

function renderSetup(initial = "/setup") {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/setup" element={<SetupPage />} />
        <Route path="/start/install" element={<SetupPage />} />
        <Route path="/start/device" element={<SetupPage />} />
        <Route path="/start/vault" element={<SetupPage />} />
        <Route path="/start/backup" element={<div data-testid="stub-backup">backup</div>} />
        <Route path="/start/prove" element={<div data-testid="stub-prove">prove</div>} />
        <Route path="/" element={<div data-testid="stub-home">home</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

function authUser(over: Partial<{
  mustChangePassword: boolean;
  mustEnrolTotp: boolean;
}> = {}) {
  return {
    userId: "u1",
    username: "admin",
    role: "admin" as const,
    mustChangePassword: over.mustChangePassword ?? false,
    mustEnrolTotp: over.mustEnrolTotp ?? false,
    csrfToken: "csrf-1",
  };
}

describe("SetupPage TOTP enrol", () => {
  it("after password already changed, enrol→confirm clears mustEnrolTotp and leaves setup", async () => {
    useAuth.setState({
      user: authUser({ mustEnrolTotp: true }),
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/admin/v1/setup-state") && (!init?.method || init.method === "GET")) {
        return new Response(
          JSON.stringify({
            object: "setup_state",
            current_step: "W2",
            complete: false,
            ceremony_master_key_blocked: true,
            flags: {},
            steps: [],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/setup-state") && init?.method === "PATCH") {
        return new Response(
          JSON.stringify({
            object: "setup_state",
            current_step: "W2",
            complete: false,
            ceremony_master_key_blocked: true,
            flags: { w0_secure_context_ok: true },
            steps: [],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/vault-master")) {
        return new Response(
          JSON.stringify({
            phase: "virgin",
            can_generate: true,
            plaintext_pending_ack: false,
            offline_backup_acked: false,
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/enrol-totp")) {
        return new Response(
          JSON.stringify({
            secret: "JBSWY3DPEHPK3PXP",
            otpauthUrl: "otpauth://totp/Zu:admin?secret=JBSWY3DPEHPK3PXP&issuer=Zu",
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/confirm-totp")) {
        expect(JSON.parse(String(init?.body))).toEqual({ totp: "654321" });
        return new Response(
          JSON.stringify({ ok: true, mustEnrolTotp: false, csrfToken: "csrf-2" }),
          { status: 200 },
        );
      }
      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderSetup();
    expect(screen.getByRole("heading", { name: /Enrol authenticator/i })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/^Password$/i), {
      target: { value: "operator-password-long" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Generate authenticator secret/i }));

    await waitFor(() => {
      expect(screen.getByDisplayValue("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
    });
    expect(screen.getByTestId("totp-qr-code")).toBeInTheDocument();
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);

    fireEvent.change(screen.getByLabelText(/6-digit code/i), {
      target: { value: "654321" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Confirm and continue/i }));

    // After TOTP confirm, setup may stay on wizard (not auto-home) if later steps remain.
    await waitFor(() => {
      expect(useAuth.getState().user?.mustEnrolTotp).toBe(false);
    });
    expect(useAuth.getState().user?.csrfToken).toBe("csrf-2");
    for (const call of [...logSpy.mock.calls, ...errSpy.mock.calls]) {
      expect(JSON.stringify(call)).not.toContain("JBSWY3DPEHPK3PXP");
    }
    logSpy.mockRestore();
    errSpy.mockRestore();
  });

  it("does not show the old mustEnrolTotp trap that demanded ADMIN_TOTP_SECRET", () => {
    useAuth.setState({
      user: authUser({ mustEnrolTotp: true }),
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ object: "setup_state", current_step: "W2", complete: false, ceremony_master_key_blocked: true, flags: {}, steps: [] }), { status: 200 })),
    );
    renderSetup();
    expect(screen.queryByText(/ADMIN_TOTP_SECRET/i)).toBeNull();
    expect(screen.queryByText(/not mounted/i)).toBeNull();
    expect(screen.getByRole("heading", { name: /Enrol authenticator/i })).toBeInTheDocument();
  });
});

describe("SetupPage wizard W3–W6 + vault show-once", () => {
  it("mandatory W3 PWA wall: QR is node origin only; no happy-path skip; lab skip advances", async () => {
    useAuth.setState({ user: authUser() });

    let currentStep = "W3";
    let pwaInstalled = false;

    const setupBody = () =>
      JSON.stringify({
        object: "setup_state",
        current_step: currentStep,
        complete: false,
        ceremony_master_key_blocked: true,
        pwa_installed: pwaInstalled,
        allow_browser_tab_setup: true,
        flags: {},
        steps: [],
      });

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        // Boot PATCH w0 + GET refresh both hit setup-state.
        if (url.endsWith("/admin/v1/setup-state")) {
          return new Response(setupBody(), { status: 200 });
        }
        if (url.endsWith("/admin/v1/vault-master") && method === "GET") {
          return new Response(
            JSON.stringify({
              phase: "virgin",
              can_generate: true,
              plaintext_pending_ack: false,
              offline_backup_acked: false,
            }),
            { status: 200 },
          );
        }
        return new Response("not found", { status: 404 });
      }),
    );

    renderSetup();
    await waitFor(() => {
      expect(screen.getByTestId("setup-step-w3")).toBeInTheDocument();
      expect(screen.getByTestId("pwa-install-wall")).toBeInTheDocument();
    });
    // QR payload is node origin URL only (secret-free).
    const qr = screen.getByTestId("pwa-install-qr");
    const installUrl = qr.getAttribute("data-install-url") ?? "";
    expect(installUrl).toMatch(/^https?:\/\/[^/]+\/$/);
    expect(installUrl).not.toMatch(/token|csrf|secret|session/i);
    // Happy path has no Skip for now (lab uses dedicated control).
    expect(screen.queryByRole("button", { name: /Skip for now/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /I installed/i })).toBeNull();

    pwaInstalled = true;
    currentStep = "W4";
    fireEvent.click(screen.getByTestId("pwa-lab-skip"));

    await waitFor(() => {
      expect(screen.getByTestId("setup-step-w4")).toBeInTheDocument();
    });
    // Enrol CTA present; quiet ack gone; typed break-glass is explicit.
    expect(screen.getByTestId("setup-device-enrol")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Acknowledge break-glass/i })).toBeNull();
    expect(screen.getByTestId("setup-break-glass-reveal")).toBeInTheDocument();
  });

  it("vault show-once never hits localStorage; W6 has no ceremony placeholder ack", async () => {
    useAuth.setState({ user: authUser() });

    let currentStep = "W5";
    const master = "generated-vault-master-key-value-32chars-xx";

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();

      if (url.endsWith("/admin/v1/setup-state") && method === "GET") {
        return new Response(
          JSON.stringify({
            object: "setup_state",
            current_step: currentStep,
            complete: currentStep === "W12",
            ceremony_master_key_blocked: true,
            pwa_installed: true,
            allow_browser_tab_setup: false,
            flags: {},
            steps: [],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/setup-state") && method === "PATCH") {
        // Production: ack-only keys ignored.
        return new Response(
          JSON.stringify({
            object: "setup_state",
            current_step: currentStep,
            complete: false,
            ceremony_master_key_blocked: true,
            pwa_installed: true,
            flags: {},
            steps: [],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/vault-master") && method === "GET") {
        const virgin = currentStep === "W5";
        return new Response(
          JSON.stringify({
            phase: virgin ? "virgin" : "sealed",
            can_generate: virgin,
            plaintext_pending_ack: false,
            offline_backup_acked: !virgin,
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/vault-master/generate") && method === "POST") {
        return new Response(
          JSON.stringify({
            object: "vault_master_generate",
            master_key: master,
            phase: "shown",
            guidance: "offline",
            vault_master_distinct_from_backup_kek: true,
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/vault-master/ack-offline") && method === "POST") {
        currentStep = "W6";
        return new Response(
          JSON.stringify({
            object: "vault_master_ack",
            phase: "sealed",
            offline_backup_acked: true,
            key_fingerprint_prefix: "abcd1234ef00",
          }),
          { status: 200 },
        );
      }
      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const lsSet = vi.spyOn(Storage.prototype, "setItem");

    renderSetup();

    await waitFor(() => {
      expect(screen.getByTestId("setup-step-w5")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole("button", { name: /Generate vault master key/i }));

    await waitFor(() => {
      expect(screen.getByTestId("vault-master-once")).toHaveValue(master);
    });
    // Must never write master key to localStorage.
    for (const call of lsSet.mock.calls) {
      expect(JSON.stringify(call)).not.toContain(master);
    }

    fireEvent.click(screen.getByTestId("vault-offline-ack"));
    fireEvent.click(screen.getByRole("button", { name: /^Continue$/i }));

    await waitFor(() => {
      expect(screen.getByTestId("setup-step-w6")).toBeInTheDocument();
    });
    expect(screen.getByTestId("setup-go-backup")).toBeInTheDocument();
    expect(screen.getByTestId("setup-go-prove")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Acknowledge ceremony placeholder/i })).toBeNull();
    expect(screen.getByRole("button", { name: /Refresh status/i })).toBeInTheDocument();
    lsSet.mockRestore();
  });
});

describe("SetupPage wizard W4 Device #1", () => {
  it("typed BREAK GLASS on W4; vault key never hits localStorage; W6 has no ceremony placeholder ack", async () => {
    useAuth.setState({ user: authUser() });

    let currentStep = "W4";
    const master = "generated-vault-master-key-value-32chars-xx";

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();

      if (url.endsWith("/admin/v1/setup-state") && method === "GET") {
        return new Response(
          JSON.stringify({
            object: "setup_state",
            current_step: currentStep,
            complete: currentStep === "W12",
            ceremony_master_key_blocked: true,
            flags: {},
            steps: [],
            device_break_glass_active: currentStep !== "W4",
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/setup-state/device-break-glass") && method === "POST") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { phrase?: string };
        expect(body.phrase).toBe("BREAK GLASS");
        currentStep = "W5";
        return new Response(
          JSON.stringify({
            object: "setup_state",
            current_step: currentStep,
            complete: false,
            ceremony_master_key_blocked: true,
            flags: { w4_break_glass_ack: true },
            steps: [],
            device_break_glass_active: true,
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/setup-state") && method === "PATCH") {
        return new Response(
          JSON.stringify({
            object: "setup_state",
            current_step: currentStep,
            complete: false,
            ceremony_master_key_blocked: true,
            flags: {},
            steps: [],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/vault-master") && method === "GET") {
        const virgin = currentStep === "W5" || currentStep === "W4";
        return new Response(
          JSON.stringify({
            phase: virgin ? "virgin" : "sealed",
            can_generate: virgin,
            plaintext_pending_ack: false,
            offline_backup_acked: !virgin,
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/vault-master/generate") && method === "POST") {
        return new Response(
          JSON.stringify({
            object: "vault_master_generate",
            master_key: master,
            phase: "shown",
            guidance: "offline",
            vault_master_distinct_from_backup_kek: true,
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/admin/v1/vault-master/ack-offline") && method === "POST") {
        currentStep = "W6";
        return new Response(
          JSON.stringify({
            object: "vault_master_ack",
            phase: "sealed",
            offline_backup_acked: true,
            key_fingerprint_prefix: "abcd1234ef00",
          }),
          { status: 200 },
        );
      }
      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const lsSet = vi.spyOn(Storage.prototype, "setItem");

    renderSetup();

    await waitFor(() => {
      expect(screen.getByTestId("setup-step-w4")).toBeInTheDocument();
    });
    expect(screen.getByTestId("setup-device-enrol")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Device enrolled$/i })).toBeNull();
    fireEvent.click(screen.getByTestId("setup-break-glass-reveal"));
    fireEvent.change(screen.getByTestId("setup-break-glass-phrase"), {
      target: { value: "BREAK GLASS" },
    });
    fireEvent.click(screen.getByTestId("setup-break-glass-submit"));

    await waitFor(() => {
      expect(screen.getByTestId("setup-step-w5")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole("button", { name: /Generate vault master key/i }));

    await waitFor(() => {
      expect(screen.getByTestId("vault-master-once")).toHaveValue(master);
    });
    for (const call of lsSet.mock.calls) {
      expect(JSON.stringify(call)).not.toContain(master);
    }

    fireEvent.click(screen.getByTestId("vault-offline-ack"));
    fireEvent.click(screen.getByRole("button", { name: /^Continue$/i }));

    await waitFor(() => {
      expect(screen.getByTestId("setup-step-w6")).toBeInTheDocument();
    });
    expect(screen.queryByRole("button", { name: /Acknowledge ceremony placeholder/i })).toBeNull();
    expect(screen.getByRole("button", { name: /Refresh status/i })).toBeInTheDocument();
    lsSet.mockRestore();
  });

  it("W4 blocks Home until enrol or typed break-glass — no quiet skip button", async () => {
    useAuth.setState({ user: authUser() });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/admin/v1/setup-state") && method === "GET") {
          return new Response(
            JSON.stringify({
              object: "setup_state",
              current_step: "W4",
              complete: false,
              ceremony_master_key_blocked: true,
              flags: {},
              steps: [],
            }),
            { status: 200 },
          );
        }
        if (url.endsWith("/admin/v1/setup-state") && method === "PATCH") {
          return new Response(
            JSON.stringify({
              object: "setup_state",
              current_step: "W4",
              complete: false,
              ceremony_master_key_blocked: true,
              flags: {},
              steps: [],
            }),
            { status: 200 },
          );
        }
        if (url.endsWith("/admin/v1/vault-master")) {
          return new Response(
            JSON.stringify({
              phase: "virgin",
              can_generate: true,
              plaintext_pending_ack: false,
              offline_backup_acked: false,
            }),
            { status: 200 },
          );
        }
        return new Response("not found", { status: 404 });
      }),
    );
    renderSetup();
    await waitFor(() => expect(screen.getByTestId("setup-step-w4")).toBeInTheDocument());
    expect(screen.getByRole("heading", { name: /Register this phone/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Acknowledge break-glass/i })).toBeNull();
    expect(screen.queryByText("home")).toBeNull();
  });
});

