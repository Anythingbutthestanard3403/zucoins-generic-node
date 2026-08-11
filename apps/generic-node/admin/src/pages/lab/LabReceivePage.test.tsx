import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LabReceivePage } from "./LabReceivePage.js";
import { ApiError } from "../../lib/api.js";

const apiMock = vi.fn();

vi.mock("../../store/auth.js", () => ({
  useAuth: Object.assign(
    (sel: (s: { user: null }) => unknown) => sel({}),
    { getState: () => ({ user: { csrfToken: "tok" } }) },
  ),
}));

vi.mock("../../lib/api.js", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api.js")>("../../lib/api.js");
  return {
    ...actual,
    api: (...args: unknown[]) => apiMock(...args),
  };
});

vi.mock("../../lib/money.js", () => ({
  fetchReadinessChecklist: async () => ({
    object: "readiness_checklist",
    generated_at: new Date().toISOString(),
    rows: [
      {
        id: "recovery_verified_wallet",
        status: "ok",
        title: "Recovery-verified wallet",
        detail: "ok",
        href: "/recovery-ceremony",
      },
    ],
  }),
}));

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <LabReceivePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("LabReceivePage", () => {
  afterEach(() => cleanup());
  beforeEach(() => {
    apiMock.mockReset();
  });

  it("shows lab/non-production banner and cap", () => {
    renderPage();
    expect(screen.getByTestId("lab-banner").textContent).toMatch(/Lab \/ non-production/i);
    expect(screen.getByTestId("lab-banner").textContent).toMatch(/Wake ≠ proof|Wake ≠ proof/i);
    expect(screen.getByTestId("lab-receive-form")).toBeInTheDocument();
    expect(screen.getByLabelText(/Lab receive amount/i)).toHaveValue("0.01");
  });

  it("does not claim paid in copy", () => {
    renderPage();
    const body = document.body.textContent ?? "";
    expect(body.toLowerCase()).not.toMatch(/\bpaid\b(?!)/);
    expect(body).toMatch(/never treat this screen as "paid"|not settlement|not paid/i);
  });

  it("clears the reporting seed from the input on mutation error (ZTR-1168)", async () => {
    apiMock.mockRejectedValueOnce(
      new ApiError(400, {
        error: { code: "validation_error", message: "lab refused" },
      }),
    );
    renderPage();
    const q = (label: string) =>
      document.querySelector(`[aria-label="${label}"]`) as HTMLInputElement;
    const seed = q("Reporting private seed hex");
    fireEvent.change(seed, { target: { value: "deadbeefcafebabe" } });
    expect(seed.value).toBe("deadbeefcafebabe");
    fireEvent.change(q("Reporting key id"), {
      target: { value: "00000000-0000-4000-8000-000000000099" },
    });
    fireEvent.change(q("TOTP code"), { target: { value: "123456" } });
    fireEvent.submit(screen.getByTestId("lab-receive-form"));
    await waitFor(() => {
      expect(apiMock).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(q("Reporting private seed hex").value).toBe("");
    });
  });
});
