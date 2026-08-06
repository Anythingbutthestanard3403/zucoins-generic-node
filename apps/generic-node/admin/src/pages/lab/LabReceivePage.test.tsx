import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { LabReceivePage } from "./LabReceivePage.js";

vi.mock("../../store/auth.js", () => ({
  useAuth: (sel: (s: { demoMode: boolean }) => unknown) => sel({ demoMode: false }),
}));

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
    // explicit no false paid messaging
    expect(body).toMatch(/never treat this screen as "paid"|not settlement|not paid/i);
  });
});
