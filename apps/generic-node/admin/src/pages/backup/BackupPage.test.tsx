import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router";
import { BackupPage } from "./BackupPage.js";

function renderPage() {
  return render(
    <MemoryRouter>
      <BackupPage />
    </MemoryRouter>,
  );
}

describe("BackupPage honesty", () => {
  afterEach(() => cleanup());

  it("shows both controls disabled, DR host path, Recovery link, with no fake success copy", () => {
    renderPage();

    const exportBtn = screen.getByRole("button", { name: /export backup/i });
    const importBtn = screen.getByRole("button", { name: /import backup/i });

    expect(exportBtn).toBeDisabled();
    expect(exportBtn).toHaveAttribute("aria-disabled", "true");
    expect(importBtn).toBeDisabled();
    expect(importBtn).toHaveAttribute("aria-disabled", "true");

    expect(screen.getByText(/dist\/dr\/cli\.js/)).toBeInTheDocument();
    expect(screen.getByText(/Backup is not recovery verification/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^Recovery$/i })).toHaveAttribute(
      "href",
      "/recovery-ceremony",
    );
    expect(screen.queryByText(/\(demo\)/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/requested|completed/i)).not.toBeInTheDocument();
  });

  it("never opens a TOTP prompt or renders success copy when the disabled controls are clicked", () => {
    renderPage();

    fireEvent.click(screen.getByRole("button", { name: /export backup/i }));
    fireEvent.click(screen.getByRole("button", { name: /import backup/i }));

    expect(screen.queryByText(/confirm the operator/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/\(demo\)/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/requested|completed/i)).not.toBeInTheDocument();
  });
});
