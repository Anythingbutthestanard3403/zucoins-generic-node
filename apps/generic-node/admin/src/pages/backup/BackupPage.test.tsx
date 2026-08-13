import { cleanup, render, screen } from "@testing-library/react";
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

  it("is host-CLI only: DR path, Recovery link, no mounted export/import controls", () => {
    renderPage();

    // Dashboard export/import buttons are intentionally not mounted.
    expect(screen.queryByRole("button", { name: /export backup/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /import backup/i })).not.toBeInTheDocument();

    expect(screen.getByText(/dist\/dr\/cli\.js/)).toBeInTheDocument();
    expect(screen.getByText(/Backup is not recovery verification/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^Recovery$/i })).toHaveAttribute(
      "href",
      "/recovery-ceremony",
    );
    expect(screen.getByRole("link", { name: /Open recovery ceremony/i })).toHaveAttribute(
      "href",
      "/recovery-ceremony",
    );
    expect(screen.queryByText(/\(demo\)/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/requested|completed/i)).not.toBeInTheDocument();
  });

  it("never renders TOTP prompt or success copy on the host-CLI backup surface", () => {
    renderPage();

    expect(screen.queryByText(/confirm the operator/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/\(demo\)/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/requested|completed/i)).not.toBeInTheDocument();
  });
});
