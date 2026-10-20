import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { SettingsPage } from "./SettingsPage.js";

vi.mock("../../lib/api.js", () => ({
  apiSoftRead: vi.fn(async (_path: string, fallback: unknown) => ({
    data: fallback,
    live: false,
  })),
}));

vi.mock("../../store/auth.js", () => ({
  useAuth: (sel: (s: { user: null }) => unknown) => sel({}),
}));

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: 0 } } });
  return render(
    <QueryClientProvider client={qc}>
      <SettingsPage />
    </QueryClientProvider>,
  );
}

describe("SettingsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders allowlisted support fields (read-only)", async () => {
    renderPage();
    expect(screen.getByRole("heading", { name: "Settings" })).toBeTruthy();
    await waitFor(() => {
      expect(screen.getByText("Public base URL")).toBeTruthy();
    });
    expect(screen.getByText("Node ID")).toBeTruthy();
    expect(screen.getByText("Gateway hosts")).toBeTruthy();
    expect(screen.getByText("Version")).toBeTruthy();
    expect(screen.getByText("Backup schedule")).toBeTruthy();
    expect(screen.getByText("Push configured")).toBeTruthy();
    // Security, recovery & policy module links
    expect(screen.getByTestId("settings-admin-links")).toBeTruthy();
    expect(screen.getByTestId("settings-link-devices").getAttribute("href")).toBe("/devices");
    expect(screen.getByTestId("settings-link-backup").getAttribute("href")).toBe("/backup");
    expect(screen.getByTestId("settings-link-recovery-ceremony").getAttribute("href")).toBe("/recovery-ceremony");
    expect(screen.getByTestId("settings-link-operator-security").getAttribute("href")).toBe("/operator-security");
    expect(screen.getByTestId("settings-link-reporting-keys").getAttribute("href")).toBe("/reporting-keys");
    expect(screen.getByTestId("settings-link-auto-approve").getAttribute("href")).toBe("/auto-approve");
    expect(screen.getByTestId("settings-link-verification-mode").getAttribute("href")).toBe("/verification-mode");
    expect(screen.getByTestId("settings-link-api-keys").getAttribute("href")).toBe("/api-keys");
    // No edit controls
    expect(screen.queryByRole("button", { name: /save|edit|update/i })).toBeNull();
    expect(screen.queryByRole("textbox")).toBeNull();
  });
});
