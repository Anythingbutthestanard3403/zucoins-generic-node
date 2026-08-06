/** @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PwaInstallWall } from "./PwaInstallWall.js";
import * as pwa from "../lib/pwa.js";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("PwaInstallWall", () => {
  it("QR payload is node origin URL only", () => {
    vi.spyOn(pwa, "nodeOriginInstallUrl").mockReturnValue("https://node.example/");
    vi.spyOn(pwa, "observePwaInstallEvidence").mockReturnValue(null);
    vi.spyOn(pwa, "isStandaloneDisplay").mockReturnValue(false);

    render(
      <PwaInstallWall csrf="csrf-1" allowBrowserTabSetup={false} onInstalled={() => undefined} />,
    );

    const qr = screen.getByTestId("pwa-install-qr");
    expect(qr.getAttribute("data-install-url")).toBe("https://node.example/");
    expect(screen.getByTestId("pwa-install-url")).toHaveTextContent("https://node.example/");
    expect(screen.queryByTestId("pwa-lab-skip")).toBeNull();
  });

  it("does not show skip unless lab allow_browser_tab_setup", () => {
    vi.spyOn(pwa, "observePwaInstallEvidence").mockReturnValue(null);
    vi.spyOn(pwa, "isStandaloneDisplay").mockReturnValue(false);

    const { rerender } = render(
      <PwaInstallWall csrf="c" allowBrowserTabSetup={false} onInstalled={() => undefined} />,
    );
    expect(screen.queryByTestId("pwa-lab-skip")).toBeNull();

    rerender(
      <PwaInstallWall csrf="c" allowBrowserTabSetup onInstalled={() => undefined} />,
    );
    expect(screen.getByTestId("pwa-lab-skip")).toBeInTheDocument();
  });

  it("posts evidence enum when display-mode is standalone", async () => {
    vi.spyOn(pwa, "observePwaInstallEvidence").mockReturnValue("standalone");
    vi.spyOn(pwa, "isStandaloneDisplay").mockReturnValue(true);
    const report = vi.spyOn(pwa, "reportPwaInstalled").mockResolvedValue({ pwa_installed: true });
    const onInstalled = vi.fn();

    render(<PwaInstallWall csrf="csrf-x" allowBrowserTabSetup={false} onInstalled={onInstalled} />);

    await waitFor(() => {
      expect(report).toHaveBeenCalledWith("standalone", "csrf-x");
      expect(onInstalled).toHaveBeenCalled();
    });
  });

  it("continue button refuses when still a browser tab", async () => {
    vi.spyOn(pwa, "observePwaInstallEvidence").mockReturnValue(null);
    vi.spyOn(pwa, "isStandaloneDisplay").mockReturnValue(false);
    vi.spyOn(pwa, "reportPwaInstalled").mockResolvedValue({ pwa_installed: true });

    render(
      <PwaInstallWall csrf="c" allowBrowserTabSetup={false} onInstalled={() => undefined} />,
    );

    const cont = await screen.findByLabelText(/Continue after opening installed app/i);
    fireEvent.click(cont);
    expect(await screen.findByText(/not running as an installed app/i)).toBeInTheDocument();
    expect(pwa.reportPwaInstalled).not.toHaveBeenCalled();
  });
});

describe("nodeOriginInstallUrl", () => {
  it("is origin + slash with no query secrets", () => {
    expect(pwa.nodeOriginInstallUrl({ origin: "https://ops.example.com" })).toBe(
      "https://ops.example.com/",
    );
    expect(pwa.nodeOriginInstallUrl({ origin: "https://ops.example.com/" })).toBe(
      "https://ops.example.com/",
    );
  });
});
