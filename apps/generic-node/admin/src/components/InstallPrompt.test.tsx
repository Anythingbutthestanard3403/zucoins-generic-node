import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { INSTALL_DISMISS_KEY } from "../lib/pwa.js";
import { InstallHomeNudge, InstallPrompt } from "./InstallPrompt.js";
import { OfflineBanner } from "./OfflineBanner.js";

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.restoreAllMocks();
});

describe("InstallPrompt a11y", () => {
  it("exposes labelled Install and Not now actions and is skippable", () => {
    const onClose = vi.fn();
    render(<InstallPrompt open onClose={onClose} />);
    expect(screen.getByRole("dialog", { name: /Install Zu Node/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Not now — skip installing Zu Node/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Not now — skip installing Zu Node/i }));
    expect(onClose).toHaveBeenCalled();
    expect(localStorage.getItem(INSTALL_DISMISS_KEY)).toBe("1");
  });

  it("renders nothing when closed", () => {
    const { container } = render(<InstallPrompt open={false} onClose={() => undefined} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("InstallHomeNudge", () => {
  it("shows after skip so Home can re-offer install", () => {
    localStorage.setItem(INSTALL_DISMISS_KEY, "1");
    render(<InstallHomeNudge />);
    expect(screen.getByRole("region", { name: /Install Zu Node/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Install Zu Node on this device|How to install/i })).toBeInTheDocument();
  });

  it("hides when install was never skipped", () => {
    const { container } = render(<InstallHomeNudge />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("OfflineBanner honesty", () => {
  it("states node unreachable when offline and never implies live balances", () => {
    render(<OfflineBanner healthState="offline" />);
    const el = screen.getByTestId("offline-honesty-banner");
    expect(el).toHaveTextContent(/Node unreachable/i);
    expect(el).toHaveTextContent(/never treat offline UI as live money state/i);
    expect(el.textContent).not.toMatch(/1248|demo balance|Healthy/i);
  });

  it("states degraded without claiming verified money state", () => {
    render(<OfflineBanner healthState="degraded" />);
    expect(screen.getByTestId("offline-honesty-banner")).toHaveTextContent(/Node degraded/i);
  });

  it("is silent when healthy or checking", () => {
    const { rerender, container } = render(<OfflineBanner healthState="healthy" />);
    expect(container).toBeEmptyDOMElement();
    rerender(<OfflineBanner healthState="checking" />);
    expect(container).toBeEmptyDOMElement();
  });
});
