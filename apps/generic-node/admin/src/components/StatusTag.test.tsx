import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatusTag } from "./StatusTag.js";

describe("StatusTag wallet severity (ZTR-1255)", () => {
  it("renders QUARANTINED as danger, not muted", () => {
    render(<StatusTag status="QUARANTINED" />);
    const el = screen.getByTestId("status-tag-quarantined");
    expect(el).toHaveAttribute("data-severity", "danger");
    expect(el.className).toContain("danger");
    expect(el.className).not.toContain("muted");
  });

  it("renders AVAILABLE as ok and PINNED as warn", () => {
    const { rerender } = render(<StatusTag status="AVAILABLE" />);
    expect(screen.getByTestId("status-tag-available")).toHaveAttribute("data-severity", "ok");
    rerender(<StatusTag status="PINNED" />);
    expect(screen.getByTestId("status-tag-pinned")).toHaveAttribute("data-severity", "warn");
    rerender(<StatusTag status="RETIRED" />);
    expect(screen.getByTestId("status-tag-retired")).toHaveAttribute("data-severity", "muted");
  });

  it("does not map bare busy (undifferentiated pill removed)", () => {
    render(<StatusTag status="busy" />);
    // legacy key removed — falls through to muted unknown, not a warn "busy" synonym
    expect(screen.getByTestId("status-tag-busy")).toHaveAttribute("data-severity", "muted");
  });
});
