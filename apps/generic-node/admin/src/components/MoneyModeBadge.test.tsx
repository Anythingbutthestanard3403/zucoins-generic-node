import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MoneyModeBadge } from "./MoneyModeBadge.js";

describe("MoneyModeBadge", () => {
  it("renders plain-language labels for all four presets", () => {
    const { rerender } = render(<MoneyModeBadge mode="FULL" />);
    expect(screen.getByTestId("money-mode-badge-full")).toHaveTextContent("Full");

    rerender(<MoneyModeBadge mode="RECEIVE_ONLY" />);
    expect(screen.getByTestId("money-mode-badge-receive_only")).toHaveTextContent("Receive only");

    rerender(<MoneyModeBadge mode="SEND_ONLY" />);
    expect(screen.getByTestId("money-mode-badge-send_only")).toHaveTextContent("Send only");

    rerender(<MoneyModeBadge mode="INTERNAL_ONLY" />);
    expect(screen.getByTestId("money-mode-badge-internal_only")).toHaveTextContent(
      "Internal only",
    );
  });
});
