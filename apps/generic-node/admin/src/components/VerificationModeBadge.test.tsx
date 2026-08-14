import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { VerificationModeBadge } from "./VerificationModeBadge.js";

describe("VerificationModeBadge", () => {
  it("renders plain-language labels for both modes", () => {
    const { rerender } = render(<VerificationModeBadge mode="INDEPENDENT" />);
    expect(screen.getByTestId("verification-mode-badge-independent")).toHaveTextContent(
      "Independent",
    );

    rerender(<VerificationModeBadge mode="NODE_VERIFIED" />);
    expect(screen.getByTestId("verification-mode-badge-node_verified")).toHaveTextContent(
      "Node-verified",
    );
  });

  it("defaults missing mode to independent", () => {
    render(<VerificationModeBadge mode={null} />);
    expect(screen.getByTestId("verification-mode-badge-independent")).toBeTruthy();
  });
});
