/** @vitest-environment jsdom */
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { TotpQrCode } from "./TotpQrCode.js";

afterEach(cleanup);

describe("TotpQrCode", () => {
  it("renders an SVG QR code with at least one dark module for an otpauth URI", () => {
    render(
      <TotpQrCode value="otpauth://totp/ZuPayments:admin?secret=JBSWY3DPEHPK3PXP&issuer=ZuPayments&algorithm=SHA1&digits=6&period=30" />,
    );
    const svg = screen.getByTestId("totp-qr-code");
    expect(svg.tagName).toBe("svg");
    expect(svg.getAttribute("role")).toBe("img");
    expect(svg.querySelectorAll("rect").length).toBeGreaterThan(0);
  });

  it("changes shape when the encoded value changes", () => {
    const { container: a } = render(<TotpQrCode value="otpauth://totp/A?secret=AAAA" />);
    const rectsA = a.querySelectorAll("rect").length;
    cleanup();
    const { container: b } = render(<TotpQrCode value="otpauth://totp/B?secret=BBBBBBBBBBBBBBBB" />);
    const rectsB = b.querySelectorAll("rect").length;
    expect(rectsA).not.toBe(rectsB);
  });

  // Oversized otpauth URI exceeds QR capacity; must not throw.
  it("renders null (no crash) when value exceeds QR capacity", () => {
    // Build a string well past the ~2.3 KB byte-mode capacity at type 0 / EC "M".
    const oversized = "otpauth://totp/ZuPayments:admin?secret=" + "A".repeat(3000);
    const { container } = render(<TotpQrCode value={oversized} />);
    expect(container.querySelector("svg")).toBeNull();
    expect(container.innerHTML).toBe("");
  });
});
