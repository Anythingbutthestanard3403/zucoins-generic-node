import { describe, expect, it } from "vitest";
import { ApiError } from "./api.js";
import { formatApproveFailure } from "./approve-device-sign.js";

describe("formatApproveFailure", () => {
  it("surfaces dual-control same operator distinctly", () => {
    const err = new ApiError(401, {
      error: {
        code: "same_operator_both_sides",
        message: "Two-human dual control requires a different admin operator.",
      },
    });
    expect(formatApproveFailure(err)).toMatch(/different admin operator/i);
  });

  it("maps opaque approval_rejected without inventing factor detail", () => {
    const err = new ApiError(401, {
      error: { code: "approval_rejected", message: "approval rejected" },
    });
    expect(formatApproveFailure(err)).toMatch(/approval rejected/i);
  });

  it("hints device when message mentions device", () => {
    const err = new ApiError(401, {
      error: { code: "approval_rejected", message: "device signature missing" },
    });
    expect(formatApproveFailure(err)).toMatch(/Device signature required/i);
  });
});
