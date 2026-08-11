import { describe, expect, it } from "vitest";
import {
  decideSetupStateHttp,
  decideSetupStateNetworkError,
} from "./setup-state-gate.js";

describe("decideSetupStateHttp (ZTR-1168 fail-closed day-0 gate)", () => {
  it("opens only on genuine 404 (legacy nodes without setup-state)", () => {
    expect(decideSetupStateHttp({ ok: false, status: 404 })).toEqual({ kind: "open_legacy" });
  });

  it("closes on 500 and 503", () => {
    expect(decideSetupStateHttp({ ok: false, status: 500 })).toEqual({
      kind: "closed",
      reason: "http_error",
    });
    expect(decideSetupStateHttp({ ok: false, status: 503 })).toEqual({
      kind: "closed",
      reason: "http_error",
    });
  });

  it("passes through successful responses for body parsing", () => {
    expect(decideSetupStateHttp({ ok: true, status: 200 })).toEqual({
      kind: "body",
      status: 200,
    });
  });

  it("closes on network rejection", () => {
    expect(decideSetupStateNetworkError()).toEqual({ kind: "closed", reason: "network" });
  });
});
