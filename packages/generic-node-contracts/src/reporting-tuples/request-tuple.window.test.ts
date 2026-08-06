// Window enforcement tests for buildReportRequestPreimage. Proves the A.5 60s window
// is enforced at mint time, matching node-core's enforceSignedWindow. Boundary: exactly 60s passes
// (inclusive ceiling, per A.8 golden); 61s and zero/negative windows are rejected.

import { describe, expect, it } from "vitest";

import {
  REPORT_REQUEST_GOLDEN_PAYLOAD,
  buildReportRequestPreimage,
  type ReportRequestPayload,
} from "./request-tuple.js";

function withWindow(issuedAt: string, expiresAt: string): ReportRequestPayload {
  return { ...REPORT_REQUEST_GOLDEN_PAYLOAD, issued_at: issuedAt, expires_at: expiresAt };
}

describe("buildReportRequestPreimage window enforcement", () => {
  it("builds successfully with a valid 30s window", () => {
    const p = withWindow("2026-07-18T00:00:00.000Z", "2026-07-18T00:00:30.000Z");
    const preimage = buildReportRequestPreimage(p);
    expect(preimage).toContain("zp-report-request-v1\n");
  });

  it("builds successfully at exactly 60s (boundary, inclusive)", () => {
    const p = withWindow("2026-07-18T00:00:00.000Z", "2026-07-18T00:01:00.000Z");
    const preimage = buildReportRequestPreimage(p);
    expect(preimage).toContain("zp-report-request-v1\n");
  });

  it("throws for a zero window (expires_at === issued_at)", () => {
    const p = withWindow("2026-07-18T00:00:00.000Z", "2026-07-18T00:00:00.000Z");
    expect(() => buildReportRequestPreimage(p)).toThrow("expires_at must be later than issued_at");
  });

  it("throws for a negative window (expires_at before issued_at)", () => {
    const p = withWindow("2026-07-18T00:01:00.000Z", "2026-07-18T00:00:00.000Z");
    expect(() => buildReportRequestPreimage(p)).toThrow("expires_at must be later than issued_at");
  });

  it("throws for a window exceeding 60s (61s)", () => {
    const p = withWindow("2026-07-18T00:00:00.000Z", "2026-07-18T00:01:01.000Z");
    expect(() => buildReportRequestPreimage(p)).toThrow("window exceeds 60 seconds");
  });

  it("throws for a non-canonical issued_at timestamp", () => {
    const p = withWindow("2026-07-18T00:00:00Z", "2026-07-18T00:00:30.000Z");
    expect(() => buildReportRequestPreimage(p)).toThrow("canonical RFC3339 ms timestamps");
  });

  it("throws for a non-canonical expires_at timestamp", () => {
    const p = withWindow("2026-07-18T00:00:00.000Z", "not-a-timestamp");
    expect(() => buildReportRequestPreimage(p)).toThrow("canonical RFC3339 ms timestamps");
  });
});
