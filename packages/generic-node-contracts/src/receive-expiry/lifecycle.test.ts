import { describe, it, expect } from "vitest";
import {
  isExpiryToExpiredLegal,
  isTerminalReceiveState,
  receiveExpiryEvents,
  POST_BOUNDARY_EXPIRY_OUTCOME,
  POST_EXPIRY_RECONCILING,
} from "./lifecycle.js";

describe("isExpiryToExpiredLegal — pre-boundary terminal, post-boundary forbidden (the receive-expiry rule)", () => {
  it("permits terminal expiry pre-boundary", () => {
    expect(isExpiryToExpiredLegal("CREATED", false)).toBe(true);
    expect(isExpiryToExpiredLegal("READY", false)).toBe(true);
  });
  it("NEGATIVE: post-boundary READY -> EXPIRED (and CREATED -> EXPIRED) is forbidden", () => {
    expect(isExpiryToExpiredLegal("READY", true)).toBe(false);
    expect(isExpiryToExpiredLegal("CREATED", true)).toBe(false);
  });
});

describe("post-boundary expiry outcome — stay READY, hold lease, POST_EXPIRY_RECONCILING", () => {
  it("keeps the receive READY with the one new attention reason, no expired event", () => {
    expect(POST_BOUNDARY_EXPIRY_OUTCOME).toEqual({
      state: "READY",
      attentionReason: "POST_EXPIRY_RECONCILING",
      leaseHeld: true,
      appendsNeedsAttention: true,
      appendsExpiredEvent: false,
    });
    expect(POST_EXPIRY_RECONCILING).toBe("POST_EXPIRY_RECONCILING");
  });
});

describe("receiveExpiryEvents — event sequencing (NEVER operation.expired post-boundary)", () => {
  it("pre-boundary appends the terminal expired event", () => {
    expect(receiveExpiryEvents(false)).toEqual({ appendsExpired: true, appendsNeedsAttention: false });
  });
  it("NEGATIVE: post-boundary appends needs_attention and NEVER expired", () => {
    expect(receiveExpiryEvents(true)).toEqual({ appendsExpired: false, appendsNeedsAttention: true });
  });
});

describe("terminality — EXPIRED and RECEIVE_LANDED are terminal", () => {
  it("classifies terminal vs open states", () => {
    expect(isTerminalReceiveState("EXPIRED")).toBe(true);
    expect(isTerminalReceiveState("RECEIVE_LANDED")).toBe(true);
    expect(isTerminalReceiveState("READY")).toBe(false);
    expect(isTerminalReceiveState("INDETERMINATE")).toBe(false);
    expect(isTerminalReceiveState("CREATED")).toBe(false);
  });
});
