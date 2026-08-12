/**
 * Label census (ZTR-1262): every contract wire enum used as operator-facing
 * primary text must have a STATUS_LABELS / SEVERITY entry.
 */
import { describe, expect, it } from "vitest";
import {
  ATTENTION_REASONS,
} from "@zucoins/generic-node-contracts/operations/events";
import {
  SEVERITY_LABELS,
  STATUS_LABELS,
  severityLabel,
  statusLabel,
} from "./labels.js";

/** OPERATION_STATUS from contracts api-schema (mirrored — import path is heavy). */
const OPERATION_STATUS = [
  "CREATED",
  "READY",
  "RECEIVE_LANDED",
  "INTERNAL_MOVE_LANDED",
  "APPROVED",
  "AWAITING_REDEMPTION",
  "EXTERNAL_SEND_LANDED",
  "EXPIRED",
  "REJECTED",
  "NEEDS_ATTENTION",
] as const;

const EXTERNAL_FORMATION_STATE = [
  "NOT_REQUIRED",
  "APPROVAL_PENDING",
  "APPROVED_UNSIGNED",
  "SIGNING_CLAIMED",
  "PARTIAL_PERSISTED",
  "PARTIAL_DELIVERED",
] as const;

const RECOVERY_CLASSIFICATION = [
  "LANDED_VERIFIED",
  "PROVEN_NOT_STARTED",
  "PROVEN_NOT_LANDED",
  "WAITING",
  "INDETERMINATE",
  "INVARIANT_BREACH",
] as const;

describe("label census vs contracts", () => {
  it("covers every OPERATION_STATUS value", () => {
    for (const v of OPERATION_STATUS) {
      expect(STATUS_LABELS[v], v).toBeTruthy();
      expect(statusLabel(v)).not.toBe(v.replace(/_/g, " "));
      // primary must not be bare wire
      expect(statusLabel(v)).not.toBe(v);
    }
  });

  it("covers every ATTENTION_REASONS value (15)", () => {
    expect(ATTENTION_REASONS).toHaveLength(15);
    for (const v of ATTENTION_REASONS) {
      expect(STATUS_LABELS[v], v).toBeTruthy();
      expect(statusLabel(v)).not.toBe(v);
    }
  });

  it("covers EXTERNAL_FORMATION_STATE", () => {
    for (const v of EXTERNAL_FORMATION_STATE) {
      expect(STATUS_LABELS[v], v).toBeTruthy();
      expect(statusLabel(v)).not.toBe(v);
    }
  });

  it("covers recovery classifications", () => {
    for (const v of RECOVERY_CLASSIFICATION) {
      expect(STATUS_LABELS[v], v).toBeTruthy();
      expect(statusLabel(v)).not.toBe(v);
    }
  });

  it("severity codes always carry meaning text", () => {
    for (const s of ["P0", "P1", "P2"] as const) {
      expect(SEVERITY_LABELS[s]).toMatch(/act|plan/i);
      expect(severityLabel(s)).toMatch(/P[012]/);
      expect(severityLabel(s).length).toBeGreaterThan(2);
    }
  });
});
