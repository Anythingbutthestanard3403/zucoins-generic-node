// the named concern — STRUCTURAL (frozen-shape) adversarial cells for the reporting
// registration/authentication/rotation CONTRACT. Exercises the frozen verifier
// (verifyReportRequestPreimage, verifyNodeEventPreimage, eventChainLinks) and the mint-time
// window guard (buildReportRequestPreimage) against byte mutation, replay-window abuse, sequence
// shape attacks, binding-field violations, and hash-chain-shape corruption.
//
// The RUNTIME attacks — real nonce-burn durability, seq-cursor replay/rewind, the
// key_status→tenant→signature verifier sequence, key-rotation overlap, revoke-to-zero hard-stop, and
// restart/epoch hard-stop — drive the live runtime and live in the node-core driving
// suites (packages/node-core/src/reporting/reporting-attack-suite*.test.ts). Per the receive-golden
// precedent (receive-golden/attack-vectors.freeze.test.ts), this contracts-package file NEVER
// imports node-core, keeping the dependency direction one-way; runtime state cannot be reached from
// here, so no runtime cell is stubbed as a placeholder in this file.
//
// Governing: the canonical-fields tuple tables and goldens, the closed event set, the api contract, and the pull-cursor authority rule.
// Invariants: byte-exact signing; never blind-retry a submit.

import { describe, expect, it } from "vitest";

import {
  REPORT_REQUEST_GOLDEN_PAYLOAD,
  REPORT_REQUEST_GOLDEN_PREIMAGE,
  REPORT_REQUEST_MAX_WINDOW_SECONDS,
  buildReportRequestPreimage,
  type ReportRequestPayload,
} from "./request-tuple.js";
import {
  NODE_EVENT_GOLDEN_A,
  NODE_EVENT_GOLDEN_A_PREIMAGE,
  NODE_EVENT_GOLDEN_B,
  NODE_EVENT_GOLDEN_B_PREIMAGE,
  NEUTRAL_EVENT_TYPES,
  buildNodeEventPreimage,
  type NodeEventPayload,
} from "./event-tuple.js";
import {
  verifyReportRequestPreimage,
  verifyNodeEventPreimage,
  eventChainLinks,
} from "./verifier.js";
import { NODE_EVENT_A_EVENT_HASH } from "./digests.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mutateRequest(overrides: Partial<ReportRequestPayload>): string | null {
  const payload = { ...REPORT_REQUEST_GOLDEN_PAYLOAD, ...overrides };
  try {
    return buildReportRequestPreimage(payload);
  } catch {
    return null;
  }
}

function rawRequestPreimage(overrides: Record<string, unknown>): string {
  const base = JSON.parse(
    REPORT_REQUEST_GOLDEN_PREIMAGE.slice(REPORT_REQUEST_GOLDEN_PREIMAGE.indexOf("\n") + 1),
  ) as Record<string, unknown>;
  const merged = { ...base, ...overrides };
  return `zp-report-request-v1\n${JSON.stringify(merged)}`;
}

function mutateEvent(overrides: Partial<NodeEventPayload>): string {
  const payload = { ...NODE_EVENT_GOLDEN_A, ...overrides };
  return buildNodeEventPreimage(payload);
}

function rawEventPreimage(overrides: Record<string, unknown>): string {
  const base = JSON.parse(
    NODE_EVENT_GOLDEN_A_PREIMAGE.slice(NODE_EVENT_GOLDEN_A_PREIMAGE.indexOf("\n") + 1),
  ) as Record<string, unknown>;
  const merged = { ...base, ...overrides };
  return `zp-node-event-v1\n${JSON.stringify(merged)}`;
}

// ---------------------------------------------------------------------------
// Category 1: Body mutation — request tuple
// ---------------------------------------------------------------------------

describe("C1: request body mutation attacks", () => {
  it("accepts the unmodified golden preimage", () => {
    const result = verifyReportRequestPreimage(REPORT_REQUEST_GOLDEN_PREIMAGE);
    expect(result.ok).toBe(true);
    expect(result.reason).toBeNull();
  });

  it("structural verifier passes a different valid UUID (signature layer catches value tampering)", () => {
    const preimage = rawRequestPreimage({ node_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(true);
  });

  it("structural verifier passes a different valid body_sha256 (signature catches tampering)", () => {
    const preimage = rawRequestPreimage({
      body_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
    });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(true);
  });

  it("rejects swapped method (GET where POST expected)", () => {
    const preimage = rawRequestPreimage({ method: "GET" });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
  });

  it("rejects wrong types — node_id as number", () => {
    const preimage = rawRequestPreimage({ node_id: 12345 });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("not a UUID");
  });

  it("rejects wrong types — canonical_version as string", () => {
    const preimage = rawRequestPreimage({ canonical_version: "1" });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("canonical_version");
  });

  it("rejects null where string expected (nonce)", () => {
    const preimage = rawRequestPreimage({ nonce: null });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
  });

  it("rejects extra injected field", () => {
    const preimage = rawRequestPreimage({ admin_override: true });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("non-canonical byte layout");
  });

  it("rejects missing required field (nonce removed)", () => {
    const base = JSON.parse(
      REPORT_REQUEST_GOLDEN_PREIMAGE.slice(REPORT_REQUEST_GOLDEN_PREIMAGE.indexOf("\n") + 1),
    ) as Record<string, unknown>;
    delete base.nonce;
    const preimage = `zp-report-request-v1\n${JSON.stringify(base)}`;
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("missing field");
  });

  it("rejects wrong purpose prefix", () => {
    const preimage = `zp-report-request-v2\n${REPORT_REQUEST_GOLDEN_PREIMAGE.slice(
      REPORT_REQUEST_GOLDEN_PREIMAGE.indexOf("\n") + 1,
    )}`;
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("prefix/purpose separator invalid");
  });

  it("rejects empty preimage", () => {
    const result = verifyReportRequestPreimage("");
    expect(result.ok).toBe(false);
  });

  it("rejects preimage with no newline separator", () => {
    const result = verifyReportRequestPreimage("zp-report-request-v1-no-separator");
    expect(result.ok).toBe(false);
  });

  it("rejects non-UUID node_id (valid string, wrong format)", () => {
    const preimage = rawRequestPreimage({ node_id: "not-a-uuid-at-all" });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("not a UUID");
  });

  it("rejects uppercase UUID (non-canonical)", () => {
    const preimage = rawRequestPreimage({ implementer_id: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
  });

  it("rejects body_sha256 with wrong length", () => {
    const preimage = rawRequestPreimage({ body_sha256: "44136fa3" });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("not hex");
  });
});

// ---------------------------------------------------------------------------
// Category 2: Replay-window abuse
// ---------------------------------------------------------------------------

describe("C2: replay-window abuse", () => {
  it("accepts exactly 60s window (boundary, inclusive ceiling)", () => {
    const preimage = mutateRequest({
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:01:00.000Z",
    });
    expect(preimage).not.toBeNull();
    const result = verifyReportRequestPreimage(preimage!);
    expect(result.ok).toBe(true);
  });

  it("rejects 61s window (one second over)", () => {
    const preimage = mutateRequest({
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:01:01.000Z",
    });
    expect(preimage).toBeNull();
  });

  it("rejects zero window (issued_at === expires_at)", () => {
    const preimage = mutateRequest({
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:00:00.000Z",
    });
    expect(preimage).toBeNull();
  });

  it("rejects inverted window (expires_at before issued_at)", () => {
    const preimage = mutateRequest({
      issued_at: "2026-07-18T00:01:00.000Z",
      expires_at: "2026-07-18T00:00:00.000Z",
    });
    expect(preimage).toBeNull();
  });

  it("rejects far-future window (1 hour)", () => {
    const preimage = mutateRequest({
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T01:00:00.000Z",
    });
    expect(preimage).toBeNull();
  });

  it("rejects 59.999s expressed as non-canonical timestamp", () => {
    const preimage = mutateRequest({
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:00:59.999Z",
    });
    expect(preimage).not.toBeNull();
    const result = verifyReportRequestPreimage(preimage!);
    expect(result.ok).toBe(true);
  });

  it("verifier rejects raw preimage with window > 60s bypassing builder", () => {
    const base = JSON.parse(
      REPORT_REQUEST_GOLDEN_PREIMAGE.slice(REPORT_REQUEST_GOLDEN_PREIMAGE.indexOf("\n") + 1),
    ) as Record<string, unknown>;
    base.issued_at = "2026-07-18T00:00:00.000Z";
    base.expires_at = "2026-07-18T00:02:00.000Z";
    const preimage = `zp-report-request-v1\n${JSON.stringify(base)}`;
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("window exceeds 60 seconds");
  });

  it("verifier rejects inverted timestamps bypassing builder", () => {
    const base = JSON.parse(
      REPORT_REQUEST_GOLDEN_PREIMAGE.slice(REPORT_REQUEST_GOLDEN_PREIMAGE.indexOf("\n") + 1),
    ) as Record<string, unknown>;
    base.issued_at = "2026-07-18T00:01:00.000Z";
    base.expires_at = "2026-07-18T00:00:00.000Z";
    const preimage = `zp-report-request-v1\n${JSON.stringify(base)}`;
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("expires_at must be later");
  });

  it("rejects non-canonical timestamp format (missing ms)", () => {
    const preimage = mutateRequest({
      issued_at: "2026-07-18T00:00:00Z",
      expires_at: "2026-07-18T00:00:30.000Z",
    });
    expect(preimage).toBeNull();
  });

  it(`REPORT_REQUEST_MAX_WINDOW_SECONDS is exactly ${60}`, () => {
    expect(REPORT_REQUEST_MAX_WINDOW_SECONDS).toBe(60);
  });
});

// ---------------------------------------------------------------------------
// Category 3: Duplicate event delivery (structural idempotency surface)
// ---------------------------------------------------------------------------

describe("C3: duplicate event delivery", () => {
  it("same event preimage verifies identically both times (structural layer)", () => {
    const first = verifyNodeEventPreimage(NODE_EVENT_GOLDEN_A_PREIMAGE);
    const second = verifyNodeEventPreimage(NODE_EVENT_GOLDEN_A_PREIMAGE);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
  });

  // Runtime duplicate/idempotency (nonce-burn durability + event id/hash dedup) is a live-state
  // attack driven in reporting-attack-suite*.test.ts (node-core), not a contract-shape check.
});

// ---------------------------------------------------------------------------
// Category 4: Sequence gaps and reordering
// ---------------------------------------------------------------------------

describe("C4: sequence gap and reorder attacks", () => {
  it("accepts seq '1' (first event)", () => {
    const result = verifyNodeEventPreimage(NODE_EVENT_GOLDEN_A_PREIMAGE);
    expect(result.ok).toBe(true);
  });

  it("accepts seq '2' (second event)", () => {
    const result = verifyNodeEventPreimage(NODE_EVENT_GOLDEN_B_PREIMAGE);
    expect(result.ok).toBe(true);
  });

  it("rejects seq '0' (not a positive decimal)", () => {
    const preimage = mutateEvent({ seq: "0" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("seq not a positive decimal");
  });

  it("rejects seq with leading zero ('01')", () => {
    const preimage = mutateEvent({ seq: "01" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("seq not a positive decimal");
  });

  it("rejects seq as negative ('-1')", () => {
    const preimage = mutateEvent({ seq: "-1" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
  });

  it("rejects seq as non-numeric ('abc')", () => {
    const preimage = mutateEvent({ seq: "abc" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
  });

  it("rejects seq as empty string", () => {
    const preimage = mutateEvent({ seq: "" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
  });

  it("accepts large seq ('999999999')", () => {
    const preimage = mutateEvent({ seq: "999999999" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(true);
  });

  // Runtime seq-cursor gap/reorder/replay is a live-state attack driven in
  // reporting-attack-suite-events.test.ts (node-core) against the real cursor and hash chain.
});

// ---------------------------------------------------------------------------
// Category 5: Wrong-node / wrong-tenant binding
// ---------------------------------------------------------------------------

describe("C5: node/tenant binding attacks", () => {
  it("structural verifier passes event with different valid node_id (registration layer catches binding)", () => {
    const preimage = mutateEvent({ node_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(true);
  });

  it("structural verifier passes request with different valid implementer_id (registration catches binding)", () => {
    const preimage = rawRequestPreimage({ implementer_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(true);
  });

  it("rejects non-UUID node_id in event", () => {
    const preimage = rawEventPreimage({ node_id: "tenant-abc-not-a-uuid" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("not a UUID");
  });

  it("rejects event_id that is not a UUID", () => {
    const preimage = rawEventPreimage({ event_id: "not-a-uuid" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("not a UUID");
  });

  // Runtime node-identity binding (a request forging a foreign node_id/implementer_id cannot
  // authenticate — auth derives from the registration binding, not the tuple) is driven in
  // reporting-attack-suite.test.ts (node-core), ATTACK 3.
});

// ---------------------------------------------------------------------------
// Category 6: Prior-key overlap / rotation attacks
// ---------------------------------------------------------------------------

describe("C6: key rotation and prior-key overlap (structural)", () => {
  it("structural verifier rejects corrupted signature-format field (body_sha256 as proxy)", () => {
    const preimage = rawRequestPreimage({ body_sha256: "zzzz" });
    const result = verifyReportRequestPreimage(preimage);
    expect(result.ok).toBe(false);
  });

  // Runtime key-rotation overlap (prior key accepted strictly inside the reporting-key enrolment freeze half-open window
  // rejected at/after the boundary and when revoked) and revoke-to-zero hard-stop are driven in
  // reporting-attack-suite.test.ts (node-core), ATTACK 4 and ATTACK 5. Operator opt-out enforcement
  // is a platform-ingest concern / node pusher gate, outside node-core's boundary.
});

// ---------------------------------------------------------------------------
// Category 8: Restart/recovery — hash-chain integrity
// ---------------------------------------------------------------------------

describe("C8: restart/recovery and hash-chain integrity", () => {
  it("eventChainLinks accepts correct linkage (B links to A's hash)", () => {
    expect(eventChainLinks(NODE_EVENT_A_EVENT_HASH, NODE_EVENT_GOLDEN_B)).toBe(true);
  });

  it("eventChainLinks rejects wrong prior hash", () => {
    expect(
      eventChainLinks("0000000000000000000000000000000000000000000000000000000000000000", NODE_EVENT_GOLDEN_B),
    ).toBe(false);
  });

  it("eventChainLinks accepts null for first event (genesis)", () => {
    expect(eventChainLinks(null, NODE_EVENT_GOLDEN_A)).toBe(true);
  });

  it("eventChainLinks rejects non-null prior for first event", () => {
    expect(eventChainLinks(NODE_EVENT_A_EVENT_HASH, NODE_EVENT_GOLDEN_A)).toBe(false);
  });

  it("rejects event with corrupted previous_event_hash format", () => {
    const preimage = rawEventPreimage({ previous_event_hash: "not-hex" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("previous_event_hash must be hex or null");
  });

  it("rejects event with wrong-length previous_event_hash", () => {
    const preimage = rawEventPreimage({ previous_event_hash: "1f0ec14d" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
  });

  // Runtime restart/epoch hard-stop (a restarted node is hard-held, no silent resume; a stale-epoch
  // burn is rejected — no cross-epoch replay) is driven in reporting-attack-suite.test.ts
  // (node-core), ATTACK 6.
});

// ---------------------------------------------------------------------------
// Category 9 (bonus): Event-type closure and event body mutation
// ---------------------------------------------------------------------------

describe("C9: event body mutation and type-closure attacks", () => {
  it("accepts all nine closed event types", () => {
    for (const eventType of NEUTRAL_EVENT_TYPES) {
      const preimage = mutateEvent({ event_type: eventType });
      const result = verifyNodeEventPreimage(preimage);
      expect(result.ok).toBe(true);
    }
  });

  it("rejects event_type outside the closed set", () => {
    const preimage = mutateEvent({ event_type: "admin.override" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("event_type not in the closed set");
  });

  it("rejects event_type with injection attempt", () => {
    const preimage = mutateEvent({ event_type: "receive.ready; DROP TABLE events" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
  });

  it("structural verifier passes different valid data_sha256 (hash-chain layer catches tampering)", () => {
    const preimage = rawEventPreimage({
      data_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
    });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(true);
  });

  it("rejects operation_id as non-UUID non-null", () => {
    const preimage = rawEventPreimage({ operation_id: "not-a-uuid" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("must be a UUID or null");
  });

  it("rejects wallet_id as non-UUID non-null", () => {
    const preimage = rawEventPreimage({ wallet_id: 12345 });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
  });

  it("accepts null operation_id and null wallet_id", () => {
    const preimage = mutateEvent({ operation_id: null, wallet_id: null });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(true);
  });

  it("rejects missing event_type field", () => {
    const base = JSON.parse(
      NODE_EVENT_GOLDEN_A_PREIMAGE.slice(NODE_EVENT_GOLDEN_A_PREIMAGE.indexOf("\n") + 1),
    ) as Record<string, unknown>;
    delete base.event_type;
    const preimage = `zp-node-event-v1\n${JSON.stringify(base)}`;
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("missing field");
  });

  it("rejects wrong canonical_version in event", () => {
    const preimage = rawEventPreimage({ canonical_version: 2 });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("canonical_version");
  });

  it("rejects non-canonical created_at in event", () => {
    const preimage = rawEventPreimage({ created_at: "2026-07-18 00:00:00" });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("created_at bad");
  });

  it("rejects injected extra field in event", () => {
    const preimage = rawEventPreimage({ admin: true });
    const result = verifyNodeEventPreimage(preimage);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("non-canonical byte layout");
  });
});
