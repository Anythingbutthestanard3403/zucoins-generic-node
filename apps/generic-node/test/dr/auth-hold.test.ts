import { describe, expect, it } from "vitest";

import {
  buildForceAuthHoldSetStatements,
  buildReleaseAuthHoldStatements,
  HEAL_LIFECYCLE_DEFERRED_VALIDATOR_SQL,
} from "../../src/dr/auth-hold.js";

const NODE = "11111111-1111-4111-8111-111111111111";
const IMPL = "22222222-2222-4222-8222-222222222222";
const KEY = "33333333-3333-4333-8333-333333333333";
const PREV_EVENT = "44444444-4444-4444-8444-444444444444";
const PREV_HASH = "ab".repeat(32);

describe("buildForceAuthHoldSetStatements — auth_hold force shape", () => {
  it("inserts AUTH_HOLD_SET with auth_hold=true and advances head (not bare UPDATE)", () => {
    const built = buildForceAuthHoldSetStatements({
      nodeId: NODE,
      implementerId: IMPL,
      priorEpoch: 1n,
      previousEventId: PREV_EVENT,
      previousEventHash: PREV_HASH,
      currentKeyId: KEY,
      priorKeyId: null,
      overlapExpiresAt: null,
      now: new Date("2026-07-26T12:00:00.000Z"),
      eventId: "55555555-5555-4555-8555-555555555555",
      nonceRowId: "66666666-6666-4666-8666-666666666666",
      nonceValue: "77777777-7777-4777-8777-777777777777",
      eventHash: "cd".repeat(32),
      nonceBurnSequence: 9n,
    });

    expect(built.eventSql).toMatch(/AUTH_HOLD_SET/);
    expect(built.eventSql).toMatch(/auth_hold/);
    expect(built.eventSql).toMatch(/true/);
    expect(built.eventSql).not.toMatch(/UPDATE\s+reporting_key_lifecycle_heads/i);
    expect(built.advanceSql).toMatch(/reporting_advance_lifecycle_head/);
    expect(built.nonceSql).toMatch(/zp-report-request-v1/);
    expect(built.params.epoch).toBe("2");
    expect(built.params.eventHash).toMatch(/^[0-9a-f]{64}$/);
    expect(built.params.evidenceSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("chains epoch as prior+1 and keeps key slots unchanged in SQL placeholders", () => {
    const built = buildForceAuthHoldSetStatements({
      nodeId: NODE,
      implementerId: IMPL,
      priorEpoch: 7n,
      previousEventId: PREV_EVENT,
      previousEventHash: PREV_HASH,
      currentKeyId: KEY,
      priorKeyId: null,
      overlapExpiresAt: null,
      now: new Date("2026-07-26T12:00:00.000Z"),
    });
    expect(built.params.epoch).toBe("8");
    expect(built.params.evidenceText).toContain("zp-gn-restore-auth-hold-v1");
    expect(built.params.evidenceText).toContain(NODE);
    expect(built.params.evidenceText).toContain(IMPL);
  });
});

describe("buildReleaseAuthHoldStatements — canonical release shape", () => {
  it("appends AUTH_HOLD_RELEASED with nonce evidence and advances the head", () => {
    const built = buildReleaseAuthHoldStatements({
      nodeId: NODE,
      implementerId: IMPL,
      priorEpoch: 2n,
      previousEventId: PREV_EVENT,
      previousEventHash: PREV_HASH,
      currentKeyId: KEY,
      priorKeyId: null,
      overlapExpiresAt: null,
      now: new Date("2026-07-26T12:00:00.000Z"),
      evidenceSha256: "ef".repeat(32),
      nonceBurnSequence: 10n,
    });
    expect(built.eventSql).toMatch(/AUTH_HOLD_RELEASED/);
    expect(built.eventSql).toMatch(/false/);
    expect(built.nonceSql).toMatch(/restore_auth_hold_release/);
    expect(built.advanceSql).toMatch(/reporting_advance_lifecycle_head/);
    expect(built.eventSql + built.advanceSql).not.toMatch(/UPDATE\s+reporting_key_lifecycle_heads/i);
    expect(built.params.epoch).toBe("3");
  });
});

describe("HEAL_LIFECYCLE_DEFERRED_VALIDATOR_SQL — stock reporting-DDL NEW-field fix", () => {
  it("uses IF/ELSIF per table, not a CASE that cross-evaluates NEW fields", () => {
    expect(HEAL_LIFECYCLE_DEFERRED_VALIDATOR_SQL).toMatch(
      /IF TG_TABLE_NAME = 'reporting_key_lifecycle_events'/,
    );
    expect(HEAL_LIFECYCLE_DEFERRED_VALIDATOR_SQL).toMatch(/ELSIF TG_TABLE_NAME/);
    expect(HEAL_LIFECYCLE_DEFERRED_VALIDATOR_SQL).toMatch(/NEW\.id/);
    expect(HEAL_LIFECYCLE_DEFERRED_VALIDATOR_SQL).toMatch(/NEW\.lifecycle_event_id/);
    // CASE TG_TABLE_NAME ... NEW.x / NEW.y forces every arm's field against the
    // firing row type and aborts AUTH_HOLD_SET on the events table.
    expect(HEAL_LIFECYCLE_DEFERRED_VALIDATOR_SQL).not.toMatch(
      /event_id\s*:=\s*CASE\s+TG_TABLE_NAME/i,
    );
  });
});
