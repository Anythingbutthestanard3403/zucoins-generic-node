import { describe, expect, it } from "vitest";

import {
  BACKUP_RPO_TARGET_MS,
  BACKUP_RTO_TARGET_MS,
  DEFAULT_BACKUP_POLICY,
  isRpoBreached,
  isRtoBreached,
} from "../../src/dr/policy.js";

describe("DR policy — RPO/RTO", () => {
  it("pins launch targets", () => {
    expect(BACKUP_RPO_TARGET_MS).toBe(24 * 60 * 60 * 1000);
    expect(BACKUP_RTO_TARGET_MS).toBe(60 * 60 * 1000);
    expect(DEFAULT_BACKUP_POLICY.retentionDays).toBe(14);
  });

  it("RPO breaches when no backup exists", () => {
    expect(isRpoBreached(null, Date.now())).toBe(true);
  });

  it("RPO breaches when newest backup is older than target", () => {
    const now = 1_000_000_000_000;
    expect(isRpoBreached(now - BACKUP_RPO_TARGET_MS - 1, now)).toBe(true);
    expect(isRpoBreached(now - BACKUP_RPO_TARGET_MS + 1_000, now)).toBe(false);
  });

  it("RTO breaches when drill exceeds target", () => {
    expect(isRtoBreached(BACKUP_RTO_TARGET_MS + 1)).toBe(true);
    expect(isRtoBreached(BACKUP_RTO_TARGET_MS - 1)).toBe(false);
    expect(isRtoBreached(-1)).toBe(true);
  });
});
