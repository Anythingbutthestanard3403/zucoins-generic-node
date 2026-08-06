import { describe, it, expect } from "vitest";
import {
  OPEN_SESSIONS_COMPONENTS,
  OPEN_SESSIONS_EXCLUDED_COMPONENTS,
  OPEN_SESSIONS_COUNT_SQL,
  OPEN_SESSIONS_DEFINITION,
} from "./open-sessions.js";

describe("open_sessions demand-side composition — frozen (the receive-queue backpressure rule 1)", () => {
  it("includes RECEIVE-pinned pool wallets and unassigned CREATED receive operations", () => {
    expect([...OPEN_SESSIONS_COMPONENTS]).toEqual([
      "RECEIVE-pinned pool wallets",
      "unassigned CREATED receive operations awaiting a wallet",
    ]);
  });

  it("EXCLUDES the other two money-operation kinds' source pins (NEGATIVE — these must not draw down headroom)", () => {
    expect([...OPEN_SESSIONS_EXCLUDED_COMPONENTS]).toEqual([
      "a wallet pin held for a node-internal transfer between two node-controlled wallets",
      "a wallet pin held to form a partial for an external recipient to co-sign",
    ]);
    for (const excluded of OPEN_SESSIONS_EXCLUDED_COMPONENTS) {
      expect(OPEN_SESSIONS_COMPONENTS as readonly string[]).not.toContain(excluded);
    }
  });

  it("the frozen count SQL reads the RECEIVE lease and unassigned-CREATED-operation halves, re-readable under the scale-up lock", () => {
    expect(OPEN_SESSIONS_COUNT_SQL).toContain("wallet_active_leases");
    expect(OPEN_SESSIONS_COUNT_SQL).toContain("lease_role = 'RECEIVE'");
    expect(OPEN_SESSIONS_COUNT_SQL).toContain("operation_type = 'RECEIVE_EXTERNAL'");
    expect(OPEN_SESSIONS_COUNT_SQL).toContain("state = 'CREATED'");
    expect(OPEN_SESSIONS_COUNT_SQL).toContain("AS open_sessions");
  });

  it("the aggregate definition carries the includes/excludes/sql triple", () => {
    expect(OPEN_SESSIONS_DEFINITION.includes).toBe(OPEN_SESSIONS_COMPONENTS);
    expect(OPEN_SESSIONS_DEFINITION.excludes).toBe(OPEN_SESSIONS_EXCLUDED_COMPONENTS);
    expect(OPEN_SESSIONS_DEFINITION.sql).toBe(OPEN_SESSIONS_COUNT_SQL);
  });
});
