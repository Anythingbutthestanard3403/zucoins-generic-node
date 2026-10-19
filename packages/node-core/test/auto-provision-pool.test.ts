import { describe, expect, it } from "vitest";

import {
  BLESS_RESERVE_DESTINATION_SQL,
  STAMP_RECOVERY_UNDER_VAULT_SQL,
  WRITE_MAIN_RESERVE_SETTING_SQL,
  ensureNodeReserveAndWorkerPool,
} from "../src/receive/auto-provision-pool.ts";
import { PoolScalerError } from "../src/receive/pool-scaler.ts";

describe("reserve pool provisioner (no database)", () => {
  it("rejects a cap below the floor before any transaction", async () => {
    let calls = 0;
    const run = ensureNodeReserveAndWorkerPool({
      nodeId: "b0000000-0000-4000-8000-000000000265",
      poolCapTotal: 4,
      withTx: async () => {
        calls += 1;
        return undefined as never;
      },
      query: async () => {
        calls += 1;
        return { rows: [] };
      },
      seal: async () => {
        calls += 1;
      },
    });
    await expect(run).rejects.toBeInstanceOf(PoolScalerError);
    await expect(run).rejects.toMatchObject({ reason: "POOL_CAP_INVALID" });
    expect(calls).toBe(0);
  });

  it("keeps the modifying statements in the psql ') SELECT' shape", () => {
    for (const sql of [
      STAMP_RECOVERY_UNDER_VAULT_SQL,
      BLESS_RESERVE_DESTINATION_SQL,
      WRITE_MAIN_RESERVE_SETTING_SQL,
    ]) {
      expect(sql).toContain(") SELECT");
    }
    expect(STAMP_RECOVERY_UNDER_VAULT_SQL).toContain("recovery_verified_at IS NULL");
    expect(STAMP_RECOVERY_UNDER_VAULT_SQL).toContain("SET recovery_verified_at");
  });
});
