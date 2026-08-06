import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { projectWalletState, isSelectableForReceive } from "./projection.js";
import { auditPersistedWallet } from "./boot-audit.js";
import {
  OPERATION_ROLE_DIMENSION,
  LEASE_LIFECYCLE_DIMENSION,
  STORED_STATE_DIMENSION,
  walletStateMatrixContract,
} from "./matrix.js";
import { type LeaseRole } from "./leases.js";

const RECOVERY = "2026-07-19T00:00:00.000Z";

type SelectionCell = {
  role: LeaseRole;
  quarantined: boolean;
  retired: boolean;
  recoveryVerifiedAt: string | null;
};
const selectionCells: SelectionCell[] = [];
for (const role of OPERATION_ROLE_DIMENSION) {
  for (const quarantined of [false, true]) {
    for (const retired of [false, true]) {
      for (const recoveryVerifiedAt of [null, RECOVERY]) {
        selectionCells.push({ role, quarantined, retired, recoveryVerifiedAt });
      }
    }
  }
}

describe("INVARIANT: no leased wallet is ever selected (operation-role x quarantine x retirement x recovery)", () => {
  it.each(selectionCells)(
    "leased $role q=$quarantined r=$retired rv=$recoveryVerifiedAt -> not AVAILABLE, not selectable",
    (cell) => {
      const input = {
        leases: [{ role: cell.role, lifecycle: "ACTIVE" as const }],
        quarantined: cell.quarantined,
        retired: cell.retired,
      };
      const projected = projectWalletState(input).state;
      // Lease pins selection out; quarantine (operator) is strictly more restricted and is
      // retained on the leased path rather than understated as PINNED.
      expect(projected).toBe(cell.quarantined ? "QUARANTINED" : "PINNED");
      expect(projected).not.toBe("AVAILABLE");
      expect(
        isSelectableForReceive({ ...input, keyOrigin: "node_generated", recoveryVerifiedAt: cell.recoveryVerifiedAt }),
      ).toBe(false);
    },
  );
});

const releaseCells: Array<{ role: LeaseRole; stored: (typeof STORED_STATE_DIMENSION)[number] }> = [];
for (const role of OPERATION_ROLE_DIMENSION) {
  for (const stored of STORED_STATE_DIMENSION) {
    releaseCells.push({ role, stored });
  }
}

describe("INVARIANT: no leased wallet is ever silently released (operation-role x stored-state x restart)", () => {
  it.each(releaseCells)("leased $role stored=$stored -> stays PINNED, never released", (cell) => {
    const projection = projectWalletState({
      leases: [{ role: cell.role, lifecycle: "ACTIVE" }],
      quarantined: false,
      retired: false,
    });
    expect(projection.state).toBe("PINNED");
    const audit = auditPersistedWallet(cell.stored, projection);
    // A leased wallet is either already consistent (stored PINNED / retained QUARANTINED) or
    // repaired AVAILABLE→PINNED — never released to AVAILABLE, never cleared of quarantine.
    expect(["CONSISTENT", "REPAIR_TO_PROJECTION"]).toContain(audit.disposition);
    expect(audit.disposition).not.toBe("QUARANTINE_FOR_RECONCILIATION");
    if (cell.stored === "QUARANTINED") {
      expect(audit.disposition).toBe("CONSISTENT");
      expect(audit.disposition).not.toBe("REPAIR_TO_PROJECTION");
    }
  });
});

describe("per-dimension negatives", () => {
  const clean = { leases: [], quarantined: false, retired: false };
  it("operation-role dim: a RECONCILIATION lease never pins (observation is not an operation)", () => {
    const input = { ...clean, leases: [{ role: "RECONCILIATION" as const, lifecycle: "ACTIVE" as const }] };
    expect(projectWalletState(input).state).toBe("AVAILABLE");
    expect(isSelectableForReceive({ ...input, keyOrigin: "node_generated", recoveryVerifiedAt: RECOVERY })).toBe(true);
  });
  it("lease-lifecycle dim: a RELEASED operation lease does not pin", () => {
    for (const role of OPERATION_ROLE_DIMENSION) {
      expect(projectWalletState({ ...clean, leases: [{ role, lifecycle: "RELEASED" }] }).state).toBe("AVAILABLE");
    }
  });
  it("wallet-state dim: a leased wallet is never AVAILABLE", () => {
    expect(projectWalletState({ ...clean, leases: [{ role: "MOVE_SOURCE", lifecycle: "ACTIVE" }] }).state).not.toBe("AVAILABLE");
  });
  it("quarantine dim: a quarantined unleased wallet is not selectable", () => {
    expect(isSelectableForReceive({ ...clean, quarantined: true, keyOrigin: "node_generated", recoveryVerifiedAt: RECOVERY })).toBe(false);
  });
  it("retirement dim: a retired unleased wallet is not selectable", () => {
    expect(isSelectableForReceive({ ...clean, retired: true, keyOrigin: "node_generated", recoveryVerifiedAt: RECOVERY })).toBe(false);
  });
  it("restart dim: a phantom-pin (stored PINNED, no lease) is quarantined, never released to AVAILABLE", () => {
    const projection = projectWalletState(clean);
    expect(auditPersistedWallet("PINNED", projection).disposition).toBe("QUARANTINE_FOR_RECONCILIATION");
  });
});

const snapshotPath = fileURLToPath(new URL("../../gen/wallet-state-matrix.json", import.meta.url));

describe("matrix contract — snapshot sync + census", () => {
  it("gen/wallet-state-matrix.json equals walletStateMatrixContract", () => {
    expect(JSON.parse(readFileSync(snapshotPath, "utf8"))).toEqual(walletStateMatrixContract);
  });
  it("covers the six dimensions and two invariants", () => {
    expect(OPERATION_ROLE_DIMENSION).toHaveLength(4);
    expect(LEASE_LIFECYCLE_DIMENSION).toHaveLength(2);
    expect(STORED_STATE_DIMENSION).toHaveLength(4);
    expect(Object.keys(walletStateMatrixContract.invariants)).toEqual([
      "noLeasedWalletSelected",
      "noLeasedWalletSilentlyReleased",
    ]);
  });
});
