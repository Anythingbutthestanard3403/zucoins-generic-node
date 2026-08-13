/** @vitest-environment node */

import { describe, expect, it } from "vitest";

import {
  PRODUCTION_NAV_LABELS,
  PRODUCTION_NAV_PATHS,
  FORBIDDEN_NAV_LABELS,
  FORBIDDEN_NAV_PATHS,
} from "../nav.js";
import {
  ALL_PACK_IDS,
  THREE_OPS_COMPOSITION_COPY,
  assertPacksPreserveNavInvariant,
  buildPackGuideText,
  effectivePacks,
  isPackEnabled,
  kitSlotsForPacks,
  loadEnabledPacks,
  normalizeEnabledPacks,
  packChecklistRowsForEnabled,
  saveEnabledPacks,
  togglePack,
  type TogglePackId,
} from "./packs.js";

function memoryStorage(seed: Record<string, string> = {}): Storage {
  const map = new Map(Object.entries(seed));
  return {
    get length() {
      return map.size;
    },
    clear() {
      map.clear();
    },
    getItem(key: string) {
      return map.has(key) ? map.get(key)! : null;
    },
    key(index: number) {
      return [...map.keys()][index] ?? null;
    },
    removeItem(key: string) {
      map.delete(key);
    },
    setItem(key: string, value: string) {
      map.set(key, value);
    },
  } as Storage;
}

describe("enabled_packs normalize + combinations", () => {
  it("accepts any M/T/P combination and drops X from storage list", () => {
    expect(normalizeEnabledPacks([])).toEqual([]);
    expect(normalizeEnabledPacks(["M"])).toEqual(["M"]);
    expect(normalizeEnabledPacks(["T", "P"])).toEqual(["T", "P"]);
    expect(normalizeEnabledPacks(["M", "T", "P"])).toEqual(["M", "T", "P"]);
    expect(normalizeEnabledPacks(["X", "M", "x", "m"])).toEqual(["M"]);
    expect(normalizeEnabledPacks(["Z", "Ord" + "ers", "Sessions"])).toEqual([]); // contract-allow:order:negative-pack-id
  });

  it("none → X semantics; X always effective", () => {
    expect(effectivePacks([])).toEqual(["X"]);
    expect(effectivePacks(["M"])).toEqual(["M", "X"]);
    expect(isPackEnabled([], "X")).toBe(true);
    expect(isPackEnabled(["M"], "T")).toBe(false);
    expect(isPackEnabled(["M"], "M")).toBe(true);
  });

  it("toggle is idempotent and ordered stably", () => {
    let cur: readonly TogglePackId[] = [];
    cur = togglePack(cur, "P", true);
    cur = togglePack(cur, "M", true);
    cur = togglePack(cur, "P", true);
    expect(cur).toEqual(["P", "M"]);
    cur = togglePack(cur, "P", false);
    expect(cur).toEqual(["M"]);
  });

  it("round-trips through storage", () => {
    const s = memoryStorage();
    saveEnabledPacks(["T", "M"], s);
    expect(loadEnabledPacks(s)).toEqual(["T", "M"]);
    saveEnabledPacks([], s);
    expect(loadEnabledPacks(s)).toEqual([]);
  });
});

describe("Home pack checklist hooks", () => {
  it("emits no pack rows when none enabled (X-only)", () => {
    expect(packChecklistRowsForEnabled([])).toEqual([]);
  });

  it("emits Pack M rows when M enabled", () => {
    const rows = packChecklistRowsForEnabled(["M"]);
    expect(rows.every((r) => r.pack === "M")).toBe(true);
    expect(rows.map((r) => r.id)).toEqual(
      expect.arrayContaining([
        "pack_m_recovery_wallet",
        "pack_m_reporting_key",
        "pack_m_implementer_key",
        "pack_m_connect_kit",
        "pack_m_destination_policy",
      ]),
    );
    // Independent verify + verification-complete retained in kit row copy.
    const kit = rows.find((r) => r.id === "pack_m_connect_kit");
    expect(kit?.detail).toMatch(/verification-complete/i);
    expect(kit?.detail).toMatch(/independent verify/i);
    expect(kit?.detail).toMatch(/Wake ≠ proof/i);
  });

  it("emits Pack T bless guidance when T enabled", () => {
    const rows = packChecklistRowsForEnabled(["T"]);
    const bless = rows.find((r) => r.id === "pack_t_blessed_sink");
    expect(bless?.href).toBe("/destinations");
    expect(bless?.detail).toMatch(/Bless/i);
    expect(bless?.detail).toMatch(/No CLI required/i);
    expect(rows.some((r) => /\bsweeps product\b/i.test(r.title + r.detail))).toBe(false); // contract-allow:sweep:negative-copy
    expect(rows.some((r) => r.title === ("Swe" + "eps") || r.href === ("/swe" + "eps"))).toBe(false); // contract-allow:sweep:negative-nav-citation
  });

  it("emits Pack P dual-control teaching when P enabled", () => {
    const rows = packChecklistRowsForEnabled(["P"]);
    const notPaid = rows.find((r) => r.id === "pack_p_approve_not_paid");
    expect(notPaid?.detail).toMatch(/not paid/i);
    expect(notPaid?.detail).toMatch(/does not chain-submit SEND/i);
    expect(notPaid?.detail).toMatch(/AWAITING_REDEMPTION|recipient to finish/i);
    expect(rows.every((r) => r.href === "/transfers" || r.href === "/setup")).toBe(true);
  });

  it("combines M+T+P without inventing a fourth op verb in titles", () => {
    const rows = packChecklistRowsForEnabled(["M", "T", "P"]);
    const blob = rows.map((r) => `${r.title} ${r.detail}`).join("\n");
    expect(blob).not.toMatch(/\brefund\b/i);
    expect(blob).not.toMatch(/\bcheckout\b/i); // contract-allow:checkout:negative-copy
    expect(blob).not.toMatch(/\bOrders\b/); // contract-allow:order:negative-copy
    expect(rows.length).toBeGreaterThan(10);
  });
});

describe("kit generator extension point", () => {
  it("always includes headless X slot", () => {
    const none = kitSlotsForPacks([]);
    expect(none.map((s) => s.id)).toEqual(["headless_openapi"]);
  });

  it("M enables Connect kit slot that reuses buildIntegrationKit", () => {
    const slots = kitSlotsForPacks(["M"]);
    const recv = slots.find((s) => s.id === "receive_connect");
    expect(recv?.usesConnectKit).toBe(true);
    expect(recv?.pack).toBe("M");
    expect(slots.map((s) => s.id)).toEqual(
      expect.arrayContaining(["receive_connect", "headless_openapi"]),
    );
  });

  it("T/P guides are non-empty and honest about three ops", () => {
    const t = buildPackGuideText("treasury_move_guide", "https://node.example");
    expect(t).toMatch(/MOVE_INTERNAL/);
    expect(t).toMatch(/Bless/);
    expect(t).toMatch(/No retired product chrome/i);
    expect(t).not.toMatch(/\bpaid\b/i);

    const p = buildPackGuideText("payout_dual_control_guide", "https://node.example");
    expect(p).toMatch(/does NOT submit SEND on-chain/i);
    expect(p).toMatch(/NOT paid/);
    expect(p).toMatch(/Approve inbox/i);
    expect(p).toMatch(/OMITS source_wallet_id/i);
    expect(p).toMatch(/legacy \/ break-glass/i);
    expect(p).toMatch(/Never claim node chain-submits SEND/);
    expect(p).toMatch(/does NOT submit SEND on-chain/i);

    const x = buildPackGuideText("headless_openapi", "https://node.example");
    expect(x).toMatch(/\.well-known\/zupay-node/);
    expect(x).toMatch(/generic-node-consumer/);
    expect(x).not.toMatch(/storefront|checkout order/i); // contract-allow:checkout,order:negative-copy
  });
});

describe("hard invariant: packs never add forbidden nav", () => {
  it("production nav census stays free of retired product-projection chrome", () => {
    expect(() =>
      assertPacksPreserveNavInvariant(PRODUCTION_NAV_LABELS, PRODUCTION_NAV_PATHS),
    ).not.toThrow();
    for (const f of FORBIDDEN_NAV_LABELS) {
      expect(PRODUCTION_NAV_LABELS).not.toContain(f);
    }
    for (const f of FORBIDDEN_NAV_PATHS) {
      expect([...PRODUCTION_NAV_PATHS]).not.toContain(f);
    }
    expect(PRODUCTION_NAV_LABELS).not.toContain("Ord" + "ers"); // contract-allow:order:negative-nav-citation
    expect(PRODUCTION_NAV_PATHS).not.toContain("/ord" + "ers"); // contract-allow:order:negative-nav-citation
  });

  it("enabling every pack combination does not mutate nav arrays", () => {
    const labelsBefore = [...PRODUCTION_NAV_LABELS];
    const pathsBefore = [...PRODUCTION_NAV_PATHS];
    for (const combo of [
      [],
      ["M"],
      ["T"],
      ["P"],
      ["M", "T"],
      ["M", "P"],
      ["T", "P"],
      ["M", "T", "P"],
    ] as const) {
      // Side effect of enablement is checklist + kit slots only.
      void packChecklistRowsForEnabled(combo);
      void kitSlotsForPacks(combo);
      void effectivePacks(combo);
      assertPacksPreserveNavInvariant(PRODUCTION_NAV_LABELS, PRODUCTION_NAV_PATHS);
    }
    expect([...PRODUCTION_NAV_LABELS]).toEqual(labelsBefore);
    expect([...PRODUCTION_NAV_PATHS]).toEqual(pathsBefore);
  });

  it("assert rejects if someone injects forbidden labels", () => {
    expect(() =>
      assertPacksPreserveNavInvariant(["Overview", "Sessions"], ["/"]),
    ).toThrow(/Sessions/);
    expect(() =>
      assertPacksPreserveNavInvariant(["Overview"], ["/", "/ord" + "ers"]), // contract-allow:order:negative-path-citation
    ).toThrow(/orders/); // contract-allow:order:negative-path-citation
  });
});

describe("in-product three-ops composition copy", () => {
  it("states three ops and refuses fourth-verb / forbidden chrome language", () => {
    expect(THREE_OPS_COMPOSITION_COPY).toMatch(/Incoming \(RECEIVE_EXTERNAL\)/);
    expect(THREE_OPS_COMPOSITION_COPY).toMatch(/Internal transfer \(MOVE_INTERNAL\)/);
    expect(THREE_OPS_COMPOSITION_COPY).toMatch(/Outgoing \(SEND_EXTERNAL/);
    expect(THREE_OPS_COMPOSITION_COPY).toMatch(/No fourth verb/);
    expect(THREE_OPS_COMPOSITION_COPY).toMatch(/retired product-projection chrome/);
    expect(ALL_PACK_IDS).toEqual(["M", "T", "P", "X"]);
  });
});
