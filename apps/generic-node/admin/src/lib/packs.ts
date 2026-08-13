/**
 * Connect packs framework — enablement, checklist hooks, kit slots.
 *
 * Packs are compositions of the same three money ops (no fourth verb, no
 * forbidden nav). Persistence is operator-local (localStorage) until a durable
 * setup_state prefs port exists; shape is enabled_packs M|T|P|X.
 *
 *   M — Accept external value   → RECEIVE_EXTERNAL + full Connect kit
 *   T — Internal moves          → MOVE_INTERNAL + blessed sinks
 *   P — External sends          → SEND_EXTERNAL + Approve inbox (node never chain-submits SEND)
 *   X — Headless                → API/OpenAPI/pin/verifier only (default when none of M/T/P)
 */

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

import { FORBIDDEN_NAV_LABELS, FORBIDDEN_NAV_PATHS } from "../nav.js";

export type TogglePackId = "M" | "T" | "P";
export type PackId = TogglePackId | "X";

export const TOGGLE_PACK_IDS: readonly TogglePackId[] = ["M", "T", "P"] as const;
export const ALL_PACK_IDS: readonly PackId[] = ["M", "T", "P", "X"] as const;

/** localStorage key for enabled toggle packs (M/T/P). X is never stored. */
export const ENABLED_PACKS_STORAGE_KEY = "zp-enabled-packs";

export type MoneyOpKind = OperationKind;

export interface PackDefinition {
  readonly id: PackId;
  readonly title: string;
  readonly purpose: string;
  /** Wire ops this pack composes (X composes none directly). */
  readonly ops: readonly MoneyOpKind[];
  /** Whether the operator can toggle this pack off Connect. X is always effective. */
  readonly toggleable: boolean;
}

/**
 * Plain-language pack cards. Copy states the three-ops composition explicitly.
 */
export const PACK_DEFINITIONS: readonly PackDefinition[] = [
  {
    id: "M",
    title: "Accept external value",
    purpose:
      "Receive ZKZ from outside this node. Composes Incoming (RECEIVE_EXTERNAL) only — " +
      "create → ARM → transfer_code → pin → independent verify → verification-complete. " +
      "Works for any receiver, not only storefronts.",
    ops: ["RECEIVE_EXTERNAL"],
    toggleable: true,
  },
  {
    id: "T",
    title: "Internal moves",
    purpose:
      "Move value between wallets you control on this node. Composes Internal transfer " +
      "(MOVE_INTERNAL) with blessed automatic sinks. No storefront required.",
    ops: ["MOVE_INTERNAL"],
    toggleable: true,
  },
  {
    id: "P",
    title: "External sends",
    purpose:
      "Request outgoing value that needs dual-control approval. Composes Outgoing " +
      "(SEND_EXTERNAL / needs approval). The node never chain-submits SEND — after " +
      "approve, the recipient must finish (not paid).",
    ops: ["SEND_EXTERNAL"],
    toggleable: true,
  },
  {
    id: "X",
    title: "Headless",
    purpose:
      "API-only operation: OpenAPI, discovery pin, and consumer verifier pointers. " +
      "No forced implementer website copy. Always available; default when no other pack is on.",
    ops: [],
    toggleable: false,
  },
] as const;

export function packDefinition(id: PackId): PackDefinition {
  const found = PACK_DEFINITIONS.find((p) => p.id === id);
  if (!found) throw new Error(`unknown pack ${id}`);
  return found;
}

/** Parse storage / API shape into toggle packs only (M|T|P). Unknown ids dropped. */
export function normalizeEnabledPacks(
  input: readonly string[] | null | undefined,
): readonly TogglePackId[] {
  if (!input || input.length === 0) return [];
  const out: TogglePackId[] = [];
  for (const raw of input) {
    const id = String(raw).trim().toUpperCase();
    if (id === "M" || id === "T" || id === "P") {
      if (!out.includes(id)) out.push(id);
    }
    // X is never stored in the enabled list — it is implicit.
  }
  return out;
}

/**
 * Effective packs for UI: enabled M/T/P plus X always.
 * When none of M/T/P are on, semantics are X-only (headless default).
 */
export function effectivePacks(
  enabled: readonly TogglePackId[],
): readonly PackId[] {
  return [...enabled, "X"];
}

export function isPackEnabled(
  enabled: readonly TogglePackId[],
  id: PackId,
): boolean {
  if (id === "X") return true;
  return enabled.includes(id);
}

export function loadEnabledPacks(
  storage: Pick<Storage, "getItem"> = localStorage,
): readonly TogglePackId[] {
  try {
    const raw = storage.getItem(ENABLED_PACKS_STORAGE_KEY);
    if (raw == null || raw === "") return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return normalizeEnabledPacks(parsed.map(String));
  } catch {
    return [];
  }
}

export function saveEnabledPacks(
  packs: readonly TogglePackId[],
  storage: Pick<Storage, "setItem"> = localStorage,
): void {
  const normalized = normalizeEnabledPacks(packs);
  storage.setItem(ENABLED_PACKS_STORAGE_KEY, JSON.stringify(normalized));
}

export function togglePack(
  current: readonly TogglePackId[],
  id: TogglePackId,
  on: boolean,
): readonly TogglePackId[] {
  if (on) {
    if (current.includes(id)) return current;
    return normalizeEnabledPacks([...current, id]);
  }
  return current.filter((p) => p !== id);
}

// ---------------------------------------------------------------------------
// Home checklist hooks
// ---------------------------------------------------------------------------

export type PackChecklistStatus = "guidance" | "ok" | "blocked" | "unknown";

export interface PackChecklistRow {
  readonly id: string;
  readonly pack: PackId;
  readonly title: string;
  readonly detail: string;
  readonly href: string;
  readonly status: PackChecklistStatus;
}

/** Pack M checklist — teachable in-product. */
export const PACK_M_CHECKLIST: readonly Omit<PackChecklistRow, "status">[] = [
  {
    id: "pack_m_recovery_wallet",
    pack: "M",
    title: "≥1 recovery-verified node_generated wallet",
    detail:
      "Receive-eligible = node_generated ∧ recovery_verified_at ∧ AVAILABLE. Ceremony is the sole writer of recovery_verified_at.",
    href: "/recovery-ceremony",
  },
  {
    id: "pack_m_reporting_key",
    pack: "M",
    title: "ACTIVE reporting key",
    detail:
      "ARM and verification-complete need a reporting-signed request. Issue on Reporting; keep the private seed server-side only.",
    href: "/reporting-keys",
  },
  {
    id: "pack_m_implementer_key",
    pack: "M",
    title: "Implementer key (or path to issue)",
    detail:
      "POST /v1/receives uses an ik_… bearer on your server only — never in a browser bundle.",
    href: "/api-keys",
  },
  {
    id: "pack_m_connect_kit",
    pack: "M",
    title: "Full Connect kit understood",
    detail:
      "create → ARM → transfer_code → pin → independent verify → verification-complete. Wake ≠ proof. Skip verification-complete and the pool stays exhausted (receiver PINNED).",
    href: "/integration",
  },
  {
    id: "pack_m_destination_policy",
    pack: "M",
    title: "Destination policy: HOLD vs INTERNAL_MOVE",
    detail:
      "After landing, HOLD leaves value in the receive wallet; INTERNAL_MOVE consolidates to a blessed sink. Still only three ops — no retired product chrome.",
    href: "/destinations",
  },
] as const;

/** Pack T checklist. */
export const PACK_T_CHECKLIST: readonly Omit<PackChecklistRow, "status">[] = [
  {
    id: "pack_t_totp",
    pack: "T",
    title: "TOTP enrolled",
    detail: "Money mutations require fresh TOTP. Device signature is additive only.",
    href: "/setup",
  },
  {
    id: "pack_t_device",
    pack: "T",
    title: "Approval device enrolled",
    detail: "Bless and dual-control paths need a device key on this node.",
    href: "/destinations",
  },
  {
    id: "pack_t_blessed_sink",
    pack: "T",
    title: "≥1 blessed automatic sink",
    detail:
      "Bless a destination in-UI (zp-destination-bless-v1 + TOTP + device sign). No CLI required for the happy path.",
    href: "/destinations",
  },
  {
    id: "pack_t_move_path",
    pack: "T",
    title: "MOVE_INTERNAL path documented",
    detail:
      "Implementer API creates Internal transfers. Activity shows them with plain labels. No implementer website required.",
    href: "/operations",
  },
] as const;

/** Pack P checklist. */
export const PACK_P_CHECKLIST: readonly Omit<PackChecklistRow, "status">[] = [
  {
    id: "pack_p_totp",
    pack: "P",
    title: "TOTP enrolled",
    detail: "Approve uses TOTP floor — device signature never replaces it.",
    href: "/setup",
  },
  {
    id: "pack_p_device",
    pack: "P",
    title: "Approval device enrolled",
    detail: "Approver path = Approve inbox + TOTP + device sign.",
    href: "/transfers",
  },
  {
    id: "pack_p_inbox_dry_run",
    pack: "P",
    title: "Approver familiar with inbox",
    detail:
      "Open Transfers / pending approvals. Practice the flow before production sends.",
    href: "/transfers",
  },
  {
    id: "pack_p_approve_not_paid",
    pack: "P",
    title: "Approve alone ≠ paid",
    detail:
      "After approve, state may be waiting for recipient to finish (AWAITING_REDEMPTION) — not paid. Node does not chain-submit SEND. Observe-land is separate.",
    href: "/transfers",
  },
  {
    id: "pack_p_policy_mode",
    pack: "P",
    title: "Dual-control policy known",
    detail:
      "Single human (TOTP+device) vs two distinct operators. Policy enforcement is separate; teach the mode in-product first.",
    href: "/transfers",
  },
  {
    id: "pack_p_omit_source",
    pack: "P",
    title: "Omit source_wallet_id by default",
    detail:
      "Implementer create body: destination + amount (+ idempotency). Node assigns send-capable worker (may top up from internal-only hubs). Explicit source is legacy only. Node does not chain-submit SEND.",
    href: "/transfers",
  },
] as const;

const PACK_CHECKLISTS: Record<TogglePackId, readonly Omit<PackChecklistRow, "status">[]> = {
  M: PACK_M_CHECKLIST,
  T: PACK_T_CHECKLIST,
  P: PACK_P_CHECKLIST,
};

/**
 * Home rows for enabled packs. Status stays "guidance" unless a caller
 * enriches from readiness signals — never fake green.
 */
export function packChecklistRowsForEnabled(
  enabled: readonly TogglePackId[],
): readonly PackChecklistRow[] {
  const rows: PackChecklistRow[] = [];
  for (const id of TOGGLE_PACK_IDS) {
    if (!enabled.includes(id)) continue;
    for (const item of PACK_CHECKLISTS[id]) {
      rows.push({ ...item, status: "guidance" });
    }
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Kit generator extension point
// ---------------------------------------------------------------------------

export type KitGeneratorId =
  | "receive_connect"
  | "treasury_move_guide"
  | "payout_dual_control_guide"
  | "headless_openapi";

export interface KitGeneratorSlot {
  readonly id: KitGeneratorId;
  readonly pack: PackId;
  readonly title: string;
  readonly description: string;
  /** When true, slot reuses the issue-time Connect kit (buildIntegrationKit). */
  readonly usesConnectKit: boolean;
}

export const KIT_GENERATOR_REGISTRY: readonly KitGeneratorSlot[] = [
  {
    id: "receive_connect",
    pack: "M",
    title: "Connect kit — full Incoming path",
    description:
      "Issue-time handoff: create → ARM → transfer_code → pin → independent verify → verification-complete. Uses the existing Connect kit generator.",
    usesConnectKit: true,
  },
  {
    id: "treasury_move_guide",
    pack: "T",
    title: "Internal moves guide",
    description:
      "Bless sinks in-UI, create MOVE_INTERNAL via implementer API, read Activity with plain Internal transfer labels.",
    usesConnectKit: false,
  },
  {
    id: "payout_dual_control_guide",
    pack: "P",
    title: "External send dual-control guide",
    description:
      "Request SEND server-side (omit source_wallet_id by default) → Approve inbox (TOTP + device) or auto-approve → recipient finishes. Approve ≠ paid; node never chain-submits SEND.",
    usesConnectKit: false,
  },
  {
    id: "headless_openapi",
    pack: "X",
    title: "Headless pointers",
    description:
      "OpenAPI surface, /.well-known/zupay-node discovery pin, and @zucoins/generic-node-consumer / consumer-example verifiers. No forced implementer copy.",
    usesConnectKit: false,
  },
] as const;

/** Kit slots visible for the current enablement (X always included). */
export function kitSlotsForPacks(
  enabled: readonly TogglePackId[],
): readonly KitGeneratorSlot[] {
  const effective = new Set<PackId>(effectivePacks(enabled));
  return KIT_GENERATOR_REGISTRY.filter((slot) => effective.has(slot.pack));
}

/** Static guide text for non-Connect kit slots (downloadable / copyable). */
export function buildPackGuideText(slotId: KitGeneratorId, nodeBaseUrl: string): string {
  const base = nodeBaseUrl.replace(/\/$/, "");
  switch (slotId) {
    case "treasury_move_guide":
      return `ZU NODE — PACK T INTERNAL MOVES GUIDE
=====================================

Three money ops only. This pack composes Internal transfer (MOVE_INTERNAL).

1. TOTP enrolled (operator session).
2. Approval device enrolled on this node.
3. Bless ≥1 automatic sink in-UI at ${base}/destinations
   (zp-destination-bless-v1 + device signature + fresh TOTP — not CLI).
4. Create MOVE_INTERNAL via implementer API (server-side ik_… bearer).
5. Activity / Operations shows Internal transfer with plain labels.

No implementer website required. No retired product chrome. No fourth money verb.
`;
    case "payout_dual_control_guide":
      return `ZU NODE — PACK P EXTERNAL SENDS (DUAL-CONTROL)
=============================================

Three money ops only. This pack composes Outgoing (SEND_EXTERNAL / needs approval).

Normative semantics (also on Transfer detail + Approve inbox):
1. Someone REQUESTS SEND via implementer API (server-side only).
2. Default create body OMITS source_wallet_id — node assigns a free
   send-capable worker (and may MOVE_INTERNAL top-up from internal-only
   hubs). Do not pin “the send wallet” in integration config.
3. Explicit source_wallet_id remains accepted as a legacy / break-glass
   path; must be send-capable (internal-only sources are refused).
4. Approver uses Approve inbox with TOTP + device sign (or auto-approve
   under policy caps — see docs/operations/auto-approve-external-sends.md).
5. The node does NOT submit SEND on-chain.
6. After approve, state may be waiting for recipient to finish
   (AWAITING_REDEMPTION) — NOT paid.
7. Observe-land / completion lander is separate.
8. Dual-control modes: single human (TOTP+device) vs two distinct operators.
9. Support: “which wallet sent?” → GET operation source_wallet_id on the
   node — not an env/config key in the implementer product.

Happy-path create (preferred):
  POST /v1/external-sends
  { "destination_address": "…", "amount_zkz": "…" }
  (+ Idempotency-Key). Response always includes resolved source_wallet_id.

Operator setup: designate internal-only hubs + send-capable workers on the
admin wallet money-mode controls; fund hubs; size the worker pool for peak
concurrent unsettled sends. Hand integrations only base URL + ik_… key.

Approver path: ${base}/transfers
Approve alone ≠ paid. Never claim node chain-submits SEND.
`;
    case "headless_openapi":
      return `ZU NODE — PACK X HEADLESS POINTERS
=================================

No forced implementer website copy. Operate via API only.

1. OpenAPI / route surface on this node (implementer + admin).
2. Discovery pin: GET ${base}/.well-known/zupay-node
   Pin node identity independently of any hosted platform.
3. Independent verify packages:
   - @zucoins/generic-node-consumer
   - @zucoins/consumer-example
4. Wake (SSE/status) ≠ proof of settlement. Consumers verify on chain.

Still only three money ops: Incoming, Internal transfer, Outgoing (needs approval).
`;
    case "receive_connect":
      return ""; // filled by buildIntegrationKit when ik_ present
    default: {
      const _exhaustive: never = slotId;
      return _exhaustive;
    }
  }
}

// ---------------------------------------------------------------------------
// Hard invariant: packs never add forbidden nav
// ---------------------------------------------------------------------------

/**
 * Assert production nav labels/paths stay free of retired product-projection chrome
 * after pack enablement. Packs must not inject nav entries.
 */
export function assertPacksPreserveNavInvariant(
  navLabels: readonly string[],
  navPaths: readonly string[] = [],
): void {
  for (const forbidden of FORBIDDEN_NAV_LABELS) {
    if (navLabels.includes(forbidden)) {
      throw new Error(`packs must not add forbidden nav label: ${forbidden}`);
    }
  }
  for (const label of navLabels) {
    if (/session|sweep|webhook|orders?/i.test(label) && !/^reporting$/i.test(label)) { // contract-allow:sweep,order:retired-nav-label-guard
      // "Reporting" is allowed; bare retired product-projection labels are not.
      if (
        FORBIDDEN_NAV_LABELS.includes(label as (typeof FORBIDDEN_NAV_LABELS)[number]) ||
        /^orders?$/i.test(label) // contract-allow:order:retired-nav-label-guard
      ) {
        throw new Error(`packs must not add forbidden nav label: ${label}`);
      }
    }
  }
  for (const forbidden of FORBIDDEN_NAV_PATHS) {
    if (navPaths.includes(forbidden)) {
      throw new Error(`packs must not add forbidden nav path: ${forbidden}`);
    }
  }
  for (const p of navPaths) {
    if (
      p === "/sessions" ||
      p === "/sweeps" || // contract-allow:sweep:retired-nav-path-guard
      p === "/webhooks" ||
      p === "/orders" || // contract-allow:order:retired-nav-path-guard
      p.startsWith("/orders/") // contract-allow:order:retired-nav-path-guard
    ) {
      throw new Error(`packs must not add forbidden nav path: ${p}`);
    }
  }
}

/** Three-ops composition sentence for in-product Connect copy. */
export const THREE_OPS_COMPOSITION_COPY =
  "Packs compose the same three money ops only: Incoming (RECEIVE_EXTERNAL), " +
  "Internal transfer (MOVE_INTERNAL), and Outgoing (SEND_EXTERNAL / needs approval). " +
  "No fourth verb. No retired product-projection chrome.";
