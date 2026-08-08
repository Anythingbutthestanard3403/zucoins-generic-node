// Dual-control approval policy.
//
// Modes:
// - single_operator: same admin_operator may issue the approval-challenge and approve.
// - two_human: distinct admin_operator on challenge vs approve; same operator both sides → fail closed.
//
// Server enforces; SPA copy must match. An unset setting means the deployment added
// no optional policy — doc 01 §4.2 makes node policy opt-in — which is single_operator.
// A setting that is PRESENT but unrecognised never resolves to a mode; see
// parseDualControlMode.

export const DUAL_CONTROL_MODES = ["single_operator", "two_human"] as const;
export type DualControlMode = (typeof DUAL_CONTROL_MODES)[number];

export const DUAL_CONTROL_SETTING_KEY = "ops.dual_control_mode" as const;

/** Plain-language labels for inbox + Pack P / security notes. */
export const DUAL_CONTROL_COPY: Readonly<
  Record<
    DualControlMode,
    {
      readonly short: string;
      readonly long: string;
      readonly approve_hint: string;
    }
  >
> = {
  single_operator: {
    short: "Single-operator",
    long: "One human may both request the approval challenge and approve. TOTP + device still required when enrolled.",
    approve_hint: "You may approve sends you challenged (single-operator mode).",
  },
  two_human: {
    short: "Two-human dual control",
    long: "A different admin operator must approve than the one who requested the challenge. Same person on both sides is rejected.",
    approve_hint: "A different operator must approve (two-human dual control).",
  },
};

/**
 * Resolve a configured dual-control setting, fail closed (doc 01 §4.2).
 *
 * Only an exact mode literal selects a mode. Absence selects the documented
 * "no optional policy" default. Everything else — `two-human`, `TWO_HUMAN`,
 * `" two_human"`, `""` — is `"invalid"`: the caller must refuse to boot rather
 * than pick a mode, because silently picking one always picks the weaker one.
 * The production caller is the frozen schema's DUAL_CONTROL_MODE field
 * (apps/generic-node/src/config/env-schema.ts), which rejects the same set.
 */
export function parseDualControlMode(
  raw: string | null | undefined,
): DualControlMode | "invalid" {
  if (raw === null || raw === undefined) return "single_operator";
  return (DUAL_CONTROL_MODES as readonly string[]).includes(raw)
    ? (raw as DualControlMode)
    : "invalid";
}

export function dualControlModeLabel(mode: DualControlMode): string {
  return DUAL_CONTROL_COPY[mode].short;
}

export type DualControlCheckResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code: "same_operator_both_sides";
      readonly detail: string;
    };

/**
 * Enforce two-human distinctness. `challengeOperatorId` is the admin_operators.id
 * that issued/refreshed the approval challenge; `approverOperatorId` is the
 * session user approving.
 */
export function enforceDualControlOperators(
  mode: DualControlMode,
  challengeOperatorId: string | null | undefined,
  approverOperatorId: string,
): DualControlCheckResult {
  if (mode !== "two_human") {
    return { ok: true };
  }
  if (
    typeof challengeOperatorId === "string" &&
    challengeOperatorId.length > 0 &&
    challengeOperatorId === approverOperatorId
  ) {
    return {
      ok: false,
      code: "same_operator_both_sides",
      detail:
        "Two-human dual control requires a different admin operator to approve than the one who requested the challenge.",
    };
  }
  // No recorded challenge issuer → cannot prove distinctness; fail closed in two_human.
  if (challengeOperatorId === null || challengeOperatorId === undefined || challengeOperatorId.length === 0) {
    return {
      ok: false,
      code: "same_operator_both_sides",
      detail:
        "Two-human dual control requires a recorded challenge issuer; re-issue the approval challenge.",
    };
  }
  return { ok: true };
}

export interface DualControlPolicyPort {
  getMode(): DualControlMode | Promise<DualControlMode>;
}

export function fixedDualControlPolicy(mode: DualControlMode): DualControlPolicyPort {
  return { getMode: () => mode };
}

/** In-memory policy for tests / lab. */
export class InMemoryDualControlPolicy implements DualControlPolicyPort {
  constructor(private mode: DualControlMode = "single_operator") {}

  getMode(): DualControlMode {
    return this.mode;
  }

  setMode(mode: DualControlMode): void {
    this.mode = mode;
  }
}
