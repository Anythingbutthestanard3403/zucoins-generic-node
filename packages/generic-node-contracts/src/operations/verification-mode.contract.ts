/**
 * Per-operation verification mode (ZTR-1299 / epic ZTR-1298).
 *
 * Operation-level metadata vocabulary only — NOT a Layer-1 operation state and NOT a
 * durable public event. Chosen at admission, immutable thereafter.
 *
 * - INDEPENDENT (default): consumer arms for the transfer code and posts
 *   verification-complete (verdict + landing proof) to release the wallet lease.
 * - NODE_VERIFIED: the node's own landing proof closes custody when operator policy
 *   allows it; arm / verification-complete against such an op are mode mismatches.
 */
export const VERIFICATION_MODES = ["INDEPENDENT", "NODE_VERIFIED"] as const;

export type VerificationMode = (typeof VERIFICATION_MODES)[number];

/** Default when the create request omits `verification_mode`. */
export const DEFAULT_VERIFICATION_MODE = "INDEPENDENT" as const satisfies VerificationMode;

/**
 * Lease-release status when custody closes under NODE_VERIFIED (landing commit mints
 * the release proof). Distinct from consumer-driven RELEASED so audit can tell the paths
 * apart. Wire/ack vocabulary extension — not a receive_release_status / expiry token.
 */
export const RELEASED_NODE_VERIFIED = "RELEASED_NODE_VERIFIED" as const;

/**
 * Operator policy document key (node_settings) gating NODE_VERIFIED at admission.
 * Fail-closed: absent / unreadable / disabled → refuse NODE_VERIFIED (never silent
 * downgrade). Naming parallel to `ops.auto_approve_sends`.
 */
export const ALLOW_NODE_VERIFIED_SETTING_KEY = "ops.allow_node_verified" as const;

/**
 * Audit action when an operator edits the allow-node-verified policy document.
 * Parallel to `ops.auto_approve_sends_changed`.
 */
export const ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION =
  "ops.allow_node_verified_changed" as const;

/**
 * API error codes for verification-mode conflicts and admission refusal.
 * HTTP bindings are restated here so downstream packages import one table; the
 * cited-error census also lists the code strings.
 */
export const VERIFICATION_MODE_ERROR_CODES = [
  {
    code: "verification_mode_mismatch",
    http: 409,
    meaning:
      "armed or verification-complete was called on an operation whose verification_mode does not admit that path.",
  },
  {
    code: "verification_mode_not_allowed",
    http: 422,
    meaning:
      "NODE_VERIFIED was requested at admission but operator policy does not allow it for the calling implementer.",
  },
] as const;

export type VerificationModeErrorCode = (typeof VERIFICATION_MODE_ERROR_CODES)[number]["code"];

export const SOURCE =
  "per-operation verification mode: INDEPENDENT | NODE_VERIFIED metadata; RELEASED_NODE_VERIFIED; ops.allow_node_verified" as const;
