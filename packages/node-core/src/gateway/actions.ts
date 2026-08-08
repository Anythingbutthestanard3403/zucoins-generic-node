// gateway action vocabulary and the structural read/submit split
// (the never-blind-retry rule / — never blind-retry a submit). Mirrors the retired v1
// FailoverSafeActionName guarantee (packages/splitchain/src/failover.ts, reference-only):
// the read-safe union is every gateway action EXCEPT submit_transaction__v1, and that
// ABSENCE is the compile-time guarantee that the submit action can never be handed to
// the bounded read/retry path. The submit literal is imported from the frozen
// transfer-code concern (single source of truth — one string both the type layer and
// the runtime guard reference), never re-declared here.

import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";

// Gateway actions safe to re-attempt across endpoints with bounded jittered backoff:
// none can collide with the one-in-flight-transaction-per-wallet invariant (one in-flight tx per wallet). The
// submit action is intentionally absent from this list — see GatewayReadActionName.
export const READ_SAFE_ACTION_NAMES = [
  "get_transaction__v1",
  // The push host dispatches on the exact suffixed literal. The ten-character suffix is
  // an opaque per-action token transcribed VERBATIM from the shipped wallet bundle — it
  // is part of the name, not a version qualifier, and there is no derivation rule (do
  // not add one). The bare `__v1` forms are dead: live probe 2026-08-08 (ZTR-1152) got
  // 200 {"status":false,"code":"oysinkh3cy","message":'…Unsupported "action_name"…'}
  // for the bare name and a routed domain answer for the suffixed one. These literals
  // pin OUR OUTPUT only; the host's acceptance is verified at boot by the push
  // action-vocabulary probe (apps/generic-node/src/main.ts, gateway-read region), which
  // surfaces PushActionVocabularyRejectedError on drift.
  // Wallet 200.6 app.js:4841:
  "push_notification__subscribe__v1__tos2d5b5md",
  // Wallet 200.6 main.js:8866:
  "push_notification__has_subscription_for_public_key_base64urlsafe__v1__jxqlqcj5zv",
  // Wallet 200.6 main.js:8925 — zero production callers; unused vocabulary retained so
  // the read-safe union stays the complete gateway vocabulary minus submit:
  "push_notification__send_to_public_key_base64urlsafe__v1__jc34lsh7ps",
  // Wallet 200.6 app.js:4222:
  "push_notification__get_app_server_public_key__v1__nozleh4wul",
] as const;

// The read-safe union: every gateway action EXCEPT the submit action. Passing
// SUBMIT_ACTION_NAME where this type is expected is a compile error — there is no flag,
// counter, or configuration value that could be set wrong (the never-blind-retry rule, primary
// mechanism; the runtime guard in assertReadSafeActionName is the cast-bypass backstop).
export type GatewayReadActionName = (typeof READ_SAFE_ACTION_NAMES)[number];

// The full action vocabulary: the read-safe actions plus the single-shot submit action.
// Request building (request.ts) accepts this wider union — both paths construct the
// identical frozen form body; only WHICH PATH may carry which action differs.
export type GatewayActionName = GatewayReadActionName | typeof SUBMIT_ACTION_NAME;

// Raised by the runtime guard when a caller bypasses the type-level exclusion with a
// cast (e.g. `as unknown as GatewayReadActionName`). Defence in depth only — the primary
// mechanism is that the submit action has no code path into the read primitive at all.
export class GatewayUnsafeActionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GatewayUnsafeActionError";
  }
}

// Runtime backstop for the never-blind-retry rule: rejects ANY action name outside the frozen
// read-safe list (fail-closed — stricter than naming the submit action alone, since a
// cast could also smuggle in an entirely unknown name). Called at the top of the read
// primitive; throws before any endpoint is touched.
export function assertReadSafeActionName(actionName: string): asserts actionName is GatewayReadActionName {
  if ((READ_SAFE_ACTION_NAMES as readonly string[]).includes(actionName)) {
    return;
  }
  throw new GatewayUnsafeActionError(
    `action ${actionName} is not read-safe; ${SUBMIT_ACTION_NAME} must never enter the read/retry path (the never-blind-retry rule) — use the single-shot submit primitive`,
  );
}
