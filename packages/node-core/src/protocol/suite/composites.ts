// Typed shapes for the two Appendix structured composites and the
// closed enums builders/parsers need. The registry's `encodeAfterLanding`/`encodeSourceSelector`
// validate these structurally against `unknown`; this module gives callers a TS-checked shape to
// build with instead of hand-assembling an object the encoder might reject at runtime.

import type { Uuid } from "../scalars.js";
import { NEUTRAL_EVENT_TYPES } from "./registry.js";

export type AfterLanding =
  | { readonly kind: "HOLD"; readonly destination_id: null }
  | { readonly kind: "INTERNAL_MOVE"; readonly destination_id: Uuid };

export interface SourceSelector {
  readonly kind: "WALLET_ID";
  readonly wallet_id: Uuid;
}

export type NodeEventType = (typeof NEUTRAL_EVENT_TYPES)[number];

export type WalletStateKind = "GENESIS" | "HEAD";
