import { EXPIRY_RECONCILE_RELEASE_ORDER } from "./ordering.js"; // contract-allow:ordering-module-path
import { FORBIDDEN_SHORTCUTS, EVIDENCE_DISPOSAL_ON_EXPIRY_ALLOWED } from "./shortcuts.js";
import { POST_BOUNDARY_RESOLUTIONS } from "./resolution.js";

// the named concern aggregate: the expiry -> reconcile -> release sequencing contract, frozen as data.
// Dispositions are drawn from .1 (resolution.ts) — .1 wins. There is no release proof shape here:
// the receive-expiry rule's post-boundary branch has no release disposition at any proof level (see the.2 sequencing module).
export const expiryOrderingContract = {
  order: EXPIRY_RECONCILE_RELEASE_ORDER, // contract-allow:frozen-contract-field-name
  dispositions: POST_BOUNDARY_RESOLUTIONS,
  forbiddenShortcuts: FORBIDDEN_SHORTCUTS,
  evidenceDisposalOnExpiryAllowed: EVIDENCE_DISPOSAL_ON_EXPIRY_ALLOWED,
} as const;
