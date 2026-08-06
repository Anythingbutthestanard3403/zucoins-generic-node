import { FORBIDDEN_STATE_ALIASES as OPERATIONS_FORBIDDEN_STATE_ALIASES } from "../operations/states.contract.ts";
import { FORBIDDEN_EVENT_ALIASES as OPERATIONS_FORBIDDEN_EVENT_ALIASES } from "../operations/events.contract.ts";
import { AFTER_LANDING_KINDS } from "../operations/lifecycle.contract.ts";

/**
 * The closed forbidden-alias reject-list. The state-alias and event-name-alias halves already
 * have a byte-authoritative home with their own scanner exemptions in the `operations/`
 * concern (`states.contract.ts`, `events.contract.ts`) — re-exported here under their existing
 * names, never retyped, so this module is never a second scan-exemption authority for the same
 * bytes. The event-name GLOB half has no other frozen home; this module is its first
 * freeze.
 */

/** "Must never appear as Layer-1 states" — states.contract.ts is the byte authority. */
export const FORBIDDEN_STATE_ALIASES = OPERATIONS_FORBIDDEN_STATE_ALIASES;

/** "Must never appear as ... public events" — events.contract.ts is the byte authority. */
export const FORBIDDEN_EVENT_ALIASES = OPERATIONS_FORBIDDEN_EVENT_ALIASES;

/** The closed event-NAME-GLOB reject-list. Not frozen anywhere else in this package. */
export const FORBIDDEN_EVENT_GLOBS = ["reservation.*", "payment.*", "checkout.*", "refund.*"] as const;

export type ForbiddenEventGlob = (typeof FORBIDDEN_EVENT_GLOBS)[number];

/**
 * The two documented exceptions. `SUBMIT_STARTED` is permitted only as an
 * execution-phase value — this package does not yet freeze the execution-phase enum, so only
 * the exception name is recorded for the census negative-path coverage below. `HOLD` is
 * permitted only as `after_landing.kind`; sourced from `AFTER_LANDING_KINDS` rather
 * than retyped, since that array is the byte authority for the literal.
 */
export const FORBIDDEN_ALIAS_EXCEPTIONS = {
  executionPhaseOnly: "SUBMIT_STARTED",
  afterLandingKindOnly: AFTER_LANDING_KINDS[0],
} as const;

export const SOURCE = "forbidden state/event aliases; compat-literal-preservation" as const;
