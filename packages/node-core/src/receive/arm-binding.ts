// Arm-request binding contract (pre-open half of the arm barrier).
//
// The arm request binds six fields:
// operation_id; node t0_observation_id; exact S0, P0, B0 independently captured by the
// consumer; the consumer's opened event cursor.
//
// Wire shape carries those bindings as:
// path :operation_id
// body { expected_row_version, t0:{observation_id, projection:{s,p,b_zkz}}, opened_cursor }
//
// Asymmetry — never conflate the two observation identities:
// * t0.observation_id names the **node's** durable RECEIVER_T0 row (so the node knows which
// of its own rows to compare against).
// * t0.projection is the **consumer's** independently-read {s,p,b_zkz}. The consumer never
// echoes the node's projection values; the node never imports the consumer's raw
// observation bytes into its ledger — only these three projection strings participate in
// the eventual four-field comparison (mutation deferred to).
//
// This module is pure data + validation. It does not open DB transactions, release codes, or
// burn reporting nonces.

import { ArmBody } from "../api/route-schemas.js";
import { compareT0Evidence, type T0EvidenceWire, type T0MismatchField } from "../api/routes/action-routes.js";

/** The six binding field names, as listed in the spec. */
export const ARM_REQUEST_BINDING_FIELDS = [
  "operation_id",
  "t0_observation_id",
  "s",
  "p",
  "b_zkz",
  "opened_cursor",
] as const;

export type ArmRequestBindingField = (typeof ARM_REQUEST_BINDING_FIELDS)[number];

/**
 * Consumer-supplied projection values. Named to make the asymmetry unmissable at call sites:
 * these are never the node's stored S0/P0/B0, even when they happen to equal them.
 */
export interface ConsumerT0Projection {
  readonly s: string;
  readonly p: string;
  readonly b_zkz: string;
}

/**
 * Parsed arm-request binding. `nodeT0ObservationId` is the consumer's claim about which
 * **node** durable observation to compare; `consumerProjection` is what the consumer read in
 * its own trust domain. No consumer observation id is modeled here.
 */
export interface ArmRequestBinding {
  readonly operationId: string;
  /** Node-side durable T0 observation id named by the request (wire `t0.observation_id`). */
  readonly nodeT0ObservationId: string;
  /** Independently captured consumer projection (wire `t0.projection`). */
  readonly consumerProjection: ConsumerT0Projection;
  /** Consumer's opened reporting-event cursor (wire `opened_cursor`, decimal string → bigint). */
  readonly openedCursor: bigint;
  /** CAS field (not one of the six binds; required on the wire). */
  readonly expectedRowVersion: number;
}

export type ArmBindingParseFailureCode =
  | "missing_field"
  | "invalid_scalar"
  | "unknown_field"
  | "malformed_body";

export type ArmBindingParseResult =
  | { readonly ok: true; readonly binding: ArmRequestBinding }
  | {
      readonly ok: false;
      readonly code: ArmBindingParseFailureCode;
      readonly field: ArmRequestBindingField | "expected_row_version" | "body" | "t0" | string;
      readonly message: string;
    };

const LOWER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Parse and validate the six-field arm-request binding from path operation_id + JSON body.
 * Rejects a request missing any binding field rather than silently defaulting.
 *
 * `body` is the already-decoded JSON value (strict-JSON intake is the caller's job). This
 * function never reads node-side T0 storage and never fills projection fields from anywhere.
 */
export function parseArmRequestBinding(input: {
  readonly operationId: string;
  readonly body: unknown;
}): ArmBindingParseResult {
  const { operationId, body } = input;

  if (typeof operationId !== "string" || operationId.length === 0 || !LOWER_UUID.test(operationId)) {
    return {
      ok: false,
      code: "invalid_scalar",
      field: "operation_id",
      message: "operation_id must be a lowercase canonical UUID",
    };
  }

  if (body === null || body === undefined) {
    return {
      ok: false,
      code: "malformed_body",
      field: "body",
      message: "arm request body is required",
    };
  }

  if (!isPlainObject(body)) {
    return {
      ok: false,
      code: "malformed_body",
      field: "body",
      message: "arm request body must be a JSON object",
    };
  }

  // Explicit presence checks for the six fields (plus expected_row_version) BEFORE Zod,
  // so a missing field reports the binding-field name rather than a generic schema failure.
  if (!("t0" in body) || body.t0 === undefined) {
    return {
      ok: false,
      code: "missing_field",
      field: "t0_observation_id",
      message: "t0 is required (carries node t0_observation_id and consumer projection)",
    };
  }
  if (!isPlainObject(body.t0)) {
    return {
      ok: false,
      code: "invalid_scalar",
      field: "t0",
      message: "t0 must be an object",
    };
  }
  const t0 = body.t0;
  if (!("observation_id" in t0) || t0.observation_id === undefined) {
    return {
      ok: false,
      code: "missing_field",
      field: "t0_observation_id",
      message: "t0.observation_id (node t0_observation_id) is required",
    };
  }
  if (!("projection" in t0) || t0.projection === undefined) {
    return {
      ok: false,
      code: "missing_field",
      field: "s",
      message: "t0.projection is required (consumer S0/P0/B0)",
    };
  }
  if (!isPlainObject(t0.projection)) {
    return {
      ok: false,
      code: "invalid_scalar",
      field: "s",
      message: "t0.projection must be an object",
    };
  }
  const projection = t0.projection;
  if (!("s" in projection) || projection.s === undefined) {
    return {
      ok: false,
      code: "missing_field",
      field: "s",
      message: "t0.projection.s (consumer S0) is required",
    };
  }
  if (!("p" in projection) || projection.p === undefined) {
    return {
      ok: false,
      code: "missing_field",
      field: "p",
      message: "t0.projection.p (consumer P0) is required",
    };
  }
  if (!("b_zkz" in projection) || projection.b_zkz === undefined) {
    return {
      ok: false,
      code: "missing_field",
      field: "b_zkz",
      message: "t0.projection.b_zkz (consumer B0) is required",
    };
  }
  if (!("opened_cursor" in body) || body.opened_cursor === undefined) {
    return {
      ok: false,
      code: "missing_field",
      field: "opened_cursor",
      message: "opened_cursor is required",
    };
  }
  if (!("expected_row_version" in body) || body.expected_row_version === undefined) {
    return {
      ok: false,
      code: "missing_field",
      field: "expected_row_version",
      message: "expected_row_version is required",
    };
  }

  const parsed = ArmBody.safeParse(body);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue?.path.join(".") ?? "body";
    // Map unknown keys to unknown_field; everything else is invalid_scalar at this stage.
    const isUnknown =
      issue?.code === "unrecognized_keys" ||
      (typeof issue?.message === "string" && issue.message.toLowerCase().includes("unrecognized"));
    return {
      ok: false,
      code: isUnknown ? "unknown_field" : "invalid_scalar",
      field: path,
      message: issue?.message ?? "arm body failed schema validation",
    };
  }

  const data = parsed.data;
  return {
    ok: true,
    binding: {
      operationId,
      nodeT0ObservationId: data.t0.observation_id,
      consumerProjection: {
        s: data.t0.projection.s,
        p: data.t0.projection.p,
        b_zkz: data.t0.projection.b_zkz,
      },
      openedCursor: BigInt(data.opened_cursor),
      expectedRowVersion: data.expected_row_version,
    },
  };
}

// Node durable T0 + four-field comparison shape (mutation still) -----------------

/** Node-owned durable RECEIVER_T0 as stored after READY (operations.t0_observation_id + projection). */
export interface NodeDurableT0 {
  readonly observationId: string;
  readonly projection: ConsumerT0Projection;
}

/**
 * Prepared four-field comparison the guarded arm transition will execute.
 * `consumerProjection` is comparison data only — callers MUST NOT write it into the node's
 * observation ledger or overwrite durable T0 with it.
 */
export interface ArmT0ComparisonShape {
  /** Node durable observation id resolved from the named operation. */
  readonly nodeObservationId: string;
  /** observation_id the consumer named (must equal nodeObservationId for a match). */
  readonly namedNodeObservationId: string;
  readonly nodeProjection: ConsumerT0Projection;
  /** Consumer-supplied projection values; never auto-populated from nodeProjection. */
  readonly consumerProjection: ConsumerT0Projection;
  readonly openedCursor: bigint;
  readonly expectedRowVersion: number;
  readonly operationId: string;
}

export type ArmT0ComparePrepResult =
  | {
      readonly ok: true;
      readonly comparison: ArmT0ComparisonShape;
      /** null when all four fields agree; otherwise the first mismatched wire field name. */
      readonly mismatchField: T0MismatchField | null;
    }
  | {
      readonly ok: false;
      readonly reason: "t0_not_found";
      readonly operationId: string;
    };

/**
 * Resolve the node's durable T0 for the named operation and prepare the exact four-field
 * comparison (observation_id + s + p + b_zkz). Does not mutate state.
 *
 * Asymmetry guards:
 * - `binding.nodeT0ObservationId` is compared as an identity claim against the node row; it is
 * never used to load a consumer-side observation and never written back.
 * - `binding.consumerProjection` is taken verbatim from the request; this function never
 * substitutes the node's stored projection into the consumer side of the shape.
 */
export function prepareArmT0Comparison(
  binding: ArmRequestBinding,
  nodeT0: NodeDurableT0 | null,
): ArmT0ComparePrepResult {
  if (nodeT0 === null) {
    return { ok: false, reason: "t0_not_found", operationId: binding.operationId };
  }

  // Consumer-supplied side — copy field-by-field so a later mutation of `binding` cannot
  // alias into the comparison shape, and so nothing here can silently point at nodeT0.projection.
  const consumerProjection: ConsumerT0Projection = {
    s: binding.consumerProjection.s,
    p: binding.consumerProjection.p,
    b_zkz: binding.consumerProjection.b_zkz,
  };

  const nodeProjection: ConsumerT0Projection = {
    s: nodeT0.projection.s,
    p: nodeT0.projection.p,
    b_zkz: nodeT0.projection.b_zkz,
  };

  const comparison: ArmT0ComparisonShape = {
    nodeObservationId: nodeT0.observationId,
    namedNodeObservationId: binding.nodeT0ObservationId,
    nodeProjection,
    consumerProjection,
    openedCursor: binding.openedCursor,
    expectedRowVersion: binding.expectedRowVersion,
    operationId: binding.operationId,
  };

  const durable: T0EvidenceWire = {
    observation_id: nodeT0.observationId,
    projection: nodeProjection,
  };
  const supplied: T0EvidenceWire = {
    observation_id: binding.nodeT0ObservationId,
    projection: consumerProjection,
  };

  return {
    ok: true,
    comparison,
    mismatchField: compareT0Evidence(durable, supplied),
  };
}

/**
 * Cross-domain safety: the comparison shape must never carry a field that looks like a
 * consumer observation id or raw observation body. Used by tests and fail-closed call sites.
 */
export function comparisonImportsConsumerObservation(comparison: ArmT0ComparisonShape): boolean {
  // Structural: only the named node observation id and the three projection strings exist.
  // A future field like `consumerObservationId` or `rawBody` would be a relay-notice wire value breach.
  const keys = Object.keys(comparison).sort();
  const allowed = [
    "consumerProjection",
    "expectedRowVersion",
    "namedNodeObservationId",
    "nodeObservationId",
    "nodeProjection",
    "openedCursor",
    "operationId",
  ];
  if (keys.length !== allowed.length || keys.some((k, i) => k !== allowed[i])) {
    return true;
  }
  const projKeys = Object.keys(comparison.consumerProjection).sort();
  return projKeys.length !== 3 || projKeys[0] !== "b_zkz" || projKeys[1] !== "p" || projKeys[2] !== "s";
}
