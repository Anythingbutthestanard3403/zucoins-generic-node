/**
 * Closed-set check for node-claimed operation states (doc 10 §10 / doc 11 §11.6).
 * Unrecognised vocabulary fails closed with a typed drift error — never stored as a claim.
 */

import {
  FORBIDDEN_STATE_ALIASES,
  MOVE_INTERNAL_STATES,
  RECEIVE_EXTERNAL_STATES,
  SEND_EXTERNAL_STATES,
} from "@zucoins/generic-node-contracts/operations";

/** Union of every Layer-1 operation state across the three public kinds. */
export const KNOWN_NODE_CLAIM_STATES = [
  ...RECEIVE_EXTERNAL_STATES,
  ...MOVE_INTERNAL_STATES,
  ...SEND_EXTERNAL_STATES,
] as const;

export type KnownNodeClaimState = (typeof KNOWN_NODE_CLAIM_STATES)[number];

const KNOWN_SET: ReadonlySet<string> = new Set(KNOWN_NODE_CLAIM_STATES);
const FORBIDDEN_SET: ReadonlySet<string> = new Set(FORBIDDEN_STATE_ALIASES);

export class NodeStateDriftError extends Error {
  readonly code = "NODE_STATE_DRIFT" as const;
  readonly state: string;
  readonly reason: "unknown_state" | "forbidden_alias";

  constructor(state: string, reason: "unknown_state" | "forbidden_alias") {
    super(
      reason === "forbidden_alias"
        ? `node_claim_state ${JSON.stringify(state)} is a forbidden product-projection alias`
        : `node_claim_state ${JSON.stringify(state)} is outside the closed operation-state vocabulary`,
    );
    this.name = "NodeStateDriftError";
    this.state = state;
    this.reason = reason;
  }
}

export function isKnownNodeClaimState(state: string): state is KnownNodeClaimState {
  return KNOWN_SET.has(state);
}

/**
 * Parse a node-claimed state. Throws `NodeStateDriftError` on unknown or forbidden tokens
 * so integrators can alert without ever persisting drift vocabulary.
 */
export function parseNodeClaimState(state: string): KnownNodeClaimState {
  if (FORBIDDEN_SET.has(state)) {
    throw new NodeStateDriftError(state, "forbidden_alias");
  }
  if (!KNOWN_SET.has(state)) {
    throw new NodeStateDriftError(state, "unknown_state");
  }
  return state as KnownNodeClaimState;
}
