/**
 * The frozen operation model: the node exposes exactly three public money operations.
 * Business-specific interpretations layered on top by an implementer are projections owned
 * by that implementer; they are not additional node money-operation kinds. There is no
 * general workflow engine.
 */
export const OPERATION_KINDS = ["RECEIVE_EXTERNAL", "MOVE_INTERNAL", "SEND_EXTERNAL"] as const;

export type OperationKind = (typeof OPERATION_KINDS)[number];

/**
 * A receive may request exactly one `after_landing=INTERNAL_MOVE`, which creates one separate
 * `MOVE_INTERNAL` operation linked by `spawned_from_operation_id`. No second child, no
 * arbitrary workflow graph.
 */
export const CHILD_LINK = {
  parent: "RECEIVE_EXTERNAL",
  spawns: "MOVE_INTERNAL",
  via: "spawned_from_operation_id",
  maxChildrenPerReceive: 1,
} as const;

export const WORKFLOW_GRAPH_SUPPORTED = false;

export const SOURCE = "core operation model: three public money operations" as const;
