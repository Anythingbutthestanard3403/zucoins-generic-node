/**
 * The `after_landing` shape a `RECEIVE_EXTERNAL` create request may supply, and the one
 * lifecycle rule it can trigger: at most one after-landing `MOVE_INTERNAL` child, linked by
 * `spawned_from_operation_id`. No second child and no generic workflow graph exist at launch
 * ("arbitrary workflows or more than one automatic child move" is a deliberate launch
 * exclusion).
 */
export const AFTER_LANDING_KINDS = ["HOLD", "INTERNAL_MOVE"] as const;

export type AfterLandingKind = (typeof AFTER_LANDING_KINDS)[number];

export const CHILD_LINK_FIELD = "spawned_from_operation_id" as const;

export const LIFECYCLE_RULES = {
  parentOperation: "RECEIVE_EXTERNAL",
  childOperation: "MOVE_INTERNAL",
  maxChildrenPerReceive: 1,
  childLinkField: CHILD_LINK_FIELD,
  workflowGraphSupported: false,
} as const;

export const SOURCE = "core operation model; after-landing lifecycle; API create contract" as const;
