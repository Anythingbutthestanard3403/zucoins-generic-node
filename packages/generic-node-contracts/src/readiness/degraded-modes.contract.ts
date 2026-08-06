/**
 * SOURCE: the node-core leadership section (money engines run under one process-wide signer leadership lock;
 * leadership and wallet leases do not replace one another) + the operations-recovery spec
 * (degraded operation, signer unavailable) reconciled tothe readiness-leadership decoupling rule (a
 * web-active-but-not-leader instance is ready and serves non-signing traffic).
 *
 * the named concern freezes the four readiness x leadership modes and, for each, the allowed and
 * forbidden operation classes as data. Every mode partitions the whole operation vocabulary
 * (allowed and forbidden are disjoint and together total), so classification is exhaustive.
 */

/** The closed operation-class vocabulary a node instance can be asked to run. */
export const NODE_OPERATION_CLASSES = [
  "REPORT_HEALTH",
  "SERVE_READS",
  "SERVE_ADMIN_QUERIES",
  "ADMIT_BOUNDED_QUEUE",
  "SERVE_EXACT_PARTIAL",
  "SIGN",
  "SUBMIT",
  "RUN_MONEY_ENGINES",
  "MUTATE_ECONOMIC_STATE",
] as const;

export type NodeOperationClass = (typeof NODE_OPERATION_CLASSES)[number];

/** The four operation classes gated on BOTH readiness and leadership (the money path). */
export const LEADER_ONLY_OPERATION_CLASSES = [
  "SIGN",
  "SUBMIT",
  "RUN_MONEY_ENGINES",
  "MUTATE_ECONOMIC_STATE",
] as const satisfies readonly NodeOperationClass[];

export interface NodeMode {
  readonly id: string;
  readonly ready: boolean;
  readonly leader: boolean;
  readonly degraded: boolean;
  readonly allowed: readonly NodeOperationClass[];
  readonly forbidden: readonly NodeOperationClass[];
}

/**
 * The nominal mode is the only one that runs the money path. The two named degraded modes are
 * READY_NOT_LEADER (serves all non-signing traffic; the normal overlap-deploy standby) and
 * LEADER_NOT_READY (holds leadership but a gating dependency dropped: fail-closed to health and
 * already-durable exact partials only). NOT_READY_NOT_LEADER is the booting/failed instance.
 */
export const NODE_MODES = [
  {
    id: "READY_AND_LEADER",
    ready: true,
    leader: true,
    degraded: false,
    allowed: [
      "REPORT_HEALTH",
      "SERVE_READS",
      "SERVE_ADMIN_QUERIES",
      "ADMIT_BOUNDED_QUEUE",
      "SERVE_EXACT_PARTIAL",
      "SIGN",
      "SUBMIT",
      "RUN_MONEY_ENGINES",
      "MUTATE_ECONOMIC_STATE",
    ],
    forbidden: [],
  },
  {
    id: "READY_NOT_LEADER",
    ready: true,
    leader: false,
    degraded: true,
    allowed: [
      "REPORT_HEALTH",
      "SERVE_READS",
      "SERVE_ADMIN_QUERIES",
      "ADMIT_BOUNDED_QUEUE",
      "SERVE_EXACT_PARTIAL",
    ],
    forbidden: ["SIGN", "SUBMIT", "RUN_MONEY_ENGINES", "MUTATE_ECONOMIC_STATE"],
  },
  {
    id: "LEADER_NOT_READY",
    ready: false,
    leader: true,
    degraded: true,
    allowed: ["REPORT_HEALTH", "SERVE_EXACT_PARTIAL"],
    forbidden: [
      "SERVE_READS",
      "SERVE_ADMIN_QUERIES",
      "ADMIT_BOUNDED_QUEUE",
      "SIGN",
      "SUBMIT",
      "RUN_MONEY_ENGINES",
      "MUTATE_ECONOMIC_STATE",
    ],
  },
  {
    id: "NOT_READY_NOT_LEADER",
    ready: false,
    leader: false,
    degraded: true,
    allowed: ["REPORT_HEALTH"],
    forbidden: [
      "SERVE_READS",
      "SERVE_ADMIN_QUERIES",
      "ADMIT_BOUNDED_QUEUE",
      "SERVE_EXACT_PARTIAL",
      "SIGN",
      "SUBMIT",
      "RUN_MONEY_ENGINES",
      "MUTATE_ECONOMIC_STATE",
    ],
  },
] as const satisfies readonly NodeMode[];

export type NodeModeId = (typeof NODE_MODES)[number]["id"];
