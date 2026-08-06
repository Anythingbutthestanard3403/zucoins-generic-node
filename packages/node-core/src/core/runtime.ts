import {
  requireDatabaseAdapter,
  type DatabaseAdapter,
  type DatabaseConfiguration,
} from "../data/index.js";
import {
  createGatewayClient,
  type GatewayClient,
  type GatewayConfiguration,
} from "../gateway/index.js";
import {
  NodeCoreReadinessState,
  type NodeCoreReadinessStateOptions,
} from "./readiness-state.js";

export interface NodeCoreConfiguration {
  readonly database: DatabaseConfiguration;
  readonly gateway: GatewayConfiguration;
  /**
   * Optional readiness-stamp surface. When omitted, a default state
   * is still attached so mount points can always read vault / leadership /
   * observation stamps; callers that own a custom observation failure budget
   * pass it here.
   */
  readonly readiness?: NodeCoreReadinessStateOptions;
}

/**
 * Vault / signer-leadership / observation availability as exposed to health
 * routes and boot. Stamps only — no private key material (the key-custody rule).
 */
export interface NodeCoreRuntimeServices {
  readonly readiness: NodeCoreReadinessState;
}

export interface NodeCoreRuntime extends NodeCoreRuntimeServices {
  readonly database: DatabaseAdapter;
  readonly gateway: GatewayClient;
}

export class NodeCoreConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NodeCoreConfigurationError";
  }
}

const DEFAULT_OBSERVATION_FAILURE_BUDGET = 3;

export function createNodeCore(
  configuration: NodeCoreConfiguration,
): NodeCoreRuntime {
  if (configuration === undefined) {
    throw new NodeCoreConfigurationError("node core configuration is required");
  }

  const database = requireDatabaseAdapter(configuration.database);
  const gateway = createGatewayClient(configuration.gateway);
  const readiness = new NodeCoreReadinessState(
    configuration.readiness ?? {
      observationFailureBudget: DEFAULT_OBSERVATION_FAILURE_BUDGET,
    },
  );
  return Object.freeze({ database, gateway, readiness });
}
