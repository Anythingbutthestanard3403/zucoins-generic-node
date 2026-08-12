// Implementer registry port — named integration identities.
// Schema: packages/node-core/src/schema/node-implementer-registry.sql
// (id uuid PK, name text NOT NULL, created_at, retired_at).
//
// Retire sets retired_at. Issuance under a retired implementer is refused;
// existing credentials KEEP working until revoked/expired — retirement is an
// issuance gate, not a credential kill switch.

export interface ImplementerRecord {
  readonly id: string;
  readonly name: string;
  readonly created_at: string;
  readonly retired_at: string | null;
}

export interface ImplementerCreateInput {
  readonly name: string;
  /** Operator session id for the audit row (actor_kind=OPERATOR_SESSION). */
  readonly actorId: string;
  readonly nodeId: string;
}

export interface ImplementerRetireInput {
  readonly id: string;
  readonly actorId: string;
  readonly nodeId: string;
}

/**
 * Registry of named integration identities. Implementations must write the
 * audit row (`implementer.created` / `implementer.retired`) in the same
 * persistence unit as the row mutation.
 */
export interface ImplementerRegistry {
  list(): Promise<readonly ImplementerRecord[]>;
  get(id: string): Promise<ImplementerRecord | null>;
  /** Non-retired row or null (absent / retired both collapse to null). */
  getActive(id: string): Promise<ImplementerRecord | null>;
  /**
   * Genesis default: earliest non-retired implementer by created_at, then id.
   * Null when the registry is empty or every row is retired.
   */
  resolveGenesisId(): Promise<string | null>;
  create(input: ImplementerCreateInput): Promise<ImplementerRecord>;
  retire(input: ImplementerRetireInput): Promise<ImplementerRecord>;
}

export type ImplementerRegistryErrorCode =
  | "IMPLEMENTER_NOT_FOUND"
  | "IMPLEMENTER_ALREADY_RETIRED"
  | "IMPLEMENTER_NAME_INVALID";

export class ImplementerRegistryError extends Error {
  constructor(
    message: string,
    readonly code: ImplementerRegistryErrorCode,
  ) {
    super(message);
    this.name = "ImplementerRegistryError";
  }
}

export const IMPLEMENTER_AUDIT_CREATED = "implementer.created" as const;
export const IMPLEMENTER_AUDIT_RETIRED = "implementer.retired" as const;
