import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import {
  IMPLEMENTER_SCOPES,
  type ImplementerScope,
} from "@zucoins/generic-node-contracts/api-schema";
import {
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_AUTH_FAILURE_MESSAGE,
} from "@zucoins/generic-node-contracts/auth-errors";

// The scope vocabulary is consumed, never re-minted: `api-schema/auth-scopes.ts` freezes it
// from the API contract's credential-binding section. Re-exported so consumers of this module see the same values
// under the same names, not a structurally identical copy.
export { IMPLEMENTER_SCOPES, type ImplementerScope };

// Three statuses, because three is all the store can write (ISSUE -> ACTIVE, ROTATE -> GRACE,
// REVOKE -> REVOKED). Expiry is a property of `expires_at`, evaluated at read time by
// `validate`; there is no writer that would set a stored EXPIRED, so the state is not
// declared here or in the schema enum.
export type CredentialStatus = "ACTIVE" | "GRACE" | "REVOKED";
export type CredentialAuditAction =
  | "IMPLEMENTER_CREDENTIAL_ISSUED"
  | "IMPLEMENTER_CREDENTIAL_ROTATED"
  | "IMPLEMENTER_CREDENTIAL_REVOKED";

export const BEARER_KEY_PREFIX = "ik_";
export const PUBLIC_PREFIX_LENGTH = 11;

export interface StoredCredential {
  readonly id: string;
  readonly implementer_id: string;
  readonly public_prefix: string;
  readonly credential_hash: string;
  readonly scopes: readonly ImplementerScope[];
  readonly status: CredentialStatus;
  readonly key_version: number;
  readonly issued_at: string;
  readonly expires_at: string | null;
  readonly revoked_at: string | null;
  readonly rotated_from_id: string | null;
  readonly rotated_to_id: string | null;
  readonly rotated_at: string | null;
  readonly rotation_grace_until: string | null;
}

export interface CredentialAuditEntry {
  readonly id: string;
  readonly implementer_id: string;
  readonly action: CredentialAuditAction;
  readonly credential_id: string;
  readonly replacement_credential_id: string | null;
  readonly created_at: string;
  /**
   * P1#2 (FAIL rework): the authenticated operator session principal that performed this
   * administrative action. When set, the audit row records `actor_kind='OPERATOR_SESSION'` and
   * `actor_id=<sessionId>` (the true principal), not the target implementer. When absent, the
   * legacy `IMPLEMENTER`/implementer_id principal is used (bootstrap/cli paths).
   */
  readonly operator_session_id?: string | null;
}

export interface CreateCredentialResult {
  readonly credential_id: string;
  readonly raw_key: string;
  readonly public_prefix: string;
  readonly scopes: readonly ImplementerScope[];
  readonly key_version: number;
  readonly issued_at: string;
  readonly expires_at: string | null;
}

export interface ValidatedCredential {
  readonly credential_id: string;
  readonly implementer_id: string;
  readonly scopes: readonly ImplementerScope[];
}

export interface CredentialStore {
  /**
   * Each mutation includes its audit row in one atomic persistence operation. Implementations
   * must commit both or neither; callers never append lifecycle audit rows separately.
   */
  issue(row: StoredCredential, audit: CredentialAuditEntry): Promise<void>;
  findByHash(credentialHash: string): Promise<StoredCredential | null>;
  findById(credentialId: string, implementerId: string): Promise<StoredCredential | null>;
  /**
   * Lookup by credential id alone (admin multi-implementer revoke/list).
   * Absent when the store has no global id index (tests may stub null).
   */
  findByCredentialId?(credentialId: string): Promise<StoredCredential | null>;
  listByImplementer(implementerId: string): Promise<StoredCredential[]>;
  /** Every credential across implementers (admin inventory). Optional for unit stubs. */
  listAll?(): Promise<StoredCredential[]>;
  rotate(
    credentialId: string,
    implementerId: string,
    replacement: StoredCredential,
    rotatedAt: string,
    graceUntil: string,
    audit: CredentialAuditEntry,
  ): Promise<boolean>;
  revoke(
    credentialId: string,
    implementerId: string,
    revokedAt: string,
    audit: CredentialAuditEntry,
  ): Promise<boolean>;
}

/**
 * Management-path failures only: bad scope input at issue time, and a credential id that the
 * authenticated tenant does not own (which is deliberately the same code as "no such id" —
 * ABSENT_OBJECT and CROSS_TENANT_OBJECT collapse onto the frozen `not_found`).
 *
 * The authorization path never raises this: every bearer-authorization rejection is
 * `CredentialAuthError`. The union below deliberately holds no revoked / expired /
 * scope-denied member, so a future edit cannot reintroduce a distinguishable auth outcome
 * without failing to compile.
 */
export class CredentialError extends Error {
  constructor(
    message: string,
    readonly code: "INVALID_SCOPES" | "CREDENTIAL_NOT_FOUND",
  ) {
    super(message);
    this.name = "CredentialError";
  }
}

/**
 * the single rejection every bearer-authorization failure raises. A missing,
 * malformed, unknown, expired or revoked key AND a valid key used outside its scope all
 * produce this exact value: same class, same `code`, same `message`, same own-property set.
 * There is deliberately no failure-state discriminator, so no caller — HTTP mapper, logger or
 * internal RPC — can recover a "valid key, wrong scope" oracle from it.
 *
 * `code` is the frozen `CANONICAL_AUTH_FAILURE_CODE` literal and takes no constructor
 * argument, so the generic mapping `apiErrorResponse(err.code, requestId)` (api/error-envelope)
 * cannot emit anything but the frozen 401 `invalid_api_key` — there is no scope-specific code
 * to select, and the frozen enum holds no 403 to select it with.
 */
export class CredentialAuthError extends Error {
  readonly code = CANONICAL_AUTH_FAILURE_CODE;

  constructor() {
    super(CANONICAL_AUTH_FAILURE_MESSAGE);
    this.name = "CredentialAuthError";
  }
}

/**
 * The ONE throw site for the whole authorization path. `validate`, `assertScope` and
 * `authorize` all reject through here, so every state collapses to a byte-identical thrown
 * value — down to the stack line, since there is only one `throw` to attribute it to.
 */
function rejectAuthorization(): never {
  throw new CredentialAuthError();
}

export function hashCredential(rawKey: string): string {
  return createHash("sha256").update(rawKey, "utf8").digest("hex");
}

export function generateRawKey(): string {
  return BEARER_KEY_PREFIX + randomBytes(32).toString("base64url");
}

export function validateScopes(scopes: readonly string[]): ImplementerScope[] {
  const valid: ImplementerScope[] = [];
  for (const scope of scopes) {
    if (!(IMPLEMENTER_SCOPES as readonly string[]).includes(scope)) {
      throw new CredentialError(`unknown scope: ${scope}`, "INVALID_SCOPES");
    }
    valid.push(scope as ImplementerScope);
  }
  if (valid.length === 0) {
    throw new CredentialError("at least one scope is required", "INVALID_SCOPES");
  }
  return [...new Set(valid)];
}

// an out-of-scope credential is rejected through the same funnel as an unknown one, and
// the rejection never names the required scope — naming it is the scope oracle itself.
export function assertScope(
  credential: ValidatedCredential,
  required: ImplementerScope,
): void {
  if (!credential.scopes.includes(required)) {
    rejectAuthorization();
  }
}

function createStoredCredential(
  implementerId: string,
  scopes: readonly ImplementerScope[],
  rawKey: string,
  issuedAt: string,
  expiresAt: string | null,
  keyVersion: number,
  rotatedFromId: string | null,
): StoredCredential {
  return {
    id: crypto.randomUUID(),
    implementer_id: implementerId,
    public_prefix: rawKey.slice(0, PUBLIC_PREFIX_LENGTH),
    credential_hash: hashCredential(rawKey),
    scopes,
    status: "ACTIVE",
    key_version: keyVersion,
    issued_at: issuedAt,
    expires_at: expiresAt,
    revoked_at: null,
    rotated_from_id: rotatedFromId,
    rotated_to_id: null,
    rotated_at: null,
    rotation_grace_until: null,
  };
}

function createResult(row: StoredCredential, rawKey: string): CreateCredentialResult {
  return {
    credential_id: row.id,
    raw_key: rawKey,
    public_prefix: row.public_prefix,
    scopes: row.scopes,
    key_version: row.key_version,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
  };
}

export class CredentialService {
  constructor(
    private readonly store: CredentialStore,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async create(
    implementerId: string,
    scopes: readonly string[],
    expiresAt: string | null = null,
    operatorSessionId?: string | null,
  ): Promise<CreateCredentialResult> {
    const issuedAt = this.now().toISOString();
    if (expiresAt !== null && Date.parse(expiresAt) <= Date.parse(issuedAt)) {
      throw new RangeError("expiresAt must be later than issuedAt");
    }
    const rawKey = generateRawKey();
    const row = createStoredCredential(
      implementerId,
      validateScopes(scopes),
      rawKey,
      issuedAt,
      expiresAt,
      1,
      null,
    );
    const audit: CredentialAuditEntry = {
      id: crypto.randomUUID(),
      implementer_id: implementerId,
      action: "IMPLEMENTER_CREDENTIAL_ISSUED",
      credential_id: row.id,
      replacement_credential_id: null,
      created_at: issuedAt,
      operator_session_id: operatorSessionId ?? null,
    };
    await this.store.issue(row, audit);
    return createResult(row, rawKey);
  }

  async rotate(
    credentialId: string,
    implementerId: string,
    graceSeconds: number,
  ): Promise<CreateCredentialResult> {
    if (!Number.isInteger(graceSeconds) || graceSeconds < 0) {
      throw new RangeError("graceSeconds must be a non-negative integer");
    }
    const current = await this.store.findById(credentialId, implementerId);
    const rotatedAt = this.now();
    // The expiry guard mirrors create's: the replacement takes a fresh issued_at and
    // inherits the parent's absolute expires_at, so rotating a past-expiry credential would
    // build a row the schema's `expires_at > issued_at` CHECK rejects — and because ROTATE is
    // one statement, that abort rolls the retirement back too and leaves the credential
    // permanently un-rotatable. An already-expired credential is unusable for authorization
    // (see validate), so the management path collapses it onto the same not-found outcome as
    // a revoked or foreign id rather than inventing a new one.
    if (
      current === null ||
      current.status !== "ACTIVE" ||
      (current.expires_at !== null &&
        Date.parse(current.expires_at) <= rotatedAt.getTime())
    ) {
      throw new CredentialError("credential not found", "CREDENTIAL_NOT_FOUND");
    }
    const graceUntil = new Date(rotatedAt.getTime() + graceSeconds * 1000).toISOString();
    const rawKey = generateRawKey();
    const replacement = createStoredCredential(
      implementerId,
      current.scopes,
      rawKey,
      rotatedAt.toISOString(),
      current.expires_at,
      current.key_version + 1,
      current.id,
    );
    const audit: CredentialAuditEntry = {
      id: crypto.randomUUID(),
      implementer_id: implementerId,
      action: "IMPLEMENTER_CREDENTIAL_ROTATED",
      credential_id: current.id,
      replacement_credential_id: replacement.id,
      created_at: rotatedAt.toISOString(),
    };
    const rotated = await this.store.rotate(
      credentialId,
      implementerId,
      replacement,
      rotatedAt.toISOString(),
      graceUntil,
      audit,
    );
    if (!rotated) {
      throw new CredentialError("credential not found", "CREDENTIAL_NOT_FOUND");
    }
    return createResult(replacement, rawKey);
  }

  // Every rejection here is `rejectAuthorization`: missing, malformed and unknown keys are
  // indistinguishable from expired and revoked ones (AUTH_FAILURE_STATE_TO_CODE collapses
  // MISSING/MALFORMED/UNKNOWN/EXPIRED/REVOKED_KEY onto one code). The branches decide only
  // WHETHER to reject, never how.
  async validate(rawKey: string): Promise<ValidatedCredential> {
    const credentialHash = hashCredential(rawKey);
    const stored = await this.store.findByHash(credentialHash);
    if (
      stored === null ||
      !timingSafeEqual(
        Buffer.from(stored.credential_hash, "hex"),
        Buffer.from(credentialHash, "hex"),
      )
    ) {
      rejectAuthorization();
    }
    const now = this.now().getTime();
    if (stored.expires_at !== null && Date.parse(stored.expires_at) <= now) {
      rejectAuthorization();
    }
    if (
      stored.status === "REVOKED" ||
      (stored.status === "GRACE" &&
        (stored.rotation_grace_until === null ||
          Date.parse(stored.rotation_grace_until) <= now))
    ) {
      rejectAuthorization();
    }
    return {
      credential_id: stored.id,
      implementer_id: stored.implementer_id,
      scopes: stored.scopes,
    };
  }

  async revoke(credentialId: string, implementerId: string, operatorSessionId?: string | null): Promise<void> {
    const revokedAt = this.now().toISOString();
    const audit: CredentialAuditEntry = {
      id: crypto.randomUUID(),
      implementer_id: implementerId,
      action: "IMPLEMENTER_CREDENTIAL_REVOKED",
      credential_id: credentialId,
      replacement_credential_id: null,
      created_at: revokedAt,
      operator_session_id: operatorSessionId ?? null,
    };
    const found = await this.store.revoke(
      credentialId,
      implementerId,
      revokedAt,
      audit,
    );
    if (!found) {
      throw new CredentialError("credential not found", "CREDENTIAL_NOT_FOUND");
    }
  }

  async list(implementerId: string): Promise<StoredCredential[]> {
    return this.store.listByImplementer(implementerId);
  }

  /** Cross-implementer inventory for the admin list surface. */
  async listAll(): Promise<StoredCredential[]> {
    if (this.store.listAll !== undefined) {
      return this.store.listAll();
    }
    return [];
  }

  /**
   * Resolve a credential by id alone so admin revoke can target any implementer's key.
   * Falls back to CREDENTIAL_NOT_FOUND when the store has no global id lookup.
   */
  async findByCredentialId(credentialId: string): Promise<StoredCredential> {
    if (this.store.findByCredentialId === undefined) {
      throw new CredentialError("credential not found", "CREDENTIAL_NOT_FOUND");
    }
    const row = await this.store.findByCredentialId(credentialId);
    if (row === null) {
      throw new CredentialError("credential not found", "CREDENTIAL_NOT_FOUND");
    }
    return row;
  }

  async authorize(
    rawKey: string,
    requiredScope: ImplementerScope,
  ): Promise<ValidatedCredential> {
    const credential = await this.validate(rawKey);
    assertScope(credential, requiredScope);
    return credential;
  }
}
