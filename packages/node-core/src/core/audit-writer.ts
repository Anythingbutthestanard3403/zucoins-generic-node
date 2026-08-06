// the append-only audit writer with a WRITE-TIME redaction guard for the
// audit_log table. The frozen schema (schema/audit-log.sql /
// audit-log.contract.ts) has no column for key material, and its schema obligations state:
// "details_text is scrubbed at the application boundary and never carries a private key,
// TOTP code/secret, session secret, unredacted authorization header, or decrypted vault
// material; the schema and the writing code paths must prove the scrubbing -- the column
// absence is necessary but not sufficient." This module IS that application boundary: it is
// the load-bearing security half. Redaction runs BEFORE the row's details_text/details_sha256
// are formed, so a secret can never reach the persisted bytes, and a fail-closed re-scan turns
// any redaction miss into a thrown error rather than a silent cleartext leak into a permanent,
// append-only trail.
//
// The store seam mirrors the house pattern (reporting/store.ts + in-memory adapter): the port
// is append-only (no update/read-mutate/delete method exists), matching audit_log's frozen
// insert-only regime. A durable Postgres adapter drops in behind the
// same interface without a call-site change.

import { sha256Hex } from "../gateway/index.js";

const UTF8 = new TextEncoder();

// JSON value shape the audit details carry. audit_log stores the exact details JSON text plus
// its digest, never JSONB, so the details are a plain JSON tree.
export type AuditDetailValue =
  | string
  | number
  | boolean
  | null
  | readonly AuditDetailValue[]
  | { readonly [key: string]: AuditDetailValue };

// actor_kind CHECK closed set, mirrored from the frozen schema (audit-log.contract.ts
// AUDIT_LOG_ACTOR_KINDS). audit-writer.test.ts asserts this list equals the schema's, so the
// writer can never emit an actor_kind the DDL CHECK would reject.
export const AUDIT_WRITER_ACTOR_KINDS = [
  "SYSTEM",
  "OPERATOR_SESSION",
  "ACTION_KEY",
  "DEVICE_KEY",
  "IMPLEMENTER",
] as const;

export type AuditActorKind = (typeof AUDIT_WRITER_ACTOR_KINDS)[number];

// Detail-field key tokens that must never be persisted in cleartext, mirroring the frozen
// audit-log.contract.ts AUDIT_LOG_FORBIDDEN_SECRET_TOKENS. A details key is secret-classed
// when its lowercased form CONTAINS any token, so `private_key`, `totp`, `totp_secret`,
// `authorization`, `sessionSecret`, and `vaultMaterial` are all caught. audit-writer.test.ts
// asserts this set covers the schema's frozen tokens.
export const AUDIT_SECRET_CLASSED_KEY_TOKENS = [
  "private_key",
  "totp",
  "secret",
  "authorization",
  "vault",
] as const;

export const AUDIT_REDACTION_PLACEHOLDER = "[REDACTED]" as const;

export function isSecretClassedKey(key: string): boolean {
  const lower = key.toLowerCase();
  return AUDIT_SECRET_CLASSED_KEY_TOKENS.some((token) => lower.includes(token));
}

// Recursively replaces the value of every secret-classed key with the redaction placeholder,
// leaving all other structure byte-for-byte intact. Pure and deterministic. Key-name based:
// a secret embedded in a free-text value under a benign key is out of reach here (see the
// ponytail note below), which is why the redaction basis is the frozen key-token list, not a
// value scan that would false-positive on benign prose containing "authorization".
// ponytail: key-name redaction, not value scanning. Upgrade path if a value-embedded-secret
// threat is ever in scope: add a typed secret-carrying details schema at the call sites so
// secrets are always keyed, never free-text.
export function redactAuditDetails(details: AuditDetailValue): AuditDetailValue {
  if (Array.isArray(details)) {
    return details.map((entry) => redactAuditDetails(entry));
  }
  if (details !== null && typeof details === "object") {
    const source = details as { readonly [key: string]: AuditDetailValue };
    const redacted: { [key: string]: AuditDetailValue } = {};
    for (const [key, value] of Object.entries(source)) {
      redacted[key] = isSecretClassedKey(key)
        ? AUDIT_REDACTION_PLACEHOLDER
        : redactAuditDetails(value);
    }
    return redacted;
  }
  return details;
}

// Fail-closed guard: re-walk the already-redacted tree and confirm no secret-classed key
// still carries a non-placeholder value. If the primary redaction ever missed one, this throws
// BEFORE the row is written, so a secret can never be persisted into the permanent append-only
// trail. Returns nothing on success.
function assertFullyRedacted(details: AuditDetailValue): void {
  if (Array.isArray(details)) {
    for (const entry of details) assertFullyRedacted(entry);
    return;
  }
  if (details !== null && typeof details === "object") {
    for (const [key, value] of Object.entries(details)) {
      if (isSecretClassedKey(key) && value !== AUDIT_REDACTION_PLACEHOLDER) {
        throw new AuditWriteError(`secret-classed field "${key}" survived redaction`);
      }
      assertFullyRedacted(value);
    }
  }
}

export class AuditWriteError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditWriteError";
  }
}

// The writer's projection of an audit_log row, minus the DB-generated identity `seq`.
// id and created_at are writer-supplied per the frozen DDL; the details are stored as exact
// text plus SHA-256 digest.
export interface AuditLogRow {
  readonly id: string;
  readonly nodeId: string;
  readonly actorKind: AuditActorKind;
  readonly actorId: string | null;
  readonly action: string;
  readonly operationId: string | null;
  readonly walletId: string | null;
  readonly detailsText: string;
  readonly detailsSha256: string;
  readonly createdAt: string;
}

export interface AuditWriteInput {
  readonly id: string;
  readonly nodeId: string;
  readonly actorKind: AuditActorKind;
  readonly actorId?: string | null;
  readonly action: string;
  readonly operationId?: string | null;
  readonly walletId?: string | null;
  readonly details: AuditDetailValue;
  readonly createdAt: string;
}

// Builds the audit_log row from raw input: validate the structural CHECK invariants the frozen
// DDL enforces (so the writer never emits a row the schema would reject), redact secrets at
// write time, then form details_text and its digest over the REDACTED bytes. A caller bug
// (unknown actor_kind, empty action) is a thrown error, never a silently written row.
export function buildAuditRow(input: AuditWriteInput): AuditLogRow {
  if (!(AUDIT_WRITER_ACTOR_KINDS as readonly string[]).includes(input.actorKind)) {
    throw new AuditWriteError(`actor_kind "${input.actorKind}" is outside the frozen closed set`);
  }
  if (input.action.length === 0) {
    throw new AuditWriteError("action is required (action text NOT NULL)");
  }
  if (input.createdAt.length === 0) {
    throw new AuditWriteError("created_at is required (created_at timestamptz NOT NULL)");
  }
  const redacted = redactAuditDetails(input.details);
  assertFullyRedacted(redacted);
  const detailsText = JSON.stringify(redacted);
  return {
    id: input.id,
    nodeId: input.nodeId,
    actorKind: input.actorKind,
    actorId: input.actorId ?? null,
    action: input.action,
    operationId: input.operationId ?? null,
    walletId: input.walletId ?? null,
    detailsText,
    detailsSha256: sha256Hex(UTF8.encode(detailsText)),
    createdAt: input.createdAt,
  };
}

// Append-only sink for audit_log. NO update/read-mutate/delete method exists — the frozen
// audit_log regime is insert-only. A durable adapter implements the same
// single method with an INSERT under the id/(id,node_id) UNIQUE constraints.
export interface AuditLogStore {
  append(row: AuditLogRow): Promise<void>;
}

export interface AuditWriter {
  write(input: AuditWriteInput): Promise<AuditLogRow>;
}

// The writer: redaction happens in buildAuditRow, strictly before store.append, so the sink
// only ever receives already-scrubbed bytes. A store rejection propagates unchanged — the
// caller decides how to handle a persistence failure.
export function createAuditWriter(store: AuditLogStore): AuditWriter {
  return {
    async write(input: AuditWriteInput): Promise<AuditLogRow> {
      const row = buildAuditRow(input);
      await store.append(row);
      return row;
    },
  };
}

// Single-process reference adapter (mirrors reporting/in-memory-store.ts): an append-only list
// with an id-uniqueness guard matching the DDL `id uuid NOT NULL UNIQUE`. No mutate/delete.
export class InMemoryAuditLogStore implements AuditLogStore {
  private readonly appended: AuditLogRow[] = [];
  private readonly ids = new Set<string>();

  append(row: AuditLogRow): Promise<void> {
    if (this.ids.has(row.id)) {
      return Promise.reject(new AuditWriteError(`duplicate audit id "${row.id}" (id UNIQUE)`));
    }
    this.ids.add(row.id);
    this.appended.push(row);
    return Promise.resolve();
  }

  rows(): readonly AuditLogRow[] {
    return this.appended;
  }
}
