// Break-glass authority freeze and TOTP-reset under frozen ceremony.
//
// Ceremony design (implementer mechanics; release still requires reviewer confirmation
// that the design was accepted — review indicators):
//
// 1. Host-local freeze writes ONLY the Ed25519 public key into the
// BreakGlassAuthorityStore. Private key never enters the node (the key-custody rule).
// 2. Ratification is NOT reachable from a bare operator session/TOTP path: the
// freeze function accepts no session credential; the shell/CLI that holds
// host access (VAULT_MASTER_KEY / host possession) is the outer gate.
// 3. Break-glass enrollment reuses zp-device-enrol-v1 (same A.1.1 preimage) with
// the frozen key as the authorizer — see enrollment.ts breakGlass branch.
// 4. Lost-TOTP reset under break-glass requires a signature from an active
// frozen break-glass key over a fixed purpose-prefixed preimage; bare
// login/TOTP alone cannot reset the factor via this path.
//
// Wallet / destination custody classification fields are structurally unreachable
// from this module (no imports of wallet or destination code).

import { Buffer } from "node:buffer";

import { verifyRawEd25519 } from "../protocol/ed25519-verify.js";

import type { BreakGlassAuthorityStore } from "./break-glass-store.js";
import type {
  BreakGlassAuthority,
  BreakGlassAuditEntry,
  BreakGlassRatifyResult,
  BreakGlassTotpResetResult,
} from "./types.js";

function verifyEd25519Detached(
  preimageText: string,
  signatureText: string,
  publicKeyText: string,
): boolean {
  try {
    return verifyRawEd25519({
      publicKeyBytes: Buffer.from(publicKeyText, "base64url"),
      preimageBytes: Buffer.from(preimageText, "utf8"),
      signatureBytes: Buffer.from(signatureText, "base64url"),
    });
  } catch {
    return false;
  }
}

/** Fixed purpose for the lost-TOTP break-glass reset preimage (not a money-path tuple). */
export const BREAK_GLASS_TOTP_RESET_PURPOSE = "zp-break-glass-totp-reset-v1" as const;

export interface BreakGlassAuditLog {
  append(entry: BreakGlassAuditEntry): void;
}

export class InMemoryBreakGlassAuditLog implements BreakGlassAuditLog {
  readonly entries: BreakGlassAuditEntry[] = [];

  append(entry: BreakGlassAuditEntry): void {
    this.entries.push(entry);
  }
}

export interface RatifyBreakGlassInput {
  readonly id: string;
  readonly nodeId: string;
  readonly publicKey: string;
  readonly label: string;
  readonly nowMs: number;
  /**
   * Explicit host-local attestation string recorded in the audit row.
   * Callers (CLI/shell) MUST only invoke this after host-access proof; this
   * module cannot verify host possession itself and records the attestation.
   */
  readonly hostAttestation: string;
}

const PADDED_BASE64URL_32_RE = /^[A-Za-z0-9_-]{43}=$/;

/**
 * Ratify a break-glass public key for a node. Host-local only by contract:
 * no session/TOTP parameter exists on this API surface. Rejects malformed keys
 * and duplicate (node, publicKey). Never stores private key material.
 */
export function ratifyBreakGlassAuthority(
  store: BreakGlassAuthorityStore,
  audit: BreakGlassAuditLog,
  input: RatifyBreakGlassInput,
): BreakGlassRatifyResult {
  const at = new Date(input.nowMs).toISOString();

  if (input.hostAttestation.trim().length === 0) {
    const detail = "host attestation is required for break-glass freeze";
    audit.append({
      outcome: "REJECTED",
      action: "RATIFY",
      code: "HOST_ATTESTATION_REQUIRED",
      nodeId: input.nodeId,
      authorityId: input.id,
      publicKey: input.publicKey,
      detail,
      at,
    });
    return { ok: false, code: "HOST_ATTESTATION_REQUIRED", detail };
  }

  if (!PADDED_BASE64URL_32_RE.test(input.publicKey)) {
    const detail = "break-glass public key is not valid padded base64url (32 raw bytes)";
    audit.append({
      outcome: "REJECTED",
      action: "RATIFY",
      code: "INVALID_PUBLIC_KEY",
      nodeId: input.nodeId,
      authorityId: input.id,
      publicKey: input.publicKey,
      detail,
      at,
    });
    return { ok: false, code: "INVALID_PUBLIC_KEY", detail };
  }

  if (input.label.trim().length === 0) {
    const detail = "break-glass authority label must be non-empty";
    audit.append({
      outcome: "REJECTED",
      action: "RATIFY",
      code: "INVALID_LABEL",
      nodeId: input.nodeId,
      authorityId: input.id,
      publicKey: input.publicKey,
      detail,
      at,
    });
    return { ok: false, code: "INVALID_LABEL", detail };
  }

  const existing = store.findByNodeAndPublicKey(input.nodeId, input.publicKey);
  if (existing !== null) {
    const detail = "break-glass authority already frozen for this node/public key";
    audit.append({
      outcome: "REJECTED",
      action: "RATIFY",
      code: "DUPLICATE_AUTHORITY",
      nodeId: input.nodeId,
      authorityId: input.id,
      publicKey: input.publicKey,
      detail,
      at,
    });
    return { ok: false, code: "DUPLICATE_AUTHORITY", detail };
  }

  if (store.findById(input.id) !== null) {
    const detail = "break-glass authority id already in use";
    audit.append({
      outcome: "REJECTED",
      action: "RATIFY",
      code: "DUPLICATE_AUTHORITY",
      nodeId: input.nodeId,
      authorityId: input.id,
      publicKey: input.publicKey,
      detail,
      at,
    });
    return { ok: false, code: "DUPLICATE_AUTHORITY", detail };
  }

  const authority: BreakGlassAuthority = {
    id: input.id,
    nodeId: input.nodeId,
    publicKey: input.publicKey,
    label: input.label,
    ratifiedAt: at,
    revokedAt: null,
  };
  store.insert(authority);

  audit.append({
    outcome: "RATIFIED",
    action: "RATIFY",
    code: "OK",
    nodeId: input.nodeId,
    authorityId: input.id,
    publicKey: input.publicKey,
    detail: `frozen under host attestation: ${input.hostAttestation}`,
    at,
  });

  return { ok: true, authority };
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * Build the exact preimage the break-glass private key must sign for a
 * lost-TOTP reset. Not a suite money-path tuple — purpose-prefixed text only.
 *
 * Built by frozen field-sequence concatenation (no JSON.stringify in this module:
 * device production sources are construction-site audited against ad-hoc
 * stringify of enrollment-adjacent preimages). Inputs are UUID/ISO-only so the
 * resulting payload is byte-stable and quote-safe.
 */
export function buildBreakGlassTotpResetPreimage(input: {
  readonly nodeId: string;
  readonly authorityId: string;
  readonly nonce: string;
  readonly issuedAt: string;
}): string {
  if (!UUID_RE.test(input.nodeId)) throw new Error("nodeId must be a UUID");
  if (!UUID_RE.test(input.authorityId)) throw new Error("authorityId must be a UUID");
  if (!UUID_RE.test(input.nonce)) throw new Error("nonce must be a UUID");
  if (!ISO_MS_RE.test(input.issuedAt)) {
    throw new Error("issuedAt must be canonical ISO-8601 with milliseconds Z");
  }
  // Field sequence frozen: purpose, node_id, authority_id, nonce, issued_at.
  const payload =
    `{"purpose":"${BREAK_GLASS_TOTP_RESET_PURPOSE}",` +
    `"node_id":"${input.nodeId}",` +
    `"authority_id":"${input.authorityId}",` +
    `"nonce":"${input.nonce}",` +
    `"issued_at":"${input.issuedAt}"}`;
  return `${BREAK_GLASS_TOTP_RESET_PURPOSE}\n${payload}`;
}

/** Port the shell implements to clear operator TOTP factors (apps/node admin-reset analogue). */
export interface TotpFactorResetPort {
  /**
   * Clear the operator TOTP factor for this node. Must NOT touch wallet rows,
   * destination rows, vault keys, or device private keys.
   */
  resetTotpFactor(nodeId: string): void;
}

export interface BreakGlassTotpResetInput {
  readonly nodeId: string;
  readonly authorityId: string;
  readonly authorityPublicKey: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly signature: string;
  readonly nowMs: number;
  /** Max age of issued_at (default 300s). */
  readonly maxAgeMs?: number;
}

/**
 * Reset a lost TOTP factor under the frozen break-glass ceremony.
 * Bare login / TOTP alone cannot call this successfully: signature over the
 * fixed preimage from an active frozen break-glass key is mandatory.
 */
export function resetTotpUnderBreakGlass(
  store: BreakGlassAuthorityStore,
  audit: BreakGlassAuditLog,
  totpReset: TotpFactorResetPort,
  input: BreakGlassTotpResetInput,
): BreakGlassTotpResetResult {
  const at = new Date(input.nowMs).toISOString();
  const maxAgeMs = input.maxAgeMs ?? 300_000;

  const authority = store.findActiveByNodeAndPublicKey(input.nodeId, input.authorityPublicKey);
  if (authority === null) {
    const any = store.findByNodeAndPublicKey(input.nodeId, input.authorityPublicKey);
    const code = any !== null && any.revokedAt !== null ? "AUTHORITY_REVOKED" : "AUTHORITY_UNKNOWN";
    const detail =
      code === "AUTHORITY_REVOKED"
        ? "break-glass authority has been revoked"
        : "no active frozen break-glass authority for this public key";
    audit.append({
      outcome: "REJECTED",
      action: "TOTP_RESET",
      code,
      nodeId: input.nodeId,
      authorityId: input.authorityId,
      publicKey: input.authorityPublicKey,
      detail,
      at,
    });
    return { ok: false, code, detail };
  }

  if (authority.id !== input.authorityId) {
    const detail = "break-glass authority id does not match store row";
    audit.append({
      outcome: "REJECTED",
      action: "TOTP_RESET",
      code: "AUTHORITY_ID_MISMATCH",
      nodeId: input.nodeId,
      authorityId: input.authorityId,
      publicKey: input.authorityPublicKey,
      detail,
      at,
    });
    return { ok: false, code: "AUTHORITY_ID_MISMATCH", detail };
  }

  const issuedMs = Date.parse(input.issuedAt);
  if (!Number.isFinite(issuedMs) || input.nowMs - issuedMs > maxAgeMs || input.nowMs < issuedMs) {
    const detail = "break-glass TOTP-reset ceremony window is invalid or expired";
    audit.append({
      outcome: "REJECTED",
      action: "TOTP_RESET",
      code: "CEREMONY_EXPIRED",
      nodeId: input.nodeId,
      authorityId: input.authorityId,
      publicKey: input.authorityPublicKey,
      detail,
      at,
    });
    return { ok: false, code: "CEREMONY_EXPIRED", detail };
  }

  const preimage = buildBreakGlassTotpResetPreimage({
    nodeId: input.nodeId,
    authorityId: input.authorityId,
    nonce: input.nonce,
    issuedAt: input.issuedAt,
  });
  if (!verifyEd25519Detached(preimage, input.signature, authority.publicKey)) {
    const detail = "break-glass signature over TOTP-reset preimage is invalid";
    audit.append({
      outcome: "REJECTED",
      action: "TOTP_RESET",
      code: "SIGNATURE_INVALID",
      nodeId: input.nodeId,
      authorityId: input.authorityId,
      publicKey: input.authorityPublicKey,
      detail,
      at,
    });
    return { ok: false, code: "SIGNATURE_INVALID", detail };
  }

  totpReset.resetTotpFactor(input.nodeId);

  audit.append({
    outcome: "TOTP_RESET",
    action: "TOTP_RESET",
    code: "OK",
    nodeId: input.nodeId,
    authorityId: input.authorityId,
    publicKey: input.authorityPublicKey,
    detail: "TOTP factor reset under frozen break-glass ceremony",
    at,
  });

  return { ok: true };
}
