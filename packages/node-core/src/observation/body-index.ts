// index and verify retained observation bodies on every authoritative read.
//
// Governing: ("Recompute and compare their digest on
// every authoritative read from storage")
// (canonical_bytes_mismatch).
//
// Read-path discipline over gateway_observations retained material: re-hash the stored
// completed transaction text, re-derive role projection, recompute the A.7 fingerprint,
// and re-run Ed25519 over both step signatures. A stored "verified at write" boolean is
// never trusted. Fail closed on drift, hash collision-with-content mismatch, or wrong-role
// lookup. Does not promote state or authorize retries (non-authority).
//
// The index is a resolver over the same gateway_observations columns — never a second
// source of truth. Body text and signatures stay linked as one unit on every return path.

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { verifyRawEd25519 } from "../protocol/ed25519-verify.js";
import type { SettledSplitChainTransaction } from "../protocol/inner.js";
import { parseEd25519Signature, parseWalletPublicKey } from "../protocol/scalars.js";
import {
  buildGenesisWalletHeadFingerprint,
  buildWalletHeadFingerprintFromProjection,
} from "./fingerprint.js";
import {
  projectGenesisState,
  projectRoleState,
  type WalletObservationRole,
} from "./projection.js";

/** Role vocabulary used by retained observation bodies. */
type ObservationWalletRole = WalletObservationRole;

export type BodyIndexFailureReason =
  | "BODY_MISSING"
  | "BODY_HASH_DRIFT"
  | "FINGERPRINT_DRIFT"
  | "SIGNATURE_INVALID"
  | "ROLE_MISMATCH"
  | "WALLET_ROLE_INVALID"
  | "CANONICAL_BYTES_MISMATCH"
  | "MALFORMED_BODY"
  | "WRONG_ROLE_LOOKUP"
  | "NOT_FOUND"
  | "HASH_CONTENT_COLLISION";

export interface RetainedBodyRecord {
  /** Durable gateway_observations.id — primary resolve key. */
  readonly observation_id: string;
  readonly wallet_public_key: string;
  /** Per-stream sequence (UNIQUE with observer + wallet). */
  readonly wallet_seq: number;
  /** Role claimed/stored for this observation row. */
  readonly wallet_role: ObservationWalletRole;
  readonly parse_result: "VERIFIED_HEAD" | "VERIFIED_GENESIS";
  readonly completed_transaction_text: string | null;
  readonly completed_transaction_sha256: string | null;
  readonly inner_preimage_text: string | null;
  readonly step_1_signature: string | null;
  readonly step_2_signature: string | null;
  readonly s_signature: string;
  readonly p_signature: string;
  readonly b_amount: string;
  readonly semantic_fingerprint: string;
}

/** Body + role projection returned as one unit after re-verification (never split). */
export interface ResolvedRetainedBody {
  readonly observation_id: string;
  readonly wallet_public_key: string;
  readonly wallet_seq: number;
  readonly role: ObservationWalletRole;
  readonly completed_transaction_text: string | null;
  readonly completed_transaction_sha256: string | null;
  readonly inner_preimage_text: string | null;
  readonly step_1_signature: string | null;
  readonly step_2_signature: string | null;
  readonly s_signature: string;
  readonly p_signature: string;
  readonly b_amount: string;
  readonly semantic_fingerprint: string;
}

export type BodyIndexVerifyResult =
  | {
      readonly ok: true;
      readonly role: ObservationWalletRole;
      readonly semanticFingerprint: string;
      readonly completedTransactionSha256: string | null;
    }
  | {
      readonly ok: false;
      readonly reason: BodyIndexFailureReason;
      readonly detail: string;
    };

export type BodyIndexResolveResult =
  | { readonly ok: true; readonly body: ResolvedRetainedBody }
  | {
      readonly ok: false;
      readonly reason: BodyIndexFailureReason;
      readonly detail: string;
    };

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function verifyEd25519(
  preimageText: string,
  publicKeyText: string,
  signatureText: string,
): boolean {
  let canonicalKey: string;
  let canonicalSignature: string;
  try {
    canonicalKey = parseWalletPublicKey(publicKeyText);
    canonicalSignature = parseEd25519Signature(signatureText);
  } catch {
    return false;
  }
  return verifyRawEd25519({
    publicKeyBytes: Buffer.from(canonicalKey, "base64url"),
    preimageBytes: Buffer.from(preimageText, "utf8"),
    signatureBytes: Buffer.from(canonicalSignature, "base64url"),
  });
}

/**
 * Parse settled transaction text without re-serializing: the stored string is the
 * authority; we only extract fields for role projection and signature checks.
 */
function parseSettledTransactionText(
  text: string,
): SettledSplitChainTransaction | { error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return { error: "completed_transaction_text is not valid JSON" };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { error: "completed_transaction_text is not an object" };
  }
  const obj = parsed as Record<string, unknown>;
  if (
    typeof obj.step_1_signature !== "string" ||
    typeof obj.step_2_signature !== "string" ||
    obj.inner === null ||
    typeof obj.inner !== "object" ||
    Array.isArray(obj.inner)
  ) {
    return { error: "completed_transaction_text missing inner/signatures" };
  }
  return {
    inner: obj.inner as SettledSplitChainTransaction["inner"],
    step_1_signature: obj.step_1_signature,
    step_2_signature: obj.step_2_signature,
  };
}

function toResolved(record: RetainedBodyRecord): ResolvedRetainedBody {
  return {
    observation_id: record.observation_id,
    wallet_public_key: record.wallet_public_key,
    wallet_seq: record.wallet_seq,
    role: record.wallet_role,
    completed_transaction_text: record.completed_transaction_text,
    completed_transaction_sha256: record.completed_transaction_sha256,
    inner_preimage_text: record.inner_preimage_text,
    step_1_signature: record.step_1_signature,
    step_2_signature: record.step_2_signature,
    s_signature: record.s_signature,
    p_signature: record.p_signature,
    b_amount: record.b_amount,
    semantic_fingerprint: record.semantic_fingerprint,
  };
}

/**
 * Authoritative read: re-verify digest, role projection, fingerprint, and both signatures
 * against the retained body. Optional `expectedRole` rejects wrong-role lookups.
 */
export function verifyRetainedBodyOnRead(
  record: RetainedBodyRecord,
  options: { readonly expectedRole?: ObservationWalletRole } = {},
): BodyIndexVerifyResult {
  if (options.expectedRole !== undefined && options.expectedRole !== record.wallet_role) {
    return {
      ok: false,
      reason: "WRONG_ROLE_LOOKUP",
      detail: `expected role ${options.expectedRole}, record carries ${record.wallet_role}`,
    };
  }

  if (record.parse_result === "VERIFIED_GENESIS") {
    return verifyGenesisOnRead(record);
  }
  return verifyHeadOnRead(record);
}

function verifyGenesisOnRead(record: RetainedBodyRecord): BodyIndexVerifyResult {
  if (record.wallet_role !== "genesis") {
    return {
      ok: false,
      reason: "ROLE_MISMATCH",
      detail: "VERIFIED_GENESIS requires wallet_role=genesis",
    };
  }
  if (
    record.completed_transaction_text !== null ||
    record.completed_transaction_sha256 !== null ||
    record.inner_preimage_text !== null ||
    record.step_1_signature !== null ||
    record.step_2_signature !== null
  ) {
    return {
      ok: false,
      reason: "CANONICAL_BYTES_MISMATCH",
      detail: "genesis rows must carry null signed-material fields",
    };
  }
  if (record.s_signature !== "" || record.p_signature !== "" || record.b_amount !== "0") {
    return {
      ok: false,
      reason: "CANONICAL_BYTES_MISMATCH",
      detail: "genesis requires S=\"\", P=\"\", B=\"0\"",
    };
  }

  const genesis = projectGenesisState();
  const fp = buildGenesisWalletHeadFingerprint(record.wallet_public_key, genesis);
  if (!fp.ok) {
    return { ok: false, reason: "FINGERPRINT_DRIFT", detail: fp.detail };
  }
  if (fp.fingerprint.sha256 !== record.semantic_fingerprint) {
    return {
      ok: false,
      reason: "FINGERPRINT_DRIFT",
      detail: "stored semantic_fingerprint does not match recomputed genesis digest",
    };
  }
  return {
    ok: true,
    role: "genesis",
    semanticFingerprint: fp.fingerprint.sha256,
    completedTransactionSha256: null,
  };
}

function verifyHeadOnRead(record: RetainedBodyRecord): BodyIndexVerifyResult {
  if (record.wallet_role !== "sender" && record.wallet_role !== "receiver") {
    return {
      ok: false,
      reason: "ROLE_MISMATCH",
      detail: "VERIFIED_HEAD requires wallet_role sender|receiver",
    };
  }
  if (
    record.completed_transaction_text === null ||
    record.completed_transaction_sha256 === null ||
    record.inner_preimage_text === null ||
    record.step_1_signature === null ||
    record.step_2_signature === null
  ) {
    return {
      ok: false,
      reason: "BODY_MISSING",
      detail: "VERIFIED_HEAD requires complete signed material",
    };
  }

  // Body hash re-verify — digest alone is never equality authority.
  const recomputedBodyHash = sha256Hex(record.completed_transaction_text);
  if (recomputedBodyHash !== record.completed_transaction_sha256) {
    return {
      ok: false,
      reason: "BODY_HASH_DRIFT",
      detail: "completed_transaction_sha256 does not match stored body text",
    };
  }

  const settled = parseSettledTransactionText(record.completed_transaction_text);
  if ("error" in settled) {
    return { ok: false, reason: "MALFORMED_BODY", detail: settled.error };
  }

  // Stored signature fields must bind to the same body unit (verify A, display A).
  if (
    settled.step_1_signature !== record.step_1_signature ||
    settled.step_2_signature !== record.step_2_signature
  ) {
    return {
      ok: false,
      reason: "CANONICAL_BYTES_MISMATCH",
      detail: "indexed signatures do not match body signatures",
    };
  }

  // Inner preimage text must be byte-exact with the body's inner (no re-serialize drift).
  const bodyInnerText = JSON.stringify(settled.inner);
  if (bodyInnerText !== record.inner_preimage_text) {
    return {
      ok: false,
      reason: "CANONICAL_BYTES_MISMATCH",
      detail: "inner_preimage_text does not match body's inner JSON",
    };
  }

  // Live Ed25519 re-verification (not a cached flag).
  if (
    !verifyEd25519(
      record.inner_preimage_text,
      settled.inner.step_1_key_public__base64urlsafe,
      record.step_1_signature,
    )
  ) {
    return {
      ok: false,
      reason: "SIGNATURE_INVALID",
      detail: "step_1_signature failed Ed25519 re-verify on read",
    };
  }
  const step2Preimage =
    `{"inner":${record.inner_preimage_text}` +
    `,"step_1_signature":${JSON.stringify(record.step_1_signature)}}`;
  if (
    !verifyEd25519(
      step2Preimage,
      settled.inner.step_2_key_public__base64urlsafe,
      record.step_2_signature,
    )
  ) {
    return {
      ok: false,
      reason: "SIGNATURE_INVALID",
      detail: "step_2_signature failed Ed25519 re-verify on read",
    };
  }

  const projected = projectRoleState(settled, record.wallet_public_key);
  if (!projected.ok) {
    return {
      ok: false,
      reason: "WALLET_ROLE_INVALID",
      detail: projected.detail,
    };
  }
  if (projected.projection.role !== record.wallet_role) {
    return {
      ok: false,
      reason: "ROLE_MISMATCH",
      detail: `re-derived role ${projected.projection.role} != stored ${record.wallet_role}`,
    };
  }
  if (
    projected.projection.S !== record.s_signature ||
    projected.projection.P !== record.p_signature ||
    projected.projection.B !== record.b_amount
  ) {
    return {
      ok: false,
      reason: "CANONICAL_BYTES_MISMATCH",
      detail: "stored S/P/B does not match re-derived projection",
    };
  }

  const fp = buildWalletHeadFingerprintFromProjection(
    projected.projection,
    record.wallet_public_key,
  );
  if (!fp.ok) {
    return { ok: false, reason: "FINGERPRINT_DRIFT", detail: fp.detail };
  }
  if (fp.fingerprint.sha256 !== record.semantic_fingerprint) {
    return {
      ok: false,
      reason: "FINGERPRINT_DRIFT",
      detail: "stored semantic_fingerprint does not match recomputed digest",
    };
  }

  return {
    ok: true,
    role: projected.projection.role,
    semanticFingerprint: fp.fingerprint.sha256,
    completedTransactionSha256: recomputedBodyHash,
  };
}

/**
 * Content-keyed lookup helper: two bodies with equal digests are still distinguished by
 * exact byte comparison of the retained text (digest is never equality authority).
 */
export function retainedBodiesExactEqual(leftText: string, rightText: string): boolean {
  return leftText === rightText;
}

function walletSeqKey(walletPublicKey: string, walletSeq: number): string {
  return `${walletPublicKey}\0${walletSeq}`;
}

/**
 * Read-path index over retained bodies. Not a duplicate store of truth — callers feed it
 * gateway_observations rows; every resolve re-runs verifyRetainedBodyOnRead so crypto is
 * live on read, not a cached write-time boolean.
 */
export interface RetainedBodyIndex {
  /** Register a captured row. Does not re-verify at write (capture already did). */
  put(record: RetainedBodyRecord): void;
  /** Resolve by gateway_observations.id and re-verify on read. */
  resolveByObservationId(
    observationId: string,
    options?: { readonly expectedRole?: ObservationWalletRole },
  ): BodyIndexResolveResult;
  /** Resolve by (wallet_public_key, wallet_seq) and re-verify on read. */
  resolveByWalletSeq(
    walletPublicKey: string,
    walletSeq: number,
    options?: { readonly expectedRole?: ObservationWalletRole },
  ): BodyIndexResolveResult;
  /**
   * Detect distinct bodies indexed under the same completed_transaction_sha256.
   * Digest is a lookup hint only — content comparison is the equality authority.
   */
  detectHashContentCollision(
    bodySha256: string,
  ): BodyIndexResolveResult | { readonly ok: true; readonly distinct: false };
}

export class InMemoryRetainedBodyIndex implements RetainedBodyIndex {
  private readonly byObservationId = new Map<string, RetainedBodyRecord>();
  private readonly byWalletSeq = new Map<string, RetainedBodyRecord>();
  /** body_sha256 → observation_ids claiming that digest (collision detector). */
  private readonly byBodyHash = new Map<string, Set<string>>();

  put(record: RetainedBodyRecord): void {
    this.byObservationId.set(record.observation_id, record);
    this.byWalletSeq.set(walletSeqKey(record.wallet_public_key, record.wallet_seq), record);
    if (record.completed_transaction_sha256 !== null) {
      let set = this.byBodyHash.get(record.completed_transaction_sha256);
      if (set === undefined) {
        set = new Set();
        this.byBodyHash.set(record.completed_transaction_sha256, set);
      }
      set.add(record.observation_id);
    }
  }

  resolveByObservationId(
    observationId: string,
    options: { readonly expectedRole?: ObservationWalletRole } = {},
  ): BodyIndexResolveResult {
    const record = this.byObservationId.get(observationId);
    if (record === undefined) {
      return {
        ok: false,
        reason: "NOT_FOUND",
        detail: `no retained body for observation_id=${observationId}`,
      };
    }
    return this.resolveRecord(record, options);
  }

  resolveByWalletSeq(
    walletPublicKey: string,
    walletSeq: number,
    options: { readonly expectedRole?: ObservationWalletRole } = {},
  ): BodyIndexResolveResult {
    const record = this.byWalletSeq.get(walletSeqKey(walletPublicKey, walletSeq));
    if (record === undefined) {
      return {
        ok: false,
        reason: "NOT_FOUND",
        detail: `no retained body for wallet_public_key/wallet_seq`,
      };
    }
    return this.resolveRecord(record, options);
  }

  detectHashContentCollision(
    bodySha256: string,
  ): BodyIndexResolveResult | { readonly ok: true; readonly distinct: false } {
    const ids = this.byBodyHash.get(bodySha256);
    if (ids === undefined || ids.size < 2) {
      return { ok: true, distinct: false };
    }
    const texts = new Map<string, string>();
    for (const id of ids) {
      const row = this.byObservationId.get(id);
      if (row === undefined || row.completed_transaction_text === null) continue;
      const prior = texts.get(row.completed_transaction_text);
      if (prior === undefined) {
        texts.set(row.completed_transaction_text, id);
      }
    }
    if (texts.size < 2) {
      return { ok: true, distinct: false };
    }
    const [first, second] = [...texts.values()];
    return {
      ok: false,
      reason: "HASH_CONTENT_COLLISION",
      detail: `distinct bodies share completed_transaction_sha256; observation_ids=${first},${second}`,
    };
  }

  private resolveRecord(
    record: RetainedBodyRecord,
    options: { readonly expectedRole?: ObservationWalletRole },
  ): BodyIndexResolveResult {
    // Collision gate: if another distinct body claims this digest, fail closed before
    // returning either body (digest is never equality authority).
    if (record.completed_transaction_sha256 !== null) {
      const collision = this.detectHashContentCollision(record.completed_transaction_sha256);
      if (!collision.ok) {
        return collision;
      }
    }

    const verified = verifyRetainedBodyOnRead(record, options);
    if (!verified.ok) {
      return { ok: false, reason: verified.reason, detail: verified.detail };
    }
    // Body + signatures returned as one unit — never a path that returns a signature
    // verified against a different body than the one displayed.
    return { ok: true, body: toResolved(record) };
  }
}
