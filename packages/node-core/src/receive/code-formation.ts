// Expiry freeze, unsigned receive
// transfer code, zp-receive-expected-v1 preimage, node-identity signature.
//
// The signer persists the preimage before (or with) the signature; the byte-exact signing and key-custody rules.
//
// Step 8 (CREATED→READY DB-TX) is code-ready-commit.ts. This module builds the exact bytes
// and stages them through an injected store so a crash between preimage persistence and
// signature persistence is recoverable from the identical stored preimage (never a re-derived
// one). The store deliberately separates preimage write from signature write — OPS row 2
// and the INVARIANT_BREACH branch (row 4) are only detectable when those two facts are not a
// single atomic insert.
//
// Boundaries: receive may import protocol + api only (test/boundaries.test.ts). Fingerprint
// construction uses the suite builder in protocol/, not observation/.

import {
  parsePositiveZkzAmount,
  type PositiveZkzAmount,
} from "../protocol/amounts.js";
import {
  clampReceiveTtlSecs,
  deriveExpiryUnixTimeSecs,
  type ReceiveTtlBounds,
} from "../protocol/receive-ttl.js";
import {
  buildReceiveTransferCode,
  type ReceiveTransferCode,
} from "../protocol/receive-transfer-code.js";
import {
  parseExpiryUnixTimeSecs,
  parseSha256Hex,
  parseUuid,
  parseWalletPublicKey,
  type ExpiryUnixTimeSecs,
  type Sha256Hex,
  type Uuid,
  type WalletPublicKey,
} from "../protocol/scalars.js";
import {
  buildReceiveExpectedArtifact,
  buildWalletHeadFingerprint,
  parseReceiveExpectedArtifact,
  type AfterLanding as SuiteAfterLanding,
} from "../protocol/suite/index.js";
import type { T0Projection } from "./arm-mutation.js";

export const RECEIVE_EXPECTED_ARTIFACT_PURPOSE = "zp-receive-expected-v1" as const;
export const RECEIVE_EXPECTED_CANONICAL_VERSION = 1 as const;

/** A.3.4 envelope field sequence; wire `key_id` maps to storage `signing_key_id`. */
export interface ArtifactEnvelope {
  readonly key_id: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly signature: string;
}

export type ReceiveAfterLanding =
  | { readonly kind: "HOLD"; readonly destination_id: null }
  | { readonly kind: "INTERNAL_MOVE"; readonly destination_id: string };

/**
 * The key-custody rule: node-core never holds a private key. The composition root injects this
 * narrow capability over the active node identity key.
 */
export interface NodeIdentitySigner {
  readonly signingKeyId: string;
  sign(preimageBytes: Uint8Array): Promise<string> | string;
}

/**
 * Durable staging for the artifact preimage and its signature, plus the withheld code.
 * Implementations MUST NOT update a persisted preimage, and MUST refuse a signature write
 * whose digest does not match the stored preimage_sha256 (byte-exact resume).
 */
export interface ReceiveCodeFormationStore {
  /**
   * Persist the exact artifact preimage BEFORE the signer is called (first
   * half). Returns the durable artifact id. Idempotent on (operation_id): a second call with
   * identical bytes returns the existing id; a second call with different bytes is a hard
   * error (bytes are never regenerated).
   */
  persistArtifactPreimage(input: {
    readonly artifactId: string;
    readonly operationId: string;
    readonly purpose: typeof RECEIVE_EXPECTED_ARTIFACT_PURPOSE;
    readonly canonicalVersion: typeof RECEIVE_EXPECTED_CANONICAL_VERSION;
    readonly preimageText: string;
    readonly preimageSha256: string;
  }): Promise<{ readonly artifactId: string; readonly alreadyPresent: boolean }>;

  /**
   * Attach the node-identity signature without changing the preimage (step 7 second half).
   * Must be a separate write from persistArtifactPreimage.
   */
  persistArtifactSignature(input: {
    readonly artifactId: string;
    readonly operationId: string;
    readonly signingKeyId: string;
    readonly signature: string;
    readonly expectedPreimageSha256: string;
  }): Promise<void>;

  /** Load a durable preimage for crash-resume. */
  loadArtifactPreimage(operationId: string): Promise<{
    readonly artifactId: string;
    readonly preimageText: string;
    readonly preimageSha256: string;
    readonly signingKeyId: string | null;
    readonly signature: string | null;
  } | null>;

  /**
   * True when a signer audit row indicates the node identity key was invoked for this
   * operation's artifact purpose. Used by classifyReceiveCodePhase.
   */
  hasSignerAuditForArtifact(operationId: string): Promise<boolean>;

  /**
   * True when a complete receive_codes row exists for the operation (code + artifact link).
   * Does not imply READY — the state transition may still be pending.
   */
  hasCompleteCodeRecord(operationId: string): Promise<boolean>;
}

export interface FormReceiveCodeInput {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly operationId: string;
  readonly receiverWalletId: string;
  readonly receiverPubkey: string;
  readonly amountZkz: string;
  readonly anchor: string;
  readonly afterLanding: ReceiveAfterLanding;
  /** Verified T0 from captureReceiveT0. */
  readonly t0: T0Projection;
  /**
   * Request-supplied TTL in seconds, or undefined for the configured default. Clamped once
   * here; the derived expiry string is byte-frozen from this point (receive TTL policy; destination binding).
   */
  readonly requestedTtlSecs: number | undefined;
  readonly ttlBounds: ReceiveTtlBounds;
  /**
   * Formation clock (ms). Used exactly once on first formation for expiry derivation.
   * Ignored on resume when a durable preimage already freezes expiry_unix_time_secs
   */
  readonly nowUnixMs: number;
  readonly artifactId: string;
  readonly signer: NodeIdentitySigner;
  readonly store: ReceiveCodeFormationStore;
}

export interface FormedReceiveCode {
  readonly transferCode: ReceiveTransferCode;
  readonly expiryUnixTimeSecs: ExpiryUnixTimeSecs;
  readonly receiverT0Fingerprint: Sha256Hex;
  readonly artifact: {
    readonly id: string;
    readonly operationId: string;
    readonly purpose: typeof RECEIVE_EXPECTED_ARTIFACT_PURPOSE;
    readonly canonicalVersion: typeof RECEIVE_EXPECTED_CANONICAL_VERSION;
    readonly envelope: ArtifactEnvelope;
  };
  readonly t0: T0Projection;
  readonly receiverPubkey: WalletPublicKey;
  readonly amountZkz: PositiveZkzAmount;
  readonly discriminator: Uuid;
  /** Request anchor, bound into the code message and the expected artifact. */
  readonly anchor: string;
  readonly afterLanding: ReceiveAfterLanding;
}

export type FormReceiveCodeRejectionReason =
  | "invalid_field"
  | "t0_fingerprint_rejected"
  | "preimage_bytes_diverged"
  | "signer_rejected";

export type FormReceiveCodeResult =
  | { readonly ok: true; readonly formed: FormedReceiveCode }
  | {
      readonly ok: false;
      readonly reason: FormReceiveCodeRejectionReason;
      readonly detail: string;
    };

/**
 * A.7 semantic fingerprint of the verified T0 projection. Genesis (S="", P="", B="0") uses
 * state_kind GENESIS with null inner/step signatures; any other head uses state_kind HEAD.
 * The digest is what `receiver_t0_fingerprint` binds — never a placeholder of zeros.
 */
export function buildReceiverT0Fingerprint(
  receiverPubkey: string,
  t0: Pick<T0Projection, "s0" | "p0" | "b0">,
): { readonly ok: true; readonly fingerprint: Sha256Hex } | { readonly ok: false; readonly detail: string } {
  try {
    const pubkey = parseWalletPublicKey(receiverPubkey);
    const isGenesis = t0.s0 === "" && t0.p0 === "" && t0.b0 === "0";
    const built = buildWalletHeadFingerprint({
      wallet_public_key: pubkey,
      state_kind: isGenesis ? "GENESIS" : "HEAD",
      s_signature: t0.s0 as never,
      p_signature: t0.p0 as never,
      b_amount: t0.b0 as never,
      inner_sha256: null,
      step_1_signature: null,
      step_2_signature: null,
    });
    return { ok: true, fingerprint: parseSha256Hex(built.sha256) };
  } catch (error) {
    return {
      ok: false,
      detail: error instanceof Error ? error.message : "t0 fingerprint rejected",
    };
  }
}

function toSuiteAfterLanding(afterLanding: ReceiveAfterLanding): SuiteAfterLanding {
  if (afterLanding.kind === "HOLD") {
    return { kind: "HOLD", destination_id: null };
  }
  return {
    kind: "INTERNAL_MOVE",
    destination_id: parseUuid(afterLanding.destination_id),
  };
}

/**
 * Steps 5–7.
 *
 * 5. Freeze expiry; construct unsigned transfer code from S0/B0; hash it.
 * 6. Construct the exact zp-receive-expected-v1 preimage (14-field A.3.1 sequence via suite builder).
 * 7. Persist preimage, then sign the identical persisted bytes, then persist signature.
 *
 * On crash-resume, if a preimage is already durable (unsigned or signed), the transfer code is
 * rebuilt from the preimage's frozen expiry_unix_time_secs and the signer (when still needed)
 * is called against those exact stored preimage bytes — never a freshly re-derived expiry or
 * re-serialized preimage.
 */
export async function formReceiveCodeAndArtifact(
  input: FormReceiveCodeInput,
): Promise<FormReceiveCodeResult> {
  let amountZkz: PositiveZkzAmount;
  let nodeId: Uuid;
  let implementerId: Uuid;
  let operationId: Uuid;
  let receiverWalletId: Uuid;
  let receiverPubkey: WalletPublicKey;
  try {
    amountZkz = parsePositiveZkzAmount(input.amountZkz);
    nodeId = parseUuid(input.nodeId);
    implementerId = parseUuid(input.implementerId);
    operationId = parseUuid(input.operationId);
    receiverWalletId = parseUuid(input.receiverWalletId);
    receiverPubkey = parseWalletPublicKey(input.receiverPubkey);
  } catch (error) {
    return {
      ok: false,
      reason: "invalid_field",
      detail: error instanceof Error ? error.message : "field parse rejected",
    };
  }

  const fp = buildReceiverT0Fingerprint(receiverPubkey, input.t0);
  if (!fp.ok) {
    return { ok: false, reason: "t0_fingerprint_rejected", detail: fp.detail };
  }

  // Load durable preimage before minting expiry. Transfer-code plaintext is not durable
  // until INSERT_RECEIVE_CODE (step 8); the only freeze of expiry before READY is the
  // preimage field expiry_unix_time_secs. Resume MUST rebuild the code from that field
  // and never call deriveExpiryUnixTimeSecs again.
  const existing = await input.store.loadArtifactPreimage(operationId);

  let expiryUnixTimeSecs: ExpiryUnixTimeSecs;
  let transferCode: ReceiveTransferCode;

  if (existing !== null) {
    let boundCodeDigest: string;
    try {
      const parsed = parseReceiveExpectedArtifact(existing.preimageText);
      if (parsed.sha256 !== existing.preimageSha256) {
        return {
          ok: false,
          reason: "preimage_bytes_diverged",
          detail: "durable preimage_sha256 does not match preimage bytes",
        };
      }
      if (String(parsed.payload.operation_id) !== operationId) {
        return {
          ok: false,
          reason: "preimage_bytes_diverged",
          detail: "durable preimage binds a different operation_id",
        };
      }
      const frozenExpiry = parsed.payload.expiry_unix_time_secs;
      if (frozenExpiry === null || frozenExpiry === undefined) {
        return {
          ok: false,
          reason: "preimage_bytes_diverged",
          detail: "durable preimage missing expiry_unix_time_secs",
        };
      }
      expiryUnixTimeSecs = parseExpiryUnixTimeSecs(frozenExpiry);
      boundCodeDigest = String(parsed.payload.transfer_code_sha256);
      transferCode = buildReceiveTransferCode({
        receiverPubkey,
        amountZkz,
        b0: input.t0.b0,
        discriminator: operationId,
        anchor: input.anchor,
        expiryUnixTimeSecs,
      });
    } catch (error) {
      return {
        ok: false,
        reason: "preimage_bytes_diverged",
        detail: error instanceof Error ? error.message : "durable preimage is not parseable",
      };
    }

    if (boundCodeDigest !== transferCode.transferCodeSha256) {
      return {
        ok: false,
        reason: "preimage_bytes_diverged",
        detail:
          existing.signature !== null
            ? "reconstructed transfer_code_sha256 does not match durable artifact binding"
            : "durable unsigned preimage binds a different transfer_code_sha256",
      };
    }

    if (existing.signature !== null && existing.signingKeyId !== null) {
      // Artifact already complete — return formed view from durable bytes + code rebuilt
      // under the frozen expiry bound inside the preimage.
      return {
        ok: true,
        formed: {
          transferCode,
          expiryUnixTimeSecs,
          receiverT0Fingerprint: fp.fingerprint,
          artifact: {
            id: existing.artifactId,
            operationId,
            purpose: RECEIVE_EXPECTED_ARTIFACT_PURPOSE,
            canonicalVersion: RECEIVE_EXPECTED_CANONICAL_VERSION,
            envelope: {
              key_id: existing.signingKeyId,
              preimage_text: existing.preimageText,
              preimage_sha256: existing.preimageSha256,
              signature: existing.signature,
            },
          },
          t0: input.t0,
          receiverPubkey,
          amountZkz,
          discriminator: operationId,
          anchor: input.anchor,
          afterLanding: input.afterLanding,
        },
      };
    }

    // Sign the identical persisted preimage (unsigned resume).
    const preimageText = existing.preimageText;
    const preimageSha256 = existing.preimageSha256;
    const preimageBytes = Buffer.from(preimageText, "utf8");
    const artifactId = existing.artifactId;

    let signature: string;
    try {
      signature = await input.signer.sign(preimageBytes);
    } catch (error) {
      return {
        ok: false,
        reason: "signer_rejected",
        detail: error instanceof Error ? error.message : "signer rejected",
      };
    }

    await input.store.persistArtifactSignature({
      artifactId,
      operationId,
      signingKeyId: input.signer.signingKeyId,
      signature,
      expectedPreimageSha256: preimageSha256,
    });

    return {
      ok: true,
      formed: {
        transferCode,
        expiryUnixTimeSecs,
        receiverT0Fingerprint: fp.fingerprint,
        artifact: {
          id: artifactId,
          operationId,
          purpose: RECEIVE_EXPECTED_ARTIFACT_PURPOSE,
          canonicalVersion: RECEIVE_EXPECTED_CANONICAL_VERSION,
          envelope: {
            key_id: input.signer.signingKeyId,
            preimage_text: preimageText,
            preimage_sha256: preimageSha256,
            signature,
          },
        },
        t0: input.t0,
        receiverPubkey,
        amountZkz,
        discriminator: operationId,
        anchor: input.anchor,
        afterLanding: input.afterLanding,
      },
    };
  }

  // First formation — Step 5: mint expiry once from the formation clock, then the unsigned code.
  try {
    const clampedTtl = clampReceiveTtlSecs(input.requestedTtlSecs, input.ttlBounds);
    expiryUnixTimeSecs = parseExpiryUnixTimeSecs(
      deriveExpiryUnixTimeSecs(input.nowUnixMs, clampedTtl),
    );
    transferCode = buildReceiveTransferCode({
      receiverPubkey,
      amountZkz,
      b0: input.t0.b0,
      discriminator: operationId,
      anchor: input.anchor,
      expiryUnixTimeSecs,
    });
  } catch (error) {
    return {
      ok: false,
      reason: "invalid_field",
      detail: error instanceof Error ? error.message : "code construction rejected",
    };
  }

  // Step 6 — construct the exact preimage.
  let built;
  try {
    built = buildReceiveExpectedArtifact({
      node_id: nodeId,
      implementer_id: implementerId,
      operation_id: operationId,
      receiver_wallet_id: receiverWalletId,
      receiver_pubkey: receiverPubkey,
      amount_zkz: amountZkz,
      discriminator: operationId,
      anchor: input.anchor,
      receiver_t0_fingerprint: fp.fingerprint,
      expiry_unix_time_secs: expiryUnixTimeSecs,
      after_landing: toSuiteAfterLanding(input.afterLanding),
      transfer_code_sha256: parseSha256Hex(transferCode.transferCodeSha256),
    });
  } catch (error) {
    return {
      ok: false,
      reason: "invalid_field",
      detail: error instanceof Error ? error.message : "artifact construction rejected",
    };
  }

  let preimageText = built.preimageText;
  let preimageSha256 = built.sha256;
  let preimageBytes = built.preimageBytes;
  let artifactId = input.artifactId;

  // Step 7 first half — persist preimage BEFORE the signer call.
  const persisted = await input.store.persistArtifactPreimage({
    artifactId,
    operationId,
    purpose: RECEIVE_EXPECTED_ARTIFACT_PURPOSE,
    canonicalVersion: RECEIVE_EXPECTED_CANONICAL_VERSION,
    preimageText,
    preimageSha256,
  });
  artifactId = persisted.artifactId;
  if (persisted.alreadyPresent) {
    // Another worker won the insert; reload and continue from durable bytes.
    // Recurse into the resume path semantics by reloading — do not re-mint expiry.
    const reloaded = await input.store.loadArtifactPreimage(operationId);
    if (reloaded === null) {
      return {
        ok: false,
        reason: "preimage_bytes_diverged",
        detail: "preimage claimed present but not loadable",
      };
    }
    if (reloaded.preimageText !== preimageText || reloaded.preimageSha256 !== preimageSha256) {
      return {
        ok: false,
        reason: "preimage_bytes_diverged",
        detail: "concurrent formation produced different preimage bytes",
      };
    }
    preimageText = reloaded.preimageText;
    preimageSha256 = reloaded.preimageSha256;
    preimageBytes = Buffer.from(preimageText, "utf8");
    artifactId = reloaded.artifactId;
    if (reloaded.signature !== null && reloaded.signingKeyId !== null) {
      return {
        ok: true,
        formed: {
          transferCode,
          expiryUnixTimeSecs,
          receiverT0Fingerprint: fp.fingerprint,
          artifact: {
            id: artifactId,
            operationId,
            purpose: RECEIVE_EXPECTED_ARTIFACT_PURPOSE,
            canonicalVersion: RECEIVE_EXPECTED_CANONICAL_VERSION,
            envelope: {
              key_id: reloaded.signingKeyId,
              preimage_text: preimageText,
              preimage_sha256: preimageSha256,
              signature: reloaded.signature,
            },
          },
          t0: input.t0,
          receiverPubkey,
          amountZkz,
          discriminator: operationId,
          anchor: input.anchor,
          afterLanding: input.afterLanding,
        },
      };
    }
  }

  // Step 7 second half — sign the identical persisted preimage bytes, then persist signature.
  let signature: string;
  try {
    signature = await input.signer.sign(preimageBytes);
  } catch (error) {
    return {
      ok: false,
      reason: "signer_rejected",
      detail: error instanceof Error ? error.message : "signer rejected",
    };
  }

  await input.store.persistArtifactSignature({
    artifactId,
    operationId,
    signingKeyId: input.signer.signingKeyId,
    signature,
    expectedPreimageSha256: preimageSha256,
  });

  return {
    ok: true,
    formed: {
      transferCode,
      expiryUnixTimeSecs,
      receiverT0Fingerprint: fp.fingerprint,
      artifact: {
        id: artifactId,
        operationId,
        purpose: RECEIVE_EXPECTED_ARTIFACT_PURPOSE,
        canonicalVersion: RECEIVE_EXPECTED_CANONICAL_VERSION,
        envelope: {
          key_id: input.signer.signingKeyId,
          preimage_text: preimageText,
          preimage_sha256: preimageSha256,
          signature,
        },
      },
      t0: input.t0,
      receiverPubkey,
      amountZkz,
      discriminator: operationId,
      anchor: input.anchor,
      afterLanding: input.afterLanding,
    },
  };
}

/**
 * Durable-evidence classification for the code/artifact half of the
 * lease-acquired / not-READY window. Composed with classifyReceiveT0Phase by
 * boot recovery.
 */
export type ReceiveCodePhase =
  | "NO_PREIMAGE"
  | "PREIMAGE_UNSIGNED"
  | "ARTIFACT_COMPLETE"
  | "CODE_COMPLETE_STATE_PENDING"
  | "INVARIANT_BREACH";

export async function classifyReceiveCodePhase(
  store: ReceiveCodeFormationStore,
  operationId: string,
): Promise<ReceiveCodePhase> {
  const preimage = await store.loadArtifactPreimage(operationId);
  const signerAudit = await store.hasSignerAuditForArtifact(operationId);
  const codeComplete = await store.hasCompleteCodeRecord(operationId);

  if (preimage === null) {
    // Any expected exact byte record missing while a signer audit indicates use.
    if (signerAudit) return "INVARIANT_BREACH";
    return "NO_PREIMAGE";
  }
  if (preimage.signature === null) {
    if (signerAudit) return "INVARIANT_BREACH";
    return "PREIMAGE_UNSIGNED";
  }
  if (codeComplete) return "CODE_COMPLETE_STATE_PENDING";
  return "ARTIFACT_COMPLETE";
}
