// The node-identity directory and its non-equivocation property.
// TEST-ONLY: A.8 seed keys are TEST-ONLY and MUST never be used with live ZKZ.
//
// Covers A.6 ("validates the signing key against the seq-canonical key via the
// node-identity directory. A conflicting equal-epoch head is an INVARIANT_BREACH — alarmed, never
// silently resolved by picking one"); binding condition C3, same words; the
// instruction-origin identity rule (node identity key); the pull-cursor authority rule (seq-canonical event key, retirement by seq cursor).
//
// `implementer-checkpoint.ts` already asserts `CHECKPOINT_ANTI_ROLLBACK.validatesSigningKeyAgainst =
// "seq_canonical_key_via_node_identity_directory"` and already decides the equal-epoch INVARIANT_BREACH
// for HEADS. What was missing is the directory
// those two lean on, and the transparency control that stops a node serving one directory view to one
// tenant and a different one to another. Anti-rollback is per-tenant and therefore blind to that:
// each tenant's own view can be internally perfect while the views disagree with each other. NC2
// keeps tenant streams disjoint, so cross-stream divergence is invisible without this comparison.
//
// NOT a wire artifact. This introduces no new `zp-*-v1` canonical purpose — the suite purpose census
// (`machine-manifests/purposes.contract.ts`) is a closed frozen set of ten live + three C4-deferred
// purposes, and minting an eleventh would need a decision this row does not have. The view digest
// below is an internal transparency digest that tenants compare out-of-band; nothing is signed here
// and no golden bytes change (the byte-exact signing rule).

import { createHash } from "node:crypto";

/** One directory binding: an event-signing public key made seq-canonical from a given epoch (C3). */
export interface NodeIdentityDirectoryEntry {
  /** The `signing_key_id` a `zp-implementer-checkpoint-v1` names. */
  readonly signing_key_id: string;
  /** Padded base64url Ed25519 public key of that signing key. */
  readonly public_key: string;
  /** Decimal-string epoch from which this key is the seq-canonical signer (the pull-cursor seq-cursor model).*/
  readonly seq_canonical_epoch: string;
}

/** The C3 binding this directory exists to carry, in one machine-readable place. */
export const NODE_IDENTITY_DIRECTORY_RULE = {
  binds: "event_signing_public_key <-> implementer_seq_canonical_epoch",
  conflictingEqualEpochBinding: "INVARIANT_BREACH",
  resolvesConflictByPicking: false,
  singlePublishedHead: true,
  crossTenantViewDivergence: "EQUIVOCATION",
  identityKeyDecision: "instruction-origin-identity",
} as const;

export type DirectoryResolution =
  | { readonly outcome: "RESOLVED"; readonly entry: NodeIdentityDirectoryEntry }
  | { readonly outcome: "NO_CANONICAL_KEY" }
  | { readonly outcome: "MALFORMED_DIRECTORY" }
  | { readonly outcome: "INVARIANT_BREACH"; readonly epoch: string };

export type CheckpointKeyVerdict =
  | "ACCEPT"
  | "REJECT_UNKNOWN_KEY"
  | "REJECT_NOT_SEQ_CANONICAL"
  | "NO_CANONICAL_KEY"
  | "MALFORMED_DIRECTORY"
  | "INVARIANT_BREACH";

export type DirectoryViewComparison = "CONSISTENT" | "EQUIVOCATION";

// Epochs are non-negative decimal strings so they can exceed Number.MAX_SAFE_INTEGER; compare as
// BigInt, never lexically ("10" < "9" as text) and never as float. A malformed epoch is refused
// rather than thrown on: the directory is read from node storage, so a bad row must fail closed as a
// verdict the caller can alarm on, not as an exception that unwinds the checkpoint path.
const EPOCH_PATTERN = /^(0|[1-9][0-9]*)$/;

const epochOf = (entry: NodeIdentityDirectoryEntry): bigint => BigInt(entry.seq_canonical_epoch);

function isWellFormed(entries: readonly NodeIdentityDirectoryEntry[]): boolean {
  return entries.every(
    (entry) =>
      typeof entry.seq_canonical_epoch === "string" &&
      EPOCH_PATTERN.test(entry.seq_canonical_epoch) &&
      typeof entry.signing_key_id === "string" &&
      entry.signing_key_id.length > 0 &&
      typeof entry.public_key === "string" &&
      entry.public_key.length > 0,
  );
}

/**
 * Canonical ordering for a directory view: ascending epoch, then `signing_key_id`. Two nodes holding
 * the same bindings therefore produce the same bytes regardless of how rows are sequenced, so a digest
 * difference means a *content* difference — which is what makes the equivocation check sound rather
 * than merely noisy.
 */
function canonicalizeView(
  entries: readonly NodeIdentityDirectoryEntry[],
): readonly NodeIdentityDirectoryEntry[] {
  return [...entries].sort((a, b) => {
    const ea = epochOf(a);
    const eb = epochOf(b);
    if (ea !== eb) return ea < eb ? -1 : 1;
    return a.signing_key_id < b.signing_key_id ? -1 : a.signing_key_id > b.signing_key_id ? 1 : 0;
  });
}

/**
 * The epoch at which two different public keys both claim to be seq-canonical, if any — the
 * C3 equal-epoch conflict.
 *
 * Scanned over the WHOLE view, not just up to the epoch being resolved: a conflict introduced at a
 * later epoch is already a silent rebind of that implementer's key, and a checkpoint arriving at an
 * earlier epoch must not sail past it. Reported, never resolved by picking one — picking is the
 * behaviour canon forbids, because it is what makes the rebind invisible.
 */
export function findEqualEpochConflict(
  entries: readonly NodeIdentityDirectoryEntry[],
): string | undefined {
  const keyByEpoch = new Map<string, string>();
  for (const entry of entries) {
    const seen = keyByEpoch.get(entry.seq_canonical_epoch);
    if (seen !== undefined && seen !== entry.public_key) return entry.seq_canonical_epoch;
    keyByEpoch.set(entry.seq_canonical_epoch, entry.public_key);
  }
  return undefined;
}

/**
 * The seq-canonical key at `epoch`: the binding with the greatest epoch not after it.
 */
export function resolveSeqCanonicalKey(
  entries: readonly NodeIdentityDirectoryEntry[],
  epoch: string,
): DirectoryResolution {
  if (!isWellFormed(entries) || !EPOCH_PATTERN.test(epoch)) return { outcome: "MALFORMED_DIRECTORY" };

  const conflict = findEqualEpochConflict(entries);
  if (conflict !== undefined) return { outcome: "INVARIANT_BREACH", epoch: conflict };

  const target = BigInt(epoch);
  let best: NodeIdentityDirectoryEntry | undefined;
  for (const entry of canonicalizeView(entries)) {
    if (epochOf(entry) > target) break;
    best = entry;
  }

  return best === undefined ? { outcome: "NO_CANONICAL_KEY" } : { outcome: "RESOLVED", entry: best };
}

/**
 * The half of binding condition C3 the checkpoint path could not perform without a directory:
 * validate a checkpoint's `signing_key_id` against the seq-canonical key at its epoch. Every
 * checkpoint key check routes through here, so the conflict and malformed-row guards above sit on the
 * one path rather than at each call site.
 */
export function validateCheckpointSigningKey(
  entries: readonly NodeIdentityDirectoryEntry[],
  checkpoint: { readonly checkpoint_epoch: string; readonly signing_key_id: string },
): CheckpointKeyVerdict {
  const resolution = resolveSeqCanonicalKey(entries, checkpoint.checkpoint_epoch);
  if (resolution.outcome !== "RESOLVED") return resolution.outcome;
  if (!entries.some((entry) => entry.signing_key_id === checkpoint.signing_key_id)) {
    return "REJECT_UNKNOWN_KEY";
  }
  return resolution.entry.signing_key_id === checkpoint.signing_key_id ? "ACCEPT" : "REJECT_NOT_SEQ_CANONICAL";
}

/**
 * The exact bytes a directory view digests to: a fixed field sequence per entry, in canonical sequence.
 * Internal transparency preimage — not a signed suite tuple, no `zp-` purpose, no golden.
 */
export function buildDirectoryViewPreimage(entries: readonly NodeIdentityDirectoryEntry[]): string {
  const view = canonicalizeView(entries).map((entry) => ({
    signing_key_id: entry.signing_key_id,
    public_key: entry.public_key,
    seq_canonical_epoch: entry.seq_canonical_epoch,
  }));
  return `node-identity-directory-view\n${JSON.stringify({ entry_count: view.length, entries: view })}`;
}

/** The single published head: one digest over the whole directory view. */
export function computeDirectoryViewDigest(entries: readonly NodeIdentityDirectoryEntry[]): string {
  return createHash("sha256").update(buildDirectoryViewPreimage(entries), "utf8").digest("hex");
}

/**
 * Non-equivocation: the head digest a node published to one tenant must equal the one it published to
 * every other. Any difference is EQUIVOCATION — the node served divergent directory views and at most
 * one of them can be true.
 */
export function compareDirectoryViews(headDigestA: string, headDigestB: string): DirectoryViewComparison {
  return headDigestA === headDigestB ? "CONSISTENT" : "EQUIVOCATION";
}

/**
 * Fold every head digest a node published this epoch into one verdict. Tenants cannot see each other's
 * streams (NC2), so this is the check an auditor — or the tenants comparing out-of-band — actually runs.
 */
export function detectDirectoryEquivocation(
  publishedHeadDigests: readonly string[],
): DirectoryViewComparison {
  return new Set(publishedHeadDigests).size <= 1 ? "CONSISTENT" : "EQUIVOCATION";
}
