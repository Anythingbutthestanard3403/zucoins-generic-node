// The node-identity directory's non-equivocation property, proven not asserted.
// TEST-ONLY: A.8 seed keys are TEST-ONLY and MUST never be used with live ZKZ.
//
// Covers A.6; binding condition C3; instruction-origin identity; pull-cursor authority.
// Every case below is fail-first: it goes red if the property breaks. The two that matter most are
// "equal epoch, two keys => INVARIANT_BREACH" (silent rebind) and "two tenants, two views =>
// EQUIVOCATION" (cross-stream divergence, which per-tenant anti-rollback cannot see).
import { describe, expect, it } from "vitest";

import {
  CHECKPOINT_ANTI_ROLLBACK,
  IMPLEMENTER_CHECKPOINT_GOLDEN,
} from "./implementer-checkpoint.js";
import {
  NODE_IDENTITY_DIRECTORY_RULE,
  buildDirectoryViewPreimage,
  compareDirectoryViews,
  computeDirectoryViewDigest,
  detectDirectoryEquivocation,
  findEqualEpochConflict,
  resolveSeqCanonicalKey,
  validateCheckpointSigningKey,
  type NodeIdentityDirectoryEntry,
} from "./node-identity-directory.js";

// A.8 node identity/event key (seed 00) and the checkpoint golden's signing_key_id.
const NODE_EVENT_PUBKEY = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
const ROTATED_PUBKEY = "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw="; // seed 04
const KEY_ID_1 = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"; // the checkpoint golden's signing_key_id
const KEY_ID_2 = "ffffffff-ffff-4fff-8fff-ffffffffffff";

const entry = (
  signing_key_id: string,
  public_key: string,
  seq_canonical_epoch: string,
): NodeIdentityDirectoryEntry => ({ signing_key_id, public_key, seq_canonical_epoch });

const HONEST: readonly NodeIdentityDirectoryEntry[] = [
  entry(KEY_ID_1, NODE_EVENT_PUBKEY, "1"),
  entry(KEY_ID_2, ROTATED_PUBKEY, "4"),
];

describe("node-identity directory — seq-canonical key binding (C3)", () => {
  it("resolves the binding in force at an epoch, not the newest one", () => {
    const atOne = resolveSeqCanonicalKey(HONEST, "1");
    expect(atOne.outcome).toBe("RESOLVED");
    expect(atOne.outcome === "RESOLVED" && atOne.entry.public_key).toBe(NODE_EVENT_PUBKEY);

    // Epoch 3 predates the epoch-4 rotation, so the OLD key is still canonical there.
    const atThree = resolveSeqCanonicalKey(HONEST, "3");
    expect(atThree.outcome === "RESOLVED" && atThree.entry.public_key).toBe(NODE_EVENT_PUBKEY);

    const atFour = resolveSeqCanonicalKey(HONEST, "4");
    expect(atFour.outcome === "RESOLVED" && atFour.entry.public_key).toBe(ROTATED_PUBKEY);
  });

  it("sequences epochs numerically, not lexically (epoch 10 is after epoch 9)", () => {
    const wide = [entry(KEY_ID_1, NODE_EVENT_PUBKEY, "9"), entry(KEY_ID_2, ROTATED_PUBKEY, "10")];
    const atNine = resolveSeqCanonicalKey(wide, "9");
    expect(atNine.outcome === "RESOLVED" && atNine.entry.public_key).toBe(NODE_EVENT_PUBKEY);
    const atTen = resolveSeqCanonicalKey(wide, "10");
    expect(atTen.outcome === "RESOLVED" && atTen.entry.public_key).toBe(ROTATED_PUBKEY);
  });

  it("reports no canonical key before the first binding rather than inventing one", () => {
    expect(resolveSeqCanonicalKey(HONEST, "0").outcome).toBe("NO_CANONICAL_KEY");
    expect(resolveSeqCanonicalKey([], "1").outcome).toBe("NO_CANONICAL_KEY");
  });

  it("refuses a malformed directory row instead of throwing out of the checkpoint path", () => {
    const malformed = [entry(KEY_ID_1, NODE_EVENT_PUBKEY, "not-a-number")];
    expect(resolveSeqCanonicalKey(malformed, "1").outcome).toBe("MALFORMED_DIRECTORY");
    expect(resolveSeqCanonicalKey([entry(KEY_ID_1, "", "1")], "1").outcome).toBe("MALFORMED_DIRECTORY");
    expect(validateCheckpointSigningKey(malformed, IMPLEMENTER_CHECKPOINT_GOLDEN)).toBe("MALFORMED_DIRECTORY");
  });
});

describe("non-equivocation — equal-epoch conflict is INVARIANT_BREACH, never picked", () => {
  // Two different public keys both claiming to be canonical at epoch 1: a silent rebind.
  const CONFLICTED = [...HONEST, entry(KEY_ID_2, ROTATED_PUBKEY, "1")];

  it("detects the conflict and names the epoch", () => {
    expect(findEqualEpochConflict(CONFLICTED)).toBe("1");
    expect(findEqualEpochConflict(HONEST)).toBeUndefined();
  });

  it("resolves to INVARIANT_BREACH rather than choosing either key", () => {
    const resolution = resolveSeqCanonicalKey(CONFLICTED, "1");
    expect(resolution.outcome).toBe("INVARIANT_BREACH");
    expect(resolution.outcome === "INVARIANT_BREACH" && resolution.epoch).toBe("1");
    // The forbidden behaviour, stated as an assertion: no entry is handed back.
    expect(resolution).not.toHaveProperty("entry");
    expect(NODE_IDENTITY_DIRECTORY_RULE.resolvesConflictByPicking).toBe(false);
  });

  it("does not let a conflict at a LATER epoch pass a checkpoint at an earlier one", () => {
    // Directory is clean at epoch 1 but rebound at epoch 4. A scan bounded by the checkpoint's own
    // epoch would return ACCEPT here and the rebind would stay invisible.
    const laterConflict = [...HONEST, entry(KEY_ID_1, NODE_EVENT_PUBKEY, "4")];
    expect(findEqualEpochConflict(laterConflict)).toBe("4");
    expect(validateCheckpointSigningKey(laterConflict, { checkpoint_epoch: "1", signing_key_id: KEY_ID_1 })).toBe(
      "INVARIANT_BREACH",
    );
  });

  it("is sequence-independent — the conflict is a fact about content, not about row placement", () => {
    expect(findEqualEpochConflict([...CONFLICTED].reverse())).toBe("1");
    expect(resolveSeqCanonicalKey([...CONFLICTED].reverse(), "1").outcome).toBe("INVARIANT_BREACH");
  });
});

describe("non-equivocation — single published head across tenants", () => {
  it("digests the same bindings identically regardless of row sequence (no false positives)", () => {
    const shuffled = [...HONEST].reverse();
    expect(buildDirectoryViewPreimage(shuffled)).toBe(buildDirectoryViewPreimage(HONEST));
    expect(computeDirectoryViewDigest(shuffled)).toBe(computeDirectoryViewDigest(HONEST));
    expect(compareDirectoryViews(computeDirectoryViewDigest(shuffled), computeDirectoryViewDigest(HONEST))).toBe(
      "CONSISTENT",
    );
  });

  it("detects a node serving tenant A and tenant B divergent views", () => {
    // The node shows tenant B a directory in which the epoch-4 rotation never happened — the
    // cross-stream equivocation NC2 stream separation would otherwise hide.
    const viewForTenantA = HONEST;
    const viewForTenantB = [entry(KEY_ID_1, NODE_EVENT_PUBKEY, "1")];
    const digestA = computeDirectoryViewDigest(viewForTenantA);
    const digestB = computeDirectoryViewDigest(viewForTenantB);

    expect(digestB).not.toBe(digestA);
    expect(compareDirectoryViews(digestA, digestB)).toBe("EQUIVOCATION");
    expect(detectDirectoryEquivocation([digestA, digestB])).toBe("EQUIVOCATION");
  });

  it("detects a substituted public key even when epochs and key ids match exactly", () => {
    // The subtlest divergence: same shape, same ids, same epochs — only the bound key differs.
    const honestDigest = computeDirectoryViewDigest(HONEST);
    const rebound = [entry(KEY_ID_1, ROTATED_PUBKEY, "1"), entry(KEY_ID_2, ROTATED_PUBKEY, "4")];
    expect(compareDirectoryViews(honestDigest, computeDirectoryViewDigest(rebound))).toBe("EQUIVOCATION");
  });

  it("calls a single view, or many identical views, CONSISTENT", () => {
    const digest = computeDirectoryViewDigest(HONEST);
    expect(detectDirectoryEquivocation([])).toBe("CONSISTENT");
    expect(detectDirectoryEquivocation([digest])).toBe("CONSISTENT");
    expect(detectDirectoryEquivocation([digest, digest, digest])).toBe("CONSISTENT");
  });

  it("mints no new canonical wire purpose (the suite purpose census stays closed)", () => {
    expect(buildDirectoryViewPreimage(HONEST).startsWith("zp-")).toBe(false);
  });
});

describe("checkpoint validation path (C3) has the directory it names", () => {
  it("accepts the A.8 checkpoint golden signed by the seq-canonical key", () => {
    expect(IMPLEMENTER_CHECKPOINT_GOLDEN.signing_key_id).toBe(KEY_ID_1);
    expect(validateCheckpointSigningKey(HONEST, IMPLEMENTER_CHECKPOINT_GOLDEN)).toBe("ACCEPT");
  });

  it("rejects a checkpoint signed by a key that is real but not canonical at that epoch", () => {
    // KEY_ID_2 is canonical only from epoch 4; using it at epoch 1 is a rollback to a key that had
    // no authority then.
    expect(validateCheckpointSigningKey(HONEST, { checkpoint_epoch: "1", signing_key_id: KEY_ID_2 })).toBe(
      "REJECT_NOT_SEQ_CANONICAL",
    );
  });

  it("rejects a checkpoint signed by a key absent from the directory", () => {
    expect(
      validateCheckpointSigningKey(HONEST, {
        checkpoint_epoch: "1",
        signing_key_id: "00000000-0000-4000-8000-000000000000",
      }),
    ).toBe("REJECT_UNKNOWN_KEY");
  });

  it("discharges the claim implementer-checkpoint.ts makes about this directory", () => {
    // implementer-checkpoint.ts asserts it validates against the seq-canonical key via the
    // node-identity directory. This binds the two.
    expect(CHECKPOINT_ANTI_ROLLBACK.validatesSigningKeyAgainst).toBe(
      "seq_canonical_key_via_node_identity_directory",
    );
    expect(CHECKPOINT_ANTI_ROLLBACK.conflictingEqualEpochHeads).toBe("INVARIANT_BREACH");
    expect(NODE_IDENTITY_DIRECTORY_RULE.conflictingEqualEpochBinding).toBe("INVARIANT_BREACH");
    expect(NODE_IDENTITY_DIRECTORY_RULE.identityKeyDecision).toBe("instruction-origin-identity");
  });
});
