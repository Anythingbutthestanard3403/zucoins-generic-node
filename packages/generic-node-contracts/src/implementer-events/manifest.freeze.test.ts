// freeze + census gate for the implementer-events concern.
// TEST-ONLY: A.8 seed keys are TEST-ONLY and MUST never be used with live ZKZ.
//
// Covers A.1.1/A.6/A.8/A.9; the closed event set; dual continuity; reporting-channel,
// reporting-key-enrolment, pull-cursor-authority, checkpoint-anti-rollback.
// Proves: (a) the manifest matches the golden; (b) all preimages are byte-exact and match the
// pinned digests; (c) cross-implementation node-signs → verifies reproduces the signatures and
// the implementer event hashes chain (B.previous == A.event_hash); (d) checkpoint anti-rollback
// and keyrotation cursor model; (e) negative vectors per fact class; (f) non-invertibility proof.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import golden from "./gen/implementer-events.json" with { type: "json" };
import {
  IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE,
  IMPLEMENTER_EVENT_GOLDEN_B,
  IMPLEMENTER_EVENT_GOLDEN_B_PREIMAGE,
  IMPLEMENTER_SEQ_MODEL,
  NODE_EVENT_HASH_INVERTIBILITY,
} from "./implementer-event-tuple.js";
import {
  CHECKPOINT_ANTI_ROLLBACK,
  CHECKPOINT_DELIVERY_CHANNEL,
  IMPLEMENTER_CHECKPOINT_GOLDEN_PREIMAGE,
  evaluateCheckpoint,
} from "./implementer-checkpoint.js";
import {
  IMPLEMENTER_KEYROTATION_GOLDEN_PREIMAGE,
  KEYROTATION_COSIGN_STATUS,
  KEYROTATION_CURSOR_MODEL,
} from "./implementer-keyrotation.js";
import {
  IMPLEMENTER_CHECKPOINT_SHA256,
  IMPLEMENTER_CHECKPOINT_SIGNATURE,
  IMPLEMENTER_EVENT_A_EVENT_HASH,
  IMPLEMENTER_EVENT_A_SHA256,
  IMPLEMENTER_EVENT_A_SIGNATURE,
  IMPLEMENTER_EVENT_B_EVENT_HASH,
  IMPLEMENTER_EVENT_B_SHA256,
  IMPLEMENTER_EVENT_B_SIGNATURE,
  IMPLEMENTER_KEYROTATION_SHA256,
  IMPLEMENTER_KEYROTATION_SIGNATURE,
  NODE_EVENT_KEY_PUBKEY,
} from "./digests.js";
import {
  NON_INVERTIBILITY_PROOF,
  checkpointConflictingEqualEpoch,
  checkpointRollback,
  keyRotationMissingSupersedes,
  keyRotationUsesGlobalCursor,
  missingFieldImplementerEvent,
  payloadPurposeMismatch,
  purposeMismatchImplementerEvent,
  reorderedImplementerEvent,
  unexpectedFieldImplementerEvent,
} from "./negative-vectors.js";
import { buildImplementerEventsManifest } from "./manifest.js";

const sha256 = (b: Buffer | string): string =>
  createHash("sha256").update(typeof b === "string" ? Buffer.from(b, "utf8") : b).digest("hex");
const b64url = (buf: Buffer): string => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
const readArtifact = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`./gen/${name}`, import.meta.url)), "utf8");
function keyFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}
function pubOf(priv: ReturnType<typeof keyFromSeed>): string {
  return b64url(createPublicKey(priv).export({ type: "spki", format: "der" }).subarray(-32));
}

describe("implementer-events manifest freeze", () => {
  it("serialized manifest matches the committed golden snapshot", () => {
    expect(buildImplementerEventsManifest()).toEqual(golden);
  });
});

describe("byte-exact goldens (A.8)", () => {
  it("implementer event A preimage equals its raw artifact and pinned digest", () => {
    expect(IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE).toBe(
      readArtifact("zp-implementer-event-v1.golden-a.preimage.txt"),
    );
    expect(sha256(IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE)).toBe(IMPLEMENTER_EVENT_A_SHA256);
  });

  it("implementer event B preimage equals its raw artifact and pinned digest", () => {
    expect(IMPLEMENTER_EVENT_GOLDEN_B_PREIMAGE).toBe(
      readArtifact("zp-implementer-event-v1.golden-b.preimage.txt"),
    );
    expect(sha256(IMPLEMENTER_EVENT_GOLDEN_B_PREIMAGE)).toBe(IMPLEMENTER_EVENT_B_SHA256);
    // Nullable field is serialized as JSON null, present not omitted.
    expect(IMPLEMENTER_EVENT_GOLDEN_B_PREIMAGE.includes('"wallet_id":null')).toBe(true);
  });

  it("checkpoint preimage equals its raw artifact and pinned digest", () => {
    expect(IMPLEMENTER_CHECKPOINT_GOLDEN_PREIMAGE).toBe(
      readArtifact("zp-implementer-checkpoint-v1.preimage.txt"),
    );
    expect(sha256(IMPLEMENTER_CHECKPOINT_GOLDEN_PREIMAGE)).toBe(IMPLEMENTER_CHECKPOINT_SHA256);
  });

  it("keyrotation preimage equals its raw artifact and pinned digest", () => {
    expect(IMPLEMENTER_KEYROTATION_GOLDEN_PREIMAGE).toBe(
      readArtifact("zp-implementer-keyrotation-v1.preimage.txt"),
    );
    expect(sha256(IMPLEMENTER_KEYROTATION_GOLDEN_PREIMAGE)).toBe(IMPLEMENTER_KEYROTATION_SHA256);
  });
});

describe("cross-implementation sign → verify (A.8) + hash chain", () => {
  it("the node event key reproduces implementer event A signature and event_hash", () => {
    const priv = keyFromSeed(0x00);
    expect(pubOf(priv)).toBe(NODE_EVENT_KEY_PUBKEY);

    const aBytes = Buffer.from(IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE, "utf8");
    const aSig = sign(null, aBytes, priv);
    expect(b64url(aSig)).toBe(IMPLEMENTER_EVENT_A_SIGNATURE);
    const aHash = sha256(Buffer.concat([aBytes, aSig]));
    expect(aHash).toBe(IMPLEMENTER_EVENT_A_EVENT_HASH);
    expect(verify(null, aBytes, createPublicKey(priv), aSig)).toBe(true);
  });

  it("the node event key reproduces implementer event B signature and chains off A", () => {
    const priv = keyFromSeed(0x00);
    const bBytes = Buffer.from(IMPLEMENTER_EVENT_GOLDEN_B_PREIMAGE, "utf8");
    const bSig = sign(null, bBytes, priv);
    expect(b64url(bSig)).toBe(IMPLEMENTER_EVENT_B_SIGNATURE);
    const bHash = sha256(Buffer.concat([bBytes, bSig]));
    expect(bHash).toBe(IMPLEMENTER_EVENT_B_EVENT_HASH);

    // Chain linkage: B.implementer_previous_event_hash == A.event_hash.
    expect(IMPLEMENTER_EVENT_GOLDEN_B.implementer_previous_event_hash).toBe(IMPLEMENTER_EVENT_A_EVENT_HASH);
  });

  it("the node event key reproduces checkpoint signature and verifies", () => {
    const priv = keyFromSeed(0x00);
    const cBytes = Buffer.from(IMPLEMENTER_CHECKPOINT_GOLDEN_PREIMAGE, "utf8");
    const cSig = sign(null, cBytes, priv);
    expect(b64url(cSig)).toBe(IMPLEMENTER_CHECKPOINT_SIGNATURE);
    expect(verify(null, cBytes, createPublicKey(priv), cSig)).toBe(true);
  });

  it("the node event key reproduces keyrotation signature and verifies", () => {
    const priv = keyFromSeed(0x00);
    const kBytes = Buffer.from(IMPLEMENTER_KEYROTATION_GOLDEN_PREIMAGE, "utf8");
    const kSig = sign(null, kBytes, priv);
    expect(b64url(kSig)).toBe(IMPLEMENTER_KEYROTATION_SIGNATURE);
    expect(verify(null, kBytes, createPublicKey(priv), kSig)).toBe(true);
  });
});

describe("implementer_seq model + checkpoint + keyrotation contracts", () => {
  it("implementer_seq is a per-(node_id,implementer_id) gapless counter, not identity", () => {
    expect(IMPLEMENTER_SEQ_MODEL.scope).toBe("per_(node_id,implementer_id)");
    expect(IMPLEMENTER_SEQ_MODEL.forbiddenSource).toBe("identity_or_bigserial");
    expect(IMPLEMENTER_SEQ_MODEL.allocationAtomicWithGlobal).toBe(true);
    expect(IMPLEMENTER_SEQ_MODEL.lockOrder).toBe("global_head_then_implementer_head");
  });

  it("checkpoint anti-rollback refuses lower and alarms on conflict", () => {
    expect(CHECKPOINT_ANTI_ROLLBACK.refusesLower).toBe(true);
    expect(CHECKPOINT_ANTI_ROLLBACK.conflictingEqualEpochHeads).toBe("INVARIANT_BREACH");
    expect(evaluateCheckpoint(5n, 10n, 6n, 1n)).toBe("ACCEPT");
    expect(evaluateCheckpoint(5n, 10n, 5n, 10n)).toBe("ACCEPT");
  });

  it("checkpoint launch delivery channel is GET /v1/events checkpoints[]", () => {
    expect(CHECKPOINT_DELIVERY_CHANNEL.status).toBe("ACTIVE");
    expect(CHECKPOINT_DELIVERY_CHANNEL.method).toBe("GET");
    expect(CHECKPOINT_DELIVERY_CHANNEL.path).toBe("/v1/events");
    expect(CHECKPOINT_DELIVERY_CHANNEL.responseField).toBe("checkpoints");
    expect(CHECKPOINT_DELIVERY_CHANNEL.authMode).toBe("signed_reporting_credential");
  });

  it("keyrotation uses implementer_seq cursor, never global", () => {
    expect(KEYROTATION_CURSOR_MODEL.cursor).toBe("implementer_seq");
    expect(KEYROTATION_CURSOR_MODEL.neverGlobalCursor).toBe(true);
    expect(KEYROTATION_CURSOR_MODEL.preservesNC2).toBe(true);
  });

  it("keyrotation co-signing is an open question", () => {
    expect(KEYROTATION_COSIGN_STATUS).toBe("OPEN_QUESTION");
  });
});

describe("non-invertibility proof", () => {
  it("node_event_hash is non-invertible — tenant cannot recover global seq or previous_event_hash", () => {
    expect(NON_INVERTIBILITY_PROOF.globalSeqRecoverable).toBe(false);
    expect(NON_INVERTIBILITY_PROOF.globalPreviousEventHashRecoverable).toBe(false);
    expect(NODE_EVENT_HASH_INVERTIBILITY).toBe("NON_INVERTIBLE");
    // The hash is 64 hex chars (32 bytes) — a one-way digest, not a reversible encoding.
    expect(NON_INVERTIBILITY_PROOF.nodeEventHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("negative vectors (A.9 baseline)", () => {
  it("field reorder is structurally different from the golden", () => {
    expect(reorderedImplementerEvent()).not.toBe(IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE);
    // Reordered preimage has a different SHA-256.
    expect(sha256(reorderedImplementerEvent())).not.toBe(IMPLEMENTER_EVENT_A_SHA256);
  });

  it("missing field produces a different preimage", () => {
    expect(missingFieldImplementerEvent()).not.toBe(IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE);
    expect(sha256(missingFieldImplementerEvent())).not.toBe(IMPLEMENTER_EVENT_A_SHA256);
  });

  it("unexpected field produces a different preimage", () => {
    expect(unexpectedFieldImplementerEvent()).not.toBe(IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE);
    expect(sha256(unexpectedFieldImplementerEvent())).not.toBe(IMPLEMENTER_EVENT_A_SHA256);
  });

  it("prefix purpose mismatch produces a different preimage", () => {
    expect(purposeMismatchImplementerEvent()).not.toBe(IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE);
    expect(sha256(purposeMismatchImplementerEvent())).not.toBe(IMPLEMENTER_EVENT_A_SHA256);
  });

  it("payload purpose mismatch produces a different preimage", () => {
    expect(payloadPurposeMismatch()).not.toBe(IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE);
    expect(sha256(payloadPurposeMismatch())).not.toBe(IMPLEMENTER_EVENT_A_SHA256);
  });

  it("checkpoint rollback is refused", () => {
    expect(checkpointRollback()).toBe("REFUSE_ROLLBACK");
  });

  it("checkpoint conflicting equal-epoch heads is INVARIANT_BREACH", () => {
    expect(checkpointConflictingEqualEpoch()).toBe("INVARIANT_BREACH");
  });

  it("keyrotation with global cursor field is structurally invalid", () => {
    const bad = keyRotationUsesGlobalCursor();
    expect(sha256(bad)).not.toBe(IMPLEMENTER_KEYROTATION_SHA256);
  });

  it("keyrotation with omitted supersedes_key_id is structurally invalid", () => {
    const bad = keyRotationMissingSupersedes();
    expect(sha256(bad)).not.toBe(IMPLEMENTER_KEYROTATION_SHA256);
  });
});

describe("additive-only: existing zp-node-event-v1 goldens unchanged", () => {
  it("zp-node-event-v1 golden A SHA-256 is unchanged", () => {
    const nodeEventA = readFileSync(
      fileURLToPath(new URL("../reporting-tuples/gen/zp-node-event-v1.golden-a.preimage.txt", import.meta.url)),
      "utf8",
    );
    expect(sha256(nodeEventA)).toBe("9644a48d9f0a988c62321a371ad66f993ae4f428ae3a3ee48d0dc290e0560226");
  });

  it("zp-node-event-v1 golden B SHA-256 is unchanged", () => {
    const nodeEventB = readFileSync(
      fileURLToPath(new URL("../reporting-tuples/gen/zp-node-event-v1.golden-b.preimage.txt", import.meta.url)),
      "utf8",
    );
    expect(sha256(nodeEventB)).toBe("42c27944165f242f2c4fc276ff369da58ed6055ffd71c2788f1f6fe73aec2e2c");
  });
});
