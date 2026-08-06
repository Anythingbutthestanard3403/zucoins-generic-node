// retained-body index re-verify-on-read + role-aware resolver tests.
// Drift, signature flip, wrong-role lookup, content-not-digest authority, collision.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import type { SettledSplitChainTransaction } from "../protocol/inner.js";
import {
  InMemoryRetainedBodyIndex,
  retainedBodiesExactEqual,
  verifyRetainedBodyOnRead,
  type RetainedBodyRecord,
} from "./body-index.js";
import {
  buildGenesisWalletHeadFingerprint,
  buildWalletHeadFingerprintFromProjection,
} from "./fingerprint.js";
import { projectRoleState } from "./projection.js";

const GEN_DIR = new URL(
  "../../../generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};

const RECEIVER = MANIFEST.public_keys.seed_03;
const SENDER = MANIFEST.public_keys.seed_02;

function settled(name: string): SettledSplitChainTransaction {
  return JSON.parse(fixtureText(name)) as SettledSplitChainTransaction;
}

function headRecordFor(
  walletKey: string,
  role: "sender" | "receiver",
  ids: { observation_id: string; wallet_seq: number } = {
    observation_id: "obs-default",
    wallet_seq: 1,
  },
  bodyName = "target.settled.json",
): RetainedBodyRecord {
  const bodyText = fixtureText(bodyName);
  const tx = settled(bodyName);
  const projected = projectRoleState(tx, walletKey);
  if (!projected.ok) throw new Error(projected.detail);
  if (projected.projection.role !== role) {
    throw new Error(`expected ${role}, got ${projected.projection.role}`);
  }
  const fp = buildWalletHeadFingerprintFromProjection(projected.projection, walletKey);
  if (!fp.ok) throw new Error(fp.detail);
  return {
    observation_id: ids.observation_id,
    wallet_public_key: walletKey,
    wallet_seq: ids.wallet_seq,
    wallet_role: role,
    parse_result: "VERIFIED_HEAD",
    completed_transaction_text: bodyText,
    completed_transaction_sha256: sha256Hex(bodyText),
    inner_preimage_text: projected.projection.inner_preimage_text,
    step_1_signature: projected.projection.step_1_signature,
    step_2_signature: projected.projection.step_2_signature,
    s_signature: projected.projection.S,
    p_signature: projected.projection.P,
    b_amount: projected.projection.B,
    semantic_fingerprint: fp.fingerprint.sha256,
  };
}

describe("verifyRetainedBodyOnRead — happy path", () => {
  it("re-verifies a receiver head and returns the recomputed fingerprint", () => {
    const record = headRecordFor(RECEIVER, "receiver");
    const result = verifyRetainedBodyOnRead(record);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.role).toBe("receiver");
    expect(result.semanticFingerprint).toBe(record.semantic_fingerprint);
    expect(result.completedTransactionSha256).toBe(record.completed_transaction_sha256);
  });

  it("re-verifies a sender head", () => {
    const record = headRecordFor(SENDER, "sender");
    const result = verifyRetainedBodyOnRead(record);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.role).toBe("sender");
  });
});

describe("verifyRetainedBodyOnRead — drift / corruption", () => {
  it("fails closed when completed_transaction_text is corrupted after capture", () => {
    const record = headRecordFor(RECEIVER, "receiver");
    const corrupted: RetainedBodyRecord = {
      ...record,
      completed_transaction_text: record.completed_transaction_text!.replace(
        "2.25",
        "2.26",
      ),
    };
    const result = verifyRetainedBodyOnRead(corrupted);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("BODY_HASH_DRIFT");
  });

  it("fails closed when a stored signature byte is flipped (live Ed25519 re-verify)", () => {
    const record = headRecordFor(RECEIVER, "receiver");
    const sig = record.step_1_signature!;
    const flipped = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    const bodyObj = JSON.parse(record.completed_transaction_text!) as {
      inner: unknown;
      step_1_signature: string;
      step_2_signature: string;
    };
    bodyObj.step_1_signature = flipped;
    const patchedBody = JSON.stringify(bodyObj);
    const corrupted: RetainedBodyRecord = {
      ...record,
      step_1_signature: flipped,
      completed_transaction_text: patchedBody,
      completed_transaction_sha256: sha256Hex(patchedBody),
    };
    const result = verifyRetainedBodyOnRead(corrupted);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("SIGNATURE_INVALID");
  });

  it("fails closed when step_2_signature byte is flipped (live Ed25519 re-verify)", () => {
    const record = headRecordFor(RECEIVER, "receiver");
    const sig = record.step_2_signature!;
    const flipped = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    const bodyObj = JSON.parse(record.completed_transaction_text!) as {
      inner: unknown;
      step_1_signature: string;
      step_2_signature: string;
    };
    bodyObj.step_2_signature = flipped;
    const patchedBody = JSON.stringify(bodyObj);
    const corrupted: RetainedBodyRecord = {
      ...record,
      step_2_signature: flipped,
      completed_transaction_text: patchedBody,
      completed_transaction_sha256: sha256Hex(patchedBody),
    };
    const result = verifyRetainedBodyOnRead(corrupted);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("SIGNATURE_INVALID");
  });

  it("fails closed when semantic_fingerprint is rewritten without body change", () => {
    const record = headRecordFor(RECEIVER, "receiver");
    const corrupted: RetainedBodyRecord = {
      ...record,
      semantic_fingerprint: "0".repeat(64),
    };
    const result = verifyRetainedBodyOnRead(corrupted);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("FINGERPRINT_DRIFT");
  });
});

describe("verifyRetainedBodyOnRead — wrong-role lookup", () => {
  it("rejects expectedRole=sender against a receiver record", () => {
    const record = headRecordFor(RECEIVER, "receiver");
    const result = verifyRetainedBodyOnRead(record, { expectedRole: "sender" });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("WRONG_ROLE_LOOKUP");
  });

  it("accepts expectedRole matching the stored role", () => {
    const record = headRecordFor(RECEIVER, "receiver");
    const result = verifyRetainedBodyOnRead(record, { expectedRole: "receiver" });
    expect(result.ok).toBe(true);
  });

  it("rejects stored role that disagrees with re-derived projection", () => {
    const record = headRecordFor(RECEIVER, "receiver");
    const lied: RetainedBodyRecord = { ...record, wallet_role: "sender" };
    const result = verifyRetainedBodyOnRead(lied);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("ROLE_MISMATCH");
  });
});

describe("digest collision / exact content authority", () => {
  it("two different bodies are never equal by content even if digests were trusted alone", () => {
    const a = fixtureText("target.settled.json");
    const b = fixtureText("predecessor.settled.json");
    expect(sha256Hex(a)).not.toBe(sha256Hex(b));
    expect(retainedBodiesExactEqual(a, b)).toBe(false);
    expect(retainedBodiesExactEqual(a, a)).toBe(true);
  });

  it("index distinguishes two distinct bodies forced under a colliding digest by content", () => {
    const a = headRecordFor(
      RECEIVER,
      "receiver",
      { observation_id: "obs-a", wallet_seq: 1 },
      "target.settled.json",
    );
    const bBody = fixtureText("predecessor.settled.json");
    const b: RetainedBodyRecord = {
      ...a,
      observation_id: "obs-b",
      wallet_seq: 2,
      completed_transaction_text: bBody,
      completed_transaction_sha256: a.completed_transaction_sha256,
    };
    expect(
      retainedBodiesExactEqual(a.completed_transaction_text!, b.completed_transaction_text!),
    ).toBe(false);

    const index = new InMemoryRetainedBodyIndex();
    index.put(a);
    index.put(b);

    const collision = index.detectHashContentCollision(a.completed_transaction_sha256!);
    expect(collision.ok).toBe(false);
    if (collision.ok) return;
    expect(collision.reason).toBe("HASH_CONTENT_COLLISION");

    const resolved = index.resolveByObservationId("obs-a");
    expect(resolved.ok).toBe(false);
    if (resolved.ok) return;
    expect(resolved.reason).toBe("HASH_CONTENT_COLLISION");
  });
});

describe("InMemoryRetainedBodyIndex — role-aware resolver", () => {
  it("resolves by observation_id and returns body+signatures as one unit", () => {
    const record = headRecordFor(RECEIVER, "receiver", {
      observation_id: "obs-recv-1",
      wallet_seq: 7,
    });
    const index = new InMemoryRetainedBodyIndex();
    index.put(record);

    const result = index.resolveByObservationId("obs-recv-1");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.body.observation_id).toBe("obs-recv-1");
    expect(result.body.wallet_seq).toBe(7);
    expect(result.body.role).toBe("receiver");
    expect(result.body.completed_transaction_text).toBe(record.completed_transaction_text);
    expect(result.body.step_1_signature).toBe(record.step_1_signature);
    expect(result.body.step_2_signature).toBe(record.step_2_signature);
    expect(result.body.s_signature).toBe(record.s_signature);
    expect(result.body.p_signature).toBe(record.p_signature);
    expect(result.body.b_amount).toBe(record.b_amount);
    expect(result.body.inner_preimage_text).toBe(record.inner_preimage_text);
    expect(result.body.semantic_fingerprint).toBe(record.semantic_fingerprint);
  });

  it("resolves by (wallet_public_key, wallet_seq)", () => {
    const record = headRecordFor(SENDER, "sender", {
      observation_id: "obs-send-1",
      wallet_seq: 3,
    });
    const index = new InMemoryRetainedBodyIndex();
    index.put(record);

    const result = index.resolveByWalletSeq(SENDER, 3);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.body.role).toBe("sender");
    expect(result.body.observation_id).toBe("obs-send-1");
  });

  it("wrong-role lookup on resolve fails closed", () => {
    const record = headRecordFor(RECEIVER, "receiver", {
      observation_id: "obs-recv-2",
      wallet_seq: 2,
    });
    const index = new InMemoryRetainedBodyIndex();
    index.put(record);

    const result = index.resolveByWalletSeq(RECEIVER, 2, { expectedRole: "sender" });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("WRONG_ROLE_LOOKUP");
  });

  it("signature flip after put causes next resolve to fail closed (live crypto)", () => {
    const record = headRecordFor(RECEIVER, "receiver", {
      observation_id: "obs-drift",
      wallet_seq: 9,
    });
    const index = new InMemoryRetainedBodyIndex();
    index.put(record);

    const sig = record.step_1_signature!;
    const flipped = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    const bodyObj = JSON.parse(record.completed_transaction_text!) as {
      inner: unknown;
      step_1_signature: string;
      step_2_signature: string;
    };
    bodyObj.step_1_signature = flipped;
    const patchedBody = JSON.stringify(bodyObj);
    index.put({
      ...record,
      step_1_signature: flipped,
      completed_transaction_text: patchedBody,
      completed_transaction_sha256: sha256Hex(patchedBody),
    });

    const result = index.resolveByObservationId("obs-drift");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("SIGNATURE_INVALID");
  });

  it("NOT_FOUND for unknown observation_id", () => {
    const index = new InMemoryRetainedBodyIndex();
    const result = index.resolveByObservationId("missing");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("NOT_FOUND");
  });
});

describe("genesis on-read", () => {
  it("accepts a well-formed genesis record", () => {
    const fp = buildGenesisWalletHeadFingerprint(RECEIVER);
    expect(fp.ok).toBe(true);
    if (!fp.ok) return;
    const record: RetainedBodyRecord = {
      observation_id: "obs-gen-1",
      wallet_public_key: RECEIVER,
      wallet_seq: 1,
      wallet_role: "genesis",
      parse_result: "VERIFIED_GENESIS",
      completed_transaction_text: null,
      completed_transaction_sha256: null,
      inner_preimage_text: null,
      step_1_signature: null,
      step_2_signature: null,
      s_signature: "",
      p_signature: "",
      b_amount: "0",
      semantic_fingerprint: fp.fingerprint.sha256,
    };
    const result = verifyRetainedBodyOnRead(record);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.role).toBe("genesis");

    const index = new InMemoryRetainedBodyIndex();
    index.put(record);
    const resolved = index.resolveByObservationId("obs-gen-1");
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.body.role).toBe("genesis");
    expect(resolved.body.completed_transaction_text).toBeNull();
  });
});
