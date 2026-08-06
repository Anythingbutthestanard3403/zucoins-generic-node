// the named concern — byte freeze for the frozen adversarial suite that attacks the
// the named concern envelope parser and the named concern transaction verifier. Every fixture under
// ./attack-vectors/ is a single documented mutation of the frozen A.8.1 golden
// (./gen/target.settled.json); this test reconstructs each one byte-exact from that golden
// plus its one mutation, pins its SHA-256 to the manifest, and proves the two re-signed
// vectors carry genuine Ed25519 signatures over their mutated preimages (so the defect each
// isolates is the only thing wrong with them). Runtime rejection of these vectors is the
// node-core driving test's job (packages/node-core/src/verifier/attack-vectors.test.ts);
// this file never imports node-core and so keeps the dependency direction one-way.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
const sha256 = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");
const keyFromSeed = (byte: number) =>
  createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, byte),
    ]),
    type: "pkcs8",
    format: "der",
  });
const signText = (text: string, seedByte: number): string =>
  paddedBase64Url(sign(null, Buffer.from(text, "utf8"), keyFromSeed(seedByte)));
const ed25519Ok = (
  preimageText: string,
  privateKey: ReturnType<typeof keyFromSeed>,
  signatureText: string,
): boolean =>
  verify(
    null,
    Buffer.from(preimageText, "utf8"),
    createPublicKey(privateKey),
    Buffer.from(signatureText, "base64url"),
  );

const seed02 = keyFromSeed(0x02);
const seed03 = keyFromSeed(0x03);
const seed02Public = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const seed05Public = "bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E=";

const ATTACK_DIR = new URL("./attack-vectors/", import.meta.url);
const readAttack = (file: string): Buffer => readFileSync(new URL(file, ATTACK_DIR));
const readAttackText = (file: string): string => readAttack(file).toString("utf8");

const GOLDEN_SETTLED_TEXT = readFileSync(
  fileURLToPath(new URL("./gen/target.settled.json", import.meta.url)),
  "utf8",
);
const goldenSettled = JSON.parse(GOLDEN_SETTLED_TEXT) as {
  inner: Record<string, unknown>;
  step_1_signature: string;
  step_2_signature: string;
};
const goldenInner = goldenSettled.inner;

const envelopeOf = (dataLiteral: string): string =>
  `{"status":true,"code":"success","message":"","data":${dataLiteral}}`;
const HEAD_ENVELOPE_TEXT = envelopeOf(`[${GOLDEN_SETTLED_TEXT}]`);
const settledWith = (
  mutatedInner: Record<string, unknown>,
  step1: string = goldenSettled.step_1_signature,
  step2: string = goldenSettled.step_2_signature,
): string => JSON.stringify({ inner: mutatedInner, step_1_signature: step1, step_2_signature: step2 });

// The two re-signed constructions, rebuilt from the same seed primitives the generator used
// so the committed bytes and the signature checks below share one source of truth.
const prettyInnerText = JSON.stringify(goldenInner, null, 1);
const wsStep1 = signText(prettyInnerText, 0x02);
const wsStep2 = signText(JSON.stringify({ inner: goldenInner, step_1_signature: wsStep1 }), 0x03);
const selfInner = { ...goldenInner, step_2_key_public__base64urlsafe: seed02Public };
const selfStep1 = signText(JSON.stringify(selfInner), 0x02);
const selfStep2 = signText(JSON.stringify({ inner: selfInner, step_1_signature: selfStep1 }), 0x02);

// Each entry rebuilds exactly one committed fixture from the golden plus its single documented
// mutation. A hand-fabricated or doubly-mutated fixture cannot match.
const RECONSTRUCTIONS: Readonly<Record<string, () => Buffer>> = {
  "invalid-utf8": () => {
    const bytes = Buffer.from(HEAD_ENVELOPE_TEXT, "utf8");
    bytes[60] = 0xff;
    return bytes;
  },
  "duplicate-entries": () => Buffer.from(envelopeOf(`[${GOLDEN_SETTLED_TEXT},${GOLDEN_SETTLED_TEXT}]`), "utf8"),
  "wrong-action-wrapper": () =>
    Buffer.from(`{"status":true,"code":"success","message":"","result":[${GOLDEN_SETTLED_TEXT}]}`, "utf8"),
  "wrong-action-data": () =>
    Buffer.from(`{"status":true,"code":"success","message":"","data":{"available_balance":"10"}}`, "utf8"),
  "partial-entry-missing-step-2": () =>
    Buffer.from(
      envelopeOf(`[${JSON.stringify({ inner: goldenInner, step_1_signature: goldenSettled.step_1_signature })}]`),
      "utf8",
    ),
  "partial-entry-empty-step-2": () =>
    Buffer.from(
      envelopeOf(
        `[${JSON.stringify({
          inner: goldenInner,
          step_1_signature: goldenSettled.step_1_signature,
          step_2_signature: "",
        })}]`,
      ),
      "utf8",
    ),
  "unknown-inner-field": () => Buffer.from(settledWith({ ...goldenInner, extra_field: "x" }), "utf8"),
  "key-reorder": () => {
    const { type, ...innerRest } = goldenInner;
    return Buffer.from(settledWith({ ...innerRest, type }), "utf8");
  },
  "whitespace-preimage": () =>
    Buffer.from(
      `{"inner":${prettyInnerText},"step_1_signature":${JSON.stringify(wsStep1)},"step_2_signature":${JSON.stringify(wsStep2)}}`,
      "utf8",
    ),
  "numeric-amount": () => Buffer.from(settledWith({ ...goldenInner, step_1_state: { amount: 7.75 } }), "utf8"),
  "unpadded-key": () =>
    Buffer.from(settledWith({ ...goldenInner, step_1_key_public__base64urlsafe: seed02Public.slice(0, -1) }), "utf8"),
  "malformed-key": () =>
    Buffer.from(
      settledWith({
        ...goldenInner,
        step_1_key_public__base64urlsafe: seed02Public.replace(/-/g, "+").replace(/_/g, "/"),
      }),
      "utf8",
    ),
  "mutated-step-1-signature": () =>
    Buffer.from(settledWith(goldenInner, `x${goldenSettled.step_1_signature.slice(1)}`), "utf8"),
  "mutated-step-2-signature": () =>
    Buffer.from(
      settledWith(goldenInner, goldenSettled.step_1_signature, `v${goldenSettled.step_2_signature.slice(1)}`),
      "utf8",
    ),
  "wrong-signer-key": () =>
    Buffer.from(settledWith({ ...goldenInner, step_1_key_public__base64urlsafe: seed05Public }), "utf8"),
  "self-transfer": () => Buffer.from(settledWith(selfInner, selfStep1, selfStep2), "utf8"),
  "absent-wallet": () => Buffer.from(GOLDEN_SETTLED_TEXT, "utf8"),
};

const FROZEN_VECTOR_NAMES = Object.keys(RECONSTRUCTIONS);

interface AttackVectorEntry {
  readonly name: string;
  readonly file: string;
  readonly stage: "envelope" | "verifier";
  readonly checklist_item: string;
  readonly defect: string;
  readonly mutation: string;
  readonly expected: Record<string, unknown>;
  readonly sha256: string;
  readonly reordered_key_sequence?: readonly string[];
  readonly step_1_preimage_sha256?: string;
}
interface AttackManifest {
  readonly schema_version: number;
  readonly baseline_settled_sha256: string;
  readonly role_rejection_detail: string;
  readonly public_keys: Readonly<Record<string, string>>;
  readonly vectors: readonly AttackVectorEntry[];
}

const manifest = JSON.parse(readAttackText("manifest.json")) as AttackManifest;
const vectorByName = new Map(manifest.vectors.map((vector) => [vector.name, vector]));

describe("the named concern attack-vector fixtures are committed static adversarial bytes", () => {
  it("freezes the manifest vector name set as a closed set", () => {
    assertClosedSet(
      manifest.vectors.map((vector) => vector.name),
      FROZEN_VECTOR_NAMES,
    );
    expect(manifest.schema_version).toBe(1);
    expect(manifest.baseline_settled_sha256).toBe(sha256(Buffer.from(GOLDEN_SETTLED_TEXT, "utf8")));
  });

  it("has no trailing LF in the manifest", () => {
    expect(readAttackText("manifest.json").endsWith("\n")).toBe(false);
  });

  it.each(manifest.vectors)(
    "reconstructs $name byte-exact from the golden plus its single mutation and pins its digest",
    (vector) => {
      const reconstruct = RECONSTRUCTIONS[vector.name];
      if (!reconstruct) throw new Error(`no reconstruction for attack vector ${vector.name}`);
      const rebuilt = reconstruct();
      const committed = readAttack(vector.file);

      expect(committed.equals(rebuilt)).toBe(true);
      expect(committed.toString("utf8").endsWith("\n")).toBe(false);
      expect(sha256(committed)).toBe(vector.sha256);
    },
  );

  it("isolates the key-reorder defect to the rotated inner insertion sequence", () => {
    const vector = vectorByName.get("key-reorder");
    if (!vector?.reordered_key_sequence) throw new Error("key-reorder sequence pin missing");
    const committed = JSON.parse(readAttackText(vector.file)) as { inner: Record<string, unknown> };
    assertFieldOrder(Object.keys(committed.inner), [...vector.reordered_key_sequence]);
    // Same field set as the golden — only the insertion sequence moved.
    assertClosedSet(Object.keys(committed.inner), Object.keys(goldenInner));
    expect(Object.keys(committed.inner)[0]).not.toBe("type");
    expect(Object.keys(committed.inner).at(-1)).toBe("type");
  });

  it("proves the invalid-utf8 bytes are undecodable under strict UTF-8", () => {
    const vector = vectorByName.get("invalid-utf8");
    if (!vector) throw new Error("invalid-utf8 vector missing");
    const committed = readAttack(vector.file);
    expectRejects(
      () => committed,
      (bytes) => new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes),
    );
    // One byte away from a decodable envelope: flipping the corrupt byte back restores it.
    const healed = Buffer.from(committed);
    healed[60] = 0x22;
    expect(() => new TextDecoder("utf-8", { fatal: true }).decode(healed)).not.toThrow();
  });

  it("verifies the whitespace-preimage re-signing is genuine over the whitespace bytes", () => {
    const vector = vectorByName.get("whitespace-preimage");
    if (!vector?.step_1_preimage_sha256) throw new Error("whitespace-preimage pin missing");
    const entry = JSON.parse(readAttackText(vector.file)) as {
      inner: Record<string, unknown>;
      step_1_signature: string;
      step_2_signature: string;
    };
    const prettyPreimage = JSON.stringify(entry.inner, null, 1);
    expect(sha256(Buffer.from(prettyPreimage, "utf8"))).toBe(vector.step_1_preimage_sha256);
    expect(ed25519Ok(prettyPreimage, seed02, entry.step_1_signature)).toBe(true);
    const step2Preimage = JSON.stringify({ inner: entry.inner, step_1_signature: entry.step_1_signature });
    expect(ed25519Ok(step2Preimage, seed03, entry.step_2_signature)).toBe(true);
  });

  it("verifies the self-transfer re-signing is genuine under the single duplicated key", () => {
    const vector = vectorByName.get("self-transfer");
    if (!vector) throw new Error("self-transfer vector missing");
    const entry = JSON.parse(readAttackText(vector.file)) as {
      inner: { step_1_key_public__base64urlsafe: string; step_2_key_public__base64urlsafe: string };
      step_1_signature: string;
      step_2_signature: string;
    };
    expect(entry.inner.step_1_key_public__base64urlsafe).toBe(seed02Public);
    expect(entry.inner.step_2_key_public__base64urlsafe).toBe(seed02Public);
    const step1Preimage = JSON.stringify(entry.inner);
    expect(ed25519Ok(step1Preimage, seed02, entry.step_1_signature)).toBe(true);
    const step2Preimage = JSON.stringify({ inner: entry.inner, step_1_signature: entry.step_1_signature });
    expect(ed25519Ok(step2Preimage, seed02, entry.step_2_signature)).toBe(true);
  });
});
