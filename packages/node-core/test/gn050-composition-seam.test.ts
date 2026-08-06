// parent composition seam.
//
// Proves the observation-service stack:
//   verified settled body → projectRoleState → buildWalletHeadFingerprintFromProjection
//   → verifyRetainedBodyOnRead
// under sender, receiver, genesis, absent-role, envelope-mutation, and foreign-B
// (non-canonical head balance) round-trip cases.
// Wrapper-only envelope changes keep the same semantic fingerprint while remaining
// distinct raw evidence (fingerprint sameness never suppresses raw append).
// Foreign-B policy (Byte-exact): observed balance text is bound verbatim through the
// single suite A.7 constructor on both write (verifySettledTransaction) and read
// (verifyRetainedBodyOnRead) — no dual preimage constructors.
import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  buildWalletHeadFingerprintFromProjection,
  fingerprintsSemanticallyEqual,
  projectRoleState,
  verifyRetainedBodyOnRead,
  type RetainedBodyRecord,
} from "../src/observation/index.js";
import { buildWalletHeadFingerprint } from "../src/protocol/suite/builders.js";
import { parseGatewayEnvelope, type ParsedSettledTransaction } from "../src/verifier/gateway-envelope.js";
import {
  buildWalletHeadFingerprintPreimage,
  computeWalletHeadFingerprint,
  verifySettledTransaction,
} from "../src/verifier/transaction-verify.js";

const GEN_DIR = new URL(
  "../../generic-node-contracts/src/receive-golden/gen/",
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
  target: {
    receiver_terminal_head: { fingerprint: string };
  };
};

const SENDER = MANIFEST.public_keys.seed_02;
const RECEIVER = MANIFEST.public_keys.seed_03;
const OTHER = MANIFEST.public_keys.seed_05;

function envelope(txJson: string, message = ""): Uint8Array {
  return new TextEncoder().encode(
    `{"status":true,"code":"success","message":${JSON.stringify(message)},"data":[${txJson}]}`,
  );
}

describe("composition seam — verified → project → fingerprint → re-read", () => {
  it("receiver path reproduces the A.8.2 fingerprint through the observation stack", () => {
    const txText = fixtureText("target.settled.json");
    const env = parseGatewayEnvelope(envelope(txText));
    expect(env.classification).toBe("HEAD");
    if (env.classification !== "HEAD") return;

    const verified = verifySettledTransaction(env.parsed, RECEIVER);
    expect(verified.verdict).toBe("VERIFIED");
    if (verified.verdict !== "VERIFIED") return;

    const projected = projectRoleState(verified.transaction, RECEIVER);
    expect(projected.ok).toBe(true);
    if (!projected.ok) return;

    const fp = buildWalletHeadFingerprintFromProjection(projected.projection, RECEIVER);
    expect(fp.ok).toBe(true);
    if (!fp.ok) return;
    expect(fp.fingerprint.sha256).toBe(MANIFEST.target.receiver_terminal_head.fingerprint);
    expect(fp.fingerprint.sha256).toBe(verified.semanticFingerprint);

    const record: RetainedBodyRecord = {
      observation_id: "obs-composition-receiver",
      wallet_public_key: RECEIVER,
      wallet_seq: 1,
      wallet_role: "receiver",
      parse_result: "VERIFIED_HEAD",
      completed_transaction_text: verified.completedTransactionText,
      completed_transaction_sha256: verified.completedTransactionSha256,
      inner_preimage_text: verified.innerPreimageText,
      step_1_signature: verified.transaction.step_1_signature,
      step_2_signature: verified.transaction.step_2_signature,
      s_signature: projected.projection.S,
      p_signature: projected.projection.P,
      b_amount: projected.projection.B,
      semantic_fingerprint: fp.fingerprint.sha256,
    };
    const reread = verifyRetainedBodyOnRead(record);
    expect(reread.ok).toBe(true);
    if (!reread.ok) return;
    expect(reread.semanticFingerprint).toBe(fp.fingerprint.sha256);
  });

  it("sender path projects and fingerprints without cross-wiring receiver material", () => {
    const txText = fixtureText("target.settled.json");
    const env = parseGatewayEnvelope(envelope(txText));
    if (env.classification !== "HEAD") throw new Error("expected HEAD");
    const verified = verifySettledTransaction(env.parsed, SENDER);
    expect(verified.verdict).toBe("VERIFIED");
    if (verified.verdict !== "VERIFIED") return;
    const projected = projectRoleState(verified.transaction, SENDER);
    expect(projected.ok).toBe(true);
    if (!projected.ok) return;
    expect(projected.projection.role).toBe("sender");
    const fp = buildWalletHeadFingerprintFromProjection(projected.projection, SENDER);
    expect(fp.ok).toBe(true);
    if (!fp.ok) return;
    expect(fp.fingerprint.sha256).not.toBe(MANIFEST.target.receiver_terminal_head.fingerprint);
  });

  it("absent-role queries reject WALLET_ROLE_INVALID at both verify and project stages", () => {
    const txText = fixtureText("target.settled.json");
    const env = parseGatewayEnvelope(envelope(txText));
    if (env.classification !== "HEAD") throw new Error("expected HEAD");
    const verified = verifySettledTransaction(env.parsed, OTHER);
    expect(verified.verdict).toBe("WALLET_ROLE_INVALID");
    // Even given the parsed body without the verify gate, projection rejects.
    const projected = projectRoleState(
      JSON.parse(txText) as Parameters<typeof projectRoleState>[0],
      OTHER,
    );
    expect(projected.ok).toBe(false);
    if (projected.ok) return;
    expect(projected.reason).toBe("wallet_role_invalid");
  });

  it("wrapper-only envelope mutation keeps the same fingerprint (distinct raw evidence)", () => {
    const txText = fixtureText("target.settled.json");
    const cleanBytes = envelope(txText, "");
    const wrappedBytes = envelope(txText, "perturbed wrapper text");
    // Raw digests differ — both would append as distinct evidence rows.
    expect(sha256Hex(new TextDecoder().decode(cleanBytes))).not.toBe(
      sha256Hex(new TextDecoder().decode(wrappedBytes)),
    );

    const cleanEnv = parseGatewayEnvelope(cleanBytes);
    const wrapEnv = parseGatewayEnvelope(wrappedBytes);
    expect(cleanEnv.classification).toBe("HEAD");
    expect(wrapEnv.classification).toBe("HEAD");
    if (cleanEnv.classification !== "HEAD" || wrapEnv.classification !== "HEAD") return;

    const cleanV = verifySettledTransaction(cleanEnv.parsed, RECEIVER);
    const wrapV = verifySettledTransaction(wrapEnv.parsed, RECEIVER);
    expect(cleanV.verdict).toBe("VERIFIED");
    expect(wrapV.verdict).toBe("VERIFIED");
    if (cleanV.verdict !== "VERIFIED" || wrapV.verdict !== "VERIFIED") return;

    const cleanP = projectRoleState(cleanV.transaction, RECEIVER);
    const wrapP = projectRoleState(wrapV.transaction, RECEIVER);
    expect(cleanP.ok && wrapP.ok).toBe(true);
    if (!cleanP.ok || !wrapP.ok) return;

    const cleanFp = buildWalletHeadFingerprintFromProjection(cleanP.projection, RECEIVER);
    const wrapFp = buildWalletHeadFingerprintFromProjection(wrapP.projection, RECEIVER);
    expect(cleanFp.ok && wrapFp.ok).toBe(true);
    if (!cleanFp.ok || !wrapFp.ok) return;

    expect(
      fingerprintsSemanticallyEqual(cleanFp.fingerprint.sha256, wrapFp.fingerprint.sha256),
    ).toBe(true);
    // Same semantic state, different raw envelopes — both remain distinct evidence.
    expect(cleanV.completedTransactionText).toBe(wrapV.completedTransactionText);
  });
});


// A.8 test-only seed derivation (public material per A.8) — builds a re-signed settled
// body whose role-relative B is a foreign non-canonical spelling under Byte-exact (byte-exact signing).
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function paddedBase64Url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

function seedKeyPair(seedByte: number): {
  publicKeyText: string;
  signText: (text: string) => string;
} {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.alloc(32, seedByte)]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKeyText = paddedBase64Url(spki.subarray(spki.length - 32));
  return {
    publicKeyText,
    signText: (text) => paddedBase64Url(edSign(null, Buffer.from(text, "utf8"), privateKey)),
  };
}

function settledSignedBy(
  inner: ParsedSettledTransaction["inner"],
  step1Seed: number,
  step2Seed: number,
): ParsedSettledTransaction {
  const step1Signature = seedKeyPair(step1Seed).signText(JSON.stringify(inner));
  const step2Signature = seedKeyPair(step2Seed).signText(
    JSON.stringify({ inner, step_1_signature: step1Signature }),
  );
  return { inner, step_1_signature: step1Signature, step_2_signature: step2Signature };
}

function foreignBalanceHead(receiverAmount: string): {
  parsed: ParsedSettledTransaction;
  bodyText: string;
} {
  const base = JSON.parse(fixtureText("target.settled.json")) as ParsedSettledTransaction;
  // Preserve insertion sequence: rebuild step_2_state with only `amount` so key order
  // stays amount-first (fixture shape). Amount text is bound verbatim into signed bytes.
  const inner = {
    ...base.inner,
    step_2_state: { amount: receiverAmount },
  } as ParsedSettledTransaction["inner"];
  const parsed = settledSignedBy(inner, 0x02, 0x03);
  const bodyText =
    `{"inner":${JSON.stringify(parsed.inner)}` +
    `,"step_1_signature":${JSON.stringify(parsed.step_1_signature)}` +
    `,"step_2_signature":${JSON.stringify(parsed.step_2_signature)}}`;
  return { parsed, bodyText };
}

describe("foreign-B (Byte-exact) — one suite constructor on write+read", () => {
  it.each(["2.50", "2.250", "10.0"] as const)(
    "foreign spelling %s survives verify → retain → verifyRetainedBodyOnRead",
    (foreignB) => {
      const { parsed, bodyText } = foreignBalanceHead(foreignB);
      const verified = verifySettledTransaction(parsed, RECEIVER);
      expect(verified.verdict).toBe("VERIFIED");
      if (verified.verdict !== "VERIFIED") return;

      // Projection carries the foreign spelling verbatim (wallet-role takes step_*_state.amount).
      expect(verified.projection.B).toBe(foreignB);

      const projected = projectRoleState(verified.transaction, RECEIVER);
      expect(projected.ok).toBe(true);
      if (!projected.ok) return;
      expect(projected.projection.B).toBe(foreignB);

      const obsFp = buildWalletHeadFingerprintFromProjection(projected.projection, RECEIVER);
      expect(obsFp.ok).toBe(true);
      if (!obsFp.ok) return;

      // Write-path (verifier) and read-path (observation suite) digests MUST match.
      expect(obsFp.fingerprint.sha256).toBe(verified.semanticFingerprint);
      expect(
        computeWalletHeadFingerprint({
          walletPublicKey: RECEIVER,
          stateKind: "HEAD",
          sSignature: projected.projection.S,
          pSignature: projected.projection.P,
          bAmount: foreignB,
          innerSha256: projected.projection.I,
          step1Signature: verified.transaction.step_1_signature,
          step2Signature: verified.transaction.step_2_signature,
        }),
      ).toBe(verified.semanticFingerprint);

      // Suite builder embeds foreign B verbatim — never rewrites to shortest form.
      const suite = buildWalletHeadFingerprint({
        wallet_public_key: RECEIVER as never,
        state_kind: "HEAD" as never,
        s_signature: projected.projection.S as never,
        p_signature: projected.projection.P as never,
        b_amount: foreignB as never,
        inner_sha256: projected.projection.I as never,
        step_1_signature: verified.transaction.step_1_signature as never,
        step_2_signature: verified.transaction.step_2_signature as never,
      });
      expect(suite.preimageText).toContain(`"b_amount":"${foreignB}"`);
      expect(suite.sha256).toBe(verified.semanticFingerprint);
      // Preimage helper is the same suite path (no hand-rolled sibling).
      expect(
        buildWalletHeadFingerprintPreimage({
          walletPublicKey: RECEIVER,
          stateKind: "HEAD",
          sSignature: projected.projection.S,
          pSignature: projected.projection.P,
          bAmount: foreignB,
          innerSha256: projected.projection.I,
          step1Signature: verified.transaction.step_1_signature,
          step2Signature: verified.transaction.step_2_signature,
        }),
      ).toBe(suite.preimageText);

      const retained: RetainedBodyRecord = {
        observation_id: `obs-foreign-b-${foreignB}`,
        wallet_public_key: RECEIVER,
        wallet_seq: 1,
        wallet_role: "receiver",
        parse_result: "VERIFIED_HEAD",
        completed_transaction_text: bodyText,
        completed_transaction_sha256: sha256Hex(bodyText),
        inner_preimage_text: projected.projection.inner_preimage_text,
        step_1_signature: verified.transaction.step_1_signature,
        step_2_signature: verified.transaction.step_2_signature,
        s_signature: projected.projection.S,
        p_signature: projected.projection.P,
        b_amount: foreignB,
        semantic_fingerprint: verified.semanticFingerprint,
      };

      const reread = verifyRetainedBodyOnRead(retained);
      expect(reread.ok).toBe(true);
      if (!reread.ok) return;
      expect(reread.semanticFingerprint).toBe(verified.semanticFingerprint);
      expect(reread.role).toBe("receiver");
    },
  );

  it("rejects structural grammar violations on b_amount (not merely non-canonical spelling)", () => {
    expect(() =>
      buildWalletHeadFingerprint({
        wallet_public_key: RECEIVER as never,
        state_kind: "HEAD" as never,
        s_signature: "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==" as never,
        p_signature: "" as never,
        b_amount: "2.5e1" as never,
        inner_sha256: "a".repeat(64) as never,
        step_1_signature: "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==" as never,
        step_2_signature: "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==" as never,
      }),
    ).toThrow();
  });
});
