// A.7 zp-wallet-head-fingerprint-v1 constructor tests.
// Golden vector sourced from frozen A.8.2 / receive-golden fixtures — never regenerated.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import type { SettledSplitChainTransaction } from "../protocol/inner.js";
import {
  WALLET_HEAD_FINGERPRINT_FIELDS,
  WALLET_HEAD_FINGERPRINT_PURPOSE,
  buildGenesisWalletHeadFingerprint,
  buildWalletHeadFingerprintFromProjection,
  fingerprintsSemanticallyEqual,
} from "./fingerprint.js";
import { projectGenesisState, projectRoleState } from "./projection.js";

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
  target: {
    receiver_terminal_head: { preimage_sha256: string; fingerprint: string };
  };
};

const RECEIVER = MANIFEST.public_keys.seed_03;
const SENDER = MANIFEST.public_keys.seed_02;

function settled(name: string): SettledSplitChainTransaction {
  return JSON.parse(fixtureText(name)) as SettledSplitChainTransaction;
}

describe("A.8.2 zp-wallet-head-fingerprint-v1 golden", () => {
  it("reproduces the frozen preimage text and digest for the receiver head", () => {
    const tx = settled("target.settled.json");
    const projected = projectRoleState(tx, RECEIVER);
    expect(projected.ok).toBe(true);
    if (!projected.ok) return;

    const result = buildWalletHeadFingerprintFromProjection(projected.projection, RECEIVER);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const fixturePreimage = fixtureText("receiver-head-fingerprint.txt").replace(/\n$/, "");
    // Fixture may or may not carry a trailing newline; compare against purpose-line form.
    const fixtureLines = fixtureText("receiver-head-fingerprint.txt").split("\n");
    const fixtureJoined =
      fixtureLines[fixtureLines.length - 1] === ""
        ? fixtureLines.slice(0, -1).join("\n")
        : fixtureLines.join("\n");

    expect(result.fingerprint.preimageText).toBe(fixtureJoined);
    expect(result.fingerprint.sha256).toBe(MANIFEST.target.receiver_terminal_head.fingerprint);
    expect(result.fingerprint.sha256).toBe(
      MANIFEST.target.receiver_terminal_head.preimage_sha256,
    );
    expect(sha256Hex(result.fingerprint.preimageText)).toBe(result.fingerprint.sha256);
    // A.8.2 machine-output table (current appendix, not the stale ticket digests).
    expect(result.fingerprint.sha256).toBe(
      "d03a98b770684e577667f9bde01276b196b98db31663f23b0900623d6dffca2a",
    );
    void fixturePreimage;
  });

  it("pins the A.7 field sequence (1–10) and purpose literal", () => {
    expect(WALLET_HEAD_FINGERPRINT_PURPOSE).toBe("zp-wallet-head-fingerprint-v1");
    expect([...WALLET_HEAD_FINGERPRINT_FIELDS]).toEqual([
      "purpose",
      "canonical_version",
      "wallet_public_key",
      "state_kind",
      "s_signature",
      "p_signature",
      "b_amount",
      "inner_sha256",
      "step_1_signature",
      "step_2_signature",
    ]);
  });

  it("excludes transport fields from the preimage", () => {
    const tx = settled("target.settled.json");
    const projected = projectRoleState(tx, RECEIVER);
    expect(projected.ok).toBe(true);
    if (!projected.ok) return;
    const result = buildWalletHeadFingerprintFromProjection(projected.projection, RECEIVER);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    for (const banned of [
      "raw_response",
      "endpoint",
      "observed_at",
      "http_status",
      "wallet_seq",
    ]) {
      expect(result.fingerprint.preimageText.includes(banned)).toBe(false);
    }
  });
});

describe("fingerprint comparison — equivalent envelopes", () => {
  it("sender and receiver fingerprints from the same tx differ (role-relative material)", () => {
    const tx = settled("target.settled.json");
    const s = projectRoleState(tx, SENDER);
    const r = projectRoleState(tx, RECEIVER);
    expect(s.ok && r.ok).toBe(true);
    if (!s.ok || !r.ok) return;
    const sf = buildWalletHeadFingerprintFromProjection(s.projection, SENDER);
    const rf = buildWalletHeadFingerprintFromProjection(r.projection, RECEIVER);
    expect(sf.ok && rf.ok).toBe(true);
    if (!sf.ok || !rf.ok) return;
    expect(fingerprintsSemanticallyEqual(sf.fingerprint.sha256, rf.fingerprint.sha256)).toBe(
      false,
    );
  });

  it("identical projections yield equal digests (semantic equality independent of raw bytes)", () => {
    const tx = settled("target.settled.json");
    const a = projectRoleState(tx, RECEIVER);
    const b = projectRoleState(tx, RECEIVER);
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    const fa = buildWalletHeadFingerprintFromProjection(a.projection, RECEIVER);
    const fb = buildWalletHeadFingerprintFromProjection(b.projection, RECEIVER);
    expect(fa.ok && fb.ok).toBe(true);
    if (!fa.ok || !fb.ok) return;
    expect(fingerprintsSemanticallyEqual(fa.fingerprint.sha256, fb.fingerprint.sha256)).toBe(
      true,
    );
  });
});

describe("genesis fingerprint", () => {
  it("builds GENESIS state_kind with null inner/step signatures", () => {
    const g = projectGenesisState();
    const result = buildGenesisWalletHeadFingerprint(RECEIVER, g);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.fingerprint.stateKind).toBe("GENESIS");
    expect(result.fingerprint.preimageText).toContain('"state_kind":"GENESIS"');
    expect(result.fingerprint.preimageText).toContain('"inner_sha256":null');
    expect(result.fingerprint.preimageText).toContain('"step_1_signature":null');
    expect(result.fingerprint.preimageText).toContain('"step_2_signature":null');
    expect(result.fingerprint.preimageText).toContain('"s_signature":""');
    expect(result.fingerprint.preimageText).toContain('"p_signature":""');
    expect(result.fingerprint.preimageText).toContain('"b_amount":"0"');
    expect(result.fingerprint.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});
