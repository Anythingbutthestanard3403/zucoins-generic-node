// Security & abuse suite.
// Binds every signing custody / observation verification / operations recovery item to proof files
// that exist and contain load-bearing negative markers, and runs a small set of
// behavioral negatives (operator-boundary absence, direct-successor reject,
// vault no-plaintext, threat-class no-orphan).
//
// Governing: signing custody; observation verification; canonical fields; operations recovery; the API contract.
// Verification is local-only.

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ALL_ABUSE_ROWS,
  CANONICAL_FIELD_NEGATIVE_ROWS,
  CAPTURE_ABUSE_ROWS,
  PREDICATE_ABUSE_ROWS,
  OPERATOR_BOUNDARY_PROOFS,
  FORBIDDEN_OPERATOR_ACTIONS,
  REQUIRED_THREAT_CLASSES,
  SECURITY_ABUSE_ROWS,
  WEB_AND_DERIVED_ROWS,
  type AbuseProofRef,
  type AbuseRow,
} from "./security-abuse-map.js";
import { FORBIDDEN_RECOVERY_ACTIONS } from "../src/operator/recovery-inspection.js";
import type { SplitChainInnerV2, SettledSplitChainTransaction } from "../src/protocol/inner.js";
import type { LandingPathProof } from "../src/protocol/reconcile/landing-proof.js";
import type { WalletStateProjection } from "../src/protocol/wallet-role.js";
import {
  verifyExternalSendLanding,
  type SendLandingEvidence,
} from "../src/send/landing-verify.js";
import { mintLandingPathProofFromOracle } from "../src/protocol/reconcile/landing-oracle-mint.fixture.js";

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, "../../..");

function readRepo(rel: string): string {
  return readFileSync(resolve(REPO_ROOT, rel), "utf8");
}

function assertProof(proof: AbuseProofRef, rowId: string): void {
  const abs = resolve(REPO_ROOT, proof.path);
  expect(existsSync(abs), `${rowId}: missing proof ${proof.path}`).toBe(true);
  const body = readFileSync(abs, "utf8");
  for (const marker of proof.mustContain) {
    expect(body.includes(marker), `${rowId}: ${proof.path} missing marker ${JSON.stringify(marker)}`).toBe(
      true,
    );
  }
}

function assertRow(row: AbuseRow): void {
  expect(row.proofs.length, `${row.id} has zero proofs`).toBeGreaterThan(0);
  for (const proof of row.proofs) assertProof(proof, row.id);
}

describe("abuse inventory counts", () => {
  it("registers all 27 security items", () => {
    expect(SECURITY_ABUSE_ROWS.map((r) => r.id)).toEqual(
      Array.from({ length: 27 }, (_, i) => `SECURITY-${String(i + 1).padStart(2, "0")}`),
    );
  });

  it("registers all 7 raw-capture items", () => {
    expect(CAPTURE_ABUSE_ROWS.map((r) => r.id)).toEqual(
      Array.from({ length: 7 }, (_, i) => `CAPTURE-0${i + 1}`),
    );
  });

  it("registers all 9 operation-predicate items", () => {
    expect(PREDICATE_ABUSE_ROWS.map((r) => r.id)).toEqual(
      Array.from({ length: 9 }, (_, i) => `PREDICATE-0${i + 1}`),
    );
  });

  it("registers A.9 general vectors 1–17 plus 6 reporting-register specifics", () => {
    const general = CANONICAL_FIELD_NEGATIVE_ROWS.filter((r) => r.id.startsWith("NEGATIVE-") && !r.id.startsWith("NEGATIVE-REG"));
    const reg = CANONICAL_FIELD_NEGATIVE_ROWS.filter((r) => r.id.startsWith("NEGATIVE-REG"));
    expect(general).toHaveLength(17);
    expect(reg).toHaveLength(6);
  });

  it("includes web-surface / derived rows from the map", () => {
    expect(WEB_AND_DERIVED_ROWS.map((r) => r.id).sort()).toEqual(
      ["RESOURCE-DOS", "SUPPLY-CHAIN", "WEB-CSRF", "WEB-SSRF", "WEB-XSS"].sort(),
    );
  });
});

describe("proof binding — every abuse row has a negative-path proof on disk", () => {
  it.each(ALL_ABUSE_ROWS.map((row) => [row.id, row] as const))("%s proofs resolve with markers", (_id, row) => {
    assertRow(row);
  });

  it("operations recovery boundary proofs resolve with all forbidden tokens", () => {
    for (const proof of OPERATOR_BOUNDARY_PROOFS) {
      assertProof(proof, "OPERATOR-BOUNDARY");
    }
  });
});

describe("no-orphan threat classes", () => {
  it("every required threat class has ≥1 bound abuse row with proofs", () => {
    for (const threatClass of REQUIRED_THREAT_CLASSES) {
      const rows = ALL_ABUSE_ROWS.filter((row) =>
        (row.categories as readonly string[]).includes(threatClass),
      );
      expect(rows.length, `orphan threat class: ${threatClass}`).toBeGreaterThan(0);
      for (const row of rows) assertRow(row);
    }
  });

  it("every signing custody controlled row 1–14 and 16 is exercised by ≥1 abuse row", () => {
    const covered = new Set<number>();
    for (const row of ALL_ABUSE_ROWS) for (const n of row.threatMapRows) covered.add(n);
    for (const n of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16] as const) {
      expect(covered.has(n), `signing custody row ${n} has no abuse binding`).toBe(true);
    }
    expect(covered.has(15), "row 15 residual is pointed by PREDICATE-07").toBe(true);
  });
});

describe("operations recovery operator-boundary — forbidden actions never permitted", () => {
  it("FORBIDDEN_RECOVERY_ACTIONS is exactly the operations recovery closed set", () => {
    expect([...FORBIDDEN_RECOVERY_ACTIONS].sort()).toEqual([...FORBIDDEN_OPERATOR_ACTIONS].sort());
  });

  it("no permitted operator recovery action equals a forbidden token", () => {
    const haltSrc = readRepo("packages/generic-node-contracts/src/operator-halt/halt.contract.ts");
    for (const token of FORBIDDEN_OPERATOR_ACTIONS) {
      expect(haltSrc.includes(`"${token}"`), `halt catalog admits ${token}`).toBe(false);
    }
  });

  it("frozen ROUTE_POLICIES never expose forbidden action verbs as routes", () => {
    const routes = readRepo("packages/generic-node-contracts/src/route-policy/routes.ts");
    for (const token of FORBIDDEN_OPERATOR_ACTIONS) {
      expect(routes.includes(token), `route surface leaks ${token}`).toBe(false);
    }
  });
});

describe("operation predicate 7 — the one-hop LANDED_DIRECT_SUCCESSOR shortcut is rejected", () => {
  const SOURCE = "source-pubkey-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  const DEST = "dest-pubkey-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
  const AMOUNT = "4";
  const OP_ID = "11111111-1111-1111-1111-111111111111";
  const APPROVAL_ID = "22222222-2222-2222-2222-222222222222";
  const SOURCE_T0_OBS = "33333333-3333-3333-3333-333333333333";
  const DEST_T0_OBS = "44444444-4444-4444-4444-444444444444";
  const HEAD_OBS = "55555555-5555-5555-5555-555555555555";
  const STEP1_SIG =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
  const STEP2_SIG =
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==";

  function sha256Hex(text: string): string {
    return createHash("sha256").update(text, "utf8").digest("hex");
  }

  function goodInner(): SplitChainInnerV2 {
    return {
      type: "unique_combinable",
      version: "2",
      unix_time_secs: "1784332700",
      signer_steps: 2,
      step_1_signer: "sender",
      step_2_signer: "receiver",
      step_1_key_public__base64urlsafe: SOURCE,
      step_2_key_public__base64urlsafe: DEST,
      step_1_state: { amount: "6" },
      step_2_state: { amount: "4" },
      previous_step_1_state_signature: "source-prior-sig",
      previous_step_2_state_signature: "dest-prior-sig",
    };
  }

  function goodTx(inner: SplitChainInnerV2 = goodInner()): SettledSplitChainTransaction {
    return {
      inner,
      step_1_signature: STEP1_SIG,
      step_2_signature: STEP2_SIG,
    };
  }

  function sourceT0(): WalletStateProjection {
    return { role: "sender", S: "source-prior-sig", P: "", B: "10", I: "d0" };
  }

  function destT0(): WalletStateProjection {
    return { role: "receiver", S: "dest-prior-sig", P: "", B: "0", I: "d1" };
  }

  function baseEvidence(overrides: Partial<SendLandingEvidence> = {}): SendLandingEvidence {
    const inner = goodInner();
    const preimage = JSON.stringify(inner);
    const tx = goodTx(inner);
    const bodyText = JSON.stringify(tx);
    const bodySha = sha256Hex(bodyText);
    const innerSha = sha256Hex(preimage);

    const base: SendLandingEvidence = {
      operationId: OP_ID,
      entryStatus: "AWAITING_REDEMPTION",
      economic: {
        operationId: OP_ID,
        sourceWalletId: "66666666-6666-6666-6666-666666666666",
        sourcePubkey: SOURCE,
        destinationAddress: DEST,
        amountZkz: AMOUNT,
        referencesOperationId: null,
      },
      expectedArtifactVerified: true,
      expectedArtifact: {
        sourcePubkey: SOURCE,
        destinationAddress: DEST,
        amountZkz: AMOUNT,
        referencesOperationId: null,
      },
      approval: {
        approvalId: APPROVAL_ID,
        totpConsumed: true,
        deviceSignatureRequired: false,
        deviceSignatureVerified: false,
        sourcePubkey: SOURCE,
        destinationAddress: DEST,
        amountZkz: AMOUNT,
        referencesOperationId: null,
      },
      signIntent: {
        approvalId: APPROVAL_ID,
        sourceT0ObservationId: SOURCE_T0_OBS,
        destinationT0ObservationId: DEST_T0_OBS,
        innerPreimageText: preimage,
        innerSha256: innerSha,
      },
      signIntentRowCount: 1,
      partial: {
        innerSha256: innerSha,
        step1Signature: STEP1_SIG,
        transferCodeSha256: sha256Hex("transfer-code"),
        deliveredTransferCodeSha256: sha256Hex("transfer-code"),
        otherDeliveredPartialSha256: [],
      },
      sourceT0: { observationId: SOURCE_T0_OBS, projection: sourceT0() },
      destinationT0: { observationId: DEST_T0_OBS, projection: destT0() },
      candidate: {
        completedTransaction: tx,
        completedTransactionText: bodyText,
        completedTransactionSha256: bodySha,
        step1PreimageText: preimage,
        step1Signature: STEP1_SIG,
        step2Signature: STEP2_SIG,
        step2SignatureVerified: true,
      },
      sourcePathProof: mintLandingPathProofFromOracle({
        walletPubkeyBase64Urlsafe: SOURCE,
        expectedBodySha256: bodySha,
        freshHeadBodySha256: bodySha,
        freshHeadObservationId: HEAD_OBS,
        depth: 0,
      }),
      sourcePathProofIncomplete: false,
      sourceLeaseActive: true,
    };

    return { ...base, ...overrides };
  }

  it("fabricated DIRECT_SUCCESSOR path kind fails closed as INDETERMINATE (not LANDED)", () => {
    const base = baseEvidence();
    const bodySha = base.candidate!.completedTransactionSha256;
    const foreign = {
      kind: "LANDED_DIRECT_SUCCESSOR",
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: bodySha,
      freshHeadBodySha256: bodySha,
      freshHeadObservationId: "obs-foreign",
      depth: 0,
    } as unknown as LandingPathProof;

    const verify = verifyExternalSendLanding(baseEvidence({ sourcePathProof: foreign }));
    expect(verify.kind).toBe("INDETERMINATE");
    if (verify.kind === "INDETERMINATE") {
      expect(verify.reason).toBe("SOURCE_PATH_PROOF_ABSENT");
      expect(verify.detail).toMatch(/issued oracle capability/);
    }
  });

  it("send-external landing SQL contract refuses the direct-successor kind", () => {
    const contract = readRepo("packages/node-core/src/schema/send-external-landing.contract.ts");
    expect(contract).toContain("LANDED_EXACT");
    expect(contract).toContain("LANDED_COMPLETE_PATH");
    expect(contract).toContain("LANDED_DIRECT_SUCCESSOR shortcut has no representation");
    expect(contract).toMatch(
      /source_path_kind text NOT NULL CHECK \(source_path_kind IN \('LANDED_EXACT', 'LANDED_COMPLETE_PATH'\)\)/,
    );
  });
});

describe("vault / secret surface — no plaintext key columns", () => {
  it("vault.sql has ciphertext/nonce/auth_tag and no private_key column", () => {
    const sql = readRepo("packages/node-core/src/schema/vault.sql");
    expect(sql).toContain("ciphertext");
    expect(sql).toContain("nonce");
    expect(sql).toContain("auth_tag");
    expect(sql).not.toMatch(/\bprivate_key\b/);
    expect(sql).not.toMatch(/\bseed_hex\b/);
    expect(sql).not.toMatch(/\bmaster_key\b/);
  });

  it("secret census: node-core src never logs privateKey via console.*", () => {
    const srcRoot = resolve(REPO_ROOT, "packages/node-core/src");
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const abs = join(dir, name);
        const st = statSync(abs);
        if (st.isDirectory()) {
          if (name === "node_modules") continue;
          walk(abs);
          continue;
        }
        if (!name.endsWith(".ts") || name.endsWith(".test.ts")) continue;
        const body = readFileSync(abs, "utf8");
        if (/console\.(log|info|debug|error|warn)\([^)]*privateKey/i.test(body)) {
          offenders.push(relative(REPO_ROOT, abs));
        }
      }
    };
    walk(srcRoot);
    expect(offenders).toEqual([]);
  });
});
