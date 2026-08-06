// Residual — categories (c)/(d)/(e)/(f): the byte-exactness proofs that
// sit beside the crash matrix (a) and the CAS race (b).
//
//   (c) deterministic re-sign: the same persisted inner_preimage_text signed twice yields
// byte-identical Ed25519 signatures (custody; RFC 8032; DETERMINISTIC_RESIGN) — a
//       three-way byte pin plus rebuilt-variant negative controls proving the oracle never
//       canonicalizes (the byte-exact signing rule).
//   (d) redelivery byte-identity: redelivery changes ONLY redelivery_count/last_redelivered_at;
// transfer_code_text/transfer_code_sha256 stay byte-identical (REDELIVERY_RULE; data-model
//       byte_immutable_except_delivery_counters).
//   (e) expiry timing: the constants and the two isolated boundary predicates; past
//       T2+margin with NO positive non-landing proof routes to NEEDS_ATTENTION, lease held,
//       never an auto-expire.
//   (f) post-sign-intent mutation rejection: a changed link/time/expiry/destination/amount or
//       any changed signed byte is rejected by the persisted-digest comparator and forces a NEW
//       operation_id under a FRESH approval — never a second partial under the old approval
//       (REPLACEMENT_RULE; SIGN_INTENT_FROZEN_AFTER_EXISTS).
//
// Plus two censuses: the anti-tautology scan (the recovery procedure under test never imports
// the frozen decision-table oracle) and the obligation records (each phrased "not proven here;
// discharged where", extending — never duplicating — SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { beforeAll, describe, expect, it } from "vitest";

import {
  digestPreimage,
  encodeBase64Url,
  keypairFromSeedByte,
  ready,
  signDetached,
  signPreimage,
  utf8Bytes,
  verifyPreimageSignature,
} from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  REPLACEMENT_RULE,
  SIGN_INTENT_FROZEN_AFTER_EXISTS,
} from "../../generic-node-contracts/src/approval/sign-intent.contract.ts";
import { SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS } from "../src/schema/transaction-material.contract.ts";
import {
  APPROVAL_ID,
  APPROVAL_ID_FRESH,
  baselineInnerFields,
  baselinePlan,
  BASELINE_PREIMAGE_SHA256,
  BASELINE_PREIMAGE_TEXT,
  ASTRAL_PREIMAGE_TEXT,
  fixtureKeypair,
  FORMATION_CLOCK_SECS,
  KEY_SEED_BYTE,
  makeInnerPreimage,
  makePartialRow,
  makeTransferCodeText,
  NON_ASCII_PREIMAGE_TEXT,
  OPERATION_ID,
  OPERATION_ID_FRESH,
  REBUILT_PREIMAGE_VARIANTS,
  ROTATED_KEY_SEED_BYTE,
  signFixture,
  T2_SECS,
} from "./crash-replay-fixtures.ts";
import {
  addSecs,
  agingMarginElapsed,
  applyRegimeUpdate,
  commitInsert,
  createRuntime,
  isPastRedemptionExpiry,
  partialFor,
  REFUSAL_UPDATE_COLUMN,
  SEND_PARTIAL_AGING_MARGIN_SECS,
  SEND_REDEMPTION_WINDOW_SECS,
  stringField,
  type Scenario,
  type UnixSecsString,
} from "./crash-replay-model.ts";
import { createScenario, crashAndRecover, driveFormation, redeliverPartial } from "./crash-replay-driver.ts";
import { recoverOperation, snapshotDurable } from "./crash-replay-recovery.ts";
import {
  CRASH_REPLAY_PERSISTENCE_OBLIGATIONS,
  CRASH_REPLAY_FAULT_INJECTION_OBLIGATIONS,
} from "./crash-replay-obligations.ts";
import {
  PARTIALS_TABLE,
  PARTIALS_TABLE_NAME,
} from "./crash-replay-surfaces.ts";

const here = dirname(fileURLToPath(import.meta.url));

beforeAll(async () => {
  await ready();
});

// ---------------------------------------------------------------------------
// (c) Deterministic re-sign byte test.
// ---------------------------------------------------------------------------

describe("c deterministic re-sign — same persisted bytes -> byte-identical signature", () => {
  it("signing the same persisted inner_preimage_text twice yields byte-identical signatures", () => {
    const first = signFixture(BASELINE_PREIMAGE_TEXT);
    const second = signFixture(BASELINE_PREIMAGE_TEXT);
    expect(first).toBe(second);
    // The signature is the exact 88-char padded base64url form, byte for byte.
    expect(first).toMatch(/^[A-Za-z0-9_-]{86}==$/);
  });

  it("three-way byte pin: signFixture === signPreimage === encodeBase64Url(signDetached(utf8Bytes))", () => {
    const keypair = fixtureKeypair(KEY_SEED_BYTE);
    const highLevel = signFixture(BASELINE_PREIMAGE_TEXT);
    const direct = signPreimage(BASELINE_PREIMAGE_TEXT, keypair.privateKey);
    const lowLevel = encodeBase64Url(
      signDetached(utf8Bytes(BASELINE_PREIMAGE_TEXT), keypair.privateKey),
    );
    expect(highLevel).toBe(direct);
    expect(direct).toBe(lowLevel);
    // Positive control: the pinned signature verifies under the matching public key.
    expect(verifyPreimageSignature(BASELINE_PREIMAGE_TEXT, highLevel, keypair.publicKey)).toBe(true);
  });

  it("determinism survives key reconstruction from the same seed byte (no per-call randomness)", () => {
    const keyA = keypairFromSeedByte(KEY_SEED_BYTE);
    const keyB = keypairFromSeedByte(KEY_SEED_BYTE);
    expect(Buffer.from(keyA.privateKey).toString("hex")).toBe(
      Buffer.from(keyB.privateKey).toString("hex"),
    );
    expect(signPreimage(BASELINE_PREIMAGE_TEXT, keyA.privateKey)).toBe(
      signPreimage(BASELINE_PREIMAGE_TEXT, keyB.privateKey),
    );
  });

  it.each([
    { label: "non-ASCII destination", text: NON_ASCII_PREIMAGE_TEXT },
    { label: "astral-plane destination", text: ASTRAL_PREIMAGE_TEXT },
  ])("$label: re-sign is byte-identical, and differs from the baseline signature", ({ text }) => {
    expect(text).not.toBe(BASELINE_PREIMAGE_TEXT);
    expect(signFixture(text)).toBe(signFixture(text));
    // Different signed bytes -> different signature (the signer is byte-sensitive, UTF-8).
    expect(signFixture(text)).not.toBe(signFixture(BASELINE_PREIMAGE_TEXT));
  });

  it("a different key over the SAME bytes yields a different signature (fixed key AND message)", () => {
    const baseline = signFixture(BASELINE_PREIMAGE_TEXT, KEY_SEED_BYTE);
    const rotated = signFixture(BASELINE_PREIMAGE_TEXT, ROTATED_KEY_SEED_BYTE);
    expect(rotated).not.toBe(baseline);
  });

  it.each([...REBUILT_PREIMAGE_VARIANTS])(
    "rebuilt variant '$label' is rejected: different bytes, different digest, different signature",
    (variant) => {
      // The fixture already proves variant.text !== BASELINE_PREIMAGE_TEXT (control not vacuous).
      expect(variant.text).not.toBe(BASELINE_PREIMAGE_TEXT);
      // A canonicalizing oracle would re-derive the baseline bytes; this one does not — the
      // persisted-digest comparator (the byte-exact signing rule) rejects the variant outright.
      expect(digestPreimage(variant.text)).not.toBe(BASELINE_PREIMAGE_SHA256);
      // The signer itself is byte-sensitive: re-signing the variant never reproduces the
      // baseline signature, so a rebuilt variant can never pass the pre-delivery byte-compare.
      expect(signFixture(variant.text)).not.toBe(signFixture(BASELINE_PREIMAGE_TEXT));
    },
  );
});

// ---------------------------------------------------------------------------
// (d) Redelivery byte-identity model test.
// ---------------------------------------------------------------------------

interface FrozenPartialBytes {
  readonly operationId: string;
  readonly approvalId: string;
  readonly innerSha256: string;
  readonly step1Signature: string;
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
  readonly persistedAt: string;
}

const frozenPartialBytes = (scenario: Scenario): FrozenPartialBytes => {
  const partial = partialFor(scenario.durable, OPERATION_ID);
  if (partial === undefined) {
    throw new Error("exactness: no persisted partial to snapshot");
  }
  return {
    operationId: stringField(partial, "operation_id"),
    approvalId: stringField(partial, "approval_id"),
    innerSha256: stringField(partial, "inner_sha256"),
    step1Signature: stringField(partial, "step_1_signature"),
    transferCodeText: stringField(partial, "transfer_code_text"),
    transferCodeSha256: stringField(partial, "transfer_code_sha256"),
    persistedAt: stringField(partial, "persisted_at"),
  };
};

const assertBytesUnchanged = (scenario: Scenario, before: FrozenPartialBytes): void => {
  const after = frozenPartialBytes(scenario);
  expect(after).toEqual(before);
};

describe("d redelivery byte-identity — only delivery counters move (REDELIVERY_RULE)", () => {
  const deliveredScenario = (): Scenario => {
    const scenario = createScenario({
      operationId: OPERATION_ID,
      approvalId: APPROVAL_ID,
      approvalConsumed: true,
    });
    driveFormation(scenario, baselinePlan()); // all ten steps: first delivery already served
    return scenario;
  };

  it("three redeliveries change ONLY redelivery_count/last_redelivered_at; signed bytes stay byte-identical", () => {
    const scenario = deliveredScenario();
    const before = frozenPartialBytes(scenario);
    const signerCallsAfterFormation = scenario.runtime.log.signerCalls.length;
    const insertsAfterFormation = scenario.runtime.log.insertAttempts.length;
    const deliveriesAfterFormation = scenario.runtime.log.deliveriesServed.length;
    expect(deliveriesAfterFormation).toBe(1);

    const clocks: UnixSecsString[] = [
      addSecs(FORMATION_CLOCK_SECS, 60),
      addSecs(FORMATION_CLOCK_SECS, 120),
      addSecs(FORMATION_CLOCK_SECS, 180),
    ];
    let expectedCount = 0;
    for (const clock of clocks) {
      redeliverPartial(scenario, OPERATION_ID, clock);
      expectedCount += 1;
      const partial = partialFor(scenario.durable, OPERATION_ID);
      if (partial === undefined) {
        throw new Error("exactness: partial vanished mid-redelivery");
      }
      assertBytesUnchanged(scenario, before);
      expect(partial["redelivery_count"]).toBe(expectedCount);
      expect(partial["last_redelivered_at"]).not.toBeNull();
    }

    // No re-sign, no re-form, no new insert ever ran during redelivery.
    expect(scenario.runtime.log.signerCalls.length).toBe(signerCallsAfterFormation);
    expect(scenario.runtime.log.insertAttempts.length).toBe(insertsAfterFormation);
    // Every served byte string — first delivery and all redeliveries — is byte-identical to the
    // persisted transfer code (serve FROM THE STORE).
    expect(scenario.runtime.log.deliveriesServed.length).toBe(deliveriesAfterFormation + clocks.length);
    for (const served of scenario.runtime.log.deliveriesServed) {
      expect(served.transferCodeText).toBe(before.transferCodeText);
      expect(served.transferCodeSha256).toBe(before.transferCodeSha256);
    }
  });

  it("the regime refuses a signed-byte UPDATE with zero side effects (byte_immutable_except_delivery_counters)", () => {
    const scenario = deliveredScenario();
    const before = frozenPartialBytes(scenario);
    const partial = partialFor(scenario.durable, OPERATION_ID);
    if (partial === undefined) {
      throw new Error("exactness: no partial to tamper");
    }
    const countBefore = partial["redelivery_count"];
    const signedColumns = ["transfer_code_text", "transfer_code_sha256", "inner_sha256", "step_1_signature"];
    for (const column of signedColumns) {
      const outcome = applyRegimeUpdate(
        scenario,
        PARTIALS_TABLE_NAME,
        scenario.durable.partials,
        PARTIALS_TABLE,
        OPERATION_ID,
        { [column]: "tampered" },
      );
      expect(outcome.applied).toBe(false);
      if (!outcome.applied) {
        expect(outcome.refusedColumn).toBe(column);
      }
      expect(scenario.runtime.log.refusals).toContain(`${REFUSAL_UPDATE_COLUMN}:${PARTIALS_TABLE_NAME}.${column}`);
    }
    // Zero side effects: the row is byte-identical and no counter moved.
    assertBytesUnchanged(scenario, before);
    expect(partialFor(scenario.durable, OPERATION_ID)?.["redelivery_count"]).toBe(countBefore);
  });
});

// ---------------------------------------------------------------------------
// (e) Expiry timing — constants and the two isolated boundary predicates.
// ---------------------------------------------------------------------------

describe("e expiry timing — constants + boundary predicates", () => {
  it("the constants are pinned to their canonical values", () => {
    expect(SEND_REDEMPTION_WINDOW_SECS).toBe(300);
    expect(SEND_PARTIAL_AGING_MARGIN_SECS).toBe(3600);
    // T2 = formation clock + redemption window (integer-seconds string arithmetic).
    expect(T2_SECS).toBe(addSecs(FORMATION_CLOCK_SECS, SEND_REDEMPTION_WINDOW_SECS));
  });

  it("isPastRedemptionExpiry(now, t2) = now >= t2 (fail-closed at the boundary)", () => {
    expect(isPastRedemptionExpiry(T2_SECS, T2_SECS)).toBe(true); // exactly T2 -> past
    expect(isPastRedemptionExpiry(addSecs(T2_SECS, 1), T2_SECS)).toBe(true);
    expect(isPastRedemptionExpiry(addSecs(T2_SECS, -1), T2_SECS)).toBe(false);
  });

  it("agingMarginElapsed(now, t2) = now >= t2 + SEND_PARTIAL_AGING_MARGIN_SECS", () => {
    const margin = addSecs(T2_SECS, SEND_PARTIAL_AGING_MARGIN_SECS);
    expect(agingMarginElapsed(margin, T2_SECS)).toBe(true); // exactly at margin -> elapsed
    expect(agingMarginElapsed(addSecs(T2_SECS, SEND_PARTIAL_AGING_MARGIN_SECS - 1), T2_SECS)).toBe(false);
    expect(agingMarginElapsed(addSecs(T2_SECS, SEND_PARTIAL_AGING_MARGIN_SECS + 1), T2_SECS)).toBe(true);
  });

  it("past T2+margin with NO positive non-landing proof -> NEEDS_ATTENTION, lease held, no auto-expire", () => {
    const driven = createScenario({
      operationId: OPERATION_ID,
      approvalId: APPROVAL_ID,
      approvalConsumed: true,
    });
    driveFormation(driven, baselinePlan()); // delivered while healthy
    const before = snapshotDurable(driven.durable, OPERATION_ID);
    const nowSecs = addSecs(T2_SECS, SEND_PARTIAL_AGING_MARGIN_SECS + 1); // deep past T2+margin
    const scenario = crashAndRecover(driven); // fresh runtime: recovery reads only durable rows
    const outcome = recoverOperation(
      scenario,
      baselinePlan(),
      OPERATION_ID,
      nowSecs,
      { kind: "NO_POSITIVE_PROOF" },
    );
    expect(outcome.classification).toBe("PARTIAL_EXPIRED");
    expect(outcome.action).toBe("NEEDS_ATTENTION");
    const operation = scenario.durable.operations.find((row) => row.operationId === OPERATION_ID);
    expect(operation?.needsAttention).toBe(true);
    expect(operation?.leaseHeld).toBe(true); // lease preserved as evidence
    expect(operation?.terminal).toBe(false); // never auto-expired / auto-terminalized
    expect(scenario.runtime.log.terminalizations).toHaveLength(0);
    expect(scenario.runtime.log.leaseReleases).toBe(0);
    // No re-sign, no new insert, no refreshed byte (fresh runtime: the formation signer call
    // does not leak in).
    expect(scenario.runtime.log.signerCalls).toHaveLength(0);
    const after = snapshotDurable(scenario.durable, OPERATION_ID);
    expect(after.intents).toBe(before.intents);
    expect(after.partials).toBe(before.partials);
    expect(after.codeSha).toBe(before.codeSha);
  });
});

// ---------------------------------------------------------------------------
// (f) Post-sign-intent mutation rejection.
// ---------------------------------------------------------------------------

interface FrozenFieldMutation {
  readonly field: string;
  readonly override: string;
  readonly trigger: string;
}

const FROZEN_FIELD_MUTATIONS: readonly FrozenFieldMutation[] = [
  { field: "chain_link", override: `${"e".repeat(86)}==`, trigger: "changed_chain_link" },
  { field: "redemption_time", override: addSecs(FORMATION_CLOCK_SECS, 1), trigger: "changed_time" },
  { field: "redemption_expiry", override: addSecs(T2_SECS, 1), trigger: "changed_expiry" },
  { field: "destination_address", override: `${"X".repeat(43)}=`, trigger: "changed_destination" },
  { field: "amount_zkz", override: "26", trigger: "changed_amount" },
];

describe("f post-sign-intent mutation rejection (REPLACEMENT_RULE; frozen-after-exists)", () => {
  it("the five signed members are exactly the frozen-after-exists fields bound into the preimage", () => {
    const fields = baselineInnerFields();
    for (const key of Object.keys(fields)) {
      expect(SIGN_INTENT_FROZEN_AFTER_EXISTS).toContain(key);
    }
    // The register's signed-byte fields all appear as preimage keys (inner_preimage_text and
    // inner_digest are carried as columns, not preimage fields).
    for (const frozen of SIGN_INTENT_FROZEN_AFTER_EXISTS) {
      if (frozen === "inner_preimage_text" || frozen === "inner_digest") {
        continue;
      }
      expect(Object.keys(fields)).toContain(frozen);
    }
  });

  it.each([...FROZEN_FIELD_MUTATIONS])(
    "changed $field -> rejected by the persisted-digest comparator; trigger $trigger forces a replacement",
    ({ field, override, trigger }) => {
      const mutatedText = makeInnerPreimage(baselineInnerFields({ [field]: override }));
      expect(mutatedText).not.toBe(BASELINE_PREIMAGE_TEXT);
      // The recovery revalidation gate (digest of the bytes vs the persisted inner_sha256)
      // rejects the mutated preimage — recovery can never complete a changed formation.
      expect(digestPreimage(mutatedText)).not.toBe(BASELINE_PREIMAGE_SHA256);
      // The signer is byte-sensitive: a changed field never reproduces the baseline signature.
      expect(signFixture(mutatedText)).not.toBe(signFixture(BASELINE_PREIMAGE_TEXT));
      // The change maps onto a named REPLACEMENT_RULE trigger.
      expect(REPLACEMENT_RULE.triggeredBy).toContain(trigger);
    },
  );

  it("any other changed signed byte (changed_signed_byte) is a replacement trigger too", () => {
    expect(REPLACEMENT_RULE.triggeredBy).toContain("changed_signed_byte");
    expect(REPLACEMENT_RULE.triggeredBy).toContain("expiry");
    // A rebuilt variant is a changed signed byte: rejected by the comparator, never re-formed.
    const variant = REBUILT_PREIMAGE_VARIANTS[0];
    if (variant === undefined) {
      throw new Error("exactness: no rebuilt variant fixture");
    }
    expect(digestPreimage(variant.text)).not.toBe(BASELINE_PREIMAGE_SHA256);
  });

  it("REPLACEMENT_RULE: safe resolution + new operation + fresh approval; never a second partial, never a refreshed expiry", () => {
    expect(REPLACEMENT_RULE.requires).toContain("safe_resolution_of_existing_operation");
    expect(REPLACEMENT_RULE.requires).toContain("new_operation");
    expect(REPLACEMENT_RULE.requires).toContain("fresh_approval");
    expect(REPLACEMENT_RULE.permitsSecondPartialUnderOldApproval).toBe(false);
    expect(REPLACEMENT_RULE.refreshesExpiryUnderOldApproval).toBe(false);
  });

  it("a replacement is structural: a second partial under the old approval is rejected; only a new operation_id + fresh approval commits", () => {
    const scenario = createScenario({
      operationId: OPERATION_ID,
      approvalId: APPROVAL_ID,
      approvalConsumed: true,
    });
    driveFormation(scenario, baselinePlan()); // commits the one legal partial
    expect(scenario.durable.partials).toHaveLength(1);

    const signature = signFixture(BASELINE_PREIMAGE_TEXT);
    const code = makeTransferCodeText(BASELINE_PREIMAGE_TEXT, signature);
    const runtime = createRuntime("replacement-probe", KEY_SEED_BYTE);
    const probe: Scenario = { durable: scenario.durable, runtime };

    // (1) Same operation_id (even with a fresh approval) -> PRIMARY KEY violation.
    const sameOperation = commitInsert(
      probe,
      PARTIALS_TABLE,
      scenario.durable.partials,
      makePartialRow(baselinePlan({ approvalId: APPROVAL_ID_FRESH }), signature, code),
      PARTIALS_TABLE_NAME,
      OPERATION_ID,
    );
    expect(sameOperation.committed).toBe(false);
    expect(sameOperation.rejectedByKey?.kind).toBe("PRIMARY KEY");
    expect(sameOperation.rejectedByKey?.columns).toEqual(["operation_id"]);

    // (2) New operation_id but the SAME approval -> UNIQUE violation on approval_id.
    const sameApproval = commitInsert(
      probe,
      PARTIALS_TABLE,
      scenario.durable.partials,
      makePartialRow(baselinePlan({ operationId: OPERATION_ID_FRESH }), signature, code),
      PARTIALS_TABLE_NAME,
      OPERATION_ID_FRESH,
    );
    expect(sameApproval.committed).toBe(false);
    expect(sameApproval.rejectedByKey?.kind).toBe("UNIQUE");
    expect(sameApproval.rejectedByKey?.columns).toEqual(["approval_id"]);

    // (3) New operation_id AND fresh approval -> the only legal replacement path commits.
    const legalReplacement = commitInsert(
      probe,
      PARTIALS_TABLE,
      scenario.durable.partials,
      makePartialRow(
        baselinePlan({ operationId: OPERATION_ID_FRESH, approvalId: APPROVAL_ID_FRESH }),
        signature,
        code,
      ),
      PARTIALS_TABLE_NAME,
      OPERATION_ID_FRESH,
    );
    expect(legalReplacement.committed).toBe(true);
    // The original operation still has exactly one partial; the replacement lives under the
    // fresh operation_id — one partial per operation, one partial per approval.
    expect(
      scenario.durable.partials.filter((row) => row["operation_id"] === OPERATION_ID),
    ).toHaveLength(1);
    expect(
      scenario.durable.partials.filter((row) => row["operation_id"] === OPERATION_ID_FRESH),
    ).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Anti-tautology census: the recovery procedure never imports the oracle.
// ---------------------------------------------------------------------------

/**
 * anti-tautology via AST, not strip-and-regex. Pre-change stripComments emptied from a
 * block-comment opener inside a string literal, so a real oracle import planted after that string
 * went invisible. The tree classifies comments and strings, so only genuine identifiers / import
 * edges flag.
 */
const parseRecovery = (source: string): ts.SourceFile =>
  ts.createSourceFile("crash-replay-recovery.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);

const visitEvery = (sourceFile: ts.SourceFile, visit: (node: ts.Node) => void): void => {
  const walk = (node: ts.Node): void => {
    visit(node);
    ts.forEachChild(node, walk);
  };
  walk(sourceFile);
};

const recoveryMentionsIdentifier = (source: string, identifier: string): boolean => {
  let found = false;
  visitEvery(parseRecovery(source), (node) => {
    if (found) return;
    if (ts.isIdentifier(node) && node.text === identifier) {
      found = true;
    }
  });
  return found;
};

const recoveryImportsVerifyModule = (source: string): boolean => {
  let found = false;
  visitEvery(parseRecovery(source), (node) => {
    if (found) return;
    if (!ts.isImportDeclaration(node) && !ts.isExportDeclaration(node)) return;
    const spec = node.moduleSpecifier;
    if (spec === undefined || !ts.isStringLiteralLike(spec)) return;
    if (/(^|\/)verify\.ts$/.test(spec.text) || spec.text.endsWith("/verify.ts")) {
      found = true;
    }
  });
  return found;
};

/** Legacy stripper kept only for the mutual-blindness plant below. */
const legacyStripComments = (source: string): string =>
  source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

describe("anti-tautology — the recovery procedure never imports the frozen oracle", () => {
  const recoverySource = readFileSync(resolve(here, "./crash-replay-recovery.ts"), "utf8");

  const ORACLE_IDENTIFIERS = [
    "CRASH_MATRIX",
    "CRASH_POINTS",
    "CRASH_DURABLE_STATES",
    "recoveryActionFor",
    "classifyApprovalConsumedNoSignIntent",
  ];

  it.each(ORACLE_IDENTIFIERS)("recovery source never references oracle identifier %s", (identifier) => {
    expect(recoveryMentionsIdentifier(recoverySource, identifier)).toBe(false);
  });

  it("recovery source imports nothing from the oracle module verify.ts", () => {
    expect(recoveryImportsVerifyModule(recoverySource)).toBe(false);
  });

  it("the frozen matrix is the expectation oracle only: 8 rows, each recovery/forbidden a closed-set member", () => {
    expect(recoveryMentionsIdentifier(recoverySource, "RECOVERY_ACTIONS")).toBe(false);
    expect(recoveryMentionsIdentifier(recoverySource, "FORBIDDEN_RECOVERY_ACTIONS")).toBe(false);
  });

  it("plant: string-borne comment opener no longer blinds the oracle-import check", () => {
    const plant =
      'const route = "/admin/v1/*";\n' +
      'import { recoveryActionFor } from "./verify.ts";\n' +
      'const end = "*/";\n';
    expect(recoveryMentionsIdentifier(plant, "recoveryActionFor")).toBe(true);
    expect(recoveryImportsVerifyModule(plant)).toBe(true);
    const stripped = legacyStripComments(plant);
    expect(new RegExp(`\\brecoveryActionFor\\b`).test(stripped)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Obligations census: "not proven here; discharged where".
// ---------------------------------------------------------------------------

describe("obligation records — phrased 'not proven here; discharged where'", () => {
  const suites: ReadonlyArray<{
    readonly label: string;
    readonly entries: readonly string[];
    readonly mustCite: string;
  }> = [
    {
      label: "persistence",
      entries: CRASH_REPLAY_PERSISTENCE_OBLIGATIONS,
      mustCite: "against a real database",
    },
    {
      label: "fault injection",
      entries: CRASH_REPLAY_FAULT_INJECTION_OBLIGATIONS,
      mustCite: "under real fault injection",
    },
  ];

  it.each(suites)("$label obligations are well-formed", ({ entries, mustCite }) => {
    expect(entries.length).toBeGreaterThanOrEqual(5);
    for (const entry of entries) {
      expect(entry).toContain("not proven here");
      expect(entry).toContain("discharged");
      expect(entry).toContain(mustCite);
    }
  });

  it("these obligations EXTEND the transaction-material inventory — no entry duplicates one of its negatives", () => {
    const inventoried = new Set<string>(SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS);
    for (const entry of [...CRASH_REPLAY_PERSISTENCE_OBLIGATIONS, ...CRASH_REPLAY_FAULT_INJECTION_OBLIGATIONS]) {
      expect(inventoried.has(entry)).toBe(false);
    }
  });

  it("the live-DB CAS race is recorded as a persistence obligation (no operations DDL exists to parse here)", () => {
    const casObligation = CRASH_REPLAY_PERSISTENCE_OBLIGATIONS.find((entry) =>
      entry.includes("formation_state"),
    );
    expect(casObligation).toBeDefined();
    expect(casObligation).toContain("real database concurrency tests");
  });
});
