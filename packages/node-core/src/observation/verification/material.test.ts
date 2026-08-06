// verification-material assembly acceptance tests.
// This suite asserts:
// 1. path_manifest_sha256 independently re-derived from returned path_manifest bytes
// 2. response never contains private key / vault ciphertext / TOTP / unrelated history
// 3. incomplete ancestor path → classification INDETERMINATE + correct reason
// 409/410 transitions live in packages/node-core/test/verification-material-endpoint.test.ts
// and packages/node-core/src/data/retention.test.ts.

import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  handleGetVerificationMaterial,
  VERIFICATION_MATERIAL_FIELD_KEYS,
  type VerificationMaterialSource,
} from "../../api/verification-material.js";
import { ACTION_EVIDENCE_ROLES } from "../../api/routes/action-routes.js";
import {
  DEFAULT_PROOF_ACCESS_WINDOW_MS,
  verificationMaterialAvailableUntilMs,
} from "../../data/retention.js";
import {
  asVerificationMaterialFields,
  assembleVerificationMaterial,
  assessAncestorProofCompleteness,
  computePathManifestSha256,
  containsForbiddenMaterial,
  EVIDENCE_ROLES,
  FORBIDDEN_MATERIAL_MARKERS,
  serializePathManifest,
  type AncestorProofInput,
  type PathManifestEntry,
  type VerificationMaterialInput,
} from "./material.js";

const SIG_A = `${"A".repeat(86)}==`;
const SIG_B = `${"B".repeat(86)}==`;
const SIG_C = `${"C".repeat(86)}==`;
function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// Body texts used by baseInput path — digests must match SHA-256 of exact UTF-8 text
// (integrity chain; assessAncestorProofCompleteness enforces).
const BODY_TEXT_A = `{"inner":{"amount":"1"},"step_1_signature":"${SIG_A}","step_2_signature":"${SIG_A}"}`;
const BODY_TEXT_B = `{"inner":{"amount":"1"},"step_1_signature":"${SIG_B}","step_2_signature":"${SIG_B}"}`;
const SHA_A = sha256Hex(BODY_TEXT_A);
const SHA_B = sha256Hex(BODY_TEXT_B);
const SHA_C = "c".repeat(64);
const PUB = `${"P".repeat(43)}=`;
const OP_ID = "22222222-2222-4222-8222-222222222222";
const TENANT = "tenant-a";
const REQUEST_ID = "11111111-1111-4111-8111-111111111111";
const TERMINAL_AT = Date.UTC(2026, 0, 1);

function pathEntry(
  position: number,
  step2: string,
  prev: string,
  sha: string,
  bodyIndex: number,
): PathManifestEntry {
  return {
    position,
    step_2_signature: step2,
    queried_wallet_previous_signature: prev,
    transaction_sha256: sha,
    body_index: bodyIndex,
  };
}

function baseInput(
  over: Partial<VerificationMaterialInput> = {},
): VerificationMaterialInput {
  const path: readonly PathManifestEntry[] = [
    pathEntry(0, SIG_A, "", SHA_A, 0),
    pathEntry(1, SIG_B, SIG_A, SHA_B, 1),
  ];
  const ancestor: AncestorProofInput = {
    evidence_role: "SOURCE",
    wallet_public_key: PUB,
    classification: "EXPECTED_ANCESTOR",
    expected_step_2_signature: SIG_A,
    fresh_head_step_2_signature: SIG_B,
    fresh_head_transaction_sha256: SHA_B,
    path_manifest: path,
    transaction_bodies: [
      {
        body_index: 0,
        transaction_sha256: SHA_A,
        settled_transaction_text: BODY_TEXT_A,
      },
      {
        body_index: 1,
        transaction_sha256: SHA_B,
        settled_transaction_text: BODY_TEXT_B,
      },
    ],
    indeterminate_reason: null,
  };

  return {
    operation_type: "MOVE_INTERNAL",
    state: "INTERNAL_MOVE_LANDED",
    landed_attempt_no: 1,
    expected_artifact: {
      key_id: "33333333-3333-4333-8333-333333333333",
      preimage_text: '{"purpose":"zp-move-internal-expected-v1"}',
      preimage_sha256: SHA_C,
      signature: SIG_C,
    },
    observation_evidence: [
      {
        evidence_role: "SOURCE",
        wallet_id: "44444444-4444-4444-8444-444444444444",
        wallet_public_key: PUB,
        t0: {
          observation_id: "55555555-5555-4555-8555-555555555555",
          projection: { s: SIG_A, p: "", b_zkz: "10" },
        },
        terminal: {
          observation_id: "66666666-6666-4666-8666-666666666666",
          projection: { s: SIG_B, p: SIG_A, b_zkz: "4.5" },
        },
        node_observation_raw_body_base64: Buffer.from('{"observed":true}').toString("base64"),
      },
    ],
    attempts: [
      {
        attempt_no: 1,
        classification: "LANDED_VERIFIED",
        transaction: {
          inner_preimage_text: '{"type":"unique_combinable","version":"2"}',
          inner_sha256: SHA_A,
          step_1_signature: SIG_A,
          step_2_preimage_text: `{"inner":{},"step_1_signature":"${SIG_A}"}`,
          step_2_signature: SIG_B,
          settled_transaction_text: `{"inner":{},"step_1_signature":"${SIG_A}","step_2_signature":"${SIG_B}"}`,
        },
      },
    ],
    ancestor_proofs: [ancestor],
    ...over,
  };
}

describe("assembleVerificationMaterial — shape", () => {
  it("emits the frozen field sequence between operation_type and ancestor_proofs", () => {
    const payload = assembleVerificationMaterial(baseInput());
    expect(Object.keys(payload)).toEqual([
      "operation_type",
      "state",
      "landed_attempt_no",
      "expected_artifact",
      "observation_evidence",
      "attempts",
      "ancestor_proofs",
    ]);
    expect(Object.keys(payload.expected_artifact)).toEqual([
      "key_id",
      "preimage_text",
      "preimage_sha256",
      "signature",
    ]);
    expect(Object.keys(payload.ancestor_proofs[0]!)).toEqual([
      "evidence_role",
      "wallet_public_key",
      "classification",
      "expected_step_2_signature",
      "fresh_head_step_2_signature",
      "fresh_head_transaction_sha256",
      "hop_count",
      "path_manifest_sha256",
      "path_manifest",
      "transaction_bodies",
      "indeterminate_reason",
    ]);
    expect(Object.keys(payload.ancestor_proofs[0]!.path_manifest[0]!)).toEqual([
      "position",
      "step_2_signature",
      "queried_wallet_previous_signature",
      "transaction_sha256",
      "body_index",
    ]);
  });

  it("preserves exact transaction text without re-serialization", () => {
    const exact = `{"inner":{"type":"unique_combinable","version":"2","amount":"1.00"},"step_1_signature":"${SIG_A}","step_2_signature":"${SIG_B}"}`;
    const input = baseInput();
    const attempts = [
      {
        ...input.attempts[0]!,
        transaction: {
          ...input.attempts[0]!.transaction,
          settled_transaction_text: exact,
        },
      },
    ];
    const payload = assembleVerificationMaterial({ ...input, attempts });
    expect(payload.attempts[0]!.transaction.settled_transaction_text).toBe(exact);
    expect(payload.ancestor_proofs[0]!.transaction_bodies[0]!.settled_transaction_text).toBe(
      input.ancestor_proofs[0]!.transaction_bodies[0]!.settled_transaction_text,
    );
  });

  it("sorts attempts by attempt_no ascending", () => {
    const input = baseInput({
      attempts: [
        {
          attempt_no: 2,
          classification: "LANDED_VERIFIED",
          transaction: baseInput().attempts[0]!.transaction,
        },
        {
          attempt_no: 1,
          classification: "PROVEN_NON_LANDED",
          transaction: baseInput().attempts[0]!.transaction,
        },
      ],
    });
    const payload = assembleVerificationMaterial(input);
    expect(payload.attempts.map((a) => a.attempt_no)).toEqual([1, 2]);
  });

  it("sets hop_count = path length - 1 (exact head is 0)", () => {
    const singleBodyText = BODY_TEXT_A;
    const singleSha = SHA_A;
    const single = baseInput({
      ancestor_proofs: [
        {
          ...baseInput().ancestor_proofs[0]!,
          classification: "EXPECTED_AT_HEAD",
          expected_step_2_signature: SIG_A,
          fresh_head_step_2_signature: SIG_A,
          fresh_head_transaction_sha256: singleSha,
          path_manifest: [pathEntry(0, SIG_A, "", singleSha, 0)],
          transaction_bodies: [
            {
              body_index: 0,
              transaction_sha256: singleSha,
              settled_transaction_text: singleBodyText,
            },
          ],
          indeterminate_reason: null,
        },
      ],
    });
    expect(assembleVerificationMaterial(single).ancestor_proofs[0]!.hop_count).toBe(0);
    expect(assembleVerificationMaterial(baseInput()).ancestor_proofs[0]!.hop_count).toBe(1);
  });
});

describe("path_manifest_sha256 — independent re-derivation (ticket review indicator)", () => {
  it("matches SHA-256 of UTF-8 JSON.stringify(path_manifest) with property ordering", () => {
    const payload = assembleVerificationMaterial(baseInput());
    const proof = payload.ancestor_proofs[0]!;

    // Independent re-derivation outside the node — same algorithm a consumer runs.
    const rederived = createHash("sha256")
      .update(JSON.stringify(proof.path_manifest), "utf8")
      .digest("hex");

    expect(proof.path_manifest_sha256).toBe(rederived);
    expect(proof.path_manifest_sha256).toBe(computePathManifestSha256(proof.path_manifest));
    expect(serializePathManifest(proof.path_manifest)).toBe(JSON.stringify(proof.path_manifest));
  });

  it("changes when property ordering would differ (byte-exact contract)", () => {
    const entries = [pathEntry(0, SIG_A, "", SHA_A, 0)];
    const canonical = serializePathManifest(entries);
    // Deliberately reordered keys — same values, different bytes → different digest.
    const reordered = JSON.stringify([
      {
        body_index: 0,
        transaction_sha256: SHA_A,
        queried_wallet_previous_signature: "",
        step_2_signature: SIG_A,
        position: 0,
      },
    ]);
    expect(canonical).not.toBe(reordered);
    expect(createHash("sha256").update(canonical, "utf8").digest("hex")).not.toBe(
      createHash("sha256").update(reordered, "utf8").digest("hex"),
    );
  });
});

describe("INDETERMINATE ancestor paths (ticket review indicator)", () => {
  const reasons = [
    "MISSING_BODY",
    "LINK_GAP",
    "ANOMALY",
    "FRESH_HEAD_MISMATCH",
    "BUDGET_EXCEEDED",
  ] as const;

  it.each(reasons)(
    "classification INDETERMINATE with reason %s carries diagnostic-only bodies",
    (reason) => {
      const input = baseInput({
        ancestor_proofs: [
          {
            evidence_role: "SOURCE",
            wallet_public_key: PUB,
            classification: "INDETERMINATE",
            expected_step_2_signature: SIG_A,
            fresh_head_step_2_signature: SIG_C,
            fresh_head_transaction_sha256: SHA_C,
            // Diagnostic prefix only — not a landing/non-landing claim.
            path_manifest: [pathEntry(0, SIG_A, "", SHA_A, 0)],
            transaction_bodies: [
              {
                body_index: 0,
                transaction_sha256: SHA_A,
                settled_transaction_text: '{"diagnostic":true}',
              },
            ],
            indeterminate_reason: reason,
          },
        ],
      });
      const proof = assembleVerificationMaterial(input).ancestor_proofs[0]!;
      expect(proof.classification).toBe("INDETERMINATE");
      expect(proof.indeterminate_reason).toBe(reason);
      // Must not claim EXPECTED_ANCESTOR / EXPECTED_AT_HEAD.
      expect(proof.classification).not.toBe("EXPECTED_ANCESTOR");
      expect(proof.classification).not.toBe("EXPECTED_AT_HEAD");
    },
  );

  it("rejects INDETERMINATE without a reason", () => {
    expect(() =>
      assembleVerificationMaterial(
        baseInput({
          ancestor_proofs: [
            {
              ...baseInput().ancestor_proofs[0]!,
              classification: "INDETERMINATE",
              indeterminate_reason: null,
            },
          ],
        }),
      ),
    ).toThrow(/indeterminate_reason/);
  });

  it("rejects determinate classification with a non-null reason", () => {
    expect(() =>
      assembleVerificationMaterial(
        baseInput({
          ancestor_proofs: [
            {
              ...baseInput().ancestor_proofs[0]!,
              classification: "EXPECTED_ANCESTOR",
              indeterminate_reason: "LINK_GAP",
            },
          ],
        }),
      ),
    ).toThrow(/indeterminate_reason/);
  });

  it("permits empty path_manifest/bodies for INDETERMINATE", () => {
    const proof = assembleVerificationMaterial(
      baseInput({
        ancestor_proofs: [
          {
            evidence_role: "RECEIVER",
            wallet_public_key: PUB,
            classification: "INDETERMINATE",
            expected_step_2_signature: SIG_A,
            fresh_head_step_2_signature: SIG_A,
            fresh_head_transaction_sha256: SHA_A,
            path_manifest: [],
            transaction_bodies: [],
            indeterminate_reason: "MISSING_BODY",
          },
        ],
      }),
    ).ancestor_proofs[0]!;
    expect(proof.path_manifest).toEqual([]);
    expect(proof.transaction_bodies).toEqual([]);
    expect(proof.hop_count).toBe(0);
    expect(proof.path_manifest_sha256).toBe(
      createHash("sha256").update("[]", "utf8").digest("hex"),
    );
  });

  // Assembler must DETECT incompleteness — not trust caller labels.
  it("forces INDETERMINATE/MISSING_BODY for EXPECTED_ANCESTOR with empty bodies + dangling body_index", () => {
    const broken: AncestorProofInput = {
      evidence_role: "SOURCE",
      wallet_public_key: PUB,
      classification: "EXPECTED_ANCESTOR",
      expected_step_2_signature: SIG_A,
      fresh_head_step_2_signature: SIG_B,
      fresh_head_transaction_sha256: SHA_B,
      path_manifest: [pathEntry(0, SIG_A, "", SHA_A, 99)], // dangling body_index
      transaction_bodies: [], // empty
      indeterminate_reason: null,
    };
    expect(assessAncestorProofCompleteness(broken).missingBody).toBe(true);
    const proof = assembleVerificationMaterial(
      baseInput({ ancestor_proofs: [broken] }),
    ).ancestor_proofs[0]!;
    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("MISSING_BODY");
  });

  it("forces INDETERMINATE/LINK_GAP when predecessor chain is broken", () => {
    const broken: AncestorProofInput = {
      ...baseInput().ancestor_proofs[0]!,
      path_manifest: [
        pathEntry(0, SIG_A, "", SHA_A, 0),
        pathEntry(1, SIG_B, SIG_C /* wrong prev */, SHA_B, 1),
      ],
    };
    expect(assessAncestorProofCompleteness(broken).linkGap).toBe(true);
    const proof = assembleVerificationMaterial(
      baseInput({ ancestor_proofs: [broken] }),
    ).ancestor_proofs[0]!;
    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("LINK_GAP");
  });

  it("forces INDETERMINATE/ANOMALY when body hash disagrees with manifest", () => {
    // Pure field disagreement: body.transaction_sha256 still equals sha256(text)
    // (so the integrity chain is intact) but differs from the manifest entry.
    // Digest-vs-text corruption is LINK_GAP (see body-text digest test below).
    const base = baseInput().ancestor_proofs[0]!;
    const altText = '{"alt":true,"for":"anomaly-field-mismatch"}';
    const altSha = sha256Hex(altText);
    const broken: AncestorProofInput = {
      ...base,
      transaction_bodies: [
        {
          body_index: 0,
          transaction_sha256: altSha, // matches its own text…
          settled_transaction_text: altText,
        }, // …but not the manifest entry at position 0 (still SHA_A)
        base.transaction_bodies[1]!,
      ],
    };
    expect(assessAncestorProofCompleteness(broken).anomaly).toBe(true);
    expect(assessAncestorProofCompleteness(broken).linkGap).toBe(false);
    const proof = assembleVerificationMaterial(
      baseInput({ ancestor_proofs: [broken] }),
    ).ancestor_proofs[0]!;
    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("ANOMALY");
  });

  it("forces INDETERMINATE/LINK_GAP when sha256(settled_transaction_text) ≠ transaction_sha256", () => {
    // / integrity chain: corrupted lineage_path_bodies row.
    const base = baseInput().ancestor_proofs[0]!;
    const broken: AncestorProofInput = {
      ...base,
      transaction_bodies: [
        {
          ...base.transaction_bodies[0]!,
          // Keep transaction_sha256 === manifest entry (SHA_A) but rewrite text.
          settled_transaction_text: BODY_TEXT_A.replace("amount", "TAMPERED"),
        },
        base.transaction_bodies[1]!,
      ],
    };
    expect(assessAncestorProofCompleteness(broken).linkGap).toBe(true);
    const proof = assembleVerificationMaterial(
      baseInput({ ancestor_proofs: [broken] }),
    ).ancestor_proofs[0]!;
    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("LINK_GAP");
    expect(proof.classification).not.toBe("EXPECTED_ANCESTOR");
  });

  it("forces INDETERMINATE/FRESH_HEAD_MISMATCH when last hop != fresh head anchors", () => {
    const broken: AncestorProofInput = {
      ...baseInput().ancestor_proofs[0]!,
      fresh_head_step_2_signature: SIG_C,
      fresh_head_transaction_sha256: SHA_C,
    };
    expect(assessAncestorProofCompleteness(broken).freshHeadMismatch).toBe(true);
    const proof = assembleVerificationMaterial(
      baseInput({ ancestor_proofs: [broken] }),
    ).ancestor_proofs[0]!;
    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("FRESH_HEAD_MISMATCH");
  });

  it("forces INDETERMINATE/ANOMALY for unreferenced extra bodies (padded history)", () => {
    const base = baseInput().ancestor_proofs[0]!;
    const padded: AncestorProofInput = {
      ...base,
      transaction_bodies: [
        ...base.transaction_bodies,
        {
          body_index: 99,
          transaction_sha256: SHA_C,
          settled_transaction_text: '{"unrelated":true}',
        },
      ],
    };
    expect(assessAncestorProofCompleteness(padded).anomaly).toBe(true);
    const proof = assembleVerificationMaterial(
      baseInput({ ancestor_proofs: [padded] }),
    ).ancestor_proofs[0]!;
    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("ANOMALY");
  });
});

describe("evidence_role vocabulary lock (break D1)", () => {
  it("matches + action-routes ACTION_EVIDENCE_ROLES exactly", () => {
    expect([...EVIDENCE_ROLES]).toEqual([...ACTION_EVIDENCE_ROLES]);
    expect(EVIDENCE_ROLES).toContain("EXTERNAL_DESTINATION_PARTIAL");
    expect(EVIDENCE_ROLES as readonly string[]).not.toContain("EXTERNAL_DESTINATION_LOOKUP");
  });
});

describe("exclusion — no custody material (ticket review indicator)", () => {
  it("assembled payload never contains private key, vault ciphertext, or TOTP markers", () => {
    const payload = assembleVerificationMaterial(baseInput());
    const serialized = JSON.stringify(payload);
    expect(containsForbiddenMaterial(serialized)).toBe(false);
    for (const marker of FORBIDDEN_MATERIAL_MARKERS) {
      expect(serialized).not.toContain(marker);
    }
  });

  it("exposes only the operation path — not unrelated wallet history", () => {
    const payload = assembleVerificationMaterial(baseInput());
    // Only the two bodies on the declared path, never a pre-expected transaction.
    const bodies = payload.ancestor_proofs[0]!.transaction_bodies;
    expect(bodies).toHaveLength(2);
    expect(bodies.map((b) => b.body_index)).toEqual([0, 1]);
    // path starts at expected tx position 0 — no negative positions, no branch keys.
    for (const entry of payload.ancestor_proofs[0]!.path_manifest) {
      expect(entry.position).toBeGreaterThanOrEqual(0);
    }
    const keys = JSON.stringify(payload);
    expect(keys).not.toMatch(/unrelated|branch_history|wallet_history|full_history/i);
  });

  it("detects accidental custody leakage in a hostile input", () => {
    const hostile = baseInput({
      expected_artifact: {
        key_id: "k",
        preimage_text: "x",
        preimage_sha256: SHA_A,
        // Hostile accidental leak in a free-text field — the scan must catch it.
        signature: "private_key=leak",
      },
    });
    const serialized = JSON.stringify(assembleVerificationMaterial(hostile));
    expect(containsForbiddenMaterial(serialized)).toBe(true);
  });
});

describe("end-to-end with GET verification-material handler (409/200/410)", () => {
  // Confirms the assembler payload slots into the existing transport edge without reshaping.
  const until = verificationMaterialAvailableUntilMs(TERMINAL_AT, DEFAULT_PROOF_ACCESS_WINDOW_MS);
  const material = asVerificationMaterialFields(assembleVerificationMaterial(baseInput()));

  const source: VerificationMaterialSource = {
    load: async (operationId, tenantId) =>
      operationId === OP_ID && tenantId === TENANT
        ? {
            kind: "MOVE_INTERNAL",
            status: "INTERNAL_MOVE_LANDED",
            verificationMaterialAvailableUntilMs: until,
            material,
          }
        : null,
  };

  const get = (nowMs: number) =>
    handleGetVerificationMaterial(
      { requestId: REQUEST_ID, operationId: OP_ID, tenantId: TENANT, nowMs },
      source,
    );

  it("200 serves assembled material with independent path_manifest_sha256", async () => {
    const result = await get(TERMINAL_AT + 1);
    expect(result.status).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.operation_id).toBe(OP_ID);
    expect(body.operation_type).toBe("MOVE_INTERNAL");
    expect(body.ancestor_proofs[0].path_manifest_sha256).toBe(
      createHash("sha256")
        .update(JSON.stringify(body.ancestor_proofs[0].path_manifest), "utf8")
        .digest("hex"),
    );
    expect(containsForbiddenMaterial(result.body)).toBe(false);
    expect(body.available_until).toBe(new Date(until).toISOString());
  });

  it("409 when not at landed terminal (material not ready)", async () => {
    const notReady: VerificationMaterialSource = {
      load: async () => ({
        kind: "MOVE_INTERNAL",
        status: "CREATED",
        verificationMaterialAvailableUntilMs: null,
        material, // unused on the 409 path
      }),
    };
    const result = await handleGetVerificationMaterial(
      { requestId: REQUEST_ID, operationId: OP_ID, tenantId: TENANT, nowMs: TERMINAL_AT },
      notReady,
    );
    expect(result.status).toBe(409);
    expect(JSON.parse(result.body).error.code).toBe("verification_material_not_ready");
  });

  it("410 after the access window expires", async () => {
    const result = await get(until);
    expect(result.status).toBe(410);
    expect(JSON.parse(result.body).error.code).toBe("verification_material_expired");
  });

  // Allowlisted body builder — material cannot forge operation_id or inject keys.
  it("buildBody drops unknown material keys and refuses forged operation_id", async () => {
    const hostile: VerificationMaterialSource = {
      load: async () => ({
        kind: "MOVE_INTERNAL",
        status: "INTERNAL_MOVE_LANDED",
        verificationMaterialAvailableUntilMs: until,
        material: {
          ...material,
          operation_id: "forged-op",
          private_key: "should-never-appear",
          vault_ciphertext: "nope",
          extra_wallet_history: [{ sig: "x" }],
        },
      }),
    };
    const result = await handleGetVerificationMaterial(
      { requestId: REQUEST_ID, operationId: OP_ID, tenantId: TENANT, nowMs: TERMINAL_AT + 1 },
      hostile,
    );
    expect(result.status).toBe(200);
    const body = JSON.parse(result.body) as Record<string, unknown>;
    expect(body.operation_id).toBe(OP_ID);
    expect(body.operation_id).not.toBe("forged-op");
    expect(body).not.toHaveProperty("private_key");
    expect(body).not.toHaveProperty("vault_ciphertext");
    expect(body).not.toHaveProperty("extra_wallet_history");
    expect(Object.keys(body)).toEqual([
      "operation_id",
      ...VERIFICATION_MATERIAL_FIELD_KEYS,
      "available_until",
    ]);
    expect(containsForbiddenMaterial(result.body)).toBe(false);
  });
});
