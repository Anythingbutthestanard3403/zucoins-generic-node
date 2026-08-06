// durable-table assembly for GET verification-material.
//
// This suite asserts:
// 1. key set + ordering end-to-end through table port → assembler → HTTP binder
// 2. path_manifest_sha256 independently recomputed from returned path_manifest
// 3. INDETERMINATE suppresses authoritative landing (diagnostic bodies only / empty)
// 4. attempts ordered by attempt_no; multi-attempt rebuilt-move keeps archived
// non-landed attempts alongside the landed one
// 5. 409 not ready / 410 expired (access-window gate) / 404 cross-tenant
// 6. node_observation_raw_body_base64 present; wallet_id null for external keys
// 7. evidence_role closed set includes EXTERNAL_* when seeded

import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createGatedTableVerificationMaterialSource,
  createTableBackedVerificationMaterialSource,
} from "../../api/verification-material-source.js";
import { handleGetVerificationMaterial } from "../../api/verification-material.js";
import {
  InMemoryVerificationAccessWindowStore,
  issueVerificationAccessWindow,
} from "../../api/verification-access.js";
import { verificationMaterialAvailableUntilMs } from "../../data/retention.js";
import {
  assembleVerificationMaterialFromTables,
  createInMemoryVerificationMaterialTables,
  mapLineageBodiesToManifest,
  mapLineageVerdictToClassification,
  type DurableAttemptRow,
  type DurableLineagePathRow,
  type DurableObservationEvidenceRow,
  type DurableOperationHeader,
  type VerificationMaterialTablePort,
} from "./source.js";

const SIG_A = `${"A".repeat(86)}==`;
const SIG_B = `${"B".repeat(86)}==`;
const SIG_C = `${"C".repeat(86)}==`;

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// Declared after TX0/TX1 below — placeholders replaced once TX constants exist.
let SHA_A = "a".repeat(64);
let SHA_B = "b".repeat(64);
const SHA_C = "c".repeat(64);
const PUB_SRC = `${"S".repeat(43)}=`;
const PUB_DST = `${"D".repeat(43)}=`;
const OP = "22222222-2222-4222-8222-222222222222";
const OP2 = "33333333-3333-4333-8333-333333333333";
const TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const KEY = "44444444-4444-4444-8444-444444444444";
const WALLET_SRC = "55555555-5555-4555-8555-555555555555";
const REQUEST = "11111111-1111-4111-8111-111111111111";
const TERMINAL_AT = Date.UTC(2026, 0, 1);
const UNTIL = verificationMaterialAvailableUntilMs(TERMINAL_AT);

const TX0 = `{"inner":{"v":1},"step_1_signature":"${SIG_A}","step_2_signature":"${SIG_A}"}`;
const TX1 = `{"inner":{"v":1},"step_1_signature":"${SIG_B}","step_2_signature":"${SIG_B}"}`;
SHA_A = sha256Hex(TX0);
SHA_B = sha256Hex(TX1);
const RAW_B64 = Buffer.from('{"node_observed":true,"note":"non-authoritative"}').toString(
  "base64",
);

function header(over: Partial<DurableOperationHeader> = {}): DurableOperationHeader {
  return {
    id: OP,
    implementer_id: TENANT,
    kind: "MOVE_INTERNAL",
    status: "INTERNAL_MOVE_LANDED",
    verification_material_available_until_ms: UNTIL,
    landed_attempt_no: 2,
    ...over,
  };
}

function artifact() {
  return {
    signing_key_id: KEY,
    preimage_text: '{"purpose":"zp-move-internal-expected-v1"}',
    preimage_sha256: SHA_C,
    signature: SIG_C,
  } as const;
}

function obsSource(): DurableObservationEvidenceRow {
  return {
    evidence_role: "SOURCE",
    wallet_id: WALLET_SRC,
    wallet_public_key: PUB_SRC,
    t0: {
      id: "66666666-6666-4666-8666-666666666666",
      wallet_id: WALLET_SRC,
      wallet_public_key: PUB_SRC,
      s_signature: SIG_A,
      p_signature: "",
      b_amount: "10",
      raw_response_body_base64: RAW_B64,
    },
    terminal: {
      id: "77777777-7777-4777-8777-777777777777",
      wallet_id: WALLET_SRC,
      wallet_public_key: PUB_SRC,
      s_signature: SIG_B,
      p_signature: SIG_A,
      b_amount: "4.5",
      raw_response_body_base64: RAW_B64,
    },
  };
}

function obsExternalPartial(): DurableObservationEvidenceRow {
  return {
    evidence_role: "EXTERNAL_DESTINATION_PARTIAL",
    wallet_id: null, // externally owned key
    wallet_public_key: PUB_DST,
    t0: {
      id: "88888888-8888-4888-8888-888888888888",
      wallet_id: null,
      wallet_public_key: PUB_DST,
      s_signature: "",
      p_signature: "",
      b_amount: "0",
      raw_response_body_base64: Buffer.from("{}").toString("base64"),
    },
    terminal: null, // formation-only
  };
}

function multiAttempts(): readonly DurableAttemptRow[] {
  // Rebuilt move: archived positively-proven-non-landed attempt 1 + landed attempt 2.
  return [
    {
      attempt_no: 2,
      classification: "LANDED_VERIFIED",
      inner_preimage_text: '{"attempt":2}',
      inner_sha256: SHA_B,
      step_1_signature: SIG_B,
      step_2_preimage_text: `{"inner":{"attempt":2},"step_1_signature":"${SIG_B}"}`,
      step_2_signature: SIG_B,
      settled_transaction_text: TX1,
    },
    {
      attempt_no: 1,
      classification: "PROVEN_NOT_LANDED",
      inner_preimage_text: '{"attempt":1}',
      inner_sha256: SHA_A,
      step_1_signature: SIG_A,
      step_2_preimage_text: `{"inner":{"attempt":1},"step_1_signature":"${SIG_A}"}`,
      step_2_signature: SIG_A,
      settled_transaction_text: TX0,
    },
  ];
}

function landedPath(): DurableLineagePathRow {
  return {
    path_role: "SOURCE",
    wallet_public_key: PUB_SRC,
    verdict: "LANDED_COMPLETE_PATH",
    expected_step_2_signature: SIG_A,
    fresh_head_step_2_signature: SIG_B,
    fresh_head_transaction_sha256: SHA_B,
    bodies: [
      {
        path_index: 0,
        step_2_signature: SIG_A,
        p_signature: "",
        completed_transaction_sha256: SHA_A,
        completed_transaction_text: TX0,
      },
      {
        path_index: 1,
        step_2_signature: SIG_B,
        p_signature: SIG_A,
        completed_transaction_sha256: SHA_B,
        completed_transaction_text: TX1,
      },
    ],
    indeterminate_reason: null,
  };
}

function seedFull() {
  return createInMemoryVerificationMaterialTables({
    operations: [header()],
    artifacts: [[OP, artifact()]],
    observations: [[OP, [obsSource(), obsExternalPartial()]]],
    attempts: [[OP, multiAttempts()]],
    paths: [[OP, [landedPath()]]],
  });
}

function bindSource(port: VerificationMaterialTablePort) {
  return createTableBackedVerificationMaterialSource({
    port,
    assemble: assembleVerificationMaterialFromTables as never,
    loadOperation: (operationId, implementerId) => port.loadOperation(operationId, implementerId),
  });
}

describe("mapLineageVerdictToClassification", () => {
  it("maps LANDED_EXACT → EXPECTED_AT_HEAD and LANDED_COMPLETE_PATH → EXPECTED_ANCESTOR", () => {
    expect(mapLineageVerdictToClassification("LANDED_EXACT", 1)).toEqual({
      classification: "EXPECTED_AT_HEAD",
      indeterminate_reason: null,
    });
    expect(mapLineageVerdictToClassification("LANDED_COMPLETE_PATH", 2)).toEqual({
      classification: "EXPECTED_ANCESTOR",
      indeterminate_reason: null,
    });
  });

  it("maps INDETERMINATE / unknown to INDETERMINATE with a named reason", () => {
    expect(mapLineageVerdictToClassification("INDETERMINATE", 0).classification).toBe(
      "INDETERMINATE",
    );
    expect(mapLineageVerdictToClassification("INDETERMINATE", 0).indeterminate_reason).toBe(
      "MISSING_BODY",
    );
    expect(mapLineageVerdictToClassification("INVARIANT_BREACH", 2).indeterminate_reason).toBe(
      "ANOMALY",
    );
    expect(mapLineageVerdictToClassification("NOPE", 1).classification).toBe("INDETERMINATE");
  });
});

describe("mapLineageBodiesToManifest — path_index ordering", () => {
  it("sorts by path_index and preserves durable path_index as position/body_index", () => {
    const { path_manifest, transaction_bodies } = mapLineageBodiesToManifest([
      {
        path_index: 1,
        step_2_signature: SIG_B,
        p_signature: SIG_A,
        completed_transaction_sha256: SHA_B,
        completed_transaction_text: TX1,
      },
      {
        path_index: 0,
        step_2_signature: SIG_A,
        p_signature: "",
        completed_transaction_sha256: SHA_A,
        completed_transaction_text: TX0,
      },
    ]);
    expect(path_manifest.map((e) => e.position)).toEqual([0, 1]);
    expect(path_manifest.map((e) => e.body_index)).toEqual([0, 1]);
    expect(path_manifest[0]!.step_2_signature).toBe(SIG_A);
    expect(path_manifest[1]!.queried_wallet_previous_signature).toBe(SIG_A);
    expect(transaction_bodies.map((b) => b.body_index)).toEqual([0, 1]);
    expect(Object.keys(path_manifest[0]!)).toEqual([
      "position",
      "step_2_signature",
      "queried_wallet_previous_signature",
      "transaction_sha256",
      "body_index",
    ]);
  });

  it("preserves gapped durable path_index (does not dense-renumber {0,2} → {0,1})", () => {
    const { path_manifest, transaction_bodies } = mapLineageBodiesToManifest([
      {
        path_index: 0,
        step_2_signature: SIG_A,
        p_signature: "",
        completed_transaction_sha256: SHA_A,
        completed_transaction_text: TX0,
      },
      {
        path_index: 2,
        step_2_signature: SIG_B,
        // Forged contiguous backlink — would look complete if renumbered to position 1.
        p_signature: SIG_A,
        completed_transaction_sha256: SHA_B,
        completed_transaction_text: TX1,
      },
    ]);
    expect(path_manifest.map((e) => e.position)).toEqual([0, 2]);
    expect(path_manifest.map((e) => e.body_index)).toEqual([0, 2]);
    expect(transaction_bodies.map((b) => b.body_index)).toEqual([0, 2]);
  });
});

describe("assembleVerificationMaterialFromTables — from durable rows", () => {
  it("assembles full MOVE_INTERNAL bundle with multi-attempt ordering and ancestor proofs", async () => {
    const port = seedFull();
    const result = await assembleVerificationMaterialFromTables(port, OP, TENANT);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const material = result.row.material;
    expect(Object.keys(material)).toEqual([
      "operation_type",
      "state",
      "landed_attempt_no",
      "expected_artifact",
      "observation_evidence",
      "attempts",
      "ancestor_proofs",
    ]);
    expect(material.operation_type).toBe("MOVE_INTERNAL");
    expect(material.landed_attempt_no).toBe(2);

    const artifact = material.expected_artifact as { key_id: string };
    expect(artifact.key_id).toBe(KEY); // signing_key_id → key_id

    const attempts = material.attempts as Array<{ attempt_no: number; classification: string }>;
    expect(attempts.map((a) => a.attempt_no)).toEqual([1, 2]); // sorted ascending
    expect(attempts[0]!.classification).toBe("PROVEN_NOT_LANDED");
    expect(attempts[1]!.classification).toBe("LANDED_VERIFIED");

    const obs = material.observation_evidence as Array<{
      evidence_role: string;
      wallet_id: string | null;
      node_observation_raw_body_base64: string;
      terminal: unknown;
    }>;
    expect(obs).toHaveLength(2);
    expect(obs[0]!.evidence_role).toBe("SOURCE");
    expect(obs[0]!.wallet_id).toBe(WALLET_SRC);
    expect(obs[0]!.node_observation_raw_body_base64).toBe(RAW_B64);
    expect(obs[1]!.evidence_role).toBe("EXTERNAL_DESTINATION_PARTIAL");
    expect(obs[1]!.wallet_id).toBeNull();
    expect(obs[1]!.terminal).toBeNull();

    const proofs = material.ancestor_proofs as Array<{
      evidence_role: string;
      classification: string;
      hop_count: number;
      path_manifest_sha256: string;
      path_manifest: Array<Record<string, unknown>>;
      transaction_bodies: Array<Record<string, unknown>>;
      indeterminate_reason: string | null;
      expected_step_2_signature: string;
      fresh_head_step_2_signature: string;
      fresh_head_transaction_sha256: string;
      wallet_public_key: string;
    }>;
    expect(proofs).toHaveLength(1);
    expect(proofs[0]!.evidence_role).toBe("SOURCE");
    expect(proofs[0]!.classification).toBe("EXPECTED_ANCESTOR");
    expect(proofs[0]!.hop_count).toBe(1);
    expect(proofs[0]!.indeterminate_reason).toBeNull();
    expect(proofs[0]!.wallet_public_key).toBe(PUB_SRC);
    expect(proofs[0]!.expected_step_2_signature).toBe(SIG_A);
    expect(proofs[0]!.fresh_head_step_2_signature).toBe(SIG_B);
    expect(proofs[0]!.fresh_head_transaction_sha256).toBe(SHA_B);
    expect(Object.keys(proofs[0]!)).toEqual([
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

    // Independent recompute of path_manifest_sha256 (review indicator).
    const rederived = createHash("sha256")
      .update(JSON.stringify(proofs[0]!.path_manifest), "utf8")
      .digest("hex");
    expect(proofs[0]!.path_manifest_sha256).toBe(rederived);
    expect(proofs[0]!.path_manifest).toHaveLength(2);
    expect(proofs[0]!.transaction_bodies).toHaveLength(2);
  });

  it("cross-tenant collapses to not_found", async () => {
    const port = seedFull();
    const result = await assembleVerificationMaterialFromTables(port, OP, OTHER);
    expect(result).toEqual({ ok: false, reason: "not_found" });
  });

  it("missing artifact returns missing_artifact", async () => {
    const port = createInMemoryVerificationMaterialTables({
      operations: [header()],
    });
    const result = await assembleVerificationMaterialFromTables(port, OP, TENANT);
    expect(result).toEqual({ ok: false, reason: "missing_artifact" });
  });

  it("INDETERMINATE path with empty bodies cannot read as a landing verdict", async () => {
    const port = createInMemoryVerificationMaterialTables({
      operations: [header({ landed_attempt_no: null })],
      artifacts: [[OP, artifact()]],
      observations: [[OP, [obsSource()]]],
      attempts: [
        [
          OP,
          [
            {
              attempt_no: 1,
              classification: "INDETERMINATE",
              inner_preimage_text: "{}",
              inner_sha256: SHA_A,
              step_1_signature: SIG_A,
              step_2_preimage_text: "{}",
              step_2_signature: SIG_A,
              settled_transaction_text: "",
            },
          ],
        ],
      ],
      paths: [
        [
          OP,
          [
            {
              path_role: "SOURCE",
              wallet_public_key: PUB_SRC,
              verdict: "INDETERMINATE",
              expected_step_2_signature: SIG_A,
              fresh_head_step_2_signature: SIG_A,
              fresh_head_transaction_sha256: SHA_A,
              bodies: [],
              indeterminate_reason: "MISSING_BODY",
            },
          ],
        ],
      ],
    });

    const result = await assembleVerificationMaterialFromTables(port, OP, TENANT);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const proof = (
      result.row.material.ancestor_proofs as Array<{
        classification: string;
        path_manifest: unknown[];
        transaction_bodies: unknown[];
        indeterminate_reason: string | null;
        hop_count: number;
      }>
    )[0]!;
    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("MISSING_BODY");
    expect(proof.path_manifest).toEqual([]);
    expect(proof.transaction_bodies).toEqual([]);
    expect(proof.hop_count).toBe(0);
    // Must never look like EXPECTED_AT_HEAD / EXPECTED_ANCESTOR.
    expect(["EXPECTED_AT_HEAD", "EXPECTED_ANCESTOR"]).not.toContain(proof.classification);
  });

  it("forces INDETERMINATE when determinate verdict has a broken predecessor link", async () => {
    const port = createInMemoryVerificationMaterialTables({
      operations: [header()],
      artifacts: [[OP, artifact()]],
      observations: [[OP, []]],
      attempts: [[OP, multiAttempts()]],
      paths: [
        [
          OP,
          [
            {
              path_role: "SOURCE",
              wallet_public_key: PUB_SRC,
              verdict: "LANDED_COMPLETE_PATH",
              expected_step_2_signature: SIG_A,
              fresh_head_step_2_signature: SIG_B,
              fresh_head_transaction_sha256: SHA_B,
              bodies: [
                {
                  path_index: 0,
                  step_2_signature: SIG_A,
                  p_signature: "",
                  completed_transaction_sha256: SHA_A,
                  completed_transaction_text: TX0,
                },
                {
                  path_index: 1,
                  step_2_signature: SIG_B,
                  // Broken backlink — should be SIG_A.
                  p_signature: SIG_C,
                  completed_transaction_sha256: SHA_B,
                  completed_transaction_text: TX1,
                },
              ],
              indeterminate_reason: null,
            },
          ],
        ],
      ],
    });

    const result = await assembleVerificationMaterialFromTables(port, OP, TENANT);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const proof = (
      result.row.material.ancestor_proofs as Array<{
        classification: string;
        indeterminate_reason: string | null;
      }>
    )[0]!;
    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("LINK_GAP");
  });

  it("gapped durable path_index {0,2} wires INDETERMINATE (never EXPECTED_*) even with forged backlink", async () => {
    // Dense-renumbering path_index from array index would collapse {0,2} → wire
    // positions [0,1] and, with a forged contiguous p_link, emit EXPECTED_ANCESTOR.
    // Durable coordinates must be preserved so completeness forces LINK_GAP (landing-path oracle).
    const port = createInMemoryVerificationMaterialTables({
      operations: [header()],
      artifacts: [[OP, artifact()]],
      observations: [[OP, []]],
      attempts: [[OP, multiAttempts()]],
      paths: [
        [
          OP,
          [
            {
              path_role: "SOURCE",
              wallet_public_key: PUB_SRC,
              verdict: "LANDED_COMPLETE_PATH",
              expected_step_2_signature: SIG_A,
              fresh_head_step_2_signature: SIG_B,
              fresh_head_transaction_sha256: SHA_B,
              bodies: [
                {
                  path_index: 0,
                  step_2_signature: SIG_A,
                  p_signature: "",
                  completed_transaction_sha256: SHA_A,
                  completed_transaction_text: TX0,
                },
                {
                  path_index: 2,
                  step_2_signature: SIG_B,
                  // Contiguous-looking backlink to body0 — still a hole at path_index 1.
                  p_signature: SIG_A,
                  completed_transaction_sha256: SHA_B,
                  completed_transaction_text: TX1,
                },
              ],
              indeterminate_reason: null,
            },
          ],
        ],
      ],
    });

    const result = await assembleVerificationMaterialFromTables(port, OP, TENANT);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const proof = (
      result.row.material.ancestor_proofs as Array<{
        classification: string;
        indeterminate_reason: string | null;
        hop_count: number;
        path_manifest: Array<{ position: number; body_index: number }>;
      }>
    )[0]!;
    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("LINK_GAP");
    expect(["EXPECTED_AT_HEAD", "EXPECTED_ANCESTOR"]).not.toContain(proof.classification);
    // Durable path_index survived onto the wire (not dense-renumbered).
    expect(proof.path_manifest.map((e) => e.position)).toEqual([0, 2]);
    expect(proof.path_manifest.map((e) => e.body_index)).toEqual([0, 2]);
  });
});

describe("createTableBackedVerificationMaterialSource + HTTP binder", () => {
  it("200 serves wire ordering with available_until last", async () => {
    const source = bindSource(seedFull());
    const response = await handleGetVerificationMaterial(
      { requestId: REQUEST, operationId: OP, tenantId: TENANT, nowMs: TERMINAL_AT + 1 },
      source,
    );
    expect(response.status).toBe(200);
    const body = JSON.parse(response.body) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual([
      "operation_id",
      "operation_type",
      "state",
      "landed_attempt_no",
      "expected_artifact",
      "observation_evidence",
      "attempts",
      "ancestor_proofs",
      "available_until",
    ]);
    expect(body.operation_id).toBe(OP);
    expect(body.available_until).toBe(new Date(UNTIL).toISOString());

    const proofs = body.ancestor_proofs as Array<{
      path_manifest: unknown;
      path_manifest_sha256: string;
    }>;
    const rederived = createHash("sha256")
      .update(JSON.stringify(proofs[0]!.path_manifest), "utf8")
      .digest("hex");
    expect(proofs[0]!.path_manifest_sha256).toBe(rederived);

    // Body text must not imply node evidence replaces independent gateway read.
    const obs = body.observation_evidence as Array<{ node_observation_raw_body_base64: string }>;
    expect(obs[0]!.node_observation_raw_body_base64).toBe(RAW_B64);
    expect(JSON.stringify(body)).not.toMatch(/authoritative gateway/i);
  });

  it("404 for unknown operation and cross-tenant", async () => {
    const source = bindSource(seedFull());
    const missing = await handleGetVerificationMaterial(
      { requestId: REQUEST, operationId: OP2, tenantId: TENANT, nowMs: TERMINAL_AT + 1 },
      source,
    );
    expect(missing.status).toBe(404);

    const cross = await handleGetVerificationMaterial(
      { requestId: REQUEST, operationId: OP, tenantId: OTHER, nowMs: TERMINAL_AT + 1 },
      source,
    );
    expect(cross.status).toBe(404);
  });

  it("409 when pre-terminal", async () => {
    const port = createInMemoryVerificationMaterialTables({
      operations: [
        header({ status: "CREATED", verification_material_available_until_ms: null }),
      ],
      artifacts: [[OP, artifact()]],
    });
    const source = bindSource(port);
    const response = await handleGetVerificationMaterial(
      { requestId: REQUEST, operationId: OP, tenantId: TENANT, nowMs: TERMINAL_AT },
      source,
    );
    expect(response.status).toBe(409);
    expect(JSON.parse(response.body).error.code).toBe("verification_material_not_ready");
  });

  it("410 after available_until without deleting evidence from the port", async () => {
    const port = seedFull();
    const source = bindSource(port);
    const response = await handleGetVerificationMaterial(
      { requestId: REQUEST, operationId: OP, tenantId: TENANT, nowMs: UNTIL },
      source,
    );
    expect(response.status).toBe(410);
    expect(JSON.parse(response.body).error.code).toBe("verification_material_expired");
    // Evidence still durable.
    expect(port.artifacts.has(OP)).toBe(true);
    expect(port.paths.get(OP)?.length).toBe(1);
  });
});

describe("createGatedTableVerificationMaterialSource — access-window record", () => {
  it("ACCESSIBLE when window issued; 410 after revoke without wiping tables", async () => {
    const port = seedFull();
    const windows = new InMemoryVerificationAccessWindowStore();
    await issueVerificationAccessWindow(windows, {
      nodeId: "node-1",
      implementerId: TENANT,
      operationId: OP,
      kind: "MOVE_INTERNAL",
      status: "INTERNAL_MOVE_LANDED",
      terminalAtMs: TERMINAL_AT,
    });

    const decisions: string[] = [];
    const source = createGatedTableVerificationMaterialSource({
      inner: bindSource(port),
      accessWindowStore: windows,
      nowMs: () => TERMINAL_AT + 1_000,
      onAccessDecision: (d) => {
        decisions.push(d.reason);
      },
    });

    const ok = await handleGetVerificationMaterial(
      {
        requestId: REQUEST,
        operationId: OP,
        tenantId: TENANT,
        nowMs: TERMINAL_AT + 1_000,
      },
      source,
    );
    expect(ok.status).toBe(200);
    expect(decisions).toContain("accessible");

    // Revoke access only.
    await windows.updateStatus(OP, "REVOKED", TERMINAL_AT + 2_000);
    const expired = await handleGetVerificationMaterial(
      {
        requestId: REQUEST,
        operationId: OP,
        tenantId: TENANT,
        nowMs: TERMINAL_AT + 3_000,
      },
      source,
    );
    expect(expired.status).toBe(410);
    expect(JSON.parse(expired.body).error.code).toBe("verification_material_expired");
    // Tables untouched.
    expect(port.artifacts.get(OP)?.preimage_text).toContain("zp-move-internal-expected-v1");
    expect(port.attempts.get(OP)).toHaveLength(2);
  });

  it("409 when no window has been issued yet (not ready)", async () => {
    const port = seedFull();
    const windows = new InMemoryVerificationAccessWindowStore();
    const source = createGatedTableVerificationMaterialSource({
      inner: bindSource(port),
      accessWindowStore: windows,
      nowMs: () => TERMINAL_AT + 1,
    });
    const response = await handleGetVerificationMaterial(
      { requestId: REQUEST, operationId: OP, tenantId: TENANT, nowMs: TERMINAL_AT + 1 },
      source,
    );
    expect(response.status).toBe(409);
    expect(JSON.parse(response.body).error.code).toBe("verification_material_not_ready");
  });
});
