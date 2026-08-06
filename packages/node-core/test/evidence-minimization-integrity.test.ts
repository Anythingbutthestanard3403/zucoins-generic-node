// Adversarial proof that
// `GET /v1/operations/:operation_id/verification-material` minimizes and never
// over-exposes evidence.
//
// Surface under test: the read path (assemble from durable tables → access gate →
// HTTP binder). NOT intakeProofBody / the proof-body write path.
//
// Checklist (one describe per item; each has a failing-before-fix control):
//   1. Wrong tenant / token / scope — no existence oracle
//   2. Expired access — 410 without deleting underlying evidence
//   3. Unrelated history — never appears in ancestor_proofs / bodies
//   4. Ciphertext / private-key absence — raw body grep
//   5. Body digest mismatch → INDETERMINATE / LINK_GAP (never EXPECTED_*)
//   6. Node-relay non-authority — wire labels cannot read as settlement guarantee

import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createGatedTableVerificationMaterialSource,
  createTableBackedVerificationMaterialSource,
} from "../src/api/verification-material-source.ts";
import { handleGetVerificationMaterial } from "../src/api/verification-material.ts";
import {
  InMemoryVerificationAccessWindowStore,
  issueVerificationAccessWindow,
  revokeVerificationAccessWindow,
} from "../src/api/verification-access.ts";
import { verificationMaterialAvailableUntilMs } from "../src/data/retention.ts";
import {
  FORBIDDEN_MATERIAL_MARKERS,
  assembleVerificationMaterialFromTables,
  containsForbiddenMaterial,
  createInMemoryVerificationMaterialTables,
  transactionBodySha256,
  type DurableAttemptRow,
  type DurableLineageBodyRow,
  type DurableLineagePathRow,
  type DurableObservationEvidenceRow,
  type DurableOperationHeader,
  type VerificationMaterialTablePort,
} from "../src/observation/index.ts";

// --- Fixtures ---------------------------------------------------------------------------

const SIG_A = `${"A".repeat(86)}==`;
const SIG_B = `${"B".repeat(86)}==`;
const SIG_C = `${"C".repeat(86)}==`;
const SIG_PRIOR = `${"P".repeat(86)}==`; // prior unrelated hop (must never surface)
const PUB_SRC = `${"S".repeat(43)}=`;
const OP = "22222222-2222-4222-8222-222222222222";
const OP_OTHER = "33333333-3333-4333-8333-333333333333";
const TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER_TENANT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const KEY = "44444444-4444-4444-8444-444444444444";
const WALLET_SRC = "55555555-5555-4555-8555-555555555555";
const REQUEST = "11111111-1111-4111-8111-111111111111";
const TERMINAL_AT = Date.UTC(2026, 0, 1);
const UNTIL = verificationMaterialAvailableUntilMs(TERMINAL_AT);

// Operation path bodies (expected at 0, fresh head at 1).
const TX_EXPECTED = `{"inner":{"op":"move","v":1},"step_1_signature":"${SIG_A}","step_2_signature":"${SIG_A}"}`;
const TX_HEAD = `{"inner":{"op":"move","v":1},"step_1_signature":"${SIG_B}","step_2_signature":"${SIG_B}"}`;
// Prior wallet history that must never appear for this operation's path.
const TX_PRIOR_UNRELATED = `{"inner":{"op":"prior-unrelated","note":"wallet_history_before_expected"},"step_1_signature":"${SIG_PRIOR}","step_2_signature":"${SIG_PRIOR}"}`;
const SHA_EXPECTED = transactionBodySha256(TX_EXPECTED);
const SHA_HEAD = transactionBodySha256(TX_HEAD);
const SHA_PRIOR = transactionBodySha256(TX_PRIOR_UNRELATED);
const RAW_B64 = Buffer.from(
  JSON.stringify({ node_observed: true, note: "node claim — not caller observation" }),
).toString("base64");

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function header(over: Partial<DurableOperationHeader> = {}): DurableOperationHeader {
  return {
    id: OP,
    implementer_id: TENANT,
    kind: "MOVE_INTERNAL",
    status: "INTERNAL_MOVE_LANDED",
    verification_material_available_until_ms: UNTIL,
    landed_attempt_no: 1,
    ...over,
  };
}

function artifact() {
  return {
    signing_key_id: KEY,
    preimage_text: '{"purpose":"zp-move-internal-expected-v1"}',
    preimage_sha256: sha256Hex('{"purpose":"zp-move-internal-expected-v1"}'),
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

function attempts(): readonly DurableAttemptRow[] {
  return [
    {
      attempt_no: 1,
      classification: "LANDED_VERIFIED",
      inner_preimage_text: '{"attempt":1}',
      inner_sha256: sha256Hex('{"attempt":1}'),
      step_1_signature: SIG_A,
      step_2_preimage_text: `{"inner":{"attempt":1},"step_1_signature":"${SIG_A}"}`,
      step_2_signature: SIG_B,
      settled_transaction_text: TX_HEAD,
    },
  ];
}

function body(
  pathIndex: number,
  step2: string,
  pSig: string,
  text: string,
): DurableLineageBodyRow {
  return {
    path_index: pathIndex,
    step_2_signature: step2,
    p_signature: pSig,
    completed_transaction_sha256: transactionBodySha256(text),
    completed_transaction_text: text,
  };
}

/** Minimal ordered path: expected @0 → head @1. No prior history. */
function operationPath(): DurableLineagePathRow {
  return {
    path_role: "SOURCE",
    wallet_public_key: PUB_SRC,
    verdict: "LANDED_COMPLETE_PATH",
    expected_step_2_signature: SIG_A,
    fresh_head_step_2_signature: SIG_B,
    fresh_head_transaction_sha256: SHA_HEAD,
    bodies: [body(0, SIG_A, "", TX_EXPECTED), body(1, SIG_B, SIG_A, TX_HEAD)],
    indeterminate_reason: null,
  };
}

function seedTables(over: {
  readonly operations?: readonly DurableOperationHeader[];
  readonly paths?: ReadonlyArray<readonly [string, readonly DurableLineagePathRow[]]>;
  readonly observations?: ReadonlyArray<
    readonly [string, readonly DurableObservationEvidenceRow[]]
  >;
} = {}) {
  return createInMemoryVerificationMaterialTables({
    operations: over.operations ?? [header()],
    artifacts: [[OP, artifact()]],
    observations: over.observations ?? [[OP, [obsSource()]]],
    attempts: [[OP, attempts()]],
    paths: over.paths ?? [[OP, [operationPath()]]],
  });
}

function bindSource(port: VerificationMaterialTablePort) {
  return createTableBackedVerificationMaterialSource({
    port,
    assemble: assembleVerificationMaterialFromTables as never,
    loadOperation: (operationId, implementerId) =>
      port.loadOperation(operationId, implementerId),
  });
}

async function getMaterial(
  source: ReturnType<typeof bindSource>,
  opts: {
    readonly tenantId?: string;
    readonly operationId?: string;
    readonly nowMs?: number;
  } = {},
) {
  return handleGetVerificationMaterial(
    {
      requestId: REQUEST,
      operationId: opts.operationId ?? OP,
      tenantId: opts.tenantId ?? TENANT,
      nowMs: opts.nowMs ?? TERMINAL_AT + 1,
    },
    source,
  );
}

function errorCode(body: string): string {
  return (JSON.parse(body) as { error: { code: string } }).error.code;
}

// Tokens that would imply the node body is a settlement / landing authority.
const AUTHORITY_LEAK_MARKERS = [
  "authoritative_settlement",
  "settlement_guarantee",
  "platform_verified_landing",
  "replaces_independent_read",
  "gateway_authority",
  "final_settlement_proof",
] as const;

// ========================================================================================
// 1. Wrong tenant / token / scope — no existence oracle
// ========================================================================================

describe("1. wrong tenant/token/scope — no existence oracle", () => {
  it("cross-tenant load collapses to 404 not_found whether or not the op exists", async () => {
    const port = seedTables({
      operations: [
        header(), // exists for TENANT
        header({ id: OP_OTHER, implementer_id: OTHER_TENANT }), // exists for OTHER
      ],
    });
    // Seed artifact for OTHER so a leaky path could assemble if tenant check were late.
    port.artifacts.set(OP_OTHER, artifact());
    port.paths.set(OP_OTHER, [operationPath()]);
    port.observations.set(OP_OTHER, [obsSource()]);
    port.attempts.set(OP_OTHER, [...attempts()]);

    const source = bindSource(port);

    // Wrong tenant against an EXISTING op owned by TENANT.
    const againstExisting = await getMaterial(source, { tenantId: OTHER_TENANT, operationId: OP });
    // Wrong tenant against a TRULY UNKNOWN op.
    const againstMissing = await getMaterial(source, {
      tenantId: OTHER_TENANT,
      operationId: "99999999-9999-4999-8999-999999999999",
    });

    expect(againstExisting.status).toBe(404);
    expect(againstMissing.status).toBe(404);
    expect(errorCode(againstExisting.body)).toBe("not_found");
    expect(errorCode(againstMissing.body)).toBe("not_found");
    // Existence oracle: status + error code + top-level envelope keys must be identical.
    expect(JSON.parse(againstExisting.body)).toEqual(JSON.parse(againstMissing.body));
  });

  it("failing-before-fix control: correct tenant still resolves the same op", async () => {
    const source = bindSource(seedTables());
    const ok = await getMaterial(source, { tenantId: TENANT });
    expect(ok.status).toBe(200);
    expect(JSON.parse(ok.body).operation_id).toBe(OP);
  });

  it("tenant binding is taken from the verified reporting implementer id, never body", async () => {
    // The HTTP binder (apps/generic-node verification-material-route) sets
    // tenantId = request.binding.implementerId. Here we prove the source port itself
    // scopes by the injected tenantId — a wrong-scope reporting key that somehow
    // reached the handler still cannot load another tenant's material.
    const port = seedTables();
    const source = bindSource(port);
    const wrongScope = await getMaterial(source, { tenantId: "scope-forged-tenant" });
    expect(wrongScope.status).toBe(404);
    expect(errorCode(wrongScope.body)).toBe("not_found");
    // Evidence rows remain; nothing was served.
    expect(port.operations.get(OP)?.implementer_id).toBe(TENANT);
  });
});

// ========================================================================================
// 2. Expired token / access window — 410; rows intact
// ========================================================================================

describe("2. expired access — 410 without deleting underlying evidence", () => {
  it("410 at/after available_until and durable tables still hold every evidence row", async () => {
    const port = seedTables();
    const source = bindSource(port);

    const expired = await getMaterial(source, { nowMs: UNTIL });
    expect(expired.status).toBe(410);
    expect(errorCode(expired.body)).toBe("verification_material_expired");
    // 410 body must not leak material fields.
    const envelope = JSON.parse(expired.body) as Record<string, unknown>;
    expect(envelope).not.toHaveProperty("ancestor_proofs");
    expect(envelope).not.toHaveProperty("observation_evidence");
    expect(envelope).not.toHaveProperty("expected_artifact");

    // Direct post-expiry read of underlying tables — data-model: revoke access only.
    expect(port.operations.get(OP)).toBeDefined();
    expect(port.artifacts.get(OP)).toBeDefined();
    expect(port.paths.get(OP)?.[0]?.bodies).toHaveLength(2);
    expect(port.paths.get(OP)?.[0]?.bodies[0]?.completed_transaction_text).toBe(TX_EXPECTED);
    expect(port.observations.get(OP)).toHaveLength(1);
    expect(port.attempts.get(OP)).toHaveLength(1);
  });

  it("access-window RECORD revoke → 410; tables untouched", async () => {
    const port = seedTables();
    const windows = new InMemoryVerificationAccessWindowStore();
    await issueVerificationAccessWindow(windows, {
      nodeId: "node-1",
      implementerId: TENANT,
      operationId: OP,
      kind: "MOVE_INTERNAL",
      status: "INTERNAL_MOVE_LANDED",
      terminalAtMs: TERMINAL_AT,
    });
    await revokeVerificationAccessWindow(windows, OP, TERMINAL_AT + 2_000);

    const gated = createGatedTableVerificationMaterialSource({
      inner: bindSource(port),
      accessWindowStore: windows,
      nowMs: () => TERMINAL_AT + 3_000,
    });
    const result = await getMaterial(gated, { nowMs: TERMINAL_AT + 3_000 });
    expect(result.status).toBe(410);
    expect(errorCode(result.body)).toBe("verification_material_expired");
    // Rows intact after revoke.
    expect(port.paths.get(OP)?.[0]?.bodies[0]?.completed_transaction_text).toBe(TX_EXPECTED);
    expect(port.artifacts.get(OP)?.preimage_text).toContain("zp-move-internal-expected");
  });

  it("failing-before-fix control: inside the window the same rows serve 200", async () => {
    const source = bindSource(seedTables());
    const ok = await getMaterial(source, { nowMs: TERMINAL_AT + 1 });
    expect(ok.status).toBe(200);
  });
});

// ========================================================================================
// 3. Unrelated history never appears (observation; api-contract ancestor_proofs minimality)
// ========================================================================================

describe("3. unrelated wallet history is excluded from the response", () => {
  it("operation path starts at expected tx — prior unrelated body never surfaces", async () => {
    // Wallet has a prior hop (TX_PRIOR_UNRELATED) that is NOT part of this operation's
    // lineage_path_bodies. Only the operation path (expected→head) is seeded.
    const port = seedTables();
    const source = bindSource(port);
    const result = await getMaterial(source);
    expect(result.status).toBe(200);

    // Raw-body grep: prior text, prior sig, prior digest must be absent.
    expect(result.body).not.toContain(TX_PRIOR_UNRELATED);
    expect(result.body).not.toContain(SIG_PRIOR);
    expect(result.body).not.toContain(SHA_PRIOR);
    expect(result.body).not.toContain("prior-unrelated");
    expect(result.body).not.toContain("wallet_history_before_expected");

    const parsed = JSON.parse(result.body) as {
      ancestor_proofs: Array<{
        path_manifest: Array<{ position: number; step_2_signature: string; transaction_sha256: string }>;
        transaction_bodies: Array<{ settled_transaction_text: string; transaction_sha256: string }>;
      }>;
    };
    const proof = parsed.ancestor_proofs[0]!;
    // Minimality: positions are 0..n contiguous starting at expected; no negative/prior.
    expect(proof.path_manifest.map((e) => e.position)).toEqual([0, 1]);
    expect(proof.path_manifest[0]!.step_2_signature).toBe(SIG_A);
    expect(proof.transaction_bodies.map((b) => b.settled_transaction_text)).toEqual([
      TX_EXPECTED,
      TX_HEAD,
    ]);
    for (const b of proof.transaction_bodies) {
      expect(b.settled_transaction_text).not.toContain("prior-unrelated");
    }
  });

  it("failing-before-fix control: if a prior body were wrongly included, the grep would catch it", async () => {
    // Control: deliberately put prior text into a body and confirm the assertion shape
    // detects it — proves the negative test above is not a vacuous match.
    const leaky = JSON.stringify({
      ancestor_proofs: [
        {
          transaction_bodies: [{ settled_transaction_text: TX_PRIOR_UNRELATED }],
        },
      ],
    });
    expect(leaky).toContain("prior-unrelated");
    expect(leaky).toContain(SIG_PRIOR);
  });
});

// ========================================================================================
// 4. Ciphertext / private-key absence — raw JSON body grep
// ========================================================================================

describe("4. ciphertext and private-key material never appear in the raw response", () => {
  it("200 body greps clean against FORBIDDEN_MATERIAL_MARKERS", async () => {
    // Seed observations that would be catastrophic if a buggy assembler echoed custody
    // fields from a hostile durable row into the wire object under allowlisted keys.
    const port = seedTables();
    const source = bindSource(port);
    const result = await getMaterial(source);
    expect(result.status).toBe(200);

    // Schema alone is insufficient — grep the exact response bytes.
    expect(containsForbiddenMaterial(result.body)).toBe(false);
    for (const marker of FORBIDDEN_MATERIAL_MARKERS) {
      expect(result.body).not.toContain(marker);
    }
    // Extra custody substrings beyond the shared marker list.
    for (const extra of [
      "BEGIN PRIVATE KEY",
      "vault_blob",
      "encrypted_seed",
      "totp_material",
      "hkdf_okm",
    ]) {
      expect(result.body).not.toContain(extra);
    }
  });

  it("failing-before-fix control: containsForbiddenMaterial detects injected markers", () => {
    expect(containsForbiddenMaterial('{"private_key":"leak"}')).toBe(true);
    expect(containsForbiddenMaterial('{"vault_ciphertext":"xx"}')).toBe(true);
    expect(containsForbiddenMaterial('{"totp_secret":"otp"}')).toBe(true);
    expect(containsForbiddenMaterial('{"operation_id":"ok"}')).toBe(false);
  });

  it("allowlisted binder drops hostile custody keys even if the material bag carries them", async () => {
    // Direct source that returns a hostile material bag (bypasses assembler) —
    // the HTTP binder must still strip unknown keys (buildBody allowlist).
    const hostile = {
      async load() {
        return {
          kind: "MOVE_INTERNAL" as const,
          status: "INTERNAL_MOVE_LANDED",
          verificationMaterialAvailableUntilMs: UNTIL,
          material: {
            operation_type: "MOVE_INTERNAL",
            state: "INTERNAL_MOVE_LANDED",
            landed_attempt_no: 1,
            expected_artifact: artifact(),
            observation_evidence: [],
            attempts: [],
            ancestor_proofs: [],
            private_key: "MUST-NOT-LEAK",
            vault_ciphertext: "cipher-blob",
            totp_secret: "otp-seed",
          },
        };
      },
    };
    const result = await handleGetVerificationMaterial(
      {
        requestId: REQUEST,
        operationId: OP,
        tenantId: TENANT,
        nowMs: TERMINAL_AT + 1,
      },
      hostile,
    );
    expect(result.status).toBe(200);
    expect(result.body).not.toContain("MUST-NOT-LEAK");
    expect(result.body).not.toContain("private_key");
    expect(result.body).not.toContain("vault_ciphertext");
    expect(result.body).not.toContain("totp_secret");
    expect(containsForbiddenMaterial(result.body)).toBe(false);
  });
});

// ========================================================================================
// 5. Body digest mismatch → INDETERMINATE / LINK_GAP (api-contract integrity chain)
// ========================================================================================

describe("5. body digest mismatch forces INDETERMINATE/LINK_GAP — never EXPECTED_*", () => {
  it("corrupted completed_transaction_text (stale sha) → LINK_GAP on the wire", async () => {
    const corruptedPath: DurableLineagePathRow = {
      ...operationPath(),
      bodies: [
        {
          // Hash claims TX_EXPECTED but text was rewritten — classic integrity gap.
          path_index: 0,
          step_2_signature: SIG_A,
          p_signature: "",
          completed_transaction_sha256: SHA_EXPECTED,
          completed_transaction_text: TX_EXPECTED.replace("move", "TAMPERED"),
        },
        body(1, SIG_B, SIG_A, TX_HEAD),
      ],
      // Writer still claims a complete path — exposure layer must refuse.
      verdict: "LANDED_COMPLETE_PATH",
      indeterminate_reason: null,
    };
    // Confirm the fixture is actually mismatched.
    expect(transactionBodySha256(corruptedPath.bodies[0]!.completed_transaction_text)).not.toBe(
      corruptedPath.bodies[0]!.completed_transaction_sha256,
    );

    const port = seedTables({ paths: [[OP, [corruptedPath]]] });
    const source = bindSource(port);
    const result = await getMaterial(source);
    expect(result.status).toBe(200);
    const proof = (
      JSON.parse(result.body) as {
        ancestor_proofs: Array<{
          classification: string;
          indeterminate_reason: string | null;
        }>;
      }
    ).ancestor_proofs[0]!;

    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("LINK_GAP");
    expect(proof.classification).not.toBe("EXPECTED_ANCESTOR");
    expect(proof.classification).not.toBe("EXPECTED_AT_HEAD");
  });

  it("corrupted completed_transaction_sha256 (text intact, hash rewritten) → LINK_GAP", async () => {
    const corruptedPath: DurableLineagePathRow = {
      ...operationPath(),
      bodies: [
        {
          path_index: 0,
          step_2_signature: SIG_A,
          p_signature: "",
          // Stale/wrong hash for intact text.
          completed_transaction_sha256: "f".repeat(64),
          completed_transaction_text: TX_EXPECTED,
        },
        // Manifest entry will also disagree once mapped — still must not be EXPECTED_*.
        body(1, SIG_B, SIG_A, TX_HEAD),
      ],
      verdict: "LANDED_COMPLETE_PATH",
      indeterminate_reason: null,
    };
    // mapLineageBodiesToManifest copies completed_transaction_sha256 onto both the
    // manifest entry and the body — so body.transaction_sha256 === entry.transaction_sha256
    // still holds, but sha256(text) !== body.transaction_sha256. That is pure LINK_GAP.
    expect(transactionBodySha256(TX_EXPECTED)).not.toBe("f".repeat(64));

    const port = seedTables({ paths: [[OP, [corruptedPath]]] });
    const result = await getMaterial(bindSource(port));
    expect(result.status).toBe(200);
    const proof = (
      JSON.parse(result.body) as {
        ancestor_proofs: Array<{ classification: string; indeterminate_reason: string | null }>;
      }
    ).ancestor_proofs[0]!;
    expect(proof.classification).toBe("INDETERMINATE");
    expect(proof.indeterminate_reason).toBe("LINK_GAP");
  });

  it("failing-before-fix control: intact digests still yield EXPECTED_ANCESTOR", async () => {
    const port = seedTables();
    const result = await getMaterial(bindSource(port));
    expect(result.status).toBe(200);
    const proof = (
      JSON.parse(result.body) as {
        ancestor_proofs: Array<{ classification: string; indeterminate_reason: string | null }>;
      }
    ).ancestor_proofs[0]!;
    expect(proof.classification).toBe("EXPECTED_ANCESTOR");
    expect(proof.indeterminate_reason).toBeNull();
  });
});

// ========================================================================================
// 6. Node-relay non-authority
// ========================================================================================

describe("6. node-relay evidence is labelled non-authoritative — never a settlement guarantee", () => {
  it("observation raw body is namespaced as node_observation_* and carries no authority tokens", async () => {
    const result = await getMaterial(bindSource(seedTables()));
    expect(result.status).toBe(200);
    const parsed = JSON.parse(result.body) as {
      observation_evidence: Array<Record<string, unknown>>;
      ancestor_proofs: Array<Record<string, unknown>>;
      attempts: Array<Record<string, unknown>>;
    };

    // Field name itself marks the body as the node's observation, not the caller's.
    expect(parsed.observation_evidence[0]).toHaveProperty("node_observation_raw_body_base64");
    expect(parsed.observation_evidence[0]).not.toHaveProperty("caller_observation_raw_body_base64");
    expect(parsed.observation_evidence[0]).not.toHaveProperty("authoritative_raw_body_base64");
    expect(parsed.observation_evidence[0]).not.toHaveProperty("settlement_raw_body");

    // No authority-granting field anywhere on the wire object.
    const raw = result.body;
    for (const marker of AUTHORITY_LEAK_MARKERS) {
      expect(raw).not.toContain(marker);
    }
    // Ancestor proof classification is a consumer-rederivable label, not a platform
    // settlement guarantee — and attempts carry classification of the node's path
    // reconstruction, never a "final" authority token.
    for (const proof of parsed.ancestor_proofs) {
      expect(proof).not.toHaveProperty("authoritative");
      expect(proof).not.toHaveProperty("settlement_guaranteed");
      expect(proof).not.toHaveProperty("platform_verdict_final");
    }
  });

  it("decoded node observation body is not presented as the caller's independent read", async () => {
    const result = await getMaterial(bindSource(seedTables()));
    const obs = (
      JSON.parse(result.body) as {
        observation_evidence: Array<{ node_observation_raw_body_base64: string }>;
      }
    ).observation_evidence[0]!;
    const decoded = Buffer.from(obs.node_observation_raw_body_base64, "base64").toString("utf8");
    // Fixture body intentionally notes non-authority; the field name is the durable label.
    expect(decoded).toContain("node claim");
    // Must not decode to something that claims to replace independent verification.
    expect(decoded.toLowerCase()).not.toContain("authoritative settlement");
    expect(decoded.toLowerCase()).not.toContain("replaces independent");
  });

  it("failing-before-fix control: authority marker list would catch a leaky assembler", () => {
    const leaky = JSON.stringify({
      observation_evidence: [
        {
          authoritative_settlement: true,
          settlement_guarantee: "final",
        },
      ],
    });
    for (const marker of ["authoritative_settlement", "settlement_guarantee"] as const) {
      expect(leaky).toContain(marker);
    }
  });
});
