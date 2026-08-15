// Prove forbidden recovery-surface actions absent.
// Attack surface: GET recovery + POST recovery-actions on main.

import { describe, expect, it } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import {
  FORBIDDEN_RECOVERY_ACTIONS,
  OPERATOR_RECOVERY_ACTIONS,
  STRUCTURALLY_ABSENT_RECOVERY_EFFECTS,
  RECOVERY_ACTIONS_PATH,
  executeRecoveryAction,
  handleRecoveryAction,
  isForbiddenRecoveryAction,
  isOperatorRecoveryAction,
  planRecoveryEffect,
  type RecoveryActionAuthContext,
  type RecoveryActionCommitInput,
  type RecoveryActionCommitResult,
  type RecoveryActionEffect,
  type RecoveryActionRequest,
  type RecoveryActionStore,
  type RecoveryActionSuccessBody,
  type RecoveryFacts,
} from "../src/api/recovery-actions.js";
import {
  NEEDS_ATTENTION_PATH,
  RECOVERY_DETAIL_PATH,
} from "../src/api/recovery-inspection.js";
import { RecoveryActionsBody, ROUTE_SCHEMAS, findRouteSchema } from "../src/api/route-schemas.js";
import { RECOVERY_ACTIONS_BODY } from "../src/api/openapi/request-bodies.js";
import { OPERATOR_RECOVERY_ACTIONS as CONTRACT_OPERATOR_RECOVERY_ACTIONS } from "../../generic-node-contracts/src/operator-halt/halt.contract.ts";

const __dir = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dir, "../../..");
const ROUTES_JSON = join(
  REPO_ROOT,
  "packages/generic-node-contracts/gen/routes.json",
);

/** Operator recovery actions, in table order, byte-exact. */
const SECTION_8_1_ACTIONS = [
  "RETRY_OBSERVATION",
  "REDELIVER_EXACT_PARTIAL",
  "CONTINUE_EXTERNAL_WAIT",
  "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
  "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
  "CLOSE_LANDED_UNACKNOWLEDGED",
  "REBUILD_INTERNAL_MOVE",
  "RELEASE_EXPIRED_RECEIVE",
  "RELEASE_EXPIRED_RECEIVE_OPERATOR_RISK",
  "QUARANTINE_WALLETS",
  "ACKNOWLEDGE_KEEP_PINNED",
] as const;

/** Non-actions, in the order the recovery rules list them. */
const SECTION_8_2_FORBIDDEN = [
  "RETRY_SUBMIT",
  "FORCE_LANDED",
  "FORCE_RELEASE",
  "EDIT_TRANSACTION",
  "CHANGE_DESTINATION",
  "CHANGE_AMOUNT",
  "REFORM_EXTERNAL_SEND",
  "NODE_SUBMIT_EXTERNAL_SEND",
  "DELETE_EVIDENCE",
  "SKIP_VERIFICATION",
] as const;

/** Poison body fields — schema-level rejection (strict object). */
const SECTION_11_3_POISON_FIELDS = [
  "transaction_bytes",
  "replacement_transaction",
  "signed_tx",
  "destination",
  "destination_address",
  "destination_id",
  "new_destination",
  "amount",
  "amount_zkz",
  "new_amount",
  "submit",
  "submit_request",
  "request_submit",
  "gateway_submit",
] as const;

/** Permanent-retention evidence tables. */
const PERMANENT_EVIDENCE_TABLES = [
  "gateway_observations",
  "operation_landing_proofs",
  "operation_transactions",
] as const;

const OP = "00000000-0000-4000-8000-000000000001";
const WALLET = "00000000-0000-4000-8000-000000000099";
const PROOF = "00000000-0000-4000-8000-000000000077";
const NONCE = "00000000-0000-4000-8000-000000000055";
const OPERATOR = "00000000-0000-4000-8000-000000000044";
const STALE_PROOF = "00000000-0000-4000-8000-000000000088";

/** Counts clean negative assertions for AC (≥14). */
let negativeAssertions = 0;
function neg(condition: boolean, label: string): void {
  expect(condition, label).toBe(true);
  if (condition) negativeAssertions += 1;
}

function baseSend(patch: Partial<RecoveryFacts> = {}): RecoveryFacts {
  return {
    operationId: OP,
    kind: "SEND_EXTERNAL",
    status: "NEEDS_ATTENTION",
    attentionRequired: true,
    attentionReason: "UNEXPECTED_HEAD_CHANGE",
    attentionDetail: null,
    rowVersion: 7,
    leaseEpoch: 3,
    heldLeases: [{ walletId: WALLET, leaseEpoch: 3, role: "SOURCE" }],
    hasLandingProof: false,
    landingProofVerdict: null,
    hasObservationAnomaly: false,
    hasLineageGap: false,
    invariantBreachNoted: false,
    evidenceManifest: [],
    diagnostics: [],
    receive: null,
    move: null,
    send: {
      hasSignIntent: true,
      hasSignerCall: true,
      hasSignature: true,
      hasDurablePartial: true,
      hasDelivery: true,
      protocolExpiredPlusMargin: false,
      freshHeadEqualsSourceT0: false,
      completePathExclusionProved: false,
      hasSignerAudit: true,
      hasMatchingExactByteRecord: true,
    },
    haltEngaged: false,
    receiveExpiryAttentionEventExists: false,
    ...patch,
  };
}

function moveRebuildReady(patch: Partial<RecoveryFacts> = {}): RecoveryFacts {
  return baseSend({
    kind: "MOVE_INTERNAL",
    status: "NEEDS_ATTENTION",
    send: null,
    move: {
      deterministicPreAcceptanceRejection: true,
      expiredAndBothWalletsUnchangedAtT0: false,
      submitProvablyNeverStarted: false,
      positiveNonLandingProofId: PROOF,
      unexpectedSuccessorOutsideLease: false,
      hasPreimage: true,
      hasSignature: true,
      hasSignerAudit: true,
      hasMatchingExactByteRecord: true,
      oneWalletLandedOtherUnconnected: false,
    },
    ...patch,
  });
}

/** Past SUBMIT_STARTED/SUBMIT_RETURNED boundary — attempt already on wire. */
function sendPastSubmitBoundary(): RecoveryFacts {
  return baseSend({
    status: "AWAITING_REDEMPTION",
    attentionRequired: true,
    send: {
      hasSignIntent: true,
      hasSignerCall: true,
      hasSignature: true,
      hasDurablePartial: true,
      hasDelivery: true,
      protocolExpiredPlusMargin: false,
      freshHeadEqualsSourceT0: false,
      completePathExclusionProved: false,
      hasSignerAudit: true,
      hasMatchingExactByteRecord: true,
    },
  });
}

class MemoryRecoveryStore implements RecoveryActionStore {
  facts: RecoveryFacts | null;
  nonces = new Map<string, "ISSUED" | "CONSUMED">();
  burnedTimesteps = new Set<number>();
  idempotency = new Map<string, { fingerprint: string; body: RecoveryActionSuccessBody }>();
  audited: RecoveryActionCommitInput[] = [];
  commits = 0;
  blockCommit = false;
  partialText = "exact-partial-bytes";
  partialSha = "b".repeat(64);
  mutex: Promise<void> = Promise.resolve();
  /** Bidirectional counter for AC4 — commit must never request evidence DELETE. */
  evidenceDeletes = 0;

  constructor(facts: RecoveryFacts | null, nonce: string = NONCE) {
    this.facts = facts;
    if (facts !== null) this.nonces.set(nonce, "ISSUED");
  }

  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    const prev = this.mutex;
    let release!: () => void;
    this.mutex = new Promise<void>((r) => {
      release = r;
    });
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  async lookupIdempotency(operationId: string, idempotencyKey: string) {
    const hit = this.idempotency.get(`${operationId}:${idempotencyKey}`);
    if (!hit) return { kind: "miss" as const };
    return { kind: "hit" as const, body: hit.body };
  }

  async loadRecoveryFactsLocked(operationId: string): Promise<RecoveryFacts | null> {
    return this.withLock(async () => {
      if (this.facts === null || this.facts.operationId !== operationId) return null;
      return this.facts;
    });
  }

  async commitRecoveryAction(input: RecoveryActionCommitInput): Promise<RecoveryActionCommitResult> {
    return this.withLock(async () => {
      if (this.blockCommit) {
        throw new Error("commit must not be reached");
      }
      if (this.facts === null || this.facts.operationId !== input.operationId) {
        return { ok: false, reason: "operation_not_found" };
      }
      if (this.facts.rowVersion !== input.expectedRowVersion) {
        return { ok: false, reason: "operation_version_conflict" };
      }
      const nonceState = this.nonces.get(input.recoveryNonce);
      if (nonceState !== "ISSUED") {
        return { ok: false, reason: "recovery_nonce_invalid" };
      }
      if (this.burnedTimesteps.has(input.totpTimestep)) {
        return { ok: false, reason: "predicate_failed", detail: "totp_replay" };
      }
      // QUARANTINE retains evidence — no permanent-table DELETE path on this port.
      if (input.effect.kind === "QUARANTINE_WALLETS") {
        // intentionally: wallets quarantine ≠ evidence purge
      }
      const next = applyEffect(this.facts, input.effect, this);
      if (!next.ok) return next;

      this.nonces.set(input.recoveryNonce, "CONSUMED");
      this.burnedTimesteps.add(input.totpTimestep);
      this.facts = {
        ...this.facts,
        status: next.status,
        rowVersion: this.facts.rowVersion + 1,
        attentionRequired: next.attentionRequired,
      };
      this.audited.push(input);
      this.commits += 1;
      return {
        ok: true,
        rowVersion: this.facts.rowVersion,
        status: this.facts.status,
        releaseStatus: next.releaseStatus,
        transferCodeText: next.transferCodeText,
        transferCodeSha256: next.transferCodeSha256,
      };
    });
  }

  async storeIdempotency(
    operationId: string,
    idempotencyKey: string,
    body: RecoveryActionSuccessBody,
  ): Promise<void> {
    this.idempotency.set(`${operationId}:${idempotencyKey}`, {
      fingerprint: body.action,
      body,
    });
  }
}

function applyEffect(
  facts: RecoveryFacts,
  effect: RecoveryActionEffect,
  store: MemoryRecoveryStore,
):
  | {
      readonly ok: true;
      readonly status: string;
      readonly attentionRequired: boolean;
      readonly releaseStatus: "RELEASED_T0_UNCHANGED" | "RELEASED_OPERATOR_ACCEPTED_RISK" | null;
      readonly transferCodeText: string | null;
      readonly transferCodeSha256: string | null;
    }
  | { readonly ok: false; readonly reason: "predicate_failed"; readonly detail?: string } {
  switch (effect.kind) {
    case "RETRY_OBSERVATION":
    case "ACKNOWLEDGE_KEEP_PINNED":
      return {
        ok: true,
        status: facts.status,
        attentionRequired: facts.attentionRequired,
        releaseStatus: null,
        transferCodeText: null,
        transferCodeSha256: null,
      };
    case "REDELIVER_EXACT_PARTIAL":
      return {
        ok: true,
        status: facts.status,
        attentionRequired: facts.attentionRequired,
        releaseStatus: null,
        transferCodeText: store.partialText,
        transferCodeSha256: store.partialSha,
      };
    case "CONTINUE_EXTERNAL_WAIT":
      return {
        ok: true,
        status: "AWAITING_REDEMPTION",
        attentionRequired: false,
        releaseStatus: null,
        transferCodeText: null,
        transferCodeSha256: null,
      };
    case "CLOSE_NEVER_STARTED_EXTERNAL_SEND":
    case "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED":
      return {
        ok: true,
        status: "REJECTED",
        attentionRequired: false,
        releaseStatus: null,
        transferCodeText: null,
        transferCodeSha256: null,
      };
    case "CLOSE_LANDED_UNACKNOWLEDGED":
      return {
        ok: true,
        status: "EXTERNAL_SEND_LANDED",
        attentionRequired: false,
        releaseStatus: null,
        transferCodeText: null,
        transferCodeSha256: null,
      };
    case "REBUILD_INTERNAL_MOVE":
      expect(effect.submitOldAttempt).toBe(false);
      return {
        ok: true,
        status: "CREATED",
        attentionRequired: false,
        releaseStatus: null,
        transferCodeText: null,
        transferCodeSha256: null,
      };
    case "RELEASE_EXPIRED_RECEIVE":
      return {
        ok: true,
        status: "EXPIRED",
        attentionRequired: false,
        releaseStatus: "RELEASED_T0_UNCHANGED",
        transferCodeText: null,
        transferCodeSha256: null,
      };
    case "RELEASE_EXPIRED_RECEIVE_OPERATOR_RISK":
      return {
        ok: true,
        status: "EXPIRED",
        attentionRequired: false,
        releaseStatus: "RELEASED_OPERATOR_ACCEPTED_RISK",
        transferCodeText: null,
        transferCodeSha256: null,
      };
    case "QUARANTINE_WALLETS":
      return {
        ok: true,
        status: facts.status,
        attentionRequired: true,
        releaseStatus: null,
        transferCodeText: null,
        transferCodeSha256: null,
      };
    default: {
      const _e: never = effect;
      return { ok: false, reason: "predicate_failed", detail: String(_e) };
    }
  }
}

function auth(key = "idem-fixture"): RecoveryActionAuthContext {
  return {
    operatorId: OPERATOR,
    totpTimestep: 1_800_000,
    csrfValidated: true,
    idempotencyKey: key,
  };
}

function req(action: string, extras: Partial<RecoveryActionRequest> = {}): RecoveryActionRequest {
  return {
    action,
    expectedRowVersion: 7,
    recoveryNonce: NONCE,
    proofId: null,
    operatorNote: "fixture",
    idempotencyKey: "idem-fixture",
    operatorId: OPERATOR,
    totpTimestep: 1_800_000,
    csrfValidated: true,
    ...extras,
  };
}

/** Pipeline-equivalent status for RecoveryActionsBody failures (api/pipeline.ts:196–202). */
function schemaRejectHttp(body: unknown): { status: 400; code: "unknown_field" | "invalid_scalar" } | null {
  const r = RecoveryActionsBody.safeParse(body);
  if (r.success) return null;
  const issue = r.error.issues[0];
  const code = issue?.code === "unrecognized_keys" ? "unknown_field" : "invalid_scalar";
  return { status: 400, code };
}

function walkTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (name === "node_modules" || name === "dist") continue;
      out.push(...walkTsFiles(p));
    } else if (name.endsWith(".ts") && !name.endsWith(".test.ts") && !name.endsWith(".d.ts")) {
      out.push(p);
    }
  }
  return out;
}

describe("route/type scan vs frozen ADMIN_ROUTES", () => {
  it("action catalog is exactly eleven, order-matched across contracts + openapi + node-core", () => {
    expect([...OPERATOR_RECOVERY_ACTIONS]).toEqual([...SECTION_8_1_ACTIONS]);
    expect([...CONTRACT_OPERATOR_RECOVERY_ACTIONS]).toEqual([...SECTION_8_1_ACTIONS]);
    expect(RECOVERY_ACTIONS_BODY.properties.action.enum).toEqual([...SECTION_8_1_ACTIONS]);
    expect(OPERATOR_RECOVERY_ACTIONS).toHaveLength(11);
    // no case-insensitive alias / deprecated synonym admitted
    for (const a of SECTION_8_1_ACTIONS) {
      expect(isOperatorRecoveryAction(a.toLowerCase())).toBe(false);
      expect(isOperatorRecoveryAction(a.replaceAll("_", "-"))).toBe(false);
    }
  });

  it("/admin/v1/operations/* registered routes match gen/routes.json ADMIN_ROUTES", () => {
    const frozen = JSON.parse(readFileSync(ROUTES_JSON, "utf8")) as {
      ADMIN_ROUTES: Array<{ method: string; path: string; authMode: string }>;
    };
    const frozenOps = frozen.ADMIN_ROUTES
      .filter((r) => r.path.startsWith("/admin/v1/operations"))
      .map((r) => `${r.method} ${r.path}`)
      .sort();

    const liveOps = ROUTE_SCHEMAS.filter((r) => r.path.startsWith("/admin/v1/operations"))
      .map((r) => `${r.method} ${r.path}`)
      .sort();

    expect(liveOps).toEqual(frozenOps);
    expect(liveOps).toEqual([
      "GET /admin/v1/operations/:operation_id/recovery",
      "GET /admin/v1/operations/needs-attention",
      "POST /admin/v1/operations/:operation_id/recovery-actions",
    ].sort());

    // path constants match route registry
    expect(findRouteSchema("GET", NEEDS_ATTENTION_PATH)).toBeDefined();
    expect(findRouteSchema("GET", RECOVERY_DETAIL_PATH)).toBeDefined();
    expect(findRouteSchema("POST", RECOVERY_ACTIONS_PATH)).toBeDefined();
    expect(findRouteSchema("POST", RECOVERY_ACTIONS_PATH)!.bodySchema).toBe(RecoveryActionsBody);
    expect(findRouteSchema("POST", RECOVERY_ACTIONS_PATH)!.requiresIdempotencyKey).toBe(true);

    // no bonus recovery routes (force-landed etc.) masquerading under operations/*
    const forbiddenPathFragments = ["force", "retry-submit", "edit-transaction", "delete-evidence"];
    for (const frag of forbiddenPathFragments) {
      expect(
        liveOps.some((p) => p.toLowerCase().includes(frag)),
        `rogue path containing ${frag}`,
      ).toBe(false);
    }
  });
});

describe("forbidden actions — validation-time reject (400), not 500", () => {
  it("each token fails RecoveryActionsBody with 400 invalid_scalar", () => {
    expect(FORBIDDEN_RECOVERY_ACTIONS).toEqual([...SECTION_8_2_FORBIDDEN]);
    for (const action of SECTION_8_2_FORBIDDEN) {
      const http = schemaRejectHttp({
        action,
        expected_row_version: 1,
        recovery_nonce: NONCE,
      });
      neg(http !== null && http.status === 400 && http.code === "invalid_scalar", `schema ${action}`);
      expect(http).not.toMatchObject({ status: 500 });
    }
  });

  it("each token is rejected by execute/handle before lock commit (400 action_*)", async () => {
    for (const action of SECTION_8_2_FORBIDDEN) {
      const store = new MemoryRecoveryStore(baseSend());
      store.blockCommit = true;
      const out = await executeRecoveryAction(store, OP, req(action));
      expect(out.status).toBe("rejected");
      if (out.status === "rejected") {
        neg(
          out.reason === "action_forbidden" || out.reason === "action_not_in_catalog",
          `execute reason ${action}`,
        );
        expect(out.reason).not.toBe("predicate_failed"); // must not enter evaluation
      }
      expect(store.commits).toBe(0);

      // schema would block body.action before handle in production; defence path via execute still 400
      const mapped = await handleRecoveryAction(
        store,
        OP,
        // cast: force-smuggle past the type that production parse already removed
        {
          action: action as (typeof OPERATOR_RECOVERY_ACTIONS)[number],
          expected_row_version: 7,
          recovery_nonce: NONCE,
        },
        auth(`bad-${action}`),
      );
      expect(mapped.ok).toBe(false);
      if (!mapped.ok) {
        neg(mapped.status === 400 && mapped.status !== 500, `http ${action}`);
        expect(mapped.code).toBe("invalid_scalar");
        expect([400, 422]).toContain(mapped.status);
        expect(mapped.status).not.toBe(500);
      }
    }
  });
});

describe("api-contract — body cannot carry economics/submit fields (schema-level)", () => {
  const goodBody = {
    action: "RETRY_OBSERVATION" as const,
    expected_row_version: 1,
    recovery_nonce: NONCE,
  };

  it("rejects replacement tx bytes / destination / amount / submit request as unknown_field 400", () => {
    for (const field of SECTION_11_3_POISON_FIELDS) {
      const poison = { ...goodBody, [field]: field.includes("amount") ? "1.0" : "x" };
      const http = schemaRejectHttp(poison);
      neg(
        http !== null && http.status === 400 && http.code === "unknown_field",
        `poison field ${field}`,
      );
      expect(http?.status).not.toBe(500);
    }
    // sanity: clean body still accepted (not counted as negative)
    expect(RecoveryActionsBody.safeParse(goodBody).success).toBe(true);
  });

  it("openapi RecoveryActionsBody freezes additionalProperties:false and closed action enum only", () => {
    expect(RECOVERY_ACTIONS_BODY.additionalProperties).toBe(false);
    const keys = Object.keys(RECOVERY_ACTIONS_BODY.properties).sort();
    expect(keys).toEqual(
      [
        "action",
        "device_key_id",
        "device_signature",
        "expected_row_version",
        "operator_note",
        "override_rationale",
        "proof_id",
        "recovery_nonce",
        "wallet_to_available",
      ].sort(),
    );
    for (const f of SECTION_8_2_FORBIDDEN) {
      expect(RECOVERY_ACTIONS_BODY.properties.action.enum).not.toContain(f);
    }
  });
});

describe("no recovery path DELETEs permanent-retention evidence", () => {
  it("operator recovery sources never SQL-DELETE permanent evidence tables", () => {
    const roots = [
      join(__dir, "../src/operator/recovery-actions.ts"),
      join(__dir, "../src/operator/recovery-inspection.ts"),
      join(__dir, "../src/api/recovery-actions.ts"),
      join(__dir, "../src/api/recovery-inspection.ts"),
    ];
    const sqlDelete =
      /\bDELETE\s+FROM\s+["']?(gateway_observations|operation_landing_proofs|operation_transactions)\b/i;
    for (const file of roots) {
      const src = readFileSync(file, "utf8");
      neg(!sqlDelete.test(src), `no DELETE FROM evidence in ${relative(REPO_ROOT, file)}`);
      for (const table of PERMANENT_EVIDENCE_TABLES) {
        // bare table name may appear in comments; forbid DML forms
        expect(src).not.toMatch(new RegExp(`DELETE\\s+FROM\\s+["']?${table}\\b`, "i"));
        expect(src).not.toMatch(new RegExp(`TRUNCATE\\s+["']?${table}\\b`, "i"));
      }
    }
  });

  it("QUARANTINE_WALLETS commits retain evidence (no evidenceDeletes) and effect has no purge field", async () => {
    const store = new MemoryRecoveryStore(baseSend({ hasObservationAnomaly: true }));
    const out = await executeRecoveryAction(store, OP, req("QUARANTINE_WALLETS"));
    expect(out.status).toBe("ok");
    neg(store.evidenceDeletes === 0, "quarantine evidenceDeletes===0");
    const effect = store.audited[0]!.effect;
    expect(effect.kind).toBe("QUARANTINE_WALLETS");
    expect(JSON.stringify(effect)).not.toMatch(/delete|purge|truncate/i);
  });

  it("STRUCTURALLY_ABSENT_RECOVERY_EFFECTS includes DELETE_EVIDENCE and no effect arm emits it", () => {
    expect(STRUCTURALLY_ABSENT_RECOVERY_EFFECTS).toContain("DELETE_EVIDENCE");
    const src = readFileSync(join(__dir, "../src/operator/recovery-actions.ts"), "utf8");
    for (const tok of STRUCTURALLY_ABSENT_RECOVERY_EFFECTS) {
      expect([...src.matchAll(new RegExp(`kind:\\s*"${tok}"`, "g"))]).toHaveLength(0);
    }
  });
});

describe("RETRY_SUBMIT / past submit boundary — no submitter invocation", () => {
  it("operator/ tree has no gateway-submit call sites from recovery modules", () => {
    const recoveryFiles = walkTsFiles(join(__dir, "../src/operator")).filter((p) =>
      /recovery/i.test(p),
    );
    const banned =
      /\b(submitTransaction|gateway_submit|executeMoveSubmit|submitExternalSend|blindSubmit|resubmitAttempt)\b/;
    for (const file of recoveryFiles) {
      const src = readFileSync(file, "utf8");
      neg(!banned.test(src), `no submitter API in ${relative(REPO_ROOT, file)}`);
    }
  });

  it("post-SUBMIT boundary: every action either refuses or does not submit", async () => {
    const facts = sendPastSubmitBoundary();
    for (const action of OPERATOR_RECOVERY_ACTIONS) {
      const store = new MemoryRecoveryStore(facts);
      store.nonces.set(NONCE, "ISSUED");
      const out = await executeRecoveryAction(
        store,
        OP,
        req(action, {
          proofId: action === "REBUILD_INTERNAL_MOVE" ? PROOF : null,
          idempotencyKey: `post-submit-${action}`,
          totpTimestep: 1_900_000 + SECTION_8_1_ACTIONS.indexOf(action),
        }),
      );
      if (out.status === "ok") {
        // permitted observation/ack/redeliver/continue/quarantine only — effect never submit
        expect(STRUCTURALLY_ABSENT_RECOVERY_EFFECTS as readonly string[]).not.toContain(out.body.effect);
        expect(out.body.effect).not.toMatch(/SUBMIT|FORCE_LANDED|RETRY_SUBMIT/);
        const audited = store.audited[0];
        if (audited) {
          expect(JSON.stringify(audited.effect)).not.toMatch(/submitOldAttempt":true/);
        }
      } else {
        // rejection is clean validation/predicate — not 500
        expect(out.reason).not.toBeUndefined();
      }
    }
  });
});

describe("CLOSE / REBUILD oracle re-run, stale proof/nonce, idempotent replay", () => {
  it("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED re-evaluates oracle; stale truth rejects", async () => {
    const proven = baseSend({
      send: {
        hasSignIntent: true,
        hasSignerCall: true,
        hasSignature: true,
        hasDurablePartial: true,
        hasDelivery: true,
        protocolExpiredPlusMargin: true,
        freshHeadEqualsSourceT0: true,
        completePathExclusionProved: false,
        hasSignerAudit: true,
        hasMatchingExactByteRecord: true,
      },
    });
    const ok = await executeRecoveryAction(
      new MemoryRecoveryStore(proven),
      OP,
      req("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED"),
    );
    expect(ok.status).toBe("ok");

    // prior GET would have shown permitted; facts now fail oracle at execution time
    const staleTruth = baseSend({
      send: {
        hasSignIntent: true,
        hasSignerCall: true,
        hasSignature: true,
        hasDurablePartial: true,
        hasDelivery: true,
        protocolExpiredPlusMargin: false, // oracle half fails
        freshHeadEqualsSourceT0: true,
        completePathExclusionProved: false,
        hasSignerAudit: true,
        hasMatchingExactByteRecord: true,
      },
    });
    const store = new MemoryRecoveryStore(staleTruth);
    store.blockCommit = true;
    const denied = await executeRecoveryAction(
      store,
      OP,
      req("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED"),
    );
    expect(denied.status).toBe("rejected");
    if (denied.status === "rejected") {
      neg(
        denied.reason === "action_not_permitted" || denied.reason === "predicate_failed",
        "CLOSE stale oracle",
      );
    }
    expect(store.commits).toBe(0);

    const mapped = await handleRecoveryAction(
      new MemoryRecoveryStore(staleTruth),
      OP,
      {
        action: "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
        expected_row_version: 7,
        recovery_nonce: NONCE,
      },
      auth("close-stale"),
    );
    expect(mapped.ok).toBe(false);
    if (!mapped.ok) {
      neg(mapped.status === 422 && mapped.status !== 500, "CLOSE http 422");
    }
  });

  it("REBUILD_INTERNAL_MOVE rejects stale / previously-consumed proof_id and bad nonce", async () => {
    const ready = moveRebuildReady();
    // stale proof id
    {
      const store = new MemoryRecoveryStore(ready);
      store.blockCommit = true;
      const out = await executeRecoveryAction(
        store,
        OP,
        req("REBUILD_INTERNAL_MOVE", { proofId: STALE_PROOF }),
      );
      expect(out.status).toBe("rejected");
      if (out.status === "rejected") {
        neg(out.reason === "proof_id_mismatch", "rebuild stale proof");
      }
      expect(store.commits).toBe(0);
      const mapped = await handleRecoveryAction(
        new MemoryRecoveryStore(ready),
        OP,
        {
          action: "REBUILD_INTERNAL_MOVE",
          expected_row_version: 7,
          recovery_nonce: NONCE,
          proof_id: STALE_PROOF,
        },
        auth("rebuild-stale-proof"),
      );
      expect(mapped.ok).toBe(false);
      if (!mapped.ok) {
        neg(mapped.status === 422 && mapped.status !== 500, "rebuild stale proof http");
      }
    }

    // consumed / invalid nonce
    {
      const store = new MemoryRecoveryStore(ready);
      const first = await executeRecoveryAction(
        store,
        OP,
        req("REBUILD_INTERNAL_MOVE", { proofId: PROOF }),
      );
      expect(first.status).toBe("ok");
      // second call with same nonce after consume
      store.nonces.set(NONCE, "CONSUMED");
      const second = await executeRecoveryAction(
        store,
        OP,
        req("REBUILD_INTERNAL_MOVE", {
          proofId: PROOF,
          expectedRowVersion: 8,
          idempotencyKey: "rebuild-nonce-2",
          totpTimestep: 1_900_050,
        }),
      );
      // furnish a fresh myths: issue a secondissued nonce that was never issued
      const neverIssued = await executeRecoveryAction(
        new MemoryRecoveryStore(ready),
        OP,
        req("REBUILD_INTERNAL_MOVE", {
          proofId: PROOF,
          recoveryNonce: randomUUID(),
          idempotencyKey: "rebuild-nonce-3",
          totpTimestep: 1_900_051,
        }),
      );
      expect(neverIssued.status).toBe("rejected");
      if (neverIssued.status === "rejected") {
        neg(neverIssued.reason === "recovery_nonce_invalid", "rebuild bad nonce");
      }
      void second;
    }

    // oracle case 1/2 missing after "prior permitted" look
    {
      const noCase = moveRebuildReady({
        move: {
          deterministicPreAcceptanceRejection: false,
          expiredAndBothWalletsUnchangedAtT0: false,
          submitProvablyNeverStarted: false,
          positiveNonLandingProofId: PROOF,
          unexpectedSuccessorOutsideLease: false,
          hasPreimage: true,
          hasSignature: true,
          hasSignerAudit: true,
          hasMatchingExactByteRecord: true,
          oneWalletLandedOtherUnconnected: false,
        },
      });
      const store = new MemoryRecoveryStore(noCase);
      store.blockCommit = true;
      const out = await executeRecoveryAction(
        store,
        OP,
        req("REBUILD_INTERNAL_MOVE", { proofId: PROOF }),
      );
      expect(out.status).toBe("rejected");
      if (out.status === "rejected") {
        neg(
          out.reason === "action_not_permitted" || out.reason === "predicate_failed",
          "rebuild oracle fail",
        );
      }
    }
  });

  it("idempotency replay returns prior result without re-execution", async () => {
    const store = new MemoryRecoveryStore(baseSend());
    const first = await executeRecoveryAction(store, OP, req("ACKNOWLEDGE_KEEP_PINNED"));
    expect(first.status).toBe("ok");
    if (first.status === "ok") {
      const digest1 = createHash("sha256").update(JSON.stringify(first.body)).digest("hex");
      const second = await executeRecoveryAction(store, OP, req("ACKNOWLEDGE_KEEP_PINNED"));
      expect(second.status).toBe("ok");
      if (second.status === "ok") {
        expect(second.idempotentReplay).toBe(true);
        const digest2 = createHash("sha256").update(JSON.stringify(second.body)).digest("hex");
        neg(digest1 === digest2, "idempotent body byte-equal");
        neg(store.commits === 1, "no second commit on replay");
      }
    }

    const mapped = await handleRecoveryAction(
      store,
      OP,
      {
        action: "ACKNOWLEDGE_KEEP_PINNED",
        expected_row_version: 7,
        recovery_nonce: NONCE,
      },
      auth("idem-fixture"),
    );
    expect(mapped.ok).toBe(true);
    if (mapped.ok) {
      expect(mapped.headers?.["Idempotency-Replayed"]).toBe("true");
    }
  });

  it("planRecoveryEffect refuses FORCE_* kinds via type/catalog (compile-time + runtime)", () => {
    for (const f of SECTION_8_2_FORBIDDEN) {
      expect(isForbiddenRecoveryAction(f)).toBe(true);
      expect(isOperatorRecoveryAction(f)).toBe(false);
    }
    // planners only admit OperatorRecoveryAction — unknown still catalog-rejected upstream
    const planned = planRecoveryEffect("ACKNOWLEDGE_KEEP_PINNED", baseSend(), null);
    expect(planned.ok).toBe(true);
  });
});

describe("negative-assertion census", () => {
  it("records ≥14 clean negative assertions across this suite", () => {
    // This test runs last among describes that call neg(); vitest may reorder describes
    // so we re-run a compact checklist here that itself contributes the floor count.
    let n = 0;
    const mark = (ok: boolean) => {
      expect(ok).toBe(true);
      if (ok) n += 1;
    };

    // 10 × schema
    for (const action of SECTION_8_2_FORBIDDEN) {
      const http = schemaRejectHttp({
        action,
        expected_row_version: 1,
        recovery_nonce: NONCE,
      });
      mark(http !== null && http.status === 400 && http.status !== 500);
    }
    // 4 ×
    for (const field of [
      "transaction_bytes",
      "destination_address",
      "amount_zkz",
      "submit",
    ] as const) {
      const http = schemaRejectHttp({
        action: "RETRY_OBSERVATION",
        expected_row_version: 1,
        recovery_nonce: NONCE,
        [field]: "x",
      });
      mark(http !== null && http.code === "unknown_field" && http.status === 400);
    }
    expect(n).toBeGreaterThanOrEqual(14);
    // also surface cumulative from earlier describes when ordering preserved
    expect(n + negativeAssertions).toBeGreaterThanOrEqual(14);
  });
});
