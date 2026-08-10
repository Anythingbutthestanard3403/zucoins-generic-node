// recovery-actions POST (fresh evaluation + CAS + forbidden surface).
// Spec: the API contract; operations recovery.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

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
import { RecoveryActionsBody, findRouteSchema } from "../src/api/route-schemas.js";
import { derivePermittedActions } from "../src/operator/recovery-inspection.js";

const __dir = dirname(fileURLToPath(import.meta.url));
const OP = "00000000-0000-4000-8000-000000000001";
const WALLET = "00000000-0000-4000-8000-000000000099";
const PROOF = "00000000-0000-4000-8000-000000000077";
const NONCE = "00000000-0000-4000-8000-000000000055";
const OPERATOR = "00000000-0000-4000-8000-000000000044";

function baseSend(patch: Partial<RecoveryFacts> = {}): RecoveryFacts {
  return {
    operationId: OP,
    kind: "SEND_EXTERNAL",
    status: "NEEDS_ATTENTION",
    attentionRequired: true,
    attentionReason: "UNEXPECTED_HEAD_CHANGE",
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
    ...patch,
  };
}

function receiveAllFive(patch: Partial<RecoveryFacts> = {}): RecoveryFacts {
  return baseSend({
    kind: "RECEIVE_EXTERNAL",
    status: "EXPIRED",
    send: null,
    receive: {
      codeExpiredPlusMargin: true,
      noPersistedLandedProof: true,
      freshObservationEqualsT0: true,
      noAnomalyOrSubmitReconcileDebt: true,
      childAbsentOrTerminal: true,
      hasT0: true,
      hasCodeOrArtifactPreimage: true,
      hasArtifactSignature: true,
      hasSignerAudit: false,
      hasMatchingExactByteRecord: true,
    },
    ...patch,
  });
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

/** In-memory store with CAS, single-use nonce, idempotency, and effect application. */
class MemoryRecoveryStore implements RecoveryActionStore {
  facts: RecoveryFacts | null;
  nonces = new Map<string, "ISSUED" | "CONSUMED">();
  burnedTimesteps = new Set<number>();
  idempotency = new Map<string, { fingerprint: string; body: RecoveryActionSuccessBody }>();
  audited: RecoveryActionCommitInput[] = [];
  commits = 0;
  /** When true, commit is never reached — used for REBUILD-before-write assertion. */
  blockCommit = false;
  partialText = "exact-partial-bytes";
  partialSha = "b".repeat(64);
  mutex: Promise<void> = Promise.resolve();

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
        return {
          ok: false,
          reason: "operation_version_conflict",
        };
      }
      const nonceState = this.nonces.get(input.recoveryNonce);
      if (nonceState !== "ISSUED") {
        return { ok: false, reason: "recovery_nonce_invalid" };
      }
      if (this.burnedTimesteps.has(input.totpTimestep)) {
        return { ok: false, reason: "predicate_failed", detail: "totp_replay" };
      }

      // Apply typed effect — no arm for forbidden kinds exists.
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
      readonly releaseStatus: "RELEASED_T0_UNCHANGED" | null;
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
    case "REBUILD_INTERNAL_MOVE":
      // archiveOldAttemptUnchanged + createNextAttemptNumber; never submit old.
      expect(effect.submitOldAttempt).toBe(false);
      expect(effect.archiveOldAttemptUnchanged).toBe(true);
      expect(effect.createNextAttemptNumber).toBe(true);
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

function auth(key = "idem-1"): RecoveryActionAuthContext {
  return {
    operatorId: OPERATOR,
    totpTimestep: 1_700_000,
    csrfValidated: true,
    idempotencyKey: key,
  };
}

function req(
  action: string,
  extras: Partial<RecoveryActionRequest> = {},
): RecoveryActionRequest {
  return {
    action,
    expectedRowVersion: 7,
    recoveryNonce: NONCE,
    proofId: null,
    operatorNote: "note",
    idempotencyKey: "idem-1",
    operatorId: OPERATOR,
    totpTimestep: 1_700_000,
    csrfValidated: true,
    ...extras,
  };
}

describe("route registration", () => {
  it("registers POST recovery-actions with idempotency + closed body", () => {
    const route = findRouteSchema("POST", RECOVERY_ACTIONS_PATH);
    expect(route).toBeDefined();
    expect(route!.requiresIdempotencyKey).toBe(true);
    expect(route!.bodySchema).toBe(RecoveryActionsBody);
  });

  it("body schema rejects forbidden action tokens at parse", () => {
    for (const bad of [
      "FORCE_LANDED",
      "FORCE_RELEASE",
      "RETRY_SUBMIT",
      "DELETE_EVIDENCE",
      "NODE_SUBMIT_EXTERNAL_SEND",
      "EDIT_TRANSACTION",
    ]) {
      const r = RecoveryActionsBody.safeParse({
        action: bad,
        expected_row_version: 1,
        recovery_nonce: NONCE,
      });
      expect(r.success).toBe(false);
    }
  });

  it("body schema accepts every action and requires recovery_nonce", () => {
    for (const action of OPERATOR_RECOVERY_ACTIONS) {
      const r = RecoveryActionsBody.safeParse({
        action,
        expected_row_version: 1,
        recovery_nonce: NONCE,
      });
      expect(r.success).toBe(true);
    }
    expect(
      RecoveryActionsBody.safeParse({
        action: "RETRY_OBSERVATION",
        expected_row_version: 1,
      }).success,
    ).toBe(false);
  });
});

describe("structural forbidden surface", () => {
  it("closed catalog is exactly nine and has no forbidden tokens", () => {
    expect(OPERATOR_RECOVERY_ACTIONS).toHaveLength(9);
    for (const f of FORBIDDEN_RECOVERY_ACTIONS) {
      expect(isOperatorRecoveryAction(f)).toBe(false);
      expect(isForbiddenRecoveryAction(f)).toBe(true);
    }
  });

  it("source has no force-landed / retry-submit / node-submit / evidence-delete arms", () => {
    const src = readFileSync(
      join(__dir, "../src/operator/recovery-actions.ts"),
      "utf8",
    );
    for (const token of STRUCTURALLY_ABSENT_RECOVERY_EFFECTS) {
      // Mentions only appear in the absentee census constant, never as effect kinds.
      const hits = [...src.matchAll(new RegExp(`kind:\\s*"${token}"`, "g"))];
      expect(hits).toHaveLength(0);
    }
    // Code identifiers — not free-text mentions in section comments.
    expect(src).not.toMatch(/\bsubmitTransaction\b/);
    expect(src).not.toMatch(/\bgateway_submit\b/);
    expect(src).not.toMatch(/case\s+"FORCE_LANDED"/);
    expect(src).not.toMatch(/case\s+"RETRY_SUBMIT"/);
    expect(src).not.toMatch(/kind:\s*"SUBMIT_ATTEMPT"/);
  });

  it("execute rejects forbidden and unknown before any store write", async () => {
    const store = new MemoryRecoveryStore(baseSend());
    store.blockCommit = true;
    for (const action of ["FORCE_LANDED", "RETRY_SUBMIT", "NOT_A_REAL_ACTION"]) {
      const out = await executeRecoveryAction(store, OP, req(action));
      expect(out.status).toBe("rejected");
      if (out.status === "rejected") {
        expect(["action_forbidden", "action_not_in_catalog"]).toContain(out.reason);
      }
      expect(store.commits).toBe(0);
    }
  });
});

describe("fresh evaluation under locks", () => {
  it("REBUILD_INTERNAL_MOVE without proof_id rejects before DB write", async () => {
    const store = new MemoryRecoveryStore(moveRebuildReady());
    store.blockCommit = true;
    const out = await executeRecoveryAction(
      store,
      OP,
      req("REBUILD_INTERNAL_MOVE", { proofId: null }),
    );
    expect(out).toEqual({ status: "rejected", reason: "proof_id_required" });
    expect(store.commits).toBe(0);
    expect(store.nonces.get(NONCE)).toBe("ISSUED");
  });

  it("REBUILD_INTERNAL_MOVE archives old attempt and returns CREATED (no submit)", async () => {
    const store = new MemoryRecoveryStore(moveRebuildReady());
    const out = await executeRecoveryAction(
      store,
      OP,
      req("REBUILD_INTERNAL_MOVE", { proofId: PROOF }),
    );
    expect(out.status).toBe("ok");
    if (out.status === "ok") {
      expect(out.body.status).toBe("CREATED");
      expect(out.body.effect).toBe("REBUILD_INTERNAL_MOVE");
      expect(out.body.row_version).toBe(8);
    }
    const effect = store.audited[0]!.effect;
    expect(effect.kind).toBe("REBUILD_INTERNAL_MOVE");
    if (effect.kind === "REBUILD_INTERNAL_MOVE") {
      expect(effect.submitOldAttempt).toBe(false);
      expect(effect.decision).toBe("SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING");
    }
  });

  it("REBUILD refused when halt engaged", async () => {
    const store = new MemoryRecoveryStore(moveRebuildReady({ haltEngaged: true }));
    // derivePermittedActions already strips REBUILD when haltEngaged — expect not_permitted.
    const out = await executeRecoveryAction(
      store,
      OP,
      req("REBUILD_INTERNAL_MOVE", { proofId: PROOF }),
    );
    expect(out.status).toBe("rejected");
    if (out.status === "rejected") {
      expect(["action_not_permitted", "halt_engaged"]).toContain(out.reason);
    }
  });

  it("RELEASE_EXPIRED_RECEIVE requires all five predicates", async () => {
    const ok = new MemoryRecoveryStore(receiveAllFive());
    const good = await executeRecoveryAction(ok, OP, req("RELEASE_EXPIRED_RECEIVE"));
    expect(good.status).toBe("ok");
    if (good.status === "ok") {
      expect(good.body.release_status).toBe("RELEASED_T0_UNCHANGED");
    }

    const badFacts = receiveAllFive({
      receive: {
        codeExpiredPlusMargin: true,
        noPersistedLandedProof: true,
        freshObservationEqualsT0: false,
        noAnomalyOrSubmitReconcileDebt: true,
        childAbsentOrTerminal: true,
        hasT0: true,
        hasCodeOrArtifactPreimage: true,
        hasArtifactSignature: true,
        hasSignerAudit: false,
        hasMatchingExactByteRecord: true,
      },
    });
    const bad = new MemoryRecoveryStore(badFacts);
    const denied = await executeRecoveryAction(bad, OP, req("RELEASE_EXPIRED_RECEIVE"));
    expect(denied.status).toBe("rejected");
  });

  it("CLOSE_NEVER_STARTED re-proves five negatives under lock", async () => {
    const clean = baseSend({
      status: "APPROVED",
      attentionRequired: false,
      send: {
        hasSignIntent: false,
        hasSignerCall: false,
        hasSignature: false,
        hasDurablePartial: false,
        hasDelivery: false,
        protocolExpiredPlusMargin: false,
        freshHeadEqualsSourceT0: false,
        completePathExclusionProved: false,
        hasSignerAudit: false,
        hasMatchingExactByteRecord: true,
      },
    });
    expect(derivePermittedActions(clean).permittedActions).toContain(
      "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
    );
    const store = new MemoryRecoveryStore(clean);
    const out = await executeRecoveryAction(store, OP, req("CLOSE_NEVER_STARTED_EXTERNAL_SEND"));
    expect(out.status).toBe("ok");
    if (out.status === "ok") expect(out.body.status).toBe("REJECTED");

    const dirty = baseSend({
      status: "APPROVED",
      send: {
        hasSignIntent: true,
        hasSignerCall: false,
        hasSignature: false,
        hasDurablePartial: false,
        hasDelivery: false,
        protocolExpiredPlusMargin: false,
        freshHeadEqualsSourceT0: false,
        completePathExclusionProved: false,
        hasSignerAudit: false,
        hasMatchingExactByteRecord: true,
      },
    });
    const blocked = await executeRecoveryAction(
      new MemoryRecoveryStore(dirty),
      OP,
      req("CLOSE_NEVER_STARTED_EXTERNAL_SEND"),
    );
    expect(blocked.status).toBe("rejected");
  });

  it("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED needs the two-part oracle", async () => {
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
    const store = new MemoryRecoveryStore(proven);
    const out = await executeRecoveryAction(
      store,
      OP,
      req("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED"),
    );
    expect(out.status).toBe("ok");
    if (out.status === "ok") expect(out.body.status).toBe("REJECTED");
  });

  it("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED also admits the complete-path exclusion arm", async () => {
    const excluded = baseSend({
      send: {
        hasSignIntent: true,
        hasSignerCall: true,
        hasSignature: true,
        hasDurablePartial: true,
        hasDelivery: true,
        protocolExpiredPlusMargin: true,
        freshHeadEqualsSourceT0: false,
        completePathExclusionProved: true,
        hasSignerAudit: true,
        hasMatchingExactByteRecord: true,
      },
    });
    expect(derivePermittedActions(excluded).permittedActions).toContain(
      "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
    );
    const out = await executeRecoveryAction(
      new MemoryRecoveryStore(excluded),
      OP,
      req("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED"),
    );
    expect(out.status).toBe("ok");
    if (out.status === "ok") expect(out.body.status).toBe("REJECTED");
  });

  it("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED stays unreachable while both oracle facts are withheld", async () => {
    // The RESERVED posture the SQL store holds today (ZTR-1129 freeze boundary): the
    // non-landing exclusion oracle runs and records what it read, but neither positive is
    // admitted to these two predicates while the action is RESERVED (halt.contract
    // RESERVED_RECOVERY_ACTIONS; D9.6 — no generic PROVEN_NOT_LANDED oracle; D10.21(1) — no
    // PROVEN_NOT_LANDED member in the determination space). With both false the action is
    // neither offered nor admitted, however expired the send is.
    const withheld = baseSend({
      send: {
        hasSignIntent: true,
        hasSignerCall: true,
        hasSignature: true,
        hasDurablePartial: true,
        hasDelivery: true,
        protocolExpiredPlusMargin: true,
        freshHeadEqualsSourceT0: false,
        completePathExclusionProved: false,
        hasSignerAudit: true,
        hasMatchingExactByteRecord: true,
      },
    });
    const permitted = derivePermittedActions(withheld);
    expect(permitted.classification).not.toBe("PROVEN_NOT_LANDED");
    expect(permitted.permittedActions).not.toContain("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED");
    const refused = await executeRecoveryAction(
      new MemoryRecoveryStore(withheld),
      OP,
      req("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED"),
    );
    expect(refused.status).toBe("rejected");
  });

  it("REDELIVER_EXACT_PARTIAL returns identical stored bytes", async () => {
    const store = new MemoryRecoveryStore(baseSend());
    const out = await executeRecoveryAction(store, OP, req("REDELIVER_EXACT_PARTIAL"));
    expect(out.status).toBe("ok");
    if (out.status === "ok") {
      expect(out.body.transfer_code_text).toBe("exact-partial-bytes");
      expect(out.body.transfer_code_sha256).toBe("b".repeat(64));
    }
  });

  it("CONTINUE_EXTERNAL_WAIT clears attention, keeps lease path", async () => {
    const store = new MemoryRecoveryStore(baseSend());
    const out = await executeRecoveryAction(store, OP, req("CONTINUE_EXTERNAL_WAIT"));
    expect(out.status).toBe("ok");
    if (out.status === "ok") {
      expect(out.body.status).toBe("AWAITING_REDEMPTION");
    }
    const effect = store.audited[0]!.effect;
    expect(effect.kind).toBe("CONTINUE_EXTERNAL_WAIT");
    if (effect.kind === "CONTINUE_EXTERNAL_WAIT") {
      expect(effect.keepLease).toBe(true);
    }
  });

  it("ACKNOWLEDGE_KEEP_PINNED does not change protocol status", async () => {
    const store = new MemoryRecoveryStore(baseSend());
    const out = await executeRecoveryAction(store, OP, req("ACKNOWLEDGE_KEEP_PINNED"));
    expect(out.status).toBe("ok");
    if (out.status === "ok") {
      expect(out.body.status).toBe("NEEDS_ATTENTION");
      expect(out.body.row_version).toBe(8);
    }
  });

  it("INVARIANT_BREACH admits only quarantine + acknowledge", async () => {
    const store = new MemoryRecoveryStore(baseSend({ invariantBreachNoted: true }));
    const release = await executeRecoveryAction(store, OP, req("RELEASE_EXPIRED_RECEIVE"));
    expect(release.status).toBe("rejected");
    const q = await executeRecoveryAction(
      new MemoryRecoveryStore(baseSend({ invariantBreachNoted: true })),
      OP,
      req("QUARANTINE_WALLETS"),
    );
    expect(q.status).toBe("ok");
  });

  it("stale row_version → CAS conflict, no double mutation", async () => {
    const store = new MemoryRecoveryStore(baseSend());
    const out = await executeRecoveryAction(
      store,
      OP,
      req("ACKNOWLEDGE_KEEP_PINNED", { expectedRowVersion: 1 }),
    );
    expect(out.status).toBe("rejected");
    if (out.status === "rejected") {
      expect(out.reason).toBe("operation_version_conflict");
    }
    expect(store.commits).toBe(0);
    expect(store.nonces.get(NONCE)).toBe("ISSUED");
  });

  it("race: two concurrent POSTs same expected_row_version — one wins", async () => {
    const store = new MemoryRecoveryStore(baseSend());
    // Second call needs its own nonce (GET issues a fresh one each time).
    store.nonces.set("00000000-0000-4000-8000-000000000066", "ISSUED");
    const a = executeRecoveryAction(
      store,
      OP,
      req("ACKNOWLEDGE_KEEP_PINNED", {
        idempotencyKey: "a",
        totpTimestep: 100,
      }),
    );
    const b = executeRecoveryAction(
      store,
      OP,
      req("ACKNOWLEDGE_KEEP_PINNED", {
        idempotencyKey: "b",
        totpTimestep: 101,
        recoveryNonce: "00000000-0000-4000-8000-000000000066",
      }),
    );
    const [ra, rb] = await Promise.all([a, b]);
    const statuses = [ra.status, rb.status].sort();
    expect(statuses).toEqual(["ok", "rejected"]);
    expect(store.commits).toBe(1);
    expect(store.facts!.rowVersion).toBe(8);
  });

  it("invalid recovery_nonce is rejected", async () => {
    const store = new MemoryRecoveryStore(baseSend());
    const out = await executeRecoveryAction(
      store,
      OP,
      req("ACKNOWLEDGE_KEEP_PINNED", { recoveryNonce: randomUUID() }),
    );
    expect(out.status).toBe("rejected");
    if (out.status === "rejected") expect(out.reason).toBe("recovery_nonce_invalid");
  });

  it("idempotent replay returns stored body without second commit", async () => {
    const store = new MemoryRecoveryStore(baseSend());
    const first = await executeRecoveryAction(store, OP, req("ACKNOWLEDGE_KEEP_PINNED"));
    expect(first.status).toBe("ok");
    // Fresh nonce for a retry would be wrong — same key returns prior body.
    const second = await executeRecoveryAction(store, OP, req("ACKNOWLEDGE_KEEP_PINNED"));
    expect(second.status).toBe("ok");
    if (second.status === "ok") {
      expect(second.idempotentReplay).toBe(true);
      expect(second.body.row_version).toBe(8);
    }
    expect(store.commits).toBe(1);
  });
});

describe("handleRecoveryAction HTTP mapping", () => {
  it("maps version conflict to 409 and success to 200 with CSRF+TOTP context", async () => {
    const store = new MemoryRecoveryStore(baseSend());
    const body = {
      action: "ACKNOWLEDGE_KEEP_PINNED" as const,
      expected_row_version: 7,
      recovery_nonce: NONCE,
    };
    const ok = await handleRecoveryAction(store, OP, body, auth());
    expect(ok.ok).toBe(true);
    if (ok.ok) expect(ok.status).toBe(200);

    const store2 = new MemoryRecoveryStore(baseSend());
    const conflict = await handleRecoveryAction(
      store2,
      OP,
      { ...body, expected_row_version: 99 },
      auth("other"),
    );
    expect(conflict.ok).toBe(false);
    if (!conflict.ok) {
      expect(conflict.status).toBe(409);
      expect(conflict.code).toBe("operation_version_conflict");
    }
  });
});

describe("planRecoveryEffect exhaustiveness over every action", () => {
  it("plans every permitted action on a synthetic fixture matrix", () => {
    const fixtures: Array<{ action: (typeof OPERATOR_RECOVERY_ACTIONS)[number]; facts: RecoveryFacts; proof: string | null }> = [
      { action: "RETRY_OBSERVATION", facts: baseSend(), proof: null },
      { action: "REDELIVER_EXACT_PARTIAL", facts: baseSend(), proof: null },
      { action: "CONTINUE_EXTERNAL_WAIT", facts: baseSend(), proof: null },
      {
        action: "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
        facts: baseSend({
          status: "APPROVED",
          send: {
            hasSignIntent: false,
            hasSignerCall: false,
            hasSignature: false,
            hasDurablePartial: false,
            hasDelivery: false,
            protocolExpiredPlusMargin: false,
            freshHeadEqualsSourceT0: false,
            completePathExclusionProved: false,
            hasSignerAudit: false,
            hasMatchingExactByteRecord: true,
          },
        }),
        proof: null,
      },
      {
        action: "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
        facts: baseSend({
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
        }),
        proof: null,
      },
      { action: "REBUILD_INTERNAL_MOVE", facts: moveRebuildReady(), proof: PROOF },
      { action: "RELEASE_EXPIRED_RECEIVE", facts: receiveAllFive(), proof: null },
      { action: "QUARANTINE_WALLETS", facts: baseSend({ hasObservationAnomaly: true }), proof: null },
      { action: "ACKNOWLEDGE_KEEP_PINNED", facts: baseSend(), proof: null },
    ];
    for (const f of fixtures) {
      const planned = planRecoveryEffect(f.action, f.facts, f.proof);
      expect(planned.ok, f.action).toBe(true);
    }
  });
});
