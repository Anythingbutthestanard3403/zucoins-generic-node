// Recovery inspection (classification + handlers).
// Spec: the API contract; operations recovery.

import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";

import {
  FORBIDDEN_RECOVERY_ACTIONS,
  NEEDS_ATTENTION_PATH,
  NeedsAttentionQuerySchema,
  OPERATOR_RECOVERY_ACTIONS,
  RECOVERY_DETAIL_PATH,
  classifyRecovery,
  derivePermittedActions,
  handleGetRecovery,
  handleNeedsAttention,
  type RecoveryFacts,
  type RecoveryInspectionStore,
  type IssuedRecoveryNonce,
} from "../src/api/recovery-inspection.js";
import { findRouteSchema } from "../src/api/route-schemas.js";

const OP = "00000000-0000-4000-8000-000000000001";
const WALLET = "00000000-0000-4000-8000-000000000099";

function baseFacts(patch: Partial<RecoveryFacts> = {}): RecoveryFacts {
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
    evidenceManifest: [
      {
        kind: "gateway_observation",
        id: "00000000-0000-4000-8000-000000000010",
        role: "SOURCE",
        digest_sha256: "a".repeat(64),
        summary: "source head observation",
      },
    ],
    diagnostics: [
      {
        at: "2026-07-15T10:00:00.000Z",
        code: "ATTENTION",
        message: "parked for operator",
      },
    ],
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

function receiveFacts(patch: Partial<RecoveryFacts> = {}): RecoveryFacts {
  return baseFacts({
    kind: "RECEIVE_EXTERNAL",
    status: "EXPIRED",
    attentionRequired: true,
    attentionReason: "POST_EXPIRY_RECONCILING",
    send: null,
    receive: {
      codeExpiredPlusMargin: false,
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
    ...patch,
  });
}

function moveFacts(patch: Partial<RecoveryFacts> = {}): RecoveryFacts {
  return baseFacts({
    kind: "MOVE_INTERNAL",
    status: "NEEDS_ATTENTION",
    send: null,
    move: {
      deterministicPreAcceptanceRejection: false,
      expiredAndBothWalletsUnchangedAtT0: false,
      submitProvablyNeverStarted: false,
      positiveNonLandingProofId: null,
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

class MemoryStore implements RecoveryInspectionStore {
  readonly nonces: string[] = [];
  constructor(private readonly byId: Map<string, RecoveryFacts>) {}

  async listNeedsAttention(query: {
    readonly limit?: number;
    readonly after?: string;
    readonly kind?: string;
  } = {}): Promise<{
    readonly items: readonly RecoveryFacts[];
    readonly total: number;
    readonly has_more: boolean;
    readonly next_cursor: string | null;
  }> {
    let rows = [...this.byId.values()].filter(
      (f) => f.attentionRequired || f.status === "NEEDS_ATTENTION",
    );
    if (query.kind !== undefined) {
      rows = rows.filter((f) => f.kind === query.kind);
    }
    // Newest-first by operationId (fixtures use sequential UUIDs).
    rows.sort((a, b) => (a.operationId < b.operationId ? 1 : a.operationId > b.operationId ? -1 : 0));
    const total = rows.length;
    if (query.after !== undefined) {
      const idx = rows.findIndex((f) => f.operationId === query.after);
      rows = idx >= 0 ? rows.slice(idx + 1) : [];
    }
    const limit = query.limit ?? 50;
    const hasMore = rows.length > limit;
    const items = hasMore ? rows.slice(0, limit) : rows;
    const last = items[items.length - 1];
    return {
      items,
      total,
      has_more: hasMore,
      next_cursor: hasMore && last !== undefined ? last.operationId : null,
    };
  }

  async loadRecoveryFacts(operationId: string): Promise<RecoveryFacts | null> {
    return this.byId.get(operationId) ?? null;
  }

  async issueRecoveryNonce(_operationId: string): Promise<IssuedRecoveryNonce> {
    const nonce = randomUUID();
    this.nonces.push(nonce);
    const issued = new Date().toISOString();
    return {
      nonce,
      issued_at: issued,
      expires_at: new Date(Date.now() + 300_000).toISOString(),
    };
  }
}

describe("recovery route registration", () => {
  it("registers GET needs-attention and GET recovery detail", () => {
    const list = findRouteSchema("GET", NEEDS_ATTENTION_PATH);
    const detail = findRouteSchema("GET", RECOVERY_DETAIL_PATH);
    expect(list).toBeDefined();
    expect(list!.requiresIdempotencyKey).toBe(false);
    expect(list!.querySchema).toBeDefined();
    expect(detail).toBeDefined();
    expect(detail!.requiresIdempotencyKey).toBe(false);
  });

  it("does not invent /admin/recovery/status", () => {
    expect(findRouteSchema("GET", "/admin/recovery/status")).toBeUndefined();
  });
});

describe("NeedsAttentionQuerySchema", () => {
  it("accepts empty and valid filters", () => {
    expect(NeedsAttentionQuerySchema.safeParse({}).success).toBe(true);
    expect(
      NeedsAttentionQuerySchema.safeParse({ classification: "INVARIANT_BREACH", limit: "10" })
        .success,
    ).toBe(true);
    // Inclusive ceiling — string coerce to number (query-string shape).
    const ceiling = NeedsAttentionQuerySchema.safeParse({ limit: "200" });
    expect(ceiling.success).toBe(true);
    if (ceiling.success) expect(ceiling.data.limit).toBe(200);
    const withCursor = NeedsAttentionQuerySchema.safeParse({
      after: "00000000-0000-4000-8000-000000000001",
      limit: "25",
    });
    expect(withCursor.success).toBe(true);
    if (withCursor.success) {
      expect(withCursor.data.after).toBe("00000000-0000-4000-8000-000000000001");
      expect(withCursor.data.limit).toBe(25);
    }
  });
  it("rejects unknown fields and bad enums", () => {
    expect(NeedsAttentionQuerySchema.safeParse({ bog: 1 }).success).toBe(false);
    expect(NeedsAttentionQuerySchema.safeParse({ classification: "NOPE" }).success).toBe(false);
    expect(NeedsAttentionQuerySchema.safeParse({ kind: "REFUND" }).success).toBe(false);
  });
  it("rejects non-integer and out-of-range limit (ZTR-1198)", () => {
    for (const limit of ["abc", "0", "-1", "201", "1.5", NaN]) {
      expect(NeedsAttentionQuerySchema.safeParse({ limit }).success, String(limit)).toBe(false);
    }
  });
  it("rejects non-uuid after cursor (ZTR-1284)", () => {
    expect(NeedsAttentionQuerySchema.safeParse({ after: "not-a-uuid" }).success).toBe(false);
    expect(NeedsAttentionQuerySchema.safeParse({ after: "ABCDEF00-0000-4000-8000-000000000001" }).success).toBe(
      false,
    );
  });
});

describe("classifyRecovery + derivePermittedActions (pure)", () => {
  it("closed action set is exactly nine", () => {
    expect(OPERATOR_RECOVERY_ACTIONS).toHaveLength(9);
  });

  it("NEVER includes forbidden actions for any fixture", () => {
    const fixtures: RecoveryFacts[] = [
      baseFacts(),
      baseFacts({ invariantBreachNoted: true }),
      receiveFacts({
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
      }),
      moveFacts({
        move: {
          deterministicPreAcceptanceRejection: true,
          expiredAndBothWalletsUnchangedAtT0: false,
          submitProvablyNeverStarted: false,
          positiveNonLandingProofId: "00000000-0000-4000-8000-000000000077",
          unexpectedSuccessorOutsideLease: false,
          hasPreimage: true,
          hasSignature: true,
          hasSignerAudit: true,
          hasMatchingExactByteRecord: true,
          oneWalletLandedOtherUnconnected: false,
        },
      }),
      baseFacts({
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
    ];
    for (const f of fixtures) {
      const { permittedActions } = derivePermittedActions(f);
      for (const forbidden of FORBIDDEN_RECOVERY_ACTIONS) {
        expect(permittedActions as readonly string[]).not.toContain(forbidden);
      }
      // Force landed / force release / evidence deletion called out by review indicators.
      expect(permittedActions as readonly string[]).not.toContain("FORCE_LANDED");
      expect(permittedActions as readonly string[]).not.toContain("FORCE_RELEASE");
      expect(permittedActions as readonly string[]).not.toContain("DELETE_EVIDENCE");
      expect(permittedActions as readonly string[]).not.toContain("RETRY_SUBMIT");
      expect(permittedActions as readonly string[]).not.toContain("EDIT_TRANSACTION");
      expect(permittedActions as readonly string[]).not.toContain("NODE_SUBMIT_EXTERNAL_SEND");
    }
  });

  it("INVARIANT_BREACH negative path: only QUARANTINE_WALLETS + ACKNOWLEDGE_KEEP_PINNED", () => {
    const f = baseFacts({ invariantBreachNoted: true });
    expect(classifyRecovery(f).classification).toBe("INVARIANT_BREACH");
    const { permittedActions } = derivePermittedActions(f);
    expect([...permittedActions].sort()).toEqual(
      ["ACKNOWLEDGE_KEEP_PINNED", "QUARANTINE_WALLETS"].sort(),
    );
    // Never a resolving action.
    for (const resolving of [
      "RELEASE_EXPIRED_RECEIVE",
      "REBUILD_INTERNAL_MOVE",
      "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
      "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
      "CONTINUE_EXTERNAL_WAIT",
      "REDELIVER_EXACT_PARTIAL",
      "RETRY_OBSERVATION",
    ] as const) {
      expect(permittedActions).not.toContain(resolving);
    }
  });

  it("signer audit without exact bytes → INVARIANT_BREACH (receive)", () => {
    const f = receiveFacts({
      receive: {
        codeExpiredPlusMargin: false,
        noPersistedLandedProof: true,
        freshObservationEqualsT0: false,
        noAnomalyOrSubmitReconcileDebt: true,
        childAbsentOrTerminal: true,
        hasT0: true,
        hasCodeOrArtifactPreimage: false,
        hasArtifactSignature: false,
        hasSignerAudit: true,
        hasMatchingExactByteRecord: false,
      },
    });
    expect(classifyRecovery(f).classification).toBe("INVARIANT_BREACH");
    expect(classifyRecovery(f).rationale).toBe("receive_signer_audit_without_exact_bytes");
  });

  it("positive landing proof wins over mismatched exact-byte facts (LANDED_VERIFIED)", () => {
    // Store bugs historically set hasMatchingExactByteRecord=false by comparing T0
    // completed_transaction_sha256 to the expected-artifact preimage. Once a
    // landing proof exists, classification must still be LANDED_VERIFIED.
    const f = receiveFacts({
      hasLandingProof: true,
      landingProofVerdict: "LANDED_EXACT",
      status: "RECEIVE_LANDED",
      attentionRequired: false,
      receive: {
        codeExpiredPlusMargin: false,
        noPersistedLandedProof: false,
        freshObservationEqualsT0: false,
        noAnomalyOrSubmitReconcileDebt: true,
        childAbsentOrTerminal: true,
        hasT0: true,
        hasCodeOrArtifactPreimage: true,
        hasArtifactSignature: true,
        hasSignerAudit: true,
        hasMatchingExactByteRecord: false,
      },
    });
    expect(classifyRecovery(f)).toMatchObject({
      classification: "LANDED_VERIFIED",
      rationale: "landing_exact",
    });
  });

  it("RELEASE_EXPIRED_RECEIVE only when all five predicates hold", () => {
    const ok = receiveFacts({
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
    });
    expect(classifyRecovery(ok).classification).toBe("PROVEN_NOT_LANDED");
    expect(derivePermittedActions(ok).permittedActions).toContain("RELEASE_EXPIRED_RECEIVE");

    const missingT0Eq = receiveFacts({
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
    expect(derivePermittedActions(missingT0Eq).permittedActions).not.toContain(
      "RELEASE_EXPIRED_RECEIVE",
    );
  });

  it("does not offer RETRY_OBSERVATION for attention-parked EXPIRED receives (ZTR-1283)", () => {
    // Default receiveFacts: RECEIVE_EXTERNAL + EXPIRED + attention_required.
    // RETRY is a no-op CAS bump post-1277; only state-changing paths remain.
    const parked = receiveFacts();
    const parkedActions = derivePermittedActions(parked).permittedActions;
    expect(parkedActions).not.toContain("RETRY_OBSERVATION");
    expect(parkedActions).toContain("ACKNOWLEDGE_KEEP_PINNED");

    // All-five release ground: RELEASE is offered, RETRY still suppressed.
    const releasable = receiveFacts({
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
    });
    const releasableActions = derivePermittedActions(releasable).permittedActions;
    expect(releasableActions).toContain("RELEASE_EXPIRED_RECEIVE");
    expect(releasableActions).not.toContain("RETRY_OBSERVATION");
    expect(releasableActions).toContain("ACKNOWLEDGE_KEEP_PINNED");

    // Non-expiry RETRY paths unchanged: attention-parked non-EXPIRED receive still
    // gets RETRY (e.g. READY parked for lineage/anomaly before expiry CAS).
    const nonExpiredParked = receiveFacts({
      status: "READY",
      attentionReason: "LINEAGE_GAP",
    });
    expect(derivePermittedActions(nonExpiredParked).permittedActions).toContain(
      "RETRY_OBSERVATION",
    );

    // EXPIRED without attention is terminal and not in the inbox; no RETRY.
    const expiredClear = receiveFacts({
      attentionRequired: false,
      attentionReason: null,
    });
    expect(derivePermittedActions(expiredClear).permittedActions).not.toContain(
      "RETRY_OBSERVATION",
    );

    // Send WAITING / NEEDS_ATTENTION RETRY path unchanged (covered above too).
    expect(derivePermittedActions(baseFacts()).permittedActions).toContain(
      "RETRY_OBSERVATION",
    );
  });

  it("REBUILD_INTERNAL_MOVE only with stored positive proof for cases 1/2", () => {
    const ok = moveFacts({
      move: {
        deterministicPreAcceptanceRejection: true,
        expiredAndBothWalletsUnchangedAtT0: false,
        submitProvablyNeverStarted: false,
        positiveNonLandingProofId: "00000000-0000-4000-8000-000000000077",
        unexpectedSuccessorOutsideLease: false,
        hasPreimage: true,
        hasSignature: true,
        hasSignerAudit: true,
        hasMatchingExactByteRecord: true,
        oneWalletLandedOtherUnconnected: false,
      },
    });
    expect(classifyRecovery(ok).classification).toBe("PROVEN_NOT_LANDED");
    expect(derivePermittedActions(ok).permittedActions).toContain("REBUILD_INTERNAL_MOVE");

    const noProofId = moveFacts({
      move: {
        deterministicPreAcceptanceRejection: true,
        expiredAndBothWalletsUnchangedAtT0: false,
        submitProvablyNeverStarted: false,
        positiveNonLandingProofId: null,
        unexpectedSuccessorOutsideLease: false,
        hasPreimage: true,
        hasSignature: true,
        hasSignerAudit: true,
        hasMatchingExactByteRecord: true,
        oneWalletLandedOtherUnconnected: false,
      },
    });
    expect(derivePermittedActions(noProofId).permittedActions).not.toContain(
      "REBUILD_INTERNAL_MOVE",
    );

    const halted = moveFacts({
      haltEngaged: true,
      move: {
        deterministicPreAcceptanceRejection: true,
        expiredAndBothWalletsUnchangedAtT0: false,
        submitProvablyNeverStarted: false,
        positiveNonLandingProofId: "00000000-0000-4000-8000-000000000077",
        unexpectedSuccessorOutsideLease: false,
        hasPreimage: true,
        hasSignature: true,
        hasSignerAudit: true,
        hasMatchingExactByteRecord: true,
        oneWalletLandedOtherUnconnected: false,
      },
    });
    expect(derivePermittedActions(halted).permittedActions).not.toContain("REBUILD_INTERNAL_MOVE");
  });

  it("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED only when two-part oracle holds", () => {
    const ok = baseFacts({
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
    expect(classifyRecovery(ok).classification).toBe("PROVEN_NOT_LANDED");
    expect(derivePermittedActions(ok).permittedActions).toContain(
      "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
    );

    const expiryOnly = baseFacts({
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
    // Expiry alone never proves non-landing.
    expect(classifyRecovery(expiryOnly).classification).not.toBe("PROVEN_NOT_LANDED");
    expect(derivePermittedActions(expiryOnly).permittedActions).not.toContain(
      "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
    );
  });

  it("WAITING send with unexpired partial admits CONTINUE_EXTERNAL_WAIT + REDELIVER", () => {
    const f = baseFacts();
    expect(classifyRecovery(f).classification).toBe("WAITING");
    const actions = derivePermittedActions(f).permittedActions;
    expect(actions).toContain("CONTINUE_EXTERNAL_WAIT");
    expect(actions).toContain("REDELIVER_EXACT_PARTIAL");
    expect(actions).toContain("RETRY_OBSERVATION");
    expect(actions).toContain("ACKNOWLEDGE_KEEP_PINNED");
  });

  it("CLOSE_NEVER_STARTED_EXTERNAL_SEND requires APPROVED + PROVEN_NOT_STARTED", () => {
    const f = baseFacts({
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
    expect(classifyRecovery(f).classification).toBe("PROVEN_NOT_STARTED");
    expect(derivePermittedActions(f).permittedActions).toContain(
      "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
    );
  });

  it("LANDED_VERIFIED strips resolving close/release/rebuild actions", () => {
    const f = baseFacts({
      hasLandingProof: true,
      landingProofVerdict: "LANDED_EXACT",
    });
    expect(classifyRecovery(f).classification).toBe("LANDED_VERIFIED");
    const actions = derivePermittedActions(f).permittedActions;
    expect(actions).not.toContain("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED");
    expect(actions).not.toContain("REBUILD_INTERNAL_MOVE");
    expect(actions).not.toContain("RELEASE_EXPIRED_RECEIVE");
  });
});

describe("handleNeedsAttention / handleGetRecovery", () => {
  it("lists parked ops with freshly derived actions and P0 on breach", async () => {
    const store = new MemoryStore(
      new Map([
        [OP, baseFacts()],
        [
          "00000000-0000-4000-8000-000000000002",
          baseFacts({
            operationId: "00000000-0000-4000-8000-000000000002",
            invariantBreachNoted: true,
            kind: "MOVE_INTERNAL",
            send: null,
            move: {
              deterministicPreAcceptanceRejection: false,
              expiredAndBothWalletsUnchangedAtT0: false,
              submitProvablyNeverStarted: false,
              positiveNonLandingProofId: null,
              unexpectedSuccessorOutsideLease: false,
              hasPreimage: true,
              hasSignature: true,
              hasSignerAudit: true,
              hasMatchingExactByteRecord: true,
              oneWalletLandedOtherUnconnected: false,
            },
          }),
        ],
      ]),
    );
    const result = await handleNeedsAttention(store, {});
    expect(result.operations).toHaveLength(2);
    expect(result.summary.total).toBe(2);
    expect(result.has_more).toBe(false);
    expect(result.next_cursor).toBeNull();
    expect(result.summary.p0_invariant_breach).toBe(1);
    const breach = result.operations.find((o) => o.classification === "INVARIANT_BREACH");
    expect(breach?.severity).toBe("P0");
    expect(breach?.permitted_actions).toEqual([
      "QUARANTINE_WALLETS",
      "ACKNOWLEDGE_KEEP_PINNED",
    ]);
  });

  it("summary.total is full set size when page is truncated (ZTR-1284)", async () => {
    const byId = new Map<string, RecoveryFacts>();
    for (let i = 1; i <= 5; i += 1) {
      const id = `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`;
      byId.set(id, baseFacts({ operationId: id }));
    }
    const store = new MemoryStore(byId);
    const page1 = await handleNeedsAttention(store, { limit: 2 });
    expect(page1.operations).toHaveLength(2);
    expect(page1.summary.total).toBe(5);
    expect(page1.has_more).toBe(true);
    expect(page1.next_cursor).toBeTruthy();
    // Page length must never become the badge authority.
    expect(page1.summary.total).not.toBe(page1.operations.length);

    const page2 = await handleNeedsAttention(store, {
      limit: 2,
      after: page1.next_cursor!,
    });
    expect(page2.operations).toHaveLength(2);
    expect(page2.summary.total).toBe(5);
    expect(page2.has_more).toBe(true);

    const page3 = await handleNeedsAttention(store, {
      limit: 2,
      after: page2.next_cursor!,
    });
    expect(page3.operations).toHaveLength(1);
    expect(page3.summary.total).toBe(5);
    expect(page3.has_more).toBe(false);
    expect(page3.next_cursor).toBeNull();

    const seen = new Set([
      ...page1.operations.map((o) => o.operation_id),
      ...page2.operations.map((o) => o.operation_id),
      ...page3.operations.map((o) => o.operation_id),
    ]);
    expect(seen.size).toBe(5);
  });

  it("detail returns classification, evidence, row_version, lease_epoch, diagnostics", async () => {
    const store = new MemoryStore(new Map([[OP, baseFacts()]]));
    const outcome = await handleGetRecovery(store, OP);
    expect(outcome.status).toBe("ok");
    if (outcome.status !== "ok") return;
    expect(outcome.body.operation_id).toBe(OP);
    expect(outcome.body.classification).toBe("WAITING");
    expect(outcome.body.row_version).toBe(7);
    expect(outcome.body.lease_epoch).toBe(3);
    expect(outcome.body.evidence_manifest).toHaveLength(1);
    expect(outcome.body.held_leases[0]?.wallet_id).toBe(WALLET);
    expect(outcome.body.diagnostics).toHaveLength(1);
    expect(outcome.body.recovery_nonce).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
    expect(outcome.body.permitted_actions.length).toBeGreaterThan(0);
  });

  it("nonce freshness: two consecutive GET recovery calls issue two different nonces", async () => {
    const store = new MemoryStore(new Map([[OP, baseFacts()]]));
    const a = await handleGetRecovery(store, OP);
    const b = await handleGetRecovery(store, OP);
    expect(a.status).toBe("ok");
    expect(b.status).toBe("ok");
    if (a.status !== "ok" || b.status !== "ok") return;
    expect(a.body.recovery_nonce).not.toBe(b.body.recovery_nonce);
    expect(store.nonces).toHaveLength(2);
    expect(new Set(store.nonces).size).toBe(2);
  });

  it("returns not_found for unknown operation", async () => {
    const store = new MemoryStore(new Map());
    const outcome = await handleGetRecovery(store, OP);
    expect(outcome).toEqual({ status: "not_found", operation_id: OP });
  });

  it("is read-only: listing does not issue nonces", async () => {
    const store = new MemoryStore(new Map([[OP, baseFacts()]]));
    await handleNeedsAttention(store, {});
    expect(store.nonces).toHaveLength(0);
  });
});
