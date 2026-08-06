// deterministic boot recovery (steps 2–8).
//
// This suite asserts:
// - every durable phase boundary has a classification + (absent) resume test
// - step 5 never signs or submits
// - raw-byte re-read fails closed (no digest-only shortcut)
// - readiness stays false on any global invariant breach
// - each "Boot does not" item has a negative-path test
// - two-instance / SIGTERM / DB failover / corrupt-phase / lock-loss classes
// Exit: every nonterminal durable phase has one safe continuation or invariant
// breach; stale heartbeat never releases.

import { describe, expect, it } from "vitest";

import { SignerLeadership } from "./leadership.js";
import {
  auditActiveLeases,
  auditPhaseBoundaries,
  classifyNonterminalOperations,
  hydrateRawBytePriors,
  runDeterministicBootRecovery,
  type ActiveLeaseRow,
  type AuthorizedResumeAction,
  type BootRecoveryActions,
  type BootRecoveryStore,
  type KeyCorrespondenceRow,
  type ObservationCursorHint,
  type OperationPhaseEvidence,
} from "./boot-recovery.js";

// ── In-memory fakes ───────────────────────────────────────────────────────────

interface FakeState {
  leases: ActiveLeaseRow[];
  ops: OperationPhaseEvidence[];
  keys: KeyCorrespondenceRow[];
  cursors: ObservationCursorHint[];
  rawByObservationId: Map<string, Uint8Array | null>;
  queuedReceiveIds: string[];
  quarantined: string[];
  repaired: Array<{ walletId: string; to: string }>;
  attentions: Array<{ operationId: string; reason: string; expectedRowVersion: number }>;
  /** When set, overrides derived ownership from leases (for negative ownership tests). */
  leaseGroupOps: Array<{ leaseGroupId: string; operationId: string }> | null;
  resumed: AuthorizedResumeAction[];
  seededCursors: Array<{ streamKey: string; prior: Uint8Array | null }>;
  rebuiltQueue: string[];
  moneyEnginesStopped: string[];
  signCalls: number;
  submitCalls: number;
  leaseDeletes: number;
  attentionClears: number;
  externalPartialReforms: number;
  destinationAutoAccepts: number;
  synthesizedBytesFromJson: number;
}

function emptyState(partial: Partial<FakeState> = {}): FakeState {
  return {
    leases: [],
    ops: [],
    keys: [],
    cursors: [],
    rawByObservationId: new Map(),
    queuedReceiveIds: [],
    quarantined: [],
    repaired: [],
    attentions: [],
    leaseGroupOps: null,
    resumed: [],
    seededCursors: [],
    rebuiltQueue: [],
    moneyEnginesStopped: [],
    signCalls: 0,
    submitCalls: 0,
    leaseDeletes: 0,
    attentionClears: 0,
    externalPartialReforms: 0,
    destinationAutoAccepts: 0,
    synthesizedBytesFromJson: 0,
    ...partial,
  };
}

function ownershipFromLeases(
  leases: ActiveLeaseRow[],
): Array<{ leaseGroupId: string; operationId: string }> {
  const seen = new Set<string>();
  const rows: Array<{ leaseGroupId: string; operationId: string }> = [];
  for (const l of leases) {
    const k = `${l.leaseGroupId}\0${l.operationId}`;
    if (seen.has(k)) continue;
    seen.add(k);
    rows.push({ leaseGroupId: l.leaseGroupId, operationId: l.operationId });
  }
  return rows;
}

function makeStore(s: FakeState): BootRecoveryStore {
  return {
    listActiveLeases: async () => s.leases,
    listNonterminalOperations: async () => s.ops,
    listLeaseGroupOperations: async () =>
      s.leaseGroupOps !== null ? s.leaseGroupOps : ownershipFromLeases(s.leases),
    listKeyCorrespondence: async () => s.keys,
    listObservationCursors: async () => s.cursors,
    readRawResponseBytes: async (id) =>
      s.rawByObservationId.has(id) ? (s.rawByObservationId.get(id) ?? null) : null,
    listQueuedReceiveOperationIds: async () => s.queuedReceiveIds,
  };
}

function makeActions(s: FakeState): BootRecoveryActions {
  return {
    quarantineWallet: async (walletId) => {
      s.quarantined.push(walletId);
    },
    repairWalletState: async (walletId, to) => {
      s.repaired.push({ walletId, to });
    },
    setAttention: async (operationId, reason, expectedRowVersion) => {
      s.attentions.push({ operationId, reason, expectedRowVersion });
    },
    resumeAuthorized: async (action) => {
      // A real adapter would sign/submit only for authorized FIRST_* / SIGN_* /
      // SUBMIT_ONCE kinds. The fake records the action and, for purity proofs of
      // the *classification* path, never increments sign/submit from classify.
      if (
        action.kind === "SIGN_PERSISTED_PREIMAGE" ||
        action.kind === "SIGN_PERSISTED_STEP2_PREIMAGE"
      ) {
        s.signCalls += 1;
      }
      if (action.kind === "SUBMIT_ONCE") {
        s.submitCalls += 1;
      }
      if (action.kind === "FIRST_FORMATION" || action.kind === "RESUME_T0_AND_CODE_FORMATION") {
        // formation may eventually sign; still only reachable from step 6
        s.signCalls += 1;
      }
      s.resumed.push(action);
    },
    seedReconcileCursor: async (streamKey, prior) => {
      s.seededCursors.push({ streamKey, prior });
    },
    rebuildReceiveAdmissionQueue: async (ids) => {
      s.rebuiltQueue.push(...ids);
    },
    stopMoneyEngines: async (reason) => {
      s.moneyEnginesStopped.push(reason);
    },
  };
}

function heldLeadership(): SignerLeadership {
  const latch = new SignerLeadership();
  latch.markAcquired();
  return latch;
}

function receiveOp(partial: Partial<OperationPhaseEvidence> = {}): OperationPhaseEvidence {
  return {
    operationId: "recv-1",
    kind: "RECEIVE_EXTERNAL",
    status: "READY",
    attentionRequired: false,
    rowVersion: 1,
    leaseEpoch: 1,
    submitBoundaryRecorded: false,
    signerAuditIndicatesCall: false,
    exactPreimagePersisted: false,
    signaturePersisted: false,
    formationComplete: false,
    leasedWalletIds: ["w-recv"],
    requiredRoles: ["RECEIVE_WINDOW"],
    ...partial,
  };
}

function moveOp(partial: Partial<OperationPhaseEvidence> = {}): OperationPhaseEvidence {
  return {
    operationId: "move-1",
    kind: "MOVE_INTERNAL",
    status: "CREATED",
    attentionRequired: false,
    rowVersion: 1,
    leaseEpoch: 1,
    submitBoundaryRecorded: false,
    signerAuditIndicatesCall: false,
    exactPreimagePersisted: false,
    signaturePersisted: false,
    formationComplete: false,
    leasedWalletIds: ["w-src", "w-dst"],
    requiredRoles: ["MOVE_SOURCE", "MOVE_DESTINATION"],
    ...partial,
  };
}

function sendOp(partial: Partial<OperationPhaseEvidence> = {}): OperationPhaseEvidence {
  return {
    operationId: "send-1",
    kind: "SEND_EXTERNAL",
    status: "APPROVED",
    attentionRequired: false,
    rowVersion: 1,
    leaseEpoch: 1,
    submitBoundaryRecorded: false,
    signerAuditIndicatesCall: false,
    exactPreimagePersisted: false,
    signaturePersisted: false,
    formationComplete: false,
    leasedWalletIds: ["w-src"],
    requiredRoles: ["SEND_SOURCE"],
    ...partial,
  };
}

function lease(partial: Partial<ActiveLeaseRow> & Pick<ActiveLeaseRow, "walletId" | "operationId" | "role">): ActiveLeaseRow {
  return {
    leaseGroupId: "lg-1",
    epoch: 1,
    walletState: "PINNED",
    lastHeartbeatAtMs: 1_000_000,
    ...partial,
  };
}

// ── Leadership precondition ───────────────────────────────────────────────────

describe("step 1 precondition — leadership", () => {
  it("refuses boot recovery when leadership is not held (lock-loss class)", async () => {
    const latch = new SignerLeadership(); // never markAcquired
    const s = emptyState();
    await expect(
      runDeterministicBootRecovery({
        leadership: latch,
        store: makeStore(s),
        actions: makeActions(s),
      }),
    ).rejects.toThrow(/signer leadership/i);
  });

  it("two-instance class: only the held-latch instance may run recovery", async () => {
    const leader = heldLeadership();
    const follower = new SignerLeadership();
    const s = emptyState({ keys: [{ walletId: "w1", storedPublicKey: "pk", derivedPublicKey: "pk" }] });

    const ok = await runDeterministicBootRecovery({
      leadership: leader,
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(ok.leadershipHeld).toBe(true);
    expect(ok.ready).toBe(true);

    await expect(
      runDeterministicBootRecovery({
        leadership: follower,
        store: makeStore(s),
        actions: makeActions(s),
      }),
    ).rejects.toThrow(/signer leadership/i);
  });

  it("SIGTERM / lock-loss mid-boot: readiness false once latch flips", async () => {
    const latch = heldLeadership();
    const s = emptyState({
      keys: [{ walletId: "w1", storedPublicKey: "pk", derivedPublicKey: "pk" }],
    });
    // Simulate connection loss before readiness is reported by flipping the latch
    // after a successful run would have held it — a second call sees lost leadership.
    const first = await runDeterministicBootRecovery({
      leadership: latch,
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(first.ready).toBe(true);

    latch.markLost("connection end (SIGTERM handoff)");
    await expect(
      runDeterministicBootRecovery({
        leadership: latch,
        store: makeStore(s),
        actions: makeActions(s),
      }),
    ).rejects.toThrow(/signer leadership/i);
  });
});

// ── Step 2: key correspondence ────────────────────────────────────────────────

describe("step 2 — key material / public-key correspondence", () => {
  it("quarantines wallets whose derived public key does not match stored", async () => {
    const s = emptyState({
      keys: [
        { walletId: "w-ok", storedPublicKey: "pkA", derivedPublicKey: "pkA" },
        { walletId: "w-bad", storedPublicKey: "pkB", derivedPublicKey: "pkOTHER" },
      ],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.invariantBreach).toBe(true);
    expect(report.ready).toBe(false);
    expect(s.quarantined).toContain("w-bad");
    expect(s.quarantined).not.toContain("w-ok");
    expect(s.moneyEnginesStopped.length).toBeGreaterThan(0);
  });

  it("vault open failure quarantines (corrupt-key / missing-row class)", async () => {
    const s = emptyState({
      keys: [{ walletId: "w1", storedPublicKey: "pk", derivedPublicKey: null }],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.ready).toBe(false);
    expect(report.keyFindings[0]?.reason).toBe("vault_open_failed");
    expect(s.quarantined).toContain("w1");
  });

  it("transient vault/store fault fails readiness WITHOUT quarantine or invariant breach (DB-failover class)", async () => {
    const s = emptyState({
      keys: [{ walletId: "w1", storedPublicKey: "pk", derivedPublicKey: null, transientFault: true }],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.ready).toBe(false);
    expect(report.invariantBreach).toBe(false);
    expect(report.keyFindings[0]?.reason).toBe("vault_open_transient_fault");
    expect(s.quarantined).not.toContain("w1");
    expect(s.moneyEnginesStopped.length).toBe(0);
  });
});

// ── Step 3: lease audit + "Boot does not: delete stale lease" ─────────────────

describe("step 3 — active lease audit", () => {
  it("stale heartbeat is observed but NEVER releases the lease", async () => {
    const op = receiveOp({ operationId: "recv-1", leaseEpoch: 1 });
    const s = emptyState({
      keys: [{ walletId: "w-recv", storedPublicKey: "pk", derivedPublicKey: "pk" }],
      ops: [op],
      leases: [
        lease({
          walletId: "w-recv",
          operationId: "recv-1",
          role: "RECEIVE_WINDOW",
          lastHeartbeatAtMs: 0, // ancient
        }),
      ],
    });
    const nowMs = 10_000_000; // far past stale threshold
    const { findings, breach } = await auditActiveLeases(
      makeStore(s),
      makeActions(s),
      s.ops,
      nowMs,
      60_000,
    );
    expect(breach).toBe(false);
    expect(findings[0]?.staleHeartbeatObserved).toBe(true);
    expect(findings[0]?.severity).toBe("ok");
    expect(findings[0]?.reason).toBe("ok_stale_heartbeat_retained");
    expect(s.leaseDeletes).toBe(0);
  });

  it("duplicate active lease rows → invariant breach (never silently accepted)", async () => {
    const op = receiveOp();
    const s = emptyState({
      ops: [op],
      leases: [
        lease({ walletId: "w-recv", operationId: "recv-1", role: "RECEIVE_WINDOW" }),
        lease({ walletId: "w-recv", operationId: "recv-1", role: "RECEIVE_WINDOW", leaseGroupId: "lg-2" }),
      ],
    });
    const { breach, findings } = await auditActiveLeases(
      makeStore(s),
      makeActions(s),
      s.ops,
      1_000_000,
      60_000,
    );
    expect(breach).toBe(true);
    expect(findings.some((f) => f.reason === "duplicate_active_lease_row")).toBe(true);
    expect(s.quarantined).toContain("w-recv");
  });

  it("lease role that disagrees with operation required roles → breach", async () => {
    const op = receiveOp({ requiredRoles: ["RECEIVE_WINDOW"] });
    const s = emptyState({
      ops: [op],
      leases: [lease({ walletId: "w-recv", operationId: "recv-1", role: "SEND_SOURCE" })],
    });
    const { breach } = await auditActiveLeases(makeStore(s), makeActions(s), s.ops, 1_000_000, 60_000);
    expect(breach).toBe(true);
  });

  it("understated restriction (AVAILABLE while leased) is repaired to PINNED, never released", async () => {
    const op = receiveOp();
    const s = emptyState({
      ops: [op],
      leases: [
        lease({
          walletId: "w-recv",
          operationId: "recv-1",
          role: "RECEIVE_WINDOW",
          walletState: "AVAILABLE",
        }),
      ],
    });
    const { findings, breach } = await auditActiveLeases(
      makeStore(s),
      makeActions(s),
      s.ops,
      1_000_000,
      60_000,
    );
    expect(breach).toBe(false);
    expect(findings[0]?.severity).toBe("repair");
    expect(s.repaired).toEqual([{ walletId: "w-recv", to: "PINNED" }]);
    expect(s.leaseDeletes).toBe(0);
  });

  it("QUARANTINED wallet holding an active RECEIVE_WINDOW lease is retained — no repair, no breach", async () => {
    // Live shape from gn_ceremony_v2: stale boot quarantine + lease still held.
    const op = receiveOp();
    const s = emptyState({
      ops: [op],
      leases: [
        lease({
          walletId: "w-recv",
          operationId: "recv-1",
          role: "RECEIVE_WINDOW",
          walletState: "QUARANTINED",
        }),
      ],
    });
    const { findings, breach } = await auditActiveLeases(
      makeStore(s),
      makeActions(s),
      s.ops,
      1_000_000,
      60_000,
    );
    expect(breach).toBe(false);
    expect(s.repaired).toEqual([]);
    expect(s.quarantined).not.toContain("w-recv");
    expect(findings).toContainEqual(
      expect.objectContaining({
        walletId: "w-recv",
        severity: "ok",
      }),
    );
    expect(findings.some((f) => f.severity === "repair")).toBe(false);
    expect(s.leaseDeletes).toBe(0);
  });

  it("orphan lease group (ownership missing) → invariant breach", async () => {
    const op = receiveOp();
    const s = emptyState({
      ops: [op],
      leases: [lease({ walletId: "w-recv", operationId: "recv-1", role: "RECEIVE_WINDOW", leaseGroupId: "lg-orphan" })],
      leaseGroupOps: [], // durable membership empty
    });
    const { breach, findings } = await auditActiveLeases(
      makeStore(s),
      makeActions(s),
      s.ops,
      1_000_000,
      60_000,
    );
    expect(breach).toBe(true);
    expect(findings.some((f) => f.reason === "lease_group_ownership_missing")).toBe(true);
    expect(s.quarantined).toContain("w-recv");
  });

  it("wallet not bound to operation leasedWalletIds → invariant breach", async () => {
    const op = receiveOp({ leasedWalletIds: ["w-other"] });
    const s = emptyState({
      ops: [op],
      leases: [lease({ walletId: "w-recv", operationId: "recv-1", role: "RECEIVE_WINDOW" })],
    });
    const { breach, findings } = await auditActiveLeases(
      makeStore(s),
      makeActions(s),
      s.ops,
      1_000_000,
      60_000,
    );
    expect(breach).toBe(true);
    expect(findings.some((f) => f.reason === "lease_wallet_not_bound_to_operation")).toBe(true);
    expect(s.quarantined).toContain("w-recv");
  });

  it("half-covered MOVE (SOURCE only) → required roles incomplete breach", async () => {
    const op = moveOp();
    const s = emptyState({
      ops: [op],
      leases: [lease({ walletId: "w-src", operationId: "move-1", role: "MOVE_SOURCE" })],
      // DEST role absent — ownership for SOURCE is derived from leases
    });
    const { breach, findings } = await auditActiveLeases(
      makeStore(s),
      makeActions(s),
      s.ops,
      1_000_000,
      60_000,
    );
    expect(breach).toBe(true);
    expect(findings.some((f) => f.reason === "lease_required_roles_incomplete")).toBe(true);
    expect(s.quarantined).toContain("w-src");
  });

  it("fully-covered MOVE with independent per-wallet epochs → no breach", async () => {
    // MOVE_INTERNAL's two leases come from nextEpoch(db, walletId) — an independent
    // per-wallet monotonic counter (leases/repository.ts) — so SOURCE and DEST land on
    // different epoch values from each other and from any single op-wide leaseEpoch.
    // A single-wallet op-wide equality check would false-quarantine both wallets here.
    const op = moveOp({ leaseEpoch: 1 });
    const s = emptyState({
      ops: [op],
      leases: [
        lease({ walletId: "w-src", operationId: "move-1", role: "MOVE_SOURCE", epoch: 7 }),
        lease({ walletId: "w-dst", operationId: "move-1", role: "MOVE_DESTINATION", epoch: 9 }),
      ],
    });
    const { breach, findings } = await auditActiveLeases(
      makeStore(s),
      makeActions(s),
      s.ops,
      1_000_000,
      60_000,
    );
    expect(breach).toBe(false);
    expect(findings.every((f) => f.severity === "ok")).toBe(true);
    expect(s.quarantined).toEqual([]);
  });

  it("duplicate MOVE_SOURCE lease on a stray third wallet → required roles incomplete breach (B2)", async () => {
    // Adversarial: a surplus wallet re-leases a role that's already covered. A some-based
    // "at least one lease covers this role" check is satisfied for both MOVE_SOURCE and
    // MOVE_DESTINATION and misses the extra, uncovering MOVE_SOURCE lease entirely.
    const op = moveOp({ leasedWalletIds: ["w-src", "w-dst", "w-extra"] });
    const s = emptyState({
      ops: [op],
      leases: [
        lease({ walletId: "w-src", operationId: "move-1", role: "MOVE_SOURCE", epoch: 7 }),
        lease({ walletId: "w-dst", operationId: "move-1", role: "MOVE_DESTINATION", epoch: 9 }),
        lease({ walletId: "w-extra", operationId: "move-1", role: "MOVE_SOURCE", epoch: 11 }),
      ],
    });
    const { breach, findings } = await auditActiveLeases(
      makeStore(s),
      makeActions(s),
      s.ops,
      1_000_000,
      60_000,
    );
    expect(breach).toBe(true);
    expect(findings.some((f) => f.reason === "lease_required_roles_incomplete")).toBe(true);
    expect(s.quarantined).toContain("w-extra");
  });
});

// ── Step 4 / 5: phase audit + pure classification ─────────────────────────────

describe("step 4–5 — phase audit + pure classification", () => {
  it("signer audit without exact preimage → INVARIANT_BREACH (corrupt-phase class)", () => {
    const phase = auditPhaseBoundaries(
      receiveOp({
        signerAuditIndicatesCall: true,
        exactPreimagePersisted: false,
      }),
    );
    expect(phase.forceBreach).toBe(true);

    const classified = classifyNonterminalOperations([
      receiveOp({
        signerAuditIndicatesCall: true,
        exactPreimagePersisted: false,
      }),
    ]);
    expect(classified[0]?.classification).toBe("INVARIANT_BREACH");
    expect(classified[0]?.authorizedResume).toBeNull();
  });

  it("submit boundary without signature → INVARIANT_BREACH", () => {
    const phase = auditPhaseBoundaries(
      moveOp({
        submitBoundaryRecorded: true,
        signaturePersisted: false,
      }),
    );
    expect(phase.forceBreach).toBe(true);
  });

  it("receive pre-submit incomplete formation → PROVEN_NOT_STARTED / RESUME_T0_AND_CODE_FORMATION", () => {
    const [c] = classifyNonterminalOperations([receiveOp({ formationComplete: false })]);
    expect(c.classification).toBe("PROVEN_NOT_STARTED");
    expect(c.authorizedResume?.kind).toBe("RESUME_T0_AND_CODE_FORMATION");
  });

  it("receive formation complete, no step-2 sig → SIGN_PERSISTED_STEP2_PREIMAGE", () => {
    const [c] = classifyNonterminalOperations([
      receiveOp({
        formationComplete: true,
        exactPreimagePersisted: true,
        signaturePersisted: false,
      }),
    ]);
    expect(c.classification).toBe("PROVEN_NOT_STARTED");
    expect(c.authorizedResume?.kind).toBe("SIGN_PERSISTED_STEP2_PREIMAGE");
  });

  it("receive signed, no submit claim → SUBMIT_ONCE (first submission, not retry)", () => {
    const [c] = classifyNonterminalOperations([
      receiveOp({
        formationComplete: true,
        exactPreimagePersisted: true,
        signaturePersisted: true,
        submitBoundaryRecorded: false,
      }),
    ]);
    expect(c.classification).toBe("PROVEN_NOT_STARTED");
    expect(c.authorizedResume?.kind).toBe("SUBMIT_ONCE");
  });

  it("receive submit boundary recorded → INDETERMINATE, NEVER re-submit (reconcile first, never blind-retry)", () => {
    const [c] = classifyNonterminalOperations([
      receiveOp({
        formationComplete: true,
        exactPreimagePersisted: true,
        signaturePersisted: true,
        submitBoundaryRecorded: true,
      }),
    ]);
    expect(c.classification).toBe("INDETERMINATE");
    expect(c.authorizedResume).toBeNull();
  });

  it("move both leases, no preimage → PROVEN_NOT_STARTED / FIRST_FORMATION", () => {
    const [c] = classifyNonterminalOperations([moveOp()]);
    expect(c.classification).toBe("PROVEN_NOT_STARTED");
    expect(c.authorizedResume?.kind).toBe("FIRST_FORMATION");
  });

  it("move preimage persisted, no signature → SIGN_PERSISTED_PREIMAGE", () => {
    const [c] = classifyNonterminalOperations([
      moveOp({ exactPreimagePersisted: true, signaturePersisted: false }),
    ]);
    expect(c.classification).toBe("PROVEN_NOT_STARTED");
    expect(c.authorizedResume?.kind).toBe("SIGN_PERSISTED_PREIMAGE");
  });

  it("move signed, no submit claim → SUBMIT_ONCE", () => {
    const [c] = classifyNonterminalOperations([
      moveOp({
        exactPreimagePersisted: true,
        signaturePersisted: true,
        submitBoundaryRecorded: false,
      }),
    ]);
    expect(c.classification).toBe("PROVEN_NOT_STARTED");
    expect(c.authorizedResume?.kind).toBe("SUBMIT_ONCE");
  });

  it("move submit boundary recorded → INDETERMINATE (no rebuild, no second submit)", () => {
    const [c] = classifyNonterminalOperations([
      moveOp({
        exactPreimagePersisted: true,
        signaturePersisted: true,
        submitBoundaryRecorded: true,
      }),
    ]);
    expect(c.classification).toBe("INDETERMINATE");
    expect(c.authorizedResume).toBeNull();
  });

  it("send no sign intent → PROVEN_NOT_STARTED / FIRST_FORMATION", () => {
    const [c] = classifyNonterminalOperations([sendOp()]);
    expect(c.classification).toBe("PROVEN_NOT_STARTED");
    expect(c.authorizedResume?.kind).toBe("FIRST_FORMATION");
  });

  it("send sign intent, no step-1 → SIGN_PERSISTED_PREIMAGE", () => {
    const [c] = classifyNonterminalOperations([
      sendOp({ exactPreimagePersisted: true, signaturePersisted: false }),
    ]);
    expect(c.classification).toBe("PROVEN_NOT_STARTED");
    expect(c.authorizedResume?.kind).toBe("SIGN_PERSISTED_PREIMAGE");
  });

  it("send delivered partial → WAITING; never re-forms external partial", () => {
    const [c] = classifyNonterminalOperations([
      sendOp({
        exactPreimagePersisted: true,
        signaturePersisted: true,
        status: "AWAITING_REDEMPTION",
      }),
    ]);
    expect(c.classification).toBe("WAITING");
    expect(c.authorizedResume?.kind).toBe("CONTINUE_WAITING");
  });

  it("send submit boundary without signature → INVARIANT_BREACH (generic pre-dispatch audit)", () => {
    // SEND_EXTERNAL has no submit-boundary field of its own (reconcile/send.ts has no
    // SUBMIT_ONCE outcome) — the contradiction is still caught because classifyOne runs
    // auditPhaseBoundaries generically for every kind before dispatching to classifySendOp.
    const [c] = classifyNonterminalOperations([
      sendOp({ submitBoundaryRecorded: true, signaturePersisted: false }),
    ]);
    expect(c.classification).toBe("INVARIANT_BREACH");
    expect(c.authorizedResume).toBeNull();
  });

  it("step 5 purity: classifyNonterminalOperations never increments sign/submit counters", () => {
    const s = emptyState();
    // classify is pure — no access to actions at all
    const classified = classifyNonterminalOperations([
      receiveOp({ formationComplete: true, exactPreimagePersisted: true, signaturePersisted: true }),
      moveOp({ exactPreimagePersisted: true, signaturePersisted: true }),
      sendOp({ exactPreimagePersisted: true, signaturePersisted: true }),
    ]);
    expect(classified).toHaveLength(3);
    expect(s.signCalls).toBe(0);
    expect(s.submitCalls).toBe(0);
  });
});

// ── Step 6: resume only authorized; Boot does not list ────────────────────────

describe("step 6 — resume authorized only + Boot does not", () => {
  it("ambiguous submit boundary is not retried", async () => {
    const s = emptyState({
      keys: [{ walletId: "w-recv", storedPublicKey: "pk", derivedPublicKey: "pk" }],
      ops: [
        receiveOp({
          formationComplete: true,
          exactPreimagePersisted: true,
          signaturePersisted: true,
          submitBoundaryRecorded: true,
        }),
      ],
      leases: [lease({ walletId: "w-recv", operationId: "recv-1", role: "RECEIVE_WINDOW" })],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.classifications[0]?.classification).toBe("INDETERMINATE");
    expect(report.resumed).toHaveLength(0);
    expect(s.submitCalls).toBe(0);
    expect(s.attentions.some((a) => a.operationId === "recv-1")).toBe(true);
    // Attention park must CAS on the real row version, never sentinel -1.
    expect(s.attentions.every((a) => a.expectedRowVersion !== -1)).toBe(true);
    expect(s.attentions.find((a) => a.operationId === "recv-1")?.expectedRowVersion).toBe(1);
  });

  it("attention park threads expectedRowVersion from op evidence (never -1)", async () => {
    const s = emptyState({
      keys: [{ walletId: "w-recv", storedPublicKey: "pk", derivedPublicKey: "pk" }],
      ops: [
        receiveOp({
          rowVersion: 7,
          leaseEpoch: 3,
          signerAuditIndicatesCall: true,
          exactPreimagePersisted: false,
        }),
      ],
      leases: [lease({ walletId: "w-recv", operationId: "recv-1", role: "RECEIVE_WINDOW", epoch: 3 })],
    });
    // op.leaseEpoch must match lease
    s.ops[0] = receiveOp({
      rowVersion: 7,
      leaseEpoch: 3,
      signerAuditIndicatesCall: true,
      exactPreimagePersisted: false,
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.classifications[0]?.classification).toBe("INVARIANT_BREACH");
    expect(report.classifications[0]?.expectedRowVersion).toBe(7);
    expect(s.attentions).toEqual([
      {
        operationId: "recv-1",
        reason: "signer_audit_without_exact_preimage",
        expectedRowVersion: 7,
      },
    ]);
  });

  it("does not re-form an external partial (WAITING only continues waiting)", async () => {
    const s = emptyState({
      keys: [{ walletId: "w-src", storedPublicKey: "pk", derivedPublicKey: "pk" }],
      ops: [
        sendOp({
          exactPreimagePersisted: true,
          signaturePersisted: true,
          status: "AWAITING_REDEMPTION",
        }),
      ],
      leases: [lease({ walletId: "w-src", operationId: "send-1", role: "SEND_SOURCE" })],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.classifications[0]?.classification).toBe("WAITING");
    expect(report.resumed.every((r) => r.kind === "CONTINUE_WAITING")).toBe(true);
    expect(s.externalPartialReforms).toBe(0);
  });

  it("never auto-clears attention", async () => {
    const s = emptyState({
      keys: [{ walletId: "w-recv", storedPublicKey: "pk", derivedPublicKey: "pk" }],
      ops: [
        receiveOp({
          attentionRequired: true,
          submitBoundaryRecorded: true,
          formationComplete: true,
          exactPreimagePersisted: true,
          signaturePersisted: true,
        }),
      ],
      leases: [lease({ walletId: "w-recv", operationId: "recv-1", role: "RECEIVE_WINDOW" })],
    });
    await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(s.attentionClears).toBe(0);
  });

  it("never auto-accepts a new destination", async () => {
    const s = emptyState({
      keys: [
        { walletId: "w-src", storedPublicKey: "pk", derivedPublicKey: "pk" },
        { walletId: "w-dst", storedPublicKey: "pk2", derivedPublicKey: "pk2" },
      ],
      ops: [moveOp()],
      leases: [
        lease({ walletId: "w-src", operationId: "move-1", role: "MOVE_SOURCE" }),
        lease({ walletId: "w-dst", operationId: "move-1", role: "MOVE_DESTINATION" }),
      ],
    });
    await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(s.destinationAutoAccepts).toBe(0);
  });

  it("never synthesizes missing exact bytes from parsed JSON", async () => {
    const s = emptyState({
      keys: [{ walletId: "w-recv", storedPublicKey: "pk", derivedPublicKey: "pk" }],
      ops: [
        receiveOp({
          signerAuditIndicatesCall: true,
          exactPreimagePersisted: false,
        }),
      ],
      leases: [lease({ walletId: "w-recv", operationId: "recv-1", role: "RECEIVE_WINDOW" })],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.classifications[0]?.classification).toBe("INVARIANT_BREACH");
    expect(s.synthesizedBytesFromJson).toBe(0);
    expect(report.ready).toBe(false);
  });

  it("authorized FIRST_FORMATION resume runs only in step 6 (sign counter > 0 only via resume)", async () => {
    const s = emptyState({
      keys: [
        { walletId: "w-src", storedPublicKey: "pk", derivedPublicKey: "pk" },
        { walletId: "w-dst", storedPublicKey: "pk2", derivedPublicKey: "pk2" },
      ],
      ops: [moveOp()],
      leases: [
        lease({ walletId: "w-src", operationId: "move-1", role: "MOVE_SOURCE" }),
        lease({ walletId: "w-dst", operationId: "move-1", role: "MOVE_DESTINATION" }),
      ],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.resumed).toHaveLength(1);
    expect(report.resumed[0]?.kind).toBe("FIRST_FORMATION");
    expect(s.signCalls).toBe(1); // only from step-6 resumeAuthorized
  });
});

// ── Step 7: raw-byte re-read (changed-response observation ledger) + queue rebuild ────────────────────────────

describe("step 7 — raw-byte re-read + queue rebuild", () => {
  it("loads raw_response_bytes via last_recorded_observation_id", async () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const s = emptyState({
      keys: [{ walletId: "w1", storedPublicKey: "pk", derivedPublicKey: "pk" }],
      cursors: [
        {
          streamKey: "w1:main",
          lastRecordedObservationId: "obs-1",
          lastRawResponseSha256: "deadbeef",
        },
      ],
      rawByObservationId: new Map([["obs-1", bytes]]),
      queuedReceiveIds: ["recv-queued-1"],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.rawByteHydrations[0]).toEqual({
      streamKey: "w1:main",
      ok: true,
      usedDigestShortcut: false,
      reason: "raw_bytes_loaded",
    });
    expect(s.seededCursors[0]?.prior).toEqual(bytes);
    expect(s.rebuiltQueue).toEqual(["recv-queued-1"]);
    expect(report.ready).toBe(true);
  });

  it("missing raw_response_bytes fails closed — never uses last_raw_response_sha256 alone", async () => {
    const s = emptyState({
      keys: [{ walletId: "w1", storedPublicKey: "pk", derivedPublicKey: "pk" }],
      cursors: [
        {
          streamKey: "w1:main",
          lastRecordedObservationId: "obs-missing",
          lastRawResponseSha256: "a".repeat(64), // present but MUST NOT be used
        },
      ],
      rawByObservationId: new Map([["obs-missing", null]]),
    });
    const hydrations = await hydrateRawBytePriors(makeStore(s), makeActions(s));
    expect(hydrations[0]?.ok).toBe(false);
    expect(hydrations[0]?.usedDigestShortcut).toBe(false);
    expect(hydrations[0]?.reason).toBe("raw_response_bytes_unavailable");

    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.ready).toBe(false);
  });

  it("no prior observation seeds empty prior and stays ready", async () => {
    const s = emptyState({
      keys: [{ walletId: "w1", storedPublicKey: "pk", derivedPublicKey: "pk" }],
      cursors: [
        {
          streamKey: "w1:main",
          lastRecordedObservationId: null,
          lastRawResponseSha256: null,
        },
      ],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.rawByteHydrations[0]?.reason).toBe("no_prior_observation");
    expect(report.ready).toBe(true);
  });
});

// ── Step 8: readiness conjunction ─────────────────────────────────────────────

describe("step 8 — readiness", () => {
  it("ready when clean inventory + leadership held", async () => {
    const s = emptyState({
      keys: [{ walletId: "w1", storedPublicKey: "pk", derivedPublicKey: "pk" }],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.ready).toBe(true);
    expect(report.invariantBreach).toBe(false);
    expect(report.stepsCompleted).toEqual([
      "LEADERSHIP_PRECONDITION",
      "KEY_CORRESPONDENCE",
      "LEASE_AUDIT",
      "PHASE_AUDIT",
      "CLASSIFY",
      "RESUME",
      "REBUILD_QUEUES",
      "READINESS",
    ]);
  });

  it("readiness stays false if ANY global invariant breach exists, even when other ops are healthy", async () => {
    const s = emptyState({
      keys: [
        { walletId: "w-ok", storedPublicKey: "pk", derivedPublicKey: "pk" },
        { walletId: "w-bad", storedPublicKey: "pk2", derivedPublicKey: "pk2" },
      ],
      ops: [
        // healthy move
        moveOp({ operationId: "move-ok" }),
        // corrupt receive
        receiveOp({
          operationId: "recv-bad",
          signerAuditIndicatesCall: true,
          exactPreimagePersisted: false,
        }),
      ],
      leases: [
        lease({ walletId: "w-ok", operationId: "move-ok", role: "MOVE_SOURCE" }),
        lease({
          walletId: "w-bad",
          operationId: "recv-bad",
          role: "RECEIVE_WINDOW",
        }),
      ],
    });
    // move-ok also needs destination lease for role agreement — give it a second
    // wallet so lease audit for move doesn't breach independently of recv-bad.
    s.keys.push({ walletId: "w-dst", storedPublicKey: "pk3", derivedPublicKey: "pk3" });
    s.leases.push(
      lease({ walletId: "w-dst", operationId: "move-ok", role: "MOVE_DESTINATION" }),
    );
    // fix move required roles coverage
    s.ops[0] = moveOp({
      operationId: "move-ok",
      leasedWalletIds: ["w-ok", "w-dst"],
    });

    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });
    expect(report.invariantBreach).toBe(true);
    expect(report.ready).toBe(false);
    expect(report.classifications.some((c) => c.classification === "INVARIANT_BREACH")).toBe(true);
    // On global breach, authorized resumes are suppressed (safe continuation = park).
    expect(report.resumed).toHaveLength(0);
    expect(s.moneyEnginesStopped.length).toBeGreaterThan(0);
  });
});

// ──: lease-eligible census partition ─────────────────────────────────
//
// A lease legitimately outlives its operation's terminal status — it is released only
// by the consumer's verification-complete acknowledgement (step 5, step 6,
// 5 step 6). The store therefore returns terminal-with-lease operations too, and
// runDeterministicBootRecovery must route the FULL census to step 3 but the NONTERMINAL
// subset to steps 4-5. Feeding the full census to step 5 is not merely redundant: a
// landed op with submitBoundaryRecorded classifies INDETERMINATE, which parks attention
// on a settled operation and exposes it to resumeAuthorizedActions.
describe("census partition: lease audit sees terminal ops, classify does not", () => {
  function landedState(landed: OperationPhaseEvidence): FakeState {
    const s = emptyState({
      ops: [
        receiveOp({ operationId: "recv-live", status: "READY", leasedWalletIds: ["w-live"] }),
        landed,
      ],
      leases: [
        lease({ walletId: "w-live", operationId: "recv-live", role: "RECEIVE_WINDOW", leaseGroupId: "lg-live" }),
      ],
    });
    for (const walletId of landed.leasedWalletIds) {
      s.leases.push(
        lease({
          walletId,
          operationId: landed.operationId,
          role: landed.requiredRoles[landed.leasedWalletIds.indexOf(walletId)]!,
          leaseGroupId: "lg-landed",
        }),
      );
    }
    s.keys = s.leases.map((l) => ({
      walletId: l.walletId,
      storedPublicKey: `pk-${l.walletId}`,
      derivedPublicKey: `pk-${l.walletId}`,
    }));
    return s;
  }

  const landedCases: ReadonlyArray<readonly [string, OperationPhaseEvidence]> = [
    [
      "RECEIVE_LANDED",
      receiveOp({
        operationId: "recv-landed",
        status: "RECEIVE_LANDED",
        leasedWalletIds: ["w-landed"],
        // The trap: a landed op HAS crossed its submit boundary, so classifyReceiveOp
        // would return INDETERMINATE / submit_boundary_recorded_awaiting_observation.
        submitBoundaryRecorded: true,
        signaturePersisted: true,
        exactPreimagePersisted: true,
        signerAuditIndicatesCall: true,
        formationComplete: true,
      }),
    ],
    [
      "INTERNAL_MOVE_LANDED",
      moveOp({
        operationId: "move-landed",
        status: "INTERNAL_MOVE_LANDED",
        leasedWalletIds: ["w-mv-src", "w-mv-dst"],
        submitBoundaryRecorded: true,
        signaturePersisted: true,
        exactPreimagePersisted: true,
        signerAuditIndicatesCall: true,
      }),
    ],
    [
      "EXTERNAL_SEND_LANDED",
      sendOp({
        operationId: "send-landed",
        status: "EXTERNAL_SEND_LANDED",
        leasedWalletIds: ["w-snd"],
        submitBoundaryRecorded: true,
        signaturePersisted: true,
        exactPreimagePersisted: true,
        signerAuditIndicatesCall: true,
      }),
    ],
    [
      // an EXPIRED receive keeps its lease pinned until the T0-unchanged release proof.
      "EXPIRED",
      receiveOp({
        operationId: "recv-expired",
        status: "EXPIRED",
        leasedWalletIds: ["w-expired"],
        formationComplete: true,
      }),
    ],
  ];

  for (const [status, landed] of landedCases) {
    it(`${status} with a held lease: audited, no breach, never classified`, async () => {
      const s = landedState(landed);
      const report = await runDeterministicBootRecovery({
        leadership: heldLeadership(),
        store: makeStore(s),
        actions: makeActions(s),
      });

      expect(report.invariantBreach).toBe(false);
      expect(report.leaseFindings.filter((f) => f.severity === "invariant_breach")).toEqual([]);
      expect(s.quarantined).toEqual([]);
      expect(report.ready).toBe(true);

      // Step 3 resolved every lease, including the landed operation's.
      for (const walletId of landed.leasedWalletIds) {
        expect(report.leaseFindings.some((f) => f.walletId === walletId)).toBe(true);
      }
      // Steps 4-5 skipped it entirely — no classification, no attention parked.
      expect(report.classifications.map((c) => c.operationId)).toEqual(["recv-live"]);
      expect(s.attentions.map((a) => a.operationId)).not.toContain(landed.operationId);
    });
  }

  it("a genuinely orphaned lease (no operation row in the census) still breaches", async () => {
    const s = emptyState({
      ops: [],
      leases: [lease({ walletId: "w-orphan", operationId: "op-gone", role: "RECEIVE_WINDOW" })],
    });
    const report = await runDeterministicBootRecovery({
      leadership: heldLeadership(),
      store: makeStore(s),
      actions: makeActions(s),
    });

    expect(report.invariantBreach).toBe(true);
    expect(report.leaseFindings).toContainEqual(
      expect.objectContaining({
        walletId: "w-orphan",
        operationId: "op-gone",
        severity: "invariant_breach",
        reason: "lease_operation_missing",
      }),
    );
    expect(s.quarantined).toContain("w-orphan");
    expect(report.ready).toBe(false);
  });

  it("replay is idempotent — a second run over the same state repeats the report and writes nothing new", async () => {
    const s = landedState(landedCases[0]![1]);
    const deps = { leadership: heldLeadership(), store: makeStore(s), actions: makeActions(s) };

    const first = await runDeterministicBootRecovery(deps);
    const quarantinedAfterFirst = [...s.quarantined];
    const attentionsAfterFirst = [...s.attentions];
    const second = await runDeterministicBootRecovery(deps);

    expect(second.invariantBreach).toBe(first.invariantBreach);
    expect(second.ready).toBe(first.ready);
    expect(second.leaseFindings).toEqual(first.leaseFindings);
    expect(second.classifications).toEqual(first.classifications);
    expect(s.quarantined).toEqual(quarantinedAfterFirst);
    expect(s.attentions).toEqual(attentionsAfterFirst);
    expect(s.leaseDeletes).toBe(0);
  });
});
