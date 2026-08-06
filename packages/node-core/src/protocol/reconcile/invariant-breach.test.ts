// MOVE invariant-breach quarantine.
//
// Exit criteria pinned here:
// 1. INVARIANT_BREACH → both wallets QUARANTINED + quarantine_reason together.
// 2. Typed evidence: observation_anomalies + lineage_proof_verdict=INVARIANT_BREACH + audit.
// 3. ACKNOWLEDGE_KEEP_PINNED changes no protocol state / lease / wallet freeze.
// 4. No FORCE_RELEASE / FORCE_LANDED / second attempt / attempt-byte edit path.
// 5. Evidence matrix: unattributed successor, asymmetric paths, endpoint conflict,
// corrupt evidence, operator race, restart, attempted bypass → quarantine only.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  classifyMoveAmbiguity,
  type MoveAmbiguityOutcome,
} from "./move-ambiguity.js";
import { type MoveObservationEvidence } from "./move.js";
import { type PathObservation } from "./observation-input.js";
import {
  MOVE_BREACH_ANOMALY_KINDS,
  MOVE_BREACH_FORBIDDEN_OPERATOR_ACTIONS,
  MOVE_BREACH_LINEAGE_VERDICT,
  MOVE_BREACH_PERMITTED_OPERATOR_ACTIONS,
  MoveInvariantBreachError,
  OPERATOR_RECOVERY_ACTION_CATALOG,
  acknowledgeMoveInvariantBreach,
  anomalyKindForBreachReason,
  applyMoveBreachOperatorAction,
  applyMoveInvariantBreachQuarantine,
  assertMoveBreachActionCatalogCoherent,
  getMoveBreachDiagnostics,
  isMoveBreachOperatorActionForbidden,
  isMoveBreachOperatorActionPermitted,
  isMoveBreachWalletFrozen,
  quarantineReasonForBreach,
  rejectMoveBreachOperatorAction,
  type MoveBreachAttemptBytes,
  type MoveBreachAuditEntry,
  type MoveBreachLeaseSnapshot,
  type MoveBreachLineageProofRow,
  type MoveBreachObservationAnomalyRow,
  type MoveBreachOperationSnapshot,
  type MoveBreachWalletSnapshot,
  type MoveInvariantBreachStore,
} from "./invariant-breach.js";
import { type ReconcileInvariantBreachReason } from "./types.js";

// ─────────────────────────────────────────────────────────────────────────────
// In-memory store (test double). moved it out of invariant-breach.ts: it had
// no consumer but this file, and a fixture has no business on @zucoins/node-core's
// exported surface or in the production module graph. Behaviour is verbatim.
// ─────────────────────────────────────────────────────────────────────────────

class InMemoryMoveInvariantBreachStore implements MoveInvariantBreachStore {
  private readonly wallets = new Map<string, MoveBreachWalletSnapshot>();
  private readonly operations = new Map<string, MoveBreachOperationSnapshot>();
  private readonly leases = new Map<string, MoveBreachLeaseSnapshot>();
  private readonly attempts = new Map<string, MoveBreachAttemptBytes>();
  private readonly anomalies: MoveBreachObservationAnomalyRow[] = [];
  private readonly proofs: MoveBreachLineageProofRow[] = [];
  private readonly auditLog: MoveBreachAuditEntry[] = [];
  private atomicDepth = 0;

  seedWallet(wallet: MoveBreachWalletSnapshot): void {
    this.wallets.set(wallet.walletId, { ...wallet });
  }

  seedOperation(operation: MoveBreachOperationSnapshot): void {
    this.operations.set(operation.operationId, { ...operation });
  }

  seedLease(lease: MoveBreachLeaseSnapshot): void {
    this.leases.set(lease.walletId, { ...lease });
  }

  seedAttemptBytes(attempt: MoveBreachAttemptBytes): void {
    this.attempts.set(attempt.operationId, { ...attempt });
  }

  /** Test-only escape hatch: prove the store refuses lease mutation from outside. */
  tryMutateLease(walletId: string): boolean {
    // No public mutator exists; this method documents the absence and always fails.
    void walletId;
    return false;
  }

  /** Test-only: prove attempt-byte mutators do not exist. */
  tryMutateAttemptBytes(operationId: string): boolean {
    void operationId;
    return false;
  }

  getAuditLog(): readonly MoveBreachAuditEntry[] {
    return this.auditLog.slice();
  }

  async getWallet(walletId: string): Promise<MoveBreachWalletSnapshot | null> {
    return this.wallets.get(walletId) ?? null;
  }

  async getOperation(operationId: string): Promise<MoveBreachOperationSnapshot | null> {
    return this.operations.get(operationId) ?? null;
  }

  async getLease(walletId: string): Promise<MoveBreachLeaseSnapshot | null> {
    return this.leases.get(walletId) ?? null;
  }

  async getAttemptBytes(operationId: string): Promise<MoveBreachAttemptBytes | null> {
    return this.attempts.get(operationId) ?? null;
  }

  async runAtomic<T>(fn: () => Promise<T>): Promise<T> {
    const isOuter = this.atomicDepth === 0;
    const walletSnap = isOuter
      ? new Map([...this.wallets.entries()].map(([k, v]) => [k, { ...v }]))
      : null;
    const opSnap = isOuter
      ? new Map([...this.operations.entries()].map(([k, v]) => [k, { ...v }]))
      : null;
    const leaseSnap = isOuter
      ? new Map([...this.leases.entries()].map(([k, v]) => [k, { ...v }]))
      : null;
    const attemptSnap = isOuter
      ? new Map([...this.attempts.entries()].map(([k, v]) => [k, { ...v }]))
      : null;
    const anomalySnap = isOuter ? this.anomalies.slice() : null;
    const proofSnap = isOuter ? this.proofs.slice() : null;
    const auditSnap = isOuter ? this.auditLog.slice() : null;

    this.atomicDepth += 1;
    try {
      return await fn();
    } catch (err) {
      if (
        isOuter &&
        walletSnap &&
        opSnap &&
        leaseSnap &&
        attemptSnap &&
        anomalySnap &&
        proofSnap &&
        auditSnap
      ) {
        this.wallets.clear();
        for (const [k, v] of walletSnap) this.wallets.set(k, v);
        this.operations.clear();
        for (const [k, v] of opSnap) this.operations.set(k, v);
        this.leases.clear();
        for (const [k, v] of leaseSnap) this.leases.set(k, v);
        this.attempts.clear();
        for (const [k, v] of attemptSnap) this.attempts.set(k, v);
        this.anomalies.length = 0;
        this.anomalies.push(...anomalySnap);
        this.proofs.length = 0;
        this.proofs.push(...proofSnap);
        this.auditLog.length = 0;
        this.auditLog.push(...auditSnap);
      }
      throw err;
    } finally {
      this.atomicDepth -= 1;
    }
  }

  async quarantineWallet(
    walletId: string,
    quarantineReason: string,
  ): Promise<MoveBreachWalletSnapshot> {
    if (quarantineReason.length === 0) {
      throw new MoveInvariantBreachError(
        "quarantine_reason must be non-empty when setting QUARANTINED (CHECK constraint)",
      );
    }
    const prior = this.wallets.get(walletId);
    if (prior === undefined) {
      throw new MoveInvariantBreachError(`wallet ${walletId} not found`);
    }
    // Identity columns are copied, never reassigned from caller input.
    if (prior.state === "RETIRED") {
      return { ...prior };
    }
    const next: MoveBreachWalletSnapshot = {
      walletId: prior.walletId,
      state: "QUARANTINED",
      quarantineReason,
      activeLeaseId: prior.activeLeaseId, // PRESERVE
      publicKey: prior.publicKey,
      keyOrigin: prior.keyOrigin,
      nodeId: prior.nodeId,
      rowVersion: prior.rowVersion + 1,
    };
    this.wallets.set(walletId, next);
    return next;
  }

  async markOperationBreach(
    operationId: string,
    attentionReason: string,
    detail: string,
  ): Promise<MoveBreachOperationSnapshot> {
    void detail;
    const prior = this.operations.get(operationId);
    if (prior === undefined) {
      throw new MoveInvariantBreachError(`operation ${operationId} not found`);
    }
    // Never invent a second attempt id; never land.
    if (prior.status === "INTERNAL_MOVE_LANDED") {
      throw new MoveInvariantBreachError(
        "refusing to rewrite a landed MOVE under invariant breach",
      );
    }
    const next: MoveBreachOperationSnapshot = {
      ...prior,
      status: "NEEDS_ATTENTION",
      rowVersion: prior.rowVersion + 1,
      attentionRequired: true,
      attentionReason,
      // moveAttemptId deliberately unchanged — no second attempt
    };
    this.operations.set(operationId, next);
    return next;
  }

  async acknowledgeOperation(
    operationId: string,
    operatorId: string,
    note: string,
    at: string,
  ): Promise<MoveBreachOperationSnapshot> {
    const prior = this.operations.get(operationId);
    if (prior === undefined) {
      throw new MoveInvariantBreachError(`operation ${operationId} not found`);
    }
    // Awareness only: status + rowVersion + moveAttemptId unchanged.
    const next: MoveBreachOperationSnapshot = {
      ...prior,
      operatorAcknowledged: true,
      acknowledgedAt: at,
      acknowledgedBy: operatorId,
      acknowledgeNote: note,
    };
    this.operations.set(operationId, next);
    return next;
  }

  async appendObservationAnomaly(row: MoveBreachObservationAnomalyRow): Promise<void> {
    if (!(MOVE_BREACH_ANOMALY_KINDS as readonly string[]).includes(row.kind)) {
      throw new MoveInvariantBreachError(`anomaly kind ${row.kind} outside closed set`);
    }
    this.anomalies.push({ ...row });
  }

  async appendLineageProofVerdict(row: MoveBreachLineageProofRow): Promise<void> {
    if (row.verdict !== MOVE_BREACH_LINEAGE_VERDICT) {
      throw new MoveInvariantBreachError(
        `lineage verdict must be INVARIANT_BREACH, got ${row.verdict}`,
      );
    }
    this.proofs.push({ ...row });
  }

  async appendAudit(entry: MoveBreachAuditEntry): Promise<void> {
    this.auditLog.push({ ...entry, details: { ...entry.details } });
  }

  async listObservationAnomalies(
    operationId: string,
  ): Promise<readonly MoveBreachObservationAnomalyRow[]> {
    return this.anomalies.filter((row) => row.operationId === operationId).map((r) => ({ ...r }));
  }

  async listLineageProofVerdicts(
    operationId: string,
  ): Promise<readonly MoveBreachLineageProofRow[]> {
    return this.proofs.filter((row) => row.operationId === operationId).map((r) => ({ ...r }));
  }

  async listAudit(operationId: string): Promise<readonly MoveBreachAuditEntry[]> {
    return this.auditLog
      .filter((row) => row.operationId === operationId)
      .map((r) => ({ ...r, details: { ...r.details } }));
  }
}

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE = readFileSync(join(HERE, "invariant-breach.ts"), "utf8");
const CONTRACTS_HALT = readFileSync(
  join(
    HERE,
    "../../../../generic-node-contracts/src/operator-halt/halt.contract.ts",
  ),
  "utf8",
);

const ATTEMPT = "move-attempt-breach-1";
const OP = "op-move-breach-1";
const SOURCE_WALLET = "wallet-source";
const DEST_WALLET = "wallet-destination";
const BODY = "move-body-sha256-breach";
const NOW = "2026-07-27T12:00:00.000Z";

const BREACH_OBS: PathObservation = { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" };
const ANOMALY_REGRESSION: PathObservation = {
  result: "ANOMALY",
  anomaly: "REGRESSION",
};
const ANOMALY_COLLISION: PathObservation = {
  result: "ANOMALY",
  anomaly: "SIGNATURE_COLLISION",
};
const ANOMALY_GENESIS: PathObservation = {
  result: "ANOMALY",
  anomaly: "GENESIS_AFTER_HISTORY",
};
const NO_SUCCESSOR: PathObservation = { result: "NO_SUCCESSOR" };
const GAP: PathObservation = { result: "PROOF_INCOMPLETE", fault: "GAP" };

function observation(
  overrides: Partial<MoveObservationEvidence> = {},
): MoveObservationEvidence {
  return {
    boundary: "POST_SUBMIT",
    moveAttemptId: ATTEMPT,
    sourceWalletId: SOURCE_WALLET,
    destinationWalletId: DEST_WALLET,
    expectedMoveBodySha256: BODY,
    sourceLeaseState: "ACTIVE",
    destinationLeaseState: "ACTIVE",
    sourceObservation: BREACH_OBS,
    destinationObservation: BREACH_OBS,
    ...overrides,
  };
}

function breachOutcome(
  obs: Partial<MoveObservationEvidence> = {},
): Extract<MoveAmbiguityOutcome, { kind: "INVARIANT_BREACH" }> {
  const outcome = classifyMoveAmbiguity({
    phase: "POST_SUBMIT",
    observation: observation(obs),
  });
  expect(outcome.kind).toBe("INVARIANT_BREACH");
  if (outcome.kind !== "INVARIANT_BREACH") {
    throw new Error(`expected INVARIANT_BREACH, got ${outcome.kind}`);
  }
  return outcome;
}

function seedStore(opts?: {
  readonly sourceState?: MoveBreachWalletSnapshot["state"];
  readonly destState?: MoveBreachWalletSnapshot["state"];
  readonly status?: string;
  readonly rowVersion?: number;
}): InMemoryMoveInvariantBreachStore {
  const store = new InMemoryMoveInvariantBreachStore();
  const sourceState = opts?.sourceState ?? "PINNED";
  const destState = opts?.destState ?? "PINNED";

  const source: MoveBreachWalletSnapshot = {
    walletId: SOURCE_WALLET,
    state: sourceState,
    quarantineReason: sourceState === "QUARANTINED" ? "pre" : null,
    activeLeaseId: "lease-source-1",
    publicKey: "pk-source",
    keyOrigin: "NODE_GENERATED",
    nodeId: "node-1",
    rowVersion: 3,
  };
  const dest: MoveBreachWalletSnapshot = {
    walletId: DEST_WALLET,
    state: destState,
    quarantineReason: destState === "QUARANTINED" ? "pre" : null,
    activeLeaseId: "lease-dest-1",
    publicKey: "pk-dest",
    keyOrigin: "NODE_GENERATED",
    nodeId: "node-1",
    rowVersion: 4,
  };
  store.seedWallet(source);
  store.seedWallet(dest);

  const op: MoveBreachOperationSnapshot = {
    operationId: OP,
    moveAttemptId: ATTEMPT,
    status: opts?.status ?? "CREATED",
    rowVersion: opts?.rowVersion ?? 7,
    attentionRequired: false,
    attentionReason: null,
    sourceWalletId: SOURCE_WALLET,
    destinationWalletId: DEST_WALLET,
    operatorAcknowledged: false,
    acknowledgedAt: null,
    acknowledgedBy: null,
    acknowledgeNote: null,
  };
  store.seedOperation(op);

  const sourceLease: MoveBreachLeaseSnapshot = {
    walletId: SOURCE_WALLET,
    leaseId: "lease-source-1",
    lifecycle: "ACTIVE",
    rowFingerprint: "fp-source-lease-v1",
  };
  const destLease: MoveBreachLeaseSnapshot = {
    walletId: DEST_WALLET,
    leaseId: "lease-dest-1",
    lifecycle: "ACTIVE",
    rowFingerprint: "fp-dest-lease-v1",
  };
  store.seedLease(sourceLease);
  store.seedLease(destLease);

  const attempt: MoveBreachAttemptBytes = {
    operationId: OP,
    moveAttemptId: ATTEMPT,
    step1PreimageText: '{"purpose":"zp-move-step1","n":1}',
    step1Signature: "sig-step1-exact-bytes",
    completedBodyText: '{"completed":true}',
    completedBodySha256: BODY,
  };
  store.seedAttemptBytes(attempt);

  return store;
}

let idCounter = 0;
function sequentialIds(): () => string {
  return () => {
    idCounter += 1;
    return `id-${idCounter}`;
  };
}

// ─── Catalog / structural pins ───────────────────────────────────────────────

describe("action catalog (permitted and forbidden)", () => {
  it("permitted set is exactly QUARANTINE_WALLETS + ACKNOWLEDGE_KEEP_PINNED", () => {
    expect([...MOVE_BREACH_PERMITTED_OPERATOR_ACTIONS]).toEqual([
      "QUARANTINE_WALLETS",
      "ACKNOWLEDGE_KEEP_PINNED",
    ]);
  });

  it("forbids every non-action and every release/rebuild token", () => {
    for (const action of [
      "FORCE_LANDED",
      "FORCE_RELEASE",
      "EDIT_TRANSACTION",
      "DELETE_EVIDENCE",
      "RETRY_SUBMIT",
      "REBUILD_INTERNAL_MOVE",
      "RESOLVE_QUARANTINE",
      "UNQUARANTINE",
      "RELEASE_WALLET",
    ] as const) {
      expect(isMoveBreachOperatorActionForbidden(action)).toBe(true);
      expect(isMoveBreachOperatorActionPermitted(action)).toBe(false);
    }
  });

  it("catalog coherence helper passes", () => {
    expect(() => assertMoveBreachActionCatalogCoherent()).not.toThrow();
  });

  it("local catalog matches generic-node-contracts OPERATOR_RECOVERY_ACTIONS source", () => {
    // Pin against contracts source so a catalog drift fails this package's tests.
    for (const action of OPERATOR_RECOVERY_ACTION_CATALOG) {
      expect(CONTRACTS_HALT).toContain(`"${action}"`);
    }
    expect(CONTRACTS_HALT).toContain("QUARANTINE_WALLETS");
    expect(CONTRACTS_HALT).toContain("ACKNOWLEDGE_KEEP_PINNED");
    // Tokens must not appear as members of the contracts catalog.
    expect(CONTRACTS_HALT).not.toMatch(/"FORCE_LANDED"/);
    expect(CONTRACTS_HALT).not.toMatch(/"FORCE_RELEASE"/);
    expect(CONTRACTS_HALT).not.toMatch(/"DELETE_EVIDENCE"/);
  });

  it("source has no resolve()/FORCE_RELEASE/unquarantine implementation", () => {
    expect(SOURCE).not.toMatch(/\basync resolve\b/);
    expect(SOURCE).not.toMatch(/\bstatus:\s*"RESOLVED"/);
    expect(SOURCE).not.toMatch(/FORCE_RELEASE_WALLETS/);
    expect(SOURCE).not.toMatch(/state:\s*"AVAILABLE"/);
    // No mutator that clears quarantine_reason.
    expect(SOURCE).not.toMatch(/quarantineReason:\s*null/);
  });
});

// ─── Reason → anomaly kind mapping ───────────────────────────────────────────

describe("anomalyKindForBreachReason", () => {
  it.each([
    [
      { source: "OBSERVATION_ANOMALY", anomaly: "REGRESSION" } as const,
      "REGRESSION",
    ],
    [
      { source: "OBSERVATION_ANOMALY", anomaly: "GENESIS_AFTER_HISTORY" } as const,
      "GENESIS_AFTER_HISTORY",
    ],
    [
      { source: "OBSERVATION_ANOMALY", anomaly: "SIGNATURE_COLLISION" } as const,
      "SIGNATURE_COLLISION",
    ],
    [{ source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE" } as const, "UNEXPLAINED_JUMP"],
    [{ source: "EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT" } as const, "UNEXPLAINED_JUMP"],
    [{ source: "SIGNER_AUDIT_CONTRADICTS_DURABLE_RECORD" } as const, "UNEXPLAINED_JUMP"],
    [{ source: "LEASE_NOT_ACTIVE_DURING_RECONCILE" } as const, "UNEXPLAINED_JUMP"],
  ] as const)("%j → %s", (reason, expected) => {
    expect(anomalyKindForBreachReason(reason as ReconcileInvariantBreachReason)).toBe(
      expected,
    );
    expect(MOVE_BREACH_ANOMALY_KINDS).toContain(expected);
  });
});

// ─── Apply quarantine ────────────────────────────────────────────────────────

describe("applyMoveInvariantBreachQuarantine", () => {
  it("quarantines BOTH wallets with quarantine_reason in one atomic unit", async () => {
    const store = seedStore();
    const outcome = breachOutcome();
    const result = await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    expect(result.sourceWallet.state).toBe("QUARANTINED");
    expect(result.destinationWallet.state).toBe("QUARANTINED");
    expect(result.sourceWallet.quarantineReason).toBe(result.quarantineReason);
    expect(result.destinationWallet.quarantineReason).toBe(result.quarantineReason);
    expect(result.sourceWallet.quarantineReason).not.toBeNull();
    expect(result.quarantineReason).toContain("MOVE_INVARIANT_BREACH");
    expect(result.quarantineReason).toContain(ATTEMPT);

    expect(isMoveBreachWalletFrozen(result.sourceWallet)).toBe(true);
    expect(isMoveBreachWalletFrozen(result.destinationWallet)).toBe(true);
  });

  it("preserves both active leases (never FORCE_RELEASE)", async () => {
    const store = seedStore();
    const outcome = breachOutcome();
    const result = await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    expect(result.sourceLeasePreserved).toBe(true);
    expect(result.destinationLeasePreserved).toBe(true);
    expect(result.sourceWallet.activeLeaseId).toBe("lease-source-1");
    expect(result.destinationWallet.activeLeaseId).toBe("lease-dest-1");

    const sourceLease = await store.getLease(SOURCE_WALLET);
    const destLease = await store.getLease(DEST_WALLET);
    expect(sourceLease?.lifecycle).toBe("ACTIVE");
    expect(destLease?.lifecycle).toBe("ACTIVE");
    expect(sourceLease?.rowFingerprint).toBe("fp-source-lease-v1");
    expect(destLease?.rowFingerprint).toBe("fp-dest-lease-v1");
  });

  it("never touches key/identity columns", async () => {
    const store = seedStore();
    const outcome = breachOutcome();
    const result = await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    expect(result.sourceWallet.publicKey).toBe("pk-source");
    expect(result.sourceWallet.keyOrigin).toBe("NODE_GENERATED");
    expect(result.sourceWallet.nodeId).toBe("node-1");
    expect(result.destinationWallet.publicKey).toBe("pk-dest");
    expect(result.destinationWallet.keyOrigin).toBe("NODE_GENERATED");
    expect(result.destinationWallet.nodeId).toBe("node-1");
  });

  it("writes observation_anomalies + lineage INVARIANT_BREACH + audit_log", async () => {
    const store = seedStore();
    const outcome = breachOutcome();
    const result = await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    const anomalies = await store.listObservationAnomalies(OP);
    expect(anomalies).toHaveLength(2);
    expect(anomalies.map((a) => a.walletId).sort()).toEqual(
      [DEST_WALLET, SOURCE_WALLET].sort(),
    );
    for (const row of anomalies) {
      expect(row.kind).toBe(result.anomalyKind);
      expect(MOVE_BREACH_ANOMALY_KINDS).toContain(row.kind);
      expect(row.details).toContain(ATTEMPT);
    }

    const proofs = await store.listLineageProofVerdicts(OP);
    expect(proofs).toHaveLength(2);
    for (const row of proofs) {
      expect(row.verdict).toBe(MOVE_BREACH_LINEAGE_VERDICT);
      expect(row.verdict).toBe("INVARIANT_BREACH");
    }

    const audit = await store.listAudit(OP);
    expect(audit.some((a) => a.action === "move.invariant_breach.quarantine_wallets")).toBe(
      true,
    );
    const q = audit.find((a) => a.action === "move.invariant_breach.quarantine_wallets");
    expect(q?.actorKind).toBe("SYSTEM");
    expect(q?.details).toMatchObject({
      permits_submit_call: false,
      permits_second_attempt: false,
      retain_source_lease: true,
      retain_destination_lease: true,
      lineage_verdict: "INVARIANT_BREACH",
    });
  });

  it("leaves signed attempt bytes byte-identical", async () => {
    const store = seedStore();
    const prior = await store.getAttemptBytes(OP);
    const outcome = breachOutcome();
    const result = await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    expect(result.attemptBytesUntouched).toBe(true);
    expect(result.secondAttemptCreated).toBe(false);
    const next = await store.getAttemptBytes(OP);
    expect(next).toEqual(prior);
    expect(next?.moveAttemptId).toBe(ATTEMPT);
  });

  it("parks operation NEEDS_ATTENTION without inventing a second attempt", async () => {
    const store = seedStore();
    const outcome = breachOutcome();
    await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    const op = await store.getOperation(OP);
    expect(op?.status).toBe("NEEDS_ATTENTION");
    expect(op?.attentionRequired).toBe(true);
    expect(op?.moveAttemptId).toBe(ATTEMPT);
    expect(op?.status).not.toBe("INTERNAL_MOVE_LANDED");
  });

  it("rolls back partial writes when a later step throws", async () => {
    const store = seedStore();
    const outcome = breachOutcome();
    const original = store.appendAudit.bind(store);
    store.appendAudit = async () => {
      throw new Error("audit sink down");
    };

    await expect(
      applyMoveInvariantBreachQuarantine(store, {
        outcome,
        operationId: OP,
        sourceWalletId: SOURCE_WALLET,
        destinationWalletId: DEST_WALLET,
        nowIso: NOW,
        newId: sequentialIds(),
      }),
    ).rejects.toThrow("audit sink down");

    // Wallets restored (atomic).
    expect((await store.getWallet(SOURCE_WALLET))?.state).toBe("PINNED");
    expect((await store.getWallet(DEST_WALLET))?.state).toBe("PINNED");
    expect(await store.listObservationAnomalies(OP)).toHaveLength(0);
    expect(await store.listLineageProofVerdicts(OP)).toHaveLength(0);

    store.appendAudit = original;
  });
});

// ─── Evidence matrix ─────────────────────────────────────────────────────────

describe("evidence matrix → quarantine, never landed / second attempt", () => {
  const cases: Array<{
    readonly name: string;
    readonly obs: Partial<MoveObservationEvidence>;
    readonly expectedAnomaly: (typeof MOVE_BREACH_ANOMALY_KINDS)[number];
  }> = [
    {
      name: "unattributed successor under lease (both paths)",
      obs: {
        sourceObservation: BREACH_OBS,
        destinationObservation: BREACH_OBS,
      },
      expectedAnomaly: "UNEXPLAINED_JUMP",
    },
    {
      name: "asymmetric paths (source breach, dest gap → still breach on source)",
      obs: {
        sourceObservation: BREACH_OBS,
        destinationObservation: GAP,
      },
      expectedAnomaly: "UNEXPLAINED_JUMP",
    },
    {
      name: "REGRESSION anomaly (endpoint/history conflict class)",
      obs: {
        sourceObservation: ANOMALY_REGRESSION,
        destinationObservation: NO_SUCCESSOR,
      },
      expectedAnomaly: "REGRESSION",
    },
    {
      name: "SIGNATURE_COLLISION (corrupt / colliding evidence)",
      obs: {
        sourceObservation: ANOMALY_COLLISION,
        destinationObservation: NO_SUCCESSOR,
      },
      expectedAnomaly: "SIGNATURE_COLLISION",
    },
    {
      name: "GENESIS_AFTER_HISTORY",
      obs: {
        sourceObservation: ANOMALY_GENESIS,
        destinationObservation: NO_SUCCESSOR,
      },
      expectedAnomaly: "GENESIS_AFTER_HISTORY",
    },
    {
      name: "lease not active during reconcile",
      obs: {
        sourceLeaseState: "RELEASED",
        destinationLeaseState: "ACTIVE",
        sourceObservation: NO_SUCCESSOR,
        destinationObservation: NO_SUCCESSOR,
      },
      expectedAnomaly: "UNEXPLAINED_JUMP",
    },
  ];

  it.each(cases)("$name", async ({ obs, expectedAnomaly }) => {
    const store = seedStore();
    const outcome = breachOutcome(obs);
    const result = await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    expect(result.anomalyKind).toBe(expectedAnomaly);
    expect(result.lineageVerdict).toBe("INVARIANT_BREACH");
    expect(result.secondAttemptCreated).toBe(false);
    expect((await store.getOperation(OP))?.status).not.toBe("INTERNAL_MOVE_LANDED");
    expect((await store.getOperation(OP))?.moveAttemptId).toBe(ATTEMPT);
    expect(isMoveBreachWalletFrozen(result.sourceWallet)).toBe(true);
    expect(isMoveBreachWalletFrozen(result.destinationWallet)).toBe(true);
  });
});

// ─── ACKNOWLEDGE_KEEP_PINNED ─────────────────────────────────────────────────

describe("ACKNOWLEDGE_KEEP_PINNED", () => {
  it("records awareness without changing status, row_version, leases, or freeze", async () => {
    const store = seedStore();
    const outcome = breachOutcome();
    await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    const priorOp = await store.getOperation(OP);
    const priorSource = await store.getWallet(SOURCE_WALLET);
    const priorDest = await store.getWallet(DEST_WALLET);
    const priorSourceLease = await store.getLease(SOURCE_WALLET);
    const priorDestLease = await store.getLease(DEST_WALLET);
    const priorAttempt = await store.getAttemptBytes(OP);

    const ack = await acknowledgeMoveInvariantBreach(store, {
      operationId: OP,
      operatorId: "op-alice",
      note: "seen; holding for forensic review",
      nowIso: "2026-07-27T13:00:00.000Z",
      newId: sequentialIds(),
    });

    expect(ack.protocolStateUnchanged).toBe(true);
    expect(ack.leasesUnchanged).toBe(true);
    expect(ack.operation.status).toBe(priorOp?.status);
    expect(ack.operation.rowVersion).toBe(priorOp?.rowVersion);
    expect(ack.operation.operatorAcknowledged).toBe(true);
    expect(ack.operation.acknowledgedBy).toBe("op-alice");

    // Wallets stay frozen.
    expect(isMoveBreachWalletFrozen(await store.getWallet(SOURCE_WALLET))).toBe(true);
    expect(isMoveBreachWalletFrozen(await store.getWallet(DEST_WALLET))).toBe(true);
    expect((await store.getWallet(SOURCE_WALLET))?.state).toBe(priorSource?.state);
    expect((await store.getWallet(DEST_WALLET))?.state).toBe(priorDest?.state);
    expect((await store.getWallet(SOURCE_WALLET))?.quarantineReason).toBe(
      priorSource?.quarantineReason,
    );

    // Leases byte-identical.
    expect(await store.getLease(SOURCE_WALLET)).toEqual(priorSourceLease);
    expect(await store.getLease(DEST_WALLET)).toEqual(priorDestLease);
    expect(ack.sourceLease?.rowFingerprint).toBe(priorSourceLease?.rowFingerprint);

    // Attempt bytes untouched.
    expect(await store.getAttemptBytes(OP)).toEqual(priorAttempt);

    const audit = await store.listAudit(OP);
    expect(
      audit.some((a) => a.action === "move.invariant_breach.acknowledge_keep_pinned"),
    ).toBe(true);
  });
});

// ─── Operator race / bypass / restart ────────────────────────────────────────

describe("operator race, bypass, restart", () => {
  it("rejects FORCE_RELEASE / FORCE_LANDED / DELETE_EVIDENCE / REBUILD without mutation", async () => {
    const store = seedStore();
    const outcome = breachOutcome();
    await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    const priorSource = await store.getWallet(SOURCE_WALLET);
    const priorDest = await store.getWallet(DEST_WALLET);
    const priorOp = await store.getOperation(OP);
    const priorLeaseS = await store.getLease(SOURCE_WALLET);
    const priorAttempt = await store.getAttemptBytes(OP);
    const priorAnomalies = await store.listObservationAnomalies(OP);

    for (const action of MOVE_BREACH_FORBIDDEN_OPERATOR_ACTIONS) {
      const rejected = await applyMoveBreachOperatorAction(store, {
        operationId: OP,
        action,
        operatorId: "op-mallory",
        nowIso: NOW,
        newId: sequentialIds(),
      });
      expect(rejected.kind).toBe("REJECTED");
      if (rejected.kind === "REJECTED") {
        expect(rejected.reason).toContain(action);
      }
    }

    // Nothing changed.
    expect(await store.getWallet(SOURCE_WALLET)).toEqual(priorSource);
    expect(await store.getWallet(DEST_WALLET)).toEqual(priorDest);
    expect((await store.getOperation(OP))?.status).toBe(priorOp?.status);
    expect((await store.getOperation(OP))?.rowVersion).toBe(priorOp?.rowVersion);
    expect(await store.getLease(SOURCE_WALLET)).toEqual(priorLeaseS);
    expect(await store.getAttemptBytes(OP)).toEqual(priorAttempt);
    expect(await store.listObservationAnomalies(OP)).toEqual(priorAnomalies);
  });

  it("store exposes no lease or attempt-byte mutator (attempted bypass)", () => {
    const store = seedStore();
    expect(store.tryMutateLease(SOURCE_WALLET)).toBe(false);
    expect(store.tryMutateAttemptBytes(OP)).toBe(false);
    // No public methods that release or rewrite.
    const proto = Object.getOwnPropertyNames(Object.getPrototypeOf(store));
    expect(proto).not.toContain("releaseLease");
    expect(proto).not.toContain("clearQuarantine");
    expect(proto).not.toContain("setAttemptBytes");
    expect(proto).not.toContain("createSecondAttempt");
  });

  it("restart-shaped re-apply is idempotent (ALREADY_QUARANTINED)", async () => {
    const store = seedStore();
    const outcome = breachOutcome();
    await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    const anomalyCount = (await store.listObservationAnomalies(OP)).length;
    const proofCount = (await store.listLineageProofVerdicts(OP)).length;

    const again = await applyMoveBreachOperatorAction(store, {
      operationId: OP,
      action: "QUARANTINE_WALLETS",
      operatorId: "system-restart",
      breachOutcome: outcome,
      nowIso: NOW,
      newId: sequentialIds(),
    });
    expect(again.kind).toBe("ALREADY_QUARANTINED");

    // No duplicate evidence storm on restart.
    expect((await store.listObservationAnomalies(OP)).length).toBe(anomalyCount);
    expect((await store.listLineageProofVerdicts(OP)).length).toBe(proofCount);
    expect(isMoveBreachWalletFrozen(await store.getWallet(SOURCE_WALLET))).toBe(true);
    expect(isMoveBreachWalletFrozen(await store.getWallet(DEST_WALLET))).toBe(true);
  });

  it("rejectMoveBreachOperatorAction alone leaves freeze intact", async () => {
    const store = seedStore();
    await applyMoveInvariantBreachQuarantine(store, {
      outcome: breachOutcome(),
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    const rejected = await rejectMoveBreachOperatorAction(store, {
      operationId: OP,
      action: "FORCE_RELEASE",
      operatorId: "op-bob",
      nowIso: NOW,
      newId: sequentialIds(),
    });
    expect(rejected.rejected).toBe(true);
    expect(isMoveBreachWalletFrozen(await store.getWallet(SOURCE_WALLET))).toBe(true);
    expect(isMoveBreachWalletFrozen(await store.getWallet(DEST_WALLET))).toBe(true);
  });
});

// ─── Diagnostics ─────────────────────────────────────────────────────────────

describe("diagnostics (recovery GET surface)", () => {
  it("exposes quarantine reason, anomaly, verdict, wallet/operation ids", async () => {
    const store = seedStore();
    const outcome = breachOutcome();
    const applied = await applyMoveInvariantBreachQuarantine(store, {
      outcome,
      operationId: OP,
      sourceWalletId: SOURCE_WALLET,
      destinationWalletId: DEST_WALLET,
      nowIso: NOW,
      newId: sequentialIds(),
    });

    const diag = await getMoveBreachDiagnostics(store, OP);
    expect(diag).not.toBeNull();
    expect(diag?.operationId).toBe(OP);
    expect(diag?.moveAttemptId).toBe(ATTEMPT);
    expect(diag?.quarantineReason).toBe(applied.quarantineReason);
    expect(diag?.anomalyKind).toBe(applied.anomalyKind);
    expect(diag?.lineageVerdict).toBe("INVARIANT_BREACH");
    expect(diag?.sourceWalletId).toBe(SOURCE_WALLET);
    expect(diag?.destinationWalletId).toBe(DEST_WALLET);
    expect(diag?.sourceWalletState).toBe("QUARANTINED");
    expect(diag?.destinationWalletState).toBe("QUARANTINED");
    expect(diag?.sourceLeaseId).toBe("lease-source-1");
    expect(diag?.destinationLeaseId).toBe("lease-dest-1");
    expect(diag?.permittedOperatorActions).toEqual([
      "QUARANTINE_WALLETS",
      "ACKNOWLEDGE_KEEP_PINNED",
    ]);
    expect(diag?.forbiddenOperatorActions).toEqual(
      expect.arrayContaining(["FORCE_LANDED", "FORCE_RELEASE", "DELETE_EVIDENCE"]),
    );
  });
});

// ─── quarantine_reason helper ────────────────────────────────────────────────

describe("quarantineReasonForBreach", () => {
  it("embeds source + anomaly kind + attempt id", () => {
    const reason: ReconcileInvariantBreachReason = {
      source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE",
    };
    const text = quarantineReasonForBreach(reason, ATTEMPT);
    expect(text).toBe(
      `MOVE_INVARIANT_BREACH:UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE:UNEXPLAINED_JUMP:attempt=${ATTEMPT}`,
    );
  });
});
