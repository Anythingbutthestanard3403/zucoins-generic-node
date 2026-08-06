// InMemoryReportingStore, the single-process REFERENCE adapter for the
// reporting store seam (store.ts). It is the only concrete store in-repo and drives every
// test; a durable Postgres adapter (migration/driver slice, separately ticketed) drops in
// behind the same interfaces for production.
//
// Atomicity argument: the burn critical section below contains NO `await` between check and
// insert. JavaScript runs each synchronous section to completion, so two concurrent calls on
// one process cannot interleave between the recheck and the map insert — the second call
// always observes the first's committed state.
//
// commitMutationWithCompletedIdempotency cannot be await-free: persistChild is async (and on
// the durable adapter issues SQL). Together-or-neither is instead enforced by (1) a per-store
// UoW mutex so concurrent handlers cannot interleave mid-section, and (2) a child-effect
// journal via tx.stageChildEffect — apply runs immediately, rollback runs on CONFLICT or
// throw so child side effects never outlive a failed parent. The
// durable adapter provides the same guarantee with one Postgres transaction. This adapter's
// scope is one node process (the v1 deployment posture).
//
// Fail-closed defaults: a node with no seeded restore-state row is hard-held
// (RESTORE_POLICY — reporting authorization starts hard-held after restore, automatic
// release forbidden), and a missing lifecycle head/key state admits nothing.

import type { ReportingPresentedKeyState } from "./store.js";
import {
  isFingerprintGuardedRouteId,
  ReportingStoreError,
  reportingKeyAdmissionEligible,
  type AppendNodeEventsOutcome,
  type BurnNonceOutcome,
  type BurnNonceRequest,
  type CommitMutationWithCompletedIdempotencyOutcome,
  type CompletedIdempotencyDraft,
  type CompletedIdempotencyRecord,
  type InsertCompletedIdempotencyOutcome,
  type NodeEventCursor,
  type NodeEventSigningKey,
  type NodeEventVerificationStore,
  type RecordedNodeEvent,
  type ReportingAdmissionSnapshot,
  type ReportingMutationTx,
  type ReportingNonceEvidence,
  type ReportingRegistration,
  type ReportingRequestStore,
} from "./store.js";

export interface InMemoryLifecycleHeadSeed {
  readonly epoch: bigint;
  readonly authHold: boolean;
  readonly currentKeyId: string | null;
  readonly priorKeyId: string | null;
  readonly overlapExpiresAtMs: number | null;
  readonly successorCommittedAtMs: number | null;
}

export interface InMemoryKeyStateSeed {
  readonly state: ReportingPresentedKeyState;
  readonly revokedAtMs: number | null;
}

const joinKey = (...parts: readonly string[]): string => parts.join(":");

export class InMemoryReportingStore implements ReportingRequestStore, NodeEventVerificationStore {
  private readonly registrations = new Map<string, ReportingRegistration>();
  private readonly restoreHolds = new Map<string, boolean>();
  private readonly heads = new Map<string, InMemoryLifecycleHeadSeed>();
  private readonly keyStates = new Map<string, InMemoryKeyStateSeed>();
  private readonly nonceEvidence = new Map<string, ReportingNonceEvidence>();
  private readonly burnCounters = new Map<string, bigint>();
  private readonly completedIdempotency = new Map<string, CompletedIdempotencyRecord>();
  private readonly guardedFingerprints = new Set<string>();
  private readonly eventKeys = new Map<string, NodeEventSigningKey>();
  private readonly cursors = new Map<string, NodeEventCursor>();
  private readonly recordedEvents = new Map<string, RecordedNodeEvent>();
  private nextRowId = 0n;
  // Serializes commitMutationWithCompletedIdempotency so concurrent handlers cannot
  // interleave between persistChild and the parent insert (await gap is otherwise racy).
  private mutationUowTail: Promise<void> = Promise.resolve();

  // -------- seed surface (test/deploy harness; the registration lane owns real writes) -------

  seedRegistration(registration: ReportingRegistration): void {
    this.registrations.set(joinKey(registration.nodeId, registration.reportingKeyId), registration);
  }

  seedRestoreHold(nodeId: string, restoreHold: boolean): void {
    this.restoreHolds.set(nodeId, restoreHold);
  }

  seedLifecycleHead(nodeId: string, implementerId: string, head: InMemoryLifecycleHeadSeed): void {
    this.heads.set(joinKey(nodeId, implementerId), head);
  }

  seedReportingKeyState(
    nodeId: string,
    implementerId: string,
    keyId: string,
    seed: InMemoryKeyStateSeed,
  ): void {
    this.keyStates.set(joinKey(nodeId, implementerId, keyId), seed);
  }

  seedEventSigningKey(key: NodeEventSigningKey): void {
    this.eventKeys.set(joinKey(key.nodeId, key.keyId), key);
  }

  listNonceEvidence(): readonly ReportingNonceEvidence[] {
    return [...this.nonceEvidence.values()];
  }

  // -------- ReportingRequestStore -------

  findRegistration(nodeId: string, reportingKeyId: string): Promise<ReportingRegistration | null> {
    return Promise.resolve(this.registrations.get(joinKey(nodeId, reportingKeyId)) ?? null);
  }

  readAdmissionSnapshot(
    nodeId: string,
    implementerId: string,
    reportingKeyId: string,
  ): Promise<ReportingAdmissionSnapshot | null> {
    const head = this.heads.get(joinKey(nodeId, implementerId));
    if (head === undefined) return Promise.resolve(null);
    const keyState = this.keyStates.get(joinKey(nodeId, implementerId, reportingKeyId));
    return Promise.resolve({
      restoreHold: this.restoreHolds.get(nodeId) ?? true,
      epoch: head.epoch,
      authHold: head.authHold,
      currentKeyId: head.currentKeyId,
      priorKeyId: head.priorKeyId,
      overlapExpiresAtMs: head.overlapExpiresAtMs,
      successorCommittedAtMs: head.successorCommittedAtMs,
      presentedKeyState: keyState?.state ?? null,
      presentedKeyRevokedAtMs: keyState?.revokedAtMs ?? null,
    });
  }

  peekNonceBurned(nodeId: string, implementerId: string, nonce: string): Promise<boolean> {
    return Promise.resolve(this.nonceEvidence.has(joinKey(nodeId, implementerId, nonce)));
  }

  // The burn critical section: no `await` between the recheck and the insert (see header).
  burnNonceAtomically(request: BurnNonceRequest): Promise<BurnNonceOutcome> {
    const { evidence } = request;
    const headKey = joinKey(evidence.nodeId, evidence.implementerId);
    if (this.restoreHolds.get(evidence.nodeId) ?? true) {
      return Promise.resolve({ kind: "HOLD" });
    }
    const head = this.heads.get(headKey);
    if (head === undefined || head.epoch !== request.expectedEpoch) {
      return Promise.resolve({ kind: "LIFECYCLE_RECHECK_FAILED" });
    }
    if (head.authHold) {
      return Promise.resolve({ kind: "HOLD" });
    }
    const keyState = this.keyStates.get(
      joinKey(evidence.nodeId, evidence.implementerId, evidence.reportingKeyId),
    );
    const admitted = reportingKeyAdmissionEligible({
      presentedKeyId: evidence.reportingKeyId,
      currentKeyId: head.currentKeyId,
      priorKeyId: head.priorKeyId,
      overlapExpiresAtMs: head.overlapExpiresAtMs,
      successorCommittedAtMs: head.successorCommittedAtMs,
      presentedKeyState: keyState?.state ?? null,
      presentedKeyRevokedAtMs: keyState?.revokedAtMs ?? null,
      receivedAtMs: evidence.receivedAtMs,
    });
    if (!admitted) {
      return Promise.resolve({ kind: "LIFECYCLE_RECHECK_FAILED" });
    }
    const nonceKey = joinKey(evidence.nodeId, evidence.implementerId, evidence.nonce);
    if (this.nonceEvidence.has(nonceKey)) {
      return Promise.resolve({ kind: "REPLAY" });
    }
    const nextSequence = this.burnCounters.get(evidence.nodeId) ?? 1n;
    this.burnCounters.set(evidence.nodeId, nextSequence + 1n);
    this.nextRowId += 1n;
    const inserted = Object.freeze({
      ...evidence,
      id: `nonce-evidence-${this.nextRowId.toString()}`,
      nonceBurnSequence: nextSequence,
    });
    this.nonceEvidence.set(nonceKey, inserted);
    return Promise.resolve({ kind: "BURNED", evidence: inserted });
  }

  findCompletedIdempotency(
    nodeId: string,
    implementerId: string,
    routeId: string,
    idempotencyKey: string,
  ): Promise<CompletedIdempotencyRecord | null> {
    const key = joinKey(nodeId, implementerId, routeId, idempotencyKey);
    return Promise.resolve(this.completedIdempotency.get(key) ?? null);
  }

  // The completion critical section: no `await` between the uniqueness checks and the insert.
  insertCompletedIdempotency(
    record: CompletedIdempotencyRecord,
  ): Promise<InsertCompletedIdempotencyOutcome> {
    try {
      return Promise.resolve(this.insertCompletedIdempotencySync(record));
    } catch (err) {
      return Promise.reject(err);
    }
  }

  // Child + completed parent as one unit of work. Serialized + journaled so a
  // CONFLICT/throw undoes every staged child side effect (together-or-neither).
  async commitMutationWithCompletedIdempotency(input: {
    readonly persistChild: (
      tx: ReportingMutationTx,
      completedIdempotencyId: string,
    ) => Promise<string>;
    readonly record: CompletedIdempotencyDraft;
  }): Promise<CommitMutationWithCompletedIdempotencyOutcome> {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const previous = this.mutationUowTail;
    this.mutationUowTail = previous.then(() => gate);
    await previous;
    const rollbacks: Array<() => void> = [];
    const undoChild = (): void => {
      for (let i = rollbacks.length - 1; i >= 0; i -= 1) {
        rollbacks[i]!();
      }
      rollbacks.length = 0;
    };
    try {
      const tx: ReportingMutationTx = {
        stageChildEffect: (apply, rollback) => {
          apply();
          rollbacks.push(rollback);
        },
      };
      const childRecordId = await input.persistChild(tx, input.record.id);
      if (childRecordId.length === 0) {
        undoChild();
        throw new ReportingStoreError("persistChild returned an empty childRecordId");
      }
      // Parent insert is sync — no await between uniqueness check and map write.
      const outcome = this.insertCompletedIdempotencySync({
        ...input.record,
        childRecordId,
      });
      if (outcome.kind === "CONFLICT") {
        undoChild();
        return { kind: "CONFLICT" };
      }
      rollbacks.length = 0;
      return { kind: "INSERTED", childRecordId };
    } catch (err) {
      undoChild();
      throw err;
    } finally {
      release();
    }
  }

  private insertCompletedIdempotencySync(
    record: CompletedIdempotencyRecord,
  ): InsertCompletedIdempotencyOutcome {
    if (
      !Number.isInteger(record.responseStatus) ||
      record.responseStatus < 100 ||
      record.responseStatus > 599 ||
      !Number.isSafeInteger(record.completedAtMs) ||
      record.idempotencyKey.length === 0 ||
      record.reportingNonceId.length === 0 ||
      record.childRecordId.length === 0
    ) {
      throw new ReportingStoreError(
        "completed idempotency record misses a mandatory completion field",
      );
    }
    const key = joinKey(record.nodeId, record.implementerId, record.routeId, record.idempotencyKey);
    if (this.completedIdempotency.has(key)) {
      return { kind: "CONFLICT" };
    }
    const guardedKey = joinKey(
      record.nodeId,
      record.implementerId,
      record.routeId,
      record.method,
      record.rawTarget,
      record.bodySha256,
    );
    if (isFingerprintGuardedRouteId(record.routeId) && this.guardedFingerprints.has(guardedKey)) {
      return { kind: "CONFLICT" };
    }
    this.completedIdempotency.set(key, Object.freeze(record));
    if (isFingerprintGuardedRouteId(record.routeId)) {
      this.guardedFingerprints.add(guardedKey);
    }
    return { kind: "INSERTED" };
  }

  // -------- NodeEventVerificationStore -------

  findEventSigningKey(nodeId: string, keyId: string): Promise<NodeEventSigningKey | null> {
    return Promise.resolve(this.eventKeys.get(joinKey(nodeId, keyId)) ?? null);
  }

  readCursor(nodeId: string): Promise<NodeEventCursor> {
    const cursor = this.cursors.get(nodeId);
    return Promise.resolve(
      cursor ?? { nodeId, lastEventHash: null, lastSeq: 0n, lastEventId: null },
    );
  }

  findRecordedEvent(nodeId: string, eventId: string): Promise<RecordedNodeEvent | null> {
    return Promise.resolve(this.recordedEvents.get(joinKey(nodeId, eventId)) ?? null);
  }

  appendVerifiedEvents(
    nodeId: string,
    events: readonly RecordedNodeEvent[],
    expectedCursor: NodeEventCursor,
  ): Promise<AppendNodeEventsOutcome> {
    const current = this.cursors.get(nodeId) ?? {
      nodeId,
      lastEventHash: null,
      lastSeq: 0n,
      lastEventId: null,
    };
    if (
      current.lastEventHash !== expectedCursor.lastEventHash ||
      current.lastSeq !== expectedCursor.lastSeq
    ) {
      return Promise.resolve({ kind: "CURSOR_STALE" });
    }
    for (const event of events) {
      const key = joinKey(nodeId, event.eventId);
      if (this.recordedEvents.has(key)) {
        return Promise.reject(
          new ReportingStoreError("verified batch carries an already-recorded event id"),
        );
      }
    }
    let head = current;
    for (const event of events) {
      this.recordedEvents.set(joinKey(nodeId, event.eventId), Object.freeze(event));
      head = {
        nodeId,
        lastEventHash: event.eventHash,
        lastSeq: event.seq,
        lastEventId: event.eventId,
      };
    }
    this.cursors.set(nodeId, head);
    return Promise.resolve({ kind: "APPENDED" });
  }
}
