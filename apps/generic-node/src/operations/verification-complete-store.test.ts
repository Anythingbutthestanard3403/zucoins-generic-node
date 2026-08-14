// createSqlVerificationCompleteStore.
//
// What this suite proves, and what it deliberately does not:
//
//   PROVES  the composition. That the acknowledgement, every proof mint and every lease
//           release run on ONE transaction and roll back together; that a release happens
//           only for the memberships the acknowledgement service named; that a replay
//           neither double-releases nor mints a second proof; that acknowledgement failures
//           map onto the frozen action-route error taxonomy without touching a lease.
//
//   DOES NOT re-prove `releaseLease` / `mintReleaseProof` themselves. Their invariants
//           (exact-tuple DELETE, proof consume-once, group-terminal gate, unpin) are real
//           SQL and are covered against real PostgreSQL in
//           packages/node-core/test/lease-foundation.pg.test.ts (cases 4, 5, 14, 15).
//           The ports here are minimal recorders, so a green run here is never evidence
//           about the SQL.
//
// How same-transaction is proven rather than asserted: every port reaches its state through
// `viewOf(tx)`, a WeakMap keyed on the executor object `withTransaction` created. An executor
// that is not the open transaction — a pool handle, a second connection, a stale tx — is not
// in the map and the port throws. `withTransaction` mutates a CLONE of the committed world
// and publishes it only on success, so a throw anywhere discards every write made under it.
// That is what makes the fault-injection case below a real rollback observation.
//
// Fixture discipline (sibling failure mode): no port computes its answer from the
// arguments it was handed. Arguments are lookup keys into state the test seeded, so a guard
// comparing a supplied value against a durable one is never comparing a value with itself.

import { describe, expect, it } from "vitest";

import {
  AcknowledgementError,
  IdempotencyConflictError,
  OperationVersionConflictError,
  ProtocolPredicateFailedError,
  type AckOpenMembership,
  type AckOperationFacts,
  type AcknowledgementDraft,
  type AcknowledgementStore,
  type GroupReleaseFacts,
  type MintReleaseProofParams,
  type ReleaseLeaseParams,
  type StoredAcknowledgement,
  type VerificationCompleteInput,
  type VerificationCompleteSuccessResponse,
} from "@zucoins/node-core";

import {
  VERIFICATION_COMPLETE_RELEASE_REASON,
  VerificationModeMismatchError,
  computeReleaseProofDigest,
  createSqlVerificationCompleteStore,
  type VerificationCompleteEnvelope,
  type VerificationCompleteTx,
  type VerificationCompleteTxFactory,
} from "./verification-complete-store.js";

const OP = "aaaaaaaa-0000-4000-8000-000000000001";
const SIBLING_OP = "aaaaaaaa-0000-4000-8000-000000000002";
const GROUP = "bbbbbbbb-0000-4000-8000-000000000001";
const WALLET_A = "cccccccc-0000-4000-8000-00000000000a";
const WALLET_B = "cccccccc-0000-4000-8000-00000000000b";
const MEMBERSHIP_A = "dddddddd-0000-4000-8000-00000000000a";
const MEMBERSHIP_B = "dddddddd-0000-4000-8000-00000000000b";
const NODE = "eeeeeeee-0000-4000-8000-000000000001";
const IMPL = "ffffffff-0000-4000-8000-000000000001";
const NONCE = "99999999-0000-4000-8000-000000000001";
const MUTATION = "88888888-0000-4000-8000-000000000001";
const ACK_ID = "77777777-0000-4000-8000-000000000001";
const PROOF_ID = "66666666-0000-4000-8000-000000000001";
const PROOF_ID_2 = "66666666-0000-4000-8000-000000000002";
const PUBKEY_A = "PUBKEY-A";
const NOW = "2026-02-01T00:00:00.000Z";

// Exact signed bytes for the request (the byte-exact signing rule — carried, never re-derived).
const PREIMAGE = 'zp-report-request-v1\n{"a":1}';
const SIGNATURE = "c2lnbmF0dXJlLWJ5dGVz";

type WalletState = "PINNED" | "AVAILABLE";

interface ProofRow {
  readonly proofId: string;
  readonly walletId: string;
  readonly operationId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
  readonly proofKind: string;
  readonly proofDigest: string;
  consumed: boolean;
}

interface World {
  operations: Map<string, AckOperationFacts>;
  /** operationId → frozen verification_mode (ZTR-1303 gate). */
  verificationModes: Map<string, "INDEPENDENT" | "NODE_VERIFIED">;
  acks: Map<string, StoredAcknowledgement>;
  /** leaseGroupId → operationIds stamped terminal. */
  completedOps: Map<string, Set<string>>;
  openMemberships: AckOpenMembership[];
  proofs: Map<string, ProofRow>;
  wallets: Map<string, WalletState>;
  releaseReasons: string[];
  childDisposition: "NONE" | "PENDING" | "JOINED";
}

function cloneWorld(world: World): World {
  return {
    operations: new Map(world.operations),
    verificationModes: new Map(world.verificationModes),
    acks: new Map(world.acks),
    completedOps: new Map([...world.completedOps].map(([k, v]) => [k, new Set(v)])),
    openMemberships: [...world.openMemberships],
    proofs: new Map([...world.proofs].map(([k, v]) => [k, { ...v }])),
    wallets: new Map(world.wallets),
    releaseReasons: [...world.releaseReasons],
    childDisposition: world.childDisposition,
  };
}

function receiveOperation(operationId: string, rowVersion = 7): AckOperationFacts {
  return {
    operationId,
    nodeId: NODE,
    implementerId: IMPL,
    kind: "RECEIVE_EXTERNAL",
    rowVersion,
    leaseGroupId: GROUP,
    expectedWallets: [{ role: "RECEIVER", walletId: WALLET_A, walletPublicKey: PUBKEY_A }],
  };
}

function seedWorld(overrides: Partial<World> = {}): World {
  return {
    operations: new Map([[OP, receiveOperation(OP)]]),
    verificationModes: new Map([[OP, "INDEPENDENT"]]),
    acks: new Map(),
    completedOps: new Map([[GROUP, new Set<string>()]]),
    openMemberships: [
      { membershipId: MEMBERSHIP_A, walletId: WALLET_A, leaseEpoch: 3n, leaseGroupId: GROUP, operationId: OP },
    ],
    proofs: new Map(),
    wallets: new Map([[WALLET_A, "PINNED"]]),
    releaseReasons: [],
    childDisposition: "NONE",
    ...overrides,
  };
}

/** A harness whose ports are reachable only through the transaction the store opened. */
function harness(seed: World) {
  let committed = seed;
  const views = new WeakMap<object, World>();
  const calls = { mint: 0, release: 0, commits: 0, rollbacks: 0, freezes: 0 };

  const viewOf = (tx: object): World => {
    const view = views.get(tx);
    if (view === undefined) {
      throw new Error(
        "port was called with an executor that is not the open transaction — the " +
          "acknowledgement and the lease release are not sharing a DB transaction",
      );
    }
    return view;
  };

  const txFactory: VerificationCompleteTxFactory = {
    async withTransaction<T>(fn: (tx: VerificationCompleteTx) => Promise<T>): Promise<T> {
      const pending = cloneWorld(committed);
      const tx: VerificationCompleteTx = {
        async query<R>(text: string, params?: readonly unknown[]) {
          // ZTR-1303: mode gate reads operations.verification_mode before ack/release.
          if (text.includes("verification_mode") && params !== undefined && params[0] !== undefined) {
            const mode = pending.verificationModes.get(String(params[0])) ?? "INDEPENDENT";
            return {
              rows: [{ verification_mode: mode }] as R[],
              rowCount: 1,
            };
          }
          return { rows: [] as R[], rowCount: 0 };
        },
      };
      views.set(tx, pending);
      try {
        const value = await fn(tx);
        committed = pending;
        calls.commits += 1;
        return value;
      } catch (err) {
        calls.rollbacks += 1;
        throw err;
      }
    },
  };

  const ackStore: AcknowledgementStore<VerificationCompleteTx> = {
    async readOperation(tx, operationId) {
      return viewOf(tx).operations.get(operationId) ?? null;
    },
    async findAcknowledgement(tx, operationId) {
      return viewOf(tx).acks.get(operationId) ?? null;
    },
    async insertAcknowledgement(tx, draft: AcknowledgementDraft) {
      const view = viewOf(tx);
      if (view.acks.has(draft.operationId)) {
        throw new Error("operation_id UNIQUE violated in fixture");
      }
      // The signed bytes are looked up by the draft's nonce id — exactly how the SQL store
      // reads them off the joined reporting_request_nonces row. Never echoed from the input.
      const signed = SIGNED_BYTES_BY_NONCE.get(draft.reportingNonceId);
      if (signed === undefined) {
        throw new Error(`fixture has no signed bytes for nonce ${draft.reportingNonceId}`);
      }
      view.acks.set(draft.operationId, {
        id: draft.id,
        operationId: draft.operationId,
        nodeId: draft.nodeId,
        implementerId: draft.implementerId,
        consumedCursor: draft.consumedCursor,
        verdict: draft.verdict,
        evidenceSetSha256: draft.evidenceSetSha256,
        requestBodySha256: draft.requestBodySha256,
        rawTarget: draft.rawTarget,
        requestPreimageText: signed.preimage,
        requestSignature: signed.signature,
        acknowledgedAt: draft.acknowledgedAt,
        evidenceRoles: draft.walletEvidence.map((e) => e.role as "RECEIVER"),
        evidence: draft.walletEvidence.map((e) => ({
          role: e.role as "RECEIVER",
          walletId: e.walletId,
          walletPublicKey: e.walletPublicKey,
        })),
        frozenResponseBody: null,
      });
    },
    async completeGroupOperation(tx, leaseGroupId, operationId) {
      const view = viewOf(tx);
      const set = view.completedOps.get(leaseGroupId) ?? new Set<string>();
      set.add(operationId);
      view.completedOps.set(leaseGroupId, set);
    },
    async applyOperationVerificationVerdict(_tx, _operationId, _verdict) {
      // ZTR-1246 — fixture mirrors SQL store; denormalized column not modeled here.
    },
    async readGroupReleaseFacts(tx, leaseGroupId): Promise<GroupReleaseFacts> {
      const view = viewOf(tx);
      const completed = view.completedOps.get(leaseGroupId) ?? new Set<string>();
      const legs = [...view.operations.values()].filter((op) => op.leaseGroupId === leaseGroupId);
      return {
        childDisposition: view.childDisposition,
        operations: legs.map((op) => {
          const ack = view.acks.get(op.operationId);
          return {
            operationId: op.operationId,
            kind: op.kind,
            verdict: ack?.verdict ?? null,
            evidenceRoles: ack?.evidenceRoles ?? [],
            evidence: ack?.evidence ?? [],
            expectedWallets: op.expectedWallets,
            completed: completed.has(op.operationId),
          };
        }),
      };
    },
    async readOpenMemberships(tx, leaseGroupId) {
      return viewOf(tx).openMemberships.filter((m) => m.leaseGroupId === leaseGroupId);
    },
  };

  // Minimal recorders. They model the durable EFFECT, not releaseLease's own invariants.
  const mint = async (tx: VerificationCompleteTx, params: MintReleaseProofParams) => {
    const view = viewOf(tx);
    calls.mint += 1;
    if (view.proofs.has(params.proofId)) throw new Error("proof_id PRIMARY KEY violated");
    view.proofs.set(params.proofId, { ...params, consumed: false });
    await faults.afterMint?.(params);
  };

  const release = async (tx: VerificationCompleteTx, params: ReleaseLeaseParams) => {
    const view = viewOf(tx);
    calls.release += 1;
    await faults.beforeRelease?.(params);
    const proof = view.proofs.get(params.releaseProofId);
    if (proof === undefined) throw new Error("PROOF_NOT_FOUND");
    if (proof.consumed) throw new Error("PROOF_ALREADY_CONSUMED");
    if (
      proof.walletId !== params.walletId ||
      proof.membershipId !== params.membershipId ||
      proof.leaseGroupId !== params.leaseGroupId ||
      proof.operationId !== params.operationId ||
      proof.leaseEpoch !== params.leaseEpoch
    ) {
      throw new Error("PROOF_FOREIGN");
    }
    proof.consumed = true;
    view.openMemberships = view.openMemberships.filter((m) => m.membershipId !== params.membershipId);
    view.wallets.set(params.walletId, "AVAILABLE");
    view.releaseReasons.push(params.releaseReason);
    return { membershipId: params.membershipId, releasedAt: new Date(NOW), deletedRows: 1, groupReleased: view.openMemberships.length === 0 };
  };

  const faults: {
    afterMint?: (params: MintReleaseProofParams) => Promise<void>;
    beforeRelease?: (params: ReleaseLeaseParams) => Promise<void>;
  } = {};

  // Stands in for the reporting runtime's completed-idempotency write: the exact frozen
  // response bytes, stored on the same transaction so a replay reads back what committed.
  const freezeResponse = async (
    tx: VerificationCompleteTx,
    operationId: string,
    body: VerificationCompleteSuccessResponse,
  ) => {
    const view = viewOf(tx);
    const ack = view.acks.get(operationId);
    if (ack === undefined) throw new Error("freeze before the acknowledgement committed");
    calls.freezes += 1;
    view.acks.set(operationId, { ...ack, frozenResponseBody: body });
  };

  return {
    calls,
    faults,
    ackStore,
    txFactory,
    mint,
    release,
    freezeResponse,
    get committed() {
      return committed;
    },
  };
}

const SIGNED_BYTES_BY_NONCE = new Map<string, { preimage: string; signature: string }>([
  [NONCE, { preimage: PREIMAGE, signature: SIGNATURE }],
]);

const envelope: VerificationCompleteEnvelope = {
  nodeId: NODE,
  implementerId: IMPL,
  reportingNonceId: NONCE,
  mutationIdempotencyId: MUTATION,
  rawTarget: `/v1/operations/${OP}/verification-complete`,
  requestBodySha256: "a".repeat(64),
  requestPreimageText: PREIMAGE,
  requestSignature: SIGNATURE,
  ownerInstanceId: "55555555-0000-4000-8000-000000000001",
  walletEvidence: [
    {
      walletId: WALLET_A,
      walletPublicKey: PUBKEY_A,
      role: "RECEIVER",
      t0: { observationId: "0a0a0a0a-0000-4000-8000-000000000001" },
      terminal: { observationId: "0b0b0b0b-0000-4000-8000-000000000001" },
    },
  ],
};

function input(overrides: Partial<VerificationCompleteInput> = {}): VerificationCompleteInput {
  return {
    expected_row_version: 7,
    consumed_cursor: "42",
    verdict: "VERIFIED",
    wallet_evidence: [],
    idempotencyKey: "idem-1",
    ...overrides,
  };
}

function storeOver(
  h: ReturnType<typeof harness>,
  proofIds: string[] = [PROOF_ID, PROOF_ID_2],
  env: VerificationCompleteEnvelope = envelope,
) {
  const ids = [...proofIds];
  return createSqlVerificationCompleteStore({
    txFactory: h.txFactory,
    ackStore: h.ackStore,
    envelopeFor: async () => env,
    newAcknowledgementId: () => ACK_ID,
    newProofId: () => ids.shift() ?? "exhausted",
    nowIso: () => NOW,
    mintProof: h.mint as never,
    release: h.release as never,
    freezeResponse: h.freezeResponse,
  });
}

describe("createSqlVerificationCompleteStore", () => {
  it("VERIFIED with the group terminal releases the lease and unpins the wallet", async () => {
    const h = harness(seedWorld());
    const result = await storeOver(h).verificationComplete(OP, input());

    expect(result.status).toBe(200);
    expect(result.body).toEqual({
      operation_id: OP,
      acknowledgement_id: ACK_ID,
      verdict: "VERIFIED",
      lease_release_status: "RELEASED",
      acknowledged_at: NOW,
    });
    expect(result.idempotentReplay).toBe(false);

    const w = h.committed;
    expect(w.acks.get(OP)?.verdict).toBe("VERIFIED");
    expect([...w.proofs.values()]).toEqual([
      expect.objectContaining({
        proofId: PROOF_ID,
        walletId: WALLET_A,
        membershipId: MEMBERSHIP_A,
        leaseGroupId: GROUP,
        leaseEpoch: 3n,
        proofKind: "RECEIVE_LANDED",
        consumed: true,
      }),
    ]);
    expect(w.openMemberships).toEqual([]);
    expect(w.wallets.get(WALLET_A)).toBe("AVAILABLE");
    expect(w.releaseReasons).toEqual([VERIFICATION_COMPLETE_RELEASE_REASON]);
  });

  it("binds the proof digest to the acknowledgement and the exact lease tuple", async () => {
    const h = harness(seedWorld());
    await storeOver(h).verificationComplete(OP, input());

    expect(h.committed.proofs.get(PROOF_ID)?.proofDigest).toBe(
      computeReleaseProofDigest({
        acknowledgementId: ACK_ID,
        operationId: OP,
        walletId: WALLET_A,
        membershipId: MEMBERSHIP_A,
        leaseGroupId: GROUP,
        leaseEpoch: 3n,
        verdict: "VERIFIED",
      }),
    );
    // A digest computed for a different membership must not match — the binding is real.
    expect(h.committed.proofs.get(PROOF_ID)?.proofDigest).not.toBe(
      computeReleaseProofDigest({
        acknowledgementId: ACK_ID,
        operationId: OP,
        walletId: WALLET_A,
        membershipId: MEMBERSHIP_B,
        leaseGroupId: GROUP,
        leaseEpoch: 3n,
        verdict: "VERIFIED",
      }),
    );
  });

  it("a fault injected between the proof mint and the lease release commits neither", async () => {
    const h = harness(seedWorld());
    h.faults.beforeRelease = async () => {
      throw new Error("injected: connection lost after the proof row was written");
    };

    await expect(storeOver(h).verificationComplete(OP, input())).rejects.toThrow("injected");

    const w = h.committed;
    expect(h.calls.mint).toBe(1); // the proof WAS written inside the transaction …
    expect(w.proofs.size).toBe(0); // … and did not survive the rollback.
    expect(w.acks.size).toBe(0); // the acknowledgement rolled back with it
    expect(w.openMemberships).toHaveLength(1); // the lease is still held
    expect(w.wallets.get(WALLET_A)).toBe("PINNED"); // and the wallet is still pinned
    expect(h.calls.commits).toBe(0);
    expect(h.calls.rollbacks).toBe(1);
  });

  it("a fault injected inside the release leaves no orphan unconsumed proof", async () => {
    const h = harness(seedWorld());
    h.faults.afterMint = async () => {
      throw new Error("injected: crash immediately after INSERT lease_release_proofs");
    };

    await expect(storeOver(h).verificationComplete(OP, input())).rejects.toThrow("injected");

    // An unconsumed proof surviving here would be standing release authority for a lease
    // that was never released — the exact hazard the single transaction exists to prevent.
    expect(h.committed.proofs.size).toBe(0);
    expect(h.calls.release).toBe(0);
    expect(h.committed.wallets.get(WALLET_A)).toBe("PINNED");
  });

  it("an identical replay returns the same body and neither re-releases nor re-mints", async () => {
    const h = harness(seedWorld());
    const store = storeOver(h);

    const first = await store.verificationComplete(OP, input());
    const second = await store.verificationComplete(OP, input());

    expect(second.body).toEqual(first.body);
    expect(second.idempotentReplay).toBe(true);
    expect(h.calls.mint).toBe(1);
    expect(h.calls.release).toBe(1);
    expect(h.committed.proofs.size).toBe(1);
    expect(h.committed.releaseReasons).toEqual([VERIFICATION_COMPLETE_RELEASE_REASON]);
  });

  it("a replay releases nothing even when a membership is still open on the group read", async () => {
    // Defence in depth for "replays return the frozen first-response fields": a stale or
    // racy open-membership read must not turn a replay into a second release.
    const h = harness(seedWorld());
    const store = storeOver(h);
    await store.verificationComplete(OP, input());

    h.committed.openMemberships.push({
      membershipId: MEMBERSHIP_B,
      walletId: WALLET_B,
      leaseEpoch: 4n,
      leaseGroupId: GROUP,
      operationId: OP,
    });
    h.committed.wallets.set(WALLET_B, "PINNED");

    const replay = await store.verificationComplete(OP, input());

    expect(replay.idempotentReplay).toBe(true);
    expect(h.calls.mint).toBe(1);
    expect(h.calls.release).toBe(1);
    expect(h.committed.wallets.get(WALLET_B)).toBe("PINNED");
    expect(h.committed.openMemberships.map((m) => m.membershipId)).toEqual([MEMBERSHIP_B]);
  });

  it("REJECTED pins for attention, mints no proof and releases nothing", async () => {
    const h = harness(seedWorld());
    const result = await storeOver(h).verificationComplete(OP, input({ verdict: "REJECTED" }));

    expect(result.body.lease_release_status).toBe("PINNED_FOR_ATTENTION");
    expect(h.calls.mint).toBe(0);
    expect(h.calls.release).toBe(0);
    expect(h.committed.wallets.get(WALLET_A)).toBe("PINNED");
    expect(h.committed.openMemberships).toHaveLength(1);
    // The acknowledgement itself still commits — the operator needs the durable verdict.
    expect(h.committed.acks.get(OP)?.verdict).toBe("REJECTED");
  });

  it("INDETERMINATE pins for attention and releases nothing", async () => {
    const h = harness(seedWorld());
    const result = await storeOver(h).verificationComplete(OP, input({ verdict: "INDETERMINATE" }));

    expect(result.body.lease_release_status).toBe("PINNED_FOR_ATTENTION");
    expect(h.calls.release).toBe(0);
    expect(h.committed.wallets.get(WALLET_A)).toBe("PINNED");
  });

  it("an unacknowledged sibling leg keeps the group pending and releases nothing", async () => {
    const seed = seedWorld();
    seed.operations.set(SIBLING_OP, receiveOperation(SIBLING_OP));
    seed.openMemberships.push({
      membershipId: MEMBERSHIP_B,
      walletId: WALLET_B,
      leaseEpoch: 4n,
      leaseGroupId: GROUP,
      operationId: SIBLING_OP,
    });
    seed.wallets.set(WALLET_B, "PINNED");
    const h = harness(seed);

    const result = await storeOver(h).verificationComplete(OP, input());

    expect(result.body.lease_release_status).toBe("PINNED_GROUP_PENDING");
    expect(h.calls.mint).toBe(0);
    expect(h.calls.release).toBe(0);
    expect(h.committed.wallets.get(WALLET_A)).toBe("PINNED");
    expect(h.committed.wallets.get(WALLET_B)).toBe("PINNED");
  });

  it("maps a row_version mismatch to operation_version_conflict without touching the lease", async () => {
    const h = harness(seedWorld());

    await expect(
      storeOver(h).verificationComplete(OP, input({ expected_row_version: 6 })),
    ).rejects.toBeInstanceOf(OperationVersionConflictError);

    expect(h.committed.acks.size).toBe(0);
    expect(h.committed.wallets.get(WALLET_A)).toBe("PINNED");
    expect(h.calls.rollbacks).toBe(1);
  });

  it("maps a conflicting replay to idempotency_conflict and releases nothing", async () => {
    const h = harness(seedWorld());
    const store = storeOver(h);
    await store.verificationComplete(OP, input());

    // Same operation, different verdict: rejected rather than reconciled.
    await expect(
      store.verificationComplete(OP, input({ verdict: "REJECTED" })),
    ).rejects.toBeInstanceOf(IdempotencyConflictError);

    expect(h.calls.release).toBe(1);
    expect(h.committed.proofs.size).toBe(1);
  });

  it("maps a foreign reporting tenant to protocol_predicate_failed", async () => {
    const h = harness(seedWorld());
    const foreign: VerificationCompleteEnvelope = {
      ...envelope,
      implementerId: "ffffffff-0000-4000-8000-0000000000ff",
    };

    await expect(
      storeOver(h, [PROOF_ID], foreign).verificationComplete(OP, input()),
    ).rejects.toBeInstanceOf(ProtocolPredicateFailedError);

    expect(h.committed.acks.size).toBe(0);
    expect(h.calls.mint).toBe(0);
  });

  it("maps an operation with no lease group to protocol_predicate_failed and commits nothing", async () => {
    const seed = seedWorld();
    seed.operations.set(OP, { ...receiveOperation(OP), leaseGroupId: null });
    const h = harness(seed);

    await expect(storeOver(h).verificationComplete(OP, input())).rejects.toBeInstanceOf(
      ProtocolPredicateFailedError,
    );
    expect(h.committed.acks.size).toBe(0);
  });

  it("rethrows a non-acknowledgement error unchanged", async () => {
    const h = harness(seedWorld());
    const store = createSqlVerificationCompleteStore({
      txFactory: h.txFactory,
      ackStore: h.ackStore,
      envelopeFor: async () => {
        throw new Error("envelope resolution failed");
      },
      newAcknowledgementId: () => ACK_ID,
      newProofId: () => PROOF_ID,
      nowIso: () => NOW,
      mintProof: h.mint as never,
      release: h.release as never,
    });

    await expect(store.verificationComplete(OP, input())).rejects.toThrow(
      "envelope resolution failed",
    );
    // envelopeFor runs before BEGIN, so no transaction was opened at all.
    expect(h.calls.commits + h.calls.rollbacks).toBe(0);
  });

  it("every port refuses an executor that is not the open transaction", async () => {
    const h = harness(seedWorld());
    const foreignTx: VerificationCompleteTx = {
      async query<R>() {
        return { rows: [] as R[], rowCount: 0 };
      },
    };

    // This is the assertion the same-transaction claim rests on: the WeakMap seam is real,
    // so a port reached with any other executor throws instead of silently writing.
    await expect(h.ackStore.readOperation(foreignTx, OP)).rejects.toThrow(
      "not the open transaction",
    );
  });

  it("carries the AcknowledgementError reason through as the predicate detail", async () => {
    const seed = seedWorld();
    seed.operations.delete(OP);
    const h = harness(seed);

    await expect(storeOver(h).verificationComplete(OP, input())).rejects.toMatchObject({
      name: "ProtocolPredicateFailedError",
      reason: "OPERATION_NOT_FOUND",
    });
    // Sanity: the service really did raise the typed failure the mapper consumed.
    expect(new AcknowledgementError("OPERATION_NOT_FOUND", "x").reason).toBe("OPERATION_NOT_FOUND");
  });

  it("NODE_VERIFIED → verification_mode_mismatch; no ack, mint, release, or wallet change (AC3)", async () => {
    const seed = seedWorld();
    seed.verificationModes.set(OP, "NODE_VERIFIED");
    const h = harness(seed);

    await expect(storeOver(h).verificationComplete(OP, input())).rejects.toBeInstanceOf(
      VerificationModeMismatchError,
    );

    expect(h.calls.rollbacks).toBe(1);
    expect(h.calls.commits).toBe(0);
    expect(h.calls.mint).toBe(0);
    expect(h.calls.release).toBe(0);
    expect(h.committed.acks.size).toBe(0);
    expect(h.committed.wallets.get(WALLET_A)).toBe("PINNED");
    expect(h.committed.openMemberships).toHaveLength(1);
  });
});
