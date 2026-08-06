// unit tests for the in-memory reference store: burn atomicity and
// replay, lifecycle recheck outcomes, evidence immutability (append-only), the guarded
// partial-uniqueness on the two mutation routes, the mandatory completion-field mandate,
// cursor staleness, and the fixed-window limiter. The logical-fingerprint formula is checked
// against an independent restatement of the SQL.

import { describe, expect, it } from "vitest";

import { computeReportingLogicalFingerprint, sha256HexUtf8 } from "./ed25519.js";
import { InMemoryReportingRateLimiter } from "./in-memory-rate-limiter.js";
import { InMemoryReportingStore } from "./in-memory-store.js";
import type { BurnNonceEvidence, CompletedIdempotencyRecord } from "./store.js";
import { ReportingStoreError } from "./store.js";
import { IMPLEMENTER_ID, ISSUED_MS, KEY_ID, NODE_ID } from "./test-fixtures.js";

const NONCE = "99999999-9999-4999-8999-999999999999";

function seededStore(): InMemoryReportingStore {
  const store = new InMemoryReportingStore();
  store.seedRestoreHold(NODE_ID, false);
  store.seedLifecycleHead(NODE_ID, IMPLEMENTER_ID, {
    epoch: 1n,
    authHold: false,
    currentKeyId: KEY_ID,
    priorKeyId: null,
    overlapExpiresAtMs: null,
    successorCommittedAtMs: null,
  });
  store.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, {
    state: "ACTIVE",
    revokedAtMs: null,
  });
  return store;
}

function evidence(nonce: string, preimageText = "preimage"): BurnNonceEvidence {
  return {
    nodeId: NODE_ID,
    implementerId: IMPLEMENTER_ID,
    nonce,
    purpose: "zp-report-request-v1",
    routeId: "verification_complete",
    requestClass: "MUTATION",
    reportingKeyId: KEY_ID,
    lifecycleEpoch: 1n,
    requestPreimageText: preimageText,
    requestPreimageSha256: sha256HexUtf8(preimageText),
    requestSignature: "sig",
    method: "POST",
    rawTarget: "/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete",
    bodySha256: sha256HexUtf8("{}"),
    logicalFingerprint: "f".repeat(64),
    issuedAt: "2026-07-18T00:00:00.000Z",
    expiresAt: "2026-07-18T00:01:00.000Z",
    receivedAtMs: ISSUED_MS + 1_000,
    consumedAtMs: ISSUED_MS + 1_000,
    retentionClass: "PERMANENT_MUTATION",
  };
}

function completionRecord(idempotencyKey: string, bodySha256 = sha256HexUtf8("{}")): CompletedIdempotencyRecord {
  return {
    id: `idem-${idempotencyKey}`,
    nodeId: NODE_ID,
    implementerId: IMPLEMENTER_ID,
    routeId: "verification_complete",
    idempotencyKey,
    reportingNonceId: "nonce-evidence-1",
    childRecordId: "child-1",
    method: "POST",
    rawTarget: "/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete",
    bodySha256,
    logicalFingerprint: "f".repeat(64),
    responseStatus: 200,
    responseBytes: new TextEncoder().encode("{\"ok\":true}"),
    completedAtMs: ISSUED_MS + 2_000,
  };
}

describe("atomic burn", () => {
  it("burns once per (node, implementer, nonce) and replays any later attempt", async () => {
    const store = seededStore();
    const first = await store.burnNonceAtomically({ expectedEpoch: 1n, evidence: evidence(NONCE) });
    expect(first.kind).toBe("BURNED");
    if (first.kind === "BURNED") {
      expect(first.evidence.nonceBurnSequence).toBe(1n);
      expect(first.evidence.lifecycleEpoch).toBe(1n);
    }
    const replay = await store.burnNonceAtomically({
      expectedEpoch: 1n,
      evidence: evidence(NONCE, "a different preimage entirely"),
    });
    expect(replay.kind).toBe("REPLAY");
    const rows = store.listNonceEvidence();
    expect(rows.length).toBe(1);
    expect(rows[0]!.requestPreimageText).toBe("preimage");
    const second = await store.burnNonceAtomically({
      expectedEpoch: 1n,
      evidence: evidence("88888888-8888-4888-8888-888888888888"),
    });
    expect(second.kind).toBe("BURNED");
    if (second.kind === "BURNED") expect(second.evidence.nonceBurnSequence).toBe(2n);
  });

  it("rechecks epoch, holds, and key admission inside the burn", async () => {
    const store = seededStore();
    const staleEpoch = await store.burnNonceAtomically({ expectedEpoch: 2n, evidence: evidence(NONCE) });
    expect(staleEpoch.kind).toBe("LIFECYCLE_RECHECK_FAILED");
    store.seedLifecycleHead(NODE_ID, IMPLEMENTER_ID, {
      epoch: 1n,
      authHold: true,
      currentKeyId: KEY_ID,
      priorKeyId: null,
      overlapExpiresAtMs: null,
      successorCommittedAtMs: null,
    });
    const held = await store.burnNonceAtomically({ expectedEpoch: 1n, evidence: evidence(NONCE) });
    expect(held.kind).toBe("HOLD");
    const fresh = new InMemoryReportingStore();
    const noHead = await fresh.burnNonceAtomically({ expectedEpoch: 1n, evidence: evidence(NONCE) });
    expect(noHead.kind).toBe("HOLD");
    expect(store.listNonceEvidence().length).toBe(0);
  });
});

describe("completed idempotency", () => {
  it("enforces the primary uniqueness and the guarded fingerprint partial uniqueness", async () => {
    const store = seededStore();
    const first = await store.insertCompletedIdempotency(completionRecord("key-one"));
    expect(first.kind).toBe("INSERTED");
    const sameKey = await store.insertCompletedIdempotency(completionRecord("key-one"));
    expect(sameKey.kind).toBe("CONFLICT");
    const sameFingerprintNewKey = await store.insertCompletedIdempotency(completionRecord("key-two"));
    expect(sameFingerprintNewKey.kind).toBe("CONFLICT");
    const differentFingerprint = await store.insertCompletedIdempotency(
      completionRecord("key-three", sha256HexUtf8("{\"other\":true}")),
    );
    expect(differentFingerprint.kind).toBe("INSERTED");
  });

  it("does not guard the fingerprint on non-guarded routes", async () => {
    const store = seededStore();
    const readRouteRecord: CompletedIdempotencyRecord = {
      ...completionRecord("key-one"),
      routeId: "events_list",
    };
    expect((await store.insertCompletedIdempotency(readRouteRecord)).kind).toBe("INSERTED");
    const second = await store.insertCompletedIdempotency({ ...readRouteRecord, id: "idem-key-two", idempotencyKey: "key-two" });
    expect(second.kind).toBe("INSERTED");
  });

  it("rejects a record missing a mandatory completion field", async () => {
    const store = seededStore();
    await expect(
      store.insertCompletedIdempotency({ ...completionRecord("key-one"), responseStatus: 99 }),
    ).rejects.toBeInstanceOf(ReportingStoreError);
    await expect(
      store.insertCompletedIdempotency({ ...completionRecord("key-two"), completedAtMs: Number.NaN }),
    ).rejects.toBeInstanceOf(ReportingStoreError);
    await expect(
      store.insertCompletedIdempotency({ ...completionRecord("key-three"), childRecordId: "" }),
    ).rejects.toBeInstanceOf(ReportingStoreError);
  });
});

describe("logical fingerprint formula (restatement)", () => {
  it("matches an independent recomputation of the SQL expression", () => {
    const method = "POST";
    const target = "/v1/operations/33333333-3333-4333-8333-333333333333/armed";
    const bodySha256 = sha256HexUtf8("{\"armed\":true}");
    const utf8Length = (text: string): number => new TextEncoder().encode(text).length;
    const restated = `m${utf8Length(method)}:${method}t${utf8Length(target)}:${target}b64:${bodySha256}`;
    expect(computeReportingLogicalFingerprint(method, target, bodySha256)).toBe(
      sha256HexUtf8(restated),
    );
  });
});

describe("event cursor and recorded events", () => {
  it("appends atomically against the expected cursor and rejects a stale expectation", async () => {
    const store = new InMemoryReportingStore();
    const cursor = await store.readCursor(NODE_ID);
    expect(cursor.lastSeq).toBe(0n);
    expect(cursor.lastEventHash).toBeNull();
    const event = {
      nodeId: NODE_ID,
      eventId: "10000000-0000-4000-8000-000000000001",
      eventHash: "a".repeat(64),
      seq: 1n,
    };
    expect((await store.appendVerifiedEvents(NODE_ID, [event], cursor)).kind).toBe("APPENDED");
    const stale = await store.appendVerifiedEvents(
      NODE_ID,
      [{ ...event, eventId: "10000000-0000-4000-8000-000000000002", seq: 2n }],
      cursor,
    );
    expect(stale.kind).toBe("CURSOR_STALE");
    await expect(store.appendVerifiedEvents(NODE_ID, [event], await store.readCursor(NODE_ID))).rejects.toBeInstanceOf(
      ReportingStoreError,
    );
  });
});

describe("fixed-window rate limiter", () => {
  it("admits up to the ceiling per window and resets on the next window", () => {
    const limiter = new InMemoryReportingRateLimiter(60_000, 2);
    expect(limiter.consume(NODE_ID, KEY_ID, ISSUED_MS)).toBe(true);
    expect(limiter.consume(NODE_ID, KEY_ID, ISSUED_MS + 1)).toBe(true);
    expect(limiter.consume(NODE_ID, KEY_ID, ISSUED_MS + 2)).toBe(false);
    expect(limiter.consume(NODE_ID, "another-principal", ISSUED_MS + 3)).toBe(true);
    expect(limiter.consume(NODE_ID, KEY_ID, ISSUED_MS + 60_000)).toBe(true);
  });

  it("C2: clears the whole map at the tracked-principal cap instead of denying", () => {
    const limiter = new InMemoryReportingRateLimiter(60_000, 2);
    const capped = limiter as unknown as { buckets: Map<string, unknown> };
    for (let i = 0; i < 100_000; i += 1) {
      limiter.consume(NODE_ID, `flood-principal-${i}`, ISSUED_MS);
    }
    expect(capped.buckets.size).toBe(100_000);
    expect(limiter.consume(NODE_ID, "flood-principal-100000", ISSUED_MS)).toBe(true);
    expect(capped.buckets.size).toBe(1);
    expect(limiter.consume(NODE_ID, KEY_ID, ISSUED_MS)).toBe(true);
    expect(limiter.consume(NODE_ID, KEY_ID, ISSUED_MS + 1)).toBe(true);
    expect(limiter.consume(NODE_ID, KEY_ID, ISSUED_MS + 2)).toBe(false);
  });
});

describe("commitMutationWithCompletedIdempotency", () => {
  it("inserts the completed parent with the child id from persistChild", async () => {
    const store = new InMemoryReportingStore();
    const base = completionRecord("key-atomic");
    const { childRecordId: _c, ...draft } = base;
    const outcome = await store.commitMutationWithCompletedIdempotency({
      persistChild: async () => "child-from-uow",
      record: draft,
    });
    expect(outcome).toEqual({ kind: "INSERTED", childRecordId: "child-from-uow" });
    const found = await store.findCompletedIdempotency(
      base.nodeId,
      base.implementerId,
      base.routeId,
      base.idempotencyKey,
    );
    expect(found?.childRecordId).toBe("child-from-uow");
  });

  it("returns CONFLICT and rolls back staged child side effects when the key is taken", async () => {
    const store = new InMemoryReportingStore();
    const first = completionRecord("key-taken");
    await store.insertCompletedIdempotency(first);
    const base = completionRecord("key-taken");
    const { childRecordId: _c, ...draft } = base;
    const childSideEffects = new Map<string, string>();
    const outcome = await store.commitMutationWithCompletedIdempotency({
      persistChild: async (tx) => {
        expect(typeof tx.stageChildEffect).toBe("function");
        tx.stageChildEffect!(
          () => {
            childSideEffects.set("loser", "applied");
          },
          () => {
            childSideEffects.delete("loser");
          },
        );
        return "child-loser";
      },
      record: { ...draft, id: "idem-other", reportingNonceId: "nonce-other" },
    });
    expect(outcome).toEqual({ kind: "CONFLICT" });
    // Together-or-neither — child side effect must not outlive the failed parent.
    expect(childSideEffects.has("loser")).toBe(false);
    const found = await store.findCompletedIdempotency(
      first.nodeId,
      first.implementerId,
      first.routeId,
      first.idempotencyKey,
    );
    expect(found?.childRecordId).toBe(first.childRecordId);
  });

  it("keeps staged child side effects on INSERTED and undoes them when persistChild throws after staging", async () => {
    const store = new InMemoryReportingStore();
    const base = completionRecord("key-keep");
    const { childRecordId: _c, ...draft } = base;
    const effects = new Map<string, string>();
    const ok = await store.commitMutationWithCompletedIdempotency({
      persistChild: async (tx) => {
        tx.stageChildEffect!(
          () => {
            effects.set("winner", "applied");
          },
          () => {
            effects.delete("winner");
          },
        );
        return "child-winner";
      },
      record: draft,
    });
    expect(ok).toEqual({ kind: "INSERTED", childRecordId: "child-winner" });
    expect(effects.get("winner")).toBe("applied");

    const base2 = completionRecord("key-throw");
    const { childRecordId: _c2, ...draft2 } = base2;
    await expect(
      store.commitMutationWithCompletedIdempotency({
        persistChild: async (tx) => {
          tx.stageChildEffect!(
            () => {
              effects.set("doomed", "applied");
            },
            () => {
              effects.delete("doomed");
            },
          );
          throw new Error("child failed after stage");
        },
        record: draft2,
      }),
    ).rejects.toThrow(/child failed after stage/);
    expect(effects.has("doomed")).toBe(false);
    expect(effects.get("winner")).toBe("applied");
  });

  it("serializes concurrent UoWs so the second observes the first's committed parent", async () => {
    const store = new InMemoryReportingStore();
    const base = completionRecord("key-serial");
    const { childRecordId: _c, ...draft } = base;
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstEntered = false;
    const first = store.commitMutationWithCompletedIdempotency({
      persistChild: async (tx) => {
        firstEntered = true;
        tx.stageChildEffect!(
          () => {},
          () => {},
        );
        await firstGate;
        return "child-first";
      },
      record: draft,
    });
    // Yield so first reaches the gate inside the UoW mutex.
    await Promise.resolve();
    expect(firstEntered).toBe(true);
    let secondStartedPersist = false;
    const second = store.commitMutationWithCompletedIdempotency({
      persistChild: async () => {
        secondStartedPersist = true;
        return "child-second";
      },
      record: {
        ...draft,
        id: "idem-second",
        reportingNonceId: "nonce-second",
        // same idempotency key → must CONFLICT once first commits
      },
    });
    // Second must not have entered persistChild while first holds the mutex.
    await Promise.resolve();
    expect(secondStartedPersist).toBe(false);
    releaseFirst();
    expect(await first).toEqual({ kind: "INSERTED", childRecordId: "child-first" });
    expect(await second).toEqual({ kind: "CONFLICT" });
    expect(secondStartedPersist).toBe(true);
  });
});
