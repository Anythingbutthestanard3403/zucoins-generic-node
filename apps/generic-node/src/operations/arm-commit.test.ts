import { describe, expect, it } from "vitest";
import { createArmCommitHook, type ArmCommitPreopen } from "./arm-commit.js";
import {
  type ArmAuditLog,
  type ArmClock,
  type ArmCommitSession,
  type ArmOperationGateSnapshot,
  type ArmOperationState,
  type ArmRecord,
  type ArmReleasePayload,
  type ArmStore,
  type ArmWalletGate,
  type ArmWalletLockHandle,
  type ArmWalletStanding,
  type ArmT0Projection as T0Projection,
  expiresAtFromUnixSecs,
} from "@zucoins/node-core";

const FIXED = "2026-01-15T10:00:00.000Z";
const NOW_MS = Date.parse(FIXED);
const OP = "33333333-3333-4333-8333-333333333333";
const WALLET = "44444444-4444-4444-8444-444444444444";
const NODE = "11111111-1111-4111-8111-111111111111";
const IMPL = "22222222-2222-4222-8222-222222222222";
const T0: T0Projection = {
  observationId: "55555555-5555-4555-8555-555555555555",
  s0: "",
  p0: "",
  b0: "0",
};
const CODE = "exact-transfer-code-text";
const SHA = "a".repeat(64);
const EXPIRY = "2000000000";

function makePreopen(overrides?: {
  readonly expectedRowVersion?: number;
  readonly mismatchField?: ArmCommitPreopen["mismatchField"];
}): ArmCommitPreopen {
  return {
    ok: true,
    binding: {
      operationId: OP,
      nodeT0ObservationId: T0.observationId,
      consumerProjection: { s: T0.s0, p: T0.p0, b_zkz: T0.b0 },
      openedCursor: 1043n,
      expectedRowVersion: overrides?.expectedRowVersion ?? 2,
    },
    comparison: {
      nodeObservationId: T0.observationId,
      namedNodeObservationId: T0.observationId,
      nodeProjection: { s: T0.s0, p: T0.p0, b_zkz: T0.b0 },
      consumerProjection: { s: T0.s0, p: T0.p0, b_zkz: T0.b0 },
      openedCursor: 1043n,
      expectedRowVersion: overrides?.expectedRowVersion ?? 2,
      operationId: OP,
    },
    mismatchField: overrides?.mismatchField ?? null,
    reporting: {
      nodeId: NODE,
      implementerId: IMPL,
      reportingKeyId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      nonce: "99999999-9999-4999-8999-999999999999",
      rawTarget: `/v1/operations/${OP}/armed`,
      bodySha256: "b".repeat(64),
      requestPreimageText: "preimage",
      requestSignature: "sig",
      idempotencyKey: "idem-1",
    },
  };
}

class MemStore implements ArmStore {
  records: ArmRecord[] = [];
  releases = new Map<string, ArmReleasePayload>();
  async findByOperation(id: string) {
    return this.records.find((r) => r.operationId === id) ?? null;
  }
  async loadReleasedCode(id: string) {
    return this.releases.get(id) ?? null;
  }
  async tryInsert(record: ArmRecord, _s: ArmCommitSession) {
    if (this.records.some((r) => r.operationId === record.operationId)) return null;
    this.records.push(record);
    return record;
  }
}

class MemOps implements ArmOperationState {
  state = "READY";
  rowVersion = 2;
  codeStatus: "AWAITING_ARM" | "RELEASED" = "AWAITING_ARM";
  transitions = 0;
  async getState() {
    return this.state;
  }
  async getAssignedWallet() {
    return WALLET;
  }
  async getT0() {
    return T0;
  }
  async lockAndReadGate(): Promise<ArmOperationGateSnapshot> {
    return {
      state: this.state,
      rowVersion: this.rowVersion,
      expiryUnixTimeSecs: EXPIRY,
      receiverWalletId: WALLET,
      codeStatus: this.codeStatus,
      transferCode: CODE,
      transferCodeSha256: SHA,
    };
  }
  async transitionToArmed(
    _id: string,
    _s: ArmCommitSession,
    expected: number,
  ) {
    if (expected !== this.rowVersion) {
      return {
        ok: false as const,
        reason: "version_conflict" as const,
        currentRowVersion: this.rowVersion,
      };
    }
    this.codeStatus = "RELEASED";
    this.rowVersion += 1;
    this.transitions += 1;
    const release = {
      transferCode: CODE,
      transferCodeSha256: SHA,
      expiresAt: expiresAtFromUnixSecs(EXPIRY),
      rowVersion: this.rowVersion,
    };
    return { ok: true as const, release };
  }
}

class MemGate implements ArmWalletGate {
  async withWalletLocked<T>(
    _w: string,
    body: (lock: ArmWalletLockHandle) => Promise<T>,
  ): Promise<T> {
    const token = {};
    const standing: ArmWalletStanding = {
      walletId: WALLET,
      state: "PINNED",
      recoveryVerifiedAt: FIXED,
    };
    return body({
      readStanding: async () => standing,
      requireCommitSession: () => ({ kind: "memory", token }),
    });
  }
}

const clock: ArmClock = { now: () => FIXED };
const audit: ArmAuditLog = { append: async () => undefined };

describe("createArmCommitHook", () => {
  it("returns the RELEASED body + persistChild after commit", async () => {
    const store = new MemStore();
    const ops = new MemOps();
    const hook = createArmCommitHook({
      walletGate: new MemGate(),
      armStore: store,
      operationState: ops,
      auditLog: audit,
      clock,
      nowMs: () => NOW_MS,
      resolveReceiverWalletId: async () => WALLET,
      newRequestId: () => "req-1",
      armChildIdFor: () => "arm-child-1",
    });
    const result = await hook(makePreopen());
    expect(result.response.status).toBe(200);
    const body = JSON.parse(new TextDecoder().decode(result.response.bodyBytes));
    expect(body).toEqual({
      operation_id: OP,
      state: "READY",
      row_version: 3,
      code_status: "RELEASED",
      transfer_code: CODE,
      transfer_code_sha256: SHA,
      expires_at: expiresAtFromUnixSecs(EXPIRY),
    });
    expect(result.persistChild).not.toBeNull();
    expect(await result.persistChild!({} as never, "parent-id")).toBe("arm-child-1");
    expect(ops.transitions).toBe(1);
    expect(store.records.length).toBe(1);
  });

  it("maps version conflict to 409 with null persistChild", async () => {
    const hook = createArmCommitHook({
      walletGate: new MemGate(),
      armStore: new MemStore(),
      operationState: new MemOps(),
      auditLog: audit,
      clock,
      nowMs: () => NOW_MS,
      resolveReceiverWalletId: async () => WALLET,
      newRequestId: () => "req-2",
    });
    const result = await hook(makePreopen({ expectedRowVersion: 99 }));
    expect(result.response.status).toBe(409);
    const err = JSON.parse(new TextDecoder().decode(result.response.bodyBytes));
    expect(err.error.code).toBe("operation_version_conflict");
    expect(result.persistChild).toBeNull();
  });

  it("refuses code release when receiver wallet cannot be resolved", async () => {
    const hook = createArmCommitHook({
      walletGate: new MemGate(),
      armStore: new MemStore(),
      operationState: new MemOps(),
      auditLog: audit,
      clock,
      nowMs: () => NOW_MS,
      resolveReceiverWalletId: async () => null,
      newRequestId: () => "req-3",
    });
    const result = await hook(makePreopen());
    expect(result.response.status).toBe(409);
    const err = JSON.parse(new TextDecoder().decode(result.response.bodyBytes));
    expect(err.error.code).toBe("operation_not_armable");
    expect(result.persistChild).toBeNull();
  });

  it("defensive: mismatchField set still returns t0_mismatch without mutation", async () => {
    const store = new MemStore();
    const hook = createArmCommitHook({
      walletGate: new MemGate(),
      armStore: store,
      operationState: new MemOps(),
      auditLog: audit,
      clock,
      nowMs: () => NOW_MS,
      resolveReceiverWalletId: async () => WALLET,
      newRequestId: () => "req-4",
    });
    const result = await hook(makePreopen({ mismatchField: "s" }));
    expect(result.response.status).toBe(409);
    const err = JSON.parse(new TextDecoder().decode(result.response.bodyBytes));
    expect(err.error.code).toBe("t0_mismatch");
    expect(store.records.length).toBe(0);
    expect(result.persistChild).toBeNull();
  });
});
