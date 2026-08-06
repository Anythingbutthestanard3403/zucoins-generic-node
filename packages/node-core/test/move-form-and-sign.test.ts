// MOVE_INTERNAL dual signing under leases.
//
// The byte assertions below are against test/fixtures/splitchain-v2-byte-evidence.ts — bytes
// captured offline from wallet PWA 199.11, not from this code. WALLET_STEP_2_PREIMAGE_TEXT and
// WALLET_SETTLED_TRANSACTION_TEXT are what the wallet actually signs, so reproducing them from
// WALLET_INNER_PREIMAGE_TEXT + the two captured signatures is an independent byte-exactness
// proof rather than a round trip through our own serializer.
//
// The SQL fake models the one-way ladder that data-model's CHECKs enforce, so the ordering
// properties are testable without a server; the same properties are re-proved against real
// PostgreSQL CHECK constraints in move-form-and-sign.pg.test.ts.

import { describe, expect, it, vi } from "vitest";

import {
  MoveHaltGateMissingError,
  MoveSigningStateError,
  isDurableMovePreimage,
  readDurableMovePreimage,
  resumeMoveStep2FromPersistedStep1,
  signDurableMovePreimage,
  signMoveStepsUnderLeases,
  type DurableMovePreimage,
  type MoveHeldLease,
} from "../src/core/move-form-and-sign.ts";
import {
  MovePreimageDriftError,
  buildMoveCompletedTransactionText,
  buildMoveStep2PreimageText,
  hashMovePreimageText,
} from "../src/core/move-step2.ts";
import {
  type ActiveLeaseRecord,
  type SignerAuditEntry,
  type SignerBoundaryDeps,
} from "../src/core/signer-boundary.ts";
import type { SqlQueryFn } from "../src/core/sql-query-fn.ts";
import { OperatorHaltError } from "../src/operator/halt.ts";
import {
  WALLET_INNER_PREIMAGE_SHA256,
  WALLET_INNER_PREIMAGE_TEXT,
  WALLET_SETTLED_TRANSACTION_SHA256,
  WALLET_SETTLED_TRANSACTION_TEXT,
  WALLET_STEP_1_SIGNATURE,
  WALLET_STEP_2_PREIMAGE_SHA256,
  WALLET_STEP_2_PREIMAGE_TEXT,
  WALLET_STEP_2_SIGNATURE,
} from "./fixtures/splitchain-v2-byte-evidence.ts";

const OPERATION = "11111111-1111-4111-8111-111111111111";
const SOURCE_WALLET = "22222222-2222-4222-8222-222222222222";
const DESTINATION_WALLET = "33333333-3333-4333-8333-333333333333";

const SOURCE_LEASE: MoveHeldLease = { walletId: SOURCE_WALLET, leaseEpoch: 7n };
const DESTINATION_LEASE: MoveHeldLease = { walletId: DESTINATION_WALLET, leaseEpoch: 9n };

// ── attempt-row fake: the data-model one-way ladder, without a server ─────────────────────────────

type AttemptRow = Record<string, string | null>;

/**
 * Models exactly what advanceAttemptPhase's WHERE clause asks of the database: the row must be
 * at the immediately prior phase and every target column must still be NULL. It does not parse
 * SQL beyond the target phase and the SET column list, because those are the only two things
 * the statement varies.
 */
function makeAttemptStore(initial: AttemptRow | null) {
  const state: { row: AttemptRow | null } = { row: initial === null ? null : { ...initial } };
  const statements: string[] = [];

  const query: SqlQueryFn = async (text, values) => {
    statements.push(text);
    if (text.startsWith("SELECT")) {
      return state.row === null ? [] : [{ ...state.row }];
    }
    const setClause = /SET ([\s\S]*?)\s+WHERE /.exec(text)?.[1];
    const toPhase = /attempt_phase = '([A-Z0-9_]+)'/.exec(setClause ?? "")?.[1];
    if (setClause === undefined || toPhase === undefined) {
      throw new Error(`unexpected statement: ${text}`);
    }
    // Only the SET list — the WHERE clause names columns too, and treating those as targets
    // would make every advance look like an overwrite.
    const columns = [...setClause.matchAll(/([a-z0-9_]+) = \$\d+/g)].map((m) => m[1]!);
    const row = state.row;
    if (row === null) return [];
    // The one-way guard: prior phase must match and every target column must still be NULL.
    if (row.attempt_phase !== values[1]) return [];
    if (columns.some((column) => row[column] !== null)) return [];
    columns.forEach((column, index) => {
      row[column] = String(values[index + 2]);
    });
    row.attempt_phase = toPhase;
    return [{ attempt_phase: toPhase }];
  };

  return { query, state, statements };
}

const attemptAtInnerPersisted = (
  overrides: Partial<AttemptRow> = {},
): AttemptRow => ({
  attempt_phase: "INNER_PREIMAGE_PERSISTED",
  inner_preimage_text: WALLET_INNER_PREIMAGE_TEXT,
  inner_sha256: WALLET_INNER_PREIMAGE_SHA256,
  step_1_signature: null,
  step_2_preimage_text: null,
  step_2_preimage_sha256: null,
  step_2_signature: null,
  completed_transaction_text: null,
  completed_transaction_sha256: null,
  ...overrides,
});

// ── signer fake ──────────────────────────────────────────────────────────────────────────────

interface SignerFakeOptions {
  /** Lease returned per wallet id. `undefined` for a wallet means "no lease row". */
  readonly leases: Readonly<Record<string, ActiveLeaseRecord | undefined>>;
  /** Signatures returned in call order. */
  readonly signatures?: readonly string[];
}

function makeSigner(options: SignerFakeOptions) {
  const audit: SignerAuditEntry[] = [];
  const signatures = options.signatures ?? [WALLET_STEP_1_SIGNATURE, WALLET_STEP_2_SIGNATURE];
  const signed: Array<{ walletId: string; preimage: string }> = [];
  const vaultSign = vi.fn(async (walletId: string, bytes: Uint8Array) => {
    signed.push({ walletId, preimage: new TextDecoder().decode(bytes) });
    const next = signatures[signed.length - 1];
    if (next === undefined) throw new Error("signer fake ran out of scripted signatures");
    return next;
  });
  const deps: SignerBoundaryDeps & {
    assertHaltAdmitsKind: (kind: string) => void;
  } = {
    leadership: { held: true },
    leaseReader: {
      readActiveLease: async (walletId: string) => options.leases[walletId] ?? null,
    },
    vaultSigner: { sign: vaultSign },
    auditLog: {
      append: async (entry) => {
        audit.push(entry);
      },
    },
    now: () => "2026-07-27T00:00:00.000Z",
    assertMoneyAdmitted: () => {},
    assertCanOperate: () => {},
    assertWalletMaySign: async () => {},
    assertHaltAdmitsKind: () => {},
  };
  return { deps, audit, vaultSign, signed };
}

const lease = (
  walletId: string,
  role: ActiveLeaseRecord["role"],
  epoch: bigint,
  overrides: Partial<ActiveLeaseRecord> = {},
): ActiveLeaseRecord => ({
  walletId,
  operationId: OPERATION,
  epoch,
  role,
  lifecycle: "ACTIVE",
  ...overrides,
});

const bothLeasesHeld = {
  [SOURCE_WALLET]: lease(SOURCE_WALLET, "MOVE_SOURCE", 7n),
  [DESTINATION_WALLET]: lease(DESTINATION_WALLET, "MOVE_DESTINATION", 9n),
};

// ─────────────────────────────────────────────────────────────────────────────────────────────

describe("MOVE first formation is halt-gated", () => {
  it("signMoveStepsUnderLeases throws OperatorHaltError before vault under engaged halt", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const signer = makeSigner({ leases: bothLeasesHeld });
    signer.deps.assertHaltAdmitsKind = () => {
      throw new OperatorHaltError();
    };

    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        signerDeps: signer.deps,
      }),
    ).rejects.toBeInstanceOf(OperatorHaltError);

    expect(signer.vaultSign).not.toHaveBeenCalled();
    expect(store.state.row?.attempt_phase).toBe("INNER_PREIMAGE_PERSISTED");
  });

  it("signMoveStepsUnderLeases fail-closes when assertHaltAdmitsKind is missing", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const signer = makeSigner({ leases: bothLeasesHeld });
    const { assertHaltAdmitsKind: _omit, ...rest } = signer.deps;
    void _omit;

    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        // @ts-expect-error prove runtime fail-closed without the kind gate
        signerDeps: rest,
      }),
    ).rejects.toBeInstanceOf(MoveHaltGateMissingError);
    expect(signer.vaultSign).not.toHaveBeenCalled();
  });

  it("resumeMoveStep2FromPersistedStep1 stays permeable under halt (in-flight)", async () => {
    const crashed = makeAttemptStore(
      attemptAtInnerPersisted({
        attempt_phase: "STEP1_SIGNATURE_PERSISTED",
        step_1_signature: WALLET_STEP_1_SIGNATURE,
      }),
    );
    const resumeSigner = makeSigner({
      leases: bothLeasesHeld,
      signatures: [WALLET_STEP_2_SIGNATURE],
    });
    resumeSigner.deps.assertHaltAdmitsKind = () => {
      throw new OperatorHaltError();
    };

    const resumed = await resumeMoveStep2FromPersistedStep1({
      operationId: OPERATION,
      destinationLease: DESTINATION_LEASE,
      query: crashed.query,
      signerDeps: resumeSigner.deps,
    });
    expect(resumed.step2Signature).toBe(WALLET_STEP_2_SIGNATURE);
    expect(resumeSigner.vaultSign).toHaveBeenCalledOnce();
  });
});

describe("operation-flow steps 3–8 — MOVE_INTERNAL signs both steps under leases", () => {
  it("advances the exact phase ladder and signs once per wallet role", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const signer = makeSigner({ leases: bothLeasesHeld });

    const result = await signMoveStepsUnderLeases({
      operationId: OPERATION,
      leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
      query: store.query,
      signerDeps: signer.deps,
    });

    expect(store.state.row?.attempt_phase).toBe("STEP2_SIGNATURE_PERSISTED");
    // Exactly two signer calls, source first, each over the preimage its step owns.
    expect(signer.signed.map((call) => call.walletId)).toEqual([
      SOURCE_WALLET,
      DESTINATION_WALLET,
    ]);
    expect(signer.signed[0]!.preimage).toBe(WALLET_INNER_PREIMAGE_TEXT);
    expect(signer.signed[1]!.preimage).toBe(WALLET_STEP_2_PREIMAGE_TEXT);
    // The audit trail carries the step-scoped purposes and the held epochs.
    expect(audited(signer.audit)).toEqual([
      { walletId: SOURCE_WALLET, purpose: "SPLITCHAIN_STEP_1", leaseEpoch: 7n, outcome: "SIGNED" },
      {
        walletId: DESTINATION_WALLET,
        purpose: "SPLITCHAIN_STEP_2",
        leaseEpoch: 9n,
        outcome: "SIGNED",
      },
    ]);
    expect(result.step1Signature).toBe(WALLET_STEP_1_SIGNATURE);
    expect(result.step2Signature).toBe(WALLET_STEP_2_SIGNATURE);
  });

  it("persists bytes identical to the offline wallet capture (the byte-exact signing rule)", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const signer = makeSigner({ leases: bothLeasesHeld });

    const result = await signMoveStepsUnderLeases({
      operationId: OPERATION,
      leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
      query: store.query,
      signerDeps: signer.deps,
    });

    // Byte equality against the wallet's own step-2 preimage and settled transaction.
    expect(result.step2PreimageText).toBe(WALLET_STEP_2_PREIMAGE_TEXT);
    expect(result.completedTransactionText).toBe(WALLET_SETTLED_TRANSACTION_TEXT);
    expect(result.step2PreimageSha256).toBe(WALLET_STEP_2_PREIMAGE_SHA256);
    expect(result.completedTransactionSha256).toBe(WALLET_SETTLED_TRANSACTION_SHA256);
    // And the same bytes are what landed in the row, not just what was returned.
    expect(store.state.row?.step_2_preimage_text).toBe(WALLET_STEP_2_PREIMAGE_TEXT);
    expect(store.state.row?.completed_transaction_text).toBe(WALLET_SETTLED_TRANSACTION_TEXT);
  });

  it("keeps the step-2 preimage to exactly two keys in sequence (A.1.2), not the settled shape", () => {
    const step2 = buildMoveStep2PreimageText(WALLET_INNER_PREIMAGE_TEXT, WALLET_STEP_1_SIGNATURE);
    expect(Object.keys(JSON.parse(step2) as object)).toEqual(["inner", "step_1_signature"]);
    expect(
      Object.keys(
        JSON.parse(buildMoveCompletedTransactionText(step2, WALLET_STEP_2_SIGNATURE)) as object,
      ),
    ).toEqual(["inner", "step_1_signature", "step_2_signature"]);
  });
});

describe("step 5 — persisted-inner round-trip guard", () => {
  it("rejects a persisted inner whose JSON.stringify round trip is not byte-identical", async () => {
    // Same fields, different key order: a jsonb-style re-emission of the same object.
    const reordered = JSON.stringify({
      version: "2",
      type: "unique_combinable",
      ...(JSON.parse(WALLET_INNER_PREIMAGE_TEXT) as Record<string, unknown>),
    });
    const drifted = ` ${reordered}`; // leading space: stringify(parse(x)) !== x
    const store = makeAttemptStore(
      attemptAtInnerPersisted({
        inner_preimage_text: drifted,
        inner_sha256: hashMovePreimageText(drifted),
      }),
    );
    const signer = makeSigner({ leases: bothLeasesHeld });

    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        signerDeps: signer.deps,
      }),
    ).rejects.toBeInstanceOf(MovePreimageDriftError);

    // The guard is at step 5, so step 1 is already durable — but nothing step-2 exists.
    expect(store.state.row?.attempt_phase).toBe("STEP1_SIGNATURE_PERSISTED");
    expect(store.state.row?.step_2_preimage_text).toBeNull();
    expect(signer.vaultSign).toHaveBeenCalledTimes(1);
  });

  it("rejects a persisted inner carrying \\u escapes JSON.stringify would emit raw (A.9 #8)", () => {
    // The two texts denote the same object; only the escaping differs. A signature over one is
    // not a signature over the other, so the round trip must refuse to build on it.
    const escaped = '{"message":"caf\\u00e9"}';
    expect(JSON.stringify(JSON.parse(escaped))).not.toBe(escaped);
    expect(() => buildMoveStep2PreimageText(escaped, WALLET_STEP_1_SIGNATURE)).toThrow(
      MovePreimageDriftError,
    );
  });

  it("catches an NFC→NFD substitution of the persisted text at the digest gate, not the round trip", async () => {
    // A JSON round trip preserves a decomposed string verbatim, so the step-5 guard alone would
    // not see this. The defence is readDurableMovePreimage recomputing SHA-256 over the bytes
    // the column actually returned and comparing it to the digest frozen at formation (A.9 #9).
    const nfc = JSON.stringify({ message: "café" });
    const nfd = nfc.normalize("NFD");
    expect(nfd).not.toBe(nfc);
    // The round trip is blind to it: parse/stringify hands the decomposed form straight back.
    expect(JSON.stringify(JSON.parse(nfd))).toBe(nfd);
    // The digest frozen at formation was taken over the composed bytes; the column now holds
    // the decomposed ones.
    const store = makeAttemptStore(
      attemptAtInnerPersisted({
        inner_preimage_text: nfd,
        inner_sha256: hashMovePreimageText(nfc),
      }),
    );
    const signer = makeSigner({ leases: bothLeasesHeld });
    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        signerDeps: signer.deps,
      }),
    ).rejects.toMatchObject({ code: "PERSISTED_DIGEST_MISMATCH" });
    expect(signer.vaultSign).not.toHaveBeenCalled();
  });

  it("accepts the untouched persisted inner", () => {
    expect(() =>
      buildMoveStep2PreimageText(WALLET_INNER_PREIMAGE_TEXT, WALLET_STEP_1_SIGNATURE),
    ).not.toThrow();
  });
});

describe("custody — the lease capability, not key possession, authorizes each signature", () => {
  it("refuses step 2 when the destination lease is lost between the steps", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const signer = makeSigner({
      leases: {
        [SOURCE_WALLET]: lease(SOURCE_WALLET, "MOVE_SOURCE", 7n),
        [DESTINATION_WALLET]: lease(DESTINATION_WALLET, "MOVE_DESTINATION", 9n, {
          lifecycle: "RELEASED",
        }),
      },
    });

    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        signerDeps: signer.deps,
      }),
    ).rejects.toMatchObject({ name: "SignerBoundaryError", code: "LEASE_RELEASED" });

    // Step-2 preimage is durable (it commits before the signer call), the signature is not.
    expect(store.state.row?.attempt_phase).toBe("STEP2_PREIMAGE_PERSISTED");
    expect(store.state.row?.step_2_signature).toBeNull();
    expect(store.state.row?.completed_transaction_text).toBeNull();
    expect(signer.vaultSign).toHaveBeenCalledTimes(1);
  });

  it("refuses step 2 when the destination lease epoch has moved on", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const signer = makeSigner({
      leases: {
        [SOURCE_WALLET]: lease(SOURCE_WALLET, "MOVE_SOURCE", 7n),
        [DESTINATION_WALLET]: lease(DESTINATION_WALLET, "MOVE_DESTINATION", 11n),
      },
    });

    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        signerDeps: signer.deps,
      }),
    ).rejects.toMatchObject({ name: "SignerBoundaryError", code: "EPOCH_MISMATCH" });
    expect(store.state.row?.step_2_signature).toBeNull();
  });

  it("refuses step 2 when no lease row exists for the destination wallet at all", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const signer = makeSigner({
      leases: { [SOURCE_WALLET]: lease(SOURCE_WALLET, "MOVE_SOURCE", 7n) },
    });

    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        signerDeps: signer.deps,
      }),
    ).rejects.toMatchObject({ name: "SignerBoundaryError", code: "NO_LEASE" });
    expect(store.state.row?.step_2_signature).toBeNull();
  });

  it("refuses a lease held for the other side of the move (role is step-scoped)", async () => {
    // MOVE_DESTINATION may not originate value: it is refused for step 1 …
    const forStep1 = makeSigner({
      leases: { [SOURCE_WALLET]: lease(SOURCE_WALLET, "MOVE_DESTINATION", 7n) },
    });
    const store1 = makeAttemptStore(attemptAtInnerPersisted());
    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store1.query,
        signerDeps: forStep1.deps,
      }),
    ).rejects.toMatchObject({ name: "SignerBoundaryError", code: "ROLE_NOT_PERMITTED" });
    expect(forStep1.vaultSign).not.toHaveBeenCalled();

    // … and MOVE_SOURCE may not receive it: it is refused for step 2.
    const forStep2 = makeSigner({
      leases: {
        [SOURCE_WALLET]: lease(SOURCE_WALLET, "MOVE_SOURCE", 7n),
        [DESTINATION_WALLET]: lease(DESTINATION_WALLET, "MOVE_SOURCE", 9n),
      },
    });
    const store2 = makeAttemptStore(attemptAtInnerPersisted());
    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store2.query,
        signerDeps: forStep2.deps,
      }),
    ).rejects.toMatchObject({ name: "SignerBoundaryError", code: "ROLE_NOT_PERMITTED" });
    expect(store2.state.row?.step_2_signature).toBeNull();
  });

  it("refuses to sign at all when the node does not hold signer leadership", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const signer = makeSigner({ leases: bothLeasesHeld });
    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        signerDeps: { ...signer.deps, leadership: { held: false, reason: "lock lost" } },
      }),
    ).rejects.toMatchObject({ name: "NotSignerLeaderError" });
    expect(signer.vaultSign).not.toHaveBeenCalled();
    expect(store.state.row?.step_1_signature).toBeNull();
  });
});

describe("operation-flow — a signer only ever sees an already-persisted preimage", () => {
  it("refuses to sign when no attempt row is durable yet", async () => {
    const store = makeAttemptStore(null);
    const signer = makeSigner({ leases: bothLeasesHeld });
    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        signerDeps: signer.deps,
      }),
    ).rejects.toMatchObject({ name: "MoveSigningStateError", code: "ATTEMPT_NOT_FOUND" });
    expect(signer.vaultSign).not.toHaveBeenCalled();
  });

  it("refuses to sign step 1 for an attempt that is not at INNER_PREIMAGE_PERSISTED", async () => {
    const store = makeAttemptStore(
      attemptAtInnerPersisted({
        attempt_phase: "STEP1_SIGNATURE_PERSISTED",
        step_1_signature: WALLET_STEP_1_SIGNATURE,
      }),
    );
    const signer = makeSigner({ leases: bothLeasesHeld });
    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        signerDeps: signer.deps,
      }),
    ).rejects.toMatchObject({ name: "MoveSigningStateError", code: "WRONG_ATTEMPT_PHASE" });
    expect(signer.vaultSign).not.toHaveBeenCalled();
  });

  it("refuses a persisted preimage whose stored digest disagrees with its own bytes", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted({ inner_sha256: "0".repeat(64) }));
    await expect(
      readDurableMovePreimage(store.query, OPERATION, "STEP_1", SOURCE_LEASE),
    ).rejects.toBeInstanceOf(MoveSigningStateError);
  });

  it("brands only what a committed row produced", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const fromRow = await readDurableMovePreimage(store.query, OPERATION, "STEP_1", SOURCE_LEASE);
    expect(isDurableMovePreimage(fromRow)).toBe(true);

    const handMade = {
      operationId: OPERATION,
      walletId: SOURCE_WALLET,
      leaseEpoch: 7n,
      purpose: "SPLITCHAIN_STEP_1" as const,
      preimageText: WALLET_INNER_PREIMAGE_TEXT,
      preimageSha256: WALLET_INNER_PREIMAGE_SHA256,
    };
    expect(isDurableMovePreimage(handMade)).toBe(false);

    // …and the signer refuses it even when a cast smuggles it past the compiler.
    const signer = makeSigner({ leases: bothLeasesHeld });
    expect(() =>
      signDurableMovePreimage(handMade as unknown as DurableMovePreimage, signer.deps),
    ).toThrow(MoveSigningStateError);
    expect(signer.vaultSign).not.toHaveBeenCalled();
  });
});

describe("data-model / the never-blind-retry rule — one attempt, no overwrite, no second signature", () => {
  it("refuses a replayed ceremony on an already-signed attempt", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const first = makeSigner({ leases: bothLeasesHeld });
    await signMoveStepsUnderLeases({
      operationId: OPERATION,
      leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
      query: store.query,
      signerDeps: first.deps,
    });

    const replay = makeSigner({ leases: bothLeasesHeld });
    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query: store.query,
        signerDeps: replay.deps,
      }),
    ).rejects.toMatchObject({ name: "MoveSigningStateError", code: "WRONG_ATTEMPT_PHASE" });
    expect(replay.vaultSign).not.toHaveBeenCalled();
    expect(store.state.row?.step_1_signature).toBe(WALLET_STEP_1_SIGNATURE);
    expect(store.state.row?.step_2_signature).toBe(WALLET_STEP_2_SIGNATURE);
  });

  it("refuses a move whose source and destination are the same wallet before any read", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const signer = makeSigner({ leases: bothLeasesHeld });
    await expect(
      signMoveStepsUnderLeases({
        operationId: OPERATION,
        leases: { source: SOURCE_LEASE, destination: { ...SOURCE_LEASE } },
        query: store.query,
        signerDeps: signer.deps,
      }),
    ).rejects.toMatchObject({ name: "MoveSigningStateError", code: "SAME_WALLET_BOTH_STEPS" });
    expect(store.statements).toHaveLength(0);
  });
});

describe("crash between step-1 signature and step-2 preimage — resume without drift", () => {
  it("re-derives a step-2 preimage byte-identical to the uninterrupted build", async () => {
    // Uninterrupted run, for the reference bytes.
    const straight = makeAttemptStore(attemptAtInnerPersisted());
    const reference = await signMoveStepsUnderLeases({
      operationId: OPERATION,
      leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
      query: straight.query,
      signerDeps: makeSigner({ leases: bothLeasesHeld }).deps,
    });

    // Crashed run: the row is durable at STEP1_SIGNATURE_PERSISTED and nothing else exists.
    const crashed = makeAttemptStore(
      attemptAtInnerPersisted({
        attempt_phase: "STEP1_SIGNATURE_PERSISTED",
        step_1_signature: WALLET_STEP_1_SIGNATURE,
      }),
    );
    const resumeSigner = makeSigner({
      leases: bothLeasesHeld,
      signatures: [WALLET_STEP_2_SIGNATURE],
    });
    const resumed = await resumeMoveStep2FromPersistedStep1({
      operationId: OPERATION,
      destinationLease: DESTINATION_LEASE,
      query: crashed.query,
      signerDeps: resumeSigner.deps,
    });

    expect(resumed.step2PreimageText).toBe(reference.step2PreimageText);
    expect(resumed.completedTransactionText).toBe(reference.completedTransactionText);
    expect(resumed.step2PreimageSha256).toBe(reference.step2PreimageSha256);
    // Step 1 was never re-signed: the resume signs exactly once, as the destination.
    expect(resumeSigner.signed.map((call) => call.walletId)).toEqual([DESTINATION_WALLET]);
    expect(crashed.state.row?.attempt_phase).toBe("STEP2_SIGNATURE_PERSISTED");
  });

  it("refuses to resume an attempt that is not at STEP1_SIGNATURE_PERSISTED", async () => {
    const store = makeAttemptStore(attemptAtInnerPersisted());
    const signer = makeSigner({ leases: bothLeasesHeld });
    await expect(
      resumeMoveStep2FromPersistedStep1({
        operationId: OPERATION,
        destinationLease: DESTINATION_LEASE,
        query: store.query,
        signerDeps: signer.deps,
      }),
    ).rejects.toMatchObject({ name: "MoveSigningStateError", code: "WRONG_ATTEMPT_PHASE" });
    expect(signer.vaultSign).not.toHaveBeenCalled();
  });
});

function audited(entries: readonly SignerAuditEntry[]) {
  return entries.map((entry) => ({
    walletId: entry.walletId,
    purpose: entry.purpose,
    leaseEpoch: entry.leaseEpoch,
    outcome: entry.outcome,
  }));
}

describe("MOVE signature advances carry AttemptLeaseGuard", () => {
  it("STEP1 and STEP2 signature advances lock the lease row under FOR SHARE", async () => {
    const store = makeAttemptStore({
      attempt_phase: "INNER_PREIMAGE_PERSISTED",
      inner_preimage_text: WALLET_INNER_PREIMAGE_TEXT,
      inner_sha256: WALLET_INNER_PREIMAGE_SHA256,
      step_1_signature: null,
      step_2_preimage_text: null,
      step_2_preimage_sha256: null,
      step_2_signature: null,
      completed_transaction_text: null,
      completed_transaction_sha256: null,
    });
    await signMoveStepsUnderLeases({
      operationId: OPERATION,
      leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
      query: store.query,
      signerDeps: makeSigner({ leases: bothLeasesHeld }).deps,
    });
    // Two signature-bearing advances (step-1 + step-2); preimage advance is unguarded.
    const guarded = store.statements.filter((s) => s.includes("FOR SHARE"));
    expect(guarded).toHaveLength(2);
    for (const statement of guarded) {
      expect(statement).toContain("wallet_active_leases");
      expect(statement).toContain("AND EXISTS (SELECT 1 FROM held_lease)");
    }
    // The preimage advance must remain unguarded — it signs nothing.
    const preimageAdvance = store.statements.find((s) =>
      s.includes("STEP2_PREIMAGE_PERSISTED"),
    );
    expect(preimageAdvance).toBeDefined();
    expect(preimageAdvance).not.toContain("FOR SHARE");
  });
});
