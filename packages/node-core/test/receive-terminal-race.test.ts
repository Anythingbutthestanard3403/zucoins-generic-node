// Offline crash + verification-complete ACK terminal races for RECEIVE.
//
// Complements receive-terminal-race.pg.test.ts (real PG) and
// src/protocol/reconcile/receive.terminal-race.test.ts (oracle).
// Cases covered:
//   * second SUBMIT never occurs on timeout/malformed recovery
//   * crash at each RECEIVE durable phase boundary: one attempt, one submit
//   * REJECTED verification-complete never RELEASED
//   * lost ACK response: identical idempotency key does not re-run group-release
//
// Governing: operation flows; operations recovery.
// Fixed seed: receive-terminal-race-fault-seed.

import { beforeAll, describe, expect, it } from "vitest";

import { ready } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  crashAt,
  type CrashPoint,
} from "./crash-injection-lifecycle.ts";
import {
  buildInnerPreimage,
  createRuntime,
  KEY_SEED_BYTE,
  OPERATION_IDS,
  PAYER_SEED_BYTE,
  signWithSeed,
  type Scenario,
  type SubmitPort,
} from "./crash-injection-model.ts";
import {
  crashThenRecover,
  snapshotDurable,
  type LandingObservation,
} from "./crash-injection-recovery.ts";
import {
  AcknowledgementInsertConflict,
  clampReleaseToVerdict,
  createAcknowledgementService,
  type AckOpenMembership,
  type AckOperationFacts,
  type AcknowledgementDraft,
  type AcknowledgementInput,
  type AcknowledgementResponseBody,
  type AcknowledgementStore,
  type DurableEvidenceFact,
  type GroupReleaseFacts,
  type OperationWalletAssignment,
  type StoredAcknowledgement,
} from "../src/verification/index.ts";

const FAULT_SEED = "receive-terminal-race-fault-seed";

beforeAll(async () => {
  await ready();
});

const LANDED: LandingObservation = { kind: "LANDED_VERIFIED" };
const NOT_LANDED: LandingObservation = { kind: "NOT_LANDED_YET" };

const payerStep1Signature = (): string =>
  signWithSeed(buildInnerPreimage("RECEIVE_EXTERNAL"), PAYER_SEED_BYTE);

const freshReceive = (): Scenario => ({
  durable: {
    operations: [
      {
        operationId: OPERATION_IDS.RECEIVE_EXTERNAL,
        kind: "RECEIVE_EXTERNAL",
        status: "CREATED",
        leaseHeld: false,
        needsAttention: false,
        terminal: false,
      },
    ],
    attempts: [],
    signerAudit: [],
    externalPartials: [],
    events: [],
  },
  runtime: createRuntime("worker-receive-terminal-race", KEY_SEED_BYTE, payerStep1Signature()),
});

const countingSubmit = (): { port: SubmitPort; calls: number[] } => {
  const calls: number[] = [];
  const port: SubmitPort = (request) => {
    calls.push(request.attemptNo);
    return { kind: "ACCEPTED", gatewayRef: "gw-ref-receive-terminal-race" };
  };
  return { port, calls };
};

const RECEIVE_CRASH_POINTS: CrashPoint[] = [
  "AFTER_CREATE",
  "AFTER_STEP2_PREIMAGE",
  "AFTER_SIGN_STEP2",
  "AFTER_SUBMIT",
];

describe("RECEIVE_EXTERNAL crash phase boundaries", () => {
  it.each(RECEIVE_CRASH_POINTS)(
    "%s crash + recover to land: exactly one SUBMIT and single attempt",
    (crashPoint) => {
      const { port, calls } = countingSubmit();
      const crashed = crashAt(freshReceive(), port, crashPoint);
      const { scenario, outcome } = crashThenRecover(crashed, port, LANDED);
      expect(outcome.landed).toBe(true);
      expect(calls).toHaveLength(1);
      const snap = snapshotDurable(scenario.durable);
      expect(snap.attempts).toBe(1);
      expect(snap.operations).toBe(1);
    },
  );

  it("AFTER_SUBMIT + timeout/malformed (NOT_LANDED): never a second SUBMIT; lease retained", () => {
    const { port, calls } = countingSubmit();
    const crashed = crashAt(freshReceive(), port, "AFTER_SUBMIT");
    expect(calls).toHaveLength(1);
    const parked = crashThenRecover(crashed, port, NOT_LANDED);
    expect(parked.outcome.landed).toBe(false);
    expect(calls).toHaveLength(1);
    const snap = snapshotDurable(parked.scenario.durable);
    expect(snap.leaseHeld).toBe(true);
    expect(snap.needsAttention).toBe(true);
    expect(snap.attempts).toBe(1);
  });

  it("RECEIVE never creates a later attempt across every crash point", () => {
    for (const crashPoint of RECEIVE_CRASH_POINTS) {
      const { port } = countingSubmit();
      const crashed = crashAt(freshReceive(), port, crashPoint);
      const { scenario } = crashThenRecover(crashed, port, LANDED);
      expect(scenario.durable.attempts).toHaveLength(1);
      expect(scenario.durable.attempts[0]!.attemptNo).toBe(1);
    }
  });
});

// ── REJECTED / lost ACK ──────────────────────────────────────────────────────

const RECEIVE_OP = "28100000-0000-4000-8000-00000000aa01";
const GROUP = "28100000-0000-4000-8000-00000000bb01";
const NODE = "28100000-0000-4000-8000-00000000cc01";
const IMPLEMENTER = "28100000-0000-4000-8000-00000000dd01";
const WALLET = "28100000-0000-4000-8000-00000000ee01";
const PUB = `${"A".repeat(43)}=`;

type Tx = { readonly label: string };

function harness() {
  const rows: AcknowledgementDraft[] = [];
  const frozenById = new Map<string, AcknowledgementResponseBody>();
  const preimages = new Map<string, string>();
  const signatures = new Map<string, string>();
  const completed = new Set<string>();
  let releaseEvals = 0;
  const assignment: OperationWalletAssignment = {
    role: "RECEIVER",
    walletId: WALLET,
    walletPublicKey: PUB,
  };

  const store: AcknowledgementStore<Tx> = {
    async readOperation(): Promise<AckOperationFacts | null> {
      return {
        operationId: RECEIVE_OP,
        nodeId: NODE,
        implementerId: IMPLEMENTER,
        kind: "RECEIVE_EXTERNAL",
        rowVersion: 1,
        leaseGroupId: GROUP,
        expectedWallets: [assignment],
      };
    },
    async findAcknowledgement(_tx, operationId): Promise<StoredAcknowledgement | null> {
      const row = rows.find((r) => r.operationId === operationId);
      if (row === undefined) return null;
      const evidenceFacts: DurableEvidenceFact[] = row.walletEvidence.map((e) => ({
        role: e.role as DurableEvidenceFact["role"],
        walletId: e.walletId,
        walletPublicKey: e.walletPublicKey,
      }));
      return {
        id: row.id,
        operationId: row.operationId,
        nodeId: row.nodeId,
        implementerId: row.implementerId,
        consumedCursor: row.consumedCursor,
        verdict: row.verdict,
        evidenceSetSha256: row.evidenceSetSha256,
        requestBodySha256: row.requestBodySha256,
        rawTarget: row.rawTarget,
        requestPreimageText: preimages.get(row.id) ?? "",
        requestSignature: signatures.get(row.id) ?? "",
        acknowledgedAt: row.acknowledgedAt,
        evidenceRoles: evidenceFacts.map((e) => e.role),
        evidence: evidenceFacts,
        frozenResponseBody: frozenById.get(row.id) ?? null,
      };
    },
    async insertAcknowledgement(_tx, draft): Promise<void> {
      if (rows.some((r) => r.operationId === draft.operationId)) {
        throw new AcknowledgementInsertConflict();
      }
      rows.push(draft);
    },
    async completeGroupOperation(_tx, _g, operationId): Promise<void> {
      completed.add(operationId);
    },
    async readGroupReleaseFacts(): Promise<GroupReleaseFacts> {
      releaseEvals += 1;
      const operations = rows.map((row) => {
        const evidenceFacts: DurableEvidenceFact[] = row.walletEvidence.map((e) => ({
          role: e.role as DurableEvidenceFact["role"],
          walletId: e.walletId,
          walletPublicKey: e.walletPublicKey,
        }));
        return {
          operationId: row.operationId,
          kind: "RECEIVE_EXTERNAL" as const,
          verdict: row.verdict,
          evidenceRoles: evidenceFacts.map((e) => e.role),
          evidence: evidenceFacts,
          expectedWallets: [assignment],
          completed: completed.has(row.operationId),
        };
      });
      return { childDisposition: "NONE", operations };
    },
    async readOpenMemberships(): Promise<readonly AckOpenMembership[]> {
      return [
        {
          membershipId: "28100000-0000-4000-8000-00000000ff01",
          walletId: WALLET,
          leaseEpoch: 1n,
          leaseGroupId: GROUP,
          operationId: RECEIVE_OP,
        },
      ];
    },
  };

  let seq = 0;
  const service = createAcknowledgementService<Tx>({
    store,
    newAcknowledgementId: () => {
      seq += 1;
      return `28100000-0000-4000-8000-00000000a${String(seq).padStart(3, "0")}`;
    },
    nowIso: () => "2026-07-28T00:00:00.000Z",
  });

  const acknowledge = async (input: AcknowledgementInput) => {
    const before = rows.length;
    const outcome = await service.acknowledge({ label: "tx" }, RECEIVE_OP, input);
    if (rows.length > before) {
      const written = rows[rows.length - 1]!;
      preimages.set(written.id, input.requestPreimageText);
      signatures.set(written.id, input.requestSignature);
      frozenById.set(written.id, outcome.body);
    }
    return outcome;
  };

  return {
    acknowledge,
    get releaseEvals() {
      return releaseEvals;
    },
  };
}

const baseInput = (verdict: "VERIFIED" | "REJECTED" | "INDETERMINATE"): AcknowledgementInput => ({
  expectedRowVersion: 1,
  consumedCursor: 1n,
  verdict,
  walletEvidence: [
    {
      role: "RECEIVER",
      walletId: WALLET,
      walletPublicKey: PUB,
      t0: { observationId: "28100000-0000-4000-8000-00000000t001" },
      terminal: { observationId: "28100000-0000-4000-8000-00000000t002" },
    },
  ],
  nodeId: NODE,
  implementerId: IMPLEMENTER,
  reportingNonceId: "28100000-0000-4000-8000-00000000n001",
  mutationIdempotencyId: "28100000-0000-4000-8000-00000000i001",
  rawTarget: `/v1/operations/${RECEIVE_OP}/verification-complete`,
  requestBodySha256: "ab".repeat(32),
  requestPreimageText: `{"seed":"${FAULT_SEED}","purpose":"zp-report-request-v1"}`,
  requestSignature: `${"B".repeat(86)}==`,
});

describe("verification-complete ACK terminal races", () => {
  it("REJECTED verdict clamp never yields RELEASED", () => {
    expect(clampReleaseToVerdict("REJECTED", "RELEASED")).toBe("PINNED_FOR_ATTENTION");
    expect(clampReleaseToVerdict("INDETERMINATE", "RELEASED")).toBe("PINNED_FOR_ATTENTION");
  });

  it("REJECTED acknowledgement service outcome is never RELEASED", async () => {
    const h = harness();
    const outcome = await h.acknowledge(baseInput("REJECTED"));
    expect(outcome.body.verdict).toBe("REJECTED");
    expect(outcome.body.lease_release_status).not.toBe("RELEASED");
    expect(outcome.idempotentReplay).toBe(false);
  });

  it("lost/dropped ACK response: identical replay does not re-run group-release evaluation", async () => {
    const h = harness();
    const input = baseInput("INDETERMINATE");
    const first = await h.acknowledge(input);
    expect(first.idempotentReplay).toBe(false);
    const evalsAfterFirst = h.releaseEvals;
    expect(evalsAfterFirst).toBeGreaterThan(0);

    const second = await h.acknowledge(input);
    expect(second.idempotentReplay).toBe(true);
    expect(second.body).toEqual(first.body);
    expect(h.releaseEvals).toBe(evalsAfterFirst);
  });
});

describe("harness reproducibility", () => {
  it("pins the shared fixed seed constant", () => {
    expect(FAULT_SEED).toBe("receive-terminal-race-fault-seed");
  });
});
