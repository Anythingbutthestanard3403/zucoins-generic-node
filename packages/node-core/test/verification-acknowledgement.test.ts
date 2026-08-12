// The verification-complete decision layer, without a database.
//
// The cases here are the acceptance criteria that are pure logic. The runtime half —
// the same predicate over real rows, real constraints, and a real conflicting replay — is
// verification-acknowledgement.pg.test.ts.
//
// Governing rules: the group-release predicate; the acknowledgement + evidence tables and
// their binding prose; the lease group tables; the two database test obligations; and the
// `lease_release_status` contract.

import { describe, expect, it } from "vitest";

import {
  AcknowledgementError,
  AcknowledgementInsertConflict,
  clampReleaseToVerdict,
  computeEvidenceSetSha256,
  createAcknowledgementService,
  evaluateGroupRelease,
  expectedWalletsForOperation,
  REQUIRED_EVIDENCE_ROLES,
  validateEvidenceSet,
  validateRoleSet,
  type AckOpenMembership,
  type AckOperationFacts,
  type AckWalletEvidenceInput,
  type AcknowledgementDraft,
  type AcknowledgementInput,
  type AcknowledgementResponseBody,
  type AcknowledgementStore,
  type DurableEvidenceFact,
  type GroupReleaseFacts,
  type OperationWalletAssignment,
  type StoredAcknowledgement,
} from "../src/verification/index.ts";

const RECEIVE_OP = "d0000000-0000-4000-8000-000000000001";
const MOVE_OP = "d0000000-0000-4000-8000-000000000002";
const GROUP = "e0000000-0000-4000-8000-000000000001";
const NODE = "b0000000-0000-4000-8000-0000000000aa";
const IMPLEMENTER = "b0000000-0000-4000-8000-0000000000bb";
const REAL_RECEIVER_WALLET = "a0000000-0000-4000-8000-000000000001";
const WRONG_WALLET = "a0000000-0000-4000-8000-000000000099";
const REAL_RECEIVER_PUB = (): string => pubkey("w3");
const WRONG_PUB = (): string => pubkey("xx");

const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const evidence = (
  role: string,
  key: string,
  extra: Partial<AckWalletEvidenceInput> = {},
): AckWalletEvidenceInput => ({
  walletId: null,
  walletPublicKey: pubkey(key),
  role,
  t0: { observationId: `f0000000-0000-4000-8000-0000000000${key}` },
  terminal: { observationId: `f1000000-0000-4000-8000-0000000000${key}` },
  ...extra,
});

const receiveAssignment = (
  walletId: string = REAL_RECEIVER_WALLET,
  walletPublicKey: string = REAL_RECEIVER_PUB(),
): OperationWalletAssignment => ({
  role: "RECEIVER",
  walletId,
  walletPublicKey,
});

const receiveEvidence = (
  extra: Partial<AckWalletEvidenceInput> = {},
): AckWalletEvidenceInput =>
  evidence("RECEIVER", "w3", {
    walletId: REAL_RECEIVER_WALLET,
    walletPublicKey: REAL_RECEIVER_PUB(),
    ...extra,
  });

/* ─── evidence role sets (binding prose) ────────────────────────── */

describe("required evidence role set per operation kind", () => {
  it("binds receive to RECEIVER, move and send to SOURCE plus DESTINATION", () => {
    expect(REQUIRED_EVIDENCE_ROLES).toEqual({
      RECEIVE_EXTERNAL: ["RECEIVER"],
      MOVE_INTERNAL: ["SOURCE", "DESTINATION"],
      SEND_EXTERNAL: ["SOURCE", "DESTINATION"],
    });
  });

  it("accepts the exact set for each kind (role-only view)", () => {
    expect(validateEvidenceSet("RECEIVE_EXTERNAL", [evidence("RECEIVER", "01")])).toBeNull();
    expect(
      validateEvidenceSet("MOVE_INTERNAL", [
        evidence("SOURCE", "01"),
        evidence("DESTINATION", "02"),
      ]),
    ).toBeNull();
    expect(
      validateEvidenceSet("SEND_EXTERNAL", [
        evidence("SOURCE", "01"),
        evidence("DESTINATION", "02"),
      ]),
    ).toBeNull();
  });

  it("accepts the required set in any sequence — exactness is about membership", () => {
    expect(
      validateEvidenceSet("MOVE_INTERNAL", [
        evidence("DESTINATION", "02"),
        evidence("SOURCE", "01"),
      ]),
    ).toBeNull();
  });

  // Requirement: "submit a move acknowledgement missing the DESTINATION evidence
  // row — reject; must exactly match required role set, not accept a subset/superset."
  it("rejects a move missing its DESTINATION row rather than truncating", () => {
    expect(validateEvidenceSet("MOVE_INTERNAL", [evidence("SOURCE", "01")])).toEqual({
      kind: "MISSING_ROLE",
      role: "DESTINATION",
    });
  });

  it("rejects a superset", () => {
    expect(
      validateEvidenceSet("RECEIVE_EXTERNAL", [
        evidence("RECEIVER", "01"),
        evidence("SOURCE", "02"),
      ]),
    ).toEqual({ kind: "UNEXPECTED_ROLE", role: "SOURCE" });
  });

  it("rejects a repeated role (PRIMARY KEY) before the database has to", () => {
    expect(
      validateEvidenceSet("MOVE_INTERNAL", [
        evidence("SOURCE", "01"),
        evidence("SOURCE", "02"),
        evidence("DESTINATION", "03"),
      ]),
    ).toEqual({ kind: "DUPLICATE_ROLE", role: "SOURCE" });
  });

  it("rejects a repeated wallet public key (UNIQUE) before the database has to", () => {
    expect(
      validateEvidenceSet("MOVE_INTERNAL", [
        evidence("SOURCE", "01"),
        evidence("DESTINATION", "01"),
      ]),
    ).toEqual({ kind: "DUPLICATE_WALLET_PUBLIC_KEY", walletPublicKey: pubkey("01") });
  });

  it("rejects a role outside the closed set", () => {
    expect(
      validateEvidenceSet("RECEIVE_EXTERNAL", [evidence("EXTERNAL_SENDER_PREFLIGHT", "01")]),
    ).toEqual({ kind: "UNKNOWN_ROLE", role: "EXTERNAL_SENDER_PREFLIGHT" });
  });

  it("shares one exactness definition with the group predicate's role-only view", () => {
    expect(validateRoleSet("MOVE_INTERNAL", ["SOURCE"])).toEqual({
      kind: "MISSING_ROLE",
      role: "DESTINATION",
    });
    expect(validateRoleSet("MOVE_INTERNAL", ["SOURCE", "DESTINATION"])).toBeNull();
  });
});

/* ─── wallet-identity binding (One-in-flight) ─────────────────────────────────── */

describe("wallet-identity binding on the evidence set", () => {
  const expected = [receiveAssignment()];

  it("accepts evidence whose wallet_id and public key match the operation assignment", () => {
    expect(
      validateEvidenceSet(
        "RECEIVE_EXTERNAL",
        [receiveEvidence()],
        expected,
      ),
    ).toBeNull();
  });

  it("rejects a wrong wallet_id even when the role set is exact", () => {
    expect(
      validateEvidenceSet(
        "RECEIVE_EXTERNAL",
        [receiveEvidence({ walletId: WRONG_WALLET })],
        expected,
      ),
    ).toEqual({
      kind: "WALLET_ID_MISMATCH",
      role: "RECEIVER",
      expected: REAL_RECEIVER_WALLET,
      actual: WRONG_WALLET,
    });
  });

  it("rejects a wrong wallet_public_key even when wallet_id matches", () => {
    expect(
      validateEvidenceSet(
        "RECEIVE_EXTERNAL",
        [receiveEvidence({ walletPublicKey: WRONG_PUB() })],
        expected,
      ),
    ).toEqual({
      kind: "WALLET_PUBLIC_KEY_MISMATCH",
      role: "RECEIVER",
      expected: REAL_RECEIVER_PUB(),
      actual: WRONG_PUB(),
    });
  });

  it("builds expected wallets from operation columns", () => {
    expect(
      expectedWalletsForOperation("RECEIVE_EXTERNAL", {
        sourceWalletId: null,
        sourcePublicKey: null,
        receiverWalletId: REAL_RECEIVER_WALLET,
        receiverPublicKey: REAL_RECEIVER_PUB(),
        destinationWalletId: null,
        destinationPublicKey: null,
        destinationAddress: null,
      }),
    ).toEqual([receiveAssignment()]);

    expect(
      expectedWalletsForOperation("SEND_EXTERNAL", {
        sourceWalletId: "src",
        sourcePublicKey: pubkey("s1"),
        receiverWalletId: null,
        receiverPublicKey: null,
        destinationWalletId: null,
        destinationPublicKey: null,
        destinationAddress: pubkey("ext"),
      }),
    ).toEqual([
      { role: "SOURCE", walletId: "src", walletPublicKey: pubkey("s1") },
      { role: "DESTINATION", walletId: null, walletPublicKey: pubkey("ext") },
    ]);
  });
});

/* ─── evidence-set digest ───────────────────────────────────────────── */

describe("evidence_set_sha256 (encoding is implementer-defined)", () => {
  const set: readonly AckWalletEvidenceInput[] = [
    evidence("SOURCE", "01"),
    evidence("DESTINATION", "02"),
  ];

  it("is a lowercase 64-hex digest", () => {
    expect(computeEvidenceSetSha256(set)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is stable for the same set in the same sequence (a replay re-derives it)", () => {
    expect(computeEvidenceSetSha256(set)).toBe(computeEvidenceSetSha256([...set]));
  });

  // The byte-exact signing rule: the caller signed a body carrying this sequence. Re-sequencing would
  // change the bytes, so the digest must notice.
  it("changes when the sequence changes", () => {
    expect(computeEvidenceSetSha256([set[1]!, set[0]!])).not.toBe(computeEvidenceSetSha256(set));
  });

  it("changes when any bound field changes", () => {
    for (const mutated of [
      [{ ...set[0]!, role: "DESTINATION" }, { ...set[1]!, role: "SOURCE" }],
      [{ ...set[0]!, walletPublicKey: pubkey("99") }, set[1]!],
      [{ ...set[0]!, walletId: "a0000000-0000-4000-8000-000000000001" }, set[1]!],
      [{ ...set[0]!, t0: { observationId: "changed" } }, set[1]!],
      [{ ...set[0]!, terminal: { observationId: "changed" } }, set[1]!],
    ]) {
      expect(computeEvidenceSetSha256(mutated)).not.toBe(computeEvidenceSetSha256(set));
    }
  });

  // The byte-length prefix is the whole point: no field value can forge a field boundary.
  it("cannot be collided by moving a delimiter into a field value", () => {
    const a = [evidence("SOURCE", "01", { walletPublicKey: "AB" })];
    const b = [evidence("SOURCE", "01", { walletPublicKey: "A" })];
    expect(computeEvidenceSetSha256(a)).not.toBe(computeEvidenceSetSha256(b));
  });

  it("distinguishes an empty set from a one-entry set", () => {
    expect(computeEvidenceSetSha256([])).not.toBe(computeEvidenceSetSha256(set));
  });
});

/* ─── group-release predicate ─────────────────────────────── */

const factFromRoles = (
  operationId: string,
  kind: GroupReleaseFacts["operations"][number]["kind"],
  roles: readonly DurableEvidenceFact["role"][],
  overrides: Partial<GroupReleaseFacts["operations"][number]> = {},
): GroupReleaseFacts["operations"][number] => {
  const expectedWallets: OperationWalletAssignment[] =
    overrides.expectedWallets ??
    roles.map((role) => ({
      role,
      walletId: `wallet-${role.toLowerCase()}`,
      walletPublicKey: pubkey(role.slice(0, 2).toLowerCase()),
    }));
  const evidenceRows: DurableEvidenceFact[] =
    overrides.evidence ??
    expectedWallets
      .filter((w) => roles.includes(w.role))
      .map((w) => ({
        role: w.role,
        walletId: w.walletId,
        walletPublicKey: w.walletPublicKey,
      }));
  return {
    operationId,
    kind,
    verdict: "VERIFIED",
    completed: true,
    ...overrides,
    evidence: overrides.evidence ?? evidenceRows,
    expectedWallets: overrides.expectedWallets ?? expectedWallets,
    evidenceRoles:
      overrides.evidenceRoles ??
      (overrides.evidence ?? evidenceRows).map((e) => e.role),
  };
};

const leg = (
  operationId: string,
  overrides: Partial<GroupReleaseFacts["operations"][number]> = {},
): GroupReleaseFacts["operations"][number] =>
  factFromRoles(operationId, "RECEIVE_EXTERNAL", ["RECEIVER"], overrides);

describe("evaluateGroupRelease (release predicate)", () => {
  it("releases a single-leg group that is terminal, VERIFIED and evidence-complete", () => {
    expect(evaluateGroupRelease({ childDisposition: "NONE", operations: [leg(RECEIVE_OP)] })).toEqual(
      { status: "RELEASED", reason: "ALL_LEGS_PROVEN", blockingOperationIds: [] },
    );
  });

  // Requirement: "a receive that spawned a child move must NOT release its shared
  // source-wallet lease membership until BOTH legs' acknowledgement + wallet-evidence rows
  // satisfy the release predicate — assert PINNED_GROUP_PENDING after only one leg
  // acknowledges, RELEASED only after both."
  it("holds a receive+child-move group at PINNED_GROUP_PENDING after only one leg acknowledges", () => {
    const oneLeg = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [
        leg(RECEIVE_OP),
        factFromRoles(MOVE_OP, "MOVE_INTERNAL", [], {
          kind: "MOVE_INTERNAL",
          verdict: null,
          evidenceRoles: [],
          evidence: [],
          expectedWallets: [
            { role: "SOURCE", walletId: "src", walletPublicKey: pubkey("s1") },
            { role: "DESTINATION", walletId: "dst", walletPublicKey: pubkey("d1") },
          ],
          completed: false,
        }),
      ],
    });
    expect(oneLeg.status).toBe("PINNED_GROUP_PENDING");
    expect(oneLeg.reason).toBe("LEG_NOT_ACKNOWLEDGED");
    expect(oneLeg.blockingOperationIds).toEqual([MOVE_OP]);
  });

  it("releases the same group only once BOTH legs are proven", () => {
    expect(
      evaluateGroupRelease({
        childDisposition: "JOINED",
        operations: [
          leg(RECEIVE_OP),
          factFromRoles(MOVE_OP, "MOVE_INTERNAL", ["SOURCE", "DESTINATION"]),
        ],
      }),
    ).toEqual({ status: "RELEASED", reason: "ALL_LEGS_PROVEN", blockingOperationIds: [] });
  });

  it("refuses while a declared child has not joined (child_disposition PENDING)", () => {
    const pending = evaluateGroupRelease({
      childDisposition: "PENDING",
      operations: [leg(RECEIVE_OP)],
    });
    expect(pending.status).toBe("PINNED_GROUP_PENDING");
    expect(pending.reason).toBe("CHILD_OPERATION_NOT_JOINED");
  });

  it("pins for attention when any leg is REJECTED or INDETERMINATE", () => {
    for (const verdict of ["REJECTED", "INDETERMINATE"] as const) {
      const decided = evaluateGroupRelease({
        childDisposition: "JOINED",
        operations: [
          leg(RECEIVE_OP),
          factFromRoles(MOVE_OP, "MOVE_INTERNAL", ["SOURCE", "DESTINATION"], { verdict }),
        ],
      });
      expect(decided.status).toBe("PINNED_FOR_ATTENTION");
      expect(decided.reason).toBe("LEG_VERDICT_NOT_VERIFIED");
      expect(decided.blockingOperationIds).toEqual([MOVE_OP]);
    }
  });

  // A sibling rejection is the stronger signal: attention beats waiting, because the only way
  // out is the operations-recovery path, not the arrival of another acknowledgement.
  it("prefers attention over pending when a leg is rejected and another is unacknowledged", () => {
    expect(
      evaluateGroupRelease({
        childDisposition: "PENDING",
        operations: [
          leg(RECEIVE_OP, { verdict: "REJECTED" }),
          factFromRoles(MOVE_OP, "MOVE_INTERNAL", [], {
            verdict: null,
            evidence: [],
            evidenceRoles: [],
            expectedWallets: [
              { role: "SOURCE", walletId: "src", walletPublicKey: pubkey("s1") },
              { role: "DESTINATION", walletId: "dst", walletPublicKey: pubkey("d1") },
            ],
          }),
        ],
      }).status,
    ).toBe("PINNED_FOR_ATTENTION");
  });

  it("pins for attention when an acknowledged leg's evidence set is not its required set", () => {
    const decided = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [
        factFromRoles(MOVE_OP, "MOVE_INTERNAL", ["SOURCE"], {
          expectedWallets: [
            { role: "SOURCE", walletId: "src", walletPublicKey: pubkey("s1") },
            { role: "DESTINATION", walletId: "dst", walletPublicKey: pubkey("d1") },
          ],
          evidence: [
            { role: "SOURCE", walletId: "src", walletPublicKey: pubkey("s1") },
          ],
        }),
      ],
    });
    expect(decided.status).toBe("PINNED_FOR_ATTENTION");
    expect(decided.reason).toBe("LEG_EVIDENCE_SET_INCOMPLETE");
  });

  it("pins for attention when durable evidence names the wrong wallet identity", () => {
    const decided = evaluateGroupRelease({
      childDisposition: "NONE",
      operations: [
        leg(RECEIVE_OP, {
          expectedWallets: [receiveAssignment()],
          evidence: [
            {
              role: "RECEIVER",
              walletId: WRONG_WALLET,
              walletPublicKey: REAL_RECEIVER_PUB(),
            },
          ],
        }),
      ],
    });
    expect(decided.status).toBe("PINNED_FOR_ATTENTION");
    expect(decided.reason).toBe("LEG_EVIDENCE_SET_INCOMPLETE");
  });

  it("refuses while an acknowledged leg is not yet stamped terminal", () => {
    const decided = evaluateGroupRelease({
      childDisposition: "NONE",
      operations: [leg(RECEIVE_OP, { completed: false })],
    });
    expect(decided.status).toBe("PINNED_GROUP_PENDING");
    expect(decided.reason).toBe("LEG_NOT_TERMINAL");
  });

  it("treats a group with no legs as an operator problem, never as releasable", () => {
    expect(evaluateGroupRelease({ childDisposition: "NONE", operations: [] })).toEqual({
      status: "PINNED_FOR_ATTENTION",
      reason: "GROUP_HAS_NO_OPERATIONS",
      blockingOperationIds: [],
    });
  });
});

// "Acknowledging REJECTED or INDETERMINATE never silently releases a wallet."
describe("clampReleaseToVerdict", () => {
  it("passes a VERIFIED verdict's group decision through unchanged", () => {
    for (const status of ["RELEASED", "PINNED_GROUP_PENDING", "PINNED_FOR_ATTENTION"] as const) {
      expect(clampReleaseToVerdict("VERIFIED", status)).toBe(status);
    }
  });

  it("never yields RELEASED for a non-VERIFIED verdict, whatever the group says", () => {
    for (const verdict of ["REJECTED", "INDETERMINATE"] as const) {
      expect(clampReleaseToVerdict(verdict, "RELEASED")).toBe("PINNED_FOR_ATTENTION");
      expect(clampReleaseToVerdict(verdict, "PINNED_GROUP_PENDING")).toBe("PINNED_GROUP_PENDING");
      expect(clampReleaseToVerdict(verdict, "PINNED_FOR_ATTENTION")).toBe("PINNED_FOR_ATTENTION");
    }
  });
});

/* ─── the service ───────────────────────────────────────────────────── */

type Tx = { readonly label: string };

interface HarnessOptions {
  readonly kind?: AckOperationFacts["kind"];
  readonly rowVersion?: number;
  readonly leaseGroupId?: string | null;
  readonly siblingUnacknowledged?: boolean;
  /** When true, a later call mutates group facts so a naive re-eval would flip to RELEASED. */
  readonly mutableSibling?: { flipToAcknowledged: () => void };
  readonly expectedWallets?: readonly OperationWalletAssignment[];
  readonly openMembershipWalletId?: string;
}

function harness(options: HarnessOptions = {}) {
  const kind = options.kind ?? "RECEIVE_EXTERNAL";
  const rows: AcknowledgementDraft[] = [];
  const frozenById = new Map<string, AcknowledgementResponseBody>();
  const completed = new Set<string>();
  const operationVerdicts = new Map<string, string>();
  const attentionByOp = new Map<string, string | null>();
  let siblingStillPending = options.siblingUnacknowledged === true;

  const defaultExpected: readonly OperationWalletAssignment[] =
    options.expectedWallets ??
    (kind === "RECEIVE_EXTERNAL"
      ? [receiveAssignment()]
      : kind === "MOVE_INTERNAL"
        ? [
            {
              role: "SOURCE",
              walletId: "a0000000-0000-4000-8000-000000000010",
              walletPublicKey: pubkey("s1"),
            },
            {
              role: "DESTINATION",
              walletId: "a0000000-0000-4000-8000-000000000011",
              walletPublicKey: pubkey("d1"),
            },
          ]
        : [
            {
              role: "SOURCE",
              walletId: "a0000000-0000-4000-8000-000000000010",
              walletPublicKey: pubkey("s1"),
            },
            {
              role: "DESTINATION",
              walletId: null,
              walletPublicKey: pubkey("ex"),
            },
          ]);

  const store: AcknowledgementStore<Tx> = {
    async readOperation(): Promise<AckOperationFacts | null> {
      return {
        operationId: RECEIVE_OP,
        nodeId: NODE,
        implementerId: IMPLEMENTER,
        kind,
        rowVersion: options.rowVersion ?? 7,
        leaseGroupId: options.leaseGroupId === undefined ? GROUP : options.leaseGroupId,
        expectedWallets: defaultExpected,
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
    async completeGroupOperation(_tx, _groupId, operationId): Promise<void> {
      completed.add(operationId);
    },
    async applyOperationVerificationVerdict(_tx, operationId, verdict): Promise<void> {
      operationVerdicts.set(operationId, verdict);
      if (verdict === "VERIFIED") {
        attentionByOp.set(operationId, null);
      }
    },
    async readGroupReleaseFacts(): Promise<GroupReleaseFacts> {
      const operations = rows.map((row) => {
        const evidenceFacts: DurableEvidenceFact[] = row.walletEvidence.map((e) => ({
          role: e.role as DurableEvidenceFact["role"],
          walletId: e.walletId,
          walletPublicKey: e.walletPublicKey,
        }));
        return {
          operationId: row.operationId,
          kind,
          verdict: row.verdict,
          evidenceRoles: evidenceFacts.map((e) => e.role),
          evidence: evidenceFacts,
          expectedWallets: [...defaultExpected],
          completed: completed.has(row.operationId),
        };
      });
      if (siblingStillPending) {
        operations.push({
          operationId: MOVE_OP,
          kind: "MOVE_INTERNAL",
          verdict: null,
          evidenceRoles: [],
          evidence: [],
          expectedWallets: [
            {
              role: "SOURCE",
              walletId: "a0000000-0000-4000-8000-000000000010",
              walletPublicKey: pubkey("s1"),
            },
            {
              role: "DESTINATION",
              walletId: "a0000000-0000-4000-8000-000000000011",
              walletPublicKey: pubkey("d1"),
            },
          ],
          completed: false,
        });
      }
      return { childDisposition: "NONE", operations };
    },
    async readOpenMemberships(): Promise<readonly AckOpenMembership[]> {
      return [
        {
          membershipId: "c0000000-0000-4000-8000-000000000001",
          walletId: options.openMembershipWalletId ?? REAL_RECEIVER_WALLET,
          leaseEpoch: 1n,
          leaseGroupId: GROUP,
          operationId: RECEIVE_OP,
        },
      ];
    },
  };

  const preimages = new Map<string, string>();
  const signatures = new Map<string, string>();
  let seq = 0;
  const service = createAcknowledgementService<Tx>({
    store,
    newAcknowledgementId: () => {
      seq += 1;
      return `aa000000-0000-4000-8000-00000000000${seq}`;
    },
    nowIso: () => "2026-07-26T00:00:00.000Z",
  });

  // The service does not persist the preimage itself (keeps it on the nonce row), so the
  // harness records it alongside the write to mirror what the SQL store reads back. It also
  // freezes the first-success body the way the completed idempotency parent does.
  const acknowledge = async (tx: Tx, input: AcknowledgementInput) => {
    const before = rows.length;
    const outcome = await service.acknowledge(tx, RECEIVE_OP, input);
    if (rows.length > before) {
      const written = rows[rows.length - 1]!;
      preimages.set(written.id, input.requestPreimageText);
      signatures.set(written.id, input.requestSignature);
      frozenById.set(written.id, outcome.body);
    }
    return outcome;
  };

  const flipSibling = () => {
    siblingStillPending = false;
  };

  return { acknowledge, rows, completed, flipSibling, store, operationVerdicts, attentionByOp };
}

const baseInput = (overrides: Partial<AcknowledgementInput> = {}): AcknowledgementInput => ({
  expectedRowVersion: 7,
  consumedCursor: 1051n,
  verdict: "VERIFIED",
  walletEvidence: [receiveEvidence()],
  nodeId: NODE,
  implementerId: IMPLEMENTER,
  reportingNonceId: "aa000000-0000-4000-8000-0000000000n1",
  mutationIdempotencyId: "aa000000-0000-4000-8000-0000000000i1",
  rawTarget: `/v1/operations/${RECEIVE_OP}/verification-complete`,
  requestBodySha256: "ab".repeat(32),
  requestPreimageText: '{"purpose":"zp-report-request-v1","canonical_version":1}',
  requestSignature: `${"A".repeat(86)}==`,
  ...overrides,
});

const TX: Tx = { label: "unit" };

describe("createAcknowledgementService (backing implementation)", () => {
  it("writes the acknowledgement, stamps the leg terminal, and releases a proven group", async () => {
    const h = harness();
    h.attentionByOp.set(RECEIVE_OP, "LINEAGE_GAP");
    const outcome = await h.acknowledge(TX, baseInput());
    expect(outcome.body).toEqual({
      operation_id: RECEIVE_OP,
      acknowledgement_id: "aa000000-0000-4000-8000-000000000001",
      verdict: "VERIFIED",
      lease_release_status: "RELEASED",
      acknowledged_at: "2026-07-26T00:00:00.000Z",
    });
    expect(outcome.idempotentReplay).toBe(false);
    expect(h.completed.has(RECEIVE_OP)).toBe(true);
    expect(outcome.releasableMemberships).toHaveLength(1);
    // ZTR-1246 / ZTR-1245
    expect(h.operationVerdicts.get(RECEIVE_OP)).toBe("VERIFIED");
    expect(h.attentionByOp.get(RECEIVE_OP)).toBeNull();
  });

  it("does not re-apply verification_verdict on identical replay (ZTR-1246)", async () => {
    const h = harness();
    await h.acknowledge(TX, baseInput());
    h.operationVerdicts.clear();
    h.attentionByOp.set(RECEIVE_OP, "LINEAGE_GAP");
    const second = await h.acknowledge(TX, baseInput());
    expect(second.idempotentReplay).toBe(true);
    expect(h.operationVerdicts.size).toBe(0);
    expect(h.attentionByOp.get(RECEIVE_OP)).toBe("LINEAGE_GAP");
  });

  it("derives evidence_set_sha256 from the supplied set", async () => {
    const h = harness();
    const input = baseInput();
    await h.acknowledge(TX, input);
    expect(h.rows[0]!.evidenceSetSha256).toBe(
      computeEvidenceSetSha256(input.walletEvidence),
    );
  });

  it("replays an identical acknowledgement idempotently without a second row", async () => {
    const h = harness();
    const first = await h.acknowledge(TX, baseInput());
    const second = await h.acknowledge(TX, baseInput());
    expect(second.idempotentReplay).toBe(true);
    expect(second.body).toEqual(first.body);
    expect(h.rows).toHaveLength(1);
  });

  // Freeze: matching replay must not re-derive lease_release_status after siblings move.
  it("freezes lease_release_status on matching replay after the group becomes releasable", async () => {
    const h = harness({ siblingUnacknowledged: true });
    const first = await h.acknowledge(TX, baseInput());
    expect(first.body.lease_release_status).toBe("PINNED_GROUP_PENDING");
    expect(first.releasableMemberships).toEqual([]);

    // Sibling completes out-of-band — a re-eval would flip to RELEASED.
    h.flipSibling();

    const second = await h.acknowledge(TX, baseInput());
    expect(second.idempotentReplay).toBe(true);
    expect(second.body).toEqual(first.body);
    expect(second.body.lease_release_status).toBe("PINNED_GROUP_PENDING");
    expect(second.releasableMemberships).toEqual([]);
  });

  // One-in-flight /: wrong-wallet RECEIVER evidence must not RELEASED + real leased membership.
  it("refuses wrong wallet_id evidence and never returns a release directive", async () => {
    const h = harness();
    await expect(
      h.acknowledge(
        TX,
        baseInput({
          walletEvidence: [receiveEvidence({ walletId: WRONG_WALLET })],
        }),
      ),
    ).rejects.toMatchObject({
      name: "AcknowledgementError",
      reason: "EVIDENCE_SET_INVALID",
    });
    expect(h.rows).toEqual([]);
  });

  it("refuses wrong wallet_public_key evidence and never returns a release directive", async () => {
    const h = harness();
    await expect(
      h.acknowledge(
        TX,
        baseInput({
          walletEvidence: [receiveEvidence({ walletPublicKey: WRONG_PUB() })],
        }),
      ),
    ).rejects.toMatchObject({ reason: "EVIDENCE_SET_INVALID" });
    expect(h.rows).toEqual([]);
  });

  it("refuses evidence for a wallet that is not the operation's assigned wallet", async () => {
    const h = harness({
      expectedWallets: [receiveAssignment(REAL_RECEIVER_WALLET, REAL_RECEIVER_PUB())],
      openMembershipWalletId: REAL_RECEIVER_WALLET,
    });
    // Role is correct, public key of an unrelated key — not the leased receiver.
    await expect(
      h.acknowledge(
        TX,
        baseInput({
          walletEvidence: [
            receiveEvidence({
              walletId: REAL_RECEIVER_WALLET,
              walletPublicKey: WRONG_PUB(),
            }),
          ],
        }),
      ),
    ).rejects.toMatchObject({ reason: "EVIDENCE_SET_INVALID" });
    expect(h.rows).toEqual([]);
  });

  it("maps a concurrent operation_id unique collision to matching replay", async () => {
    const h = harness();
    const first = await h.acknowledge(TX, baseInput());
    // Force the insert path to see an existing row via conflict (simulate lost race after
    // findAcknowledgement returned null by clearing the find side only is hard; instead call
    // insert path by racing two services that share rows — second insert throws conflict and
    // re-reads). Directly: insert already happened; a second service instance sharing store
    // sees existing via find. For conflict path: insertAcknowledgement throws when duplicate.
    const racing: AcknowledgementStore<Tx> = {
      ...h.store,
      async findAcknowledgement(tx, operationId) {
        // First call pretends empty (lost the initial read race); subsequent calls see the row.
        if ((racing as { _n?: number })._n === undefined) {
          (racing as { _n?: number })._n = 0;
        }
        (racing as { _n: number })._n += 1;
        if ((racing as { _n: number })._n === 1) return null;
        return h.store.findAcknowledgement(tx, operationId);
      },
    };
    const racingService = createAcknowledgementService<Tx>({
      store: racing,
      newAcknowledgementId: () => "aa000000-0000-4000-8000-000000000099",
      nowIso: () => "2026-07-26T00:00:00.000Z",
    });
    const outcome = await racingService.acknowledge(TX, RECEIVE_OP, baseInput());
    expect(outcome.idempotentReplay).toBe(true);
    expect(outcome.body.acknowledgement_id).toBe(first.body.acknowledgement_id);
    expect(outcome.body).toEqual(first.body);
  });

  // "A conflicting replay is rejected." Each bound field is a conflict on
  // its own; none of them may write, and none may release.
  it.each([
    ["verdict", { verdict: "REJECTED" }],
    ["consumed cursor", { consumedCursor: 9999n }],
    ["body digest", { requestBodySha256: "cd".repeat(32) }],
    ["raw target", { rawTarget: "/v1/operations/other/verification-complete" }],
    ["preimage bytes", { requestPreimageText: '{"purpose":"zp-report-request-v1"} ' }],
    ["signature bytes", { requestSignature: `${"B".repeat(86)}==` }],
    [
      "evidence set",
      {
        walletEvidence: [
          receiveEvidence({
            // Different t0 observation keeps role+wallet identity valid but changes the digest.
            t0: { observationId: "f0000000-0000-4000-8000-000000000099" },
          }),
        ],
      },
    ],
  ])("rejects a conflicting replay differing only in %s", async (_label, overrides) => {
    const h = harness();
    await h.acknowledge(TX, baseInput());
    await expect(h.acknowledge(TX, baseInput(overrides))).rejects.toMatchObject({
      name: "AcknowledgementError",
      reason: "CONFLICTING_REPLAY",
    });
    expect(h.rows).toHaveLength(1);
    expect(h.rows[0]!.verdict).toBe("VERIFIED");
  });

  // Requirement: "acknowledging REJECTED or INDETERMINATE never produces
  // lease_release_status: RELEASED."
  it.each(["REJECTED", "INDETERMINATE"] as const)(
    "never releases on a %s verdict, and offers no membership to release",
    async (verdict) => {
      const h = harness();
      const outcome = await h.acknowledge(TX, baseInput({ verdict }));
      expect(outcome.body.lease_release_status).toBe("PINNED_FOR_ATTENTION");
      expect(outcome.releasableMemberships).toEqual([]);
    },
  );

  it("reports PINNED_GROUP_PENDING while a sibling leg is unacknowledged", async () => {
    const h = harness({ siblingUnacknowledged: true });
    const outcome = await h.acknowledge(TX, baseInput());
    expect(outcome.body.lease_release_status).toBe("PINNED_GROUP_PENDING");
    expect(outcome.releasableMemberships).toEqual([]);
  });

  it("refuses PENDING as a verdict (CHECK verdict <> 'PENDING')", async () => {
    const h = harness();
    await expect(h.acknowledge(TX, baseInput({ verdict: "PENDING" }))).rejects.toMatchObject({
      reason: "VERDICT_NOT_ACKNOWLEDGEABLE",
    });
    expect(h.rows).toEqual([]);
  });

  it("refuses a foreign reporting-credential tenant (composite operation FK)", async () => {
    const h = harness();
    await expect(
      h.acknowledge(TX, baseInput({ implementerId: "b0000000-0000-4000-8000-0000000000cc" })),
    ).rejects.toMatchObject({ reason: "TENANT_MISMATCH" });
    expect(h.rows).toEqual([]);
  });

  it("refuses a stale expected_row_version", async () => {
    const h = harness({ rowVersion: 9 });
    await expect(h.acknowledge(TX, baseInput({ expectedRowVersion: 7 }))).rejects.toMatchObject({
      reason: "OPERATION_VERSION_CONFLICT",
    });
    expect(h.rows).toEqual([]);
  });

  it("keeps a genuine replay idempotent after the operation's row_version moved on", async () => {
    const h = harness();
    await h.acknowledge(TX, baseInput());
    // Same request bytes, stale version: replays return the stored result unchanged.
    const replay = await h.acknowledge(TX, baseInput({ expectedRowVersion: 3 }));
    expect(replay.idempotentReplay).toBe(true);
  });

  it("refuses an incomplete evidence set for the operation's kind", async () => {
    const h = harness({ kind: "MOVE_INTERNAL" });
    await expect(
      h.acknowledge(
        TX,
        baseInput({
          walletEvidence: [
            evidence("SOURCE", "s1", {
              walletId: "a0000000-0000-4000-8000-000000000010",
              walletPublicKey: pubkey("s1"),
            }),
          ],
        }),
      ),
    ).rejects.toMatchObject({ reason: "EVIDENCE_SET_INVALID" });
    expect(h.rows).toEqual([]);
  });

  it("refuses to decide release for an operation that holds no lease group", async () => {
    const h = harness({ leaseGroupId: null });
    await expect(h.acknowledge(TX, baseInput())).rejects.toMatchObject({
      reason: "OPERATION_HAS_NO_LEASE_GROUP",
    });
  });

  it("carries a machine-readable reason on every failure", () => {
    const err = new AcknowledgementError("CONFLICTING_REPLAY", "detail");
    expect(err.reason).toBe("CONFLICTING_REPLAY");
    expect(err.message).toContain("CONFLICTING_REPLAY");
  });
});
