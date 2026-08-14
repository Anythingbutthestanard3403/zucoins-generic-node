// ZTR-1273 — epic exit-bar scenario matrix for wallet money capabilities +
// auto-funded external send (composition of ZTR-1267…1271).
//
// Each cell maps to an automated assertion. Load-bearing selection SQL cells also
// run against real PostgreSQL in money-capability-acceptance.pg.test.ts and the
// existing assign-and-topup / wallet-money-capability-gates PG suites.
//
// Product constraint: three money verbs only. No fourth verb. Drift-gate clean.

import { createPrivateKey, sign as edSign } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  flagsFromMode,
  isEligibleForMoveParty,
  isEligibleForReceiveAssign,
  isEligibleForSendSource,
  type WalletMoneyMode,
} from "@zucoins/generic-node-contracts/wallet-state";

import {
  assignAndTopUpExternalSend,
  decideWorkerFunding,
  isTopUpHubEligible,
  SELECT_SEND_WORKER_SQL,
  SELECT_TOPUP_HUB_SQL,
  type AssignSqlExecutor,
} from "../src/assign-and-topup.js";
import {
  createInternalMove,
  isMoveDestinationEligible,
  isMoveSourceEligible,
  MOVE_OPERATION_KIND,
  type MoveAdmitInsert,
  type MoveCreateStore,
  type MoveDestinationRecord,
  type MoveInsertOutcome,
  type MoveSourceWalletRecord,
  type StoredMoveOperation,
} from "../src/move/create.js";
import {
  isSendSourceEligible,
  type SendArtifactSigner,
  type SendCreateStore,
  type SendExpectedArtifact,
  type SendInsertOutcome,
  type SendOperation,
  type SendSourceWalletRecord,
  type StoredSendOperation,
} from "../src/send/create.js";

/* ─── goldens / constants ─────────────────────────────────────────────── */

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const DEST_EXTERNAL = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const WORKER_PUB = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const HUB_PUB = "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=";
const OTHER_PUB = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const SIGNING_KEY_ID = "66666666-6666-4666-8666-666666666666";
const FIXED_NOW = 1_700_000_000_000;

const NODE_IDENTITY_KEY = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, 0),
  ]),
  format: "der",
  type: "pkcs8",
});

const signer: SendArtifactSigner = {
  signingKeyId: SIGNING_KEY_ID,
  sign: (preimageBytes) => edSign(null, preimageBytes, NODE_IDENTITY_KEY),
};

const uuid = (n: number): string => {
  const hex = n.toString(16).padStart(12, "0");
  return `c0000000-0000-4000-8000-${hex}`;
};

/** Scenario catalogue — epic exit bar (ZTR-1273). Keep in lockstep with Linear AC. */
export const ACCEPTANCE_SCENARIOS = [
  {
    id: "S1_hub_funded_worker_empty_move_then_send",
    setup: "Hub INTERNAL_ONLY funded; worker SEND_ONLY empty",
    action: "External send N (omit source)",
    expect: "MOVE hub→worker; SEND source=worker",
  },
  {
    id: "S2_worker_prefunded_no_move",
    setup: "Worker pre-funded SEND_ONLY",
    action: "External send",
    expect: "No MOVE; SEND source=worker",
  },
  {
    id: "S3_only_internal_only_reject",
    setup: "Only INTERNAL_ONLY wallets",
    action: "External send",
    expect: "Reject (no_free_send_worker)",
  },
  {
    id: "S4_only_receive_only_reject",
    setup: "Only RECEIVE_ONLY wallets",
    action: "External send",
    expect: "Reject (no_free_send_worker)",
  },
  {
    id: "S5_underfunded_hubs_empty_no_funds",
    setup: "SEND_ONLY workers underfunded; hubs empty",
    action: "External send",
    expect: "no_hub_liquidity / no-funds reject",
  },
  {
    id: "S6_two_hubs_second_covers",
    setup: "Two hubs; only second covers shortfall",
    action: "External send needing top-up",
    expect: "Second hub used (id ASC + coverage)",
  },
  {
    id: "S7_explicit_internal_only_source_reject",
    setup: "Explicit source = INTERNAL_ONLY",
    action: "Create send",
    expect: "Reject allow_external_send=false",
  },
  {
    id: "S8_omit_source_node_assigns",
    setup: "Omit source; free SEND_ONLY present",
    action: "Create send",
    expect: "Node assigns worker",
  },
  {
    id: "S9_send_only_never_receive_assign",
    setup: "SEND_ONLY wallet in pool",
    action: "Receive assign",
    expect: "Never selects SEND_ONLY",
  },
  {
    id: "S10_two_internal_only_move_allowed",
    setup: "Two INTERNAL_ONLY wallets",
    action: "MOVE between them",
    expect: "Allowed (both allow_internal_move)",
  },
  {
    id: "S11_halt_blocks_formation",
    setup: "Halt engaged",
    action: "MOVE/SEND first formation via composition",
    expect: "Blocked per halt contract (halted)",
  },
  {
    id: "S12_funding_wallet_hop_w_to_sender",
    setup: "Funding W funded; worker empty; multi-hub also present",
    action: "External send omit source with fundingWalletId=W",
    expect: "MOVE W→worker; source_wallet_id=worker; not hub",
  },
  {
    id: "S13_funding_wallet_dry_insufficient",
    setup: "Funding W dry; worker underfunded; hubs would cover",
    action: "External send with fundingWalletId=W",
    expect: "insufficient_funding_wallet; no silent hub substitute",
  },
  {
    id: "S14_funding_wallet_idempotent_no_double_hop",
    setup: "Funding W hop already created once",
    action: "Replay same idempotency key",
    expect: "IDEMPOTENT_REPLAY; single MOVE only",
  },
] as const;

/* ─── store doubles (frozen constraints only) ─────────────────────────── */

const SEND_TERMINAL = new Set(["EXTERNAL_SEND_LANDED", "REJECTED"]);

class SendStore implements SendCreateStore {
  readonly wallets = new Map<string, SendSourceWalletRecord>();
  readonly blessedInternal = new Set<string>();
  readonly operations = new Map<string, StoredSendOperation>();
  readonly artifacts = new Map<string, SendExpectedArtifact>();

  async findSourceWallet(walletId: string): Promise<SendSourceWalletRecord | null> {
    return this.wallets.get(walletId) ?? null;
  }
  async isBlessedInternalAddress(address: string): Promise<boolean> {
    return this.blessedInternal.has(address);
  }
  async insertCreated(
    operation: SendOperation,
    artifact: SendExpectedArtifact,
  ): Promise<SendInsertOutcome> {
    for (const row of this.operations.values()) {
      if (
        row.implementerId === operation.implementerId &&
        row.httpMethod === operation.httpMethod &&
        row.route === operation.route &&
        row.idempotencyKey === operation.idempotencyKey
      ) {
        return { kind: "IDEMPOTENCY_CONFLICT" };
      }
    }
    for (const row of this.operations.values()) {
      if (row.sourceWalletId === operation.sourceWalletId && !SEND_TERMINAL.has(row.status)) {
        return { kind: "WALLET_IN_FLIGHT", walletId: operation.sourceWalletId };
      }
    }
    this.operations.set(operation.operationId, {
      ...operation,
      status: operation.status,
      rowVersion: operation.rowVersion,
      attentionRequired: operation.attentionRequired,
      formationState: operation.formationState,
      responseStatus: null,
      responseBody: null,
    });
    this.artifacts.set(artifact.operationId, artifact);
    return { kind: "INSERTED" };
  }
  async findByIdempotency(
    implementerId: string,
    httpMethod: string,
    route: string,
    idempotencyKey: string,
  ): Promise<StoredSendOperation | null> {
    for (const row of this.operations.values()) {
      if (
        row.implementerId === implementerId &&
        row.httpMethod === httpMethod &&
        row.route === route &&
        row.idempotencyKey === idempotencyKey
      ) {
        return row;
      }
    }
    return null;
  }
  async findByOperationId(
    operationId: string,
  ): Promise<{ operation: StoredSendOperation; artifact: SendExpectedArtifact } | null> {
    const operation = this.operations.get(operationId);
    const artifact = this.artifacts.get(operationId);
    if (operation === undefined || artifact === undefined) return null;
    return { operation, artifact };
  }
  async completeOperation(
    operationId: string,
    responseStatus: number,
    responseBody: string,
  ): Promise<boolean> {
    const row = this.operations.get(operationId);
    if (row === undefined || row.responseBody !== null) return false;
    this.operations.set(operationId, { ...row, responseStatus, responseBody });
    return true;
  }
}

class MoveStore implements MoveCreateStore {
  readonly sources = new Map<string, MoveSourceWalletRecord>();
  readonly destinations = new Map<string, MoveDestinationRecord>();
  readonly activeLeases = new Set<string>();
  readonly operations = new Map<string, StoredMoveOperation>();
  readonly leaseGroups = new Map<string, { root: string; childDisposition: string }>();
  readonly groupOps = new Map<string, string>();

  async findSourceWallet(walletId: string): Promise<MoveSourceWalletRecord | null> {
    return this.sources.get(walletId) ?? null;
  }
  async findDestination(destinationId: string): Promise<MoveDestinationRecord | null> {
    return this.destinations.get(destinationId) ?? null;
  }
  async hasActiveLease(walletId: string): Promise<boolean> {
    return this.activeLeases.has(walletId);
  }
  async insertAdmitted(input: MoveAdmitInsert): Promise<MoveInsertOutcome> {
    const op = input.operation;
    for (const row of this.operations.values()) {
      if (
        row.implementerId === op.implementerId &&
        row.kind === op.kind &&
        row.idempotencyKey === op.idempotencyKey
      ) {
        return { kind: "IDEMPOTENCY_CONFLICT" };
      }
    }
    let leaseGroupId: string;
    if (input.createLeaseGroup) {
      leaseGroupId = op.leaseGroupId;
      this.leaseGroups.set(leaseGroupId, { root: op.operationId, childDisposition: "NONE" });
      this.groupOps.set(op.operationId, leaseGroupId);
    } else {
      leaseGroupId = input.parentLeaseGroupId as string;
      this.groupOps.set(op.operationId, leaseGroupId);
    }
    this.operations.set(op.operationId, {
      operationId: op.operationId,
      implementerId: op.implementerId,
      nodeId: op.nodeId,
      kind: MOVE_OPERATION_KIND,
      status: op.status,
      rowVersion: op.rowVersion,
      attentionRequired: op.attentionRequired,
      sourceWalletId: op.sourceWalletId,
      destinationId: op.destinationId,
      destinationWalletId: op.destinationWalletId,
      amountZkz: op.amountZkz,
      clientReference: op.clientReference,
      spawnedFromOperationId: op.spawnedFromOperationId,
      leaseGroupId,
      idempotencyKey: op.idempotencyKey,
      requestSha256: op.requestSha256,
      verificationMode: op.verificationMode,
      createdAt: op.createdAt,
      updatedAt: op.createdAt,
    });
    return { kind: "INSERTED", leaseGroupId };
  }
  async findByIdempotency(
    implementerId: string,
    kind: typeof MOVE_OPERATION_KIND,
    idempotencyKey: string,
  ): Promise<StoredMoveOperation | null> {
    for (const row of this.operations.values()) {
      if (
        row.implementerId === implementerId &&
        row.kind === kind &&
        row.idempotencyKey === idempotencyKey
      ) {
        return row;
      }
    }
    return null;
  }
  async findByOperationId(operationId: string): Promise<StoredMoveOperation | null> {
    return this.operations.get(operationId) ?? null;
  }
}

/* ─── scenario world + SQL mock ───────────────────────────────────────── */

interface WorldWallet {
  readonly id: string;
  readonly mode: WalletMoneyMode;
  readonly balance: string | null;
  readonly destinationId: string | null;
  readonly publicKey: string;
  state: "AVAILABLE" | "PINNED";
}

function modeFlags(mode: WalletMoneyMode) {
  return flagsFromMode(mode);
}

class ScenarioWorld {
  readonly wallets: WorldWallet[] = [];
  readonly sendStore = new SendStore();
  readonly moveStore = new MoveStore();
  private seq = 0;

  addWallet(
    mode: WalletMoneyMode,
    opts: {
      balance?: string | null;
      blessed?: boolean;
      publicKey?: string;
      id?: string;
    } = {},
  ): WorldWallet {
    this.seq += 1;
    const id = opts.id ?? uuid(this.seq);
    const flags = modeFlags(mode);
    const publicKey = opts.publicKey ?? (mode === "INTERNAL_ONLY" ? HUB_PUB : WORKER_PUB);
    let destinationId: string | null = null;
    if (opts.blessed === true) {
      this.seq += 1;
      destinationId = uuid(this.seq);
    }
    const w: WorldWallet = {
      id,
      mode,
      balance: opts.balance === undefined ? null : opts.balance,
      destinationId,
      publicKey,
      state: "AVAILABLE",
    };
    this.wallets.push(w);

    // Send eligibility surface
    this.sendStore.wallets.set(id, {
      walletId: id,
      nodeId: NODE_ID,
      publicKey,
      keyOrigin: "node_generated",
      state: "AVAILABLE",
      allowExternalSend: flags.allow_external_send,
    });
    // Move surfaces
    this.moveStore.sources.set(id, {
      walletId: id,
      nodeId: NODE_ID,
      publicKey,
      keyOrigin: "node_generated",
      state: "AVAILABLE",
      allowInternalMove: flags.allow_internal_move,
    });
    if (destinationId !== null) {
      this.moveStore.destinations.set(destinationId, {
        destinationId,
        nodeId: NODE_ID,
        walletId: id,
        publicKey,
        keyOrigin: "node_generated",
        walletState: "AVAILABLE",
        destinationState: "BLESSED",
        recoveryVerifiedAt: "2026-07-01T00:00:00.000Z",
        allowInternalMove: flags.allow_internal_move,
      });
    }
    return w;
  }

  sql = (): AssignSqlExecutor => {
    const wallets = this.wallets;
    const moveStore = this.moveStore;
    return {
      query: async <R>(text: string, params: readonly unknown[] = []): Promise<{ rows: R[] }> => {
        const sql = text.replace(/\s+/g, " ");

        // Explicit source lock (composition plan path)
        if (
          sql.includes("FOR UPDATE OF w") &&
          sql.includes("w.allow_external_send") &&
          sql.includes("WHERE w.id = $1::uuid")
        ) {
          const walletId = String(params[0]);
          const w = wallets.find((x) => x.id === walletId);
          if (w === undefined) return { rows: [] };
          const flags = modeFlags(w.mode);
          return {
            rows: [
              {
                wallet_id: w.id,
                observed_balance_zkz: w.balance,
                allow_external_send: flags.allow_external_send,
              } as R,
            ],
          };
        }

        // Worker pool select
        if (sql.includes("allow_external_send IS TRUE") && sql.includes("CASE")) {
          const amount = String(params[1] ?? "0");
          const candidates = wallets
            .filter((w) => {
              const f = modeFlags(w.mode);
              return (
                w.state === "AVAILABLE" &&
                f.allow_external_send === true &&
                !moveStore.activeLeases.has(w.id)
              );
            })
            .sort((a, b) => {
              const aFunded =
                a.balance !== null && Number(a.balance) >= Number(amount) ? 0 : 1;
              const bFunded =
                b.balance !== null && Number(b.balance) >= Number(amount) ? 0 : 1;
              if (aFunded !== bFunded) return aFunded - bFunded;
              return a.id.localeCompare(b.id);
            });
          const pick = candidates[0];
          if (pick === undefined) return { rows: [] };
          return {
            rows: [
              {
                wallet_id: pick.id,
                observed_balance_zkz: pick.balance,
              } as R,
            ],
          };
        }

        // Funding wallet W lock (ZTR-1289) — by id, not INTERNAL_ONLY filter
        if (
          sql.includes("w.id = $1::uuid") &&
          sql.includes("w.node_id = $2::uuid") &&
          sql.includes("allow_internal_move") &&
          sql.includes("has_active_lease")
        ) {
          const walletId = String(params[0]);
          const w = wallets.find((x) => x.id === walletId);
          if (w === undefined) return { rows: [] };
          const f = modeFlags(w.mode);
          return {
            rows: [
              {
                wallet_id: w.id,
                observed_balance_zkz: w.balance,
                allow_internal_move: f.allow_internal_move,
                state: w.state,
                key_origin: "node_generated",
                is_retired: false,
                has_active_lease: moveStore.activeLeases.has(w.id),
              } as R,
            ],
          };
        }

        // Hub select
        if (sql.includes("money_mode = 'INTERNAL_ONLY'") && sql.includes("FOR UPDATE OF w")) {
          const shortfall = Number(params[1] ?? "0");
          const hubs = wallets
            .filter((w) => {
              const f = modeFlags(w.mode);
              return (
                w.mode === "INTERNAL_ONLY" &&
                w.state === "AVAILABLE" &&
                f.allow_external_send === false &&
                f.allow_internal_move === true &&
                w.balance !== null &&
                Number(w.balance) >= shortfall &&
                !moveStore.activeLeases.has(w.id)
              );
            })
            .sort((a, b) => a.id.localeCompare(b.id));
          const pick = hubs[0];
          if (pick === undefined) return { rows: [] };
          return {
            rows: [
              {
                wallet_id: pick.id,
                observed_balance_zkz: pick.balance as string,
              } as R,
            ],
          };
        }

        // Hub liquidity count (busy vs none)
        if (sql.includes("count(*)::text AS n") && sql.includes("money_mode = 'INTERNAL_ONLY'")) {
          const shortfall = Number(params[1] ?? "0");
          const n = wallets.filter((w) => {
            const f = modeFlags(w.mode);
            return (
              w.mode === "INTERNAL_ONLY" &&
              f.allow_external_send === false &&
              f.allow_internal_move === true &&
              w.balance !== null &&
              Number(w.balance) >= shortfall
            );
          }).length;
          return { rows: [{ n: String(n) } as R] };
        }

        // Blessed destination for worker
        if (sql.includes("d.state = 'BLESSED'") && sql.includes("d.wallet_id = $1::uuid")) {
          const walletId = String(params[0]);
          const w = wallets.find((x) => x.id === walletId);
          if (w === undefined || w.destinationId === null) return { rows: [] };
          return { rows: [{ destination_id: w.destinationId } as R] };
        }

        throw new Error(`ScenarioWorld.sql: unhandled query: ${sql.slice(0, 160)}`);
      },
    };
  }
}

function idGen() {
  let n = 0;
  return () => {
    n += 1;
    return uuid(9000 + n);
  };
}

function compose(
  world: ScenarioWorld,
  opts: {
    amountZkz?: string;
    sourceWalletId?: string | null;
    idempotencyKey?: string;
    halt?: boolean;
    fundingWalletId?: string | null;
  } = {},
) {
  const halt = opts.halt === true;
  return assignAndTopUpExternalSend(
    {
      sql: world.sql(),
      moveStore: world.moveStore,
      sendStore: world.sendStore,
      sendSigner: signer,
      generateId: idGen(),
      now: () => FIXED_NOW,
      assertHaltAdmitsKind: halt
        ? () => {
            throw new Error("operations halted");
          }
        : undefined,
    },
    {
      implementerId: IMPLEMENTER_ID,
      nodeId: NODE_ID,
      sourceWalletId: opts.sourceWalletId === undefined ? null : opts.sourceWalletId,
      destinationAddress: DEST_EXTERNAL,
      amountZkz: opts.amountZkz ?? "2",
      clientReference: null,
      description: null,
      fundingWalletId:
        opts.fundingWalletId === undefined ? null : opts.fundingWalletId,
      idempotencyKey: opts.idempotencyKey ?? `idem-accept-${Date.now()}-${Math.random()}`.slice(0, 40),
      referencesOperationId: null,
    },
  );
}

/* ─── matrix catalogue presence ───────────────────────────────────────── */

describe("ZTR-1273 acceptance scenario catalogue", () => {
  it("freezes fourteen epic-exit cells (11 + ZTR-1289 funding hop)", () => {
    expect(ACCEPTANCE_SCENARIOS).toHaveLength(14);
    const ids = new Set(ACCEPTANCE_SCENARIOS.map((s) => s.id));
    expect(ids.size).toBe(14);
  });

  it("frozen worker SQL never selects INTERNAL_ONLY by money_mode (capability gate is allow_external_send)", () => {
    expect(SELECT_SEND_WORKER_SQL).toContain("allow_external_send IS TRUE");
    expect(SELECT_SEND_WORKER_SQL).not.toMatch(/money_mode\s*=\s*'INTERNAL_ONLY'/);
  });

  it("frozen hub SQL pins INTERNAL_ONLY and never allow_external_send", () => {
    expect(SELECT_TOPUP_HUB_SQL).toContain("money_mode = 'INTERNAL_ONLY'");
    expect(SELECT_TOPUP_HUB_SQL).toContain("allow_external_send IS FALSE");
  });
});

/* ─── S1–S8, S11 composition ──────────────────────────────────────────── */

describe("ZTR-1273 composition scenarios (assign + top-up)", () => {
  it("S1: hub INTERNAL_ONLY funded + worker SEND_ONLY empty → MOVE then SEND", async () => {
    const world = new ScenarioWorld();
    // Lower id hub first in ASC — single hub covers
    const hub = world.addWallet("INTERNAL_ONLY", {
      balance: "100",
      id: "c0000000-0000-4000-8000-0000000000a1",
      publicKey: HUB_PUB,
    });
    const worker = world.addWallet("SEND_ONLY", {
      balance: null,
      blessed: true,
      id: "c0000000-0000-4000-8000-0000000000b1",
      publicKey: WORKER_PUB,
    });

    const out = await compose(world, { amountZkz: "10", idempotencyKey: "idem-s1-hub-worker-0001" });
    expect(out.outcome).toBe("CREATED");
    if (out.outcome !== "CREATED") return;
    expect(out.funding).toBe("top_up");
    expect(out.workerWalletId).toBe(worker.id);
    expect(out.hubWalletId).toBe(hub.id);
    expect(out.shortfallZkz).toBe("10");
    expect(out.move).not.toBeNull();
    expect(out.move!.sourceWalletId).toBe(hub.id);
    expect(out.move!.destinationWalletId).toBe(worker.id);
    expect(out.send.sourceWalletId).toBe(worker.id);
    expect(out.send.referencesOperationId).toBe(out.move!.operationId);
  });

  it("S2: worker pre-funded SEND_ONLY → no MOVE", async () => {
    const world = new ScenarioWorld();
    const worker = world.addWallet("SEND_ONLY", {
      balance: "50",
      blessed: true,
      id: "c0000000-0000-4000-8000-0000000000b2",
      publicKey: WORKER_PUB,
    });
    // Hub present but must not be used
    world.addWallet("INTERNAL_ONLY", {
      balance: "100",
      id: "c0000000-0000-4000-8000-0000000000a2",
      publicKey: HUB_PUB,
    });

    const out = await compose(world, { amountZkz: "10", idempotencyKey: "idem-s2-funded-worker-01" });
    expect(out.outcome).toBe("CREATED");
    if (out.outcome !== "CREATED") return;
    expect(out.funding).toBe("funded");
    expect(out.move).toBeNull();
    expect(out.hubWalletId).toBeNull();
    expect(out.shortfallZkz).toBeNull();
    expect(out.workerWalletId).toBe(worker.id);
    expect(out.send.sourceWalletId).toBe(worker.id);
    expect(out.send.referencesOperationId).toBeNull();
  });

  it("S3: only INTERNAL_ONLY → reject external send", async () => {
    const world = new ScenarioWorld();
    world.addWallet("INTERNAL_ONLY", {
      balance: "100",
      id: "c0000000-0000-4000-8000-0000000000a3",
      publicKey: HUB_PUB,
    });
    const out = await compose(world, { idempotencyKey: "idem-s3-only-internal-001" });
    expect(out).toMatchObject({ outcome: "REJECTED", code: "no_free_send_worker" });
  });

  it("S4: only RECEIVE_ONLY → reject external send", async () => {
    const world = new ScenarioWorld();
    world.addWallet("RECEIVE_ONLY", {
      balance: "100",
      blessed: true,
      id: "c0000000-0000-4000-8000-0000000000c4",
      publicKey: OTHER_PUB,
    });
    const out = await compose(world, { idempotencyKey: "idem-s4-only-receive-0001" });
    expect(out).toMatchObject({ outcome: "REJECTED", code: "no_free_send_worker" });
  });

  it("S5: underfunded workers + empty hubs → no_hub_liquidity", async () => {
    const world = new ScenarioWorld();
    world.addWallet("SEND_ONLY", {
      balance: "1",
      blessed: true,
      id: "c0000000-0000-4000-8000-0000000000b5",
      publicKey: WORKER_PUB,
    });
    // Hub with zero observed balance is skipped (fail closed)
    world.addWallet("INTERNAL_ONLY", {
      balance: null,
      id: "c0000000-0000-4000-8000-0000000000a5",
      publicKey: HUB_PUB,
    });
    const out = await compose(world, { amountZkz: "10", idempotencyKey: "idem-s5-no-funds-0000001" });
    expect(out).toMatchObject({ outcome: "REJECTED", code: "no_hub_liquidity" });
  });

  it("S6: two hubs; only second covers → second hub", async () => {
    const world = new ScenarioWorld();
    const worker = world.addWallet("SEND_ONLY", {
      balance: "0",
      blessed: true,
      id: "c0000000-0000-4000-8000-0000000000b6",
      publicKey: WORKER_PUB,
    });
    // ASC: a1 first but cannot cover shortfall 10; a2 covers
    world.addWallet("INTERNAL_ONLY", {
      balance: "5",
      id: "c0000000-0000-4000-8000-0000000000a1",
      publicKey: HUB_PUB,
    });
    const hubHigh = world.addWallet("INTERNAL_ONLY", {
      balance: "100",
      id: "c0000000-0000-4000-8000-0000000000a2",
      publicKey: HUB_PUB,
    });

    const out = await compose(world, { amountZkz: "10", idempotencyKey: "idem-s6-second-hub-00001" });
    expect(out.outcome).toBe("CREATED");
    if (out.outcome !== "CREATED") return;
    expect(out.funding).toBe("top_up");
    expect(out.hubWalletId).toBe(hubHigh.id);
    expect(out.workerWalletId).toBe(worker.id);
    expect(out.move!.sourceWalletId).toBe(hubHigh.id);
  });

  it("S7: explicit source INTERNAL_ONLY → reject", async () => {
    const world = new ScenarioWorld();
    const hub = world.addWallet("INTERNAL_ONLY", {
      balance: "100",
      id: "c0000000-0000-4000-8000-0000000000a7",
      publicKey: HUB_PUB,
    });
    const out = await compose(world, {
      sourceWalletId: hub.id,
      amountZkz: "2",
      idempotencyKey: "idem-s7-explicit-hub-0001",
    });
    expect(out).toMatchObject({
      outcome: "REJECTED",
      code: "send_rejected",
      detail: "allow_external_send=false",
    });
  });

  it("S8: omit source → node assigns send-capable worker", async () => {
    const world = new ScenarioWorld();
    const worker = world.addWallet("SEND_ONLY", {
      balance: "20",
      blessed: true,
      id: "c0000000-0000-4000-8000-0000000000b8",
      publicKey: WORKER_PUB,
    });
    const out = await compose(world, {
      sourceWalletId: null,
      amountZkz: "5",
      idempotencyKey: "idem-s8-omit-source-00001",
    });
    expect(out.outcome).toBe("CREATED");
    if (out.outcome !== "CREATED") return;
    expect(out.workerWalletId).toBe(worker.id);
    expect(out.send.sourceWalletId).toBe(worker.id);
  });

  it("S11: halt blocks new formation before durable rows", async () => {
    const world = new ScenarioWorld();
    world.addWallet("SEND_ONLY", {
      balance: "20",
      blessed: true,
      id: "c0000000-0000-4000-8000-0000000000bb",
      publicKey: WORKER_PUB,
    });
    const out = await compose(world, {
      halt: true,
      idempotencyKey: "idem-s11-halt-blocks-0001",
    });
    expect(out).toMatchObject({ outcome: "REJECTED", code: "halted" });
    expect(world.sendStore.operations.size).toBe(0);
    expect(world.moveStore.operations.size).toBe(0);
  });

  it("S12: funding W hop preferred over multi-hub; source_wallet_id = sender", async () => {
    const world = new ScenarioWorld();
    const worker = world.addWallet("SEND_ONLY", {
      balance: "0",
      blessed: true,
      id: "c0000000-0000-4000-8000-0000000000c0",
      publicKey: WORKER_PUB,
    });
    const fundingW = world.addWallet("INTERNAL_ONLY", {
      balance: "50",
      id: "c0000000-0000-4000-8000-0000000000f1",
      publicKey: HUB_PUB,
    });
    // Competing hub that would win ASC multi-hub if W were ignored
    world.addWallet("INTERNAL_ONLY", {
      balance: "100",
      id: "c0000000-0000-4000-8000-0000000000a0",
      publicKey: OTHER_PUB,
    });

    const out = await compose(world, {
      amountZkz: "10",
      fundingWalletId: fundingW.id,
      idempotencyKey: "idem-s12-funding-hop-000001",
    });
    expect(out.outcome).toBe("CREATED");
    if (out.outcome !== "CREATED") return;
    expect(out.funding).toBe("top_up");
    expect(out.hubWalletId).toBe(fundingW.id);
    expect(out.fundingWalletId).toBe(fundingW.id);
    expect(out.workerWalletId).toBe(worker.id);
    expect(out.send.sourceWalletId).toBe(worker.id);
    expect(out.move!.sourceWalletId).toBe(fundingW.id);
    expect(out.move!.destinationWalletId).toBe(worker.id);
  });

  it("S13: dry W → insufficient_funding_wallet; no silent hub substitute", async () => {
    const world = new ScenarioWorld();
    world.addWallet("SEND_ONLY", {
      balance: "1",
      blessed: true,
      id: "c0000000-0000-4000-8000-0000000000c1",
      publicKey: WORKER_PUB,
    });
    const fundingW = world.addWallet("INTERNAL_ONLY", {
      balance: "0",
      id: "c0000000-0000-4000-8000-0000000000f2",
      publicKey: HUB_PUB,
    });
    // Hub would cover shortfall if multi-hub ran — must NOT be used
    world.addWallet("INTERNAL_ONLY", {
      balance: "100",
      id: "c0000000-0000-4000-8000-0000000000a9",
      publicKey: OTHER_PUB,
    });

    const out = await compose(world, {
      amountZkz: "10",
      fundingWalletId: fundingW.id,
      idempotencyKey: "idem-s13-funding-dry-000001",
    });
    expect(out).toMatchObject({
      outcome: "REJECTED",
      code: "insufficient_funding_wallet",
    });
    expect(world.moveStore.operations.size).toBe(0);
    expect(world.sendStore.operations.size).toBe(0);
  });

  it("S14: idempotent replay does not double-hop", async () => {
    const world = new ScenarioWorld();
    const worker = world.addWallet("SEND_ONLY", {
      balance: "0",
      blessed: true,
      id: "c0000000-0000-4000-8000-0000000000c2",
      publicKey: WORKER_PUB,
    });
    const fundingW = world.addWallet("INTERNAL_ONLY", {
      balance: "50",
      id: "c0000000-0000-4000-8000-0000000000f3",
      publicKey: HUB_PUB,
    });
    const key = "idem-s14-no-double-hop-0001";

    const first = await compose(world, {
      amountZkz: "10",
      fundingWalletId: fundingW.id,
      idempotencyKey: key,
    });
    expect(first.outcome).toBe("CREATED");
    if (first.outcome !== "CREATED") return;
    // Persist create response so early findByIdempotency can replay
    await world.sendStore.completeOperation(
      first.send.operationId,
      201,
      JSON.stringify({
        operation_id: first.send.operationId,
        source_wallet_id: first.send.sourceWalletId,
      }),
    );
    const moveCountAfterFirst = world.moveStore.operations.size;
    expect(moveCountAfterFirst).toBe(1);

    const second = await compose(world, {
      amountZkz: "10",
      fundingWalletId: fundingW.id,
      idempotencyKey: key,
    });
    expect(second.outcome).toBe("IDEMPOTENT_REPLAY");
    expect(world.moveStore.operations.size).toBe(moveCountAfterFirst);
    expect(world.sendStore.operations.size).toBe(1);
    expect(first.send.sourceWalletId).toBe(worker.id);
  });
});

/* ─── S9 receive assign + S10 MOVE between hubs ───────────────────────── */

describe("ZTR-1273 admission scenarios (receive / move)", () => {
  it("S9: SEND_ONLY never receive-assign eligible", () => {
    const flags = flagsFromMode("SEND_ONLY");
    expect(isEligibleForReceiveAssign(flags)).toBe(false);
    expect(isEligibleForSendSource(flags)).toBe(true);
    // Contracts + pure admission helpers agree
    expect(isSendSourceEligible({
      walletId: uuid(1),
      nodeId: NODE_ID,
      publicKey: WORKER_PUB,
      keyOrigin: "node_generated",
      state: "AVAILABLE",
      allowExternalSend: true,
    }, NODE_ID)).toBe(true);
  });

  it("S10: two INTERNAL_ONLY wallets may MOVE between them", async () => {
    const flags = flagsFromMode("INTERNAL_ONLY");
    expect(isEligibleForMoveParty(flags)).toBe(true);
    expect(isEligibleForSendSource(flags)).toBe(false);
    expect(isTopUpHubEligible(flags)).toBe(true);

    const hubA = uuid(10);
    const hubB = uuid(11);
    const destB = uuid(12);
    const source: MoveSourceWalletRecord = {
      walletId: hubA,
      nodeId: NODE_ID,
      publicKey: HUB_PUB,
      keyOrigin: "node_generated",
      state: "AVAILABLE",
      allowInternalMove: true,
    };
    const dest: MoveDestinationRecord = {
      destinationId: destB,
      nodeId: NODE_ID,
      walletId: hubB,
      publicKey: OTHER_PUB,
      keyOrigin: "node_generated",
      walletState: "AVAILABLE",
      destinationState: "BLESSED",
      recoveryVerifiedAt: "2026-07-01T00:00:00.000Z",
      allowInternalMove: true,
    };
    expect(isMoveSourceEligible(source, NODE_ID)).toBe(true);
    expect(isMoveDestinationEligible(dest, NODE_ID, hubA)).toEqual({ ok: true });

    const store = new MoveStore();
    store.sources.set(hubA, source);
    store.destinations.set(destB, dest);
    let n = 0;
    const out = await createInternalMove(
      store,
      {
        implementerId: IMPLEMENTER_ID,
        nodeId: NODE_ID,
        sourceWalletId: hubA,
        destinationId: destB,
        amountZkz: "3",
        idempotencyKey: "idem-s10-hub-to-hub-0001",
      },
      {
        generateId: () => {
          n += 1;
          return uuid(8000 + n);
        },
        now: () => FIXED_NOW,
      },
    );
    expect(out.outcome).toBe("CREATED");
    if (out.outcome !== "CREATED") return;
    expect(out.operation.sourceWalletId).toBe(hubA);
    expect(out.operation.destinationWalletId).toBe(hubB);
  });
});

/* ─── pure funding helper pins used by S1/S2 ──────────────────────────── */

describe("ZTR-1273 funding decision pins", () => {
  it("exact shortfall on underfunded worker (S1 amount math)", () => {
    expect(decideWorkerFunding("10", null)).toEqual({
      kind: "needs_topup",
      balanceZkz: "0",
      shortfallZkz: "10",
    });
    expect(decideWorkerFunding("10", "10")).toEqual({ kind: "funded", balanceZkz: "10" });
  });
});

