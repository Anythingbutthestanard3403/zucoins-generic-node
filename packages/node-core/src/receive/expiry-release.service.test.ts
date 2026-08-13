// receive expiry service branch, restart, and race tests.
// Governing:,3.5;
// (durable candidate/submit never terminally expires); walletless-receive expiry (lease +
// operation_wallets is receiver identity, not operations.receiver_wallet_id).

import { describe, expect, it } from "vitest";

import type {
  ActiveLeaseRow,
  SqlExecutor,
  SqlQueryResult,
} from "../leases/types.js";
import { ACK_STATEMENTS } from "../verification/acknowledgement-sql.js";
import {
  POST_EXPIRY_RECONCILING,
  RECEIVE_EXPIRED_RELEASE_STATUS,
  RECEIVE_PROVEN_NOT_STARTED_RELEASE_STATUS,
  RECEIVE_EXPIRY_RELEASE_STATEMENTS as S,
  SqlReceiveExpiryReleaseService,
  type ReceiveExpiryLeaseRepository,
} from "./expiry-release.js";

const OP = "10000000-0000-4000-8000-000000000001";
const WALLET = "10000000-0000-4000-8000-000000000002";
const MEMBER = "10000000-0000-4000-8000-000000000003";
const GROUP = "10000000-0000-4000-8000-000000000004";
const OWNER = "10000000-0000-4000-8000-000000000005";
const T0 = "10000000-0000-4000-8000-000000000006";
const FRESH = "10000000-0000-4000-8000-000000000007";

type Status = "CREATED" | "READY" | "RECEIVE_LANDED" | "EXPIRED";

interface Operation {
  id: string;
  status: Status;
  row_version: string;
  receiver_wallet_id: string | null;
  expiry_unix_time_secs: string | null;
  t0_observation_id: string | null;
  attention_required: boolean;
  attention_reason: string | null;
  attention_detail: string | null;
  attention_episode: string;
  receive_release_status: string | null;
  created_at: string;
}

interface Material {
  code_exists: boolean;
  code_status: string | null;
  code_expiry_unix_time_secs: string | null;
  arm_exists: boolean;
  artifact_exists: boolean;
  signer_audit_exists: boolean;
  candidate_exists: boolean;
  submit_exists: boolean;
  landed_proof_exists: boolean;
}

interface Observation {
  t0_id: string;
  t0_wallet_id: string;
  t0_wallet_public_key: string;
  t0_observer_domain: string;
  t0_s: string;
  t0_p: string;
  t0_b: string;
  fresh_id: string;
  fresh_wallet_id: string;
  fresh_wallet_public_key: string;
  fresh_observer_domain: string;
  expected_wallet_public_key: string;
  fresh_s: string;
  fresh_p: string;
  fresh_b: string;
  fresh_parse_result: string;
  fresh_relationship: string;
  fresh_observed_at: string;
  anomaly_exists: boolean;
}

function defaultLease(): ActiveLeaseRow {
  return {
    wallet_id: WALLET,
    membership_id: MEMBER,
    lease_group_id: GROUP,
    root_operation_id: OP,
    operation_id: OP,
    lease_role: "RECEIVE_WINDOW",
    lease_epoch: "7",
    acquired_at: "1970-01-01T00:00:00.000Z",
    heartbeat_at: "1970-01-01T00:00:00.000Z",
    owner_instance_id: OWNER,
    release_not_before: null,
  };
}

class ExpiryHarness implements SqlExecutor {
  operation: Operation = {
    id: OP,
    status: "READY",
    row_version: "1",
    // regression shape: the projection is null while the durable binding + lease exist.
    receiver_wallet_id: null,
    expiry_unix_time_secs: "1",
    t0_observation_id: null,
    attention_required: false,
    attention_reason: null,
    attention_detail: null,
    attention_episode: "0",
    receive_release_status: null,
    created_at: "1970-01-01T00:00:00.000Z",
  };
  lease: ActiveLeaseRow | undefined = defaultLease();
  binding: { wallet_id: string; t0_observation_id: string | null } | undefined = {
    wallet_id: WALLET,
    t0_observation_id: T0,
  };
  material: Material = {
    code_exists: true,
    code_status: "AWAITING_ARM",
    code_expiry_unix_time_secs: "1",
    arm_exists: false,
    artifact_exists: true,
    signer_audit_exists: false,
    candidate_exists: false,
    submit_exists: false,
    landed_proof_exists: false,
  };
  observation: Observation | undefined = {
    t0_id: T0,
    t0_wallet_id: WALLET,
    t0_wallet_public_key: "PUBKEY",
    t0_observer_domain: "NODE",
    t0_s: "S0",
    t0_p: "P0",
    t0_b: "10",
    fresh_id: FRESH,
    fresh_wallet_id: WALLET,
    fresh_wallet_public_key: "PUBKEY",
    fresh_observer_domain: "NODE",
    expected_wallet_public_key: "PUBKEY",
    fresh_s: "S0",
    fresh_p: "P0",
    fresh_b: "10",
    fresh_parse_result: "VERIFIED_HEAD",
    fresh_relationship: "DUPLICATE",
    fresh_observed_at: "1970-01-01T00:00:35.000Z",
    anomaly_exists: false,
  };
  childDisposition: "NONE" | "PENDING" | "JOINED" = "NONE";
  childOperations: Record<string, unknown>[] = [];
  childEvidence: Record<string, unknown>[] = [];
  expiredEvents = 0;
  lastExpiredData: string | null = null;
  attentionEvents = 0;
  lastAttentionData: string | null = null;
  receiveProofs = 0;
  walletState: "PINNED" | "QUARANTINED" | "AVAILABLE" = "PINNED";
  casRace: "none" | "landing" | "version" = "none";
  releaseFailure = false;
  readonly releaseCalls: string[] = [];

  readonly repository: ReceiveExpiryLeaseRepository = {
    completeGroupOperation: async () => {
      this.releaseCalls.push("complete");
    },
    mintReleaseProof: async () => {
      this.releaseCalls.push("mint");
    },
    releaseLease: async () => {
      this.releaseCalls.push("release");
      if (this.releaseFailure) throw new Error("release failed");
      this.walletState = "AVAILABLE";
      this.lease = undefined;
    },
  };

  readonly txFactory = {
    withTransaction: async <T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T> =>
      fn(this),
  };

  service(): SqlReceiveExpiryReleaseService {
    return new SqlReceiveExpiryReleaseService(this.txFactory, this.repository);
  }

  private result<R>(rows: readonly unknown[], rowCount = rows.length): SqlQueryResult<R> {
    return { rows: rows as R[], rowCount };
  }

  async query<R>(
    text: string,
    _params: readonly unknown[] = [],
  ): Promise<SqlQueryResult<R>> {
    if (text === S.LOCK_OPERATION) return this.result<R>([this.operation]);
    if (text === S.LOCK_RECEIVER_LEASE) {
      return this.result<R>(this.lease === undefined ? [] : [this.lease]);
    }
    if (text === S.LOAD_RECEIVER_BINDING) {
      return this.result<R>(this.binding === undefined ? [] : [this.binding]);
    }
    if (text === S.LOAD_MATERIAL_FACTS) return this.result<R>([this.material]);
    if (text === S.LOAD_OBSERVATIONS) {
      return this.result<R>(this.observation === undefined ? [] : [this.observation]);
    }
    if (text === ACK_STATEMENTS.SELECT_GROUP_CHILD_DISPOSITION) {
      return this.result<R>([{ child_disposition: this.childDisposition }]);
    }
    if (text === ACK_STATEMENTS.SELECT_GROUP_OPERATION_FACTS) {
      return this.result<R>([
        {
          operation_id: OP,
          kind: "RECEIVE_EXTERNAL",
          verdict: null,
          completed: false,
          joined_at: "1970-01-01T00:00:00.000000",
          source_wallet_id: null,
          source_public_key: null,
          receiver_wallet_id: WALLET,
          receiver_public_key: "PUBKEY",
          destination_address: null,
          destination_wallet_id: null,
          destination_public_key: null,
          acknowledgement_id: null,
        },
        ...this.childOperations,
      ]);
    }
    if (text === ACK_STATEMENTS.SELECT_ACK_EVIDENCE) {
      return this.result<R>(this.childEvidence);
    }
    if (text === S.REVOKE_CODE) {
      const changed =
        this.material.code_status === "AWAITING_ARM" ||
        this.material.code_status === "RELEASED";
      this.material.code_status = "EXPIRED";
      return this.result<R>(changed ? [{ operation_id: OP }] : []);
    }
    if (text === S.CAS_UNASSIGNED_TO_EXPIRED || text === S.CAS_TO_EXPIRED) {
      if (this.casRace === "landing") {
        this.operation.status = "RECEIVE_LANDED";
        this.operation.row_version = "2";
        return this.result<R>([]);
      }
      if (this.casRace === "version") {
        this.operation.row_version = "2";
        return this.result<R>([]);
      }
      this.operation.status = "EXPIRED";
      this.operation.row_version = String(Number(this.operation.row_version) + 1);
      return this.result<R>([
        { status: "EXPIRED", row_version: this.operation.row_version },
      ]);
    }
    if (text === S.APPEND_EXPIRED_EVENT) {
      if (this.expiredEvents > 0) return this.result<R>([]);
      this.expiredEvents += 1;
      this.lastExpiredData = String(_params[2]);
      return this.result<R>([{ event_id: "1" }]);
    }
    if (text === S.OPEN_ATTENTION_EPISODE) {
      if (this.operation.attention_required) return this.result<R>([]);
      const params = _params;
      this.operation.attention_required = true;
      this.operation.attention_reason = String(params[1]);
      this.operation.attention_detail = String(params[2]);
      this.operation.attention_episode = String(
        Number(this.operation.attention_episode) + 1,
      );
      this.lastAttentionData = JSON.stringify({
        current_state: this.operation.status,
        attention_reason: this.operation.attention_reason,
        attention_episode: Number(this.operation.attention_episode),
        operator_action_required: true,
        failed_predicates: JSON.parse(String(params[4])),
        // ZTR-1279: durable detail JSON (params[2]) is also mirrored here for asserts.
        attention_detail: JSON.parse(String(params[2])),
      });
      this.operation.row_version = String(Number(this.operation.row_version) + 1);
      this.attentionEvents += 1;
      return this.result<R>([
        {
          status: this.operation.status,
          attention_episode: this.operation.attention_episode,
          event_id: String(this.attentionEvents),
        },
      ]);
    }
    if (text === S.LOAD_ATTENTION) {
      return this.result<R>([this.operation]);
    }
    if (text === S.ESCALATE_ATTENTION_TO_RECONCILING) {
      if (!this.operation.attention_required) return this.result<R>([]);
      this.operation.attention_reason = String(_params[1]);
      this.operation.attention_detail = String(_params[2]);
      this.operation.row_version = String(Number(this.operation.row_version) + 1);
      return this.result<R>([
        {
          status: this.operation.status,
          attention_reason: this.operation.attention_reason,
          attention_episode: this.operation.attention_episode,
        },
      ]);
    }
    if (text === S.LOAD_CURRENT_STATUS) {
      return this.result<R>([this.operation]);
    }
    if (text === S.INSERT_RECEIVE_RELEASE_PROOF) {
      this.receiveProofs += 1;
      return this.result<R>([{ id: String(_params[0]) }]);
    }
    if (text === S.SET_RELEASE_STATUS) {
      if (
        this.operation.status !== "EXPIRED" ||
        this.operation.receive_release_status !== null
      ) {
        return this.result<R>([]);
      }
      this.operation.receive_release_status = String(_params[1]);
      this.operation.attention_required = false;
      this.operation.attention_reason = null;
      return this.result<R>([
        { receive_release_status: this.operation.receive_release_status },
      ]);
    }
    if (text === S.QUARANTINE_WALLET) {
      if (this.walletState === "AVAILABLE") return this.result<R>([]);
      this.walletState = "QUARANTINED";
      return this.result<R>([{ state: "QUARANTINED" }]);
    }
    throw new Error(`unexpected expiry SQL: ${text}`);
  }
}

const run = (
  harness: ExpiryHarness,
  overrides: Partial<Parameters<SqlReceiveExpiryReleaseService["expire"]>[0]> = {},
) =>
  harness.service().expire({
    operationId: OP,
    freshObservationId: FRESH,
    nowMs: 40_000,
    newId: (() => {
      let n = 0;
      return () => `20000000-0000-4000-8000-${String(++n).padStart(12, "0")}`;
    })(),
    ...overrides,
  });

describe("receive expiry branch behaviour", () => {
  it("expires an unassigned queue timeout once with no release", async () => {
    const h = new ExpiryHarness();
    h.operation.status = "CREATED";
    h.operation.expiry_unix_time_secs = null;
    h.operation.created_at = "1970-01-01T00:00:00.000Z";
    h.lease = undefined;
    h.binding = undefined;
    h.material.code_exists = false;
    h.material.code_status = null;
    h.material.code_expiry_unix_time_secs = null;
    h.material.artifact_exists = false;

    const first = await run(h, {
      freshObservationId: null,
      nowMs: 30_001,
      queueMaxWaitMs: 30_000,
    });
    const restart = await run(h, {
      freshObservationId: null,
      nowMs: 30_002,
      queueMaxWaitMs: 30_000,
    });

    expect(first).toEqual({
      kind: "EXPIRED_UNASSIGNED",
      status: "EXPIRED",
      eventAppended: true,
    });
    expect(restart).toEqual({
      kind: "EXPIRED_UNASSIGNED",
      status: "EXPIRED",
      eventAppended: false,
    });
    expect(h.expiredEvents).toBe(1);
    expect(h.lastExpiredData).toBe(
      '{"previous_state":"CREATED","expired_at":"1970-01-01T00:00:30.001Z","wallet_assigned":false,"release_status":null}',
    );
    expect(h.releaseCalls).toEqual([]);
  });

  it("checks the attention hold candidate boundary before damaged unassigned linkage", async () => {
    const h = new ExpiryHarness();
    h.operation.status = "CREATED";
    h.lease = undefined;
    h.binding = undefined;
    h.material.candidate_exists = true;

    const result = await run(h, { freshObservationId: null });

    expect(result.kind).toBe("NEEDS_ATTENTION");
    if (result.kind !== "NEEDS_ATTENTION") return;
    expect(result.status).toBe("CREATED");
    expect(result.attentionReason).toBe(POST_EXPIRY_RECONCILING);
    expect(h.operation.status).toBe("CREATED");
    expect(h.expiredEvents).toBe(0);
    expect(h.releaseCalls).toEqual([]);
  });

  it.each([
    ["candidate", { candidate_exists: true }],
    ["phantom ACK submit", { submit_exists: true }],
    ["late landing proof", { landed_proof_exists: true }],
  ] as const)(
    "holds READY for durable %s, revokes code, and never emits operation.expired",
    async (_name, evidence) => {
      const h = new ExpiryHarness();
      Object.assign(h.material, evidence);

      const first = await run(h);
      const restart = await run(h);

      expect(first.kind).toBe("NEEDS_ATTENTION");
      if (first.kind === "NEEDS_ATTENTION") {
        expect(first.status).toBe("READY");
        expect(first.attentionReason).toBe(POST_EXPIRY_RECONCILING);
        expect(first.eventAppended).toBe(true);
      }
      expect(restart.kind).toBe("NEEDS_ATTENTION");
      if (restart.kind === "NEEDS_ATTENTION") {
        expect(restart.eventAppended).toBe(false);
      }
      expect(h.operation.status).toBe("READY");
      expect(h.material.code_status).toBe("EXPIRED");
      expect(h.expiredEvents).toBe(0);
      expect(h.attentionEvents).toBe(1);
      expect(JSON.parse(h.lastAttentionData ?? "{}")).toMatchObject({
        current_state: "READY",
        attention_reason: POST_EXPIRY_RECONCILING,
      });
      expect(h.releaseCalls).toEqual([]);
      expect(h.walletState).toBe("PINNED");
    },
  );

  it("quarantines signer-use with missing exact bytes and preserves the lease", async () => {
    const h = new ExpiryHarness();
    h.material.code_exists = false;
    h.material.code_status = null;
    h.material.artifact_exists = false;
    h.material.signer_audit_exists = true;

    const result = await run(h);

    expect(result).toMatchObject({
      kind: "INVARIANT_BREACH",
      status: "READY",
      attentionReason: "EXACT_BYTES_UNAVAILABLE",
      walletId: WALLET,
      walletState: "QUARANTINED",
      activeLeasePreserved: true,
    });
    expect(h.walletState).toBe("QUARANTINED");
    expect(h.lease?.wallet_id).toBe(WALLET);
    expect(h.expiredEvents).toBe(0);
    expect(h.releaseCalls).toEqual([]);
  });
});

describe("assigned expired-unpaid release", () => {
  it("releases PROVEN_NOT_STARTED when lease holds and T0/code/artifact/signer are all absent", async () => {
    const h = new ExpiryHarness();
    h.operation.status = "CREATED";
    h.operation.expiry_unix_time_secs = null;
    h.operation.t0_observation_id = null;
    h.binding = { wallet_id: WALLET, t0_observation_id: null };
    h.material.code_exists = false;
    h.material.code_status = null;
    h.material.code_expiry_unix_time_secs = null;
    h.material.artifact_exists = false;
    h.material.arm_exists = false;
    h.material.signer_audit_exists = false;
    h.observation = undefined;

    const result = await run(h, {
      freshObservationId: null,
      nowMs: 60_000,
      queueMaxWaitMs: 30_000,
    });

    expect(result).toMatchObject({
      kind: "RELEASED",
      status: "EXPIRED",
      releaseStatus: RECEIVE_PROVEN_NOT_STARTED_RELEASE_STATUS,
      walletId: WALLET,
      walletState: "AVAILABLE",
    });
    expect(h.releaseCalls).toEqual(["complete", "mint", "release"]);
    expect(h.walletState).toBe("AVAILABLE");
    expect(h.expiredEvents).toBe(1);
    expect(h.receiveProofs).toBe(1);
    expect(h.lastExpiredData).toBe(
      '{"previous_state":"CREATED","expired_at":"1970-01-01T00:01:00.000Z","wallet_assigned":true,"release_status":"RELEASED_PROVEN_NOT_STARTED"}',
    );
  });

  it.each([
    ["code present", { code_exists: true, code_status: "AWAITING_ARM", code_expiry_unix_time_secs: "1" }],
    ["artifact present", { artifact_exists: true }],
    ["arm present", { arm_exists: true }],
    ["candidate present", { candidate_exists: true }],
    ["T0 already bound", null],
  ] as const)(
    "does not take PROVEN_NOT_STARTED when %s",
    async (name, materialPatch) => {
      const h = new ExpiryHarness();
      h.operation.status = "CREATED";
      h.operation.expiry_unix_time_secs = null;
      h.operation.t0_observation_id = null;
      h.material.code_exists = false;
      h.material.code_status = null;
      h.material.code_expiry_unix_time_secs = null;
      h.material.artifact_exists = false;
      h.material.arm_exists = false;
      h.observation = undefined;
      if (name === "T0 already bound") {
        h.binding = { wallet_id: WALLET, t0_observation_id: T0 };
      } else if (materialPatch !== null) {
        h.binding = { wallet_id: WALLET, t0_observation_id: null };
        Object.assign(h.material, materialPatch);
      }

      const result = await run(h, {
        freshObservationId: null,
        nowMs: 60_000,
        queueMaxWaitMs: 30_000,
      });

      expect(result.kind).not.toBe("RELEASED");
      if (result.kind === "RELEASED") {
        expect(result.releaseStatus).not.toBe(
          RECEIVE_PROVEN_NOT_STARTED_RELEASE_STATUS,
        );
      }
      expect(h.walletState).toBe("PINNED");
    },
  );

  it("restart after PROVEN_NOT_STARTED is ALREADY_RELEASED without a second proof", async () => {
    const h = new ExpiryHarness();
    h.operation.status = "CREATED";
    h.operation.expiry_unix_time_secs = null;
    h.operation.t0_observation_id = null;
    h.binding = { wallet_id: WALLET, t0_observation_id: null };
    h.material.code_exists = false;
    h.material.code_status = null;
    h.material.code_expiry_unix_time_secs = null;
    h.material.artifact_exists = false;
    h.observation = undefined;

    const first = await run(h, {
      freshObservationId: null,
      nowMs: 60_000,
      queueMaxWaitMs: 30_000,
    });
    expect(first.kind).toBe("RELEASED");
    const restart = await run(h, {
      freshObservationId: null,
      nowMs: 60_001,
      queueMaxWaitMs: 30_000,
    });
    expect(restart).toEqual({
      kind: "ALREADY_RELEASED",
      status: "EXPIRED",
      releaseStatus: RECEIVE_PROVEN_NOT_STARTED_RELEASE_STATUS,
    });
    expect(h.receiveProofs).toBe(1);
  });

  it("releases the reachable pre-code walletless projection only after fresh exact T0", async () => {
    const h = new ExpiryHarness();
    h.operation.status = "CREATED";
    h.operation.expiry_unix_time_secs = null;
    h.material.code_exists = false;
    h.material.code_status = null;
    h.material.code_expiry_unix_time_secs = null;
    h.material.artifact_exists = false;
    h.observation!.fresh_observed_at = "1970-01-01T00:01:00.000Z";

    const result = await run(h, {
      nowMs: 60_000,
      queueMaxWaitMs: 30_000,
    });

    expect(result).toMatchObject({
      kind: "RELEASED",
      status: "EXPIRED",
      releaseStatus: RECEIVE_EXPIRED_RELEASE_STATUS,
      receiveReleaseProofId: expect.any(String),
      walletId: WALLET,
      walletState: "AVAILABLE",
    });
    expect(h.releaseCalls).toEqual(["complete", "mint", "release"]);
    expect(h.walletState).toBe("AVAILABLE");
    expect(h.expiredEvents).toBe(1);
    expect(h.receiveProofs).toBe(1);
    expect(h.lastExpiredData).toBe(
      '{"previous_state":"CREATED","expired_at":"1970-01-01T00:01:00.000Z","wallet_assigned":true,"release_status":"RELEASED_T0_UNCHANGED"}',
    );
  });

  it.each([
    ["operation expiry absent", null, "1"],
    ["code expiry absent", "1", null],
    ["both expiries absent", null, null],
    ["expiry bytes differ", "1", "01"],
  ] as const)(
    "retains the lease when %s",
    async (_name, operationExpiry, codeExpiry) => {
      const h = new ExpiryHarness();
      h.operation.expiry_unix_time_secs = operationExpiry;
      h.material.code_expiry_unix_time_secs = codeExpiry;

      const result = await run(h);

      expect(result).toMatchObject({
        kind: "NEEDS_ATTENTION",
        attentionReason: "T0_RELEASE_MISMATCH",
      });
      expect(h.operation.status).toBe("READY");
      expect(h.expiredEvents).toBe(0);
      expect(h.releaseCalls).toEqual([]);
      expect(h.walletState).toBe("PINNED");
      // ZTR-1279: attention_detail must name the failed predicate, not bare reason alone.
      if (result.kind === "NEEDS_ATTENTION") {
        const detail = JSON.parse(result.attentionDetail) as {
          failed_predicates: string[];
          predicate_causes: { predicate: string; cause: string }[];
        };
        expect(detail.failed_predicates).toContain("EXPIRY_PLUS_SAFETY_MARGIN");
        expect(detail.predicate_causes[0]?.cause.length).toBeGreaterThan(10);
      }
    },
  );

  it("stamps fresh-read outcome into attention_detail when supplied (ZTR-1279)", async () => {
    const h = new ExpiryHarness();
    h.observation = undefined; // force FRESH_VERIFIED_T0_EXACT failure path via missing observations

    const result = await run(h, {
      freshObservationId: null,
      freshReadOutcome: { kind: "skipped", reason: "wallet_row_undefined" },
    });

    expect(result.kind).toBe("NEEDS_ATTENTION");
    if (result.kind === "NEEDS_ATTENTION") {
      const detail = JSON.parse(result.attentionDetail) as {
        failed_predicates: string[];
        predicate_causes: { predicate: string; cause: string }[];
        fresh_read: { kind: string; reason: string; summary: string };
      };
      expect(detail.failed_predicates).toContain("FRESH_VERIFIED_T0_EXACT");
      const freshCause = detail.predicate_causes.find(
        (c) => c.predicate === "FRESH_VERIFIED_T0_EXACT",
      );
      expect(freshCause?.cause).toMatch(/skipped/i);
      expect(freshCause?.cause).toMatch(/wallet_row_undefined/);
      expect(detail.fresh_read).toMatchObject({
        kind: "skipped",
        reason: "wallet_row_undefined",
        summary: "skipped:wallet_row_undefined",
      });
    }
  });

  it.each([
    ["foreign T0 wallet", (h: ExpiryHarness) => {
      h.observation!.t0_wallet_id = OWNER;
    }],
    ["foreign fresh wallet", (h: ExpiryHarness) => {
      h.observation!.fresh_wallet_id = OWNER;
    }],
    ["foreign T0 public key", (h: ExpiryHarness) => {
      h.observation!.t0_wallet_public_key = "FOREIGN";
    }],
    ["foreign fresh public key", (h: ExpiryHarness) => {
      h.observation!.fresh_wallet_public_key = "FOREIGN";
    }],
    ["platform T0 observer", (h: ExpiryHarness) => {
      h.observation!.t0_observer_domain = "PLATFORM";
    }],
    ["platform fresh observer", (h: ExpiryHarness) => {
      h.observation!.fresh_observer_domain = "PLATFORM";
    }],
  ] as const)("rejects %s as release evidence", async (_name, mutate) => {
    const h = new ExpiryHarness();
    mutate(h);

    const result = await run(h);

    expect(result.kind).toBe("NEEDS_ATTENTION");
    expect(h.releaseCalls).toEqual([]);
    expect(h.walletState).toBe("PINNED");
  });

  it.each(["REJECTED", "INDETERMINATE"] as const)(
    "pins when a child acknowledgement verdict is %s",
    async (verdict) => {
      const h = new ExpiryHarness();
      h.childDisposition = "JOINED";
      h.childOperations = [
        {
          operation_id: OWNER,
          kind: "RECEIVE_EXTERNAL",
          verdict,
          completed: true,
          joined_at: "1970-01-01T00:00:01.000000",
          source_wallet_id: null,
          source_public_key: null,
          receiver_wallet_id: WALLET,
          receiver_public_key: "PUBKEY",
          destination_address: null,
          destination_wallet_id: null,
          destination_public_key: null,
          acknowledgement_id: MEMBER,
        },
      ];

      const result = await run(h);

      expect(result.kind).toBe("NEEDS_ATTENTION");
      if (result.kind === "NEEDS_ATTENTION") {
        expect(result.failedPredicates).toContain(
          "CHILD_ABSENT_OR_SAFE_TERMINAL",
        );
      }
      expect(h.releaseCalls).toEqual([]);
    },
  );

  it("escalates an existing attention episode to POST_EXPIRY_RECONCILING without a second event", async () => {
    const h = new ExpiryHarness();
    h.observation!.fresh_b = "9";
    const first = await run(h);
    expect(first).toMatchObject({
      kind: "NEEDS_ATTENTION",
      attentionReason: "T0_RELEASE_MISMATCH",
      eventAppended: true,
    });

    h.material.candidate_exists = true;
    const escalated = await run(h);

    expect(escalated).toMatchObject({
      kind: "NEEDS_ATTENTION",
      attentionReason: POST_EXPIRY_RECONCILING,
      attentionEpisode: 1,
      eventAppended: false,
    });
    expect(h.operation.attention_reason).toBe(POST_EXPIRY_RECONCILING);
    expect(h.attentionEvents).toBe(1);
  });

  it("does not emit the assigned expiry event before guarded release succeeds", async () => {
    const h = new ExpiryHarness();
    h.releaseFailure = true;

    await expect(run(h)).rejects.toThrow("release failed");

    expect(h.expiredEvents).toBe(0);
    expect(h.lastExpiredData).toBeNull();
  });

  it.each([
    ["T0 mutation", (h: ExpiryHarness): void => {
      h.observation!.fresh_b = "9";
    }],
    ["observation anomaly", (h: ExpiryHarness): void => {
      h.observation!.anomaly_exists = true;
    }],
    [
      "lineage gap",
      (h: ExpiryHarness): void => {
        h.observation!.fresh_relationship = "UNEXPLAINED_JUMP";
      },
    ],
    ["pre-margin fresh read", (h: ExpiryHarness): void => {
      h.observation!.fresh_observed_at = "1970-01-01T00:00:30.000Z";
    }],
    ["pending child", (h: ExpiryHarness): void => {
      h.childDisposition = "PENDING";
    }],
  ] as const)(
    "keeps the wallet pinned on %s",
    async (_name, mutate: (harness: ExpiryHarness) => void) => {
      const h = new ExpiryHarness();
      mutate(h);

      const result = await run(h);

      expect(result.kind).toBe("NEEDS_ATTENTION");
      expect(h.operation.status).toBe("EXPIRED");
      expect(JSON.parse(h.lastAttentionData ?? "{}")).toMatchObject({
        current_state: "EXPIRED",
      });
      expect(h.walletState).toBe("PINNED");
      expect(h.lease?.wallet_id).toBe(WALLET);
      expect(h.releaseCalls).toEqual([]);
    },
  );

  it("restarts idempotently after a committed release", async () => {
    const h = new ExpiryHarness();
    const first = await run(h);
    const restart = await run(h);

    expect(first.kind).toBe("RELEASED");
    expect(restart).toEqual({
      kind: "ALREADY_RELEASED",
      status: "EXPIRED",
      releaseStatus: RECEIVE_EXPIRED_RELEASE_STATUS,
    });
    expect(h.releaseCalls).toEqual(["complete", "mint", "release"]);
    expect(h.receiveProofs).toBe(1);
  });
});

describe("landing/expiry CAS orderings", () => {
  it("landing wins first: expiry observes RECEIVE_LANDED and mutates no lease", async () => {
    const h = new ExpiryHarness();
    h.operation.status = "RECEIVE_LANDED";

    expect(await run(h)).toEqual({
      kind: "LANDED",
      status: "RECEIVE_LANDED",
    });
    expect(h.expiredEvents).toBe(0);
    expect(h.releaseCalls).toEqual([]);
  });

  it("landing wins the CAS race: expiry reports LANDED, never EXPIRED", async () => {
    const h = new ExpiryHarness();
    h.casRace = "landing";

    expect(await run(h)).toEqual({
      kind: "LANDED",
      status: "RECEIVE_LANDED",
    });
    expect(h.expiredEvents).toBe(0);
    expect(h.releaseCalls).toEqual([]);
  });

  it("unrelated row-version movement fails closed as CONFLICT", async () => {
    const h = new ExpiryHarness();
    h.casRace = "version";

    expect(await run(h)).toEqual({
      kind: "CONFLICT",
      status: "READY",
      reason: "STATUS_OR_ROW_VERSION_CHANGED",
    });
    expect(h.expiredEvents).toBe(0);
    expect(h.releaseCalls).toEqual([]);
  });
});
