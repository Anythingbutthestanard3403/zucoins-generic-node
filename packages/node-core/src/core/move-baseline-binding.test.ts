import { describe, expect, it } from "vitest";

import { GENESIS_PROJECTION, type WalletStateProjection } from "../protocol/wallet-role.js";
import {
  captureAndBindMoveBaselines,
  STATEMENTS,
  type MoveBaselineBindingInput,
  type MoveBaselineObserver,
  type MoveT0ObservationRole,
  type ObservationOutcome,
  type SqlExecutor,
} from "./move-baseline-binding.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const ARTIFACT_ID = "99999999-9999-4999-8999-999999999999";
const DESTINATION_WALLET_ID = "44444444-4444-4444-8444-444444444444";
const SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const DESTINATION_ID = "66666666-6666-4666-8666-666666666666";
const SOURCE_PUBKEY = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DESTINATION_PUBKEY = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const SOURCE_OBSERVATION = "aaaaaaaa-0000-4000-8000-000000000001";
const DESTINATION_OBSERVATION = "aaaaaaaa-0000-4000-8000-000000000002";
const SIGNING_KEY_ID = "bbbbbbbb-0000-4000-8000-000000000001";
const SIGNATURE = `${"A".repeat(86)}==`;

function senderProjection(b: string): WalletStateProjection {
  return { role: "sender", S: "sig-s", P: "sig-p", B: b, I: "digest" };
}

function receiverProjection(b: string): WalletStateProjection {
  return { role: "receiver", S: "sig-s", P: "sig-p", B: b, I: "digest" };
}

/** Records every port call in sequence, so a test can assert what did NOT happen. */
class Recorder {
  readonly calls: string[] = [];

  observer(
    source: ObservationOutcome,
    destination: ObservationOutcome,
  ): MoveBaselineObserver {
    return {
      observe: (walletPublicKey: string, role: MoveT0ObservationRole) => {
        this.calls.push(`observe:${role}`);
        return Promise.resolve(role === "MOVE_SOURCE_T0" ? source : destination);
      },
    };
  }

  destinations(eligible: boolean) {
    return {
      recheckDestination: () => {
        this.calls.push("recheck");
        return Promise.resolve({
          eligible,
          detail: eligible ? "BLESSED, recovery verified" : "destination RETIRED after admission",
        });
      },
    };
  }

  signer() {
    return {
      signWithNodeIdentity: (preimageBytes: Uint8Array) => {
        this.calls.push(`sign:${preimageBytes.length}`);
        return Promise.resolve({ signingKeyId: SIGNING_KEY_ID, signature: SIGNATURE });
      },
    };
  }

  sql(failWith?: Error): SqlExecutor {
    return {
      query: <R,>(text: string, params: readonly unknown[]) => {
        const label = Object.entries(STATEMENTS).find(([, sql]) => sql === text)?.[0] ?? "UNKNOWN";
        this.calls.push(`sql:${label}:${String(params[2] ?? "")}`);
        if (failWith !== undefined) return Promise.reject(failWith);
        return Promise.resolve({ rows: [] as R[] });
      },
    };
  }

  get writes(): string[] {
    return this.calls.filter((call) => call.startsWith("sql:"));
  }

  get signatures(): string[] {
    return this.calls.filter((call) => call.startsWith("sign:"));
  }
}

const verified = (
  observationId: string,
  projection: WalletStateProjection,
): ObservationOutcome => ({ kind: "VERIFIED", observationId, projection });

function inputOf(
  recorder: Recorder,
  overrides: Partial<MoveBaselineBindingInput> = {},
): MoveBaselineBindingInput {
  return {
    nodeId: NODE_ID,
    implementerId: IMPLEMENTER_ID,
    operationId: OPERATION_ID,
    expectedArtifactId: ARTIFACT_ID,
    sourceWalletId: SOURCE_WALLET_ID,
    sourceWalletPublicKey: SOURCE_PUBKEY,
    destinationId: DESTINATION_ID,
    destinationWalletId: DESTINATION_WALLET_ID,
    destinationWalletPublicKey: DESTINATION_PUBKEY,
    amountZkz: "2.25",
    spawnedFromOperationId: null,
    referencesOperationId: null,
    sourceLease: { role: "MOVE_SOURCE", lifecycle: "ACTIVE" },
    destinationLease: { role: "MOVE_DESTINATION", lifecycle: "ACTIVE" },
    capturedAt: 1700000000000,
    observer: recorder.observer(
      verified(SOURCE_OBSERVATION, senderProjection("10")),
      verified(DESTINATION_OBSERVATION, receiverProjection("5")),
    ),
    destinations: recorder.destinations(true),
    signer: recorder.signer(),
    sql: recorder.sql(),
    ...overrides,
  };
}

describe("captureAndBindMoveBaselines — steps 2-5", () => {
  it("persists both bindings, the evidence row, and the artifact before returning", async () => {
    const recorder = new Recorder();
    const result = await captureAndBindMoveBaselines(inputOf(recorder));

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(recorder.calls).toEqual([
      "observe:MOVE_SOURCE_T0",
      "observe:MOVE_DESTINATION_T0",
      "recheck",
      `sign:${result.binding.artifact.preimageText.length}`,
      "sql:INSERT_EVIDENCE:" + DESTINATION_OBSERVATION,
      "sql:INSERT_BINDING:SOURCE_T0",
      "sql:INSERT_BINDING:DESTINATION_T0",
      "sql:INSERT_ARTIFACT:zp-move-internal-expected-v1",
    ]);
    expect(result.binding.artifact.purpose).toBe("zp-move-internal-expected-v1");
    expect(result.binding.artifact.canonicalVersion).toBe(1);
    expect(result.binding.artifact.signingKeyId).toBe(SIGNING_KEY_ID);
    expect(result.binding.sourceT0ObservationId).toBe(SOURCE_OBSERVATION);
    expect(result.binding.destinationT0ObservationId).toBe(DESTINATION_OBSERVATION);
  });

  it("binds both wallet identities and the destination id into the preimage", async () => {
    const recorder = new Recorder();
    const result = await captureAndBindMoveBaselines(inputOf(recorder));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const [prefix, payload] = result.binding.artifact.preimageText.split("\n");
    expect(prefix).toBe("zp-move-internal-expected-v1");
    expect(payload).toContain(`"source_pubkey":"${SOURCE_PUBKEY}"`);
    expect(payload).toContain(`"destination_pubkey":"${DESTINATION_PUBKEY}"`);
    expect(payload).toContain(`"destination_id":"${DESTINATION_ID}"`);
    expect(payload).toContain(`"amount_zkz":"2.25"`);
    expect(payload).toContain(`"spawned_from_operation_id":null`);
    expect(payload).toContain(`"references_operation_id":null`);
  });

  it("carries a non-null spawned_from / references pair into the bound bytes", async () => {
    const recorder = new Recorder();
    const parent = "77777777-7777-4777-8777-777777777777";
    const result = await captureAndBindMoveBaselines(
      inputOf(recorder, { spawnedFromOperationId: parent, referencesOperationId: parent }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.binding.artifact.preimageText).toContain(
      `"spawned_from_operation_id":"${parent}"`,
    );
    expect(result.binding.artifact.preimageText).toContain(
      `"references_operation_id":"${parent}"`,
    );
  });
});

describe("every rejection persists nothing and signs nothing", () => {
  // Any response that cannot support an unambiguous projection is INDETERMINATE; it must
  // never be treated as an empty wallet or a zero balance.
  const indeterminate: ObservationOutcome = {
    kind: "INDETERMINATE",
    detail: "gateway head unparseable",
  };
  const unverified: ObservationOutcome = {
    kind: "UNVERIFIED",
    detail: "signature chain did not verify",
  };

  const cases: ReadonlyArray<{
    readonly name: string;
    readonly reason: string;
    readonly build: (recorder: Recorder) => Partial<MoveBaselineBindingInput>;
  }> = [
    {
      name: "an INDETERMINATE source read",
      reason: "source_observation_indeterminate",
      build: (r) => ({
        observer: r.observer(indeterminate, verified(DESTINATION_OBSERVATION, GENESIS_PROJECTION)),
      }),
    },
    {
      name: "an INDETERMINATE destination read",
      reason: "destination_observation_indeterminate",
      build: (r) => ({
        observer: r.observer(verified(SOURCE_OBSERVATION, senderProjection("10")), indeterminate),
      }),
    },
    {
      name: "an unverified source read",
      reason: "source_observation_unverified",
      build: (r) => ({
        observer: r.observer(unverified, verified(DESTINATION_OBSERVATION, GENESIS_PROJECTION)),
      }),
    },
    {
      name: "an unverified destination read",
      reason: "destination_observation_unverified",
      build: (r) => ({
        observer: r.observer(verified(SOURCE_OBSERVATION, senderProjection("10")), unverified),
      }),
    },
    {
      name: "two T0 reads that cite one observation row",
      reason: "shared_t0_observation",
      build: (r) => ({
        observer: r.observer(
          verified(SOURCE_OBSERVATION, GENESIS_PROJECTION),
          verified(SOURCE_OBSERVATION, GENESIS_PROJECTION),
        ),
      }),
    },
    {
      name: "a destination retired between admission and observation",
      reason: "destination_not_eligible",
      build: (r) => ({ destinations: r.destinations(false) }),
    },
    {
      name: "a source that cannot cover the amount",
      reason: "source_insufficient_balance",
      build: (r) => ({
        observer: r.observer(
          verified(SOURCE_OBSERVATION, senderProjection("1")),
          verified(DESTINATION_OBSERVATION, receiverProjection("5")),
        ),
      }),
    },
    {
      name: "a zero-valued amount",
      reason: "invalid_amount",
      build: () => ({ amountZkz: "0.00" }),
    },
    {
      name: "an ACTIVE but non-pinning source lease",
      reason: "source_lease_role_invalid",
      build: () => ({ sourceLease: { role: "RECONCILIATION", lifecycle: "ACTIVE" } }),
    },
    {
      name: "a malformed wallet public key",
      reason: "invalid_artifact_field",
      build: () => ({ sourceWalletId: "not-a-uuid" }),
    },
  ];

  it.each(cases)("rejects $name without writing or signing", async ({ reason, build }) => {
    const recorder = new Recorder();
    const result = await captureAndBindMoveBaselines(inputOf(recorder, build(recorder)));

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe(reason);
    expect(recorder.writes).toEqual([]);
    expect(recorder.signatures).toEqual([]);
  });

  it("rechecks the destination only after BOTH reads have completed", async () => {
    const recorder = new Recorder();
    await captureAndBindMoveBaselines(
      inputOf(recorder, { destinations: recorder.destinations(false) }),
    );
    expect(recorder.calls.indexOf("recheck")).toBeGreaterThan(
      recorder.calls.indexOf("observe:MOVE_DESTINATION_T0"),
    );
  });
});

describe("durable one-capture-per-operation", () => {
  it("maps a unique violation on the first write to already_captured", async () => {
    const recorder = new Recorder();
    const duplicate = Object.assign(new Error("duplicate key value"), { code: "23505" });
    const result = await captureAndBindMoveBaselines(
      inputOf(recorder, { sql: recorder.sql(duplicate) }),
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("already_captured");
    // The exclusive claim is the FIRST statement issued, so a losing racer writes nothing else.
    expect(recorder.writes).toEqual([`sql:INSERT_EVIDENCE:${DESTINATION_OBSERVATION}`]);
  });

  it("rethrows any database error that is not a unique violation", async () => {
    const recorder = new Recorder();
    const broken = Object.assign(new Error("connection terminated"), { code: "08006" });
    await expect(
      captureAndBindMoveBaselines(inputOf(recorder, { sql: recorder.sql(broken) })),
    ).rejects.toThrow("connection terminated");
  });
});
