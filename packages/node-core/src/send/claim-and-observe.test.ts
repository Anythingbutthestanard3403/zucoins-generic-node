import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { GENESIS_PROJECTION, type WalletStateProjection } from "../protocol/wallet-role.js";
import {
  CLAIM_AND_OBSERVE_SQL,
  CLAIMABLE_FORMATION_STATE,
  CLAIMABLE_STATUS,
  SEND_T0_OBSERVATION_ROLES,
  acquireSourceLeaseWithBackoff,
  claimAndObserveSendBaselines,
  type ApprovedSendClaim,
  type ApprovedSendClaimPort,
  type ClaimAndObserveInput,
  type HeldSourceLease,
  type ObservationOutcome,
  type SendFormationObserver,
  type SourceLeasePort,
  type TryAcquireSourceLeaseResult,
} from "./claim-and-observe.js";

const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const SOURCE_PUBKEY = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DESTINATION_ADDRESS = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const SOURCE_OBSERVATION = "aaaaaaaa-0000-4000-8000-000000000001";
const DESTINATION_OBSERVATION = "aaaaaaaa-0000-4000-8000-000000000002";
const OWNER = "owner-instance-1";

const HERE = dirname(fileURLToPath(import.meta.url));

function senderProjection(b: string): WalletStateProjection {
  return { role: "sender", S: "sig-s", P: "sig-p", B: b, I: "digest" };
}

function receiverProjection(b: string): WalletStateProjection {
  return { role: "receiver", S: "sig-s", P: "sig-p", B: b, I: "digest" };
}

const verified = (
  observationId: string,
  projection: WalletStateProjection,
): ObservationOutcome => ({ kind: "VERIFIED", observationId, projection });

function heldLease(epoch = 1n): HeldSourceLease {
  return {
    walletId: SOURCE_WALLET_ID,
    membershipId: "mmmmmmmm-0000-4000-8000-000000000001",
    leaseGroupId: "gggggggg-0000-4000-8000-000000000001",
    leaseEpoch: epoch,
    operationId: OPERATION_ID,
    lease: { role: "SEND_SOURCE", lifecycle: "ACTIVE" },
  };
}

function claimOf(overrides: Partial<ApprovedSendClaim> = {}): ApprovedSendClaim {
  return {
    operationId: OPERATION_ID,
    status: CLAIMABLE_STATUS,
    formationState: CLAIMABLE_FORMATION_STATE,
    rowVersion: 2,
    sourceWalletId: SOURCE_WALLET_ID,
    sourcePubkey: SOURCE_PUBKEY,
    destinationAddress: DESTINATION_ADDRESS,
    amountZkz: "1",
    ...overrides,
  };
}

/** Records every port call so tests assert ordering and what did NOT happen. */
class Recorder {
  readonly calls: string[] = [];
  leaseResults: TryAcquireSourceLeaseResult[] = [{ outcome: "ACQUIRED", held: heldLease() }];
  private leaseAttempt = 0;

  claimPort(result: "CLAIMED" | "NOT_CLAIMABLE" = "CLAIMED"): ApprovedSendClaimPort {
    return {
      claimApproved: (operationId: string) => {
        this.calls.push(`claim:${operationId}`);
        if (result === "NOT_CLAIMABLE") {
          return Promise.resolve({
            outcome: "NOT_CLAIMABLE",
            detail: "row not APPROVED/APPROVED_UNSIGNED",
          });
        }
        return Promise.resolve({ outcome: "CLAIMED", claim: claimOf() });
      },
    };
  }

  leasePort(): SourceLeasePort {
    return {
      tryAcquireSourceLease: (input) => {
        this.calls.push(`lease:${input.sourceWalletId}`);
        const next =
          this.leaseResults[Math.min(this.leaseAttempt, this.leaseResults.length - 1)]!;
        this.leaseAttempt += 1;
        return Promise.resolve(next);
      },
    };
  }

  observer(
    source: ObservationOutcome,
    destination: ObservationOutcome,
  ): SendFormationObserver {
    return {
      observeSource: (sourcePublicKey: string) => {
        this.calls.push(`observe:SEND_SOURCE_T0:${sourcePublicKey}`);
        return Promise.resolve(source);
      },
      observeDestination: (destinationAddress: string) => {
        // Structural: destination method signature has no wallet_id parameter.
        this.calls.push(`observe:SEND_DESTINATION_FORMATION:${destinationAddress}`);
        return Promise.resolve(destination);
      },
    };
  }

  input(overrides: Partial<ClaimAndObserveInput> = {}): ClaimAndObserveInput {
    return {
      operationId: OPERATION_ID,
      ownerInstanceId: OWNER,
      capturedAt: 1_700_000_000_000,
      claimPort: this.claimPort(),
      leasePort: this.leasePort(),
      observer: this.observer(
        verified(SOURCE_OBSERVATION, senderProjection("10")),
        verified(DESTINATION_OBSERVATION, GENESIS_PROJECTION),
      ),
      backoff: {
        maxAttempts: 3,
        baseDelayMs: 1,
        maxDelayMs: 1,
        sleep: async () => {
          this.calls.push("sleep");
        },
        random: () => 0,
      },
      ...overrides,
    };
  }

  get observes(): string[] {
    return this.calls.filter((c) => c.startsWith("observe:"));
  }

  get leases(): string[] {
    return this.calls.filter((c) => c.startsWith("lease:"));
  }
}

describe("claimAndObserveSendBaselines — steps 1–5", () => {
  it("happy path: claim → lease → source observe → dest observe → verified baselines", async () => {
    const recorder = new Recorder();
    const result = await claimAndObserveSendBaselines(recorder.input());

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.sourceT0ObservationId).toBe(SOURCE_OBSERVATION);
    expect(result.destinationFormationObservationId).toBe(DESTINATION_OBSERVATION);
    expect(result.held.leaseEpoch).toBe(1n);
    expect(result.held.lease.role).toBe("SEND_SOURCE");
    expect(result.capture.destinationAddress).toBe(DESTINATION_ADDRESS);

    // Ordering: claim before lease before any observe; source observe before destination.
    expect(recorder.calls.indexOf(`claim:${OPERATION_ID}`)).toBe(0);
    expect(recorder.calls.indexOf(`lease:${SOURCE_WALLET_ID}`)).toBe(1);
    expect(recorder.calls.indexOf(`observe:SEND_SOURCE_T0:${SOURCE_PUBKEY}`)).toBe(2);
    expect(
      recorder.calls.indexOf(`observe:SEND_DESTINATION_FORMATION:${DESTINATION_ADDRESS}`),
    ).toBe(3);
  });

  it("never observes before the source lease is acquired (structural ordering)", async () => {
    const recorder = new Recorder();
    recorder.leaseResults = [
      { outcome: "BUSY", detail: "wallet held by other op" },
      { outcome: "ACQUIRED", held: heldLease() },
    ];
    const result = await claimAndObserveSendBaselines(recorder.input());
    expect(result.ok).toBe(true);

    const firstObserve = recorder.calls.findIndex((c) => c.startsWith("observe:"));
    const leaseCalls = recorder.calls
      .map((c, i) => (c.startsWith("lease:") ? i : -1))
      .filter((i) => i >= 0);
    expect(leaseCalls.length).toBeGreaterThanOrEqual(2);
    expect(Math.max(...leaseCalls)).toBeLessThan(firstObserve);
    // Destination observe still has no wallet_id in the call label.
    expect(recorder.observes.some((c) => c.includes(SOURCE_WALLET_ID))).toBe(false);
  });

  it("on lease contention exhausts backoff, leaves APPROVED, never observes", async () => {
    const recorder = new Recorder();
    recorder.leaseResults = [{ outcome: "BUSY", detail: "held by op-other" }];
    const result = await claimAndObserveSendBaselines(recorder.input());

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("lease_contention_exhausted");
    expect(result.claim?.status).toBe("APPROVED");
    expect(result.claim?.formationState).toBe("APPROVED_UNSIGNED");
    expect(recorder.observes).toEqual([]);
    expect(recorder.leases.length).toBe(3); // maxAttempts
    expect(recorder.calls.filter((c) => c === "sleep").length).toBe(2);
  });

  it("ALREADY_HELD is treated as success (crash recovery after lease, before sign intent)", async () => {
    const recorder = new Recorder();
    recorder.leaseResults = [{ outcome: "ALREADY_HELD", held: heldLease(3n) }];
    const result = await claimAndObserveSendBaselines(recorder.input());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.held.leaseEpoch).toBe(3n);
  });

  it("not-claimable short-circuits without lease or observe", async () => {
    const recorder = new Recorder();
    const result = await claimAndObserveSendBaselines(
      recorder.input({ claimPort: recorder.claimPort("NOT_CLAIMABLE") }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("not_claimable");
    expect(recorder.leases).toEqual([]);
    expect(recorder.observes).toEqual([]);
  });

  it("INDETERMINATE destination is never treated as genesis B0=0", async () => {
    const recorder = new Recorder();
    const indeterminate: ObservationOutcome = {
      kind: "INDETERMINATE",
      detail: "gateway head unparseable",
    };
    const result = await claimAndObserveSendBaselines(
      recorder.input({
        observer: recorder.observer(
          verified(SOURCE_OBSERVATION, senderProjection("10")),
          indeterminate,
        ),
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("destination_observation_indeterminate");
    // Lease was held (observe ran) but no capture produced — and we did not invent B0="0".
    expect(result.held).toBeDefined();
    expect(result).not.toHaveProperty("capture");
  });

  it("INDETERMINATE source rejects without reading a zero balance into formation", async () => {
    const recorder = new Recorder();
    const result = await claimAndObserveSendBaselines(
      recorder.input({
        observer: recorder.observer(
          { kind: "INDETERMINATE", detail: "ambiguous envelope" },
          verified(DESTINATION_OBSERVATION, GENESIS_PROJECTION),
        ),
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_observation_indeterminate");
  });

  it("insufficient source balance fails cleanly with lease held, no capture", async () => {
    const recorder = new Recorder();
    const result = await claimAndObserveSendBaselines(
      recorder.input({
        observer: recorder.observer(
          verified(SOURCE_OBSERVATION, senderProjection("0.01")),
          verified(DESTINATION_OBSERVATION, receiverProjection("0")),
        ),
      }),
    );
    // amount is "1" from claimOf
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_insufficient_balance");
    expect(result.held?.lease.role).toBe("SEND_SOURCE");
    expect(result.claim?.status).toBe("APPROVED");
  });

  it("identical source/destination keys fail cleanly (no sign intent path)", async () => {
    const recorder = new Recorder();
    // Override claim so destination == source pubkey.
    const claimPort: ApprovedSendClaimPort = {
      claimApproved: async () => ({
        outcome: "CLAIMED",
        claim: claimOf({ destinationAddress: SOURCE_PUBKEY }),
      }),
    };
    const result = await claimAndObserveSendBaselines(recorder.input({ claimPort }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("same_wallet");
    expect(result.held).toBeDefined();
  });

  it("shared observation id across source and destination is rejected", async () => {
    const recorder = new Recorder();
    const result = await claimAndObserveSendBaselines(
      recorder.input({
        observer: recorder.observer(
          verified(SOURCE_OBSERVATION, senderProjection("10")),
          verified(SOURCE_OBSERVATION, GENESIS_PROJECTION),
        ),
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("shared_t0_observation");
  });

  it("unverified destination rejects", async () => {
    const recorder = new Recorder();
    const result = await claimAndObserveSendBaselines(
      recorder.input({
        observer: recorder.observer(
          verified(SOURCE_OBSERVATION, senderProjection("10")),
          { kind: "UNVERIFIED", detail: "sig fail" },
        ),
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("destination_observation_unverified");
  });
});

describe("acquireSourceLeaseWithBackoff", () => {
  it("returns on first ACQUIRED without sleeping", async () => {
    const sleeps: number[] = [];
    const port: SourceLeasePort = {
      tryAcquireSourceLease: async () => ({ outcome: "ACQUIRED", held: heldLease() }),
    };
    const result = await acquireSourceLeaseWithBackoff(
      port,
      { operationId: OPERATION_ID, sourceWalletId: SOURCE_WALLET_ID, ownerInstanceId: OWNER },
      {
        maxAttempts: 5,
        sleep: async (ms) => {
          sleeps.push(ms);
        },
      },
    );
    expect(result.ok).toBe(true);
    expect(sleeps).toEqual([]);
  });

  it("aborts cooperatively without further attempts", async () => {
    let attempts = 0;
    const signal = { aborted: false };
    const port: SourceLeasePort = {
      tryAcquireSourceLease: async () => {
        attempts += 1;
        signal.aborted = true;
        return { outcome: "BUSY", detail: "x" };
      },
    };
    const result = await acquireSourceLeaseWithBackoff(
      port,
      { operationId: OPERATION_ID, sourceWalletId: SOURCE_WALLET_ID, ownerInstanceId: OWNER },
      { maxAttempts: 8, signal, sleep: async () => undefined, random: () => 0 },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("aborted");
    expect(attempts).toBe(1);
  });
});

describe("surface contracts", () => {
  it("exposes the two observation roles from steps 3–4", () => {
    expect(SEND_T0_OBSERVATION_ROLES).toEqual([
      "SEND_SOURCE_T0",
      "SEND_DESTINATION_FORMATION",
    ]);
  });

  it("CLAIM_AND_OBSERVE_SQL pins APPROVED + APPROVED_UNSIGNED and joins wallets for pubkey", () => {
    const sql = CLAIM_AND_OBSERVE_SQL.CLAIM_APPROVED_SEND_OPERATION;
    expect(sql).toContain("status = 'APPROVED'");
    expect(sql).toContain("formation_state = 'APPROVED_UNSIGNED'");
    expect(sql).toContain("FOR UPDATE");
    expect(sql).toContain("w.public_key AS source_pubkey");
    expect(sql).toContain("JOIN wallets");
  });

  it("module source has no submit surface (parent acceptance)", () => {
    const src = readFileSync(join(HERE, "claim-and-observe.ts"), "utf8");
    expect(src).not.toMatch(/submitGateway/);
    expect(src).not.toMatch(/submit_transaction/);
    expect(src).not.toMatch(/createSingleShotSubmit/);
    expect(src).not.toMatch(/GatewaySubmit/);
    expect(src).not.toMatch(/enableGatewaySubmit/);
    // No sign intent / inner construction (territory).
    expect(src).not.toMatch(/external_send_sign_intents/);
    expect(src).not.toMatch(/inner_preimage/);
    expect(src).not.toMatch(/buildSplitChainInner/);
  });

  it("SendFormationObserver destination call surface carries address only (no wallet_id/lease)", () => {
    // Type-level: observeDestination(destinationAddress) — a second wallet_id/lease
    // argument is a compile error. Runtime: the happy-path call label never embeds
    // SOURCE_WALLET_ID, proving the destination path was not handed a node wallet id.
    type DestParams = Parameters<SendFormationObserver["observeDestination"]>;
    type SourceParams = Parameters<SendFormationObserver["observeSource"]>;
    const _destArity: DestParams["length"] = 1;
    const _sourceArity: SourceParams["length"] = 1;
    void _destArity;
    void _sourceArity;
    // Structural string form of the interface methods in the source module.
    const src = readFileSync(join(HERE, "claim-and-observe.ts"), "utf8");
    expect(src).toMatch(
      /observeDestination\(destinationAddress: string\): Promise<ObservationOutcome>/,
    );
    expect(src).toMatch(
      /observeSource\(sourcePublicKey: string\): Promise<ObservationOutcome>/,
    );
    expect(src).not.toMatch(/observeDestination\([^)]*walletId/);
    expect(src).not.toMatch(/observeDestination\([^)]*lease/);
  });
});
