// EVENT_SIGNING authority: arm at boot, withdraw + quiesce on runtime loss.
//
// The real-PG drill in receive-ready-event-append.pg.test.ts proves the money-path
// consequence (a lost signer rolls the READY transaction back instead of committing
// eventless). This suite pins the latch semantics themselves: order, idempotency, the
// refusal to reopen, and the boot sequence main.ts runs (installEventSigner).
//
// Governing: the boot signer-authority arming contract; 09-operations-recovery.md; the withdraw-then-quiesce shutdown ordering.

import { describe, expect, it } from "vitest";

import {
  assertNewMoneyWorkAdmitted,
  evaluateReadinessFromProbes,
  MoneyAdmissionRefusedError,
} from "@zucoins/node-core";

import {
  createEventSignerAuthority,
  installEventSigner,
  NodeReadiness,
} from "../src/boot/index.js";

const silentLogger = { info: () => {}, error: () => {} };

function harness() {
  const calls: string[] = [];
  const readiness = new NodeReadiness(3);
  const authority = createEventSignerAuthority({
    readiness,
    withdrawSignerAuthority: () => calls.push("SIGNER_AUTHORITY_WITHDRAW"),
    stopWorkers: () => calls.push("ENGINE_QUIESCE"),
    logger: silentLogger,
  });
  return { authority, readiness, calls };
}

/** Readiness with everything but EVENT_SIGNING already open. */
function armEverythingElse(readiness: NodeReadiness): void {
  readiness.markSchemaChecksPassed();
  readiness.setVaultAvailable(true);
  readiness.setSignerLeadershipHeld(true);
  readiness.recordGatewayReadSuccess();
}

const okSigner = { signingKeyId: "key-1", sign: () => "c2ln" };

describe("EVENT_SIGNING authority", () => {
  it("arming is the only thing that opens the eventSigner conjunct (deploy-ready already open)", () => {
    const { authority, readiness } = harness();
    armEverythingElse(readiness);
    expect(readiness.snapshot().ready).toBe(true);
    expect(readiness.snapshot().checks.eventSigner).toBe(false);

    authority.arm(okSigner);
    expect(readiness.snapshot().ready).toBe(true);
    expect(readiness.snapshot().checks.eventSigner).toBe(true);
  });

  it("a signing failure withdraws authority, quiesces engines, and rethrows", () => {
    const { authority, readiness, calls } = harness();
    armEverythingElse(readiness);
    const armed = authority.arm({
      signingKeyId: "key-1",
      sign: () => {
        throw new Error("sealed row unreadable");
      },
    });

    expect(() => armed.sign(new Uint8Array())).toThrow(/sealed row unreadable/);
    // Rethrow is the Byte-exact half: the caller's READY transaction must roll back, never
    // commit with the event logged away as a residual.
    expect(readiness.snapshot().checks.eventSigner).toBe(false);
    expect(readiness.snapshot().ready).toBe(true);
    // Withdraw-before-quiesce — drop the signing latch before stopping the engines.
    expect(calls).toEqual(["SIGNER_AUTHORITY_WITHDRAW", "ENGINE_QUIESCE"]);
  });

  it("withdrawal is idempotent — a quiesced surface is not re-quiesced every tick", () => {
    const { authority, calls } = harness();
    authority.arm(okSigner);

    authority.withdraw(new Error("first"));
    authority.withdraw(new Error("second"));
    authority.withdraw(new Error("third"));

    expect(calls).toEqual(["SIGNER_AUTHORITY_WITHDRAW", "ENGINE_QUIESCE"]);
    expect(authority.withdrawn).toBe(true);
  });

  it("a withdrawn signer keeps throwing rather than reverting to the null (skip-event) branch", () => {
    const { authority } = harness();
    // Underlying signer is perfectly healthy — the withdrawal alone must be enough.
    const armed = authority.arm(okSigner);
    expect(armed.sign(new Uint8Array())).toBe("c2ln");

    authority.withdraw(new Error("leadership lost"));
    expect(() => armed.sign(new Uint8Array())).toThrow(/authority withdrawn/);
  });

  it("refuses to re-arm after a withdrawal (no reopen without a restart)", () => {
    const { authority, readiness } = harness();
    armEverythingElse(readiness);
    authority.arm(okSigner);
    authority.withdraw(new Error("loss"));

    expect(() => authority.arm(okSigner)).toThrow(/already withdrawn/);
    expect(readiness.snapshot().checks.eventSigner).toBe(false);
    expect(readiness.snapshot().ready).toBe(true);
  });

  it("keeps quiescing even if the readiness stamp throws (each step is independent)", () => {
    const calls: string[] = [];
    const authority = createEventSignerAuthority({
      readiness: {
        setEventSignerAvailable: () => {
          throw new Error("readiness stamp exploded");
        },
      },
      withdrawSignerAuthority: () => calls.push("SIGNER_AUTHORITY_WITHDRAW"),
      stopWorkers: () => calls.push("ENGINE_QUIESCE"),
      logger: silentLogger,
    });

    expect(() => authority.withdraw(new Error("loss"))).toThrow(/readiness stamp exploded/);
    expect(calls).toEqual(["SIGNER_AUTHORITY_WITHDRAW", "ENGINE_QUIESCE"]);
  });
});

// One conjunct, every consumer: withdrawal must reach /health/ready's evaluator and
// money admission through the SAME node-core snapshot the shell forwards into (ZTR-1179).
describe("EVENT_SIGNING withdrawal reaches every readiness consumer (ZTR-1179)", () => {
  it("money admission refuses with event_signer_unavailable after a runtime loss", () => {
    const { authority, readiness } = harness();
    armEverythingElse(readiness);
    authority.arm(okSigner);
    expect(() => assertNewMoneyWorkAdmitted(readiness.core.snapshot(), true)).not.toThrow();

    authority.withdraw(new Error("sealed row unreadable"));

    let thrown: unknown;
    try {
      assertNewMoneyWorkAdmitted(readiness.core.snapshot(), true);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(MoneyAdmissionRefusedError);
    expect((thrown as MoneyAdmissionRefusedError).code).toBe("event_signer_unavailable");
  });

  it("the node-core readiness verdict (/health/ready's evaluator) stays ready on the same snapshot (money-only)", () => {
    const { authority, readiness } = harness();
    armEverythingElse(readiness);
    authority.arm(okSigner);
    expect(evaluateReadinessFromProbes(readiness.core.snapshot(), true).ready).toBe(true);

    authority.withdraw(new Error("loss"));
    const verdict = evaluateReadinessFromProbes(readiness.core.snapshot(), true);
    expect(verdict.ready).toBe(true);
    expect(verdict.status).toBe("ready");
    expect(readiness.snapshot().checks.eventSigner).toBe(false);
  });
});

// The boot half of the AC ("availability and correspondence are boot prerequisites").
// This exercises installEventSigner — the exact function main.ts's runBootRecovery awaits,
// with the real authority and the real readiness object; only the sealed-key ensure is
// substituted. If the ensure failure or the probe failure ever stops propagating, or the
// probe stops preceding arm, these go red.
describe("EVENT_SIGNING boot install (open → probe → arm)", () => {
  it("propagates a sealed-store ensure failure and never arms (readiness stays closed)", async () => {
    const { authority, readiness } = harness();
    armEverythingElse(readiness);

    await expect(
      installEventSigner({
        openSigner: () => Promise.reject(new Error("EVENT_SIGNING sealed row missing")),
        authority,
        logger: silentLogger,
      }),
    ).rejects.toThrow(/EVENT_SIGNING sealed row missing/);
    expect(readiness.snapshot().checks.eventSigner).toBe(false);
    expect(readiness.snapshot().ready).toBe(true);
  });

  it("propagates a correspondence-probe failure and never arms", async () => {
    const { authority, readiness } = harness();
    armEverythingElse(readiness);

    await expect(
      installEventSigner({
        openSigner: () =>
          Promise.resolve({
            signingKeyId: "key-1",
            sign: () => {
              // The ensure succeeded, but the sealed seed will not reopen and sign.
              throw new Error("sealed seed will not reopen");
            },
          }),
        authority,
        logger: silentLogger,
      }),
    ).rejects.toThrow(/sealed seed will not reopen/);
    expect(readiness.snapshot().checks.eventSigner).toBe(false);
    expect(readiness.snapshot().ready).toBe(true);
  });

  it("probes before arming, then arms the withdraw-wrapped signer", async () => {
    const { authority, readiness, calls } = harness();
    armEverythingElse(readiness);
    const signedPreimages: number[] = [];
    // Readiness as it stood at the moment of the probe: still closed, i.e. the probe
    // genuinely precedes arm rather than merely accompanying it.
    let readyAtProbe: boolean | null = null;

    const signer = await installEventSigner({
      openSigner: () =>
        Promise.resolve({
          signingKeyId: "key-1",
          sign: (preimage: Uint8Array) => {
            readyAtProbe ??= readiness.snapshot().checks.eventSigner;
            signedPreimages.push(preimage.length);
            return "c2ln";
          },
        }),
      authority,
      logger: silentLogger,
    });

    expect(readyAtProbe).toBe(false);
    expect(signedPreimages).toEqual([0]); // the empty-preimage correspondence probe
    expect(readiness.snapshot().checks.eventSigner).toBe(true);
    expect(signer.signingKeyId).toBe("key-1");
    expect(signer.sign(new Uint8Array([1]))).toBe("c2ln");
    expect(calls).toEqual([]);
  });

  it("arms the wrapper, not the raw signer — a later failure withdraws authority", async () => {
    const { authority, readiness, calls } = harness();
    armEverythingElse(readiness);
    let probed = false;

    const signer = await installEventSigner({
      openSigner: () =>
        Promise.resolve({
          signingKeyId: "key-1",
          sign: () => {
            if (!probed) {
              probed = true;
              return "c2ln";
            }
            throw new Error("sealed EVENT_SIGNING row unreadable");
          },
        }),
      authority,
      logger: silentLogger,
    });
    expect(readiness.snapshot().ready).toBe(true);

    expect(() => signer.sign(new Uint8Array())).toThrow(/sealed EVENT_SIGNING row unreadable/);
    expect(calls).toEqual(["SIGNER_AUTHORITY_WITHDRAW", "ENGINE_QUIESCE"]);
    expect(readiness.snapshot().checks.eventSigner).toBe(false);
    expect(readiness.snapshot().ready).toBe(true);
  });
});
