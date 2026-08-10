import { describe, expect, it } from "vitest";

import { NodeReadiness } from "../src/boot/readiness.js";

describe("NodeReadiness — readiness gating (schema ∧ vault ∧ observation)", () => {
  it("starts fully not-ready and opens when gating stamps pass (leadership + EVENT_SIGNING optional)", () => {
    const readiness = new NodeReadiness(3);
    expect(readiness.snapshot().ready).toBe(false);

    readiness.markSchemaChecksPassed();
    expect(readiness.snapshot().ready).toBe(false);

    readiness.setVaultAvailable(true);
    expect(readiness.snapshot().ready).toBe(false);

    // Leadership is reported but does not open readiness.
    readiness.setSignerLeadershipHeld(true);
    expect(readiness.snapshot().ready).toBe(false);

    // Deploy-ready = schema ∧ vault ∧ observation (ZPAY-252).
    readiness.recordGatewayReadSuccess();
    const beforeArm = readiness.snapshot();
    expect(beforeArm.ready).toBe(true);
    expect(beforeArm.checks.eventSigner).toBe(false);

    readiness.setEventSignerAvailable(true);
    const snapshot = readiness.snapshot();
    expect(snapshot.ready).toBe(true);
    expect(snapshot.degraded).toBe(false);
    expect(snapshot.checks).toEqual({
      schema: true,
      vault: true,
      leadership: true,
      gateway: true,
      eventSigner: true,
    });
  });

  it("each gating check independently holds readiness false; leadership does not", () => {
    const readiness = new NodeReadiness(3);
    readiness.markSchemaChecksPassed();
    readiness.setVaultAvailable(true);
    readiness.setSignerLeadershipHeld(true);
    readiness.recordGatewayReadSuccess();
    readiness.setEventSignerAvailable(true);
    expect(readiness.snapshot().ready).toBe(true);

    readiness.setVaultAvailable(false);
    expect(readiness.snapshot().ready).toBe(false);
    expect(readiness.snapshot().checks.vault).toBe(false);

    readiness.setVaultAvailable(true);
    readiness.setSignerLeadershipHeld(false);
    // Leadership loss is reported but non-gating.
    expect(readiness.snapshot().ready).toBe(true);
    expect(readiness.snapshot().checks.leadership).toBe(false);
  });

  it("rejects a non-positive failure budget", () => {
    expect(() => new NodeReadiness(0)).toThrow(RangeError);
    expect(() => new NodeReadiness(1.5)).toThrow(RangeError);
  });
});

describe("NodeReadiness — gateway failure budget", () => {
  it("keeps the gateway gate closed before the first validated read", () => {
    const readiness = new NodeReadiness(3);
    readiness.recordGatewayReadFailure();
    expect(readiness.snapshot().checks.gateway).toBe(false);
  });

  it("absorbs failures below the budget after a success", () => {
    const readiness = new NodeReadiness(3);
    readiness.recordGatewayReadSuccess();
    readiness.recordGatewayReadFailure();
    readiness.recordGatewayReadFailure();
    const snapshot = readiness.snapshot();
    expect(snapshot.checks.gateway).toBe(true);
    expect(snapshot.gatewayConsecutiveFailures).toBe(2);
  });

  it("closes the gate and reports degraded exactly at the budget", () => {
    const readiness = new NodeReadiness(3);
    readiness.markSchemaChecksPassed();
    readiness.setVaultAvailable(true);
    readiness.setSignerLeadershipHeld(true);
    readiness.recordGatewayReadSuccess();
    readiness.setEventSignerAvailable(true);
    expect(readiness.snapshot().ready).toBe(true);

    readiness.recordGatewayReadFailure();
    readiness.recordGatewayReadFailure();
    readiness.recordGatewayReadFailure();
    const snapshot = readiness.snapshot();
    expect(snapshot.checks.gateway).toBe(false);
    expect(snapshot.ready).toBe(false);
    expect(snapshot.degraded).toBe(true);
  });

  it("does not report degraded during the pre-first-read boot window", () => {
    const readiness = new NodeReadiness(1);
    readiness.markSchemaChecksPassed();
    readiness.setVaultAvailable(true);
    readiness.setSignerLeadershipHeld(true);
    readiness.recordGatewayReadFailure();
    const snapshot = readiness.snapshot();
    expect(snapshot.ready).toBe(false);
    expect(snapshot.degraded).toBe(false);
  });

  it("reopens the gate on the next validated success", () => {
    const readiness = new NodeReadiness(2);
    readiness.recordGatewayReadSuccess();
    readiness.recordGatewayReadFailure();
    readiness.recordGatewayReadFailure();
    expect(readiness.snapshot().checks.gateway).toBe(false);

    readiness.recordGatewayReadSuccess();
    const snapshot = readiness.snapshot();
    expect(snapshot.checks.gateway).toBe(true);
    expect(snapshot.gatewayConsecutiveFailures).toBe(0);
  });
});

describe("NodeReadiness — EVENT_SIGNING money-only (ZTR-1179 / ZPAY-252)", () => {
  it("starts with eventSigner unavailable but deploy-ready once schema/vault/gateway pass", () => {
    const readiness = new NodeReadiness(3);
    readiness.markSchemaChecksPassed();
    readiness.setVaultAvailable(true);
    readiness.setSignerLeadershipHeld(true);
    readiness.recordGatewayReadSuccess();
    const snapshot = readiness.snapshot();
    expect(snapshot.checks.eventSigner).toBe(false);
    expect(snapshot.ready).toBe(true);
  });

  it("deploy-ready does not require arming the event signer", () => {
    const readiness = new NodeReadiness(3);
    readiness.markSchemaChecksPassed();
    readiness.setVaultAvailable(true);
    readiness.recordGatewayReadSuccess();
    expect(readiness.snapshot().checks.eventSigner).toBe(false);
    expect(readiness.snapshot().ready).toBe(true);
    readiness.setEventSignerAvailable(true);
    expect(readiness.snapshot().ready).toBe(true);
  });

  it("runtime signer loss stamps eventSigner false but keeps deploy-ready", () => {
    const readiness = new NodeReadiness(3);
    readiness.markSchemaChecksPassed();
    readiness.setVaultAvailable(true);
    readiness.recordGatewayReadSuccess();
    readiness.setEventSignerAvailable(true);
    expect(readiness.snapshot().ready).toBe(true);

    readiness.setEventSignerAvailable(false);
    const snapshot = readiness.snapshot();
    expect(snapshot.checks.eventSigner).toBe(false);
    expect(snapshot.ready).toBe(true);
  });
});

describe("NodeReadiness — shutdown", () => {
  it("beginShutdown flips readiness false immediately", () => {
    const readiness = new NodeReadiness(3);
    readiness.markSchemaChecksPassed();
    readiness.setVaultAvailable(true);
    readiness.setSignerLeadershipHeld(true);
    readiness.recordGatewayReadSuccess();
    readiness.setEventSignerAvailable(true);
    expect(readiness.snapshot().ready).toBe(true);

    readiness.beginShutdown();
    const snapshot = readiness.snapshot();
    expect(snapshot.ready).toBe(false);
    expect(snapshot.stopping).toBe(true);
    expect(snapshot.degraded).toBe(false);
  });
});
