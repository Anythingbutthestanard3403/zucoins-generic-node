// Money worker composition: lease port + scale/promote/expire stop surface.
import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createReceiveLeasePort } from "../src/money-workers/receive-lease-port.js";
import { startMoneyWorkers } from "../src/money-workers/start-money-workers.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("money-workers composition", () => {
  it("createReceiveLeasePort binds createLeaseGroup + RECEIVE_WINDOW acquire", () => {
    const port = createReceiveLeasePort();
    expect(typeof port.createLeaseGroup).toBe("function");
    expect(typeof port.acquireReceiveWindowLease).toBe("function");
  });

  it("main.ts arms real workers (not ENGINE_QUIESCE-only) and never invents recovery_verified", () => {
    const main = readFileSync(join(here, "../src/main.ts"), "utf8");
    expect(main).toMatch(/startMoneyWorkers\(/);
    expect(main).toMatch(/from "\.\/money-workers\/index\.js"/);
    expect(main).toMatch(/moneyWorkers\?\.stop\(\)|moneyWorkers\.stop\(\)|workers\.stop\(\)/);
    expect(main).toMatch(/candidateIntakeInbox:\s*candidateIntake/);
    expect(main).toMatch(/enqueueReceiverChannelDeposit/);
    expect(main).toMatch(/createCandidateIntakeInbox/);
    expect(main).toMatch(/moneyPathGates:\s*moneyPathPorts/);
    expect(main).toMatch(/onReceiverChannelDeposit/);
    // no voided money deps; real leadership/signing inflight shutdown binds.
    expect(main).not.toMatch(/void moneyPathSignerGates/);
    expect(main).not.toMatch(/void moneyPathPorts/);
    expect(main).not.toMatch(/void shouldStartMoneyWorkersAfterRecovery/);
    expect(main).not.toMatch(/void stamped\.runUnderLeadership/);
    expect(main).not.toMatch(/void shutdownRegistry\.authority\.trackSigningInflight/);
    expect(main).toMatch(/runUnderLeadership:\s*\(work\)\s*=>\s*stamped\.runUnderLeadership\(work\)/);
    expect(main).toMatch(/trackSigningInflight:\s*\(work\)\s*=>/);
    // ZTR-1144 D2: money-tick drain uses general trackInflight; signUnderLease auto-tracks.
    expect(main).toMatch(/shutdownRegistry\.trackInflight\(work\)/);
    expect(main).not.toMatch(/authority\.trackSigningInflight\(work\)/);
    expect(main).not.toMatch(/workers running/);
    expect(main).not.toMatch(/recovery_verified_at\s*=/);
    const workers = readFileSync(
      join(here, "../src/money-workers/start-money-workers.ts"),
      "utf8",
    );
    expect(workers).toMatch(/runSharedPoolScaleUp/);
    expect(workers).toMatch(/promoteQueuedReceives/);
    expect(workers).toMatch(/expireQueueAgedReceives/);
    expect(workers).toMatch(/formReceiveCodeAndArtifact/);
    expect(workers).toMatch(/commitReceiveReady/);
    // ZTR-1142: fail closed when create-time handle is not durable — never READY with null.
    expect(workers).toMatch(/defer READY/);
    expect(workers).toMatch(/create response_body not durable yet/);
    expect(workers).toMatch(/lacks non-empty subscription_handle/);
    expect(workers).toMatch(/NO_ELIGIBLE_WALLET/);
    expect(workers).toMatch(/recovery_verified not stamped here/);
    expect(workers).toMatch(/recovery-verified ceremony/);
    expect(workers).toMatch(/runUnderLeadership/);
    expect(workers).toMatch(/trackSigningInflight/);
    expect(workers).not.toMatch(/SET\s+recovery_verified_at/);
    // Money path prefers gateway T0 OBSERVE when URLs set.
    expect(workers).toMatch(/createGatewayT0Observer|resolveMoneyPathT0Observer/);
    expect(main).toMatch(/gatewayUrls:\s*config\.SPLITCHAIN_GATEWAY_URLS/);
    // SEND post-approve formation is wired into the same tick loop.
    expect(workers).toMatch(/runSendPostApproveFormation/);
    expect(workers).toMatch(/tickSendCompletionLander/);
    // ZTR-1235: auto-approve step runs immediately before advanceApprovedSends.
    expect(workers).toMatch(/autoApprovePendingSends/);
    expect(workers).toMatch(/commitAutoApproval/);
    expect(workers).toMatch(/loadApprovalPendingSendCandidates/);
    {
      const autoIdx = workers.indexOf("autoApprovePendingSends");
      const advanceIdx = workers.indexOf("advanceApprovedSends({");
      expect(autoIdx).toBeGreaterThan(-1);
      expect(advanceIdx).toBeGreaterThan(autoIdx);
    }
    expect(workers).not.toMatch(/submit_transaction/);
    // Receive expiry-release service is wired into the tick.
    expect(workers).toMatch(/SqlReceiveExpiryReleaseService/);
    expect(workers).toMatch(/loadExpiredReceiveCandidates/);
    expect(workers).toMatch(/runReceiveExpiryReleaseStep/);
    expect(workers).toMatch(/receive expiry-release/);
    // ZTR-1251: fresh head for T0-unchanged release (not hardcoded null forever).
    expect(workers).toMatch(/readFreshHead/);
    expect(workers).toMatch(/freshObservationId/);
    expect(workers).not.toMatch(/freshObservationId:\s*null,\s*\n\s*nowMs/);
    // ZTR-1274 r2: expiry confirm-read persists appendExactRepeat this tick, outside expire TX.
    expect(workers).toMatch(/appendExactRepeat:\s*true/);
    expect(workers).toMatch(/expiryConfirmReadFreshHead/);
    expect(main).toMatch(/signerLeadership:\s*shutdownRegistry\.authority/);
    // Review fix: production producer + retained handle enqueue path.
    expect(workers).toMatch(/runReceiveCandidateIntakeStep/);
    expect(workers).toMatch(/candidateIntake/);
    const producer = readFileSync(
      join(here, "../src/money-workers/receiver-channel-producer.ts"),
      "utf8",
    );
    expect(producer).toMatch(/inbox\.enqueue\(/);
    expect(producer).toMatch(/zucoin_wallet_sender_partial_transfer_code__v1/);
  });

  it("startMoneyWorkers stop callback quiets the interval", () => {
    const query = vi.fn(async () => ({ rows: [], rowCount: 0 }));
    const connect = vi.fn(async () => ({
      query: async (sql: string) => {
        if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [], rowCount: 0 };
      },
      release: () => {},
    }));
    const pool = { query, connect } as never;
    const vault = { seal: vi.fn(async () => {}) } as never;
    const logs: string[] = [];
    const handle = startMoneyWorkers({
      pool,
      vault,
      config: {
        nodeId: "11111111-1111-4111-8111-111111111111",
        ownerInstanceId: "11111111-1111-4111-8111-111111111111",
        poolCapTotal: 50,
        receiveQueueCap: 50,
        receiveQueueMaxWaitSecs: 30,
        receiveTtlDefaultSecs: 300,
        receiveTtlMinSecs: 60,
        receiveTtlMaxSecs: 3600,
        tickIntervalMs: 60_000,
        // URL required, or explicit test stub flag. Composition uses injection.
        gatewayUrls: ["https://gateway.test.invalid/"],
        // Composition assertion only — no event append.
        allowMissingEventSigner: true,
      },
      logger: {
        info: (m) => logs.push(m),
        error: (m) => logs.push(`err:${m}`),
      },
      moneyPathGates: {
        assertMoneyAdmitted: () => {
          throw new Error("closed for unit test");
        },
        assertCanOperate: () => {},
        assertWalletMaySign: () => {},
        assertHaltAdmitsKind: () => {},
      },
      nodeIdentitySigner: () => null,
      // Injected observer so tick composition does not hit gateway exchange.
      t0Observer: {
        observe: async () => ({
          kind: "INDETERMINATE" as const,
          detail: "unit-test composition",
        }),
      },
    });
    expect(logs.some((l) => l.includes("money workers started"))).toBe(true);
    expect(logs.some((l) => l.includes("T0 observer kind=injected"))).toBe(true);
    handle.stop();
    expect(logs.some((l) => l.includes("ENGINE_QUIESCE"))).toBe(true);
  });

  it("D2: startMoneyWorkers without gatewayUrls refuses silent genesis stub", () => {
    expect(() =>
      startMoneyWorkers({
        pool: { query: vi.fn(), connect: vi.fn() } as never,
        vault: { seal: vi.fn(async () => {}) } as never,
        config: {
          nodeId: "11111111-1111-4111-8111-111111111111",
          ownerInstanceId: "11111111-1111-4111-8111-111111111111",
          poolCapTotal: 50,
          receiveQueueCap: 50,
          receiveQueueMaxWaitSecs: 30,
          receiveTtlDefaultSecs: 300,
          receiveTtlMinSecs: 60,
          receiveTtlMaxSecs: 3600,
          tickIntervalMs: 60_000,
          // Isolate the gateway gate: without this the signer gate would
          // refuse first and this assertion would stop testing what it names.
          allowMissingEventSigner: true,
        },
        logger: { info: () => {}, error: () => {} },
        moneyPathGates: {
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          assertWalletMaySign: () => {},
          assertHaltAdmitsKind: () => {},
        },
        nodeIdentitySigner: () => null,
      }),
    ).toThrow(/non-empty gatewayUrls/);
  });
});

describe("money-workers EVENT_SIGNING requirement", () => {
  const baseDeps = (
    overrides: Partial<Parameters<typeof startMoneyWorkers>[0]> = {},
  ): Parameters<typeof startMoneyWorkers>[0] => ({
    pool: { query: vi.fn(), connect: vi.fn() } as never,
    vault: { seal: vi.fn(async () => {}) } as never,
    config: {
      nodeId: "11111111-1111-4111-8111-111111111111",
      ownerInstanceId: "11111111-1111-4111-8111-111111111111",
      poolCapTotal: 50,
      receiveQueueCap: 50,
      receiveQueueMaxWaitSecs: 30,
      receiveTtlDefaultSecs: 300,
      receiveTtlMinSecs: 60,
      receiveTtlMaxSecs: 3600,
      tickIntervalMs: 0,
      gatewayUrls: ["https://gateway.test.invalid/"],
    },
    logger: { info: () => {}, error: () => {} },
    moneyPathGates: {
      assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: () => {},
      assertHaltAdmitsKind: () => {},
    },
    nodeIdentitySigner: () => null,
    t0Observer: {
      observe: async () => ({ kind: "INDETERMINATE" as const, detail: "unit test" }),
    },
    ...overrides,
  });

  // The boot half (ensure → probe → arm) is covered behaviourally in
  // event-signer-authority.test.ts against the real installEventSigner main.ts awaits —
  // a source-text regex on main.ts proved only that a substring was present.
  it("refuses to start with no eventSigner dep (production default)", () => {
    expect(() => startMoneyWorkers(baseDeps())).toThrow(/EVENT_SIGNING signer/);
  });

  it("refuses to start when the eventSigner accessor returns null", () => {
    expect(() => startMoneyWorkers(baseDeps({ eventSigner: () => null }))).toThrow(
      /EVENT_SIGNING signer/,
    );
  });

  it("starts when a signer is available", () => {
    const handle = startMoneyWorkers(
      baseDeps({ eventSigner: () => ({ signingKeyId: "key-1", sign: () => "c2ln" }) }),
    );
    handle.stop();
  });

  it("starts without a signer only under the explicit test-only escape", () => {
    const handle = startMoneyWorkers(
      baseDeps({
        config: { ...baseDeps().config, allowMissingEventSigner: true },
      }),
    );
    handle.stop();
  });
});
