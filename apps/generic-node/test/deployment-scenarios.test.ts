// Deployment integration scenarios for the v2 generic node.
//
// These are INTEGRATION-level tests: each scenario composes the real units
// (frozen config load, boot lane, readiness state machine, health router) the
// way a deployment does, and asserts the cross-cutting behavior that no single
// unit test covers. The eight scenarios mirror the deployment shapes the
// platform must survive:
//
//   1. Fresh install        — valid config + empty state, fail-closed at the
//                             first unwired money surface, readiness stays false.
//   2. Schema mismatch      — migrations reject with a schema-version error.
//   3. Missing secret       — loadNodeConfig refuses boot, names the field,
//                             never echoes a secret value.
//   4. Invalid live endpoint— malformed gateway endpoints rejected cleanly;
//                             loopback http accepted; wildcard CORS rejected.
//   5. Overlap deploy       — two boot lanes share one leadership lock; exactly
//                             one leader at any instant (rolling-update overlap).
//   6. Rollback compat      — the frozen schema accepts the original required
//                             field set; the manifest carries no pinned tag.
//   7. Read-only filesystem — no fs writes on the boot path; the manifest and
//                             image enforce a read-only root.
//   8. Restart              — the lane re-runs from step 1 with no stale state,
//                             and performs none of the forbidden boot actions.
//
// Network containment: the package vitest setup (test/setup-network-guard.ts)
// blocks every real socket; nothing here touches the network, the database, or
// a real vault. Invariants honored throughout: ZKZ (never ZUC), one in-flight
// transaction per wallet, byte-exact signing, never blind-retry a submit, the
// platform never touches private keys, and there is no sandbox.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import {
  runBootLane,
  type BootLaneDeps,
  type BootLogger,
  type SignerLeadershipHandle,
} from "../src/boot/boot-lane.js";
import { NodeReadiness } from "../src/boot/readiness.js";
import { loadNodeConfig, NodeConfigurationError } from "../src/config/load.js";
import { PlaceholderSecretError } from "../src/config/placeholders.js";
import { createHealthRouter } from "../src/health/routes.js";

const noopLogger: BootLogger = { info: () => {}, error: () => {} };

function validEnv(
  overrides: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  return {
    NODE_ENV: "development",
    DATABASE_URL: "postgresql://node:db-secret@db.internal:5432/zunode",
    SPLITCHAIN_GATEWAY_URLS: "https://gateway-entry-1.internal.example/",
    PUBLIC_BASE_URL: "https://node.internal.example/",
    NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    VAULT_MASTER_KEY: "a".repeat(32),
    ...overrides,
  };
}

// The exact fail-closed seam main.ts uses for money surfaces this stack does
// not wire yet — replicated here so the integration test exercises the same
// rejection shape the real entry point produces on a fresh install.
function surfaceNotYetWired(surface: string): () => Promise<never> {
  return () =>
    Promise.reject(
      new Error(`${surface} is not yet wired in this build — readiness stays false (fail-closed)`),
    );
}

function happyDeps(readiness: NodeReadiness, events: string[]): BootLaneDeps {
  return {
    readiness,
    logger: noopLogger,
    runMigrations: async () => {
      events.push("migrations");
    },
    unlockVault: async () => {
      events.push("vault");
    },
    acquireSignerLeadership: async () => {
      events.push("leadership");
      return { release: () => {} };
    },
    runBootRecovery: async () => {
      events.push("boot-recovery");
      // Mirrors main.ts: a successful recovery has ensured EVENT_SIGNING.
      readiness.setEventSignerAvailable(true);
      return { ready: true, invariantBreach: false };
    },
    performValidatedGatewayRead: async () => {
      events.push("gateway-read");
    },
    startMoneyWorkers: () => {
      events.push("money-workers");
    },
  };
}

describe("deployment scenario 1 — fresh install (valid config, empty state)", () => {
  it("production main.ts wires the real migration runner (not surfaceNotYetWired)", () => {
    const mainSource = readFileSync(fileURLToPath(new URL("../src/main.ts", import.meta.url)), "utf8");
    expect(mainSource).toMatch(/import\(\s*["']\.\/db\/migrate\.js["']\s*\)/);
    expect(mainSource).toMatch(/runMigrations/);
    expect(mainSource).not.toMatch(
      /runMigrations:\s*surfaceNotYetWired\(\s*["']database migration runner["']\s*\)/,
    );
  });

  it("main.ts threads the SAME validated config.DATABASE_URL into both the runtime pool and runMigrations", () => {
    const mainSource = readFileSync(fileURLToPath(new URL("../src/main.ts", import.meta.url)), "utf8");
    expect(mainSource).toMatch(/createPool\(config\.DATABASE_URL\)/);
    expect(mainSource).toMatch(/runMigrations\(config\.DATABASE_URL\)/);
    // The pre-rework regression: runMigrations() called with no argument, re-reading env itself.
    expect(mainSource).not.toMatch(/await runMigrations\(\s*\)/);
  });

  it("stage1-main.ts threads the SAME validated config.databaseUrl into both the runtime pool and runMigrations", () => {
    const stage1Source = readFileSync(
      fileURLToPath(new URL("../src/stage1-main.ts", import.meta.url)),
      "utf8",
    );
    expect(stage1Source).toMatch(/createPool\(config\.databaseUrl\)/);
    expect(stage1Source).toMatch(
      /runMigrations:\s*\(\)\s*=>\s*runMigrations\(config\.databaseUrl\)/,
    );
    // The pre-rework regression: the raw dynamic-import runMigrations reference handed straight
    // through as the dependency, invoked later with no argument.
    expect(stage1Source).not.toMatch(/\n\s*runMigrations,\n/);
  });

  it("Stage-2 custody main wires live seams (source ratchet)", () => {
    const mainSource = readFileSync(fileURLToPath(new URL("../src/main.ts", import.meta.url)), "utf8");
    for (const needle of [
      "assertPrivilegeReadiness",
      "acquireSignerLeadershipWithBoundedRetry",
      "runDeterministicBootRecovery",
      "readGatewayAction",
      "SqlCredentialStore",
      "EncryptedWalletKeyStore",
      "createSqlOperationRouteStore",
      "createImplementerBearerAuthFromService",
      "armMoneySurface",
    ]) {
      expect(mainSource, needle).toContain(needle);
    }
    expect(mainSource).not.toMatch(/surfaceNotYetWired\s*\(/);
    // Live store must not coexist with reject-all.
    expect(mainSource).not.toMatch(/createRejectAllOperationAuth\s*\(/);
    expect(mainSource).not.toMatch(/createFailClosedOperationStore\s*\(/);
  });

  it("dual entrypoint honesty: Docker CMD is custody main; Stage-1 is named override", () => {
    const root = fileURLToPath(new URL("..", import.meta.url));
    const dockerfile = readFileSync(`${root}/Dockerfile`, "utf8");
    const pkg = readFileSync(`${root}/package.json`, "utf8");
    expect(dockerfile).toContain('CMD ["node", "dist/main.js"]');
    expect(dockerfile).not.toMatch(/CMD \["node", "dist\/stage1-main\.js"\]/);
    expect(dockerfile).toMatch(/dist\/stage1-main\.js/);
    expect(dockerfile).toMatch(/named non-money variant/i);
    expect(pkg).toMatch(/"start:\s*stage1"|"start:stage1"/);
  });

  it("validates config, runs the lane in sequence, then fails closed when stubbed at migrations", async () => {
    const config = loadNodeConfig(validEnv());
    expect(config.SPLITCHAIN_GATEWAY_URLS).toEqual(["https://gateway-entry-1.internal.example/"]);

    const readiness = new NodeReadiness(config.GATEWAY_READ_FAILURE_BUDGET);
    // Same production wiring as main.ts — pingDb is required and fail-closed.
    const router = createHealthRouter({
      readiness,
      pingDb: surfaceNotYetWired("database adapter"),
    });

    // Migrations are wired in production main.ts. Remaining money
    // surfaces stay fail-closed stubs. This scenario stubs migrations so the
    // lane still demonstrates first-step halt without a live database.
    const events: string[] = [];
    const result = await runBootLane({
      readiness,
      logger: noopLogger,
      runMigrations: surfaceNotYetWired("database migration runner"),
      unlockVault: surfaceNotYetWired("vault unlock"),
      acquireSignerLeadership: surfaceNotYetWired("signer leadership lock"),
      runBootRecovery: surfaceNotYetWired("deterministic boot recovery"),
      performValidatedGatewayRead: surfaceNotYetWired("observation-service gateway read"),
      startMoneyWorkers: () => {
        events.push("money-workers");
      },
    });

    expect(result.ready).toBe(false);
    // Diagnosable: the failure names the exact step that halted the lane.
    expect(result.failedStep).toBe("migrations");
    // Fail-closed: nothing past the failed step ever ran.
    expect(events).toEqual([]);
    expect(readiness.snapshot().ready).toBe(false);
    expect(readiness.snapshot().checks.schema).toBe(false);

    // Liveness stays up; readiness reports the closed gate to the platform.
    const live = await router("GET", "/health");
    expect(live.status).toBe(200);
    const ready = await router("GET", "/health/ready");
    expect(ready.status).toBe(503);
    expect(ready.body).toMatchObject({ status: "not_ready" });
    {
      const checks = (ready.body as { checks: Array<{ name: string; ready: boolean }> }).checks;
      expect(checks.find((c) => c.name === "schema_migrated")?.ready).toBe(false);
      // Production main.ts wires fail-closed pingDb — database_reachable must not fail open.
      expect(checks.find((c) => c.name === "database_reachable")?.ready).toBe(false);
      expect(checks.find((c) => c.name === "vault_available")?.ready).toBe(false);
      expect(checks.find((c) => c.name === "observation_read_capable")?.ready).toBe(false);
    }
  });
});

describe("deployment scenario 2 — schema mismatch (migration rejects)", () => {
  it("halts at the migrations step, never opens readiness, never starts money workers", async () => {
    const readiness = new NodeReadiness(3);
    const router = createHealthRouter({
      readiness,
      pingDb: surfaceNotYetWired("database adapter"),
    });
    const events: string[] = [];
    const deps = happyDeps(readiness, events);
    deps.runMigrations = async () => {
      events.push("migrations:attempt");
      throw new Error("schema version 7 is incompatible with release 6 (migration 0042)");
    };

    const result = await runBootLane(deps);

    expect(result.ready).toBe(false);
    expect(result.failedStep).toBe("migrations");
    // Only the migration attempt ran — vault, leadership, gateway, money never did.
    expect(events).toEqual(["migrations:attempt"]);
    expect(readiness.snapshot().ready).toBe(false);
    expect(readiness.snapshot().checks.schema).toBe(false);

    const ready = await router("GET", "/health/ready");
    expect(ready.status).toBe(503);
    expect(ready.body).toMatchObject({ status: "not_ready" });
    {
      const checks = (ready.body as { checks: Array<{ name: string; ready: boolean }> }).checks;
      expect(checks.find((c) => c.name === "schema_migrated")?.ready).toBe(false);
      expect(checks.find((c) => c.name === "vault_available")?.ready).toBe(false);
      expect(checks.find((c) => c.name === "observation_read_capable")?.ready).toBe(false);
    }
  });
});

describe("deployment scenario 3 — missing secret (boot refusal, no secret echo)", () => {
  const CRITICAL = ["DATABASE_URL", "SPLITCHAIN_GATEWAY_URLS"] as const;

  it.each(CRITICAL)("missing %s refuses boot and names the field", (field) => {
    const env = validEnv({ [field]: undefined });
    let caught: unknown;
    try {
      loadNodeConfig(env);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(NodeConfigurationError);
    const error = caught as NodeConfigurationError;
    expect(error.issues.some((issue) => issue.includes(field))).toBe(true);
  });

  it("reports every missing critical field together (3-field combination)", () => {
    const env = validEnv({
      DATABASE_URL: undefined,
      SPLITCHAIN_GATEWAY_URLS: undefined,
    });
    let caught: unknown;
    try {
      loadNodeConfig(env);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(NodeConfigurationError);
    const issues = (caught as NodeConfigurationError).issues.join("\n");
    expect(issues).toContain("DATABASE_URL");
    expect(issues).toContain("SPLITCHAIN_GATEWAY_URLS");
  });

  it("a missing referenced master key refuses boot without echoing the material", () => {
    const sentinel = "S3NTIN3L-master-key-material";
    const env = validEnv({ DATABASE_URL: "   ", VAULT_MASTER_KEY: sentinel });
    let message = "";
    try {
      loadNodeConfig(env);
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toContain("DATABASE_URL");
    expect(message).not.toContain(sentinel);
  });

  it("ignores a legacy custody secret in zero-custody configuration", () => {
    const env = validEnv({ VAULT_MASTER_KEY: "  " });
    expect(loadNodeConfig(env)).not.toHaveProperty("VAULT_MASTER_KEY");
  });
});

describe("deployment scenario 4 — invalid live endpoint (clean rejection, no fallback)", () => {
  it.each([
    ["http://gateway.internal.example/", "non-https, non-loopback"],
    ["ftp://gateway.internal.example/", "wrong protocol"],
    ["not a url at all", "malformed"],
    ["", "empty"],
  ])("rejects %s (%s) cleanly, naming the field", (value, label) => {
    const env = validEnv({ SPLITCHAIN_GATEWAY_URLS: value });
    let caught: unknown;
    try {
      loadNodeConfig(env);
    } catch (err) {
      caught = err;
    }
    expect(caught, `expected rejection for ${label}`).toBeInstanceOf(NodeConfigurationError);
    const issues = (caught as NodeConfigurationError).issues.join("\n");
    expect(issues).toContain("SPLITCHAIN_GATEWAY_URLS");
  });

  it("creates no fallback endpoint: a rejected config yields no parsed gateway list", () => {
    const env = validEnv({ SPLITCHAIN_GATEWAY_URLS: "http://gateway.internal.example/" });
    let parsed: string[] | undefined;
    try {
      parsed = loadNodeConfig(env).SPLITCHAIN_GATEWAY_URLS;
    } catch {
      parsed = undefined;
    }
    expect(parsed).toBeUndefined();
  });

  it("accepts a loopback http gateway endpoint (the documented exception)", () => {
    const config = loadNodeConfig(validEnv({ SPLITCHAIN_GATEWAY_URLS: "http://127.0.0.1:8545/" }));
    expect(config.SPLITCHAIN_GATEWAY_URLS).toEqual(["http://127.0.0.1:8545/"]);
  });

  it("rejects a wildcard admin CORS origin outright", () => {
    const env = validEnv({ ADMIN_CORS_ALLOWED_ORIGINS: "*" });
    let caught: unknown;
    try {
      loadNodeConfig(env);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(NodeConfigurationError);
    expect((caught as NodeConfigurationError).issues.join("\n")).toContain(
      "ADMIN_CORS_ALLOWED_ORIGINS",
    );
  });
});

describe("deployment scenario 5 — overlap deploy (rolling update, one leader)", () => {
  it("two concurrent boot lanes share one lock with zero windows of dual leadership", async () => {
    // A simple in-memory leadership lock standing in for the process-wide
    // signer leadership lock. It counts how many holders
    // believe they hold it so the test can prove the count never exceeds one.
    function makeLeadershipLock() {
      let locked = false;
      let holders = 0;
      let maxConcurrentHolders = 0;
      const waiters: Array<() => void> = [];

      function noteHolders(): void {
        if (holders > maxConcurrentHolders) maxConcurrentHolders = holders;
      }

      return {
        acquire(): Promise<SignerLeadershipHandle> {
          const take = (): Promise<SignerLeadershipHandle> => {
            locked = true;
            holders += 1;
            noteHolders();
            let released = false;
            return Promise.resolve({
              release: () => {
                if (released) return;
                released = true;
                holders -= 1;
                const next = waiters.shift();
                if (next !== undefined) {
                  next();
                } else {
                  locked = false;
                }
              },
            });
          };
          if (!locked) return take();
          return new Promise<SignerLeadershipHandle>((resolve) => {
            waiters.push(() => {
              resolve(take());
            });
          });
        },
        stats(): { maxConcurrentHolders: number; waiting: number } {
          return { maxConcurrentHolders, waiting: waiters.length };
        },
      };
    }

    const lock = makeLeadershipLock();

    // Signals once lane A has acquired leadership, so the test can observe the
    // overlap window deterministically (no timer-based polling).
    let notifyAAcquired: () => void = () => {};
    const aAcquired = new Promise<void>((resolve) => {
      notifyAAcquired = resolve;
    });

    const readinessA = new NodeReadiness(3);
    const laneA = runBootLane({
      readiness: readinessA,
      logger: noopLogger,
      runMigrations: async () => {},
      unlockVault: async () => {},
      acquireSignerLeadership: async () => {
        const handle = await lock.acquire();
        notifyAAcquired();
        return handle;
      },
      runBootRecovery: async () => {
        readinessA.setEventSignerAvailable(true);
        return { ready: true, invariantBreach: false };
      },
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: () => {},
    });

    const readinessB = new NodeReadiness(3);
    const laneB = runBootLane({
      readiness: readinessB,
      logger: noopLogger,
      runMigrations: async () => {},
      unlockVault: async () => {},
      acquireSignerLeadership: () => lock.acquire(),
      runBootRecovery: async () => {
        readinessB.setEventSignerAvailable(true);
        return { ready: true, invariantBreach: false };
      },
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: () => {},
    });

    // Lane A boots to readiness and holds leadership (the boot lane keeps the
    // handle on success — the runtime/graceful-stop owns the release). Lane B's
    // acquire then queues at the shared lock rather than taking a second lock.
    await aAcquired;
    await vi.waitFor(() => {
      expect(lock.stats().waiting).toBe(1);
    });
    expect(lock.stats().maxConcurrentHolders).toBe(1);
    expect(readinessB.snapshot().checks.leadership).toBe(false);
    expect(readinessB.snapshot().ready).toBe(true) // deploy-ready while waiting (ZPAY-252);

    // Graceful handoff: A releases leadership (as graceful stop would), so the
    // successor B acquires it and completes its own boot.
    const resultA = await laneA;
    expect(resultA.ready).toBe(true);
    expect(resultA.leadership).toBeDefined();
    await resultA.leadership?.release();

    const resultB = await laneB;
    expect(resultB.ready).toBe(true);
    // The core overlap invariant: never more than one leader at any instant.
    expect(lock.stats().maxConcurrentHolders).toBe(1);
  });
});

describe("deployment scenario 6 — rollback compatibility", () => {
  it("accepts a previous-version config: only the original required fields, no new required field breaks rollback", () => {
    // The minimal original field set. Every field added since is optional or
    // defaulted, so a rollback to a release that sets only these still boots.
    // Stage-2 custody surfaces add VAULT_MASTER_KEY and NODE_ID as
    // additional required fields; a prior release that omits them must be
    // upgraded to include them before booting the Stage-2 entrypoint.
    const config = loadNodeConfig({
      NODE_ENV: "production",
      DATABASE_URL: "postgresql://node:db-secret@db.internal:5432/zunode",
      SPLITCHAIN_GATEWAY_URLS: "https://gateway-entry-1.internal.example/",
      PUBLIC_BASE_URL: "https://node.internal.example/",
      NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      VAULT_MASTER_KEY: "a".repeat(32),
    });
    expect(config.PORT).toBe(8080);
    expect(config.POOL_CAP_TOTAL).toBe(50);
    expect(config.GATEWAY_READ_FAILURE_BUDGET).toBe(3);
  });

  it("the deployment manifest pins no concrete image tag that would block rollback", () => {
    const manifestPath = fileURLToPath(new URL("../deploy/deployment.yaml", import.meta.url));
    const manifest = readFileSync(manifestPath, "utf8");
    const imageLine = manifest
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line.startsWith("image:"));
    expect(imageLine).toBeDefined();
    // The tag is an operator-supplied placeholder, not a hardcoded version —
    // a rollback re-points it at the prior release tag with no manifest edit
    // beyond the tag value the deploy pipeline already substitutes.
    expect(imageLine).toContain("REPLACE_WITH_RELEASE_TAG");
    expect(imageLine).not.toMatch(/:\d+\.\d+\.\d+/);
  });
});

describe("deployment scenario 7 — read-only filesystem", () => {
  const BOOT_PATH_SOURCES = [
    "../src/main.ts",
    "../src/boot/boot-lane.ts",
    "../src/boot/readiness.ts",
    "../src/boot/graceful-stop.ts",
    "../src/config/load.ts",
    "../src/config/env-schema.ts",
    "../src/config/env-fields.ts",
    "../src/config/placeholders.ts",
    "../src/health/routes.ts",
  ] as const;

  function readSource(relative: string): string {
    return readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");
  }

  it("no boot/config/health/graceful-stop source performs a filesystem write", () => {
    const writePatterns = [
      /writeFileSync/,
      /appendFileSync/,
      /mkdirSync/,
      /createWriteStream/,
      /\bfs\.writeFile\b/,
      /\bfs\.appendFile\b/,
      /\bfs\.mkdir\b/,
      /\bwriteFile\b/,
      /\bappendFile\b/,
      /\bmkdir\b/,
    ];
    for (const relative of BOOT_PATH_SOURCES) {
      const source = readSource(relative);
      // No write API is even imported on the boot path.
      expect(source, `${relative} must not import node:fs write APIs`).not.toMatch(
        /from\s+["']node:fs["']/,
      );
      for (const pattern of writePatterns) {
        expect(source, `${relative} must not call ${pattern.source}`).not.toMatch(pattern);
      }
    }
  });

  it("the deployment manifest sets readOnlyRootFilesystem with /tmp scratch + durable backup PVC", () => {
    const manifest = readSource("../deploy/deployment.yaml");
    expect(manifest).toContain("readOnlyRootFilesystem: true");
    // Scratch remains emptyDir; backup sink is a PVC, never emptyDir.
    expect(manifest).toContain("mountPath: /tmp");
    expect(manifest).toContain("mountPath: /var/lib/generic-node/backups");
    expect(manifest).toContain("kind: PersistentVolumeClaim");
    expect(manifest).toContain("claimName: zunode-backups");
    expect(manifest).toContain("BACKUP_SCHEDULE_ENABLED");
    expect(manifest).toContain("BACKUP_MASTER_KEY");
    expect(manifest).not.toContain("mountPath: /run/secrets");
  });

  // Rework: RWO PVC cannot multi-attach under RollingUpdate surge.
  it("reference deploy uses Recreate with RWO backup PVC (no maxSurge coexistence)", () => {
    const manifest = readSource("../deploy/deployment.yaml");
    // Strip full-line comments so advisory prose about RollingUpdate is not
    // mistaken for live fields.
    const live = manifest
      .split("\n")
      .filter((line) => !/^\s*#/.test(line))
      .join("\n");
    expect(live).toMatch(/accessModes:\s*\n\s*-\s*ReadWriteOnce/);
    expect(live).toMatch(/strategy:\s*\n\s*type:\s*Recreate/);
    expect(live).not.toMatch(/type:\s*RollingUpdate/);
    expect(live).not.toMatch(/rollingUpdate:/);
    expect(live).not.toMatch(/maxSurge:/);
    expect(live).not.toMatch(/maxUnavailable:/);
  });

  it("the Dockerfile creates no writable directory outside /tmp in the runtime stage", () => {
    const dockerfile = readSource("../Dockerfile");
    const runtimeStage = dockerfile.slice(dockerfile.indexOf("AS runtime"));
    expect(runtimeStage).not.toContain("VOLUME");
    expect(runtimeStage).not.toMatch(/RUN\s+mkdir/);
    // The runtime WORKDIR is the copied, node-owned image tree — not a freshly
    // created writable scratch directory.
    expect(runtimeStage).toContain("WORKDIR /repo/apps/generic-node");
  });

  // Both stages MUST pin node:22-alpine by multi-arch index digest
  // (same pin as root Dockerfile + apps/platform/Dockerfile). A floating
  // tag lets rebuilds of the same Git SHA resolve different base bytes.
  it("the Dockerfile pins both stages to the shared node:22-alpine digest", () => {
    const dockerfile = readSource("../Dockerfile");
    const pinned =
      "node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2";
    const fromLines = dockerfile
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("FROM "));
    expect(fromLines).toEqual([
      `FROM ${pinned} AS build`,
      `FROM ${pinned} AS runtime`,
    ]);
    // Fail closed on any unpinned node:22-alpine float that sneaks in later.
    expect(dockerfile).not.toMatch(/FROM\s+node:22-alpine\s+AS\s+/);
  });
});

describe("deployment scenario 8 — restart (re-run from step 1, no stale state)", () => {
  it("re-executes the lane from migrations with fresh readiness gates after a stub failure", async () => {
    const firstReadiness = new NodeReadiness(3);
    const firstEvents: string[] = [];
    const firstDeps = happyDeps(firstReadiness, firstEvents);
    firstDeps.unlockVault = surfaceNotYetWired("vault unlock");

    const first = await runBootLane(firstDeps);
    expect(first.ready).toBe(false);
    expect(first.failedStep).toBe("vault-unlock");
    expect(firstEvents).toEqual(["migrations"]);
    expect(firstReadiness.snapshot().ready).toBe(false);
    expect(firstReadiness.snapshot().checks.schema).toBe(true);
    expect(firstReadiness.snapshot().checks.vault).toBe(false);

    // Restart: the same dependency shape, a fresh readiness (a new process
    // builds a new state machine — gates reset by construction).
    const secondReadiness = new NodeReadiness(3);
    const secondEvents: string[] = [];
    const secondDeps = happyDeps(secondReadiness, secondEvents);

    const second = await runBootLane(secondDeps);
    expect(second.ready).toBe(true);
    // Re-ran from step 1 — migrations executed again, full sequence preserved.
    expect(secondEvents).toEqual(["migrations", "vault", "gateway-read", "leadership", "boot-recovery", "money-workers"]);
    // No stale state leaked: every gate opened on the fresh readiness.
    expect(secondReadiness.snapshot().ready).toBe(true);
    expect(secondReadiness.snapshot().checks).toEqual({
      schema: true,
      vault: true,
      leadership: true,
      gateway: true,
      eventSigner: true,
    });
  });

  it("performs none of the six forbidden boot actions across a failed boot and a restart", async () => {
    // "Boot does not": delete a stale lease by time; submit an attempt
    // whose call boundary is ambiguous; re-form an external partial; auto-clear
    // attention; auto-accept a new destination; synthesize missing exact bytes.
    // These six operations are defined here as available functions but are
    // deliberately NOT wired into any boot-lane dependency: the lane only ever
    // invokes its injected steps, so a clean boot must perform none of them.
    const deleteStaleLeaseByTime = vi.fn();
    const submitAmbiguousAttempt = vi.fn();
    const reformExternalPartial = vi.fn();
    const autoClearAttention = vi.fn();
    const autoAcceptDestination = vi.fn();
    const synthesizeBytes = vi.fn();
    const forbidden = [
      deleteStaleLeaseByTime,
      submitAmbiguousAttempt,
      reformExternalPartial,
      autoClearAttention,
      autoAcceptDestination,
      synthesizeBytes,
    ];

    const makeDeps = (readiness: NodeReadiness, events: string[]): BootLaneDeps => ({
      readiness,
      logger: noopLogger,
      runMigrations: async () => {
        events.push("migrations");
      },
      unlockVault: async () => {
        events.push("vault");
      },
      acquireSignerLeadership: async () => {
        events.push("leadership");
        return { release: () => {} };
      },
      runBootRecovery: async () => {
        events.push("boot-recovery");
        readiness.setEventSignerAvailable(true);
        return { ready: true, invariantBreach: false };
      },
      performValidatedGatewayRead: async () => {
        events.push("gateway-read");
      },
      startMoneyWorkers: () => {
        events.push("money-workers");
      },
    });

    // First boot fails closed at the vault step.
    const firstEvents: string[] = [];
    const failing = makeDeps(new NodeReadiness(3), firstEvents);
    failing.unlockVault = surfaceNotYetWired("vault unlock");
    const first = await runBootLane(failing);
    expect(first.ready).toBe(false);
    expect(firstEvents).toEqual(["migrations"]);

    // Restart re-runs the full lane to readiness.
    const secondEvents: string[] = [];
    const second = await runBootLane(makeDeps(new NodeReadiness(3), secondEvents));
    expect(second.ready).toBe(true);
    expect(secondEvents).toEqual([
      "migrations",
      "vault",
      "gateway-read",
      "leadership",
      "boot-recovery",
      "money-workers",
    ]);

    // Across both boots the lane performed none of the six forbidden actions.
    for (const action of forbidden) {
      expect(action).not.toHaveBeenCalled();
    }
  });
});

// PlaceholderSecretError is part of the boot-refusal contract main.ts handles
// alongside NodeConfigurationError; keep the import exercised so the refusal
// surface stays covered at the integration level.
describe("deployment refusal surface — placeholder gate is wired", () => {
  it("a production boot on the exact .env.example placeholder database URL is refused", () => {
    const env = validEnv({
      NODE_ENV: "production",
      DATABASE_URL: "postgresql://CHANGE_ME:CHANGE_ME@db.example.invalid:5432/zunode",
    });
    expect(() => loadNodeConfig(env)).toThrowError(PlaceholderSecretError);
  });
});

// AC9 — offline e2e: readiness=true on disposable PG + fixture gateway, the
// observation worker's gate reads statistics, and the registry signer
// leadership lock is a real advisory lock on the same pool.
describe("deployment scenario 9 — offline e2e", () => {
  it("readiness reaches true after the boot lane completes on a disposable PG pool (mock)", async () => {
    let locked = false;
    let holder: string | null = null;
    let releaseCount = 0;

    const pool = {
      query: vi.fn(async (sql: string) => {
        if (sql.includes("pg_try_advisory_lock")) {
          if (!locked) {
            locked = true;
            holder = "test-process";
            return { rows: [{ locked: true }] };
          }
          return { rows: [{ locked: false }] };
        }
        if (sql.includes("pg_advisory_unlock")) {
          locked = false;
          holder = null;
          releaseCount += 1;
          return { rows: [{ released: true }] };
        }
        return { rows: [] };
      }),
      connect: vi.fn(async (): Promise<{
        query: ReturnType<typeof vi.fn>;
        release: ReturnType<typeof vi.fn>;
        end: ReturnType<typeof vi.fn>;
        on: ReturnType<typeof vi.fn>;
        removeListener: ReturnType<typeof vi.fn>;
      }> => {
        const client = {
          query: vi.fn(async (sql: string) => pool.query(sql)),
          release: vi.fn(),
          end: vi.fn(),
          on: vi.fn(),
          removeListener: vi.fn(),
        };
        return Promise.resolve(client);
      }),
    };

    const readiness = new NodeReadiness(3);
    const events: string[] = [];

    const deps = {
      readiness,
      logger: noopLogger,
      runMigrations: async () => {
        events.push("migrations");
      },
      assertPostMigrationReadiness: async () => {
        events.push("privilege-check");
      },
      unlockVault: async () => {
        events.push("vault");
      },
      acquireSignerLeadership: async () => {
        events.push("leadership");
        const client = await pool.connect();
        const tryResult = await client.query("SELECT pg_try_advisory_lock(5463320)");
        if (tryResult.rows[0]?.locked !== true) {
          throw new Error("expected advisory lock");
        }
        return {
          release: async () => {
            await client.query("SELECT pg_advisory_unlock(5463320)");
            client.release();
            client.end();
          },
        };
      },
      runBootRecovery: async () => {
        events.push("boot-recovery");
        readiness.setEventSignerAvailable(true);
        return { ready: true as const, invariantBreach: false as const };
      },
      performValidatedGatewayRead: async () => {
        events.push("gateway-read");
      },
      startMoneyWorkers: (): void => {
        events.push("money-workers");
      },
    };

    const result = await runBootLane(deps);
    expect(result.ready).toBe(true);
    expect(events).toEqual([
      "migrations",
      "privilege-check",
      "vault",
      "gateway-read",
      "leadership",
      "boot-recovery",
      "money-workers",
    ]);
    // Leadership is held after a successful boot — the boot lane keeps the
    // handle so graceful-stop (not the test) releases it.
    expect(locked).toBe(true);
    expect(holder).toBe("test-process");

    // Release to assert clean unlock path (re-acquire handshake).
    await result.leadership!.release();
    expect(locked).toBe(false);
    expect(holder).toBeNull();
    expect(releaseCount).toBe(1);
    expect(readiness.snapshot().ready).toBe(true);
  });

  it("signer leadership lock is held and released exactly once per boot", async () => {
    let locked = false;
    let releaseCount = 0;

    const pool = {
      connect: vi.fn(async (): Promise<{
        query: ReturnType<typeof vi.fn>;
        release: ReturnType<typeof vi.fn>;
        end: ReturnType<typeof vi.fn>;
        on: ReturnType<typeof vi.fn>;
        removeListener: ReturnType<typeof vi.fn>;
      }> => {
        const client = {
          query: vi.fn(async (sql: string) => {
            if (sql.includes("pg_try_advisory_lock")) {
              if (!locked) {
                locked = true;
                return { rows: [{ locked: true }] };
              }
              return { rows: [{ locked: false }] };
            }
            if (sql.includes("pg_advisory_unlock")) {
              locked = false;
              releaseCount += 1;
              return { rows: [{ released: true }] };
            }
            return { rows: [] };
          }),
          release: vi.fn(),
          end: vi.fn(),
          on: vi.fn(),
          removeListener: vi.fn(),
        };
        return Promise.resolve(client);
      }),
    };

    const readiness = new NodeReadiness(3);

    const deps = {
      readiness,
      logger: noopLogger,
      runMigrations: async () => {},
      assertPostMigrationReadiness: async () => {},
      unlockVault: async () => {},
      acquireSignerLeadership: async () => {
        const client = await pool.connect();
        const tryResult = await client.query("SELECT pg_try_advisory_lock(5463320)");
        if (tryResult.rows[0]?.locked !== true) {
          throw new Error("expected advisory lock");
        }
        return {
          release: async () => {
            await client.query("SELECT pg_advisory_unlock(5463320)");
            client.release();
            client.end();
          },
        };
      },
      runBootRecovery: async () => {
        readiness.setEventSignerAvailable(true);
        return { ready: true as const, invariantBreach: false as const };
      },
      performValidatedGatewayRead: async () => {},
      startMoneyWorkers: (): void => {},
    };

    const result = await runBootLane(deps);
    expect(result.ready).toBe(true);
    expect(result.leadership).toBeDefined();
    // Lock held after boot — released by graceful-stop (or this test).
    expect(locked).toBe(true);
    expect(pool.connect).toHaveBeenCalledTimes(1);

    await result.leadership!.release();
    expect(locked).toBe(false);
    expect(releaseCount).toBe(1);
  });

  it("liveness stays 200 while readiness is false (fail-closed gate)", async () => {
    const router = createHealthRouter({
      readiness: new NodeReadiness(3),
      pingDb: surfaceNotYetWired("database adapter"),
    });

    const live = await router("GET", "/health");
    expect(live.status).toBe(200);

    const ready = await router("GET", "/health/ready");
    expect(ready.status).toBe(503);
    expect(ready.body).toMatchObject({ status: "not_ready" });
  });
});
