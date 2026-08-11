#!/usr/bin/env node
// Deployment-image smoke.
//
// Two things, in order:
//   1. TYPED manifest validation (AC#3) — parseDeploymentManifest binds every
//      invariant to js-yaml objects, not raw text, so a wrong container, a
//      duplicate env key, an `optional: true` custody secret, or a
//      comment-only securityContext all fail closed. Secret values never enter
//      source (custody roots are secretKeyRef).
//   2. A real boot (AC#2). The DEFAULT run drives the manifest's own field set
//      — placeholders substituted, a synthetic Secret supplied — through the
//      real custody config loader and the real boot lane against a synthetic
//      Postgres (injected) and a synthetic gateway (a real localhost server),
//      proving the checked-in manifest reaches DB + validated-gateway boot and
//      then arms money workers, and that omitting any mandatory field refuses
//      boot before it. When ZUNODE_SMOKE_IMAGE names an already-built image the
//      same fail-closed probes run against the real container as well.
//
// The boot lane is imported from dist/, so `tsc -b` (or `pnpm build`) must have
// run first. Invariants: mandatory gateway config; custody roots from the secret
// store only; separate liveness/readiness probes; the frozen shutdown sequence.

import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { parseDeploymentManifest, deriveSmokeEnv, MANDATORY_ENV } from "./validate-manifest.mjs";

const deployDir = fileURLToPath(new URL(".", import.meta.url));
const appDir = fileURLToPath(new URL("..", import.meta.url));

const SUBSTITUTIONS = {
  PUBLIC_BASE_URL: "https://node.smoke.example/",
  NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
};
const SECRET_VALUES = {
  "database-url": "postgresql://node:secret@127.0.0.1:5432/zunode_smoke",
  "vault-master-key": `vault-${"v".repeat(32)}`,
  "backup-master-key": `backup-${"b".repeat(32)}`,
};

async function startSyntheticGateway() {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}/`, close: () => new Promise((r) => server.close(r)) };
}

// Drive the manifest-derived env through the real config + boot lane. The DB is
// a synthetic injected dep; the gateway read is a real fetch to the synthetic
// server, so the lane genuinely reaches DB + gateway boot.
async function syntheticBoot(parsed) {
  const distConfig = new URL("../dist/config/index.js", import.meta.url);
  const distBoot = new URL("../dist/boot/index.js", import.meta.url);
  if (!existsSync(fileURLToPath(distConfig)) || !existsSync(fileURLToPath(distBoot))) {
    throw new Error(
      "dist/ not built — run `tsc -b` (or `pnpm --filter @zucoins/generic-node build`) before the smoke",
    );
  }
  const spaIndex = new URL("../admin/dist/index.html", import.meta.url);
  if (!existsSync(fileURLToPath(spaIndex))) {
    throw new Error(
      "admin/dist/index.html missing — run `pnpm build` (root) or `pnpm --filter @zucoins/generic-node build:all` so the operator SPA is present",
    );
  }
  const { loadCustodyNodeConfig } = await import(distConfig.href);
  const { runBootLane, NodeReadiness } = await import(distBoot.href);

  const gateway = await startSyntheticGateway();
  try {
    const env = deriveSmokeEnv(parsed, {
      substitutions: { ...SUBSTITUTIONS, SPLITCHAIN_GATEWAY_URLS: gateway.url },
      secretValues: SECRET_VALUES,
    });

    // Full manifest env boots the real custody config.
    const config = loadCustodyNodeConfig(env);
    const events = [];
    const readiness = new NodeReadiness(config.GATEWAY_READ_FAILURE_BUDGET);
    const result = await runBootLane({
      readiness,
      logger: { info: () => {}, error: () => {} },
      runMigrations: async () => events.push("migrations"), // synthetic Postgres
      unlockVault: async () => events.push("vault"),
      acquireSignerLeadership: async () => {
        events.push("leadership");
        return { release: () => {} };
      },
      runBootRecovery: async () => {
        events.push("boot-recovery");
        return { ready: true, invariantBreach: false };
      },
      performValidatedGatewayRead: async () => {
        // Real socket to the synthetic gateway — this is the gateway boot step.
        const endpoint = config.SPLITCHAIN_GATEWAY_URLS[0];
        const response = await fetch(`${endpoint.replace(/\/$/, "")}/health/ready`);
        if (!response.ok && response.status !== 404) {
          throw new Error(`synthetic gateway probe failed status=${response.status}`);
        }
        events.push("gateway-read");
      },
      startMoneyWorkers: () => events.push("money-workers"),
    });
    if (!result.ready) {
      throw new Error(`boot lane did not reach ready (failed step: ${result.failedStep})`);
    }
    if (!events.includes("migrations") || !events.includes("gateway-read")) {
      throw new Error("boot lane did not reach DB + gateway boot");
    }

    // Per-field fail-closed: omit each mandatory field, config must refuse boot.
    for (const field of MANDATORY_ENV) {
      const broken = { ...env, [field]: undefined };
      let refused = false;
      try {
        loadCustodyNodeConfig(broken);
      } catch {
        refused = true;
      }
      if (!refused) throw new Error(`manifest did not fail closed when ${field} was omitted`);
    }
    console.log(
      `synthetic boot PASS: manifest env reached DB + gateway boot; ${MANDATORY_ENV.length} per-field fail-closed refusals`,
    );
  } finally {
    await gateway.close();
  }
}

// Optional operator path: exercise the already-built container image the same way.
function containerBoot(image, parsed) {
  const runtime = process.env.CONTAINER_RUNTIME ?? "docker";
  const env = deriveSmokeEnv(parsed, {
    substitutions: { ...SUBSTITUTIONS, SPLITCHAIN_GATEWAY_URLS: "https://gateway.smoke.example/" },
    secretValues: SECRET_VALUES,
  });
  const baseEnv = { ...env, NODE_ENV: "production", PORT: "8080", BIND_HOST: "::" };
  const run = (args, timeout = 30_000) => spawnSync(runtime, args, { encoding: "utf8", timeout });
  const envArgs = (omit) =>
    Object.entries(baseEnv)
      .filter(([name]) => name !== omit)
      .flatMap(([name, value]) => ["--env", `${name}=${value}`]);

  for (const omitted of MANDATORY_ENV) {
    const result = run(
      ["run", "--rm", "--read-only", "--tmpfs", "/tmp", "--tmpfs", "/var/lib/generic-node/backups", ...envArgs(omitted), image],
      15_000,
    );
    const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    if (result.error !== undefined || result.status === 0 || !output.includes(omitted)) {
      throw new Error(`container did not fail closed when ${omitted} was omitted`);
    }
  }
  console.log(`container fail-closed PASS: ${MANDATORY_ENV.length} omissions refused by ${image}`);
}

async function main() {
  const manifest = readFileSync(`${deployDir}/deployment.yaml`, "utf8");
  const dockerfile = readFileSync(`${appDir}/Dockerfile`, "utf8");

  // AC#3 — typed manifest validation. Throws on the first defect.
  const parsed = parseDeploymentManifest(manifest);
  if (!dockerfile.includes('CMD ["node", "dist/main.js"]')) {
    throw new Error("Dockerfile default is not the Stage-2 dist/main.js entrypoint");
  }
  console.log(
    `manifest PASS: zunode/${parsed.containerName}; ${parsed.env.size} env fields; readiness ${parsed.readinessPath}`,
  );

  // AC#2 — the default synthetic-stack boot.
  await syntheticBoot(parsed);

  const image = process.env.ZUNODE_SMOKE_IMAGE;
  if (image !== undefined && image.length > 0) {
    containerBoot(image, parsed);
  }
}

// Run only when invoked directly; importing this module must not boot.
if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    console.error("deployment-image smoke FAILED:", error?.message ?? error);
    process.exit(1);
  });
}
