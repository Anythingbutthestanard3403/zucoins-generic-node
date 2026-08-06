// The reference Stage-2 deployment manifest is validated by TYPED
// YAML parse, and the manifest's own field set is proven boot-sufficient and
// fail-closed per field by driving it through the real config loader and boot
// lane against a synthetic Secret / Postgres / gateway.
//
// Invariants: mandatory gateway config; custody roots from the secret store
// only; separate liveness/readiness probes; the frozen shutdown sequence.
//
// The three prior FAIL findings this file now covers:
//   AC#3  the validator binds to typed objects (js-yaml), not raw text — the
//         adversarial table below reddens on every shape the old regex reader
//         waved through (wrong container, duplicate env, optional secret,
//         comment-only securityContext).
//   AC#2  the manifest-derived env loads the real custody config and runs the
//         real boot lane to the DB + validated-gateway steps ("reaches boot"),
//         and omitting any mandatory field refuses boot before it (fail-closed).
//   secrets never enter source — custody roots are secretKeyRef only.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  parseDeploymentManifest,
  deriveSmokeEnv,
  ManifestError,
  MANDATORY_ENV,
  SECRET_FIELDS,
} from "../deploy/validate-manifest.mjs";
import { loadCustodyNodeConfig, NodeConfigurationError } from "../src/config/index.js";
import { PlaceholderSecretError } from "../src/config/placeholders.js";
import { runBootLane, NodeReadiness, type SignerLeadershipHandle } from "../src/boot/index.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const manifestText = readFileSync(`${root}/deploy/deployment.yaml`, "utf8");

// Valid synthetic operator substitutions + Secret used to make the placeholder
// reference manifest boot. Never real secrets; VAULT and BACKUP keys differ so
// the custody-domain-separation invariant is satisfied.
const SUBSTITUTIONS = {
  SPLITCHAIN_GATEWAY_URLS: "https://gateway.internal.example/",
  PUBLIC_BASE_URL: "https://node.internal.example/",
  NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
};
const SECRET_VALUES = {
  "database-url": "postgresql://node:secret@db.internal:5432/zunode",
  "vault-master-key": `vault-${"v".repeat(32)}`,
  "backup-master-key": `backup-${"b".repeat(32)}`,
};

function derivedEnv(): Record<string, string | undefined> {
  const parsed = parseDeploymentManifest(manifestText);
  return deriveSmokeEnv(parsed, { substitutions: SUBSTITUTIONS, secretValues: SECRET_VALUES });
}

describe("reference Stage-2 deployment — typed manifest (AC#1 / AC#3)", () => {
  it("parses to the zunode Deployment → node container with every mandatory field", () => {
    const parsed = parseDeploymentManifest(manifestText);
    expect(parsed.containerName).toBe("node");
    for (const name of MANDATORY_ENV) expect(parsed.env.has(name), name).toBe(true);

    // Non-secret first-boot values are inline placeholders that fail schema
    // until the operator substitutes them.
    for (const name of ["SPLITCHAIN_GATEWAY_URLS", "PUBLIC_BASE_URL", "NODE_ID"]) {
      expect(parsed.env.get(name)?.kind).toBe("value");
    }
    // Custody roots are platform secrets, never inline values.
    for (const [name, key] of SECRET_FIELDS) {
      const e = parsed.env.get(name);
      expect(e?.kind).toBe("secret");
      expect(e).toMatchObject({ secretName: "zunode-secrets", secretKey: key });
    }
    // Typed security posture, read as booleans (a comment cannot satisfy these).
    expect(parsed.podSecurityContext.runAsNonRoot).toBe(true);
    expect(parsed.containerSecurityContext.readOnlyRootFilesystem).toBe(true);
    expect(parsed.readinessPath).toBe("/health/ready");
    expect(parsed.livenessPath).toBe("/health");
  });

  // The RED seam: each mutation is a manifest the previous raw-text reader
  // accepted. A typed parse must reject every one.
  const mutations: ReadonlyArray<readonly [string, string]> = [
    // A duplicate env name (raw reader let the last win, accepting an attacker override).
    [
      "duplicate env name",
      manifestText.replace(
        '- name: PORT\n              value: "8080"',
        '- name: PORT\n              value: "8080"\n            - name: PORT\n              value: "9090"',
      ),
    ],
    // optional: true on a custody secret (raw reader only matched the string "true").
    [
      "optional custody secret",
      manifestText.replace(
        "key: vault-master-key",
        "key: vault-master-key\n                  optional: true",
      ),
    ],
    // A literal custody value in source (raw reader keyed off secretKeyRef presence).
    [
      "literal custody value",
      manifestText.replace(
        "- name: VAULT_MASTER_KEY\n              valueFrom:\n                secretKeyRef:\n                  name: zunode-secrets\n                  key: vault-master-key",
        '- name: VAULT_MASTER_KEY\n              value: "inline-vault-key-must-never-live-in-source"',
      ),
    ],
    // securityContext written only as a comment (raw reader .test() matched it).
    [
      "comment-only readOnlyRootFilesystem",
      manifestText.replace("readOnlyRootFilesystem: true", "# readOnlyRootFilesystem: true"),
    ],
    // Wrong readiness probe path.
    ["wrong readiness path", manifestText.replace("path: /health/ready", "path: /healthz")],
    // A missing mandatory field.
    [
      "missing gateway field",
      manifestText.replace(
        /- name: SPLITCHAIN_GATEWAY_URLS\n {14}value: "REPLACE_WITH_GATEWAY_URLS"\n/,
        "",
      ),
    ],
    // An anchor/alias injection.
    [
      "anchor/alias env injection",
      manifestText.replace(
        "env:",
        'env:\n            - name: EVIL\n              value: &x "x"\n            - name: EVIL2\n              value: *x',
      ),
    ],
    // A duplicate mapping key (js-yaml rejects natively).
    [
      "duplicate mapping key",
      manifestText.replace("kind: Deployment", "kind: Deployment\nkind: Deployment"),
    ],
    // The node container renamed — selection must not fall back to "first container".
    ["no node container", manifestText.replace("- name: node", "- name: sidecar")],
  ];

  it.each(mutations)("fail-closed on manifest defect: %s", (_label, mutated) => {
    expect(() => parseDeploymentManifest(mutated)).toThrow(ManifestError);
  });

  // AC#3 residual (whack-a-mole): a secretKeyRef `optional` is a STRICT boolean.
  // The prior `=== true` check only caught the boolean, so every truthy-but-not-
  // boolean spelling was a fail-open hole — a custody secret marked optional in a
  // form the check didn't recognise would be treated as required (or vice-versa).
  // Each spelling below must be rejected as a MALFORMED manifest; only a real
  // boolean is read. (These go RED against the old `ref.optional === true`.)
  const badOptional: ReadonlyArray<readonly [string, string]> = [
    ['optional: "true" (quoted string)', 'optional: "true"'],
    ['optional: "false" (quoted string)', 'optional: "false"'],
    ["optional: 1 (numeric truthy)", "optional: 1"],
    ["optional: 0 (numeric falsy)", "optional: 0"],
    ["optional: yes (YAML 1.1 truthy, a string under js-yaml core)", "optional: yes"],
    ["optional: on (YAML 1.1 truthy, a string under js-yaml core)", "optional: on"],
  ];
  it.each(badOptional)("rejects non-boolean secretKeyRef optional: %s", (_label, optionalLine) => {
    const mutated = manifestText.replace(
      "key: vault-master-key",
      `key: vault-master-key\n                  ${optionalLine}`,
    );
    expect(() => parseDeploymentManifest(mutated)).toThrow(ManifestError);
  });

  // A real boolean is read: `optional: true` fails closed (custody secret must
  // not be optional), `optional: false` is the accepted required form.
  it("fails closed on a real boolean optional: true", () => {
    const mutated = manifestText.replace(
      "key: vault-master-key",
      "key: vault-master-key\n                  optional: true",
    );
    expect(() => parseDeploymentManifest(mutated)).toThrow(ManifestError);
  });
  it("accepts a required secretKeyRef with an explicit boolean optional: false", () => {
    const mutated = manifestText.replace(
      "key: vault-master-key",
      "key: vault-master-key\n                  optional: false",
    );
    expect(() => parseDeploymentManifest(mutated)).not.toThrow();
  });
});

describe("manifest boots the real config + boot lane (AC#2)", () => {
  // The manifest's own field set (placeholders substituted, secrets from a
  // synthetic Secret) loads the real custody config and drives the real boot
  // lane to the DB probe and the validated gateway read — the "reaches
  // DB/gateway boot" the smoke previously never exercised. Network-contained:
  // the DB and gateway are injected synthetic deps (blocks real sockets).
  it("reaches migrations, DB ping, and the validated gateway read, then arms money workers", async () => {
    const config = loadCustodyNodeConfig(derivedEnv());
    expect(config.SPLITCHAIN_GATEWAY_URLS.length).toBeGreaterThan(0);

    const events: string[] = [];
    const gatewaySeen: string[][] = [];
    const readiness = new NodeReadiness(config.GATEWAY_READ_FAILURE_BUDGET);
    const makeHandle = (): SignerLeadershipHandle => ({
      release: () => events.push("leadership:release"),
    });
    const result = await runBootLane({
      readiness,
      logger: { info: () => {}, error: () => {} },
      runMigrations: async () => {
        events.push("migrations");
      },
      unlockVault: async () => {
        events.push("vault");
      },
      acquireSignerLeadership: async () => {
        events.push("leadership");
        return makeHandle();
      },
      runBootRecovery: async () => {
        events.push("boot-recovery");
        // Mirrors main.ts: a successful recovery has ensured EVENT_SIGNING.
        readiness.setEventSignerAvailable(true);
        return { ready: true as const, invariantBreach: false as const };
      },
      performValidatedGatewayRead: async () => {
        // The manifest's gateway endpoints are what the boot probe reads.
        gatewaySeen.push([...config.SPLITCHAIN_GATEWAY_URLS]);
        events.push("gateway-read");
      },
      startMoneyWorkers: () => {
        events.push("money-workers");
      },
    });

    expect(result.ready).toBe(true);
    expect(events).toEqual([
      "migrations",
      "vault",
      "leadership",
      "boot-recovery",
      "gateway-read",
      "money-workers",
    ]);
    expect(gatewaySeen).toEqual([["https://gateway.internal.example/"]]);
    expect(readiness.snapshot().ready).toBe(true);
  });

  it.each(MANDATORY_ENV)(
    "refuses boot when %s is omitted (per-field fail-closed, before any DB/gateway work)",
    (field) => {
      const env = derivedEnv();
      env[field] = undefined;
      // A configuration or placeholder-secret refusal, never a silent pass.
      let threw: unknown;
      try {
        loadCustodyNodeConfig(env);
      } catch (err) {
        threw = err;
      }
      expect(
        threw instanceof NodeConfigurationError || threw instanceof PlaceholderSecretError,
        `${field} must refuse boot`,
      ).toBe(true);
    },
  );
});

describe("secrets never enter source (AC#4)", () => {
  it("keeps custody roots as secretKeyRef and carries no literal secret material", () => {
    const parsed = parseDeploymentManifest(manifestText);
    for (const [name] of SECRET_FIELDS) {
      expect(parsed.env.get(name)?.kind).toBe("secret");
    }
    expect(manifestText).not.toContain("NODE_IDENTITY_SEED");
  });

  it("ships the deployment-image smoke as a runnable package script", () => {
    const pkg = JSON.parse(readFileSync(`${root}/package.json`, "utf8")) as {
      scripts?: Record<string, string>;
    };
    expect(pkg.scripts?.["smoke:deployment-image"]).toBe("node deploy/smoke-image.mjs");
    const smoke = readFileSync(`${root}/deploy/smoke-image.mjs`, "utf8");
    expect(smoke).toContain("parseDeploymentManifest");
    expect(smoke).toContain("/health/ready");
    expect(smoke).toContain("runBootLane");
  });
});
