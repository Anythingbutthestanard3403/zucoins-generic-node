// Typed deployment-manifest validator for the reference Stage-2 node.
//
// A hand-rolled indentation/regex reader is not enough here: bound to raw
// manifest TEXT, it can select the FIRST `- name:` env block rather than the
// typed Deployment container, a duplicated env key silently collapses,
// `optional: true` in a comment can satisfy a `.test()`, and a securityContext
// value written only in a comment string passes. Each of those is a fail-open
// hole a text reader cannot close.
//
// This module parses the manifest into typed YAML objects with js-yaml, then
// asserts every invariant against the TYPED fields:
//   * duplicate mapping keys are rejected by js-yaml itself (YAMLException);
//   * anchors / aliases / merge keys (`&a`, `*a`, `<<:`) are rejected by the
//     compose-time listener — a reference production manifest has no use for
//     them and they are an obfuscation vector past a shape check;
//   * the Deployment is selected by kind + metadata.name === "zunode", and the
//     container by name === "node" (never "the first env block in the doc");
//   * env names are unique, and each entry is `value` XOR a NON-optional
//     secretKeyRef — a comment can never satisfy a typed boolean/string;
//   * securityContext.runAsNonRoot / readOnlyRootFilesystem, the readiness
//     probe path, and the durable-backup PVC claim are read as typed values.
//
// Invariants enforced: mandatory gateway config; custody roots from the secret
// store only; separate liveness/readiness probes; the shutdown-sequence contract.

import yaml from "js-yaml";

// The Stage-2 runtime fields the entrypoint refuses to boot without. Value
// fields are first-boot config; secret fields are injected from the platform
// store and MUST NOT carry a literal value in source.
export const VALUE_FIELDS = ["SPLITCHAIN_GATEWAY_URLS", "PUBLIC_BASE_URL", "NODE_ID"];
export const SECRET_FIELDS = new Map([
  ["DATABASE_URL", "database-url"],
  ["VAULT_MASTER_KEY", "vault-master-key"],
  ["BACKUP_MASTER_KEY", "backup-master-key"],
]);
export const MANDATORY_ENV = [...VALUE_FIELDS, ...SECRET_FIELDS.keys()];

export class ManifestError extends Error {
  constructor(message) {
    super(message);
    this.name = "ManifestError";
  }
}

function fail(message) {
  throw new ManifestError(message);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Parse every document. js-yaml rejects duplicated mapping keys on its own; the
// listener rejects any anchored/aliased node so a `<<:` merge or `*alias` cannot
// smuggle env in past the typed checks below.
function loadDocuments(text) {
  const docs = [];
  try {
    yaml.loadAll(
      text,
      (doc) => {
        if (doc !== undefined && doc !== null) docs.push(doc);
      },
      {
        listener: (_event, state) => {
          if (state.anchor !== undefined && state.anchor !== null) {
            fail("anchors, aliases and merge keys are forbidden in the reference manifest");
          }
        },
      },
    );
  } catch (err) {
    if (err instanceof ManifestError) throw err;
    fail(`manifest is not valid YAML: ${(err && err.reason) || (err && err.message) || String(err)}`);
  }
  return docs;
}

function selectSingle(docs, kind, name, label) {
  const matches = docs.filter(
    (doc) => isPlainObject(doc) && doc.kind === kind && isPlainObject(doc.metadata) && doc.metadata.name === name,
  );
  if (matches.length === 0) fail(`manifest omits the ${label} (${kind} metadata.name=${name})`);
  if (matches.length > 1) fail(`manifest declares ${matches.length} ${label} objects; expected exactly one`);
  return matches[0];
}

/**
 * Parse and validate the reference deployment manifest. Returns a typed view
 * of the fields the smoke needs, or throws ManifestError on the first
 * violation (per-field fail-closed). Never returns partial success.
 */
export function parseDeploymentManifest(text) {
  const docs = loadDocuments(text);

  const deployment = selectSingle(docs, "Deployment", "zunode", "zunode Deployment");
  const pvc = selectSingle(docs, "PersistentVolumeClaim", "zunode-backups", "durable-backup PVC");

  const podSpec = deployment?.spec?.template?.spec;
  if (!isPlainObject(podSpec)) fail("Deployment spec.template.spec is not an object");

  const podSecurity = podSpec.securityContext;
  if (!isPlainObject(podSecurity) || podSecurity.runAsNonRoot !== true) {
    fail("pod securityContext.runAsNonRoot must be the boolean true");
  }

  const containers = podSpec.containers;
  if (!Array.isArray(containers)) fail("Deployment pod spec has no containers array");
  const nodeContainers = containers.filter((c) => isPlainObject(c) && c.name === "node");
  if (nodeContainers.length === 0) fail('no container named "node" in the zunode pod');
  if (nodeContainers.length > 1) fail('more than one container named "node" in the zunode pod');
  const container = nodeContainers[0];

  const cSec = container.securityContext;
  if (!isPlainObject(cSec) || cSec.readOnlyRootFilesystem !== true) {
    fail("node container securityContext.readOnlyRootFilesystem must be the boolean true");
  }
  if (cSec.allowPrivilegeEscalation !== false) {
    fail("node container securityContext.allowPrivilegeEscalation must be the boolean false");
  }
  const drop = cSec.capabilities?.drop;
  if (!Array.isArray(drop) || !drop.includes("ALL")) {
    fail("node container securityContext.capabilities.drop must include ALL");
  }

  // Typed env parse — unique names, value XOR non-optional secretKeyRef.
  if (!Array.isArray(container.env)) fail("node container has no env array");
  const env = new Map();
  for (const entry of container.env) {
    if (!isPlainObject(entry) || typeof entry.name !== "string") {
      fail("every env entry must be an object with a string name");
    }
    if (env.has(entry.name)) fail(`duplicate env name ${entry.name}`);
    const hasValue = Object.prototype.hasOwnProperty.call(entry, "value");
    const hasValueFrom = Object.prototype.hasOwnProperty.call(entry, "valueFrom");
    if (hasValue === hasValueFrom) {
      fail(`env ${entry.name} must set exactly one of value or valueFrom`);
    }
    if (hasValue) {
      if (typeof entry.value !== "string") fail(`env ${entry.name} value must be a string`);
      env.set(entry.name, { kind: "value", value: entry.value });
      continue;
    }
    const ref = entry.valueFrom?.secretKeyRef;
    if (!isPlainObject(ref)) fail(`env ${entry.name} valueFrom must be a secretKeyRef`);
    // `optional` is a STRICT boolean. js-yaml has already typed the node, so a
    // quoted "true"/"false" or a numeric 1/0 is a malformed manifest, not an
    // optional flag to coerce — the old `=== true` check silently waved those
    // truthy spellings through (fail-open). Reject any non-boolean here rather
    // than guess intent, then fail-closed on a real `optional: true`.
    if (Object.prototype.hasOwnProperty.call(ref, "optional")) {
      if (typeof ref.optional !== "boolean") {
        fail(`env ${entry.name} secretKeyRef optional must be a boolean, not ${typeof ref.optional} (malformed manifest)`);
      }
      if (ref.optional) fail(`env ${entry.name} secretKeyRef must not be optional (fail-closed)`);
    }
    if (typeof ref.name !== "string" || typeof ref.key !== "string") {
      fail(`env ${entry.name} secretKeyRef must name a secret and a key`);
    }
    env.set(entry.name, { kind: "secret", secretName: ref.name, secretKey: ref.key });
  }

  // Mandatory fields present and of the right injection kind.
  for (const name of VALUE_FIELDS) {
    const e = env.get(name);
    if (e === undefined) fail(`manifest omits mandatory ${name}`);
    if (e.kind !== "value") fail(`${name} must be an inline value, not a secretKeyRef`);
  }
  for (const [name, key] of SECRET_FIELDS) {
    const e = env.get(name);
    if (e === undefined) fail(`manifest omits mandatory ${name}`);
    if (e.kind !== "secret") fail(`${name} is a custody root — it must be a secretKeyRef, never a literal value`);
    if (e.secretName !== "zunode-secrets" || e.secretKey !== key) {
      fail(`${name} must reference zunode-secrets/${key}`);
    }
  }

  // Probes read as typed fields, not matched over comment text.
  const readinessPath = container.readinessProbe?.httpGet?.path;
  if (readinessPath !== "/health/ready") fail("readinessProbe.httpGet.path must be /health/ready");
  const livenessPath = container.livenessProbe?.httpGet?.path;
  if (livenessPath !== "/health") fail("livenessProbe.httpGet.path must be /health");

  // Durable-backup sink: a volume claims the PVC; the PVC is ReadWriteOnce.
  const volumes = Array.isArray(podSpec.volumes) ? podSpec.volumes : [];
  const claimsBackups = volumes.some(
    (v) => isPlainObject(v) && v.persistentVolumeClaim?.claimName === "zunode-backups",
  );
  if (!claimsBackups) fail("a pod volume must claim the zunode-backups PVC");
  const accessModes = pvc?.spec?.accessModes;
  if (!Array.isArray(accessModes) || !accessModes.includes("ReadWriteOnce")) {
    fail("zunode-backups PVC must be ReadWriteOnce");
  }

  return {
    containerName: container.name,
    env,
    podSecurityContext: podSecurity,
    containerSecurityContext: cSec,
    readinessPath,
    livenessPath,
    pvcClaimName: "zunode-backups",
  };
}

const PLACEHOLDER = /REPLACE_WITH_/;

/**
 * Build a boot-ready environment from the parsed manifest: value fields keep
 * their manifest value unless they are an operator placeholder, which is
 * substituted from `substitutions`; secret fields are filled from the synthetic
 * Secret `secretValues[secretKey]`. This is what lets the smoke feed the
 * manifest's own field set through the real config loader and boot lane.
 */
export function deriveSmokeEnv(parsed, { substitutions, secretValues }) {
  const env = {};
  for (const [name, e] of parsed.env) {
    if (e.kind === "value") {
      env[name] = PLACEHOLDER.test(e.value) ? mustGet(substitutions, name, "substitution") : e.value;
    } else {
      env[name] = mustGet(secretValues, e.secretKey, "synthetic secret value");
    }
  }
  return env;
}

function mustGet(record, key, what) {
  const value = record?.[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new ManifestError(`missing ${what} for ${key}`);
  }
  return value;
}
