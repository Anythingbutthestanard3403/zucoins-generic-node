#!/usr/bin/env node
// ZTR-1281 — staging-only, append-only audit_log annotations for the four
// forged EXPIRED_T0_UNCHANGED membership releases of 2026-08-12.
//
// ABSOLUTE RULES
// --------------
// * APPEND audit_log only. Never UPDATE/DELETE audit_log (engine-enforced).
// * Never mutate wallet_lease_memberships, receive_release_proofs, wallets,
//   operations, or any other money/evidence table.
// * Never mint receive_release_proofs to "repair" the biconditional.
// * Staging only. Requires STAGING_CONFIRM=ZTR-1281. Default mode is dry-run
//   (BEGIN … plan … ROLLBACK). --execute COMMITs the inserts.
//
// Idempotent: an op that already has action=incident.manual_release_annotated
// is reported as already_annotated and skipped.
//
// Usage:
//   DATABASE_URL=postgres://… STAGING_CONFIRM=ZTR-1281 \
//     node docs/operations/annotate-forged-expired-t0-releases.mjs \
//       --expect-host <staging-db-hostname>
//   DATABASE_URL=postgres://… STAGING_CONFIRM=ZTR-1281 \
//     node docs/operations/annotate-forged-expired-t0-releases.mjs \
//       --expect-host <staging-db-hostname> --execute
//
// --expect-host is required (ZTR-1296). The gate compares it to the host
// resolved from DATABASE_URL so a production DSN cannot slip through a
// staging-looking shell env.
//
// Incident note: docs/operations/incidents.md
//   § "Historical incident — forged EXPIRED_T0_UNCHANGED releases"
// Root cause: tasks/wallet-unpin-root-cause-2026-08-13.md

import { createHash, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

export const INCIDENT_ID = "ZTR-1281";
export const AUDIT_ACTION = "incident.manual_release_annotated";
export const INCIDENT_DOC =
  "docs/operations/incidents.md#historical-incident--forged-expired_t0_unchanged-releases-staging-2026-08-12";
export const ROOT_CAUSE_DOC = "tasks/wallet-unpin-root-cause-2026-08-13.md";

/** Closed allowlist — the only ops this script will annotate. */
export const FORGED_OPERATION_IDS = Object.freeze([
  "4bec5ae4-2b46-4542-b7e2-9d57105ab9fe",
  "4fc07a73-9b84-474f-a1ca-1ff9f7e70820",
  "5316a5f2-5d19-40f7-9324-fe0ad677646e",
  "e123d38d-3451-4bfe-9e00-7e587debd3e0",
]);

const RELEASE_REASON = "EXPIRED_T0_UNCHANGED";

async function loadPg() {
  try {
    return await import("pg");
  } catch (error) {
    if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  }
  const genericNodeManifest = fileURLToPath(
    new URL("../../apps/generic-node/package.json", import.meta.url),
  );
  return createRequire(genericNodeManifest)("pg");
}

function detailsSha256(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * Read `--expect-host <value>` (or `--expect-host=<value>`) from argv.
 * @param {readonly string[]} argv
 * @returns {string | null} trimmed host, empty string when flag present without value, null when absent
 */
export function parseExpectHost(argv) {
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--expect-host") {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) return "";
      return String(next).trim();
    }
    if (arg.startsWith("--expect-host=")) {
      return String(arg.slice("--expect-host=".length)).trim();
    }
  }
  return null;
}

/**
 * Resolve the connection target host from a postgres DATABASE_URL without
 * printing credentials. Prefers URL hostname; falls back to libpq `host=`
 * query (unix-socket / empty-host forms).
 *
 * @param {string} databaseUrl
 * @returns {{ ok: true, host: string } | { ok: false, reason: string }}
 */
export function resolveDatabaseHost(databaseUrl) {
  if (typeof databaseUrl !== "string" || databaseUrl.trim() === "") {
    return { ok: false, reason: "DATABASE_URL is not set" };
  }
  const raw = databaseUrl.trim();

  // Libpq empty-host + host=/socket form is not always WhatWG-parseable when
  // userinfo is present (`postgres://user@/db?host=/tmp`). Peel query first.
  const qIndex = raw.indexOf("?");
  if (qIndex !== -1) {
    const query = raw.slice(qIndex + 1).split("#", 1)[0];
    const params = new URLSearchParams(query);
    const hostParam = params.get("host");
    if (hostParam !== null && hostParam !== "") {
      // When host= is an absolute socket path, that is the target identity.
      if (hostParam.startsWith("/")) {
        return { ok: true, host: hostParam };
      }
    }
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    // Retry after a minimal empty-host rewrite for `scheme://user@/db?host=…`.
    const rewritten = raw.replace(
      /^((?:postgres|postgresql):\/\/[^/?#]*@)(\/[^?]*)/i,
      "$1localhost$2",
    );
    try {
      parsed = new URL(rewritten);
    } catch {
      return {
        ok: false,
        reason: "refused: DATABASE_URL is not a parseable postgres URL",
      };
    }
  }

  const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
  if (scheme !== "postgres" && scheme !== "postgresql") {
    return {
      ok: false,
      reason: `refused: DATABASE_URL scheme must be postgres/postgresql (got ${scheme})`,
    };
  }

  const hostQuery = parsed.searchParams.get("host");
  if (hostQuery !== null && hostQuery.startsWith("/")) {
    return { ok: true, host: hostQuery };
  }

  // pg percent-encoded unix-socket shorthand in host position.
  if (parsed.hostname.startsWith("%2F") || parsed.hostname.startsWith("%2f")) {
    try {
      return { ok: true, host: decodeURIComponent(parsed.hostname) };
    } catch {
      return { ok: true, host: parsed.hostname };
    }
  }

  if (parsed.hostname !== "") {
    return { ok: true, host: parsed.hostname };
  }

  if (hostQuery !== null && hostQuery !== "") {
    return { ok: true, host: hostQuery };
  }

  return {
    ok: false,
    reason: "refused: DATABASE_URL has no resolvable host",
  };
}

/**
 * Staging gate: STAGING_CONFIRM, ambient env markers, and DATABASE_URL host
 * must match the operator-supplied `--expect-host` (ZTR-1296).
 *
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{ expectHost?: string | null, databaseUrl?: string | null }} [opts]
 */
export function assertStagingGate(env, opts = {}) {
  if (env.STAGING_CONFIRM !== INCIDENT_ID) {
    return {
      ok: false,
      reason:
        `refused: STAGING_CONFIRM must equal ${INCIDENT_ID} (got ${JSON.stringify(env.STAGING_CONFIRM ?? null)}). ` +
        "This script is staging-only.",
    };
  }
  const markers = [
    env.PUBLIC_BASE_URL,
    env.NODE_PUBLIC_BASE_URL,
    env.GENERIC_NODE_ENV,
    env.DEPLOY_ENV,
    env.RAILWAY_ENVIRONMENT,
    env.RAILWAY_ENVIRONMENT_NAME,
  ]
    .filter(Boolean)
    .map((s) => String(s).toLowerCase());
  const productionHints = ["prod", "production", "live"];
  for (const m of markers) {
    for (const hint of productionHints) {
      // "production" / "prod" as a standalone token or obvious host label.
      if (
        m === hint ||
        m.startsWith(`${hint}.`) ||
        m.startsWith(`${hint}-`) ||
        m.includes(`.${hint}.`) ||
        m.includes(`/${hint}`) ||
        m.endsWith(`-${hint}`) ||
        m.endsWith(`.${hint}`)
      ) {
        // Allow explicit staging override only when the marker also says staging.
        if (!(m.includes("stag") || m.includes("lab") || m.includes("dev"))) {
          return {
            ok: false,
            reason: `refused: environment marker looks like production (${m}). Will not annotate.`,
          };
        }
      }
    }
  }

  const expectHost =
    opts.expectHost === undefined ? null : opts.expectHost === null ? null : String(opts.expectHost).trim();
  if (expectHost === null) {
    return {
      ok: false,
      reason:
        "refused: --expect-host <hostname> is required. " +
        "Pass the staging DATABASE_URL host explicitly so a production DSN cannot slip through.",
    };
  }
  if (expectHost === "") {
    return {
      ok: false,
      reason: "refused: --expect-host requires a non-empty hostname",
    };
  }

  const databaseUrl =
    opts.databaseUrl === undefined || opts.databaseUrl === null
      ? env.DATABASE_URL
      : opts.databaseUrl;
  const resolved = resolveDatabaseHost(
    typeof databaseUrl === "string" ? databaseUrl : "",
  );
  if (!resolved.ok) {
    return { ok: false, reason: resolved.reason };
  }

  // DNS hostnames are case-insensitive; socket paths compare as given after
  // normalizing only the TCP hostname form.
  const actual = resolved.host;
  const expectIsSocket = expectHost.startsWith("/");
  const actualIsSocket = actual.startsWith("/");
  const hostsMatch =
    expectIsSocket || actualIsSocket
      ? expectHost === actual
      : expectHost.toLowerCase() === actual.toLowerCase();

  if (!hostsMatch) {
    return {
      ok: false,
      reason:
        `refused: DATABASE_URL host ${JSON.stringify(actual)} does not match ` +
        `--expect-host ${JSON.stringify(expectHost)}. Will not annotate.`,
      databaseHost: actual,
      expectHost,
    };
  }

  return { ok: true, databaseHost: actual, expectHost };
}

function buildDetails({ operationId, membershipId, walletId, releasedAt, releaseProofId }) {
  // Stable key order for a deterministic digest across dry-run / execute.
  const payload = {
    incident: INCIDENT_ID,
    incident_doc: INCIDENT_DOC,
    root_cause_doc: ROOT_CAUSE_DOC,
    operation_id: operationId,
    membership_id: membershipId,
    wallet_id: walletId,
    membership_release_reason: RELEASE_REASON,
    membership_released_at: releasedAt,
    membership_release_proof_id: releaseProofId,
    receive_release_proofs_count: 0,
    note:
      "Membership closed as EXPIRED_T0_UNCHANGED by hand SQL on 2026-08-12 without " +
      "receive_release_proofs or contemporaneous audit. Annotation only; membership not mutated. " +
      "Do not treat as proof-backed auto-release.",
  };
  return JSON.stringify(payload);
}

/**
 * Plan one op. Pure DB reads + optional insert inside the caller's transaction.
 * @returns {Promise<object>}
 */
export async function planOne(client, operationId) {
  const opRes = await client.query(
    `SELECT id::text AS id, node_id::text AS node_id, status::text AS status
       FROM operations
      WHERE id = $1::uuid`,
    [operationId],
  );
  if (opRes.rows.length === 0) {
    return { operationId, outcome: "refused_operation_missing" };
  }
  const { node_id: nodeId, status } = opRes.rows[0];

  const existing = await client.query(
    `SELECT id::text AS id, created_at
       FROM audit_log
      WHERE operation_id = $1::uuid
        AND action = $2
      ORDER BY created_at
      LIMIT 1`,
    [operationId, AUDIT_ACTION],
  );
  if (existing.rows.length > 0) {
    return {
      operationId,
      outcome: "already_annotated",
      auditId: existing.rows[0].id,
      annotatedAt: existing.rows[0].created_at,
      nodeId,
      status,
    };
  }

  const mem = await client.query(
    `SELECT id::text AS id,
            wallet_id::text AS wallet_id,
            release_reason,
            released_at,
            release_proof_id::text AS release_proof_id
       FROM wallet_lease_memberships
      WHERE operation_id = $1::uuid
        AND released_at IS NOT NULL
      ORDER BY released_at DESC NULLS LAST
      LIMIT 1`,
    [operationId],
  );
  if (mem.rows.length === 0) {
    return {
      operationId,
      outcome: "refused_no_released_membership",
      nodeId,
      status,
    };
  }
  const membership = mem.rows[0];
  if (membership.release_reason !== RELEASE_REASON) {
    return {
      operationId,
      outcome: "refused_unexpected_release_reason",
      nodeId,
      status,
      releaseReason: membership.release_reason,
    };
  }

  const proofs = await client.query(
    `SELECT count(*)::int AS n
       FROM receive_release_proofs
      WHERE operation_id = $1::uuid`,
    [operationId],
  );
  const proofCount = proofs.rows[0].n;
  if (proofCount !== 0) {
    // Still annotate? No — if a real proof appeared, this is no longer the
    // forged shape; refuse so a human re-checks rather than labelling it forged.
    return {
      operationId,
      outcome: "refused_receive_release_proof_present",
      nodeId,
      status,
      proofCount,
    };
  }

  const details = buildDetails({
    operationId,
    membershipId: membership.id,
    walletId: membership.wallet_id,
    releasedAt: membership.released_at
      ? new Date(membership.released_at).toISOString()
      : null,
    releaseProofId: membership.release_proof_id,
  });
  const auditId = randomUUID();
  const sha = detailsSha256(details);

  await client.query(
    `INSERT INTO audit_log (
       id, node_id, actor_kind, actor_id, action,
       operation_id, wallet_id, details_text, details_sha256, created_at
     ) VALUES (
       $1::uuid, $2::uuid, 'SYSTEM', $3, $4,
       $5::uuid, $6::uuid, $7, $8, now()
     )`,
    [
      auditId,
      nodeId,
      `ops:${INCIDENT_ID}`,
      AUDIT_ACTION,
      operationId,
      membership.wallet_id,
      details,
      sha,
    ],
  );

  return {
    operationId,
    outcome: "annotated",
    auditId,
    nodeId,
    status,
    walletId: membership.wallet_id,
    membershipId: membership.id,
    detailsSha256: sha,
  };
}

export async function main({ argv = process.argv, env = process.env } = {}) {
  const execute = argv.includes("--execute");
  const expectHost = parseExpectHost(argv);
  const gate = assertStagingGate(env, {
    expectHost,
    databaseUrl: env.DATABASE_URL,
  });
  if (!gate.ok) {
    console.error(
      JSON.stringify(
        {
          outcome: "refused_gate",
          reason: gate.reason,
          ...(gate.databaseHost !== undefined ? { databaseHost: gate.databaseHost } : {}),
          ...(gate.expectHost !== undefined ? { expectHost: gate.expectHost } : {}),
        },
        null,
        2,
      ),
    );
    return 2;
  }

  const connectionString = env.DATABASE_URL;
  // assertStagingGate already required a resolvable DATABASE_URL host.
  const databaseHost = gate.databaseHost;

  const { Client } = await loadPg();
  const client = new Client({ connectionString });
  await client.connect();

  const results = [];
  try {
    await client.query("BEGIN");
    for (const operationId of FORGED_OPERATION_IDS) {
      results.push(await planOne(client, operationId));
    }

    const summary = {
      incident: INCIDENT_ID,
      mode: execute ? "execute" : "dry-run",
      databaseHost,
      expectHost: gate.expectHost,
      results,
      annotated: results.filter((r) => r.outcome === "annotated").length,
      already_annotated: results.filter((r) => r.outcome === "already_annotated").length,
      refused: results.filter((r) => String(r.outcome).startsWith("refused_")).length,
    };

    if (!execute) {
      await client.query("ROLLBACK");
      console.log(JSON.stringify({ ...summary, committed: false }, null, 2));
      return summary.refused > 0 ? 1 : 0;
    }

    // Refuse to commit a partial surprise: any hard refusal aborts the batch.
    if (summary.refused > 0) {
      await client.query("ROLLBACK");
      console.error(JSON.stringify({ ...summary, committed: false }, null, 2));
      return 1;
    }

    await client.query("COMMIT");
    console.log(JSON.stringify({ ...summary, committed: true }, null, 2));
    return 0;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // ignore
    }
    console.error(
      JSON.stringify(
        {
          outcome: "error",
          message: error instanceof Error ? error.message : String(error),
        },
        null,
        2,
      ),
    );
    return 2;
  } finally {
    await client.end();
  }
}


if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main({});
}
