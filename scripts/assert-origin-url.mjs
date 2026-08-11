#!/usr/bin/env node
/**
 * Assert that `origin` points at the real GitHub remote before any
 * lane trusts `origin/main`.
 *
 * A `git clone --local <path>` legitimately sets origin to that path. In that
 * state `git fetch origin` is a no-op against the parent tree's refs, so
 * `origin/main` can be stale while the command "succeeds". This is a silent-
 * corruption class bug for every consumer of origin/main (verify-local.sh
 * gitleaks range, check-lane-collisions.mjs three-dot diffs, money-path
 * derive, etc.).
 *
 * Governing: ORCHESTRATION.md §"Concurrency — the claim mutex" (lane bootstrap);
 * CLAUDE.md §"Verification before any PR" (no CI runs; local verification is
 * the only gate).
 *
 * Exit: 0 = origin is the canonical GitHub remote; 1 = not (prints the repair
 * one-liner); 2 = could not read origin (e.g. no git repo / no remote).
 */

import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Owner/repo path that every accepted origin form must resolve to. */
export const CANONICAL_OWNER_REPO = "Anythingbutthestanard3403/zucoins-generic-node";

/** Preferred repair target (https form with .git suffix). */
export const CANONICAL_ORIGIN_URL =
  "https://github.com/Anythingbutthestanard3403/zucoins-generic-node.git";

/**
 * One-liner a lane runs to re-point a poisoned origin and refresh canon refs.
 * Printed on every failure so the operator never has to re-derive it.
 */
export const REPAIR_COMMAND =
  `git remote set-url origin ${CANONICAL_ORIGIN_URL} && git fetch origin --prune`;

/**
 * Classify a remote URL string.
 *
 * Accepted forms (optional trailing `.git`, case-insensitive host/scheme):
 *   - https://github.com/Anythingbutthestanard3403/zucoins-generic-node[.git]
 *   - http://github.com/... (rare; still GitHub)
 *   - git@github.com:Anythingbutthestanard3403/zucoins-generic-node[.git]
 *   - ssh://git@github.com/Anythingbutthestanard3403/zucoins-generic-node[.git]
 *
 * Everything else (local absolute/relative paths, file://, other GitHub
 * repos, non-GitHub hosts) is rejected. A local-path origin is *fine for
 * creating* a cheap clone; it is *not* fine for trusting origin/main — the
 * check forces a re-point (or an explicit GitHub-named second remote that
 * the caller reassigns as origin) rather than silently accepting it.
 *
 * @param {unknown} url
 * @returns {{ ok: true, form: "https"|"ssh"|"ssh-url" } | { ok: false, reason: string }}
 */
export function classifyOriginUrl(url) {
  if (typeof url !== "string" || url.trim() === "") {
    return { ok: false, reason: "ORIGIN_URL_EMPTY" };
  }
  const trimmed = url.trim();

  // Local filesystem path (absolute, relative, or file://) — the poisoned-clone case.
  if (
    trimmed.startsWith("/") ||
    trimmed.startsWith("./") ||
    trimmed.startsWith("../") ||
    trimmed.startsWith("file://") ||
    /^[A-Za-z]:[\\/]/.test(trimmed) // Windows drive path
  ) {
    return { ok: false, reason: "ORIGIN_IS_LOCAL_PATH" };
  }

  // https://github.com/OWNER/REPO[.git]
  const httpsMatch = trimmed.match(
    /^https?:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/i,
  );
  if (httpsMatch) {
    const ownerRepo = `${httpsMatch[1]}/${httpsMatch[2]}`;
    if (ownerRepo.toLowerCase() !== CANONICAL_OWNER_REPO.toLowerCase()) {
      return { ok: false, reason: "ORIGIN_WRONG_GITHUB_REPO" };
    }
    return { ok: true, form: "https" };
  }

  // git@github.com:OWNER/REPO[.git]
  const scpMatch = trimmed.match(
    /^git@github\.com:([^/]+)\/([^/]+?)(?:\.git)?\/?$/i,
  );
  if (scpMatch) {
    const ownerRepo = `${scpMatch[1]}/${scpMatch[2]}`;
    if (ownerRepo.toLowerCase() !== CANONICAL_OWNER_REPO.toLowerCase()) {
      return { ok: false, reason: "ORIGIN_WRONG_GITHUB_REPO" };
    }
    return { ok: true, form: "ssh" };
  }

  // ssh://git@github.com/OWNER/REPO[.git]
  const sshUrlMatch = trimmed.match(
    /^ssh:\/\/git@github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/i,
  );
  if (sshUrlMatch) {
    const ownerRepo = `${sshUrlMatch[1]}/${sshUrlMatch[2]}`;
    if (ownerRepo.toLowerCase() !== CANONICAL_OWNER_REPO.toLowerCase()) {
      return { ok: false, reason: "ORIGIN_WRONG_GITHUB_REPO" };
    }
    return { ok: true, form: "ssh-url" };
  }

  return { ok: false, reason: "ORIGIN_NOT_GITHUB_CANON" };
}

/**
 * Assert an origin URL is the canonical GitHub remote.
 *
 * @param {unknown} url
 * @returns {{ status: "ok", url: string, form: string } | { status: "invalid", url: unknown, reason: string, repair: string }}
 */
export function assertOriginUrl(url) {
  const classified = classifyOriginUrl(url);
  if (!classified.ok) {
    return {
      status: "invalid",
      url,
      reason: classified.reason,
      repair: REPAIR_COMMAND,
    };
  }
  return { status: "ok", url: /** @type {string} */ (url), form: classified.form };
}

/**
 * Read `git remote get-url origin` from a repo and assert it.
 *
 * @param {{ cwd?: string, getUrl?: () => string }} [opts]
 *   `getUrl` is injectable for unit tests; default shells out to git.
 * @returns {ReturnType<typeof assertOriginUrl>}
 */
export function checkOriginRemote({ cwd, getUrl } = {}) {
  let url;
  try {
    url =
      typeof getUrl === "function"
        ? getUrl()
        : execFileSync("git", ["remote", "get-url", "origin"], {
            encoding: "utf8",
            stdio: ["pipe", "pipe", "pipe"],
            cwd: cwd ?? process.cwd(),
          }).trim();
  } catch (error) {
    const message =
      error && typeof error === "object" && "message" in error
        ? /** @type {{ message: string }} */ (error).message
        : String(error);
    const err = new Error(
      `could not read origin remote url (is this a git repo with an origin?): ${message}`,
    );
    /** @type {Error & { code?: string }} */ (err).code = "ORIGIN_UNREADABLE";
    throw err;
  }
  return assertOriginUrl(url);
}

/**
 * Format a human failure message with the offending url and the repair
 * one-liner. Used by the CLI and by callers that want a ready-to-print line.
 *
 * @param {{ url: unknown, reason?: string, repair?: string }} result
 */
export function formatFailureMessage(result) {
  const reason = result.reason ?? "ORIGIN_INVALID";
  const repair = result.repair ?? REPAIR_COMMAND;
  return [
    `assert-origin-url: origin does not point at the canonical GitHub remote (${reason}).`,
    `  origin = ${String(result.url)}`,
    `  expected (https or ssh) = ${CANONICAL_OWNER_REPO} on github.com`,
    `  repair: ${repair}`,
  ].join("\n");
}

function main() {
  let result;
  try {
    result = checkOriginRemote();
  } catch (error) {
    const code =
      error && typeof error === "object" && "code" in error
        ? /** @type {{ code?: string }} */ (error).code
        : undefined;
    process.stderr.write(
      `assert-origin-url: ${/** @type {Error} */ (error).message}\n  repair: ${REPAIR_COMMAND}\n`,
    );
    process.exitCode = code === "ORIGIN_UNREADABLE" ? 2 : 2;
    return;
  }

  if (result.status === "ok") {
    process.stdout.write(
      `assert-origin-url: ok (origin → ${CANONICAL_OWNER_REPO}, form=${result.form})\n`,
    );
    process.exitCode = 0;
    return;
  }

  process.stderr.write(`${formatFailureMessage(result)}\n`);
  process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
