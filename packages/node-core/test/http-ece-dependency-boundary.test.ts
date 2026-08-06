import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";

import ece from "http_ece";
import { describe, expect, test } from "vitest";

import { assertHttpEceKeyLoggingDisabled } from "../src/push/http-ece-keylog.js";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const requireFromCore = createRequire(resolve(repositoryRoot, "packages/node-core/package.json"));
const installedHttpEceSource = requireFromCore.resolve("http_ece");

const forbiddenKeylogOutput = /^(?:authsecret|decrypt|decrypted|secret dh|key|prk|extract|expand) \[\d+\]:/m;

function packageManifests(root: string): string[] {
  const manifests: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (["dist", "node_modules"].includes(entry.name)) continue;
    const path = join(root, entry.name);
    if (entry.isDirectory()) manifests.push(...packageManifests(path));
    else if (entry.name === "package.json") manifests.push(path);
  }
  return manifests;
}

describe("patched http_ece dependency boundary", () => {
  test("guards consumers against an unexpectedly unpatched dependency", () => {
    const patchedBoundary = {
      verifyKeylogDisabled(challenge: object) {
        return challenge;
      },
    };
    expect(() => assertHttpEceKeyLoggingDisabled(ece)).not.toThrow();
    expect(() => assertHttpEceKeyLoggingDisabled(patchedBoundary)).not.toThrow();
    expect(() => assertHttpEceKeyLoggingDisabled({})).toThrow(
      "Web Push decrypt refused: dependency key logging is enabled",
    );
    expect(() => assertHttpEceKeyLoggingDisabled({ keylogDisabled: true } as never)).toThrow(
      "Web Push decrypt refused: dependency key logging is enabled",
    );
    expect(() => assertHttpEceKeyLoggingDisabled({
      verifyKeylogDisabled() {
        return true;
      },
    })).toThrow("Web Push decrypt refused: dependency key logging is enabled");
  });

  test("removes the keylog sink from the single installed repository copy", () => {
    const source = readFileSync(installedHttpEceSource, "utf8");
    const consumerResolutions = [
      "apps/generic-node/package.json",
      "packages/node-core/package.json",
    ].map((manifest) => createRequire(resolve(repositoryRoot, manifest)).resolve("http_ece"));

    expect(new Set(consumerResolutions)).toEqual(new Set([installedHttpEceSource]));
    expect(source).not.toContain("process.env.ECE_KEYLOG");
    expect(source).not.toContain("console.warn");
    expect(source).toContain("keylog === keylogIdentity");
  });

  test("locks every workspace consumer to the one patched dependency snapshot", () => {
    // prod + dev declarations both count: any manifest resolving http_ece must be
    // pinned to the single patched snapshot.
    const declaredHttpEce = (manifest: string): string | undefined => {
      const parsed = JSON.parse(readFileSync(manifest, "utf8")) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      return parsed.dependencies?.http_ece ?? parsed.devDependencies?.http_ece;
    };
    const consumers = ["apps", "packages"]
      .flatMap((directory) => packageManifests(resolve(repositoryRoot, directory)))
      .filter((manifest) => declaredHttpEce(manifest) !== undefined)
      .map((manifest) => relative(repositoryRoot, manifest))
      .sort();
    expect(consumers).toEqual([
      "apps/generic-node/package.json",
      "packages/node-core/package.json",
    ]);
    for (const manifest of consumers) {
      expect(declaredHttpEce(resolve(repositoryRoot, manifest))).toBe("1.2.1");
    }

    const lockfile = readFileSync(resolve(repositoryRoot, "pnpm-lock.yaml"), "utf8");
    const patchHash = lockfile.match(/patchedDependencies:\n {2}http_ece@1\.2\.1: ([a-f0-9]{64})/)?.[1];
    expect(patchHash).toBeDefined();
    const snapshots = lockfile
      .slice(lockfile.indexOf("\nsnapshots:\n"))
      .match(/^ {2}http_ece@.*$/gm);
    expect(snapshots).toEqual([
      `  http_ece@1.2.1(patch_hash=${patchHash}): {}`,
    ]);
  });

  // Child vitest cold-starts a full vite transform; 30s is not enough under a
  // loaded full-suite run, hence the explicit timeout.
  test("keeps generic-node decrypt functional without emitting key material", () => {
    const result = spawnSync(
      "pnpm",
      ["exec", "vitest", "run", "test/fixtures/push-ece-keylog-probe.test.ts"],
      {
        cwd: resolve(repositoryRoot, "apps/generic-node"),
        encoding: "utf8",
        env: { ...process.env, ECE_KEYLOG: "1" },
      },
    );
    const output = `${result.stdout}${result.stderr}`;

    // Exit status is deliberately not asserted: it reports the child vitest runner's own
    // health, not this test's subject. The exact-count stdout assertion below is what proves
    // the decrypt path actually ran, and it fails on a crashed or empty run anyway.
    expect(result.error).toBeUndefined();
    expect(output).not.toMatch(forbiddenKeylogOutput);
    expect(output).toContain("1 passed");
  }, 180_000);
});
