// Every secret-class path the recovery ceremony tells an operator to
// produce must be git-ignored. A backup archive carries each wallet's sealed vault
// envelope, so committing one is committing full wallet control (never commit a
// wallet backup file).
//
// This fails if someone un-ignores a path, renames the ARCHIVE_OUT convention
// without updating .gitignore, or adds a negation that re-exposes one.

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));

// Paths the ceremony produces, plus the pre-existing wallet-backup patterns the
// same rule covers.
const MUST_BE_IGNORED = [
  ".recovery-ceremony/",
  ".recovery-ceremony/2026-07-30-ceremony.archive.json",
  ".recovery-ceremony/scratch/restored.dump",
  "zp-node-backup-v1.archive.json",
  "apps/generic-node/evidence.archive.json",
  "my-secret-zucoins-wallet-backup.json",
  "node-wallet-backup.json",
] as const;

function isIgnored(path: string): boolean {
  try {
    // `git check-ignore -q` exits 0 when the path is ignored, 1 when it is not.
    execFileSync("git", ["check-ignore", "-q", "--", path], {
      cwd: REPO_ROOT,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

describe("recovery-ceremony artifacts stay untrackable", () => {
  it.each(MUST_BE_IGNORED)("git ignores %s", (path) => {
    expect(isIgnored(path), `${path} is trackable — a committed archive is full wallet control`).toBe(
      true,
    );
  });

  it("does not ignore the ceremony source itself", () => {
    // Guards against a pattern so broad it swallows the code it is protecting.
    expect(isIgnored("apps/generic-node/src/ops/run-recovery-ceremony.ts")).toBe(false);
  });
});
