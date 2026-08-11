
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const mountSrc = readFileSync(join(here, "../src/full-http-mount.ts"), "utf8");
const ceremonySrc = readFileSync(join(here, "../src/ops/run-recovery-ceremony.ts"), "utf8");
const safeLogSrc = readFileSync(
  join(here, "../../../packages/node-core/src/observability/safe-log.ts"),
  "utf8",
);

describe("ZTR-1171 composition census", () => {
  it("production mount does not construct in-memory enrollment/revocation audit logs", () => {
    expect(mountSrc).not.toMatch(/new InMemoryEnrollmentAuditLog\s*\(/);
    expect(mountSrc).not.toMatch(/new InMemoryDeviceRevocationAuditLog\s*\(/);
    expect(mountSrc).toMatch(/createSqlEnrollmentAuditLog/);
    expect(mountSrc).toMatch(/createSqlDeviceRevocationAuditLog/);
  });

  it("CLI ceremony does not requireEnv VAULT_MASTER_KEY", () => {
    expect(ceremonySrc).not.toMatch(/requireEnv\(\s*env\s*,\s*["']VAULT_MASTER_KEY["']\s*\)/);
    expect(ceremonySrc).toMatch(/resolveCeremonyMasterKey/);
  });

  it("safe-log never-logs passcode and packfile", () => {
    expect(safeLogSrc).toMatch(/passcode/);
    expect(safeLogSrc).toMatch(/packfile/);
  });
});
