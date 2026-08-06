import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock node:child_process so the probe's ENOENT / version-mismatch branches
// are exercised deterministically, independent of whatever pg_dump/psql
// happen to be on the host running this suite.
vi.mock("node:child_process", () => ({
  execFile: vi.fn(),
}));

import { execFile } from "node:child_process";
import {
  EXPECTED_PG_CLIENT_MAJOR_VERSION,
  probePgClientBinaries,
} from "../../src/dr/client-probe.js";

type ExecFileCallback = (
  error: (Error & { code?: string }) | null,
  result?: { stdout: string; stderr: string },
) => void;
type ExecFileHandler = (cmd: string, args: readonly string[], callback: ExecFileCallback) => void;

const execFileMock = execFile as unknown as ReturnType<typeof vi.fn>;

function setExecFileImpl(handler: ExecFileHandler): void {
  execFileMock.mockImplementation(handler as (...args: unknown[]) => void);
}

describe("probePgClientBinaries", () => {
  beforeEach(() => {
    execFileMock.mockReset();
  });

  it("is ok when both pg_dump and psql report the pinned major version", async () => {
    setExecFileImpl((cmd, _args, callback) => {
      callback(null, { stdout: `${cmd} (PostgreSQL) ${EXPECTED_PG_CLIENT_MAJOR_VERSION}.4\n`, stderr: "" });
    });

    const result = await probePgClientBinaries();

    expect(result.ok).toBe(true);
    expect(result.pgDumpVersion).toContain(`${EXPECTED_PG_CLIENT_MAJOR_VERSION}.4`);
    expect(result.psqlVersion).toContain(`${EXPECTED_PG_CLIENT_MAJOR_VERSION}.4`);
  });

  it("fails closed with ENOENT when the postgresql-client package is missing", async () => {
    setExecFileImpl((_cmd, _args, callback) => {
      callback(Object.assign(new Error("spawn pg_dump ENOENT"), { code: "ENOENT" }));
    });

    const result = await probePgClientBinaries();

    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/not found on PATH.*postgresql-client package/);
  });

  it("fails closed when the installed client major version drifts from the pin", async () => {
    setExecFileImpl((cmd, _args, callback) => {
      callback(null, { stdout: `${cmd} (PostgreSQL) 17.10 (Homebrew)\n`, stderr: "" });
    });

    const result = await probePgClientBinaries();

    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/major version 17 does not match the pinned server major 16/);
  });

  it("fails closed when --version output is unparseable", async () => {
    setExecFileImpl((_cmd, _args, callback) => {
      callback(null, { stdout: "not a version string\n", stderr: "" });
    });

    const result = await probePgClientBinaries();

    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/unparseable/);
  });

  it("reports the failing binary first when pg_dump and psql disagree", async () => {
    setExecFileImpl((cmd, _args, callback) => {
      if (cmd === "pg_dump") {
        callback(Object.assign(new Error("ENOENT"), { code: "ENOENT" }));
        return;
      }
      callback(null, { stdout: `psql (PostgreSQL) ${EXPECTED_PG_CLIENT_MAJOR_VERSION}.4\n`, stderr: "" });
    });

    const result = await probePgClientBinaries();

    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/^pg_dump not found on PATH/);
  });
});
