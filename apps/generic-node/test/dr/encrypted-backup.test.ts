import { execFileSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";


import { runDrill } from "../../src/dr/drill.js";
import {
  HEADER_LENGTH,
  OFF_SHA256,
  awaitCleanExit,
  buildPgDumpArgs,
  buildRestorePsqlArgs,
  decryptBuffer,
  encryptBuffer,
  restoreEncryptedBackup,
} from "../../src/dr/encrypted-backup.js";
import { rotateBackupKey } from "../../src/dr/key-rotation.js";

const PG_AVAILABLE = (() => {
  try {
    execFileSync("pg_isready", ["-t", "1"], { stdio: "ignore", timeout: 2000 });
    return true;
  } catch {
    return false;
  }
})();

// Build a libpq URL for the maintenance database. A Unix-socket PGHOST is a
// directory path that cannot carry a :port, so it is percent-encoded as the
// host with no port; a TCP host keeps the usual host:port form.
function templateUrl(): string {
  if (process.env.DR_TEST_TEMPLATE_URL) return process.env.DR_TEST_TEMPLATE_URL;
  const user = process.env.PGUSER ?? "postgres";
  const host = process.env.PGHOST ?? "localhost";
  if (host.startsWith("/")) {
    return `postgresql://${user}@${encodeURIComponent(host)}/postgres`;
  }
  return `postgresql://${user}@${host}:${process.env.PGPORT ?? "5432"}/postgres`;
}
const TEMPLATE_URL = templateUrl();

const MASTER_KEY = "test-backup-master-key-" + randomBytes(8).toString("hex");
const SAMPLE_SQL = Buffer.from(
  "CREATE TABLE wallets (id serial PRIMARY KEY, pubkey text NOT NULL);\n" +
    "INSERT INTO wallets (pubkey) VALUES ('wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=');\n" +
    "INSERT INTO wallets (pubkey) VALUES ('dGVzdC1rZXktMg==');\n",
  "utf8",
);

let workDir: string;

beforeAll(async () => {
  workDir = await mkdtemp(join(tmpdir(), "dr-test-"));
});

afterAll(async () => {
  await rm(workDir, { recursive: true, force: true });
});

describe("generic-node encrypted backup envelope", () => {
  it("produces encrypted output (no plaintext in envelope)", async () => {
    const envelope = await encryptBuffer(SAMPLE_SQL, MASTER_KEY);

    expect(envelope.subarray(0, 4).toString()).toBe("ZBKP");
    expect(envelope[4]).toBe(1);
    expect(envelope.length).toBeGreaterThan(HEADER_LENGTH);

    const asText = envelope.toString("latin1");
    expect(asText).not.toContain("CREATE TABLE");
    expect(asText).not.toContain("INSERT INTO");
    expect(asText).not.toContain("wallets");
  }, 120_000);

  it("round-trips: decrypt recovers exact data", async () => {
    const envelope = await encryptBuffer(SAMPLE_SQL, MASTER_KEY);
    const { plaintext, sha256 } = await decryptBuffer(envelope, MASTER_KEY);
    try {
      expect(plaintext.equals(SAMPLE_SQL)).toBe(true);
      expect(sha256).toHaveLength(64);
    } finally {
      plaintext.fill(0);
    }
  }, 120_000);

  it("rejects a wrong master key", async () => {
    const envelope = await encryptBuffer(SAMPLE_SQL, MASTER_KEY);
    await expect(decryptBuffer(envelope, "wrong-key")).rejects.toThrow();
  }, 120_000);

  it("detects corrupted ciphertext (GCM auth failure)", async () => {
    const envelope = await encryptBuffer(SAMPLE_SQL, MASTER_KEY);
    const corrupted = Buffer.from(envelope);
    corrupted[HEADER_LENGTH + 5] ^= 0xff;
    await expect(decryptBuffer(corrupted, MASTER_KEY)).rejects.toThrow();
  }, 120_000);

  it("detects a corrupted checksum", async () => {
    const envelope = await encryptBuffer(SAMPLE_SQL, MASTER_KEY);
    // The sha256 field sits in the header (outside the GCM-authenticated region),
    // so flipping it survives GCM and trips the completeness checksum instead.
    const corrupted = Buffer.from(envelope);
    corrupted[OFF_SHA256] ^= 0xff;
    await expect(decryptBuffer(corrupted, MASTER_KEY)).rejects.toThrow(/checksum mismatch/);
  }, 120_000);

  it("rejects truncated and bad-magic envelopes", async () => {
    const envelope = await encryptBuffer(SAMPLE_SQL, MASTER_KEY);
    await expect(decryptBuffer(envelope.subarray(0, HEADER_LENGTH - 1), MASTER_KEY)).rejects.toThrow(
      /too small/,
    );
    const badMagic = Buffer.from(envelope);
    badMagic[0] = 0x00;
    await expect(decryptBuffer(badMagic, MASTER_KEY)).rejects.toThrow(/magic/);
  }, 120_000);

  it("draws a fresh DEK/IV per backup (no ciphertext reuse)", async () => {
    const env1 = await encryptBuffer(SAMPLE_SQL, MASTER_KEY);
    const env2 = await encryptBuffer(SAMPLE_SQL, MASTER_KEY);
    expect(env1.equals(env2)).toBe(false);
    const d1 = await decryptBuffer(env1, MASTER_KEY);
    const d2 = await decryptBuffer(env2, MASTER_KEY);
    expect(d1.plaintext.equals(d2.plaintext)).toBe(true);
  }, 120_000);
});

describe("key rotation", () => {
  it("preserves data while changing the master key", async () => {
    const newKey = "rotated-master-key-" + randomBytes(8).toString("hex");
    const inputPath = join(workDir, "rotate-input.zbkp");
    const outputPath = join(workDir, "rotate-output.zbkp");

    const envelope = await encryptBuffer(SAMPLE_SQL, MASTER_KEY);
    await writeFile(inputPath, envelope);
    const result = await rotateBackupKey(inputPath, outputPath, MASTER_KEY, newKey);

    const rotated = await readFile(outputPath);
    expect(rotated.subarray(0, 4).toString()).toBe("ZBKP");
    expect(result.bytesWritten).toBe(envelope.length);

    // Old key no longer decrypts the rotated envelope.
    await expect(decryptBuffer(rotated, MASTER_KEY)).rejects.toThrow();
    // New key recovers the identical plaintext.
    const { plaintext } = await decryptBuffer(rotated, newKey);
    expect(plaintext.equals(SAMPLE_SQL)).toBe(true);
  }, 120_000);

  it("rejects rotation with the wrong old key", async () => {
    const inputPath = join(workDir, "rotate-bad-input.zbkp");
    const outputPath = join(workDir, "rotate-bad-output.zbkp");
    await writeFile(inputPath, await encryptBuffer(SAMPLE_SQL, MASTER_KEY));
    await expect(
      rotateBackupKey(inputPath, outputPath, "wrong-old-key", "new-key"),
    ).rejects.toThrow();
  }, 120_000);

  it("survives repeated rotation", async () => {
    const key2 = "second-rotation-" + randomBytes(8).toString("hex");
    const key3 = "third-rotation-" + randomBytes(8).toString("hex");
    const p1 = join(workDir, "dbl-1.zbkp");
    const p2 = join(workDir, "dbl-2.zbkp");
    const p3 = join(workDir, "dbl-3.zbkp");

    await writeFile(p1, await encryptBuffer(SAMPLE_SQL, MASTER_KEY));
    await rotateBackupKey(p1, p2, MASTER_KEY, key2);
    await rotateBackupKey(p2, p3, key2, key3);

    const { plaintext } = await decryptBuffer(await readFile(p3), key3);
    expect(plaintext.equals(SAMPLE_SQL)).toBe(true);
  }, 120_000);
});

describe("awaitCleanExit exit-code guard", () => {
  // Minimal fake ChildProcess: an EventEmitter with stdout/stderr EventEmitters
  // and a stdin stub. Tests the guard deterministically without spawning or a
  // global child_process mock (which would break the PG-gated drill/detection).
  function fakeChild(): ChildProcess {
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      stderr: EventEmitter;
      stdin: { on: () => void; end: () => void };
    };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.stdin = { on: () => {}, end: () => {} };
    return child as unknown as ChildProcess;
  }

  it("rejects a signal-killed child (close(null, 'SIGKILL'))", async () => {
    const child = fakeChild();
    const p = awaitCleanExit(child, "pg_dump");
    child.stderr?.emit("data", Buffer.from("out of memory"));
    child.emit("close", null, "SIGKILL");
    await expect(p).rejects.toThrow(/pg_dump did not exit cleanly.*SIGKILL/s);
  }, 120_000);

  it("rejects a nonzero exit (close(1, null))", async () => {
    const child = fakeChild();
    const p = awaitCleanExit(child, "psql");
    child.emit("close", 1, null);
    await expect(p).rejects.toThrow(/psql did not exit cleanly.*code=1/s);
  }, 120_000);

  it("resolves a clean exit (close(0, null))", async () => {
    const child = fakeChild();
    const p = awaitCleanExit(child, "pg_dump");
    child.emit("close", 0, null);
    await expect(p).resolves.toBeUndefined();
  }, 120_000);
});

describe("buildPgDumpArgs", () => {
  it("omits --snapshot unless a snapshot id is provided", () => {
    const args = buildPgDumpArgs("postgresql://u@h/db");
    expect(args).toEqual([
      "--format=plain",
      "--no-owner",
      "--no-acl",
      "--dbname",
      "postgresql://u@h/db",
    ]);
    expect(args.some((a) => a.startsWith("--snapshot"))).toBe(false);
  });

  it("binds --snapshot when exporting under a held backend snapshot", () => {
    const args = buildPgDumpArgs("postgresql://u@h/db", "0000000A-0000000B-1");
    expect(args).toContain("--snapshot=0000000A-0000000B-1");
    expect(args[args.indexOf("--dbname") + 1]).toBe("postgresql://u@h/db");
  });
});

describe("buildRestorePsqlArgs", () => {
  it("enforces -v ON_ERROR_STOP=1 so a failed restore cannot report success", () => {
    const url = "postgresql://u@h:5432/db";
    const args = buildRestorePsqlArgs(url);
    expect(args).toContain("-v");
    expect(args).toContain("ON_ERROR_STOP=1");
    // psql wants the value immediately after the -v flag.
    expect(args.indexOf("ON_ERROR_STOP=1")).toBe(args.indexOf("-v") + 1);
    expect(args).toContain("--single-transaction");
    expect(args[args.length - 1]).toBe(url);
  }, 120_000);
});

describe("restore aborts on a failing transaction", () => {
  it.runIf(PG_AVAILABLE)(
    "rejects when the backup SQL errors mid-transaction (feeds the real breaking input)",
    async () => {
      // A ZBKP whose plaintext SQL is guaranteed to error: insert into a table
      // that does not exist. With --single-transaction the failing statement
      // aborts and rolls back (no side effect on the maintenance DB). Without
      // -v ON_ERROR_STOP=1, psql would exit 0 and restoreEncryptedBackup would
      // FALSELY resolve over an empty/rolled-back database.
      const badSql = Buffer.from(
        "INSERT INTO __nonexistent_table__ (x) VALUES (1);\n",
        "utf8",
      );
      const backupPath = join(workDir, "failing-restore.zbkp");
      await writeFile(backupPath, await encryptBuffer(badSql, MASTER_KEY));
      await expect(
        restoreEncryptedBackup(backupPath, TEMPLATE_URL, MASTER_KEY),
      ).rejects.toThrow(/psql did not exit cleanly/);
    },
    60_000,
  );
});

describe("DR drill ceremony", () => {
  it.runIf(PG_AVAILABLE)(
    "full backup → destroy → restore → verify passes against a throwaway DB",
    async () => {
      const result = await runDrill(TEMPLATE_URL, MASTER_KEY);
      expect(result.steps).not.toContainEqual(expect.stringContaining("FAILED"));
      expect(result.passed).toBe(true);
      expect(result.rpoStatement).toMatch(/RPO/);
      expect(result.rpoMs).toBe(0);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
      expect(result.backupSha256).toHaveLength(64);
      expect(result.restoreSha256).toBe(result.backupSha256);
    },
    60_000,
  );
});
