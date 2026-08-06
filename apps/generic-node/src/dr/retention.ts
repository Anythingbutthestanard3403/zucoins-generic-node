// Backup artifact retention for the generic-node DR directory.

import { readdir, rm, stat } from "node:fs/promises";
import { join } from "node:path";

import { BACKUP_ENVELOPE_EXTENSION, BACKUP_RETENTION_DEFAULT_DAYS } from "./policy.js";

export interface RetentionInput {
  readonly directory: string;
  readonly retentionDays: number;
  readonly nowMs?: number;
}

export interface RetentionReport {
  readonly kept: readonly string[];
  readonly pruned: readonly string[];
  readonly skipped: readonly string[];
  readonly retentionDays: number;
  readonly cutoffMs: number;
}

export async function pruneRetainedBackups(input: RetentionInput): Promise<RetentionReport> {
  const retentionDays =
    Number.isFinite(input.retentionDays) && input.retentionDays > 0
      ? Math.floor(input.retentionDays)
      : BACKUP_RETENTION_DEFAULT_DAYS;
  const nowMs = input.nowMs ?? Date.now();
  const cutoffMs = nowMs - retentionDays * 24 * 60 * 60 * 1000;

  const kept: string[] = [];
  const pruned: string[] = [];
  const skipped: string[] = [];

  let entries: string[];
  try {
    entries = await readdir(input.directory);
  } catch {
    return { kept, pruned, skipped, retentionDays, cutoffMs };
  }

  for (const name of entries) {
    if (!name.endsWith(BACKUP_ENVELOPE_EXTENSION) || name.endsWith(".partial")) {
      skipped.push(name);
      continue;
    }
    const full = join(input.directory, name);
    let mtimeMs: number;
    try {
      const s = await stat(full);
      if (!s.isFile()) {
        skipped.push(name);
        continue;
      }
      mtimeMs = s.mtimeMs;
    } catch {
      skipped.push(name);
      continue;
    }
    if (mtimeMs < cutoffMs) {
      try {
        await rm(full, { force: true });
        pruned.push(name);
      } catch {
        skipped.push(name);
      }
    } else {
      kept.push(name);
    }
  }

  return { kept, pruned, skipped, retentionDays, cutoffMs };
}
