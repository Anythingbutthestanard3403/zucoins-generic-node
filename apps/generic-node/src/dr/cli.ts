// Operator CLI for generic-node DR.

import { resolve } from "node:path";

import { exportEncryptedBackup, restoreEncryptedBackup } from "./encrypted-backup.js";
import { runDrill } from "./drill.js";
import {
  deriveContinuitySnapshot,
  loadContinuityMarkers,
} from "./markers.js";
import {
  BACKUP_RPO_TARGET_MS,
  BACKUP_RTO_TARGET_MS,
  DEFAULT_BACKUP_POLICY,
  isRpoBreached,
} from "./policy.js";
import { newestBackupArtifactMtimeMs } from "./schedule.js";
import { verifyProviderBackups } from "./provider-verify.js";
import { evaluateRestoreHoldRelease } from "./restore-hold.js";
import { releaseDualGatesWithTrustedMarkers } from "./auth-hold.js";

export interface CliEnv {
  readonly DATABASE_URL?: string;
  readonly BACKUP_MASTER_KEY?: string;
  readonly BACKUP_OUTPUT_DIR?: string;
  readonly BACKUP_CONTINUITY_MARKERS_PATH?: string;
  readonly BACKUP_DRILL_TEMPLATE_URL?: string;
  readonly NODE_ID?: string;
}

export interface CliIo {
  readonly log: (line: string) => void;
  readonly error: (line: string) => void;
}

const defaultIo: CliIo = {
  log: (l) => console.log(l),
  error: (l) => console.error(l),
};

function usage(): string {
  return `generic-node dr — encrypted backup / restore / drill / markers

Commands:
  backup  --out <file>          Export encrypted ZBKP of DATABASE_URL
  restore --in <file>           Restore ZBKP into DATABASE_URL (forces restore_hold + auth_hold)
  drill                         Throwaway destroy/restore drill (RPO/RTO evidence)
  verify  --path <file-or-dir>  Decrypt-verify provider artifacts (no apply)
  markers check --file <path>   Compare externally-held successful-backup markers to live DB
  markers release --file <path> Atomically append AUTH_HOLD_RELEASED and clear both holds
  status                        RPO posture against BACKUP_OUTPUT_DIR

Environment:
  DATABASE_URL, BACKUP_MASTER_KEY, BACKUP_OUTPUT_DIR,
  BACKUP_CONTINUITY_MARKERS_PATH, BACKUP_DRILL_TEMPLATE_URL, NODE_ID
`;
}

function flag(args: readonly string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx < 0) return undefined;
  return args[idx + 1];
}

function requireEnv(env: CliEnv, key: keyof CliEnv): string {
  const v = env[key];
  if (typeof v !== "string" || v.trim() === "") throw new Error(`${key} is required`);
  return v;
}

export async function runDrCli(
  argv: readonly string[],
  env: CliEnv = process.env,
  io: CliIo = defaultIo,
): Promise<number> {
  const args = argv.slice();
  const cmd = args[0];
  if (!cmd || cmd === "-h" || cmd === "--help" || cmd === "help") {
    io.log(usage());
    return 0;
  }

  try {
    switch (cmd) {
      case "backup": {
        const out = flag(args, "--out");
        if (!out) throw new Error("backup requires --out <path>");
        const result = await exportEncryptedBackup(
          requireEnv(env, "DATABASE_URL"),
          resolve(out),
          requireEnv(env, "BACKUP_MASTER_KEY"),
        );
        io.log(
          JSON.stringify({
            ok: true,
            command: "backup",
            outputPath: result.outputPath,
            bytesWritten: result.bytesWritten,
            plaintextSha256: result.sha256,
          }),
        );
        return 0;
      }
      case "restore": {
        const input = flag(args, "--in");
        if (!input) throw new Error("restore requires --in <path>");
        const nodeId = env.NODE_ID;
        const result = await restoreEncryptedBackup(
          resolve(input),
          requireEnv(env, "DATABASE_URL"),
          requireEnv(env, "BACKUP_MASTER_KEY"),
          {
            nodeId:
              nodeId !== undefined && nodeId.trim() !== "" ? nodeId.trim() : undefined,
          },
        );
        io.log(
          JSON.stringify({
            ok: true,
            command: "restore",
            bytesRestored: result.bytesRestored,
            plaintextSha256: result.sha256,
            restoreHold: result.restoreHold.applied,
            restoreHoldApplied: result.restoreHold.applied,
            restoreHoldNodeIds: result.restoreHold.nodeIds,
            authHoldApplied: result.authHold.applied,
            authHoldHeadsForced: result.authHold.headsForced,
            authHoldHeadKeys: result.authHold.headKeys,
            note:
              "Restore complete. Both post-restore gates were forced after apply: restore_hold=true and lifecycle auth_hold=true (AUTH_HOLD_SET). Clearing restore_hold alone grants nothing; admission requires both holds false after external-marker ceremonies.",
          }),
        );
        return 0;
      }
      case "drill": {
        const template = env.BACKUP_DRILL_TEMPLATE_URL ?? env.DATABASE_URL;
        if (!template) throw new Error("BACKUP_DRILL_TEMPLATE_URL or DATABASE_URL is required");
        const result = await runDrill(template, requireEnv(env, "BACKUP_MASTER_KEY"));
        io.log(
          JSON.stringify({
            command: "drill",
            passed: result.passed,
            backupSha256: result.backupSha256,
            restoreSha256: result.restoreSha256,
            durationMs: result.durationMs,
            rpoMs: result.rpoMs,
            rpoStatement: result.rpoStatement,
            steps: result.steps,
            rtoTargetMs: BACKUP_RTO_TARGET_MS,
            rpoTargetMs: BACKUP_RPO_TARGET_MS,
          }),
        );
        return result.passed ? 0 : 2;
      }
      case "verify": {
        const path = flag(args, "--path") ?? env.BACKUP_OUTPUT_DIR;
        if (!path) throw new Error("verify requires --path or BACKUP_OUTPUT_DIR");
        const report = await verifyProviderBackups(
          resolve(path),
          requireEnv(env, "BACKUP_MASTER_KEY"),
        );
        io.log(
          JSON.stringify({
            command: "verify",
            ok: report.ok,
            checked: report.checked,
            newestPath: report.newestPath,
            newestMtimeMs: report.newestMtimeMs,
          }),
        );
        return report.ok ? 0 : 2;
      }
      case "markers": {
        const sub = args[1];
        const file = flag(args, "--file") ?? env.BACKUP_CONTINUITY_MARKERS_PATH;
        if (!file) {
          io.log(JSON.stringify({ ok: false, command: `markers-${sub ?? "unknown"}`, reason: "missing_trusted_source" }));
          return 2;
        }
        const loaded = await loadContinuityMarkers(resolve(file));
        if (!loaded.ok) {
          io.log(
            JSON.stringify({
              ok: false,
              command: `markers-${sub ?? "unknown"}`,
              reason: loaded.reason === "markers_source_unreadable" ? "missing_trusted_source" : loaded.reason,
            }),
          );
          return 2;
        }
        const databaseUrl = requireEnv(env, "DATABASE_URL");
        const nodeId = requireEnv(env, "NODE_ID");
        if (sub === "check") {
          const local = await deriveContinuitySnapshot(databaseUrl, nodeId);
          const decision = evaluateRestoreHoldRelease({ trusted: loaded.markers, local });
          io.log(JSON.stringify({ ok: decision.release, command: "markers-check", decision }));
          return decision.release ? 0 : 2;
        }
        if (sub === "release") {
          const result = await releaseDualGatesWithTrustedMarkers(databaseUrl, {
            nodeId,
            trusted: loaded.markers,
          });
          io.log(
            JSON.stringify({
              ok: result.released,
              command: "markers-release",
              reason: result.released ? undefined : result.decision.reason,
              authHeadsReleased: result.released ? result.authHeadsReleased : undefined,
              decision: result.decision,
            }),
          );
          return result.released ? 0 : 2;
        }
        throw new Error("markers requires subcommand check|release");
      }
      case "status": {
        const dir = env.BACKUP_OUTPUT_DIR;
        if (!dir) throw new Error("status requires BACKUP_OUTPUT_DIR");
        const newest = await newestBackupArtifactMtimeMs(resolve(dir));
        const now = Date.now();
        const breached = isRpoBreached(newest, now, DEFAULT_BACKUP_POLICY);
        io.log(
          JSON.stringify({
            ok: !breached,
            command: "status",
            outputDir: resolve(dir),
            newestArtifactAtMs: newest,
            ageMs: newest === null ? null : now - newest,
            rpoTargetMs: DEFAULT_BACKUP_POLICY.rpoTargetMs,
            rpoBreached: breached,
          }),
        );
        return breached ? 2 : 0;
      }
      default:
        throw new Error(`unknown command: ${cmd}`);
    }
  } catch (err) {
    io.error(err instanceof Error ? err.message : String(err));
    io.error("");
    io.error(usage());
    return 1;
  }
}

const entry = process.argv[1] ?? "";
const isMain =
  entry.endsWith("/dr/cli.js") ||
  entry.endsWith("/dr/cli.ts") ||
  entry.endsWith("generic-node/src/dr/cli.ts");

if (isMain) {
  void runDrCli(process.argv.slice(2)).then((code) => {
    process.exit(code);
  });
}
