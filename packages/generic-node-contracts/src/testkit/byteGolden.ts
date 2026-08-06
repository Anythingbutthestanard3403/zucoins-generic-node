import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Raw byte-golden reader (architecture layout: testkit/byteGolden.ts).
 * Byte authority for the frozen artifacts is the file bytes on disk under `goldens/`, never a
 * TS/JSON literal (A8: no test writes a golden). Tests read through here so the exact bytes —
 * including the deliberate absence of a trailing newline — are what gets asserted.
 */
const goldensRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "goldens");

export const readGoldenBytes = (relPath: string): Buffer => readFileSync(join(goldensRoot, relPath));

export const readGoldenText = (relPath: string): string => readGoldenBytes(relPath).toString("utf8");

export const listGolden = (relDir: string): string[] => readdirSync(join(goldensRoot, relDir)).sort();

export const sha256OfBytes = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");

export const sha256OfGolden = (relPath: string): string => sha256OfBytes(readGoldenBytes(relPath));
