/**
 * HTTP + authorization surface fuzzer: REGRESSION CORPUS REPLAY.
 *
 * Seed-independent: each saved counterexample is executed DIRECTLY (not via
 * fast-check sampling), so a shrunk regression stays pinned regardless of
 * generator/seed drift. The guard asserts the corpus is non-empty AND that every
 * entry is actually executed.
 *
 * TEST-ONLY.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  driveConfirmTotpSchema,
  driveCsrfGate,
  driveCsrfUnlessActionKey,
  driveLoginSchema,
  drivePasswordGate,
  driveTotpGate,
  driveVerifyApiKey,
  isIpPairLocked,
  registerIpFailure,
  _resetIpLockoutForTests,
} from "./http-auth-fuzz-alphabet.js";

interface VerifyExpected {
  nextCalled: boolean;
  status: number | null;
  code?: string;
  apiKeyKind?: string;
  selects?: number;
  updates?: number;
}
interface LockoutActionEntry {
  ip: string | null;
  username: string;
  op: string;
  advanceMs: number;
}
interface CorpusEntry {
  id: string;
  kind: string;
  header?: string;
  expected?: VerifyExpected;
  provided?: string | null;
  authMode?: string | null;
  mustEnrol?: boolean;
  mustChange?: boolean;
  status?: number;
  code?: string;
  nextCalled?: boolean;
  actions?: LockoutActionEntry[];
  probe?: { ip: string | null; username: string; atMs: number; locked: boolean };
  schema?: string;
  value?: unknown;
  valid?: boolean;
}

const corpusPath = fileURLToPath(
  new URL("./__fuzz-corpus__/http-auth/regressions.json", import.meta.url),
);
const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as { entries: CorpusEntry[] };
const BASE_MS = 1_700_000_000_000;

const bodyCode = (body: unknown): string | undefined =>
  (body as { error?: { code?: string } })?.error?.code;

afterEach(() => {
  vi.useRealTimers();
  _resetIpLockoutForTests();
});

describe("HTTP/auth regression corpus replays deterministically", () => {
  it("corpus is non-empty", () => {
    expect(corpus.entries.length).toBeGreaterThan(0);
  });

  let executed = 0;
  it.each(corpus.entries)("$id replays to its recorded outcome", async (entry) => {
    switch (entry.kind) {
      case "verify-decision": {
        const res = await driveVerifyApiKey(entry.header);
        const exp = entry.expected!;
        expect(res.nextCalled).toBe(exp.nextCalled);
        expect(res.status ?? null).toBe(exp.status);
        if (exp.code !== undefined) expect(bodyCode(res.body)).toBe(exp.code);
        if (exp.apiKeyKind !== undefined) expect(res.apiKeyKind).toBe(exp.apiKeyKind);
        if (exp.selects !== undefined) expect(res.spy.selects).toBe(exp.selects);
        if (exp.updates !== undefined) expect(res.spy.updates).toBe(exp.updates);
        break;
      }
      case "csrf-gate": {
        const res = await driveCsrfGate(entry.provided ?? undefined, entry.expected as unknown as string);
        expect(res.nextCalled).toBe(entry.nextCalled);
        if (entry.status !== undefined) expect(res.json?.status).toBe(entry.status);
        break;
      }
      case "csrf-unless-action-key": {
        const res = await driveCsrfUnlessActionKey(
          entry.authMode ?? undefined,
          entry.provided ?? undefined,
          entry.expected as unknown as string,
        );
        expect(res.nextCalled).toBe(entry.nextCalled);
        if (entry.status !== undefined) expect(res.json?.status).toBe(entry.status);
        break;
      }
      case "totp-gate": {
        const res = await driveTotpGate(entry.mustEnrol!);
        if (entry.status !== undefined) expect(res.json?.status).toBe(entry.status);
        if (entry.nextCalled !== undefined) expect(res.nextCalled).toBe(entry.nextCalled);
        break;
      }
      case "password-gate": {
        const res = await drivePasswordGate(entry.mustChange!);
        if (entry.status !== undefined) expect(res.json?.status).toBe(entry.status);
        if (entry.code !== undefined) expect(bodyCode(res.json?.body)).toBe(entry.code);
        if (entry.nextCalled !== undefined) expect(res.nextCalled).toBe(entry.nextCalled);
        break;
      }
      case "lockout-sequence": {
        vi.useFakeTimers();
        _resetIpLockoutForTests();
        let now = BASE_MS;
        for (const a of entry.actions!) {
          now += a.advanceMs;
          vi.setSystemTime(now);
          if (a.op === "fail") registerIpFailure(a.ip, a.username);
        }
        vi.setSystemTime(BASE_MS + entry.probe!.atMs);
        expect(isIpPairLocked(entry.probe!.ip, entry.probe!.username)).toBe(entry.probe!.locked);
        break;
      }
      case "schema-shape": {
        const valid =
          entry.schema === "login" ? driveLoginSchema(entry.value) : driveConfirmTotpSchema(entry.value);
        expect(valid).toBe(entry.valid);
        break;
      }
      default:
        throw new Error(`unknown corpus entry kind: ${entry.kind}`);
    }
    executed += 1;
  });

  it("every corpus entry was executed", () => {
    expect(executed).toBe(corpus.entries.length);
  });
});
