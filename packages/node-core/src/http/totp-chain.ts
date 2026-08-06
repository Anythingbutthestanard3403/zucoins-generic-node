// TOTP mutation chain: fresh single-use TOTP verified BEFORE the mutation
// executes. The (node_id, timestep) pair is globally single-use — one mutation
// wins, others fail. The code is burned on any downstream failure and never
// restored (steps 6–8).
//
// Matching (HOTP + window walk) lives in totp/ — this module owns consume via
// the shared TotpBurnStore (confirm + reject/bless + admin money + SEND approve).

import { matchTotp, type TotpConfig, type TotpMatchOutcome } from "../totp/match.js";
import {
  InMemoryTotpBurnStore,
  TotpConsumptionLog,
  type TotpBurnStore,
} from "../totp/burn-store.js";

export type { TotpConfig, TotpMatchOutcome, TotpBurnStore };
export { TotpConsumptionLog, InMemoryTotpBurnStore };

export interface TotpVerifyRequest {
  readonly nodeId: string;
  readonly code: string;
  readonly nowMs?: number;
}

export type TotpVerifyOutcome =
  | { readonly ok: true; readonly timestep: number }
  | { readonly ok: false; readonly reason: "invalid_code" | "replay" };

/**
 * Match + durable/process claim. Shared registry so confirm-burned steps reject
 * on SEND approve (and vice versa). Store errors fail closed as invalid_code.
 */
export async function verifyTotp(
  config: TotpConfig,
  request: TotpVerifyRequest,
  log: TotpBurnStore,
): Promise<TotpVerifyOutcome> {
  const match = matchTotp(config, { code: request.code, nowMs: request.nowMs });
  if (!match.ok) return match;
  try {
    if (!(await log.claim(request.nodeId, match.timestep))) {
      return { ok: false, reason: "replay" };
    }
  } catch {
    return { ok: false, reason: "invalid_code" };
  }
  return { ok: true, timestep: match.timestep };
}

// Composed mutation guard: verifies TOTP then executes the mutation. If the
// mutation throws, the TOTP is still burned (step 8).
export async function guardedMutation<T>(
  config: TotpConfig,
  request: TotpVerifyRequest,
  log: TotpBurnStore,
  mutation: () => Promise<T>,
): Promise<{ ok: true; result: T; timestep: number } | { ok: false; reason: "invalid_code" | "replay" }> {
  const totpResult = await verifyTotp(config, request, log);
  if (!totpResult.ok) return totpResult;

  const result = await mutation();
  return { ok: true, result, timestep: totpResult.timestep };
}

// Re-export the canonical non-consuming matcher (durable claim is the arbiter).
export { matchTotp };
