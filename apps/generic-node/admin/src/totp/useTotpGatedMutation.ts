// Step-up TOTP for operator_session_totp money mutations.
// Never blind-retries a rejected code.

import {
  useMutation,
  type UseMutationOptions,
  type UseMutationResult,
} from "@tanstack/react-query";
import { useCallback, useRef } from "react";
import { ApiError, recheckSessionOn401 } from "../lib/api.js";
import { useAuth } from "../store/auth.js";
import {
  TotpCancelledError,
  useTotpPrompt,
} from "./TotpPromptProvider.js";

/**
 * Operator-facing copy for a re-promptable factor failure.
 * Approve collapses wrong TOTP / device / challenge into opaque
 * `approval_rejected` (401) — same "try again" surface as invalid_credentials.
 * A second failure inside one ceremony may be a burned timestep; nudge wait.
 */
function totpErrorMessage(code: string, consecutiveFailures: number): string {
  if (
    code === "totp_invalid" ||
    code === "invalid_credentials" ||
    code === "approval_rejected"
  ) {
    if (consecutiveFailures >= 2) {
      // Client-only hint: server still returns the opaque envelope (ZTR-1194).
      // Retyping the same 30s code after a burn surfaces as another rejection.
      return "Code invalid — wait for the next authenticator code, then try again.";
    }
    return "Code invalid — try again.";
  }
  return "Code required.";
}

/**
 * Re-promptable step-up challenge. Status stays 401 (never-403 money path).
 * Accept `approval_rejected` explicitly so the approve route's opaque factor
 * envelope re-prompts in place rather than aborting the ceremony (ZTR-1194).
 */
function isTotpChallenge(err: unknown): err is ApiError {
  return (
    err instanceof ApiError &&
    err.status === 401 &&
    (err.code === "totp_required" ||
      err.code === "totp_invalid" ||
      err.code === "invalid_credentials" ||
      err.code === "approval_rejected")
  );
}

/**
 * Retry ceiling. The 401 challenge is ambiguous by design, so a repeat of it may
 * be a mistyped code *or* a session that died mid-ceremony — the loop has to
 * terminate either way (`lib/api.ts` awaits a session recheck on 401 and forces
 * re-auth on the real expiry; this sink also fail-closes when the store is
 * already cleared). Three retries after the first rejection: three wrong codes
 * then a correct one still succeeds.
 */
const MAX_TOTP_RETRIES = 3;

function assertCurrent(signal: AbortSignal, isCurrent: () => boolean) {
  if (signal.aborted || !isCurrent()) throw new TotpCancelledError();
}

async function withTotpRetry<T>(
  requestCode: ReturnType<typeof useTotpPrompt>["requestCode"],
  title: string,
  detail: string | undefined,
  signal: AbortSignal,
  isCurrent: () => boolean,
  attempt: (totp: string) => Promise<T>,
): Promise<T> {
  let errorMessage: string | undefined;
  let consecutiveFailures = 0;
  for (let retries = 0; ; retries += 1) {
    assertCurrent(signal, isCurrent);
    const totp = await requestCode({ title, detail, errorMessage, signal });
    // Promise continuation is a separate mutation sink: re-check even when a
    // provider submission resolved just before the caller invalidated it.
    assertCurrent(signal, isCurrent);
    try {
      return await attempt(totp);
    } catch (err) {
      if (!isTotpChallenge(err)) throw err;
      // Dead / cleared session: never open another prompt (belt after api()
      // awaits recheck — covers non-api callers and jsdom href no-op).
      if (useAuth.getState().user === null) throw err;
      const verdict = await recheckSessionOn401();
      if (verdict === "dead" || verdict === "skipped") throw err;
      consecutiveFailures += 1;
      if (retries < MAX_TOTP_RETRIES) {
        errorMessage = totpErrorMessage(err.code, consecutiveFailures);
        continue;
      }
      throw err;
    }
  }
}

type TotpGatedOptions<TResponse, TVariables> = Omit<
  UseMutationOptions<TResponse, unknown, TVariables>,
  "mutationFn"
> & {
  title?: string;
  detail?: string | ((variables: TVariables) => string | undefined);
  /** Re-evaluated immediately before each POST attempt. */
  isValid?: (variables: TVariables) => boolean;
};

export type TotpGatedMutationResult<TResponse, TVariables> =
  UseMutationResult<TResponse, unknown, TVariables> & {
    /** Dismisses the owned provider prompt and invalidates resolved continuations. */
    cancel: () => void;
  };

export function useTotpGatedMutation<TResponse, TVariables = void>(
  mutationFn: (variables: TVariables, totp: string) => Promise<TResponse>,
  options?: TotpGatedOptions<TResponse, TVariables>,
): TotpGatedMutationResult<TResponse, TVariables> {
  const { requestCode } = useTotpPrompt();
  const generationRef = useRef(0);
  const controllerRef = useRef<AbortController | null>(null);
  const { title = "Enter verification code", detail, isValid, ...rest } = options ?? {};

  const cancel = useCallback(() => {
    generationRef.current += 1;
    controllerRef.current?.abort();
    controllerRef.current = null;
  }, []);

  const mutation = useMutation<TResponse, unknown, TVariables>({
    ...rest,
    mutationFn: async (variables) => {
      controllerRef.current?.abort();
      const controller = new AbortController();
      controllerRef.current = controller;
      const generation = ++generationRef.current;
      const isCurrent = () =>
        generationRef.current === generation &&
        (isValid?.(variables) ?? true);
      const d = typeof detail === "function" ? detail(variables) : detail;
      try {
        return await withTotpRetry(
          requestCode,
          title,
          d,
          controller.signal,
          isCurrent,
          (totp) => mutationFn(variables, totp),
        );
      } finally {
        if (generationRef.current === generation) controllerRef.current = null;
      }
    },
  });

  return { ...mutation, cancel };
}
