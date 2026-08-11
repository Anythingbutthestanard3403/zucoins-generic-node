import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { TotpPrompt } from "./TotpPrompt.js";

/** Thrown when the operator dismisses or invalidates the prompt. */
export class TotpCancelledError extends Error {
  constructor() {
    super("TOTP entry cancelled");
    this.name = "TotpCancelledError";
  }
}

interface PendingRequest {
  title: string;
  detail?: string;
  errorMessage?: string;
  resolve: (code: string) => void;
  reject: (err: Error) => void;
  cleanup?: () => void;
}

interface TotpRequestOptions {
  errorMessage?: string;
  signal?: AbortSignal;
}

export interface TotpPromptContextValue {
  /**
   * Opens the shared step-up prompt. Resolves with a fresh 6-digit code or
   * rejects with TotpCancelledError. Never reuses a prior code.
   */
  requestTotp: (
    title: string,
    detail?: string,
    opts?: TotpRequestOptions,
  ) => Promise<string>;
  /** Alias used by useTotpGatedMutation retry loop. */
  requestCode: (opts?: {
    title?: string;
    detail?: string;
    errorMessage?: string;
    signal?: AbortSignal;
  }) => Promise<string>;
}

const Ctx = createContext<TotpPromptContextValue | null>(null);

/** Active cancel hook — set by TotpPromptProvider so logout can dismiss without reload. */
let cancelPendingTotpImpl: (() => void) | null = null;

/** Cancel any in-flight TOTP prompt (used by logout). Safe when no provider is mounted. */
export function cancelPendingTotpPrompt(): void {
  cancelPendingTotpImpl?.();
}

export function useTotpPrompt(): TotpPromptContextValue {
  const c = useContext(Ctx);
  if (!c) throw new Error("useTotpPrompt must be used within a TotpPromptProvider");
  return c;
}

export function TotpPromptProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingRequest | null>(null);
  const pendingRef = useRef<PendingRequest | null>(null);

  const settle = useCallback((request: PendingRequest, fn: () => void) => {
    if (pendingRef.current !== request) return;
    pendingRef.current = null;
    request.cleanup?.();
    setPending(null);
    fn();
  }, []);

  const open = useCallback(
    (
      title: string,
      detail: string | undefined,
      errorMessage: string | undefined,
      signal: AbortSignal | undefined,
    ) => {
      return new Promise<string>((resolve, reject) => {
        if (signal?.aborted) {
          reject(new TotpCancelledError());
          return;
        }

        const previous = pendingRef.current;
        if (previous) {
          settle(previous, () => previous.reject(new TotpCancelledError()));
        }

        const request: PendingRequest = {
          title,
          detail,
          errorMessage,
          resolve,
          reject,
        };
        if (signal) {
          const onAbort = () => {
            settle(request, () => request.reject(new TotpCancelledError()));
          };
          signal.addEventListener("abort", onAbort, { once: true });
          request.cleanup = () => signal.removeEventListener("abort", onAbort);
        }
        pendingRef.current = request;
        setPending(request);
      });
    },
    [settle],
  );

  const requestTotp = useCallback(
    (title: string, detail?: string, opts?: TotpRequestOptions) =>
      open(title, detail, opts?.errorMessage, opts?.signal),
    [open],
  );

  const requestCode = useCallback(
    (opts?: { title?: string; detail?: string; errorMessage?: string; signal?: AbortSignal }) =>
      open(opts?.title ?? "Enter verification code", opts?.detail, opts?.errorMessage, opts?.signal),
    [open],
  );

  const handleSubmit = useCallback(
    (code: string) => {
      if (!pending) return;
      settle(pending, () => pending.resolve(code));
    },
    [pending, settle],
  );

  const handleCancel = useCallback(() => {
    const current = pendingRef.current;
    if (!current) return;
    settle(current, () => current.reject(new TotpCancelledError()));
  }, [settle]);

  // Keep module cancel in sync so logout can dismiss without a full reload (ZTR-1168).
  cancelPendingTotpImpl = handleCancel;

  const value: TotpPromptContextValue = { requestTotp, requestCode };

  return (
    <Ctx.Provider value={value}>
      {children}
      {pending ? (
        <TotpPrompt
          title={pending.title}
          detail={pending.detail}
          errorMessage={pending.errorMessage}
          onSubmit={handleSubmit}
          onCancel={handleCancel}
        />
      ) : null}
    </Ctx.Provider>
  );
}
