import type { QueryClient } from "@tanstack/react-query";
import { cancelPendingTotpPrompt } from "../totp/TotpPromptProvider.js";

let boundQueryClient: QueryClient | null = null;

/** Bind the app QueryClient so logout can clear cache without importing main.tsx. */
export function bindSessionQueryClient(client: QueryClient): void {
  boundQueryClient = client;
}

/** Clear react-query cache and cancel any open TOTP step-up (ZTR-1168 logout). */
export function resetClientSessionState(): void {
  cancelPendingTotpPrompt();
  boundQueryClient?.clear();
}
