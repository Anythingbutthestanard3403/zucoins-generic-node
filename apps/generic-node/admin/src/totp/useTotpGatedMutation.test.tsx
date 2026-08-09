/** @vitest-environment jsdom */
// useTotpGatedMutation — the step-up retry loop must terminate. The 401
// challenge is deliberately ambiguous (session gone / CSRF stale / wrong code),
// so an unbounded `for(;;)` over it re-prompts an operator forever (ZTR-1195).

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import { ApiError } from "../lib/api.js";
import { TotpPromptProvider } from "./index.js";
import { useTotpGatedMutation } from "./useTotpGatedMutation.js";

const AUTH_FACTOR_FAILURE = {
  error: { code: "invalid_credentials", message: "authentication required" },
};

function Harness({ mutationFn }: { mutationFn: (v: void, totp: string) => Promise<string> }) {
  const m = useTotpGatedMutation<string>(mutationFn);
  return (
    <div>
      <button type="button" onClick={() => m.mutate()}>
        Run
      </button>
      {m.isError ? <p>terminated: {(m.error as Error).message}</p> : null}
      {m.isSuccess ? <p>done: {m.data}</p> : null}
    </div>
  );
}

function renderHarness(mutationFn: (v: void, totp: string) => Promise<string>) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <TotpPromptProvider>
        <Harness mutationFn={mutationFn} />
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByRole("button", { name: "Run" }));
}

/** Waits for a fresh (empty, enabled) prompt, then fills it — slots auto-submit on 6. */
async function enterCode(code: string) {
  await vi.waitFor(() => {
    const first = screen.getByLabelText("Verification code") as HTMLInputElement;
    expect(first.value).toBe("");
    expect(first.disabled).toBe(false);
  });
  fireEvent.change(screen.getByLabelText("Verification code"), { target: { value: code[0]! } });
  for (let i = 1; i < 6; i += 1) {
    fireEvent.change(screen.getByLabelText(`Digit ${i + 1}`), { target: { value: code[i]! } });
  }
}

afterEach(cleanup);

describe("withTotpRetry ceiling", () => {
  test("a repeated 401 challenge terminates instead of re-prompting forever", async () => {
    const attempt = vi.fn(async () => {
      throw new ApiError(401, AUTH_FACTOR_FAILURE);
    });
    renderHarness(attempt);

    // One initial attempt + MAX_TOTP_RETRIES re-prompts. An unbounded loop would
    // keep handing out a fifth prompt and never settle the mutation.
    for (let i = 0; i < 4; i += 1) await enterCode("123456");

    expect(await screen.findByText(/^terminated:/)).toHaveTextContent(
      "terminated: authentication required",
    );
    expect(attempt).toHaveBeenCalledTimes(4);
    expect(screen.queryByLabelText("Verification code")).not.toBeInTheDocument();
  });

  test("three wrong codes followed by a correct one still succeeds", async () => {
    const attempt = vi.fn(async (_v: void, totp: string) => {
      if (totp !== "999999") throw new ApiError(401, AUTH_FACTOR_FAILURE);
      return "engaged";
    });
    renderHarness(attempt);

    for (const code of ["111111", "222222", "333333", "999999"]) await enterCode(code);

    expect(await screen.findByText("done: engaged")).toBeInTheDocument();
    expect(attempt).toHaveBeenCalledTimes(4);
  });
});
