/** @vitest-environment jsdom */
// useTotpGatedMutation — the step-up retry loop must terminate. The 401
// challenge is deliberately ambiguous (session gone / CSRF stale / wrong code),
// so an unbounded `for(;;)` over it re-prompts an operator forever (ZTR-1195).
// Money-mutation expiry path: attempt → api() 401 → awaited /me dead → no
// second prompt + /login (D1 integration).

import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { ApiError, api } from "../lib/api.js";
import { useAuth } from "../store/auth.js";
import { TotpPromptProvider } from "./index.js";
import { useTotpGatedMutation } from "./useTotpGatedMutation.js";

const AUTH_FACTOR_FAILURE = {
  error: { code: "invalid_credentials", message: "authentication required" },
};

const AUTH_401_BODY = JSON.stringify(AUTH_FACTOR_FAILURE);

const LIVE_USER = {
  userId: "u1",
  role: "admin" as const,
  mustEnrolTotp: false,
  mustChangePassword: false,
  csrfToken: "csrf-x",
};

function seedSession() {
  useAuth.setState({ user: { ...LIVE_USER } });
}

function captureRedirect(): { readonly to: () => string | undefined } {
  // ZTR-1168: logout navigates client-side via history.pushState + popstate.
  const pushState = vi.spyOn(window.history, "pushState");
  const assign = vi.fn();
  Object.defineProperty(window, "location", { configurable: true, value: { href: "" } });
  Object.defineProperty(window.location, "href", {
    configurable: true,
    set: assign,
    get: () => "",
  });
  return {
    to: () =>
      (pushState.mock.calls.find((c) => c[2] === "/login")?.[2] as string | undefined) ??
      (assign.mock.calls[0]?.[0] as string | undefined),
  };
}

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

/** Per-slot findByLabelText — avoids remount race on first empty slot wait. */
async function enterCode(code: string) {
  for (let i = 0; i < 6; i += 1) {
    const input = await screen.findByLabelText(
      i === 0 ? "Verification code" : `Digit ${i + 1}`,
    );
    fireEvent.change(input, { target: { value: code[i]! } });
  }
}

beforeEach(() => {
  seedSession();
  vi.restoreAllMocks();
});

afterEach(cleanup);

describe("withTotpRetry ceiling", () => {
  test("a repeated 401 challenge terminates instead of re-prompting forever", async () => {
    const attempt = vi.fn(async () => {
      throw new ApiError(401, AUTH_FACTOR_FAILURE);
    });
    // Alive-session recheck so wrong-code path keeps retrying under the ceiling.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/admin/v1/me") {
          return new Response(
            JSON.stringify({
              userId: "u1",
              role: "admin",
              csrfToken: "csrf-x",
              mustEnrolTotp: false,
              mustChangePassword: false,
            }),
            { status: 200 },
          );
        }
        return new Response(AUTH_401_BODY, { status: 401 });
      }),
    );
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
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/admin/v1/me") {
          return new Response(
            JSON.stringify({
              userId: "u1",
              role: "admin",
              csrfToken: "csrf-x",
              mustEnrolTotp: false,
              mustChangePassword: false,
            }),
            { status: 200 },
          );
        }
        return new Response(AUTH_401_BODY, { status: 401 });
      }),
    );
    renderHarness(attempt);

    for (const code of ["111111", "222222", "333333", "999999"]) await enterCode(code);

    expect(await screen.findByText("done: engaged")).toBeInTheDocument();
    expect(attempt).toHaveBeenCalledTimes(4);
  });
});

describe("expired session on TOTP-gated money mutation (ZTR-1195 D1)", () => {
  test("dead session after money 401 does not re-prompt and lands on /login", async () => {
    const redirect = captureRedirect();
    let moneyPosts = 0;
    let meCalls = 0;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url === "/admin/v1/external-sends/op/approve" && (init?.method ?? "GET") === "POST") {
          moneyPosts += 1;
          return new Response(AUTH_401_BODY, { status: 401 });
        }
        if (url === "/admin/v1/me") {
          meCalls += 1;
          return new Response(AUTH_401_BODY, { status: 401 });
        }
        if (url === "/admin/v1/logout") return new Response(null, { status: 204 });
        return new Response(AUTH_401_BODY, { status: 401 });
      }),
    );

    const mutationFn = vi.fn(async (_v: void, totp: string) =>
      api<string>("/external-sends/op/approve", {
        method: "POST",
        body: "{}",
        totp,
      }),
    );
    renderHarness(mutationFn);

    await enterCode("123456");

    expect(await screen.findByText(/^terminated:/)).toHaveTextContent(
      "terminated: authentication required",
    );
    // No second prompt cycle after the failed attempt.
    expect(screen.queryByLabelText("Verification code")).not.toBeInTheDocument();
    expect(screen.queryByText(/Code invalid/)).not.toBeInTheDocument();
    expect(useAuth.getState().user).toBeNull();
    expect(redirect.to()).toBe("/login");
    expect(moneyPosts).toBe(1);
    expect(mutationFn).toHaveBeenCalledTimes(1);
    expect(meCalls).toBeGreaterThanOrEqual(1);
  });

  test("alive session wrong code still re-prompts within the ceiling", async () => {
    captureRedirect();
    let moneyPosts = 0;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url === "/admin/v1/external-sends/op/approve" && (init?.method ?? "GET") === "POST") {
          moneyPosts += 1;
          // First attempt wrong; second succeeds.
          if (moneyPosts === 1) {
            return new Response(AUTH_401_BODY, { status: 401 });
          }
          return new Response(JSON.stringify({ ok: true }), { status: 200 });
        }
        if (url === "/admin/v1/me") {
          return new Response(
            JSON.stringify({
              userId: "u1",
              role: "admin",
              csrfToken: "csrf-fresh",
              mustEnrolTotp: false,
              mustChangePassword: false,
            }),
            { status: 200 },
          );
        }
        return new Response(AUTH_401_BODY, { status: 401 });
      }),
    );

    const mutationFn = vi.fn(async (_v: void, totp: string) =>
      api<{ ok: boolean }>("/external-sends/op/approve", {
        method: "POST",
        body: "{}",
        totp,
      }).then(() => "engaged"),
    );
    renderHarness(mutationFn);

    await enterCode("111111");
    // Wrong-code path surfaces try-again copy on the next prompt.
    expect(await screen.findByText(/Code invalid/)).toBeInTheDocument();
    await enterCode("999999");

    expect(await screen.findByText("done: engaged")).toBeInTheDocument();
    expect(moneyPosts).toBe(2);
    expect(useAuth.getState().user).not.toBeNull();
  });
});

describe("approve opaque factor failure re-prompt (ZTR-1194)", () => {
  const APPROVAL_REJECTED = {
    error: { code: "approval_rejected", message: "approval rejected" },
  };
  const APPROVAL_401_BODY = JSON.stringify(APPROVAL_REJECTED);

  test("401 approval_rejected re-prompts with try-again copy", async () => {
    captureRedirect();
    let moneyPosts = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url === "/admin/v1/external-sends/op/approve" && (init?.method ?? "GET") === "POST") {
          moneyPosts += 1;
          if (moneyPosts === 1) {
            return new Response(APPROVAL_401_BODY, { status: 401 });
          }
          return new Response(JSON.stringify({ ok: true }), { status: 200 });
        }
        if (url === "/admin/v1/me") {
          return new Response(
            JSON.stringify({
              userId: "u1",
              role: "admin",
              csrfToken: "csrf-fresh",
              mustEnrolTotp: false,
              mustChangePassword: false,
            }),
            { status: 200 },
          );
        }
        return new Response(APPROVAL_401_BODY, { status: 401 });
      }),
    );

    const mutationFn = vi.fn(async (_v: void, totp: string) =>
      api<{ ok: boolean }>("/external-sends/op/approve", {
        method: "POST",
        body: JSON.stringify({ challenge_nonce: "n1", expected_row_version: 1 }),
        totp,
      }).then(() => "engaged"),
    );
    renderHarness(mutationFn);

    await enterCode("111111");
    expect(await screen.findByText(/Code invalid — try again/)).toBeInTheDocument();
    await enterCode("999999");

    expect(await screen.findByText("done: engaged")).toBeInTheDocument();
    expect(moneyPosts).toBe(2);
    expect(mutationFn).toHaveBeenCalledTimes(2);
    expect(useAuth.getState().user).not.toBeNull();
  });

  test("second consecutive failure hints to wait for the next authenticator code", async () => {
    captureRedirect();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "/admin/v1/me") {
          return new Response(
            JSON.stringify({
              userId: "u1",
              role: "admin",
              csrfToken: "csrf-x",
              mustEnrolTotp: false,
              mustChangePassword: false,
            }),
            { status: 200 },
          );
        }
        return new Response(APPROVAL_401_BODY, { status: 401 });
      }),
    );

    const attempt = vi.fn(async () => {
      throw new ApiError(401, APPROVAL_REJECTED);
    });
    renderHarness(attempt);

    await enterCode("111111");
    expect(await screen.findByText(/^Code invalid — try again\.$/)).toBeInTheDocument();
    await enterCode("222222");
    expect(
      await screen.findByText(/wait for the next authenticator code/),
    ).toBeInTheDocument();
    expect(attempt).toHaveBeenCalledTimes(2);
  });

  test("challenge + device fields survive a wrong-code retry without re-signing", async () => {
    captureRedirect();
    let moneyPosts = 0;
    const signOnce = vi.fn(async () => "device-sig-held");
    let heldSig: string | null = null;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url === "/admin/v1/external-sends/op/approve" && (init?.method ?? "GET") === "POST") {
          moneyPosts += 1;
          const body = JSON.parse(String(init?.body ?? "{}")) as {
            device_signature: string | null;
            challenge_nonce: string;
          };
          expect(body.challenge_nonce).toBe("nonce-fixed");
          expect(body.device_signature).toBe("device-sig-held");
          if (moneyPosts === 1) {
            return new Response(APPROVAL_401_BODY, { status: 401 });
          }
          return new Response(JSON.stringify({ status: "APPROVED" }), { status: 200 });
        }
        if (url === "/admin/v1/me") {
          return new Response(
            JSON.stringify({
              userId: "u1",
              role: "admin",
              csrfToken: "csrf-fresh",
              mustEnrolTotp: false,
              mustChangePassword: false,
            }),
            { status: 200 },
          );
        }
        return new Response(APPROVAL_401_BODY, { status: 401 });
      }),
    );

    // Mirrors TransferDetailPage: sign once outside the TOTP attempt, reuse on retry.
    const mutationFn = vi.fn(async (_v: void, totp: string) => {
      if (heldSig === null) {
        heldSig = await signOnce();
      }
      return api<{ status: string }>("/external-sends/op/approve", {
        method: "POST",
        body: JSON.stringify({
          challenge_nonce: "nonce-fixed",
          expected_row_version: 3,
          preimage_sha256: "abc",
          device_key_id: "dev-1",
          device_signature: heldSig,
        }),
        totp,
      }).then((r) => r.status);
    });
    renderHarness(mutationFn);

    await enterCode("111111");
    expect(await screen.findByText(/Code invalid — try again/)).toBeInTheDocument();
    await enterCode("999999");

    expect(await screen.findByText("done: APPROVED")).toBeInTheDocument();
    expect(signOnce).toHaveBeenCalledTimes(1);
    expect(moneyPosts).toBe(2);
    expect(mutationFn).toHaveBeenCalledTimes(2);
  });

  test("403 approval_rejected still aborts (status must be 401)", async () => {
    const attempt = vi.fn(async () => {
      throw new ApiError(403, APPROVAL_REJECTED);
    });
    renderHarness(attempt);
    await enterCode("123456");
    expect(await screen.findByText(/^terminated:/)).toHaveTextContent(
      "terminated: approval rejected",
    );
    expect(attempt).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/Code invalid/)).not.toBeInTheDocument();
  });
});
