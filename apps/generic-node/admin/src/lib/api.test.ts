import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, apiOrDemo } from "./api.js";
import { useAuth } from "../store/auth.js";

describe("api client", () => {
  beforeEach(() => {
    useAuth.setState({
      user: {
        userId: "u1",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "csrf-x",
      },
      demoMode: false,
    });
    vi.restoreAllMocks();
  });

  it("attaches CSRF on mutations and optional TOTP / idempotency", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await api("/operations/op1/recovery-actions", {
      method: "POST",
      body: JSON.stringify({ action: "ACK" }),
      totp: "123456",
      idempotencyKey: "idem-1",
    });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/admin/v1/operations/op1/recovery-actions");
    const headers = new Headers(init.headers);
    expect(headers.get("X-CSRF-Token")).toBe("csrf-x");
    expect(headers.get("X-ZP-TOTP")).toBe("123456");
    expect(headers.get("Idempotency-Key")).toBe("idem-1");
  });

  it("apiOrDemo returns fallback on 503 without throwing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ error: { code: "service_unavailable", message: "x" } }), {
          status: 503,
        }),
      ),
    );
    const r = await apiOrDemo("/operations/needs-attention", { operations: [], summary: { total: 0 } });
    expect(r.live).toBe(false);
    expect(r.data.summary.total).toBe(0);
  });

  it("apiOrDemo rethrows 401 so the shell can force re-auth", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ error: { code: "invalid_credentials", message: "auth" } }), {
          status: 401,
        }),
      ),
    );
    await expect(apiOrDemo("/operations/needs-attention", { x: 1 })).rejects.toBeInstanceOf(ApiError);
  });

  it.each([400, 404, 409, 429, 500, 503])(
    "apiOrDemo preserves code/message/requestId on a %i response instead of discarding them",
    async (status) => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () =>
          new Response(
            JSON.stringify({
              error: { code: `err_${status}`, message: `failure ${status}`, request_id: `req-${status}` },
            }),
            { status },
          ),
        ),
      );
      const r = await apiOrDemo("/operations/needs-attention", { fallback: true });
      expect(r.live).toBe(false);
      expect(r.data).toEqual({ fallback: true });
      expect(r.error).toEqual({
        code: `err_${status}`,
        message: `failure ${status}`,
        requestId: `req-${status}`,
        status,
      });
    },
  );

  it("apiOrDemo surfaces a network failure as a distinct error code rather than swallowing it", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    const r = await apiOrDemo("/operations/needs-attention", { fallback: true });
    expect(r.live).toBe(false);
    expect(r.error).toMatchObject({ code: "network_error", status: 0 });
    expect(r.error?.message).toMatch(/Failed to fetch/);
  });

  it("demoMode short-circuits to fixtures without fetch", async () => {
    useAuth.setState({ demoMode: true });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const r = await apiOrDemo("/anything", { demo: true });
    expect(r).toEqual({ data: { demo: true }, live: false });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("mutations without CSRF throw before fetch", async () => {
    useAuth.setState({
      user: {
        userId: "u1",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "",
      },
    });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      api("/destinations/d1/retire", { method: "POST", body: "{}", totp: "123456" }),
    ).rejects.toMatchObject({ code: "csrf_required", status: 403 });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("mutations with empty TOTP throw before fetch", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      api("/external-sends/op/approve", { method: "POST", body: "{}", totp: "" }),
    ).rejects.toMatchObject({ code: "totp_required", status: 401 });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
