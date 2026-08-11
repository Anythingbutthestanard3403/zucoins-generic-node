import { beforeEach, describe, expect, it, vi } from "vitest";
import { useAuth } from "./auth.js";

describe("auth store paths (generic-node live surface)", () => {
  beforeEach(() => {
    useAuth.setState({ user: null });
    vi.restoreAllMocks();
  });

  it("login posts to /admin/v1/login without totp body field", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          userId: "u1",
          username: "admin",
          role: "admin",
          mustChangePassword: false,
          mustEnrolTotp: false,
          csrfToken: "csrf-1",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const user = await useAuth.getState().login("admin", "secret-pass");
    expect(user.csrfToken).toBe("csrf-1");
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/admin/v1/login");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ username: "admin", password: "secret-pass" });
  });

  it("me hits GET /admin/v1/me", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          userId: "u1",
          username: "admin",
          role: "admin",
          mustChangePassword: false,
          mustEnrolTotp: false,
          csrfToken: "csrf-me",
        }),
        { status: 200 },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const user = await useAuth.getState().me();
    expect(user?.csrfToken).toBe("csrf-me");
    expect(fetchMock.mock.calls[0]![0]).toBe("/admin/v1/me");
  });

  it("logout posts /admin/v1/logout with CSRF", async () => {
    useAuth.setState({
      user: {
        userId: "u1",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "tok",
      },
    });
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const pushState = vi.spyOn(window.history, "pushState");
    const popEvents: Event[] = [];
    const onPop = (e: Event) => popEvents.push(e);
    window.addEventListener("popstate", onPop);

    await useAuth.getState().logout();
    // Local clear + client-side /login must not wait on the revoke POST (ZTR-1195 / ZTR-1168).
    expect(useAuth.getState().user).toBeNull();
    expect(pushState).toHaveBeenCalledWith({}, "", "/login");
    expect(popEvents.length).toBeGreaterThanOrEqual(1);
    expect(fetchMock.mock.calls[0]![0]).toBe("/admin/v1/logout");
    const headers = new Headers((fetchMock.mock.calls[0]![1] as RequestInit).headers);
    expect(headers.get("X-CSRF-Token")).toBe("tok");
    window.removeEventListener("popstate", onPop);
    pushState.mockRestore();
  });

  it("logout clears local session before a hung revoke POST settles", async () => {
    useAuth.setState({
      user: {
        userId: "u1",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: false,
        csrfToken: "tok",
      },
    });
    let release!: () => void;
    const hung = new Promise<Response>((resolve) => {
      release = () => resolve(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    });
    vi.stubGlobal("fetch", vi.fn(async () => hung));
    const pushState = vi.spyOn(window.history, "pushState");

    const pending = useAuth.getState().logout();
    // Must clear immediately without awaiting hung revoke (ZTR-1195).
    expect(useAuth.getState().user).toBeNull();
    expect(pushState).toHaveBeenCalledWith({}, "", "/login");
    release();
    await pending;
    pushState.mockRestore();
  });


  it("changePassword posts /admin/v1/password with snake_case body", async () => {
    useAuth.setState({
      user: {
        userId: "u1",
        role: "admin",
        mustEnrolTotp: false,
        mustChangePassword: true,
        csrfToken: "tok",
      },
    });
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ ok: true, mustChangePassword: false, csrfToken: "tok2" }), {
        status: 200,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const r = await useAuth.getState().changePassword("old-pass-long", "new-pass-longer");
    expect(r.csrfToken).toBe("tok2");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/admin/v1/password");
    expect(JSON.parse(String(init.body))).toEqual({
      current_password: "old-pass-long",
      new_password: "new-pass-longer",
    });
    expect(useAuth.getState().user?.mustChangePassword).toBe(false);
    expect(useAuth.getState().user?.csrfToken).toBe("tok2");
  });

  it("enrolTotp posts password and returns secret once (not stored on auth state)", async () => {
    useAuth.setState({
      user: {
        userId: "u1",
        role: "admin",
        mustEnrolTotp: true,
        mustChangePassword: false,
        csrfToken: "tok",
      },
    });
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          secret: "JBSWY3DPEHPK3PXP",
          otpauthUrl: "otpauth://totp/Zu:admin?secret=JBSWY3DPEHPK3PXP&issuer=Zu",
        }),
        { status: 200 },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const r = await useAuth.getState().enrolTotp("operator-pass-long");
    expect(r.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(r.otpauthUrl).toContain("otpauth://totp/");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/admin/v1/enrol-totp");
    expect(JSON.parse(String(init.body))).toEqual({ password: "operator-pass-long" });
    const headers = new Headers(init.headers);
    expect(headers.get("X-CSRF-Token")).toBe("tok");
    // Secret must not leak onto durable auth state (component holds it ephemerally).
    expect(JSON.stringify(useAuth.getState())).not.toContain("JBSWY3DPEHPK3PXP");
    expect(useAuth.getState().user?.mustEnrolTotp).toBe(true);
  });

  it("confirmTotp posts 6-digit code and clears mustEnrolTotp + rotates csrf", async () => {
    useAuth.setState({
      user: {
        userId: "u1",
        role: "admin",
        mustEnrolTotp: true,
        mustChangePassword: false,
        csrfToken: "tok-old",
      },
    });
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({ ok: true, mustEnrolTotp: false, csrfToken: "tok-rotated" }),
        { status: 200 },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const r = await useAuth.getState().confirmTotp("123456");
    expect(r.csrfToken).toBe("tok-rotated");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/admin/v1/confirm-totp");
    expect(JSON.parse(String(init.body))).toEqual({ totp: "123456" });
    expect(useAuth.getState().user?.mustEnrolTotp).toBe(false);
    expect(useAuth.getState().user?.csrfToken).toBe("tok-rotated");
  });
});
