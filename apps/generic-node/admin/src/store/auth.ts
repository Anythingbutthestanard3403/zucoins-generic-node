import { resetClientSessionState } from "../lib/session-reset.js";
import { create } from "zustand";

export interface SessionUser {
  userId: string;
  username?: string;
  role: "admin" | "viewer";
  mustEnrolTotp: boolean;
  mustChangePassword: boolean;
  csrfToken: string;
}

interface AuthState {
  user: SessionUser | null;
  setUser: (u: SessionUser | null) => void;
  me: () => Promise<SessionUser | null>;
  /** Live generic-node: POST /admin/v1/login (password only — no login-body TOTP). */
  login: (username: string, password: string) => Promise<SessionUser>;
  logout: () => Promise<void>;
  /** Live generic-node: POST /admin/v1/password (+ X-CSRF-Token). */
  changePassword: (
    currentPassword: string,
    newPassword: string,
  ) => Promise<{ ok: true; csrfToken: string }>;
  /**
   * POST /admin/v1/enrol-totp — mint pending secret (returned once).
   * Does not clear mustEnrolTotp; confirm runs next.
   */
  enrolTotp: (password: string) => Promise<{ secret: string; otpauthUrl: string }>;
  /**
   * POST /admin/v1/confirm-totp — activate factor, clear mustEnrolTotp,
   * rotate session CSRF (and Set-Cookie handled by browser).
   */
  confirmTotp: (totp: string) => Promise<{ ok: true; csrfToken: string }>;
}

async function errorMessage(res: Response, fallback: string): Promise<string> {
  try {
    const b = (await res.json()) as { error?: { message?: string } };
    return b.error?.message ?? fallback;
  } catch {
    return fallback;
  }
}

function sessionFrom(data: Record<string, unknown>): SessionUser {
  return {
    userId: String(data.userId ?? ""),
    username: typeof data.username === "string" ? data.username : undefined,
    role: data.role === "viewer" ? "viewer" : "admin",
    mustEnrolTotp: Boolean(data.mustEnrolTotp),
    mustChangePassword: Boolean(data.mustChangePassword),
    csrfToken: typeof data.csrfToken === "string" ? data.csrfToken : "",
  };
}

export const useAuth = create<AuthState>((set, get) => ({
  user: null,
  setUser: (user) => set({ user }),
  me: async () => {
    try {
      const res = await fetch("/admin/v1/me", { credentials: "include" });
      if (!res.ok) {
        set({ user: null });
        return null;
      }
      const user = sessionFrom((await res.json()) as Record<string, unknown>);
      set({ user });
      return user;
    } catch {
      set({ user: null });
      return null;
    }
  },
  login: async (username, password) => {
    const res = await fetch("/admin/v1/login", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) throw new Error(await errorMessage(res, "Login failed"));
    const user = sessionFrom((await res.json()) as Record<string, unknown>);
    set({ user });
    return user;
  },
  logout: async () => {
    // Local clear + client-side navigate first so a hung revoke POST cannot keep
    // RequireAuth open or let a TOTP step-up re-prompt after session death
    // (ZTR-1195 / ZTR-1168). Clear react-query cache and cancel any TOTP prompt
    // deliberately — no full page reload.
    const csrf = get().user?.csrfToken ?? "";
    set({ user: null });
    resetClientSessionState();
    // Client-side navigation: History API so react-router picks it up without reload.
    if (typeof window !== "undefined") {
      window.history.pushState({}, "", "/login");
      window.dispatchEvent(new PopStateEvent("popstate"));
    }
    try {
      await fetch("/admin/v1/logout", {
        method: "POST",
        headers: { "X-CSRF-Token": csrf },
        credentials: "include",
      });
    } catch {
      /* offline */
    }
  },
  changePassword: async (currentPassword, newPassword) => {
    const csrf = get().user?.csrfToken ?? "";
    const res = await fetch("/admin/v1/password", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf,
      },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });
    if (!res.ok) throw new Error(await errorMessage(res, "Password change failed"));
    const data = (await res.json()) as { csrfToken?: string };
    const csrfToken = typeof data.csrfToken === "string" ? data.csrfToken : "";
    const prev = get().user;
    if (prev) {
      set({
        user: {
          ...prev,
          mustChangePassword: false,
          csrfToken: csrfToken || prev.csrfToken,
        }
      });
    }
    return { ok: true as const, csrfToken };
  },
  enrolTotp: async (password) => {
    const csrf = get().user?.csrfToken ?? "";
    const res = await fetch("/admin/v1/enrol-totp", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf,
      },
      body: JSON.stringify({ password }),
    });
    if (!res.ok) throw new Error(await errorMessage(res, "TOTP enrol failed"));
    const data = (await res.json()) as { secret?: string; otpauthUrl?: string };
    const secret = typeof data.secret === "string" ? data.secret : "";
    const otpauthUrl = typeof data.otpauthUrl === "string" ? data.otpauthUrl : "";
    if (secret.length === 0 || otpauthUrl.length === 0) {
      throw new Error("TOTP enrol response missing secret");
    }
    // Secret stays in the caller's React state only — never stash on the store.
    return { secret, otpauthUrl };
  },
  confirmTotp: async (totp) => {
    const csrf = get().user?.csrfToken ?? "";
    const res = await fetch("/admin/v1/confirm-totp", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf,
      },
      body: JSON.stringify({ totp }),
    });
    if (!res.ok) throw new Error(await errorMessage(res, "TOTP confirm failed"));
    const data = (await res.json()) as {
      ok?: boolean;
      mustEnrolTotp?: boolean;
      csrfToken?: string;
    };
    const csrfToken = typeof data.csrfToken === "string" ? data.csrfToken : "";
    const prev = get().user;
    if (prev) {
      set({
        user: {
          ...prev,
          mustEnrolTotp: false,
          csrfToken: csrfToken || prev.csrfToken,
        }
      });
    }
    return { ok: true as const, csrfToken };
  },
}));
