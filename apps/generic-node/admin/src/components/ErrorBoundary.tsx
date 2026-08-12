import { Component, type ErrorInfo, type ReactNode } from "react";

/** Dynamic-import / stale-chunk failures after a redeploy (ZTR-1252). */
export function isChunkLoadError(error: Error): boolean {
  const msg = `${error.name}: ${error.message}`;
  return (
    /Failed to fetch dynamically imported module/i.test(msg) ||
    /Importing a module script failed/i.test(msg) ||
    /error loading dynamically imported module/i.test(msg) ||
    /Loading chunk [\w-]+ failed/i.test(msg) ||
    /ChunkLoadError/i.test(msg) ||
    (/MIME type/i.test(msg) && /javascript|module/i.test(msg))
  );
}

async function unregisterServiceWorkers(): Promise<void> {
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
  try {
    const regs = await navigator.serviceWorker.getRegistrations();
    await Promise.all(regs.map((r) => r.unregister()));
  } catch {
    // best-effort — reload still helps when the server 404s missing assets
  }
  try {
    if (typeof caches !== "undefined") {
      const keys = await caches.keys();
      await Promise.all(
        keys.filter((k) => k.startsWith("zu-node-")).map((k) => caches.delete(k)),
      );
    }
  } catch {
    // ignore
  }
}

export class ErrorBoundary extends Component<
  { children: ReactNode; variant?: "page" | "inline" },
  { error: Error | null }
> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("UI error", error, info.componentStack);
  }

  private async recoverFromStaleChunk(): Promise<void> {
    await unregisterServiceWorkers();
    if (typeof window !== "undefined") {
      window.location.reload();
    }
  }

  render() {
    if (!this.state.error) return this.props.children;
    const full = this.props.variant === "page";
    const chunkFail = isChunkLoadError(this.state.error);
    return (
      <div className={full ? "auth-shell" : "empty"} role="alert">
        <div className={full ? "auth-card" : undefined}>
          <h1 style={{ fontSize: 16, marginBottom: 8 }}>
            {chunkFail ? "Console update required" : "Something went wrong"}
          </h1>
          <p className="muted" style={{ fontSize: 13 }}>
            {chunkFail
              ? "A newer build is on the server and this tab still holds a stale route. Reload to pick up the update."
              : this.state.error.message}
          </p>
          {chunkFail ? (
            <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
              {this.state.error.message}
            </p>
          ) : null}
          {chunkFail ? (
            <button
              type="button"
              className="btn-block"
              style={{ marginTop: 16 }}
              onClick={() => void this.recoverFromStaleChunk()}
            >
              Reload console
            </button>
          ) : (
            <button
              type="button"
              className="btn-block"
              style={{ marginTop: 16 }}
              onClick={() => this.setState({ error: null })}
            >
              Try again
            </button>
          )}
        </div>
      </div>
    );
  }
}
