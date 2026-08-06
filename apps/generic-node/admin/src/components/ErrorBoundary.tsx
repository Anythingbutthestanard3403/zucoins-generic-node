import { Component, type ErrorInfo, type ReactNode } from "react";

export class ErrorBoundary extends Component<
  { children: ReactNode; variant?: "page" | "inline" },
  { error: Error | null }
> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("UI error", error, info.componentStack);
  }
  render() {
    if (!this.state.error) return this.props.children;
    const full = this.props.variant === "page";
    return (
      <div className={full ? "auth-shell" : "empty"} role="alert">
        <div className={full ? "auth-card" : undefined}>
          <h1 style={{ fontSize: 16, marginBottom: 8 }}>Something went wrong</h1>
          <p className="muted" style={{ fontSize: 13 }}>{this.state.error.message}</p>
          <button type="button" className="btn-block" style={{ marginTop: 16 }} onClick={() => this.setState({ error: null })}>
            Try again
          </button>
        </div>
      </div>
    );
  }
}
