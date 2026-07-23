// A top-level error boundary so an unhandled render throw shows a recoverable card instead of a
// blank white screen (the app previously had none). Class component — the only way to catch render
// errors in React.

import { Component, type ErrorInfo, type ReactNode } from "react";

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface it for diagnostics; the app log tail also captures backend errors.
    console.error("NorthKey UI error:", error, info.componentStack);
  }

  private reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="flex h-full items-center justify-center p-8">
        <div className="surface max-w-md p-6 text-center">
          <div className="mb-2 text-base font-semibold text-[var(--danger)]">Something went wrong</div>
          <p className="mb-4 text-sm text-[var(--text-secondary)]">
            A part of the app hit an unexpected error. Your vault is safe — this only affected the
            screen. Try again, and if it keeps happening, check Settings → Diagnostics.
          </p>
          <p className="mono mb-4 max-h-24 overflow-auto rounded-[8px] bg-[var(--bg-inset)] p-2 text-left text-[11px] text-[var(--text-muted)]">
            {error.message || String(error)}
          </p>
          <div className="flex justify-center gap-2">
            <button
              onClick={this.reset}
              className="rounded-[10px] bg-[var(--accent)] px-4 py-2 text-sm font-medium text-[#04121a] hover:bg-[var(--accent-hover)]"
            >
              Try again
            </button>
            <button
              onClick={() => window.location.reload()}
              className="rounded-[10px] border border-[var(--border-strong)] px-4 py-2 text-sm hover:border-[var(--accent)]/50"
            >
              Reload app
            </button>
          </div>
        </div>
      </div>
    );
  }
}
