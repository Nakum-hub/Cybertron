import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

export default class AppErrorBoundary extends Component<Props, State> {
  state: State = {
    hasError: false,
  };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ui.render_failure', {
      message: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack,
    });
  }

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return (
      <div className="min-h-screen bg-[#04070f] text-white px-6 py-20">
        <div className="max-w-2xl mx-auto rounded-2xl border border-red-400/30 bg-red-950/30 p-8">
          <h1 className="text-2xl font-semibold mb-3">Something went wrong</h1>
          <p className="text-sm text-red-100/90 mb-5">
            The interface encountered an unexpected error. Reload the page to recover.
          </p>
          <button
            type="button"
            className="inline-flex rounded-lg bg-red-500/80 hover:bg-red-500 px-4 py-2 text-sm font-medium"
            onClick={() => window.location.reload()}
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}
