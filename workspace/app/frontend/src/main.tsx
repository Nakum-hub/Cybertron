import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App.tsx';
import AppErrorBoundary from './components/AppErrorBoundary.tsx';
import './index.css';
import { loadRuntimeConfig } from './lib/config.ts';

async function initializeApp() {
  try {
    await loadRuntimeConfig();
  } catch {
    // Runtime config is optional in local development.
  }

  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <AppErrorBoundary>
        <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <App />
        </BrowserRouter>
      </AppErrorBoundary>
    </StrictMode>
  );
}

initializeApp();
