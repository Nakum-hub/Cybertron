import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';
import path from 'node:path';

const devPort = Number(process.env.VITE_PORT ?? 3000);
const devHost = process.env.VITE_HOST || '127.0.0.1';
const backendTarget = process.env.VITE_BACKEND_TARGET || 'http://127.0.0.1:8001';
const cacheDirName = `.vite-${devHost.replace(/[^a-z0-9]+/gi, '_')}-${devPort}`;

export default defineConfig({
  plugins: [react()],
  cacheDir: path.resolve(__dirname, 'node_modules', cacheDirName),
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  esbuild: {
    drop: process.env.NODE_ENV === 'production' ? ['debugger'] : [],
    pure: process.env.NODE_ENV === 'production' ? ['console.log', 'console.debug'] : [],
  },
  build: {
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'query-vendor': ['@tanstack/react-query'],
          'three-vendor': ['three', '@react-three/fiber', '@react-three/drei'],
          'chart-vendor': ['recharts'],
        },
      },
    },
  },
  server: {
    host: devHost,
    port: devPort,
    strictPort: true,
    cors: {
      origin: [
        `http://localhost:${devPort}`,
        `http://127.0.0.1:${devPort}`,
      ],
      credentials: true,
    },
    proxy: {
      '/api': {
        target: backendTarget,
        changeOrigin: true,
      },
    },
  },
});
