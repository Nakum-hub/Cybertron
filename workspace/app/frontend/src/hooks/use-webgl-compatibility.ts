import { useEffect, useState } from 'react';

const SOFTWARE_RENDERER_MARKERS = [
  'swiftshader',
  'llvmpipe',
  'software',
  'microsoft basic render',
  'mesa offscreen',
];
const UNSTABLE_RENDERER_SIGNATURES = [
  ['angle (intel', 'direct3d11'],
];

type WebglCompatibility = 'unknown' | 'supported' | 'unsupported';

function detectWebglCompatibility(): WebglCompatibility {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return 'unsupported';
  }

  const canvas = document.createElement('canvas');
  const gl = (
    canvas.getContext('webgl2', { powerPreference: 'high-performance' }) ||
    canvas.getContext('webgl', { powerPreference: 'high-performance' }) ||
    canvas.getContext('experimental-webgl')
  ) as WebGLRenderingContext | WebGL2RenderingContext | null;

  if (!gl) {
    return 'unsupported';
  }

  const debugInfo =
    gl.getExtension('WEBGL_debug_renderer_info') ||
    gl.getExtension('MOZ_WEBGL_debug_renderer_info') ||
    gl.getExtension('WEBKIT_WEBGL_debug_renderer_info');

  const renderer = debugInfo
    ? String(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '').toLowerCase()
    : '';
  const vendor = debugInfo
    ? String(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '').toLowerCase()
    : '';
  const signature = `${vendor} ${renderer}`.trim();

  if (SOFTWARE_RENDERER_MARKERS.some(marker => signature.includes(marker))) {
    return 'unsupported';
  }

  if (UNSTABLE_RENDERER_SIGNATURES.some(markers => markers.every(marker => signature.includes(marker)))) {
    return 'unsupported';
  }

  if ('deviceMemory' in navigator && typeof navigator.deviceMemory === 'number' && navigator.deviceMemory <= 2) {
    return 'unsupported';
  }

  return 'supported';
}

export function useWebglCompatibility(): WebglCompatibility {
  const [compatibility, setCompatibility] = useState<WebglCompatibility>('unknown');

  useEffect(() => {
    setCompatibility(detectWebglCompatibility());
  }, []);

  return compatibility;
}
