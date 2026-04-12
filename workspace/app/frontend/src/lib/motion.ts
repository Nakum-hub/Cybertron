import { useEffect, useState } from 'react';

export const motionTokens = {
  duration: {
    instant: 120,
    fast: 180,
    base: 280,
    slow: 420,
    cinematic: 720,
  },
  easing: {
    standard: 'cubic-bezier(0.22, 1, 0.36, 1)',
    smooth: 'cubic-bezier(0.4, 0, 0.2, 1)',
    enter: 'cubic-bezier(0.16, 1, 0.3, 1)',
    exit: 'cubic-bezier(0.7, 0, 0.84, 0)',
  },
  spring: {
    soft: { stiffness: 120, damping: 18, mass: 0.9 },
    standard: { stiffness: 150, damping: 22, mass: 1 },
    snappy: { stiffness: 210, damping: 26, mass: 0.95 },
  },
  parallax: {
    sceneTiltDeg: 16,
    cardTiltDeg: 5,
    layerShiftPx: 40,
  },
} as const;

export function useReducedMotionPreference(): boolean {
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }

    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(media.matches);

    const onChange = () => setReduced(media.matches);

    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', onChange);
      return () => media.removeEventListener('change', onChange);
    }

    media.addListener(onChange);
    return () => media.removeListener(onChange);
  }, []);

  return reduced;
}

export function motionDuration(value: keyof typeof motionTokens.duration, reducedMotion: boolean): number {
  const duration = motionTokens.duration[value];
  return reducedMotion ? Math.max(90, Math.round(duration * 0.45)) : duration;
}

export function motionParallax(value: number, reducedMotion: boolean): number {
  if (reducedMotion) {
    return value * 0.3;
  }

  return value;
}