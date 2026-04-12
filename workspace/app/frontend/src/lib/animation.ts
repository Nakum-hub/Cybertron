import { useEffect, useRef, useState, useCallback } from 'react';

// Intersection Observer hook for scroll-triggered animations
export function useInView(threshold = 0.1, rootMargin = '0px') {
  const ref = useRef<HTMLDivElement>(null);
  const [isInView, setIsInView] = useState(false);

  useEffect(() => {
    const element = ref.current;
    if (!element) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsInView(true);
          observer.unobserve(element);
        }
      },
      { threshold, rootMargin }
    );

    observer.observe(element);
    return () => observer.disconnect();
  }, [threshold, rootMargin]);

  return { ref, isInView };
}

// Staggered animation for children
export function useStaggeredAnimation(itemCount: number, delay = 150) {
  const { ref, isInView } = useInView(0.1);
  const [visibleItems, setVisibleItems] = useState<boolean[]>(
    new Array(itemCount).fill(false)
  );

  useEffect(() => {
    if (!isInView) return;
    const timers: NodeJS.Timeout[] = [];
    for (let i = 0; i < itemCount; i++) {
      timers.push(
        setTimeout(() => {
          setVisibleItems((prev) => {
            const next = [...prev];
            next[i] = true;
            return next;
          });
        }, i * delay)
      );
    }
    return () => timers.forEach(clearTimeout);
  }, [isInView, itemCount, delay]);

  return { ref, visibleItems };
}

// Animated counter hook
export function useAnimatedCounter(
  end: number,
  duration = 2000,
  startOnView = true
) {
  const [count, setCount] = useState(0);
  const { ref, isInView } = useInView(0.2);
  const hasAnimated = useRef(false);

  useEffect(() => {
    if (startOnView && !isInView) return;
    if (hasAnimated.current) return;
    hasAnimated.current = true;

    const startTime = Date.now();
    const timer = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      setCount(Math.floor(eased * end));
      if (progress >= 1) clearInterval(timer);
    }, 16);

    return () => clearInterval(timer);
  }, [end, duration, isInView, startOnView]);

  return { ref, count };
}

// Mouse parallax effect
export function useMouseParallax(intensity = 0.02) {
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const targetRef = useRef({ x: 0, y: 0 });
  const currentRef = useRef({ x: 0, y: 0 });
  const frameRef = useRef<number | null>(null);
  const lastCommitRef = useRef(0);

  const onPointerMove = useCallback(
    (event: PointerEvent) => {
      targetRef.current.x = (event.clientX - window.innerWidth / 2) * intensity;
      targetRef.current.y = (event.clientY - window.innerHeight / 2) * intensity;
    },
    [intensity]
  );

  useEffect(() => {
    let active = true;

    const animate = () => {
      if (!active) {
        return;
      }

      const current = currentRef.current;
      const target = targetRef.current;
      const smoothing = 0.16;

      current.x += (target.x - current.x) * smoothing;
      current.y += (target.y - current.y) * smoothing;

      const x = Number(current.x.toFixed(3));
      const y = Number(current.y.toFixed(3));
      const now = performance.now();

      setOffset(prev => {
        const changedEnough = Math.abs(prev.x - x) >= 0.01 || Math.abs(prev.y - y) >= 0.01;
        const elapsed = now - lastCommitRef.current;
        if (!changedEnough || elapsed < 32) {
          return prev;
        }

        lastCommitRef.current = now;
        return { x, y };
      });

      frameRef.current = window.requestAnimationFrame(animate);
    };

    const reset = () => {
      targetRef.current = { x: 0, y: 0 };
    };

    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        return;
      }

      targetRef.current = { x: 0, y: 0 };
      currentRef.current = { x: 0, y: 0 };
      lastCommitRef.current = 0;
      setOffset({ x: 0, y: 0 });
    };

    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('pointerleave', reset);
    document.addEventListener('visibilitychange', onVisibility);

    frameRef.current = window.requestAnimationFrame(animate);

    return () => {
      active = false;
      if (frameRef.current) {
        cancelAnimationFrame(frameRef.current);
      }

      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerleave', reset);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [onPointerMove]);

  return offset;
}

// Typing animation hook
export function useTypingEffect(text: string, speed = 50, startDelay = 500) {
  const [displayText, setDisplayText] = useState('');
  const { ref, isInView } = useInView(0.3);
  const hasStarted = useRef(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!isInView || hasStarted.current) return;
    hasStarted.current = true;

    let index = 0;
    const startTimer = setTimeout(() => {
      intervalRef.current = setInterval(() => {
        if (index < text.length) {
          setDisplayText(text.slice(0, index + 1));
          index++;
        } else {
          if (intervalRef.current) clearInterval(intervalRef.current);
          intervalRef.current = null;
        }
      }, speed);
    }, startDelay);

    return () => {
      clearTimeout(startTimer);
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [isInView, text, speed, startDelay]);

  return { ref, displayText };
}

// Generate random particles for background effects
export function generateParticles(count: number) {
  return Array.from({ length: count }, (_, i) => ({
    id: i,
    x: Math.random() * 100,
    y: Math.random() * 100,
    size: Math.random() * 3 + 1,
    duration: Math.random() * 3 + 2,
    delay: Math.random() * 2,
    opacity: Math.random() * 0.5 + 0.1,
  }));
}

