import { useEffect, useRef } from "react";

// Ambient particle canvas adapted from the CyberSec Arsenal HeroBackground:
// drifting emerald dots with constellation links and mouse repulsion.
// Dependency-free, DPR-aware, honours prefers-reduced-motion.
export default function ParticleBackground({ density = 0.6 } = {}) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    let reduced = motionQuery.matches;

    let w = 0, h = 0, raf = 0;
    const DPR = Math.min(window.devicePixelRatio || 1, 2);
    const mouse = { x: 0, y: 0, active: false };
    let particles = [];

    const themeColors = () => {
      const isLight = document.documentElement.getAttribute("data-theme") === "light";
      return isLight ? { dot: "4,120,87", line: "4,120,87" } : { dot: "16,185,129", line: "16,185,129" };
    };
    let palette = themeColors();

    const countFor = () => {
      const area = w * h;
      const base = area < 400 * 600 ? 30 : area < 900 * 600 ? 60 : area < 1440 * 900 ? 95 : 120;
      return Math.round(base * density);
    };

    const spawn = () => {
      const z = 0.25 + Math.random() * 0.75;
      return {
        z,
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.22 * z,
        vy: (Math.random() - 0.5) * 0.22 * z - 0.06 * z,
        r: (0.6 + Math.random() * 1.6) * z + 0.4,
      };
    };

    const resize = () => {
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = w * DPR;
      canvas.height = h * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      particles = Array.from({ length: countFor() }, spawn);
    };

    const step = () => {
      ctx.clearRect(0, 0, w, h);
      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < -20) p.x = w + 20;
        if (p.x > w + 20) p.x = -20;
        if (p.y < -20) p.y = h + 20;
        if (p.y > h + 20) p.y = -20;
        if (mouse.active) {
          const dx = p.x - mouse.x;
          const dy = p.y - mouse.y;
          const dist2 = dx * dx + dy * dy;
          if (dist2 < 120 * 120 && dist2 > 0.01) {
            const dist = Math.sqrt(dist2);
            const force = ((120 - dist) / 120) * 0.35 * p.z;
            p.x += (dx / dist) * force;
            p.y += (dy / dist) * force;
          }
        }
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${palette.dot},${0.14 + 0.3 * p.z})`;
        ctx.fill();
      }
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const a = particles[i];
          const b = particles[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist2 = dx * dx + dy * dy;
          if (dist2 < 110 * 110) {
            const alpha = (1 - Math.sqrt(dist2) / 110) * 0.1 * Math.min(a.z, b.z);
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = `rgba(${palette.line},${alpha})`;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }
      raf = requestAnimationFrame(step);
    };

    const onPointer = (e) => {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
      mouse.active = true;
    };
    const onPointerLeave = () => {
      mouse.active = false;
    };
    const onVisibility = () => {
      if (document.hidden) {
        cancelAnimationFrame(raf);
        raf = 0;
      } else if (!raf && !reduced) {
        raf = requestAnimationFrame(step);
      }
    };
    const onMotionChange = () => {
      reduced = motionQuery.matches;
      if (reduced) {
        cancelAnimationFrame(raf);
        raf = 0;
        ctx.clearRect(0, 0, w, h);
      } else if (!raf) {
        raf = requestAnimationFrame(step);
      }
    };
    const observer = new MutationObserver(() => {
      palette = themeColors();
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", onPointer, { passive: true });
    window.addEventListener("pointerleave", onPointerLeave);
    document.addEventListener("visibilitychange", onVisibility);
    motionQuery.addEventListener?.("change", onMotionChange);
    if (!reduced) raf = requestAnimationFrame(step);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onPointer);
      window.removeEventListener("pointerleave", onPointerLeave);
      document.removeEventListener("visibilitychange", onVisibility);
      motionQuery.removeEventListener?.("change", onMotionChange);
      observer.disconnect();
    };
  }, [density]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 -z-10 h-full w-full"
    />
  );
}
