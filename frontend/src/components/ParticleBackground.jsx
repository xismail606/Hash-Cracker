import { useEffect, useRef } from "react";

// Faithful port of the site HeroBackground (palette from the Hash Cracker
// webpage landing): drifting soft-blue
// particles with twinkling, depth-layered parallax, smooth mouse repulsion,
// constellation links, and a depth glow for the closest particles. Renders a
// static field under prefers-reduced-motion, pauses when the tab is hidden,
// follows the dark/light theme, and is DPR-aware. Dependency-free.

export default function ParticleBackground({ density = 1 } = {}) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    let reduced = motionQuery.matches;

    let w = 0, h = 0, raf = 0, running = true, visible = true;
    const DPR = Math.min(window.devicePixelRatio || 1, 2);

    const mouse = { x: 0, y: 0, tx: 0, ty: 0, active: false };
    let particles = [];

    const themeColors = () => {
      const isLight =
        document.documentElement.getAttribute("data-theme") === "light";
      return isLight
        ? { dot: "77,107,254", line: "77,107,254", glow: 0.9 }
        : { dot: "142,175,255", line: "142,175,255", glow: 0.8 };
    };
    let palette = themeColors();

    const countFor = () => {
      const area = w * h;
      const base =
        area < 400 * 600
          ? 36
          : area < 900 * 600
            ? 70
            : area < 1440 * 900
              ? 110
              : 140;
      return Math.round(base * density);
    };

    const spawn = () => {
      const p = {};
      p.z = 0.25 + Math.random() * 0.75;
      p.x = Math.random() * w;
      p.y = Math.random() * h;
      p.vx = (Math.random() - 0.5) * 0.22 * p.z;
      p.vy = (Math.random() - 0.5) * 0.22 * p.z - 0.06 * p.z;
      p.r = (0.6 + Math.random() * 1.6) * p.z + 0.4;
      p.tw = Math.random() * Math.PI * 2;
      p.twSpeed = 0.008 + Math.random() * 0.02;
      return p;
    };

    const resize = () => {
      w = Math.max(1, window.innerWidth);
      h = Math.max(1, window.innerHeight);
      canvas.width = Math.round(w * DPR);
      canvas.height = Math.round(h * DPR);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);

      const targetCount = countFor();
      if (particles.length < targetCount) {
        for (let i = particles.length; i < targetCount; i++) {
          particles.push(spawn());
        }
      } else if (particles.length > targetCount) {
        particles.length = targetCount;
      }
    };

    const LINK_DIST = 130;
    const LINK_DIST_SQ = LINK_DIST * LINK_DIST;
    const REPEL_RADIUS = 150;
    const REPEL_RADIUS_SQ = REPEL_RADIUS * REPEL_RADIUS;
    const PARALLAX = 16;

    let targetPx = 0, targetPy = 0;
    let curPx = 0, curPy = 0;

    const step = () => {
      if (!running || !visible) {
        raf = 0;
        return;
      }

      // Smooth mouse coordinates and parallax interpolation
      if (mouse.active) {
        mouse.x += (mouse.tx - mouse.x) * 0.1;
        mouse.y += (mouse.ty - mouse.y) * 0.1;
        targetPx = (mouse.x - w / 2) / (w / 2 || 1);
        targetPy = (mouse.y - h / 2) / (h / 2 || 1);
      } else {
        targetPx = 0;
        targetPy = 0;
      }
      curPx += (targetPx - curPx) * 0.05;
      curPy += (targetPy - curPy) * 0.05;

      ctx.clearRect(0, 0, w, h);

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.tw += p.twSpeed;
        p.x += p.vx;
        p.y += p.vy;

        const ox = curPx * PARALLAX * p.z;
        const oy = curPy * PARALLAX * p.z;

        // Mouse repulsion
        if (mouse.active) {
          const dx = p.x + ox - mouse.x;
          const dy = p.y + oy - mouse.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < REPEL_RADIUS_SQ && d2 > 1) {
            const d = Math.sqrt(d2);
            const f = ((REPEL_RADIUS - d) / REPEL_RADIUS) * 1.1 * p.z;
            p.x += (dx / d) * f;
            p.y += (dy / d) * f;
          }
        }

        // Screen wrap
        if (p.x < -20) p.x = w + 20;
        else if (p.x > w + 20) p.x = -20;
        if (p.y < -20) p.y = h + 20;
        else if (p.y > h + 20) p.y = -20;

        p.sx = p.x + ox;
        p.sy = p.y + oy;
      }

      // Constellation links with bounding-box early rejection
      ctx.lineWidth = 1;
      for (let i = 0; i < particles.length; i++) {
        const a = particles[i];
        for (let j = i + 1; j < particles.length; j++) {
          const b = particles[j];
          const dx = a.sx - b.sx;
          if (dx > LINK_DIST || dx < -LINK_DIST) continue;
          const dy = a.sy - b.sy;
          if (dy > LINK_DIST || dy < -LINK_DIST) continue;
          const d2 = dx * dx + dy * dy;
          if (d2 < LINK_DIST_SQ) {
            const alpha =
              (1 - Math.sqrt(d2) / LINK_DIST) * 0.18 * Math.min(a.z, b.z) + 0.02;
            ctx.strokeStyle = `rgba(${palette.line},${alpha.toFixed(3)})`;
            ctx.beginPath();
            ctx.moveTo(a.sx, a.sy);
            ctx.lineTo(b.sx, b.sy);
            ctx.stroke();
          }
        }
      }

      // Particle dots with twinkle + depth glow
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        const twinkle = 0.55 + 0.45 * Math.sin(p.tw);
        const alpha = (0.25 + 0.65 * p.z * twinkle) * palette.glow;
        ctx.fillStyle = `rgba(${palette.dot},${alpha.toFixed(3)})`;
        ctx.beginPath();
        ctx.arc(p.sx, p.sy, p.r, 0, Math.PI * 2);
        ctx.fill();
        if (p.z > 0.82) {
          ctx.fillStyle = `rgba(${palette.dot},${(alpha * 0.12).toFixed(3)})`;
          ctx.beginPath();
          ctx.arc(p.sx, p.sy, p.r * 3.2, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      raf = requestAnimationFrame(step);
    };

    const kick = () => {
      if (!raf && running && visible && !reduced) {
        raf = requestAnimationFrame(step);
      }
    };

    const renderStatic = () => {
      ctx.clearRect(0, 0, w, h);
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        ctx.fillStyle = `rgba(${palette.dot},0.5)`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }
    };

    const onMove = (e) => {
      mouse.tx = e.clientX;
      mouse.ty = e.clientY;
      if (!mouse.active) {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
        mouse.active = true;
      }
    };

    const onLeave = () => {
      mouse.active = false;
    };

    const onVis = () => {
      visible = !document.hidden;
      if (visible) kick();
      else if (raf) {
        cancelAnimationFrame(raf);
        raf = 0;
      }
    };

    const onMotionChange = (e) => {
      reduced = e.matches;
      if (reduced) {
        if (raf) {
          cancelAnimationFrame(raf);
          raf = 0;
        }
        renderStatic();
      } else {
        kick();
      }
    };

    let resizeRaf = 0;
    const onResize = () => {
      if (resizeRaf) cancelAnimationFrame(resizeRaf);
      resizeRaf = requestAnimationFrame(() => {
        resize();
        if (reduced) renderStatic();
      });
    };

    const onTheme = () => {
      palette = themeColors();
      if (reduced) renderStatic();
    };

    const themeObserver = new MutationObserver(onTheme);
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme", "class"],
    });

    motionQuery.addEventListener("change", onMotionChange);
    window.addEventListener("resize", onResize, { passive: true });
    window.addEventListener("pointermove", onMove, { passive: true });
    document.documentElement.addEventListener("pointerleave", onLeave);
    document.addEventListener("visibilitychange", onVis);

    resize();
    if (reduced) {
      renderStatic();
    } else {
      kick();
    }

    return () => {
      running = false;
      if (raf) cancelAnimationFrame(raf);
      if (resizeRaf) cancelAnimationFrame(resizeRaf);
      motionQuery.removeEventListener("change", onMotionChange);
      themeObserver.disconnect();
      window.removeEventListener("resize", onResize);
      window.removeEventListener("pointermove", onMove);
      document.documentElement.removeEventListener("pointerleave", onLeave);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [density]);

  return (
    <div aria-hidden="true" className="site-bg">
      <canvas ref={canvasRef} className="site-particles" />
    </div>
  );
}
