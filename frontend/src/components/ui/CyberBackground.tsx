import { useEffect, useRef } from "react";

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  alpha: number;
}

export function CyberBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrame = 0;
    let width = 0;
    let height = 0;
    let dpr = 1;
    const particles: Particle[] = [];

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const createParticles = () => {
      particles.length = 0;
      const count = window.innerWidth < 640 ? 28 : window.innerWidth < 1024 ? 45 : 70;

      for (let i = 0; i < count; i += 1) {
        particles.push({
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * 0.25,
          vy: (Math.random() - 0.5) * 0.25,
          radius: Math.random() * 1.2 + 0.4,
          alpha: Math.random() * 0.45 + 0.15,
        });
      }
    };

    const drawGrid = () => {
      const spacing = window.innerWidth < 640 ? 34 : 44;
      ctx.strokeStyle = "rgba(34, 211, 238, 0.05)";
      ctx.lineWidth = 1;

      for (let x = 0; x <= width; x += spacing) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }

      for (let y = 0; y <= height; y += spacing) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }
    };

    const drawConnections = () => {
      const maxDistance = window.innerWidth < 640 ? 105 : 135;

      for (let i = 0; i < particles.length; i += 1) {
        for (let j = i + 1; j < particles.length; j += 1) {
          const p1 = particles[i];
          const p2 = particles[j];
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance < maxDistance) {
            const alpha = (1 - distance / maxDistance) * 0.12;
            ctx.strokeStyle = `rgba(34, 211, 238, ${alpha})`;
            ctx.lineWidth = 0.8;
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
          }
        }
      }
    };

    const drawParticles = () => {
      for (const particle of particles) {
        ctx.beginPath();
        ctx.fillStyle = `rgba(34, 211, 238, ${particle.alpha})`;
        ctx.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
        ctx.fill();
      }
    };

    const update = () => {
      for (const particle of particles) {
        particle.x += particle.vx;
        particle.y += particle.vy;

        if (particle.x < -10) particle.x = width + 10;
        if (particle.x > width + 10) particle.x = -10;
        if (particle.y < -10) particle.y = height + 10;
        if (particle.y > height + 10) particle.y = -10;
      }
    };

    const animate = () => {
      ctx.clearRect(0, 0, width, height);
      drawGrid();
      drawConnections();
      drawParticles();
      update();
      animationFrame = requestAnimationFrame(animate);
    };

    resize();
    createParticles();
    animate();

    const handleResize = () => {
      resize();
      createParticles();
    };

    window.addEventListener("resize", handleResize);

    return () => {
      cancelAnimationFrame(animationFrame);
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden" aria-hidden="true">
      <canvas ref={canvasRef} className="absolute inset-0 h-full w-full" />

      <div className="absolute -left-32 top-16 h-72 w-72 rounded-full bg-cyan-400/[0.035] blur-3xl" />
      <div className="absolute right-0 top-1/3 h-96 w-96 rounded-full bg-teal-400/[0.025] blur-3xl" />
      <div className="animate-cyber-scan absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-cyan-400/30 to-transparent" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_20%,rgba(3,7,12,0.42)_100%)]" />
    </div>
  );
}