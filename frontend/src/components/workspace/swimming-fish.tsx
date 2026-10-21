"use client";

import { useEffect, useRef } from "react";
import { useScanStore } from "@/stores/scan-store";

interface SwimmingFishProps {
  isRunningOverride?: boolean;
  stepCountOverride?: number;
}

export function SwimmingFish({
  isRunningOverride,
  stepCountOverride,
}: SwimmingFishProps) {
  const storeStatus = useScanStore((s) => s.status);
  const storeTrace = useScanStore((s) => s.agentTrace);

  const isRunning =
    isRunningOverride !== undefined ? isRunningOverride : storeStatus === "running";
  const currentStepCount =
    stepCountOverride !== undefined ? stepCountOverride : storeTrace.length;

  const containerRef = useRef<HTMLDivElement>(null);
  const fishRef = useRef<HTMLDivElement>(null);
  const tailRef = useRef<SVGGElement>(null);
  const finRef = useRef<SVGGElement>(null);
  const animIdRef = useRef<number | null>(null);

  const prevCountRef = useRef(currentStepCount);
  const isRunningRef = useRef(isRunning);
  isRunningRef.current = isRunning;

  // Kinematic simulation state
  const simRef = useRef({
    t: Math.random() * 50,
    x: 400,
    y: 800,
    vx: 0,
    vy: 0,
    pitch: 0,
    speed: 1.0,
    targetSpeed: 1.0,
    kick: 0,
    tailPhase: 0,
    facingX: 1,
    targetFacingX: 1,
    boostUntil: 0,
    mode: (isRunning ? "active" : "stopped") as "active" | "diving" | "stopped",
  });

  // Trigger speed burst when new scan/exploit steps arrive
  useEffect(() => {
    if (currentStepCount > prevCountRef.current) {
      prevCountRef.current = currentStepCount;
      const sim = simRef.current;
      sim.kick = 1.0;
      sim.boostUntil = Date.now() + 1400;
    }
  }, [currentStepCount]);

  // Main animation manager
  useEffect(() => {
    let lastTime = performance.now();

    const startLoop = () => {
      if (animIdRef.current !== null) return;

      lastTime = performance.now();
      const loop = (now: number) => {
        const dt = Math.min((now - lastTime) / 1000, 0.08);
        lastTime = now;

        const sim = simRef.current;
        const container = containerRef.current;
        const fish = fishRef.current;

        if (!container || !fish) {
          animIdRef.current = requestAnimationFrame(loop);
          return;
        }

        const cw = container.clientWidth || 1000;
        const ch = container.clientHeight || 700;
        const padX = 145;
        const padY = 85;

        // --- MODE: ACTIVE SWIMMING ---
        if (sim.mode === "active") {
          const isBoosted = now < sim.boostUntil;
          sim.targetSpeed = isBoosted ? 2.5 : 1.35;
          sim.speed += (sim.targetSpeed - sim.speed) * Math.min(1, dt * 2.8);
          if (!isBoosted) {
            sim.kick = Math.max(0, sim.kick - dt * 1.5);
          }

          sim.t += dt * sim.speed * 0.24;

          const cx = cw / 2;
          const cy = ch / 2;
          const rx = Math.max(120, cx - padX);
          const ry = Math.max(80, cy - padY);

          const targetX = cx + rx * (0.76 * Math.sin(sim.t * 0.85) + 0.24 * Math.sin(sim.t * 1.7));
          const targetY = cy + ry * (0.68 * Math.cos(sim.t * 0.65) + 0.32 * Math.sin(sim.t * 1.3));

          // If surfacing from below the viewport, swim upwards into view
          if (sim.y > ch) {
            sim.y += -280 * dt;
            sim.x += (targetX - sim.x) * Math.min(1, dt * 3.5);
            sim.pitch = -22;
            sim.facingX = 1;
            if (sim.y <= targetY) {
              sim.y = targetY;
            }
          } else {
            sim.x = targetX;
            sim.y = targetY;

            const vx = rx * (0.76 * 0.85 * Math.cos(sim.t * 0.85) + 0.24 * 1.7 * Math.cos(sim.t * 1.7));
            const vy = ry * (-0.68 * 0.65 * Math.sin(sim.t * 0.65) + 0.32 * 1.3 * Math.cos(sim.t * 1.3));
            sim.vx = vx;
            sim.vy = vy;

            sim.targetFacingX = vx >= 0 ? 1 : -1;
            sim.facingX += (sim.targetFacingX - sim.facingX) * Math.min(1, dt * 4.5);

            const forwardVx = sim.facingX >= 0 ? vx : -vx;
            const rawPitch = Math.atan2(vy, Math.max(25, Math.abs(forwardVx))) * (180 / Math.PI);
            sim.pitch = Math.max(-20, Math.min(20, rawPitch));
          }

          // Wag tail and fin
          const wagFreq = (5.2 + sim.kick * 7.5) * sim.speed;
          sim.tailPhase += dt * wagFreq;

          if (tailRef.current) {
            const tailAngle = Math.sin(sim.tailPhase) * (15 + sim.kick * 13);
            tailRef.current.style.transform = `rotate(${tailAngle}deg)`;
          }

          if (finRef.current) {
            const finAngle = Math.cos(sim.tailPhase * 0.85) * (12 + sim.kick * 9);
            finRef.current.style.transform = `rotate(${finAngle}deg)`;
          }

          fish.style.transform = `translate3d(${sim.x - 140}px, ${sim.y - 70}px, 0) scale(${sim.facingX}, 1) rotate(${sim.pitch}deg)`;
          animIdRef.current = requestAnimationFrame(loop);
        }

        // --- MODE: DIVING BELOW ON COMPLETION ---
        else if (sim.mode === "diving") {
          // Accelerate downwards into the deep
          sim.vy += (380 - sim.vy) * Math.min(1, dt * 3.5);
          sim.vx *= Math.max(0, 1 - dt * 2.0);

          sim.y += sim.vy * dt;
          sim.x += sim.vx * dt;

          // Pitch snout downwards into graceful dive
          const targetPitch = 32;
          sim.pitch += (targetPitch - sim.pitch) * Math.min(1, dt * 4);

          // Calmer tail beats while submerging
          sim.tailPhase += dt * 4.5;
          if (tailRef.current) {
            const tailAngle = Math.sin(sim.tailPhase) * 8;
            tailRef.current.style.transform = `rotate(${tailAngle}deg)`;
          }
          if (finRef.current) {
            const finAngle = Math.cos(sim.tailPhase * 0.85) * 6;
            finRef.current.style.transform = `rotate(${finAngle}deg)`;
          }

          fish.style.transform = `translate3d(${sim.x - 140}px, ${sim.y - 70}px, 0) scale(${sim.facingX}, 1) rotate(${sim.pitch}deg)`;

          // Once safely below the bottom of the container, stop animations completely
          if (sim.y >= ch + 180) {
            sim.mode = "stopped";
            if (tailRef.current) tailRef.current.style.transform = "rotate(0deg)";
            if (finRef.current) finRef.current.style.transform = "rotate(0deg)";
            animIdRef.current = null;
            return; // Animation halts completely!
          }

          animIdRef.current = requestAnimationFrame(loop);
        }

        // --- MODE: STOPPED ---
        else {
          // Parked below and idle; no loop needed
          animIdRef.current = null;
        }
      };

      animIdRef.current = requestAnimationFrame(loop);
    };

    // React to isRunning state changes
    if (isRunning) {
      if (simRef.current.mode === "stopped" || simRef.current.mode === "diving") {
        simRef.current.mode = "active";
        startLoop();
      } else if (animIdRef.current === null) {
        startLoop();
      }
    } else {
      // Completed or stopped scan
      if (simRef.current.mode === "active") {
        // Was actively swimming: smoothly dive down below
        simRef.current.mode = "diving";
        startLoop();
      } else {
        // Already stopped on load: immediately park below
        simRef.current.mode = "stopped";
        const container = containerRef.current;
        const fish = fishRef.current;
        if (container && fish) {
          const cw = container.clientWidth || 1000;
          const ch = container.clientHeight || 700;
          simRef.current.x = cw / 2;
          simRef.current.y = ch + 220;
          fish.style.transform = `translate3d(${cw / 2 - 140}px, ${ch + 220}px, 0) scale(1, 1) rotate(0deg)`;
          if (tailRef.current) tailRef.current.style.transform = "rotate(0deg)";
          if (finRef.current) finRef.current.style.transform = "rotate(0deg)";
        }
      }
    }

    // Keep parked position calibrated if window is resized
    const handleResize = () => {
      if (simRef.current.mode === "stopped") {
        const container = containerRef.current;
        const fish = fishRef.current;
        if (container && fish) {
          const cw = container.clientWidth || 1000;
          const ch = container.clientHeight || 700;
          simRef.current.x = cw / 2;
          simRef.current.y = ch + 220;
          fish.style.transform = `translate3d(${cw / 2 - 140}px, ${ch + 220}px, 0) scale(1, 1) rotate(0deg)`;
        }
      }
    };
    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
      if (animIdRef.current !== null) {
        cancelAnimationFrame(animIdRef.current);
        animIdRef.current = null;
      }
    };
  }, [isRunning]);

  return (
    <div
      ref={containerRef}
      className="absolute inset-0 pointer-events-none overflow-hidden select-none z-0"
    >
      <style>{`
        /* Soft ambient water ripple expansion */
        @keyframes ripple-pulse {
          0% {
            transform: scale(0.35);
            opacity: 0.35;
          }
          60% {
            opacity: 0.16;
          }
          100% {
            transform: scale(2.4);
            opacity: 0;
          }
        }

        /* Ambient micro-bubble slow float */
        @keyframes ambient-bubble-drift {
          0% {
            transform: translateY(110vh) translateX(0) scale(0.7);
            opacity: 0;
          }
          15% {
            opacity: 0.35;
          }
          75% {
            opacity: 0.25;
          }
          100% {
            transform: translateY(-80px) translateX(24px) scale(1.1);
            opacity: 0;
          }
        }

        /* Mascot snout tiny bubbles */
        @keyframes snout-bubble-float {
          0% {
            transform: translate(0, 0) scale(0.5);
            opacity: 0;
          }
          20% {
            opacity: 0.85;
          }
          100% {
            transform: translate(22px, -32px) scale(1.2);
            opacity: 0;
          }
        }

        .ambient-ripple-1 {
          animation: ripple-pulse 9s cubic-bezier(0.1, 0.4, 0.6, 1) infinite;
          animation-play-state: ${isRunning ? "running" : "paused"};
        }
        .ambient-ripple-2 {
          animation: ripple-pulse 11s cubic-bezier(0.1, 0.4, 0.6, 1) infinite 4.5s;
          animation-play-state: ${isRunning ? "running" : "paused"};
        }
        .ambient-ripple-3 {
          animation: ripple-pulse 10s cubic-bezier(0.1, 0.4, 0.6, 1) infinite 2.2s;
          animation-play-state: ${isRunning ? "running" : "paused"};
        }
      `}</style>

      {/* 1. Clean, minimalist ambient water background (pauses and fades when completed) */}
      <div
        className={`absolute inset-0 pointer-events-none transition-opacity duration-1000 ${
          isRunning ? "opacity-100" : "opacity-0"
        }`}
      >
        {/* Soft atmospheric gradient wash */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_75%_55%_at_50%_-5%,rgba(219,234,254,0.35),transparent_70%)] dark:bg-[radial-gradient(ellipse_75%_55%_at_50%_-5%,rgba(14,165,233,0.06),transparent_70%)]" />

        {/* Subtle Water Ripple 1 (Top Left) */}
        <div className="absolute top-[22%] left-[16%] -translate-x-1/2 -translate-y-1/2 w-80 h-80 flex items-center justify-center opacity-60">
          <div className="absolute w-full h-full rounded-full border border-sky-400/20 dark:border-sky-400/10 ambient-ripple-1" />
          <div className="absolute w-full h-full rounded-full border border-sky-400/15 dark:border-sky-400/10 ambient-ripple-2" />
        </div>

        {/* Subtle Water Ripple 2 (Bottom Right) */}
        <div className="absolute top-[68%] right-[14%] translate-x-1/2 -translate-y-1/2 w-96 h-96 flex items-center justify-center opacity-50">
          <div className="absolute w-full h-full rounded-full border border-blue-400/20 dark:border-blue-400/10 ambient-ripple-2" />
          <div className="absolute w-full h-full rounded-full border border-blue-400/15 dark:border-blue-400/10 ambient-ripple-3" />
        </div>

        {/* Floating Zen Micro-Bubbles */}
        <div
          className="absolute rounded-full border border-sky-400/40 bg-sky-300/10 dark:border-sky-300/20 dark:bg-sky-400/5 w-2 h-2"
          style={{
            left: "12%",
            animation: "ambient-bubble-drift 18s ease-in infinite 1s",
            animationPlayState: isRunning ? "running" : "paused",
          }}
        />
        <div
          className="absolute rounded-full border border-sky-400/35 bg-sky-300/10 dark:border-sky-300/20 dark:bg-sky-400/5 w-3 h-3"
          style={{
            left: "32%",
            animation: "ambient-bubble-drift 22s ease-in infinite 7s",
            animationPlayState: isRunning ? "running" : "paused",
          }}
        />
        <div
          className="absolute rounded-full border border-sky-400/30 bg-sky-300/10 dark:border-sky-300/20 dark:bg-sky-400/5 w-1.5 h-1.5"
          style={{
            left: "54%",
            animation: "ambient-bubble-drift 16s ease-in infinite 3s",
            animationPlayState: isRunning ? "running" : "paused",
          }}
        />
        <div
          className="absolute rounded-full border border-sky-400/35 bg-sky-300/10 dark:border-sky-300/20 dark:bg-sky-400/5 w-2.5 h-2.5"
          style={{
            left: "76%",
            animation: "ambient-bubble-drift 20s ease-in infinite 11s",
            animationPlayState: isRunning ? "running" : "paused",
          }}
        />
        <div
          className="absolute rounded-full border border-sky-400/30 bg-sky-300/10 dark:border-sky-300/20 dark:bg-sky-400/5 w-2 h-2"
          style={{
            left: "88%",
            animation: "ambient-bubble-drift 15s ease-in infinite 5s",
            animationPlayState: isRunning ? "running" : "paused",
          }}
        />
      </div>

      {/* 2. Larger, prominent, sleek fish mascot swimming dynamically */}
      <div
        ref={fishRef}
        className="absolute top-0 left-0 w-[260px] h-[130px] sm:w-[280px] sm:h-[140px] will-change-transform drop-shadow-[0_8px_18px_rgba(15,23,42,0.10)] dark:drop-shadow-[0_8px_22px_rgba(0,0,0,0.5)]"
      >
        <svg
          viewBox="0 0 240 120"
          className="w-full h-full stroke-slate-800 dark:stroke-slate-100 fill-none overflow-visible"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          {/* Animated Tail Fin Group - hinged at rear body (65, 60) */}
          <g
            ref={tailRef}
            style={{ transformOrigin: "65px 60px" }}
            className="transition-transform duration-75"
          >
            {/* Aerodynamic Swallowtail Fin */}
            <path
              d="M 65 60 L 22 34 Q 38 60 22 86 Z"
              strokeWidth="2.6"
              className="fill-white dark:fill-slate-900"
            />
            {/* Interior Fin Ray */}
            <path
              d="M 65 60 L 32 60"
              strokeWidth="1.6"
              className="stroke-slate-400 dark:stroke-slate-600 opacity-60"
            />
          </g>

          {/* Low-profile Hydrodynamic Dorsal Fin */}
          <path
            d="M 105 41 Q 124 26 145 43 Z"
            strokeWidth="2.2"
            className="fill-white dark:fill-slate-900"
          />

          {/* Low-profile Hydrodynamic Ventral Fin */}
          <path
            d="M 108 79 Q 124 93 142 77 Z"
            strokeWidth="2.2"
            className="fill-white dark:fill-slate-900"
          />

          {/* Slim, Streamlined Fish Body */}
          <path
            d="M 65 60 C 85 40, 140 38, 195 60 C 140 82, 85 80, 65 60 Z"
            strokeWidth="2.8"
            className="fill-white dark:fill-slate-900"
          />

          {/* Animated Pectoral Flipper Fin - hinged at (118, 60) */}
          <g
            ref={finRef}
            style={{ transformOrigin: "118px 60px" }}
            className="transition-transform duration-75"
          >
            <path
              d="M 118 60 Q 98 64 88 73 Q 104 67 118 60 Z"
              strokeWidth="2.0"
              className="fill-white dark:fill-slate-900"
            />
          </g>

          {/* Subtle Gill Line */}
          <path
            d="M 158 50 Q 150 60 158 70"
            strokeWidth="1.8"
            className="opacity-40 stroke-slate-500 dark:stroke-slate-400"
          />

          {/* Mascot Friendly Eye */}
          <circle
            cx="174"
            cy="54"
            r="4.2"
            className="fill-slate-800 dark:fill-slate-100 stroke-none"
          />
          {/* Eye Sparkle / Glint */}
          <circle
            cx="175.4"
            cy="52.6"
            r="1.4"
            className="fill-white dark:fill-slate-900 stroke-none"
          />

          {/* Mascot Smile / Snout Mouth */}
          <path
            d="M 193 62 Q 189 64 186 63"
            strokeWidth="1.6"
            className="opacity-70 stroke-slate-800 dark:stroke-slate-100"
          />

          {/* Playful Snout Bubbles when moving actively */}
          {isRunning && (
            <g>
              <circle
                cx="202"
                cy="58"
                r="2.8"
                strokeWidth="1.6"
                className="stroke-sky-400 fill-white dark:fill-slate-900"
                style={{ animation: "snout-bubble-float 1.8s ease-out infinite" }}
              />
              <circle
                cx="208"
                cy="54"
                r="1.8"
                strokeWidth="1.4"
                className="stroke-sky-400 fill-white dark:fill-slate-900"
                style={{ animation: "snout-bubble-float 1.8s ease-out infinite 0.6s" }}
              />
            </g>
          )}
        </svg>
      </div>
    </div>
  );
}
