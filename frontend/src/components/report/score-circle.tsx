"use client";

import { cn } from "@/lib/utils";

interface ScoreCircleProps {
  score: number | null | undefined;
  size?: number;
  strokeWidth?: number;
  className?: string;
}

export function ScoreCircle({
  score,
  size = 120,
  strokeWidth = 8,
  className,
}: ScoreCircleProps) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  const validScore = typeof score === "number" && !isNaN(score) ? Math.min(100, Math.max(0, score)) : null;
  const strokeDashoffset = validScore !== null ? circumference - (validScore / 100) * circumference : circumference;

  let strokeColor = "#5d6b7b";
  let textColor = "#5d6b7b";

  if (validScore !== null) {
    if (validScore >= 80) {
      strokeColor = "#ea7336";
      textColor = "#ea7336";
    } else if (validScore >= 60) {
      strokeColor = "#F5B84B";
      textColor = "#F5B84B";
    } else {
      strokeColor = "#d9485f";
      textColor = "#d9485f";
    }
  }

  return (
    <div
      className={cn("relative flex items-center justify-center shrink-0 select-none", className)}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} className="-rotate-90 transform">
        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#dfe5ec"
          strokeWidth={strokeWidth}
          fill="none"
        />
        {/* Progress */}
        {validScore !== null && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            fill="none"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
          />
        )}
      </svg>
      <div className="absolute flex flex-col items-center justify-center">
        <span
          className="font-mono font-bold tracking-tight"
          style={{ fontSize: size * 0.28, color: textColor }}
        >
          {validScore !== null ? validScore : "—"}
        </span>
        <span className="text-[10px] font-mono uppercase tracking-widest text-[#5d6b7b]">
          Score
        </span>
      </div>
    </div>
  );
}
