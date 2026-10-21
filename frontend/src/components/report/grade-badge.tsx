"use client";

import { cn } from "@/lib/utils";
import type { Grade } from "@/lib/types";

interface GradeBadgeProps {
  grade: Grade | string | null | undefined;
  className?: string;
  size?: "sm" | "md" | "lg";
}

export function GradeBadge({
  grade,
  className,
  size = "md",
}: GradeBadgeProps) {
  const normGrade = (grade || "NOT_ASSESSED").toUpperCase();

  const gradeColors: Record<string, { bg: string; text: string; border: string }> = {
    A: { bg: "bg-[#ea7336]/15", text: "text-[#ea7336]", border: "border-[#ea7336]/40" },
    B: { bg: "bg-[#ea7336]/10", text: "text-[#ea7336]", border: "border-[#ea7336]/30" },
    C: { bg: "bg-[#F5B84B]/15", text: "text-[#F5B84B]", border: "border-[#F5B84B]/40" },
    D: { bg: "bg-[#d9485f]/10", text: "text-[#d9485f]", border: "border-[#d9485f]/30" },
    F: { bg: "bg-[#d9485f]/20", text: "text-[#d9485f]", border: "border-[#d9485f]/50" },
    NOT_ASSESSED: { bg: "bg-[#f5f7fa]", text: "text-[#5d6b7b]", border: "border-[#dfe5ec]" },
  };

  const style = gradeColors[normGrade] || gradeColors.NOT_ASSESSED;

  const sizeStyles = {
    sm: "px-2 py-0.5 text-xs font-mono",
    md: "px-3 py-1 text-sm font-mono font-bold",
    lg: "px-4 py-2 text-xl font-mono font-extrabold",
  };

  return (
    <div
      className={cn(
        "inline-flex items-center justify-center rounded-lg border font-mono select-none tracking-wider",
        style.bg,
        style.text,
        style.border,
        sizeStyles[size],
        className
      )}
    >
      {normGrade === "NOT_ASSESSED" ? "NOT ASSESSED" : `GRADE ${normGrade}`}
    </div>
  );
}
