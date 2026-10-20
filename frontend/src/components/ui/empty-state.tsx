"use client";

import { cn } from "@/lib/utils";
import { AlertCircle } from "lucide-react";
import type { ReactNode } from "react";

interface EmptyStateProps {
  message?: string;
  description?: string;
  icon?: ReactNode;
  className?: string;
}

export function EmptyState({
  message = "Not reported by TinyFish",
  description,
  icon,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center p-8 text-center text-gray-400",
        className
      )}
    >
      <div className="mb-2 text-[#5d6b7b]/60">
        {icon || <AlertCircle className="h-6 w-6 stroke-[1.5]" />}
      </div>
      <div className="text-xs font-mono font-medium text-[#5d6b7b]">{message}</div>
      {description && (
        <div className="text-[11px] text-[#5d6b7b]/70 max-w-xs mt-1">
          {description}
        </div>
      )}
    </div>
  );
}
