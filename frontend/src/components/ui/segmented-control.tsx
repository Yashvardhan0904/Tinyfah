"use client";

import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export interface SegmentOption<T extends string> {
  value: T;
  label: string;
  icon?: ReactNode;
  activeColorClass?: string;
  badge?: string;
}

interface SegmentedControlProps<T extends string> {
  value: T;
  onChange: (val: T) => void;
  options: SegmentOption<T>[];
  className?: string;
}

export function SegmentedControl<T extends string>({
  value,
  onChange,
  options,
  className,
}: SegmentedControlProps<T>) {
  return (
    <div
      className={cn(
        "relative grid grid-cols-2 min-w-[min(100%,31rem)] rounded-xl border border-[#dfe5ec] bg-[#f3f6f9] p-1 select-none",
        className
      )}
      role="tablist"
    >
      <span
        aria-hidden="true"
        className="pointer-events-none absolute bottom-1 top-1 w-[calc(50%-0.25rem)] rounded-lg border border-[#cbd5e1] bg-white shadow-[0_2px_8px_rgba(21,32,43,0.08)] transition-transform duration-300 ease-out"
        style={{ transform: `translateX(${value === options[1]?.value ? "calc(100% + 0.5rem)" : "0"})` }}
      />
      {options.map((option) => {
        const isActive = value === option.value;
        return (
          <button
            key={option.value}
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(option.value)}
            className={cn(
              "relative z-10 flex min-w-0 items-center justify-center gap-2 rounded-lg border border-transparent px-3 py-2 text-xs font-medium transition-colors duration-300 select-none",
              isActive
                ? cn(option.activeColorClass || "text-[#15202b]")
                : "text-[#5d6b7b] hover:text-[#15202b]"
            )}
          >
            {option.icon}
            <span>{option.label}</span>
            {option.badge && (
              <span
                className={cn(
                  "text-[10px] px-1.5 py-0.2 rounded font-mono",
                  isActive
                    ? "bg-[#e8f7ef] text-[#16804f]"
                    : "bg-[#e8edf2] text-[#748294]"
                )}
              >
                {option.badge}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
