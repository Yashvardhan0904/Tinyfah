"use client";

import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

interface PaneProps {
  children: ReactNode;
  className?: string;
  title?: ReactNode;
  headerRight?: ReactNode;
}

export function Pane({ children, className, title, headerRight }: PaneProps) {
  return (
    <div
      className={cn(
        "flex flex-col h-full bg-[#ffffff] border border-[#dfe5ec] rounded-lg overflow-hidden",
        className
      )}
    >
      {(title || headerRight) && (
        <div className="flex items-center justify-between px-3.5 py-2.5 bg-[#f3f6f9] border-b border-[#dfe5ec] select-none shrink-0">
          <div className="text-xs font-mono font-semibold uppercase tracking-wider text-[#5d6b7b] flex items-center gap-2">
            {title}
          </div>
          {headerRight && <div className="flex items-center gap-2">{headerRight}</div>}
        </div>
      )}
      <div className="flex-1 min-h-0 overflow-auto">{children}</div>
    </div>
  );
}
