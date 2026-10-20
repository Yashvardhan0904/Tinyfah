"use client";

import { cn } from "@/lib/utils";
import { useState, type ReactNode } from "react";
import { ChevronUp, ChevronDown } from "lucide-react";

interface DrawerProps {
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
  className?: string;
  badge?: ReactNode;
  actions?: ReactNode;
}

export function Drawer({
  title,
  children,
  defaultOpen = false,
  className,
  badge,
  actions,
}: DrawerProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div
      className={cn(
        "border-t border-[#dfe5ec] bg-[#ffffff] flex flex-col transition-all",
        className
      )}
    >
      <div className="flex items-center justify-between px-4 py-2 bg-[#f5f7fa] border-b border-[#dfe5ec]/60 select-none">
        <button
          onClick={() => setOpen(!open)}
          className="flex items-center gap-2.5 text-xs font-mono font-medium text-[#5d6b7b] hover:text-[#15202b] transition-colors"
          aria-expanded={open}
        >
          {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronUp className="h-3.5 w-3.5" />}
          <span>{title}</span>
          {badge}
        </button>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
      {open && (
        <div className="h-56 overflow-y-auto bg-[#f7f9fc] border-t border-[#dfe5ec] p-2 text-xs font-mono">
          {children}
        </div>
      )}
    </div>
  );
}
