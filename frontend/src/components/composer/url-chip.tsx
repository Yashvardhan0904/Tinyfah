"use client";

import { Globe, CheckCircle, X } from "lucide-react";

interface UrlChipProps {
  url: string;
  onClear?: () => void;
  onClick?: () => void;
}

export function UrlChip({ url, onClear, onClick }: UrlChipProps) {
  return (
    <div
      onClick={onClick}
      className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#ffffff] border border-[#ea7336]/40 text-[#ea7336] text-xs font-mono select-none cursor-pointer hover:bg-[#f5f7fa] transition-all shadow-sm group"
    >
      <Globe className="h-3.5 w-3.5 shrink-0 text-[#ea7336]" />
      <span className="font-medium tracking-tight truncate max-w-sm sm:max-w-md">{url}</span>
      <CheckCircle className="h-3 w-3 shrink-0 text-[#ea7336]/70" />
      {onClear && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onClear();
          }}
          className="ml-1 text-[#5d6b7b] hover:text-[#d9485f] transition-colors"
          title="Remove URL"
        >
          <X className="h-3 w-3" />
        </button>
      )}
    </div>
  );
}
