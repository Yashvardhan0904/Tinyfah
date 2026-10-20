"use client";

import { useScanStore } from "@/stores/scan-store";
import { Drawer } from "@/components/ui/drawer";
import { Copy, Check } from "lucide-react";
import { useState } from "react";

export function EventLog() {
  const rawLogs = useScanStore((s) => s.rawLogs);
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(rawLogs.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Drawer
      title="Raw SSE Audit Log"
      badge={
        <span className="px-1.5 py-0.2 rounded bg-[#f7f9fc] border border-[#dfe5ec] text-[10px] text-[#5d6b7b]">
          {rawLogs.length} events
        </span>
      }
      actions={
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 px-2 py-0.5 rounded bg-[#f7f9fc] border border-[#dfe5ec] text-[11px] font-mono text-[#5d6b7b] hover:text-[#15202b] transition-colors"
        >
          {copied ? (
            <>
              <Check className="h-3 w-3 text-[#18a66b]" />
              <span className="text-[#18a66b]">Copied</span>
            </>
          ) : (
            <>
              <Copy className="h-3 w-3" />
              <span>Copy All</span>
            </>
          )}
        </button>
      }
    >
      {rawLogs.length === 0 ? (
        <div className="flex items-center justify-center p-8 text-xs text-[#5d6b7b] italic">
          No raw SSE chunks recorded yet. Stream logs will append here unparsed.
        </div>
      ) : (
        <div className="space-y-1 font-mono text-[11px] leading-relaxed">
          {rawLogs.map((log, idx) => (
            <div
              key={idx}
              className="px-2 py-1 rounded hover:bg-[#f5f7fa] transition-colors whitespace-pre-wrap break-all text-[#5d6b7b] selection:bg-[#18a66b]/20"
            >
              <span className="text-[#18a66b]/80 select-none mr-2">
                [{rawLogs.length - idx}]
              </span>
              <span>{log}</span>
            </div>
          ))}
        </div>
      )}
    </Drawer>
  );
}
