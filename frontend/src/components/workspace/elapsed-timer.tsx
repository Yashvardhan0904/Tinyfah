"use client";

import { useScanStore } from "@/stores/scan-store";
import { formatElapsed } from "@/lib/utils";
import { useEffect, useState } from "react";
import { Clock } from "lucide-react";

export function ElapsedTimer() {
  const startTime = useScanStore((s) => s.startTime);
  const endTime = useScanStore((s) => s.endTime);
  const status = useScanStore((s) => s.status);
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    if (!startTime) return;

    const interval = setInterval(() => {
      const finalEnd = endTime || (status === "completed" || status === "failed" || status === "not_assessed" ? Date.now() : null);
      const now = finalEnd || Date.now();
      setSeconds(Math.max(0, Math.floor((now - startTime) / 1000)));
    }, 1000);

    return () => clearInterval(interval);
  }, [startTime, endTime, status]);

  return (
    <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#f5f7fa] border border-[#dfe5ec] text-[11px] font-mono text-[#15202b]">
      <Clock className="h-3 w-3 text-[#5d6b7b]" />
      <span>{formatElapsed(seconds)}</span>
    </div>
  );
}
