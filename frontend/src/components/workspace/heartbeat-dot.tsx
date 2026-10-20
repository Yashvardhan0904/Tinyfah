"use client";

import { useScanStore } from "@/stores/scan-store";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

export function HeartbeatDot() {
  const heartbeatTimestamp = useScanStore((s) => s.heartbeatTimestamp);
  const streamStatus = useScanStore((s) => s.streamStatus);
  const [isPulsing, setIsPulsing] = useState(false);

  useEffect(() => {
    if (!heartbeatTimestamp) return;

    // Use rAF to avoid calling setState synchronously in the effect setup
    const rafId = requestAnimationFrame(() => {
      setIsPulsing(true);
    });

    const timer = setTimeout(() => {
      setIsPulsing(false);
    }, 600);

    return () => {
      cancelAnimationFrame(rafId);
      clearTimeout(timer);
    };
  }, [heartbeatTimestamp]);

  const isConnected = streamStatus === "connected";
  const isReconnecting = streamStatus === "reconnecting";

  return (
    <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#f5f7fa] border border-[#dfe5ec] text-[11px] font-mono text-[#5d6b7b]">
      <span className="relative flex h-2 w-2">
        {isConnected && isPulsing && (
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#18a66b] opacity-75" />
        )}
        <span
          className={cn(
            "relative inline-flex rounded-full h-2 w-2 transition-colors duration-200",
            isConnected
              ? isPulsing
                ? "bg-[#18a66b]"
                : "bg-[#18a66b]/60"
              : isReconnecting
              ? "bg-[#F5B84B] animate-pulse"
              : "bg-[#5d6b7b]/40"
          )}
        />
      </span>
      <span>
        {isConnected
          ? "LIVE"
          : isReconnecting
          ? "RECONNECTING"
          : streamStatus.toUpperCase()}
      </span>
    </div>
  );
}
