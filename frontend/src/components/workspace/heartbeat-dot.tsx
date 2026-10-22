"use client";

import { useScanStore } from "@/stores/scan-store";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

export function HeartbeatDot() {
  const heartbeatTimestamp = useScanStore((s) => s.heartbeatTimestamp);
  const streamStatus = useScanStore((s) => s.streamStatus);
  const scanStatus = useScanStore((s) => s.status);
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
  const isCompleted = scanStatus === "completed";
  const isFailed = scanStatus === "failed";

  let label = streamStatus === "closed" ? "IDLE" : streamStatus.toUpperCase();
  let dotColor = "bg-[#5d6b7b]/40";
  let textColor = "text-[#5d6b7b]";
  let borderColor = "border-[#dfe5ec]";
  let bgColor = "bg-[#f5f7fa]";

  if (isCompleted) {
    label = "COMPLETE";
    dotColor = "bg-[#10b981]";
    textColor = "text-[#059669]";
    borderColor = "border-[#a7f3d0]";
    bgColor = "bg-[#ecfdf5]";
  } else if (isFailed) {
    label = "FAILED";
    dotColor = "bg-[#ef4444]";
    textColor = "text-[#dc2626]";
    borderColor = "border-[#fecaca]";
    bgColor = "bg-[#fef2f2]";
  } else if (isConnected) {
    label = "LIVE";
    dotColor = isPulsing ? "bg-[#ea7336]" : "bg-[#ea7336]/60";
    textColor = "text-[#ea7336]";
    borderColor = "border-[#fed7c0]";
    bgColor = "bg-[#fff7ed]";
  } else if (isReconnecting) {
    label = "RECONNECTING";
    dotColor = "bg-[#f59e0b] animate-pulse";
    textColor = "text-[#d97706]";
    borderColor = "border-[#fde68a]";
    bgColor = "bg-[#fffbeb]";
  }

  return (
    <div
      className={cn(
        "flex items-center gap-1.5 px-2 py-1 rounded border text-[11px] font-mono font-medium transition-colors",
        bgColor,
        borderColor,
        textColor
      )}
    >
      <span className="relative flex h-2 w-2">
        {isConnected && isPulsing && (
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#ea7336] opacity-75" />
        )}
        <span
          className={cn(
            "relative inline-flex rounded-full h-2 w-2 transition-colors duration-200",
            dotColor
          )}
        />
      </span>
      <span>{label}</span>
    </div>
  );
}
