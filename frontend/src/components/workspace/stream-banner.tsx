"use client";

import { useScanStore } from "@/stores/scan-store";
import { AlertTriangle, RefreshCw } from "lucide-react";

export function StreamBanner() {
  const streamStatus = useScanStore((s) => s.streamStatus);
  const scanId = useScanStore((s) => s.scanId);
  const connectToStream = useScanStore((s) => s.connectToStream);

  if (streamStatus !== "reconnecting" && streamStatus !== "error") {
    return null;
  }

  return (
    <div className="flex items-center justify-between px-4 py-2 bg-[#F5B84B]/15 border-b border-[#F5B84B]/30 text-xs font-mono text-[#F5B84B]">
      <div className="flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>
          {streamStatus === "reconnecting"
            ? "Stream disconnected. EventSource attempting automatic reconnection..."
            : "Live telemetry stream lost. Verify backend is running on port 8000."}
        </span>
      </div>
      {scanId && (
        <button
          onClick={() => connectToStream(scanId)}
          className="flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-[#F5B84B]/20 hover:bg-[#F5B84B]/30 text-[#F5B84B] border border-[#F5B84B]/40 transition-colors"
        >
          <RefreshCw className="h-3 w-3" />
          <span>Retry Stream</span>
        </button>
      )}
    </div>
  );
}
