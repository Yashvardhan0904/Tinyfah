"use client";

import { useScanStore } from "@/stores/scan-store";
import { Monitor, ExternalLink } from "lucide-react";
import { useState } from "react";

export function LiveView() {
  const browserSession = useScanStore((s) => s.browserSession);
  const status = useScanStore((s) => s.status);
  const [iframeLoaded, setIframeLoaded] = useState(false);

  const liveUrl = browserSession?.live_view_url;
  const isRunning = status === "running" || status === "queued";

  return (
    <div className="flex flex-col h-full bg-[#f7f9fc] border border-[#dfe5ec] rounded-lg overflow-hidden">
      {/* Live View Bar */}
      <div className="flex items-center justify-between px-3.5 py-2 bg-[#f5f7fa] border-b border-[#dfe5ec] select-none shrink-0">
        <div className="flex items-center gap-2 text-xs font-mono text-[#5d6b7b]">
          <Monitor className="h-3.5 w-3.5 text-[#2774c7]" />
          <span className="font-semibold uppercase tracking-wider text-[#15202b]">
            Browser Session
          </span>
          {browserSession?.session_id && (
            <span className="text-[10px] text-[#5d6b7b] px-1.5 py-0.2 rounded bg-[#f7f9fc] border border-[#dfe5ec]">
              id: {browserSession.session_id.slice(0, 8)}...
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {liveUrl && (
            <a
              href={liveUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-[11px] font-mono text-[#5d6b7b] hover:text-[#ea7336] transition-colors"
            >
              <span>Popout</span>
              <ExternalLink className="h-3 w-3" />
            </a>
          )}
        </div>
      </div>

      {/* Frame Container */}
      <div className="relative flex-1 min-h-[300px] w-full bg-[#f7f9fc] flex items-center justify-center overflow-hidden">
        {liveUrl ? (
          <>
            <iframe
              src={liveUrl}
              title="TinyFish Browser Live Stream"
              className="w-full h-full border-0"
              allow="camera; microphone; display-capture"
              onLoad={() => setIframeLoaded(true)}
            />
            {!iframeLoaded && (
              <div className="absolute inset-0 flex flex-col items-center justify-center bg-[#f7f9fc] text-[#5d6b7b] gap-2">
                <div className="h-4 w-4 border-2 border-[#2774c7] border-t-transparent rounded-full animate-spin" />
                <span className="text-xs font-mono">Connecting to TinyFish WebRTC stream...</span>
              </div>
            )}
          </>
        ) : (
          <div className="flex flex-col items-center justify-center text-center p-8 max-w-sm">
            <div className="p-3 rounded-full bg-[#f5f7fa] border border-[#dfe5ec] mb-3 text-[#5d6b7b]">
              <Monitor className="h-6 w-6 stroke-[1.5]" />
            </div>
            <h4 className="text-sm font-semibold text-[#15202b] mb-1">
              Live view unavailable — local browser session
            </h4>
            <p className="text-xs text-[#5d6b7b] leading-relaxed">
              {isRunning
                ? "The browser is executing via headless Playwright automation. Real-time screenshots are streamed to the filmstrip below."
                : "The scan has concluded. Browse individual step captures in the filmstrip or review the final security report."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
