"use client";

import { useScanStore } from "@/stores/scan-store";
import { useUIStore } from "@/stores/ui-store";
import { Button } from "@/components/ui/button";
import { Square, AlertCircle, X } from "lucide-react";

export function StopButton() {
  const status = useScanStore((s) => s.status);
  const abortScanGracefully = useScanStore((s) => s.abortScanGracefully);
  const showStopDialog = useUIStore((s) => s.showStopDialog);
  const setShowStopDialog = useUIStore((s) => s.setShowStopDialog);

  const isTerminal =
    status === "completed" || status === "failed" || status === "not_assessed";

  if (isTerminal) {
    return null;
  }

  const handleConfirmAbort = () => {
    abortScanGracefully();
    setShowStopDialog(false);
  };

  return (
    <>
      <Button
        variant="danger"
        size="sm"
        onClick={() => setShowStopDialog(true)}
        className="gap-1.5"
      >
        <Square className="h-3 w-3 fill-current" />
        <span>Stop</span>
      </Button>

      {showStopDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80">
          <div className="w-full max-w-md bg-[#ffffff] border border-[#dfe5ec] rounded-lg p-5 shadow-2xl flex flex-col gap-4">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2.5 text-sm font-semibold text-[#d9485f]">
                <AlertCircle className="h-5 w-5" />
                <span>Stop Live Stream</span>
              </div>
              <button
                onClick={() => setShowStopDialog(false)}
                className="text-[#5d6b7b] hover:text-[#15202b]"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="text-xs text-[#5d6b7b] leading-relaxed space-y-2">
              <p>
                Disconnecting will close your live SSE telemetry feed immediately.
              </p>
              <p className="bg-[#f5f7fa] border border-[#dfe5ec] p-2.5 rounded text-[11px] font-mono text-[#15202b]">
                Notice: The backend test execution continues autonomously until completion or safety timeout. Completed results will remain safely accessible in History.
              </p>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#dfe5ec]">
              <Button
                variant="neutral"
                size="sm"
                onClick={() => setShowStopDialog(false)}
              >
                Keep Running
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleConfirmAbort}
              >
                Disconnect Feed
              </Button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
