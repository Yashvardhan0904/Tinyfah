"use client";

import { useScanStore } from "@/stores/scan-store";
import { cn } from "@/lib/utils";
import { Image as ImageIcon, Camera } from "lucide-react";

export function Filmstrip() {
  const agentTrace = useScanStore((s) => s.agentTrace);
  const selectedStepIndex = useScanStore((s) => s.selectedStepIndex);
  const selectStep = useScanStore((s) => s.selectStep);

  // Filter steps that have screenshots
  const stepsWithShots = agentTrace
    .map((step, idx) => ({ ...step, originalIndex: idx }))
    .filter((step) => Boolean(step.screenshot));

  return (
    <div className="flex flex-col bg-[#ffffff] border border-[#dfe5ec] rounded-lg overflow-hidden shrink-0">
      <div className="flex items-center justify-between px-3.5 py-1.5 bg-[#f5f7fa] border-b border-[#dfe5ec]">
        <div className="flex items-center gap-2 text-xs font-mono text-[#5d6b7b]">
          <Camera className="h-3 w-3" />
          <span className="font-semibold uppercase tracking-wider">Snapshot Filmstrip</span>
        </div>
        <span className="text-[10px] font-mono text-[#5d6b7b]">
          {stepsWithShots.length} captured
        </span>
      </div>

      <div className="p-2.5 overflow-x-auto min-h-[90px] flex items-center gap-2.5">
        {stepsWithShots.length === 0 ? (
          <div className="w-full flex items-center justify-center gap-2 text-xs font-mono text-[#5d6b7b]/60 py-4">
            <ImageIcon className="h-3.5 w-3.5" />
            <span>No step screenshots captured yet</span>
          </div>
        ) : (
          stepsWithShots.map((step) => {
            const isSelected = selectedStepIndex === step.originalIndex;
            const imgSrc = step.screenshot?.startsWith("http") || step.screenshot?.startsWith("/")
              ? step.screenshot
              : `/screenshots/${step.screenshot}`;

            return (
              <button
                key={step.originalIndex}
                onClick={() => selectStep(step.originalIndex)}
                className={cn(
                  "group relative shrink-0 flex flex-col rounded border overflow-hidden transition-all text-left",
                  isSelected
                    ? "border-[#18a66b] ring-1 ring-[#18a66b]"
                    : "border-[#dfe5ec] hover:border-[#5d6b7b]"
                )}
              >
                <div className="relative w-28 h-16 bg-[#f7f9fc] overflow-hidden">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={imgSrc}
                    alt={`Step ${step.step ?? step.originalIndex + 1} capture`}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-150"
                    loading="lazy"
                  />
                  <div className="absolute top-1 left-1 px-1 rounded bg-black/80 text-[9px] font-mono text-[#15202b]">
                    #{step.step ?? step.originalIndex + 1}
                  </div>
                </div>
                <div className="px-1.5 py-1 bg-[#f5f7fa] text-[10px] font-mono text-[#5d6b7b] truncate w-28">
                  {step.tool || "action"}
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
