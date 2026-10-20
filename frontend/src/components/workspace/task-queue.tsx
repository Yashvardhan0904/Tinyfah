"use client";

import { useScanStore } from "@/stores/scan-store";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { Pane } from "@/components/ui/pane";
import { EmptyState } from "@/components/ui/empty-state";
import { cn } from "@/lib/utils";
import { Wrench, Terminal, CheckCircle2, XCircle, Clock } from "lucide-react";

export function TaskQueue() {
  const agentTrace = useScanStore((s) => s.agentTrace);
  const selectedStepIndex = useScanStore((s) => s.selectedStepIndex);
  const selectStep = useScanStore((s) => s.selectStep);
  const status = useScanStore((s) => s.status);

  const getStatusIcon = (stepStatus: string) => {
    switch (stepStatus) {
      case "completed":
        return <CheckCircle2 className="h-3.5 w-3.5 text-[#18a66b]" />;
      case "failed":
        return <XCircle className="h-3.5 w-3.5 text-[#d9485f]" />;
      case "running":
        return (
          <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#2774c7] opacity-75" />
            <span className="relative inline-flex rounded-full h-3 w-3 bg-[#2774c7]" />
          </span>
        );
      default:
        return <Clock className="h-3.5 w-3.5 text-[#5d6b7b]" />;
    }
  };

  return (
    <Pane
      title={
        <div className="flex items-center gap-2">
          <Terminal className="h-3.5 w-3.5" />
          <span>Task Queue & Trace</span>
        </div>
      }
      headerRight={
        <span className="text-[11px] font-mono text-[#5d6b7b] px-2 py-0.5 rounded bg-[#f7f9fc] border border-[#dfe5ec]">
          {agentTrace.length} steps
        </span>
      }
      className="h-full"
    >
      {agentTrace.length === 0 ? (
        <div className="p-4">
          <EmptyState
            message={
              status === "queued"
                ? "Scan queued... waiting for agent dispatch"
                : "No agent steps recorded yet"
            }
            description="Agent reasoning, actions, and observations will stream here in real-time."
          />
        </div>
      ) : (
        <div className="divide-y divide-[#dfe5ec]">
          {agentTrace.map((step, idx) => {
            const isSelected = selectedStepIndex === idx;
            const isLatest = idx === agentTrace.length - 1 && status === "running";

            return (
              <div
                key={idx}
                onClick={() => selectStep(idx)}
                className={cn(
                  "p-3 cursor-pointer transition-colors text-left select-none relative",
                  isSelected
                    ? "bg-[#f5f7fa] border-l-2 border-l-[#18a66b]"
                    : "hover:bg-[#f5f7fa]/50 border-l-2 border-l-transparent",
                  isLatest && "border-l-[#2774c7] bg-[#2774c7]/5"
                )}
              >
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[11px] font-mono text-[#5d6b7b] font-semibold shrink-0">
                      #{step.step ?? idx + 1}
                    </span>
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-[#f7f9fc] border border-[#dfe5ec] text-[11px] font-mono text-[#6d4aca] truncate">
                      <Wrench className="h-2.5 w-2.5 shrink-0" />
                      <span className="truncate">{step.tool || "agent_action"}</span>
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {getStatusIcon(step.status)}
                    <Chip
                      status={(step.status as ChipStatus) || "pending"}
                      className="text-[10px] py-0 px-1.5"
                    />
                  </div>
                </div>

                <p className="text-xs text-[#15202b] line-clamp-2 leading-relaxed">
                  {step.reason || "Executing task requirement..."}
                </p>

                {step.observation_preview && (
                  <div className="mt-1.5 p-1.5 rounded bg-[#f7f9fc] border border-[#dfe5ec]/70 text-[11px] font-mono text-[#5d6b7b] line-clamp-1 truncate">
                    &gt; {step.observation_preview}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </Pane>
  );
}
