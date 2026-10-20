"use client";

import { useScanStore } from "@/stores/scan-store";
import { useUIStore } from "@/stores/ui-store";
import { Pane } from "@/components/ui/pane";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { EmptyState } from "@/components/ui/empty-state";
import { Wrench, Code2, Eye, Image as ImageIcon, ExternalLink } from "lucide-react";

export function StepInspector() {
  const agentTrace = useScanStore((s) => s.agentTrace);
  const selectedStepIndex = useScanStore((s) => s.selectedStepIndex);
  const showRawJSON = useUIStore((s) => s.showRawJSON);
  const toggleRawJSON = useUIStore((s) => s.toggleRawJSON);

  const currentStep =
    selectedStepIndex !== null && agentTrace[selectedStepIndex]
      ? agentTrace[selectedStepIndex]
      : null;

  if (!currentStep) {
    return (
      <Pane
        title={
          <div className="flex items-center gap-2">
            <Eye className="h-3.5 w-3.5" />
            <span>Step Inspector</span>
          </div>
        }
        className="h-full"
      >
        <div className="p-6">
          <EmptyState
            message="No step selected"
            description="Select any action in the task queue or filmstrip to inspect parameters, observations, and captures."
          />
        </div>
      </Pane>
    );
  }

  const imgSrc = currentStep.screenshot?.startsWith("http") || currentStep.screenshot?.startsWith("/")
    ? currentStep.screenshot
    : currentStep.screenshot
    ? `/screenshots/${currentStep.screenshot}`
    : null;

  return (
    <Pane
      title={
        <div className="flex items-center gap-2">
          <Eye className="h-3.5 w-3.5 text-[#18a66b]" />
          <span>Step #{currentStep.step ?? (selectedStepIndex! + 1)} Inspector</span>
        </div>
      }
      headerRight={
        <button
          onClick={toggleRawJSON}
          className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#f7f9fc] border border-[#dfe5ec] text-[11px] font-mono text-[#5d6b7b] hover:text-[#15202b] transition-colors"
        >
          <Code2 className="h-3 w-3" />
          <span>{showRawJSON ? "Form View" : "Raw JSON"}</span>
        </button>
      }
      className="h-full"
    >
      <div className="p-4 space-y-4">
        {/* Status header */}
        <div className="flex items-center justify-between pb-3 border-b border-[#dfe5ec]">
          <div className="flex items-center gap-2">
            <Wrench className="h-4 w-4 text-[#6d4aca]" />
            <span className="font-mono text-xs font-semibold text-[#15202b]">
              {currentStep.tool || "action"}
            </span>
          </div>
          <Chip status={(currentStep.status as ChipStatus) || "pending"} dot />
        </div>

        {showRawJSON ? (
          <div className="rounded-lg bg-[#f7f9fc] border border-[#dfe5ec] p-3 overflow-x-auto text-xs font-mono text-[#18a66b]">
            <pre>{JSON.stringify(currentStep, null, 2)}</pre>
          </div>
        ) : (
          <>
            {/* Step Purpose / Reason */}
            <div>
              <div className="text-[11px] font-mono uppercase tracking-wider text-[#5d6b7b] mb-1">
                Reason & Objective
              </div>
              <div className="p-3 rounded-lg bg-[#f5f7fa] border border-[#dfe5ec] text-xs text-[#15202b] leading-relaxed">
                {currentStep.reason || (
                  <span className="text-[#5d6b7b] italic">Not reported by TinyFish</span>
                )}
              </div>
            </div>

            {/* Observation Preview */}
            <div>
              <div className="text-[11px] font-mono uppercase tracking-wider text-[#5d6b7b] mb-1">
                Agent Observation
              </div>
              <div className="p-3 rounded-lg bg-[#f7f9fc] border border-[#dfe5ec] text-xs font-mono text-[#5d6b7b] whitespace-pre-wrap leading-relaxed max-h-48 overflow-y-auto">
                {currentStep.observation_preview || (
                  <span className="italic text-[#5d6b7b]/60">
                    Not reported by TinyFish
                  </span>
                )}
              </div>
            </div>

            {/* Full Screenshot Preview */}
            <div>
              <div className="flex items-center justify-between text-[11px] font-mono uppercase tracking-wider text-[#5d6b7b] mb-1">
                <span className="flex items-center gap-1.5">
                  <ImageIcon className="h-3 w-3" />
                  <span>Captured Frame</span>
                </span>
                {imgSrc && (
                  <a
                    href={imgSrc}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-[#18a66b] hover:underline"
                  >
                    <span>Full Resolution</span>
                    <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                )}
              </div>

              {imgSrc ? (
                <div className="rounded-lg border border-[#dfe5ec] overflow-hidden bg-[#f7f9fc]">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={imgSrc}
                    alt={`Screenshot for step ${currentStep.step ?? selectedStepIndex! + 1}`}
                    className="w-full h-auto object-contain max-h-80"
                  />
                </div>
              ) : (
                <div className="p-6 rounded-lg bg-[#f5f7fa] border border-[#dfe5ec] text-center">
                  <span className="text-xs font-mono text-[#5d6b7b] italic">
                    Not reported by TinyFish
                  </span>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </Pane>
  );
}
