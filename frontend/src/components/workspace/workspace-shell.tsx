"use client";

import { useScanStore } from "@/stores/scan-store";
import { useUIStore } from "@/stores/ui-store";
import { TaskQueue } from "./task-queue";

import { Filmstrip } from "./filmstrip";
import { StepInspector } from "./step-inspector";
import { EventLog } from "./event-log";
import { StreamBanner } from "./stream-banner";
import { HeartbeatDot } from "./heartbeat-dot";
import { ElapsedTimer } from "./elapsed-timer";
import { StopButton } from "./stop-button";
import { MobileTabs } from "./mobile-tabs";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { Button } from "@/components/ui/button";
import Link from "next/link";
import { Shield, ArrowLeft, FileText } from "lucide-react";

export function WorkspaceShell() {
  const scanId = useScanStore((s) => s.scanId);
  const url = useScanStore((s) => s.url);
  const status = useScanStore((s) => s.status);
  const grade = useScanStore((s) => s.grade);
  const score = useScanStore((s) => s.score);
  const activeMobileTab = useUIStore((s) => s.activeMobileTab);

  const isTerminal =
    status === "completed" || status === "failed" || status === "not_assessed";

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#f7f9fc] text-[#15202b]">
      {/* Top Workspace Header */}
      <header className="flex items-center justify-between px-4 py-2.5 bg-[#ffffff] shrink-0 select-none">
        <div className="flex items-center gap-3 min-w-0">
          <Link
            href="/"
            className="flex items-center gap-1.5 text-xs font-mono text-[#5d6b7b] hover:text-[#15202b] transition-colors shrink-0"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Composer</span>
          </Link>


          <div className="flex items-center gap-2 min-w-0">
            <div className="flex items-center gap-1.5 font-bold text-xs tracking-tight text-[#ea7336] shrink-0">
              <Shield className="h-4 w-4" />
              <span className="hidden md:inline">TINYFAH</span>
            </div>

            {/* Target URL chip */}
            <div className="px-2.5 py-1 rounded bg-[#f5f7fa] text-xs font-mono text-[#15202b] truncate max-w-[200px] sm:max-w-xs md:max-w-md">
              {url || "Initializing..."}
            </div>

            <Chip status={(status as ChipStatus) || "running"} dot />

            {grade && (
              <span className="hidden sm:inline-block px-2 py-0.5 rounded bg-[#f5f7fa] text-xs font-mono font-bold text-[#ea7336]">
                GRADE {grade}
              </span>
            )}

            {score !== null && score !== undefined && (
              <span className="hidden sm:inline-block px-2 py-0.5 rounded bg-[#f5f7fa] text-xs font-mono text-[#15202b]">
                {score}/100
              </span>
            )}
          </div>
        </div>

        {/* Right Header Telemetry & Actions */}
        <div className="flex items-center gap-2.5 shrink-0">
          <HeartbeatDot />
          <ElapsedTimer />

          {isTerminal ? (
            <Link href={`/scan/${scanId}/report`}>
              <Button variant="primary" size="sm" className="gap-1.5">
                <FileText className="h-3.5 w-3.5" />
                <span>Security Report</span>
              </Button>
            </Link>
          ) : (
            <StopButton />
          )}
        </div>
      </header>

      {/* Reconnecting / Warning Stream Banner */}
      <StreamBanner />

      {/* Desktop 2-Pane Body (Hidden on mobile) */}
      <main className="hidden lg:flex flex-col gap-3 p-3 flex-1 min-h-0 overflow-hidden bg-[#f7f9fc]">
        {/* Main Row: Task Queue + Step Inspector */}
        <div className="grid grid-cols-12 gap-3 flex-1 min-h-0">
          {/* Left Pane: Task Queue */}
          <div className="col-span-5 h-full min-h-0">
            <TaskQueue />
          </div>

          {/* Right Pane: Step Inspector */}
          <div className="col-span-7 h-full min-h-0">
            <StepInspector />
          </div>
        </div>

        {/* Bottom: Filmstrip */}
        <Filmstrip />
      </main>

      {/* Mobile Tabbed View (Visible on < lg) */}
      <main className="lg:hidden flex-1 min-h-0 overflow-hidden p-2">
        {activeMobileTab === "tasks" && <TaskQueue />}
        {activeMobileTab === "live" && <Filmstrip />}
        {activeMobileTab === "steps" && <StepInspector />}
        {activeMobileTab === "log" && (
          <div className="h-full bg-[#ffffff] border border-[#dfe5ec] rounded-lg p-3">
            <EventLog />
          </div>
        )}
      </main>

      {/* Mobile Bottom Tabs */}
      <MobileTabs />

      {/* Desktop Bottom Drawer: Raw SSE Log */}
      <div className="hidden lg:block shrink-0">
        <EventLog />
      </div>
    </div>
  );
}
