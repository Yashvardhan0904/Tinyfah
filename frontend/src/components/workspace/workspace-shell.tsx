"use client";

import { useScanStore } from "@/stores/scan-store";
import { StreamBanner } from "./stream-banner";
import { HeartbeatDot } from "./heartbeat-dot";
import { ElapsedTimer } from "./elapsed-timer";
import { StopButton } from "./stop-button";
import { ChatTaskFeed } from "./chat-task-feed";
import { TargetWebsiteBar } from "./target-website-bar";
import { SwimmingFish } from "./swimming-fish";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { Button } from "@/components/ui/button";
import Link from "next/link";
import { Shield, ArrowLeft, FileText, Flame } from "lucide-react";

export function WorkspaceShell() {
  const scanId = useScanStore((s) => s.scanId);
  const url = useScanStore((s) => s.url);
  const status = useScanStore((s) => s.status);
  const grade = useScanStore((s) => s.grade);
  const score = useScanStore((s) => s.score);

  const isTerminal =
    status === "completed" || status === "failed" || status === "not_assessed";

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#f7f9fc] text-[#15202b]">
      {/* Top Workspace Header: Kept exactly as it is */}
      <header className="flex items-center justify-between px-4 py-2.5 bg-[#ffffff] border-b border-[#dfe5ec] shrink-0 select-none">
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
            <div className="px-2.5 py-1 rounded-md bg-[#f5f7fa] border border-[#e2e8f0] text-xs font-mono text-[#15202b] truncate max-w-[180px] sm:max-w-xs md:max-w-md">
              {url || "Initializing target..."}
            </div>

            <Chip status={(status as ChipStatus) || "running"} dot />

            {grade && (
              <span className="hidden sm:inline-block px-2 py-0.5 rounded bg-[#f5f7fa] border border-[#e2e8f0] text-xs font-mono font-bold text-[#ea7336]">
                GRADE {grade}
              </span>
            )}

            {score !== null && score !== undefined && (
              <span className="hidden sm:inline-block px-2 py-0.5 rounded bg-[#f5f7fa] border border-[#e2e8f0] text-xs font-mono text-[#15202b]">
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
            <div className="flex items-center gap-2">
              <Link href={`/scan/${scanId}/exploit`}>
                <Button
                  variant="danger"
                  size="sm"
                  className="gap-1.5 font-semibold shadow-xs text-white"
                >
                  <Flame className="h-3.5 w-3.5" />
                  <span>Exploit</span>
                </Button>
              </Link>

              <Link href={`/scan/${scanId}/report`}>
                <Button variant="primary" size="sm" className="gap-1.5 shadow-xs">
                  <FileText className="h-3.5 w-3.5" />
                  <span>Security Report</span>
                </Button>
              </Link>
            </div>
          ) : (
            <StopButton />
          )}
        </div>
      </header>

      {/* Stream Reconnection / Warning Banner */}
      <StreamBanner />

      {/* Main Conversational Stream Area (WhatsApp-style auto-scrolling feed) */}
      <main className="relative flex-1 min-h-0 overflow-hidden flex flex-col bg-[#f7f9fc]">
        {/* Whole-screen wavy ocean background & single slim fish swimming freely */}
        <SwimmingFish />

        {/* Chat Stream: each task appears as a reply with attached screenshot and auto-scroll */}
        <div className="relative z-10 flex-1 min-h-0 flex flex-col">
          <ChatTaskFeed />
        </div>

        {/* Pinned Bottom Container: Name of website being Analysed */}
        <div className="relative z-10 p-3 sm:px-6 sm:pb-4 sm:pt-1 max-w-3xl w-full mx-auto shrink-0">
          <TargetWebsiteBar />
        </div>
      </main>
    </div>
  );
}
