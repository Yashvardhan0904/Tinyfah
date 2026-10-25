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
import { LogoMark } from "@/components/ui/logo-mark"; // <- adjust to wherever your main navbar imports LogoMark from
import Link from "next/link";
import { FileText, Flame } from "lucide-react";

export function WorkspaceShell() {
  const scanId = useScanStore((s) => s.scanId);
  const url = useScanStore((s) => s.url);
  const status = useScanStore((s) => s.status);
  const grade = useScanStore((s) => s.grade);
  const score = useScanStore((s) => s.score);

  const isTerminal =
    status === "completed" || status === "failed" || status === "not_assessed";

  const hasGrade = !!grade && String(grade).toUpperCase() !== "NOT_ASSESSED";
  const hasScore = score !== null && score !== undefined;

  const targetStatus = (
    <>
      <span className="min-w-0 max-w-[220px] truncate text-sm font-medium text-[#15202b] md:max-w-[340px]">
        {url || "Preparing target…"}
      </span>
      <Chip status={(status as ChipStatus) || "running"} dot />
      {hasGrade && (
        <span className="shrink-0 text-sm font-semibold text-[#c4571f]">Grade {grade}</span>
      )}
{hasScore ? (
  <span className="shrink-0 text-sm tabular-nums text-[#5d6b7b]">
    {score}/100
  </span>
) : !isTerminal ? (
  <span
    className="inline-flex shrink-0 items-center gap-2 text-sm text-[#5d6b7b]"
    role="status"
    aria-label="Calculating security score"
  >
    <span className="h-3 w-3 animate-spin rounded-full border-2 border-[#dfe5ec] border-t-[#ea7336]" />
    <span>Calculating...</span>
  </span>
) : null}
    </>
  );

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-[#f7f9fc] text-[#15202b]">
      {/* Navbar */}
      <header className="z-40 shrink-0 select-none border-b border-[#dfe5ec] bg-white/85 backdrop-blur-md">
        <div className="mx-auto max-w-7xl px-4 sm:px-8">
          <div className="flex h-16 items-center justify-between gap-4 md:grid md:grid-cols-[1fr_auto_1fr]">
            {/* Left: logo */}
            <Link
              href="/"
              aria-label="TinyFah home"
              className="group flex shrink-0 items-center gap-2.5 justify-self-start rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#ea7336]/50"
            >
              <LogoMark />
              <span className="theme-navbar-brand text-[19px] leading-none tracking-[-0.04em] text-[#15202b]">
                <span className="font-medium">tiny</span>
                <span className="font-extrabold">fah</span>
              </span>
            </Link>

            {/* Center: target and scan state */}
            <div className="hidden min-w-0 items-center gap-3 md:flex">{targetStatus}</div>

            {/* Right: live telemetry and actions */}
            <div className="flex shrink-0 items-center gap-3 justify-self-end">
              <HeartbeatDot />
              <ElapsedTimer />

              {isTerminal ? (
                <div className="flex items-center gap-2">
                  <Link href={`/scan/${scanId}/exploit`}>
                    <Button variant="danger" size="sm" className="gap-1.5 font-semibold text-white">
                      <Flame className="h-3.5 w-3.5" />
                      <span>Exploit</span>
                    </Button>
                  </Link>

                  <Link href={`/scan/${scanId}/report`}>
                    <Button variant="primary" size="sm" className="gap-1.5">
                      <FileText className="h-3.5 w-3.5" />
                      <span className="hidden sm:inline">Security report</span>
                      <span className="sm:hidden">Report</span>
                    </Button>
                  </Link>
                </div>
              ) : (
                <StopButton />
              )}
            </div>
          </div>

          {/* Mobile: target and scan state */}
          <div className="flex items-center gap-3 pb-2.5 md:hidden">{targetStatus}</div>
        </div>
      </header>

      {/* Stream reconnection / warning banner */}
      <StreamBanner />

      {/* Live task stream */}
      <main className="relative flex min-h-0 flex-1 flex-col overflow-hidden bg-[#f7f9fc]">
        {/* Ocean background and swimming fish */}
        <SwimmingFish />

        {/* Each task appears as it happens, with auto-scroll */}
        <div className="relative z-10 flex min-h-0 flex-1 flex-col">
          <ChatTaskFeed />
        </div>

        {/* Pinned: website being analysed */}
        <div className="relative z-10 mx-auto w-full max-w-3xl shrink-0 p-3 sm:px-6 sm:pb-4 sm:pt-1">
          <TargetWebsiteBar />
        </div>
      </main>
    </div>
  );
}