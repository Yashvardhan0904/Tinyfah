"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useScanStore } from "@/stores/scan-store";
import { cn } from "@/lib/utils";
import {
  Wrench,
  CheckCircle2,
  XCircle,
  Clock,
  Sparkles,
  Terminal,
  Activity,
  Maximize2,
  X,
  ExternalLink,
  Shield,
  ShieldCheck,
  Globe,
  Camera,
  Search,
  Lock,
  Cpu,
  Layers,
  FileCheck,
  FileText,
  ArrowDown,
} from "lucide-react";

export function ChatTaskFeed() {
  const agentTrace = useScanStore((s) => s.agentTrace);
  const status = useScanStore((s) => s.status);
  const url = useScanStore((s) => s.url);

  const containerRef = useRef<HTMLDivElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const prevLengthRef = useRef(0);
  const isNearBottomRef = useRef(true);

  const [showScrollBottomBtn, setShowScrollBottomBtn] = useState(false);

  // Lightbox state for clicked screenshots
  const [lightboxImage, setLightboxImage] = useState<{
    src: string;
    stepNumber: number;
    tool: string;
    reason: string;
  } | null>(null);

  // Reliable scroll-to-bottom utility
  const scrollToBottom = useCallback((behavior: ScrollBehavior = "smooth") => {
    const container = containerRef.current;
    if (!container) return;

    // Use direct container scroll for 100% reliable positioning
    container.scrollTo({
      top: container.scrollHeight + 1000,
      behavior,
    });

    bottomRef.current?.scrollIntoView({ behavior, block: "end" });
  }, []);

  // Monitor user scrolling to avoid jerking screen if they are reading history
  const handleScroll = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;

    const { scrollTop, scrollHeight, clientHeight } = container;
    const distanceFromBottom = scrollHeight - (scrollTop + clientHeight);

    // If within 140px of bottom, treat as "stick to bottom"
    const isAtBottom = distanceFromBottom < 140;
    isNearBottomRef.current = isAtBottom;
    setShowScrollBottomBtn(!isAtBottom && agentTrace.length > 2);
  }, [agentTrace.length]);

  // 1. ResizeObserver: whenever messages or images resize container, keep stick-to-bottom
  useEffect(() => {
    const content = contentRef.current;
    if (!content) return;

    const resizeObserver = new ResizeObserver(() => {
      if (isNearBottomRef.current) {
        scrollToBottom("smooth");
      }
    });

    resizeObserver.observe(content);
    return () => resizeObserver.disconnect();
  }, [scrollToBottom]);

  // 2. Direct trigger whenever new tasks arrive in store
  useEffect(() => {
    if (agentTrace.length > prevLengthRef.current) {
      prevLengthRef.current = agentTrace.length;

      // Scroll immediately
      scrollToBottom("smooth");

      // Double-tap after cascade animation finishes (150ms)
      const t1 = setTimeout(() => scrollToBottom("smooth"), 150);
      const t2 = setTimeout(() => scrollToBottom("smooth"), 350);

      return () => {
        clearTimeout(t1);
        clearTimeout(t2);
      };
    }
  }, [agentTrace.length, scrollToBottom]);

  // 3. Initial mount scroll
  useEffect(() => {
    const t = setTimeout(() => scrollToBottom("auto"), 50);
    return () => clearTimeout(t);
  }, [scrollToBottom]);

  const getToolIcon = (tool: string) => {
    const t = tool.toLowerCase();
    if (t.includes("tinyfish") || t.includes("provision")) {
      return <Cpu className="h-4 w-4 text-[#2774c7]" />;
    }
    if (t.includes("navigator") || t.includes("browser")) {
      return <Globe className="h-4 w-4 text-[#0ea5e9]" />;
    }
    if (t.includes("recon")) {
      return <Search className="h-4 w-4 text-[#f59e0b]" />;
    }
    if (t.includes("supervisor")) {
      return <Sparkles className="h-4 w-4 text-[#ea7336]" />;
    }
    if (t.includes("transport") || t.includes("crypto") || t.includes("header")) {
      return <Lock className="h-4 w-4 text-[#10b981]" />;
    }
    if (t.includes("evaluator") || t.includes("validator")) {
      return <FileCheck className="h-4 w-4 text-[#6d4aca]" />;
    }
    if (t.includes("synthesizer") || t.includes("report")) {
      return <FileText className="h-4 w-4 text-[#ea7336]" />;
    }
    return <Terminal className="h-4 w-4 text-[#5d6b7b]" />;
  };

  const getAvatarBg = (tool: string) => {
    const t = tool.toLowerCase();
    if (t.includes("tinyfish")) return "bg-[#e7f0fb] border-[#a9c8ed]";
    if (t.includes("supervisor")) return "bg-[#fff0e6] border-[#fed7c0]";
    if (t.includes("recon")) return "bg-[#fff5df] border-[#e7c784]";
    if (t.includes("evaluator")) return "bg-[#f1edff] border-[#c1aaff]";
    if (t.includes("transport")) return "bg-[#e6f9f0] border-[#a3e9c7]";
    return "bg-[#f3f6f9] border-[#dfe5ec]";
  };

  return (
    <div className="relative flex-1 w-full min-h-0 overflow-hidden flex flex-col">
      {/* Scrollable Chat Viewport */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 w-full overflow-y-auto px-3 sm:px-6 py-4 scroll-smooth"
      >
        <div ref={contentRef} className="max-w-3xl mx-auto flex flex-col gap-4">
          {/* Starting banner / Conversation Start */}
          <div className="flex flex-col items-center justify-center my-2 select-none">
            <div className="px-3 py-1 rounded-full bg-[#ffffff] border border-[#dfe5ec] text-[11px] font-mono text-[#5d6b7b] shadow-2xs flex items-center gap-1.5">
              <Shield className="h-3 w-3 text-[#ea7336]" />
              <span>Autonomous Security Agent Session Initialized</span>
            </div>
            <span className="text-[10px] text-[#748294] mt-1 font-mono">
              Target: {url || "Waiting for target..."}
            </span>
          </div>

          {/* Empty state while waiting for first task */}
          {agentTrace.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-center text-[#5d6b7b]">
              <div className="h-12 w-12 rounded-2xl bg-[#ffffff] border border-[#dfe5ec] shadow-sm flex items-center justify-center mb-3">
                <Sparkles className="h-6 w-6 text-[#ea7336] animate-pulse" />
              </div>
              <p className="text-xs font-mono font-medium text-[#15202b]">
                {status === "queued"
                  ? "Connecting cloud browser and starting mission..."
                  : "Awaiting agent stream..."}
              </p>
              <p className="text-[11px] text-[#748294] mt-1 max-w-xs">
                Actions and screenshots will appear here like live message replies.
              </p>
            </div>
          )}

          {/* Chat message replies list */}
          {agentTrace.map((step, idx) => {
            const isLatest = idx === agentTrace.length - 1;
            const isRunning = isLatest && status === "running";
            const hasScreenshot = Boolean(step.screenshot);
            const screenshotSrc = hasScreenshot
              ? `/screenshots/${step.screenshot}`
              : null;

            return (
              <div
                key={idx}
                className="flex items-start gap-2.5 sm:gap-3.5 group animate-cascade-in"
                style={{ animationDelay: `${Math.min(idx * 25, 150)}ms` }}
              >
                {/* Agent Avatar */}
                <div
                  className={cn(
                    "h-8 w-8 sm:h-9 sm:w-9 rounded-full border flex items-center justify-center shrink-0 shadow-2xs select-none",
                    getAvatarBg(step.tool || "")
                  )}
                >
                  {getToolIcon(step.tool || "")}
                </div>

                {/* Chat Message Bubble */}
                <div
                  className={cn(
                    "flex-1 max-w-2xl rounded-2xl rounded-tl-xs p-3.5 sm:p-4 text-left border shadow-2xs transition-all duration-200",
                    isRunning
                      ? "bg-[#ffffff] border-[#ea7336] ring-1 ring-[#ea7336]/25 shadow-sm"
                      : "bg-[#ffffff] border-[#dfe5ec] hover:border-[#cbd5e1]"
                  )}
                >
                  {/* Message Header: Agent Tag, Step Number & Status */}
                  <div className="flex items-center justify-between gap-2 mb-1.5 select-none">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="text-[11px] font-mono font-bold text-[#ea7336]">
                        #{step.step ?? idx + 1}
                      </span>
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-[#f5f7fa] border border-[#dfe5ec] text-[10px] font-mono font-semibold text-[#15202b]">
                        {step.tool || "agent_task"}
                      </span>
                    </div>

                    <div className="flex items-center gap-1 text-[11px] font-mono text-[#5d6b7b]">
                      {isRunning ? (
                        <span className="inline-flex items-center gap-1 text-[#ea7336] font-semibold text-[10px]">
                          <span className="h-1.5 w-1.5 rounded-full bg-[#ea7336] animate-ping" />
                          <span>RUNNING</span>
                        </span>
                      ) : step.status === "failed" ? (
                        <span className="inline-flex items-center gap-1 text-[#d9485f]">
                          <XCircle className="h-3 w-3" />
                          <span>FAIL</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[#10b981]">
                          <CheckCircle2 className="h-3 w-3 text-[#ea7336]" />
                          <span>DONE</span>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Primary Message Text: Task Reason / Objective */}
                  <p className="text-xs sm:text-[13px] font-sans text-[#15202b] font-medium leading-relaxed">
                    {step.reason || "Executing security verification routine"}
                  </p>

                  {/* Observation / Telemetry Subtext if present */}
                  {step.observation_preview && (
                    <div className="mt-2 text-[11px] font-mono text-[#5d6b7b] bg-[#f8fafc] p-2 rounded-lg border border-[#eef2f6] leading-relaxed break-words">
                      <span className="text-[#ea7336] font-bold">&gt; </span>
                      {step.observation_preview}
                    </div>
                  )}

                  {/* Attached Screenshot (Like a WhatsApp Photo Message!) */}
                  {screenshotSrc && (
                    <div className="mt-2.5 pt-2 border-t border-[#f0f3f7]">
                      <div
                        onClick={() =>
                          setLightboxImage({
                            src: screenshotSrc,
                            stepNumber: step.step ?? idx + 1,
                            tool: step.tool || "browser",
                            reason: step.reason || "",
                          })
                        }
                        className="group/shot relative rounded-xl overflow-hidden border border-[#dfe5ec] bg-[#0c1218] cursor-zoom-in max-w-md shadow-xs hover:border-[#ea7336] transition-colors"
                      >
                        {/* Browser header strip on screenshot */}
                        <div className="flex items-center justify-between px-2.5 py-1 bg-[#18232f] border-b border-[#2a3a4b] text-[9px] font-mono text-[#96a7b8]">
                          <div className="flex items-center gap-1">
                            <span className="h-1.5 w-1.5 rounded-full bg-[#ff5f56]" />
                            <span className="h-1.5 w-1.5 rounded-full bg-[#ffbd2e]" />
                            <span className="h-1.5 w-1.5 rounded-full bg-[#27c93f]" />
                            <span className="ml-1 text-[#edf3f8]">Browser Frame</span>
                          </div>
                          <span className="flex items-center gap-1 text-[#ea7336]">
                            <Camera className="h-2.5 w-2.5" />
                            <span>Captured</span>
                          </span>
                        </div>

                        {/* Image Thumbnail with onLoad auto-scroll */}
                        <div className="relative w-full h-[180px] sm:h-[220px] bg-[#0b1118] flex items-center justify-center">
                          <img
                            src={screenshotSrc}
                            alt={`Step #${step.step ?? idx + 1} screenshot`}
                            onLoad={() => {
                              if (isNearBottomRef.current) {
                                scrollToBottom("smooth");
                              }
                            }}
                            className="w-full h-full object-contain select-none transition-transform duration-300 group-hover/shot:scale-[1.02]"
                          />

                          {/* Hover expand badge */}
                          <div className="absolute inset-0 bg-[#000000]/30 opacity-0 group-hover/shot:opacity-100 transition-opacity flex items-center justify-center">
                            <span className="px-2.5 py-1 rounded-md bg-[#ffffff]/90 text-[#15202b] text-[11px] font-mono font-medium shadow-md backdrop-blur-xs flex items-center gap-1.5">
                              <Maximize2 className="h-3 w-3 text-[#ea7336]" />
                              <span>Click to expand</span>
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {/* Live typing / thinking bubble when scan is actively running */}
          {status === "running" && agentTrace.length > 0 && (
            <div className="flex items-center gap-3 pl-1 text-[#5d6b7b] text-xs font-mono animate-pulse select-none">
              <div className="h-8 w-8 rounded-full bg-[#fff0e6] border border-[#fed7c0] flex items-center justify-center text-[#ea7336]">
                <Sparkles className="h-4 w-4 animate-spin" />
              </div>
              <div className="px-3 py-2 rounded-2xl rounded-tl-xs bg-[#ffffff] border border-[#dfe5ec] shadow-2xs flex items-center gap-2">
                <span className="flex gap-1 items-center">
                  <span className="h-1.5 w-1.5 rounded-full bg-[#ea7336] animate-bounce" />
                  <span className="h-1.5 w-1.5 rounded-full bg-[#ea7336] animate-bounce [animation-delay:0.2s]" />
                  <span className="h-1.5 w-1.5 rounded-full bg-[#ea7336] animate-bounce [animation-delay:0.4s]" />
                </span>
                <span className="text-[11px] text-[#5d6b7b]">
                  Orchestrating next domain audit...
                </span>
              </div>
            </div>
          )}

          {/* Bottom anchor for WhatsApp-style auto-scroll */}
          <div ref={bottomRef} className="h-2" />
        </div>
      </div>

      {/* Floating "Jump to Latest" Button if user scrolled up */}
      {showScrollBottomBtn && (
        <div className="absolute bottom-3 right-6 z-10 animate-step-in">
          <button
            onClick={() => {
              isNearBottomRef.current = true;
              scrollToBottom("smooth");
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-[#ffffff] hover:bg-[#f7f9fc] text-[#15202b] border border-[#dfe5ec] shadow-md text-xs font-mono font-medium transition-all hover:border-[#ea7336] hover:scale-105"
          >
            <ArrowDown className="h-3.5 w-3.5 text-[#ea7336] animate-bounce" />
            <span>Latest Tasks</span>
          </button>
        </div>
      )}

      {/* Lightbox Modal for Fullscreen Screenshot Inspection */}
      {lightboxImage && (
        <div
          onClick={() => setLightboxImage(null)}
          className="fixed inset-0 z-50 bg-[#000000]/80 backdrop-blur-md flex flex-col items-center justify-center p-4 sm:p-6 animate-step-in"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="relative max-w-5xl w-full max-h-[90vh] bg-[#121a23] rounded-2xl border border-[#2a3a4b] shadow-2xl overflow-hidden flex flex-col"
          >
            {/* Modal Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#2a3a4b] bg-[#18232f]">
              <div className="flex items-center gap-2 min-w-0">
                <ShieldCheck className="h-4 w-4 text-[#ea7336] shrink-0" />
                <span className="text-xs font-mono font-bold text-[#edf3f8] truncate">
                  Step #{lightboxImage.stepNumber} • {lightboxImage.tool}
                </span>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <a
                  href={lightboxImage.src}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 rounded bg-[#243342] hover:bg-[#2e4053] text-[#edf3f8] text-[11px] font-mono flex items-center gap-1 transition-colors"
                >
                  <ExternalLink className="h-3 w-3" />
                  <span>Open Full</span>
                </a>
                <button
                  onClick={() => setLightboxImage(null)}
                  className="p-1 rounded-md text-[#9aa7b5] hover:text-[#ffffff] hover:bg-[#243342] transition-colors"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* Modal Image Body */}
            <div className="flex-1 overflow-auto p-4 flex items-center justify-center bg-[#0b1118]">
              <img
                src={lightboxImage.src}
                alt="Full resolution security telemetry capture"
                className="max-h-[75vh] w-auto object-contain rounded-lg border border-[#2a3a4b]"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
