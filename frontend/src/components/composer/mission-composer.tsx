"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { cn, extractUrls } from "@/lib/utils";
import { createScan } from "@/lib/api";
import { ModeToggle } from "./mode-toggle";
import { UrlChip } from "./url-chip";
import { PlanPreview } from "./plan-preview";
import { Button } from "@/components/ui/button";
import type { SuiteType } from "@/lib/types";
import { AlertCircle, Link2, Sparkles, Globe, ShieldAlert } from "lucide-react";

export function MissionComposer() {
  const router = useRouter();
  const [prompt, setPrompt] = useState("");
  const [suite, setSuite] = useState<SuiteType>("langgraph");
  const [manualUrl, setManualUrl] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Ensure isSubmitting is reset when navigating back via Next.js or browser bfcache
  useEffect(() => {
    setIsSubmitting(false);

    const handlePageShow = (event: PageTransitionEvent) => {
      setIsSubmitting(false);
    };

    window.addEventListener("pageshow", handlePageShow);
    return () => window.removeEventListener("pageshow", handlePageShow);
  }, []);

  // Extract URLs in real-time from prompt
  const detectedUrls = extractUrls(prompt);
  const activeUrl = manualUrl || detectedUrls[0] || null;

  const handleSelectDemoTarget = (targetUrl: string) => {
    setPrompt(targetUrl);
    setManualUrl(targetUrl);
    setErrorMessage(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const targetUrl = activeUrl || prompt.trim();
    if (!targetUrl) {
      setErrorMessage("Please enter a target URL or type an instruction with a URL.");
      return;
    }

    // Ensure valid URL scheme
    let formattedUrl = targetUrl;
    if (!formattedUrl.startsWith("http://") && !formattedUrl.startsWith("https://")) {
      formattedUrl = `https://${formattedUrl}`;
    }

    try {
      setIsSubmitting(true);
      const scan = await createScan({
        url: formattedUrl,
        suite,
        focus_prompt: prompt !== formattedUrl ? prompt : undefined,
      });

      // Reset submitting state before navigation so returning to this page is clean
      setIsSubmitting(false);

      // Navigate to live workspace
      router.push(`/scan/${scan.id}`);
    } catch (err) {
      setErrorMessage(
        err instanceof Error
          ? err.message
          : "Failed to dispatch scan. Please ensure backend is running."
      );
      setIsSubmitting(false);
    }
  };

  return (
    <div id="composer" className="w-full max-w-3xl mx-auto flex flex-col items-center gap-6">
      <form onSubmit={handleSubmit} className="w-full flex flex-col gap-4">
        {/* Main Instruction / URL Input Container */}
        <div className="relative w-full overflow-hidden rounded-[1.5rem] border border-[#d5dee7] bg-white p-2 shadow-[0_20px_60px_rgba(31,52,73,0.12)] transition-all focus-within:border-[#ea7336]/60 focus-within:shadow-[0_20px_70px_rgba(234,115,54,0.12)]">
          <div className="flex items-center justify-between px-3 pt-2">
            <label htmlFor="assessment-prompt" className="flex items-center gap-2 text-xs font-semibold tracking-wide text-[#243342]">
              <span className="flex h-6 w-6 items-center justify-center rounded-lg bg-[#fff0e6] text-[#ea7336]">
                <Link2 className="h-3.5 w-3.5" />
              </span>
              Assessment target
            </label>
            <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[#9aa7b5]">Secure dispatch</span>
          </div>
          <textarea
            id="assessment-prompt"
            value={prompt}
            onChange={(e) => {
              setPrompt(e.target.value);
              setErrorMessage(null);
            }}
            placeholder="Paste a target URL or describe what you want to verify…"
            className="w-full bg-transparent text-[#15202b] placeholder-[#9aa7b5] text-[15px] resize-none focus:outline-none min-h-[105px] px-3 pb-3 pt-4 leading-relaxed font-sans"
            rows={3}
          />

          {/* Detected URL Chip Container */}
          {activeUrl && (
            <div className="mx-2 flex items-center gap-2 border-t border-[#edf1f4] px-1 py-3">
              <span className="text-[11px] font-mono text-[#5d6b7b] shrink-0">
                Target Identified:
              </span>
              <UrlChip
                url={activeUrl}
                onClear={() => {
                  setManualUrl(null);
                  if (activeUrl) {
                    if (prompt.trim() === activeUrl) {
                      setPrompt("");
                    } else {
                      setPrompt((prev) => prev.replace(activeUrl, "").trim());
                    }
                  }
                  setErrorMessage(null);
                }}
              />
            </div>
          )}

          {/* Bottom Bar: Mode Toggle + Run Button */}
          <div className="flex flex-wrap items-center justify-between gap-4 border-t border-[#edf1f4] px-2 pb-2 pt-4">
            <ModeToggle value={suite} onChange={setSuite} />

            <Button
              type="submit"
              variant={suite === "langgraph" ? "violet" : "primary"}
              size="md"
              isLoading={isSubmitting}
              disabled={!activeUrl && !prompt.trim()}
              className="shrink-0 rounded-xl px-6 py-2.5 font-semibold"
            >
              Go
            </Button>
          </div>
        </div>

        {/* 1-Click Demo Targets */}
        <div className="flex flex-wrap items-center justify-center gap-2 px-1">
          <span className="flex items-center gap-1.5 text-xs font-mono text-[#5d6b7b]">
            <Sparkles className="h-3.5 w-3.5 text-[#ea7336]" />
            <span>1-Click Demos:</span>
          </span>
          <button
            type="button"
            onClick={() => handleSelectDemoTarget("https://iosc.win")}
            className={cn(
              "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-mono transition-all cursor-pointer",
              activeUrl === "https://iosc.win" || prompt.includes("iosc.win")
                ? "bg-[#fff0e6] text-[#ea7336] border-[#fed7c0] font-semibold shadow-2xs scale-[1.02]"
                : "bg-white text-[#475569] border-[#d5dee7] hover:border-[#ea7336]/60 hover:text-[#15202b] hover:bg-[#fafbfc]"
            )}
          >
            <Globe className="h-3.5 w-3.5 text-[#ea7336]" />
            <span>iosc.win</span>
          </button>
          <button
            type="button"
            onClick={() => handleSelectDemoTarget("https://vuln-website.vercel.app")}
            className={cn(
              "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-mono transition-all cursor-pointer",
              activeUrl === "https://vuln-website.vercel.app" || prompt.includes("vuln-website.vercel.app")
                ? "bg-[#fff0e6] text-[#ea7336] border-[#fed7c0] font-semibold shadow-2xs scale-[1.02]"
                : "bg-white text-[#475569] border-[#d5dee7] hover:border-[#ea7336]/60 hover:text-[#15202b] hover:bg-[#fafbfc]"
            )}
          >
            <ShieldAlert className="h-3.5 w-3.5 text-[#d9485f]" />
            <span>vuln-website.vercel.app</span>
          </button>
        </div>

        {/* Scope or Error Notice */}
        {errorMessage && (
          <div className="w-full flex items-center gap-2.5 p-3 rounded-lg bg-[#d9485f]/10 border border-[#d9485f]/30 text-xs font-mono text-[#d9485f]">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}
      </form>

      {/* Pre-Flight Plan Preview Card */}
      <PlanPreview suite={suite} targetUrl={activeUrl || prompt.trim()} />
    </div>
  );
}
