"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { extractUrls } from "@/lib/utils";
import { createScan } from "@/lib/api";
import { ModeToggle } from "./mode-toggle";
import { UrlChip } from "./url-chip";
import { PlanPreview } from "./plan-preview";
import { Button } from "@/components/ui/button";
import type { SuiteType } from "@/lib/types";
import { AlertCircle, Link2 } from "lucide-react";

export function MissionComposer() {
  const router = useRouter();
  const [prompt, setPrompt] = useState("");
  const [suite, setSuite] = useState<SuiteType>("langgraph");
  const [manualUrl, setManualUrl] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Extract URLs in real-time from prompt
  const detectedUrls = extractUrls(prompt);
  const activeUrl = manualUrl || detectedUrls[0] || null;

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
        <div className="relative w-full overflow-hidden rounded-[1.5rem] border border-[#d5dee7] bg-white p-2 shadow-[0_20px_60px_rgba(31,52,73,0.12)] transition-all focus-within:border-[#18a66b]/60 focus-within:shadow-[0_20px_70px_rgba(24,166,107,0.12)]">
          <div className="flex items-center justify-between px-3 pt-2">
            <label htmlFor="assessment-prompt" className="flex items-center gap-2 text-xs font-semibold tracking-wide text-[#243342]">
              <span className="flex h-6 w-6 items-center justify-center rounded-lg bg-[#e8f7ef] text-[#18a66b]">
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
                  if (detectedUrls.length === 0) setPrompt("");
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
