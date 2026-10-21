"use client";

import { useScanStore } from "@/stores/scan-store";
import {
  Globe,
  Lock,
  Unlock,
  ExternalLink,
  Shield,
  Activity,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";

export function TargetWebsiteBar() {
  const url = useScanStore((s) => s.url);
  const status = useScanStore((s) => s.status);
  const grade = useScanStore((s) => s.grade);
  const score = useScanStore((s) => s.score);
  const agentTrace = useScanStore((s) => s.agentTrace);
  const latestStep = useScanStore((s) => s.latestStep);
  const scanError = useScanStore((s) => s.error);

  // Parse domain name safely
  let domain = "Target Website";
  let isHttps = true;
  try {
    if (url) {
      const parsed = new URL(url);
      domain = parsed.hostname;
      isHttps = parsed.protocol === "https:";
    }
  } catch {
    domain = url?.replace(/^https?:\/\//, "").split("/")[0] || "Target Website";
  }

  // Estimated total steps for progress calculation
  const totalEstimatedSteps = Math.max(20, agentTrace.length);
  const progressPercent =
    status === "completed"
      ? 100
      : Math.min(Math.round((agentTrace.length / totalEstimatedSteps) * 100), 95);

  const isTerminal =
    status === "completed" || status === "failed" || status === "not_assessed";

  // Current operational phase description
  const phaseLabel =
    status === "completed"
      ? "Audit Complete • All Domain & Standard Checks Synthesized"
      : status === "failed"
      ? (scanError || "Target cannot be reached. Session terminated.")
      : latestStep?.reason || "Auditing Web Application Security Architecture";

  return (
    <div className="w-full rounded-2xl border border-[#dfe5ec] bg-[#ffffff] shadow-sm p-3.5 sm:p-4 shrink-0 transition-all duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Left: Domain Name & Target Info */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="h-10 w-10 rounded-xl bg-[#fff0e6] border border-[#fed7c0] flex items-center justify-center shrink-0 text-[#ea7336]">
            <Globe className="h-5 w-5" />
          </div>

          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-sm sm:text-base font-bold font-sans tracking-tight text-[#15202b] truncate">
                {domain}
              </h2>

              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#f3f6f9] border border-[#dfe5ec] text-[#5d6b7b] shrink-0">
                {isHttps ? (
                  <>
                    <Lock className="h-2.5 w-2.5 text-[#2774c7]" />
                    <span>HTTPS</span>
                  </>
                ) : (
                  <>
                    <Unlock className="h-2.5 w-2.5 text-[#d9485f]" />
                    <span>HTTP</span>
                  </>
                )}
              </span>

              {url && (
                <a
                  href={url}
                  target="_blank"
                  rel="noreferrer"
                  title="Open target in new tab"
                  className="text-[#5d6b7b] hover:text-[#15202b] transition-colors shrink-0"
                >
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </div>

            <p className="text-[11px] font-mono text-[#5d6b7b] truncate mt-0.5 max-w-sm sm:max-w-md">
              {phaseLabel}
            </p>
          </div>
        </div>

        {/* Right: Progress Indicator & Final Badges */}
        <div className="flex items-center gap-3 shrink-0 self-end sm:self-center">
          {/* Progress / Step Count */}
          <div className="flex flex-col items-end gap-1">
            <div className="flex items-center gap-2 text-xs font-mono">
              {!isTerminal && (
                <span className="flex items-center gap-1 text-[#ea7336] font-medium">
                  <Activity className="h-3 w-3 animate-spin" />
                  <span>Scanning</span>
                </span>
              )}
              {isTerminal && status === "completed" && (
                <span className="flex items-center gap-1 text-[#ea7336] font-medium">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span>Finished</span>
                </span>
              )}
              {status === "failed" && (
                <span className="flex items-center gap-1 text-[#d9485f] font-medium">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  <span>Failed</span>
                </span>
              )}

              <span className="text-[#5d6b7b]">
                {agentTrace.length} {isTerminal ? "steps" : `of ~${totalEstimatedSteps}`}
              </span>
            </div>

            {/* Mini Progress Bar */}
            <div className="w-28 sm:w-36 h-1.5 rounded-full bg-[#f3f6f9] border border-[#dfe5ec] overflow-hidden">
              <div
                className="h-full bg-[#ea7336] transition-all duration-500 rounded-full"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>

          {/* Grade preview badge if available */}
          {grade && (
            <div className="px-2.5 py-1 rounded-xl bg-[#fff0e6] border border-[#fed7c0] text-center shrink-0">
              <div className="text-[9px] font-mono font-semibold text-[#5d6b7b] uppercase tracking-wider">
                Posture
              </div>
              <div className="text-xs font-mono font-bold text-[#ea7336]">
                Grade {grade}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
