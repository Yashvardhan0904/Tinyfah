"use client";

import { useState } from "react";
import type { FindingItem, ASVSTestItem } from "@/lib/types";
import {
  translateFindingsToExecutiveLapses,
  type ExecutiveLapse,
} from "@/lib/threat-translator";
import {
  ShieldAlert,
  AlertTriangle,
  Wifi,
  Lock,
  Globe,
  Key,
  Code2,
  FileWarning,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  Flame,
  Wrench,
  Lightbulb,
  ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ExecutiveLapsesGridProps {
  findings: FindingItem[];
  asvsResults?: ASVSTestItem[];
}

export function ExecutiveLapsesGrid({
  findings,
  asvsResults = [],
}: ExecutiveLapsesGridProps) {
  const lapses = translateFindingsToExecutiveLapses(findings, asvsResults);
  const [openEvidenceId, setOpenEvidenceId] = useState<string | null>(null);

  const toggleEvidence = (id: string) => {
    setOpenEvidenceId((prev) => (prev === id ? null : id));
  };

  const renderIcon = (type: ExecutiveLapse["iconType"], className: string) => {
    switch (type) {
      case "wifi":
        return <Wifi className={className} />;
      case "lock":
        return <Lock className={className} />;
      case "globe":
        return <Globe className={className} />;
      case "key":
        return <Key className={className} />;
      case "code":
        return <Code2 className={className} />;
      case "file-warning":
        return <FileWarning className={className} />;
      case "shield-alert":
        return <ShieldAlert className={className} />;
      case "alert-triangle":
      default:
        return <AlertTriangle className={className} />;
    }
  };

  const getSeverityBadge = (severity: ExecutiveLapse["severity"]) => {
    switch (severity) {
      case "critical":
      case "high":
        return {
          bg: "bg-[#fff1f2]",
          text: "text-[#d9485f]",
          border: "border-[#fecdd3]",
          label: "High Risk",
        };
      case "medium":
        return {
          bg: "bg-[#fffbeb]",
          text: "text-[#b45309]",
          border: "border-[#fde68a]",
          label: "Medium Risk",
        };
      case "low":
      default:
        return {
          bg: "bg-[#eff6ff]",
          text: "text-[#1d4ed8]",
          border: "border-[#bfdbfe]",
          label: "Low Risk",
        };
    }
  };

  if (lapses.length === 0) {
    return (
      <div className="rounded-2xl bg-[#ffffff] border border-[#dfe5ec] p-8 text-center shadow-2xs space-y-3">
        <div className="h-12 w-12 rounded-full bg-[#ecfdf5] border border-[#a7f3d0] text-[#059669] mx-auto flex items-center justify-center">
          <CheckCircle2 className="h-6 w-6" />
        </div>
        <h3 className="text-base font-bold text-[#15202b]">
          No Security Lapses Detected
        </h3>
        <p className="text-xs text-[#5d6b7b] max-w-md mx-auto">
          The automated baseline scan did not identify any immediate high or medium risk security lapses across standard attack vectors.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-2">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-[#ea7336]" />
            <h2 className="text-base font-bold tracking-tight text-[#15202b]">
              Identified Security Lapses & Exploit Risks
            </h2>
            <span className="px-2 py-0.5 rounded-full text-[11px] font-mono font-medium bg-[#fff0e6] text-[#ea7336] border border-[#fed7c0]">
              {lapses.length} {lapses.length === 1 ? "Lapse" : "Lapses"} Found
            </span>
          </div>
          <p className="text-xs text-[#5d6b7b] mt-0.5">
            Plain-English breakdown of what went wrong, how a bad actor can exploit it, and what needs to be fixed.
          </p>
        </div>
      </div>

      {/* Cards Grid */}
      <div className="grid grid-cols-1 gap-4">
        {lapses.map((lapse) => {
          const badge = getSeverityBadge(lapse.severity);
          const isEvidenceOpen = openEvidenceId === lapse.id;

          const imgSrc = lapse.screenshot?.startsWith("http") || lapse.screenshot?.startsWith("/")
            ? lapse.screenshot
            : lapse.screenshot
            ? `/screenshots/${lapse.screenshot}`
            : null;

          return (
            <div
              key={lapse.id}
              className="rounded-2xl bg-[#ffffff] border border-[#dfe5ec] overflow-hidden shadow-2xs transition-all hover:border-[#cfd8e3]"
            >
              {/* Card Header */}
              <div className="p-5 sm:p-6 border-b border-[#dfe5ec]/70 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-gradient-to-r from-[#ffffff] via-[#fafbfc] to-[#ffffff]">
                <div className="flex items-start gap-3.5">
                  <div
                    className={cn(
                      "p-2.5 rounded-xl border shrink-0 mt-0.5",
                      badge.bg,
                      badge.border,
                      badge.text
                    )}
                  >
                    {renderIcon(lapse.iconType, "h-5 w-5")}
                  </div>

                  <div className="space-y-1">
                    <h3 className="text-base font-bold text-[#15202b] tracking-tight">
                      {lapse.plainTitle}
                    </h3>
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-[#5d6b7b]">
                      <span className="font-semibold text-[#15202b]/70">Technical Control:</span>
                      <span className="bg-[#f3f6f9] px-2 py-0.5 rounded border border-[#dfe5ec] text-[11px]">
                        {lapse.technicalName}
                      </span>
                      {lapse.requirementIds && lapse.requirementIds.length > 0 && (
                        <span className="text-[10px] text-[#748294]">
                          ({lapse.requirementIds.join(", ")})
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="shrink-0 self-start sm:self-center">
                  <span
                    className={cn(
                      "inline-flex items-center px-2.5 py-1 rounded-full text-xs font-mono font-semibold border",
                      badge.bg,
                      badge.text,
                      badge.border
                    )}
                  >
                    {badge.label}
                  </span>
                </div>
              </div>

              {/* Exploit Scenario (Layman's Terms) */}
              <div className="p-5 sm:p-6 space-y-4">
                {/* Analogy Pill */}
                {lapse.analogy && (
                  <div className="flex items-start gap-2.5 p-3 rounded-xl bg-[#f7f9fc] border border-[#dfe5ec]/80 text-xs text-[#334155]">
                    <Lightbulb className="h-4 w-4 text-[#ea7336] shrink-0 mt-0.5" />
                    <p className="leading-relaxed">
                      <strong className="font-semibold text-[#15202b]">In Simple Terms: </strong>
                      {lapse.analogy}
                    </p>
                  </div>
                )}

                {/* Exploit Box */}
                <div className="rounded-xl border border-[#fee2e2] bg-[#fffbfb] p-4 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-bold font-mono uppercase tracking-wider text-[#991b1b]">
                    <Flame className="h-4 w-4 text-[#dc2626]" />
                    <span>How an Attacker Exploits This</span>
                  </div>
                  <p className="text-xs sm:text-sm text-[#1f2937] leading-relaxed">
                    {lapse.exploitScenario}
                  </p>
                </div>

                {/* Impact & Action 2-Column Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 pt-1">
                  {/* Business Impact */}
                  <div className="rounded-xl border border-[#dfe5ec] bg-[#ffffff] p-3.5 space-y-1.5">
                    <div className="flex items-center gap-1.5 text-xs font-mono font-semibold uppercase tracking-wider text-[#b45309]">
                      <AlertTriangle className="h-3.5 w-3.5" />
                      <span>Potential Business Impact</span>
                    </div>
                    <p className="text-xs text-[#334155] leading-relaxed">
                      {lapse.businessImpact}
                    </p>
                  </div>

                  {/* Fix for Developers */}
                  <div className="rounded-xl border border-[#dfe5ec] bg-[#ffffff] p-3.5 space-y-1.5">
                    <div className="flex items-center gap-1.5 text-xs font-mono font-semibold uppercase tracking-wider text-[#0284c7]">
                      <Wrench className="h-3.5 w-3.5" />
                      <span>Action for Your Tech Team</span>
                    </div>
                    <p className="text-xs text-[#334155] leading-relaxed">
                      {lapse.actionForDev}
                    </p>
                  </div>
                </div>

                {/* Collapsible Technical Details / Evidence Drawer */}
                {lapse.technicalEvidence && (
                  <div className="pt-2">
                    <button
                      type="button"
                      onClick={() => toggleEvidence(lapse.id)}
                      className="flex items-center gap-1.5 text-xs font-mono text-[#5d6b7b] hover:text-[#15202b] transition-colors select-none"
                    >
                      {isEvidenceOpen ? (
                        <ChevronUp className="h-3.5 w-3.5" />
                      ) : (
                        <ChevronDown className="h-3.5 w-3.5" />
                      )}
                      <span>
                        {isEvidenceOpen
                          ? "Hide Technical Audit Evidence"
                          : "Show Technical Audit Evidence (for developers)"}
                      </span>
                    </button>

                    {isEvidenceOpen && (
                      <div className="mt-2.5 p-3.5 rounded-xl bg-[#f8fafc] border border-[#dfe5ec] font-mono text-[11px] space-y-3">
                        <div>
                          <div className="text-[10px] uppercase text-[#748294] font-bold mb-1">
                            Raw Audit Evidence
                          </div>
                          <div className="text-[#334155] whitespace-pre-wrap break-all leading-relaxed bg-[#ffffff] p-2.5 rounded-lg border border-[#e2e8f0]">
                            {lapse.technicalEvidence}
                          </div>
                        </div>

                        {imgSrc && (
                          <div>
                            <div className="flex items-center justify-between text-[10px] uppercase text-[#748294] font-bold mb-1">
                              <span>Evidence Frame</span>
                              <a
                                href={imgSrc}
                                target="_blank"
                                rel="noreferrer"
                                className="text-[#ea7336] hover:underline flex items-center gap-1"
                              >
                                <span>Open Full Screenshot</span>
                                <ExternalLink className="h-2.5 w-2.5" />
                              </a>
                            </div>
                            <div className="rounded-lg border border-[#dfe5ec] overflow-hidden max-w-sm bg-[#ffffff]">
                              {/* eslint-disable-next-line @next/next/no-img-element */}
                              <img
                                src={imgSrc}
                                alt={lapse.plainTitle}
                                className="w-full h-auto object-cover max-h-40"
                              />
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
