"use client";

import { useState } from "react";
import type { FindingItem } from "@/lib/types";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { ChevronDown, ChevronUp, ShieldAlert, ExternalLink } from "lucide-react";
import { cn } from "@/lib/utils";

interface FindingsCardProps {
  findings: FindingItem[];
}

export function FindingsCard({ findings }: FindingsCardProps) {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(0);
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const filteredFindings = findings.filter((f) => {
    if (severityFilter === "all") return true;
    return f.severity?.toLowerCase() === severityFilter.toLowerCase();
  });

  const counts = {
    high: findings.filter((f) => f.severity?.toLowerCase() === "high").length,
    medium: findings.filter((f) => f.severity?.toLowerCase() === "medium").length,
    low: findings.filter((f) => f.severity?.toLowerCase() === "low").length,
  };

  return (
    <div className="rounded-xl bg-[#ffffff] border border-[#dfe5ec] overflow-hidden">
      {/* Header with Severity Filters */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-[#f5f7fa] border-b border-[#dfe5ec]">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-[#d9485f]" />
          <h3 className="text-sm font-semibold font-mono uppercase tracking-wider text-[#15202b]">
            Security Findings ({findings.length})
          </h3>
        </div>

        <div className="flex items-center gap-1.5 text-xs font-mono">
          <button
            onClick={() => setSeverityFilter("all")}
            className={cn(
              "px-2.5 py-1 rounded border transition-colors",
              severityFilter === "all"
                ? "bg-[#dfe5ec] text-[#15202b] border-[#5d6b7b]"
                : "bg-[#ffffff] text-[#5d6b7b] border-[#dfe5ec] hover:text-[#15202b]"
            )}
          >
            All ({findings.length})
          </button>
          <button
            onClick={() => setSeverityFilter("high")}
            className={cn(
              "px-2.5 py-1 rounded border transition-colors",
              severityFilter === "high"
                ? "bg-[#d9485f]/20 text-[#d9485f] border-[#d9485f]/50"
                : "bg-[#ffffff] text-[#d9485f]/70 border-[#dfe5ec] hover:text-[#d9485f]"
            )}
          >
            High ({counts.high})
          </button>
          <button
            onClick={() => setSeverityFilter("medium")}
            className={cn(
              "px-2.5 py-1 rounded border transition-colors",
              severityFilter === "medium"
                ? "bg-[#F5B84B]/20 text-[#F5B84B] border-[#F5B84B]/50"
                : "bg-[#ffffff] text-[#F5B84B]/70 border-[#dfe5ec] hover:text-[#F5B84B]"
            )}
          >
            Medium ({counts.medium})
          </button>
          <button
            onClick={() => setSeverityFilter("low")}
            className={cn(
              "px-2.5 py-1 rounded border transition-colors",
              severityFilter === "low"
                ? "bg-[#2774c7]/20 text-[#2774c7] border-[#2774c7]/50"
                : "bg-[#ffffff] text-[#2774c7]/70 border-[#dfe5ec] hover:text-[#2774c7]"
            )}
          >
            Low ({counts.low})
          </button>
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="p-8 text-center text-xs font-mono text-[#5d6b7b]">
          {findings.length === 0
            ? "No security vulnerabilities or negative findings detected."
            : `No ${severityFilter} severity findings.`}
        </div>
      ) : (
        <div className="divide-y divide-[#dfe5ec]">
          {filteredFindings.map((finding, idx) => {
            const isExpanded = expandedIndex === idx;
            const imgSrc = finding.screenshot?.startsWith("http") || finding.screenshot?.startsWith("/")
              ? finding.screenshot
              : finding.screenshot
              ? `/screenshots/${finding.screenshot}`
              : null;

            return (
              <div key={idx} className="bg-[#ffffff]">
                <button
                  onClick={() => setExpandedIndex(isExpanded ? null : idx)}
                  className="w-full flex items-center justify-between p-4 text-left hover:bg-[#f5f7fa]/50 transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0 pr-4">
                    <Chip status={finding.severity.toLowerCase() as ChipStatus} dot />
                    <span className="text-xs font-mono text-[#5d6b7b] px-2 py-0.5 rounded bg-[#f7f9fc] border border-[#dfe5ec] shrink-0">
                      {finding.category}
                    </span>
                    <span className="text-sm font-medium text-[#15202b] truncate">
                      {finding.title}
                    </span>
                  </div>
                  <div className="text-[#5d6b7b] shrink-0">
                    {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </div>
                </button>

                {isExpanded && (
                  <div className="p-4 pt-0 space-y-3 bg-[#f7f9fc]/50 border-t border-[#dfe5ec]/40 text-xs">
                    {/* Evidence */}
                    <div>
                      <div className="font-mono text-[11px] uppercase tracking-wider text-[#5d6b7b] mb-1">
                        Vulnerability Evidence
                      </div>
                      <div className="p-3 rounded-lg bg-[#f7f9fc] border border-[#dfe5ec] font-mono text-[#d9485f] whitespace-pre-wrap leading-relaxed">
                        {finding.evidence || "No evidence string attached."}
                      </div>
                    </div>

                    {/* Remediation */}
                    <div>
                      <div className="font-mono text-[11px] uppercase tracking-wider text-[#18a66b] mb-1">
                        Remediation Guidance
                      </div>
                      <div className="p-3 rounded-lg bg-[#f5f7fa] border border-[#dfe5ec] text-[#15202b] leading-relaxed">
                        {finding.remediation || "Follow OWASP ASVS remediation guidelines."}
                      </div>
                    </div>

                    {/* Screenshot */}
                    {imgSrc && (
                      <div>
                        <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-[#5d6b7b] mb-1">
                          <span>Evidence Frame</span>
                          <a
                            href={imgSrc}
                            target="_blank"
                            rel="noreferrer"
                            className="text-[#18a66b] hover:underline flex items-center gap-1"
                          >
                            <span>Open</span>
                            <ExternalLink className="h-2.5 w-2.5" />
                          </a>
                        </div>
                        <div className="rounded-lg border border-[#dfe5ec] overflow-hidden max-w-md bg-[#f7f9fc]">
                          {/* eslint-disable-next-line @next/next/no-img-element */}
                          <img
                            src={imgSrc}
                            alt={finding.title}
                            className="w-full h-auto object-cover max-h-48"
                          />
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
