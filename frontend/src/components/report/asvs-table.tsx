"use client";

import { useState } from "react";
import type { ASVSTestItem } from "@/lib/types";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { Search, ChevronDown, ChevronUp, Shield } from "lucide-react";
import { cn } from "@/lib/utils";

interface ASVSTableProps {
  items: ASVSTestItem[];
}

export function ASVSTable({ items }: ASVSTableProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Shift all manual results to bottom while preserving their natural chapter order
  const isManual = (item: ASVSTestItem) => {
    return item.status === "MANUAL_VERIFY" || (item.status as string) === "MANUAL";
  };

  const nonManualItems = items.filter((item) => !isManual(item));
  const manualItems = items.filter((item) => isManual(item));
  const orderedItems = [...nonManualItems, ...manualItems];

  const filteredItems = orderedItems.filter((item) => {
    const matchesSearch =
      item.requirement_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.chapter_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (item.evidence && item.evidence.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (item.remediation && item.remediation.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesStatus =
      statusFilter === "all" || item.status?.toUpperCase() === statusFilter.toUpperCase();

    return matchesSearch && matchesStatus;
  });

  const passedCount = items.filter((i) => i.status === "PASS").length;
  const failedCount = items.filter((i) => i.status === "FAIL").length;
  const otherCount = items.length - passedCount - failedCount;

  return (
    <div className="rounded-xl bg-[#ffffff] border border-[#dfe5ec] overflow-hidden">
      {/* Table Header & Controls */}
      <div className="p-4 bg-[#f5f7fa] border-b border-[#dfe5ec] space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-[#ea7336]" />
            <h3 className="text-sm font-semibold font-mono uppercase tracking-wider text-[#15202b]">
              OWASP ASVS Verification Matrix ({items.length} checks)
            </h3>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-[#10b981] font-semibold">{passedCount} Passed</span>
            <span className="text-[#5d6b7b]">•</span>
            <span className="text-[#d9485f] font-semibold">{failedCount} Failed</span>
            {otherCount > 0 && (
              <>
                <span className="text-[#5d6b7b]">•</span>
                <span className="text-[#d97706]">{otherCount} Other</span>
              </>
            )}
          </div>
        </div>

        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-[#5d6b7b]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by ID (e.g. V1.2.1), chapter, or evidence..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-[#f7f9fc] border border-[#dfe5ec] text-xs font-mono text-[#15202b] placeholder-[#5d6b7b] focus:outline-none focus:border-[#ea7336]"
            />
          </div>

          <div className="flex items-center gap-1 text-xs font-mono">
            {(["all", "PASS", "FAIL", "MANUAL_VERIFY", "NOT_TESTED"] as const).map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={cn(
                  "px-2.5 py-1 rounded border transition-colors",
                  statusFilter === st
                    ? st === "PASS"
                      ? "bg-[#ecfdf5] text-[#059669] border-[#a7f3d0] font-semibold"
                      : st === "FAIL"
                      ? "bg-[#fff1f2] text-[#d9485f] border-[#fecdd3] font-semibold"
                      : st === "MANUAL_VERIFY"
                      ? "bg-[#fffbeb] text-[#b45309] border-[#fde68a] font-semibold"
                      : "bg-[#dfe5ec] text-[#15202b] border-[#5d6b7b] font-semibold"
                    : "bg-[#ffffff] text-[#5d6b7b] border-[#dfe5ec] hover:text-[#15202b]"
                )}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Rows */}
      {filteredItems.length === 0 ? (
        <div className="p-8 text-center text-xs font-mono text-[#5d6b7b]">
          No ASVS requirements matching criteria.
        </div>
      ) : (
        <div className="divide-y divide-[#dfe5ec]">
          {filteredItems.map((item) => {
            const isExpanded = expandedId === item.requirement_id;

            return (
              <div key={item.requirement_id} className="bg-[#ffffff]">
                <button
                  onClick={() => setExpandedId(isExpanded ? null : item.requirement_id)}
                  className="w-full flex items-center justify-between p-3.5 text-left hover:bg-[#f5f7fa]/50 transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0 pr-4">
                    <span
                      className={cn(
                        "font-mono text-xs font-bold shrink-0 w-16",
                        item.status === "PASS"
                          ? "text-[#10b981]"
                          : item.status === "FAIL"
                          ? "text-[#d9485f]"
                          : item.status === "MANUAL_VERIFY" || (item.status as string) === "MANUAL"
                          ? "text-[#d97706]"
                          : "text-[#5d6b7b]"
                      )}
                    >
                      {item.requirement_id}
                    </span>
                    <span className="text-xs font-mono text-[#5d6b7b] px-2 py-0.5 rounded bg-[#f7f9fc] border border-[#dfe5ec] shrink-0 truncate max-w-[140px]">
                      {item.chapter_name || item.chapter_code}
                    </span>
                    <span className="text-xs text-[#15202b] truncate">
                      {item.evidence || "Evaluated by security harness"}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <Chip status={item.status.toLowerCase() as ChipStatus} dot />
                    <span className="text-[#5d6b7b]">
                      {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </span>
                  </div>
                </button>

                {isExpanded && (
                  <div className="p-4 pt-3 space-y-3 bg-[#f8fafc] border-t border-[#dfe5ec] text-xs font-mono">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[#5d6b7b] uppercase tracking-wider text-[10px] font-bold">
                        Chapter:
                      </span>
                      <span className="text-[#15202b] font-medium">
                        {item.chapter_code} — {item.chapter_name}
                      </span>
                    </div>

                    <div>
                      <span className="text-[#5d6b7b] uppercase tracking-wider text-[10px] font-bold">
                        Verification Evidence:
                      </span>
                      <div
                        className={cn(
                          "mt-1.5 p-3 rounded-lg border text-xs whitespace-pre-wrap leading-relaxed font-mono",
                          item.status === "FAIL"
                            ? "bg-[#fff1f2] border-[#fecdd3] text-[#991b1b]"
                            : item.status === "PASS"
                            ? "bg-[#f0fdf4] border-[#bbf7d0] text-[#166534]"
                            : "bg-[#ffffff] border-[#dfe5ec] text-[#334155]"
                        )}
                      >
                        {item.evidence || "No specific evidence recorded."}
                      </div>
                    </div>

                    {item.remediation && (
                      <div>
                        <span className="text-[#ea7336] uppercase tracking-wider text-[10px] font-bold">
                          Remediation:
                        </span>
                        <div className="mt-1.5 p-3 rounded-lg bg-[#ffffff] border border-[#fed7c0] text-[#15202b] leading-relaxed font-sans text-xs">
                          {item.remediation}
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
