"use client";

import { cn } from "@/lib/utils";

export type ChipStatus =
  | "pass"
  | "fail"
  | "running"
  | "queued"
  | "completed"
  | "failed"
  | "not_assessed"
  | "error"
  | "pending"
  | "manual_verify"
  | "not_tested"
  | "not_applicable"
  | "high"
  | "medium"
  | "low"
  | "info";

const chipStyles: Record<ChipStatus, string> = {
  pass: "bg-[#e2f6ec] text-[#6ee9ae] border-[#9ed9b8]",
  completed: "bg-[#e2f6ec] text-[#6ee9ae] border-[#9ed9b8]",
  fail: "bg-[#fde8eb] text-[#ff8d98] border-[#f0aab5]",
  failed: "bg-[#fde8eb] text-[#ff8d98] border-[#f0aab5]",
  error: "bg-[#fde8eb] text-[#ff8d98] border-[#f0aab5]",
  high: "bg-[#fde8eb] text-[#ff8d98] border-[#f0aab5]",
  running: "bg-[#e7f0fb] text-[#7db8ff] border-[#a9c8ed]",
  low: "bg-[#e7f0fb] text-[#7db8ff] border-[#a9c8ed]",
  queued: "bg-[#f1f4f8] text-[#5d6b7b] border-[#cbd5e1]",
  pending: "bg-[#f1f4f8] text-[#5d6b7b] border-[#cbd5e1]",
  not_tested: "bg-[#f1f4f8] text-[#5d6b7b] border-[#cbd5e1]",
  not_applicable: "bg-[#f1f4f8] text-[#748294] border-[#cbd5e1]",
  info: "bg-[#f1f4f8] text-[#5d6b7b] border-[#cbd5e1]",
  not_assessed: "bg-[#fff5df] text-[#f5c979] border-[#e7c784]",
  medium: "bg-[#fff5df] text-[#f5c979] border-[#e7c784]",
  manual_verify: "bg-[#fff5df] text-[#f5c979] border-[#e7c784]",
};

const defaultLabels: Record<ChipStatus, string> = {
  pass: "PASS",
  completed: "COMPLETED",
  fail: "FAIL",
  failed: "FAILED",
  error: "ERROR",
  running: "RUNNING",
  queued: "QUEUED",
  pending: "PENDING",
  not_assessed: "NOT ASSESSED",
  not_tested: "NOT TESTED",
  not_applicable: "N/A",
  manual_verify: "MANUAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

interface ChipProps {
  status: ChipStatus;
  label?: string;
  className?: string;
  dot?: boolean;
}

export function Chip({ status, label, className, dot = false }: ChipProps) {
  const normalizedStatus = (status?.toLowerCase() || "pending") as ChipStatus;
  const style = chipStyles[normalizedStatus] || chipStyles.pending;
  const displayLabel = label || defaultLabels[normalizedStatus] || normalizedStatus.toUpperCase();

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-mono font-medium uppercase tracking-wider select-none",
        style,
        className
      )}
    >
      {dot && (
        <span
          className={cn(
            "h-1.5 w-1.5 rounded-full shrink-0",
            normalizedStatus === "running" && "animate-pulse bg-blue-500",
            (normalizedStatus === "pass" || normalizedStatus === "completed") && "bg-emerald-500",
            (normalizedStatus === "fail" || normalizedStatus === "failed" || normalizedStatus === "error" || normalizedStatus === "high") && "bg-red-500",
            (normalizedStatus === "not_assessed" || normalizedStatus === "medium" || normalizedStatus === "manual_verify") && "bg-amber-500",
            (normalizedStatus === "queued" || normalizedStatus === "pending" || normalizedStatus === "not_tested" || normalizedStatus === "not_applicable" || normalizedStatus === "info") && "bg-gray-400"
          )}
        />
      )}
      <span>{displayLabel}</span>
    </span>
  );
}
