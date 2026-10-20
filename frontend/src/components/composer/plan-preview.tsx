"use client";

import type { SuiteType } from "@/lib/types";
import { Check, Cpu, Zap, Eye, Terminal } from "lucide-react";

interface PlanPreviewProps {
  suite: SuiteType;
  targetUrl: string;
}

export function PlanPreview({ suite, targetUrl }: PlanPreviewProps) {
  const isV1 = suite === "v1" || suite === "chapter_v1";

  const v1Specs = [
    { title: "Input & Parameter Injection", desc: "Active payload fuzzing across form inputs & query params" },
    { title: "HTML / Attribute Encoding", desc: "Verifies DOM output against unescaped markup execution" },
    { title: "Deterministic Grade Verification", desc: "Pass/Fail evaluation based strictly on Canary tokens" },
  ];

  const agentSpecs = [
    { title: "Autonomous Reconnaissance", desc: "Deep DOM discovery, endpoints, forms, and auth surfaces" },
    { title: "6 Domain Specialists", desc: "Transport/Headers, Input, DOM, Auth, API, Crypto" },
    { title: "17 OWASP ASVS Standards", desc: "Evaluates 345 requirements across standard benchmarks" },
    { title: "Evidence Synthesis", desc: "Synthesizes multi-agent traces and generates remediation steps" },
  ];

  const specs = isV1 ? v1Specs : agentSpecs;

  return (
    <div className="w-full rounded-xl bg-[#ffffff] border border-[#dfe5ec] p-5 text-left transition-all">
      <div className="flex items-center justify-between pb-3 border-b border-[#dfe5ec] mb-4">
        <div className="flex items-center gap-2">
          {isV1 ? (
            <Zap className="h-4 w-4 text-[#18a66b]" />
          ) : (
            <Cpu className="h-4 w-4 text-[#6d4aca]" />
          )}
          <span className="text-xs font-mono font-semibold uppercase tracking-wider text-[#15202b]">
            Pre-Flight Assessment Scope
          </span>
        </div>
        <span
          className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
            isV1
              ? "bg-[#18a66b]/10 text-[#18a66b] border-[#18a66b]/30"
              : "bg-[#6d4aca]/10 text-[#6d4aca] border-[#6d4aca]/30"
          }`}
        >
          {isV1 ? "Deterministic V1 Harness" : "Multi-Agent Security Graph"}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
        {specs.map((item, idx) => (
          <div
            key={idx}
            className="flex items-start gap-2.5 p-2.5 rounded-lg bg-[#f5f7fa] border border-[#dfe5ec]/70"
          >
            <div
              className={`p-1 rounded shrink-0 mt-0.5 ${
                isV1 ? "text-[#18a66b] bg-[#18a66b]/10" : "text-[#6d4aca] bg-[#6d4aca]/10"
              }`}
            >
              <Check className="h-3 w-3 stroke-[3]" />
            </div>
            <div>
              <div className="text-xs font-medium text-[#15202b]">{item.title}</div>
              <div className="text-[11px] text-[#5d6b7b] leading-snug">{item.desc}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Target Preview Confirmation */}
      <div className="flex items-center justify-between pt-3 border-t border-[#dfe5ec] text-[11px] font-mono text-[#5d6b7b]">
        <div className="flex items-center gap-2">
          <Terminal className="h-3.5 w-3.5" />
          <span>Dispatch Target:</span>
          <span className="text-[#15202b] font-semibold truncate max-w-xs">
            {targetUrl || "None selected"}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <Eye className="h-3.5 w-3.5 text-[#2774c7]" />
          <span>Live SSE Telemetry Stream: Enabled</span>
        </div>
      </div>
    </div>
  );
}
