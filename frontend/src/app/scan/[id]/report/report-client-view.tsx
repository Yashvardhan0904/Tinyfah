"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getScan } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { ScoreCircle } from "@/components/report/score-circle";
import { GradeBadge } from "@/components/report/grade-badge";
import { ExecutiveLapsesGrid } from "@/components/report/executive-lapses-grid";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { Button } from "@/components/ui/button";
import { formatDate } from "@/lib/utils";
import {
  ArrowLeft,
  ArrowRight,
  Printer,
  Radio,
  ExternalLink,
  AlertTriangle,
  Calendar,
  Globe,
  ShieldCheck,
  Flame,
} from "lucide-react";

interface ReportClientViewProps {
  scanId: number;
}

export function ReportClientView({ scanId }: ReportClientViewProps) {
  const isInvalidId = !scanId || isNaN(scanId);
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(!isInvalidId);
  const [error, setError] = useState<string | null>(isInvalidId ? "Invalid Scan ID" : null);

  useEffect(() => {
    if (isInvalidId) return;

    let ignore = false;
    getScan(scanId)
      .then((data) => {
        if (!ignore) setScan(data);
      })
      .catch((err) => {
        if (!ignore) setError(err instanceof Error ? err.message : "Failed to load report");
      })
      .finally(() => {
        if (!ignore) setLoading(false);
      });

    return () => {
      ignore = true;
    };
  }, [scanId, isInvalidId]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-[#f7f9fc] text-[#15202b]">
        <div className="h-6 w-6 border-2 border-[#ea7336] border-t-transparent rounded-full animate-spin mb-3" />
        <span className="text-xs font-mono text-[#748294]">Compiling Security Report #{scanId}...</span>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-[#f7f9fc] text-[#15202b] p-4 text-center">
        <AlertTriangle className="h-8 w-8 text-[#d9485f] mb-2" />
        <h2 className="text-base font-bold text-[#15202b] mb-1">Failed to Load Report</h2>
        <p className="text-xs font-mono text-[#5d6b7b] mb-4">{error || "Scan not found"}</p>
        <Link href="/">
          <Button variant="neutral" size="sm">
            Return to Composer
          </Button>
        </Link>
      </div>
    );
  }

  const results = scan.results || { findings: [], asvs_results: [], agent_trace: [] };
  const findings = results.findings || [];
  const asvsResults = results.asvs_results || [];

  const handlePrint = () => {
    if (typeof window !== "undefined") {
      window.print();
    }
  };

  return (
    <div className="min-h-screen bg-[#f7f9fc] text-[#15202b] flex flex-col font-sans">
      {/* Top Navbar */}
      <header className="flex items-center justify-between px-6 py-3.5 bg-[#ffffff] border-b border-[#dfe5ec] select-none shrink-0 print:hidden">
        <div className="flex items-center gap-3">
          <Link
            href={`/scan/${scan.id}`}
            className="flex items-center gap-1.5 text-xs font-mono text-[#5d6b7b] hover:text-[#15202b] transition-colors"
          >
            <Radio className="h-3.5 w-3.5 text-[#2774c7]" />
            <span>Live Stream</span>
          </Link>
          <div className="h-4 w-[1px] bg-[#dfe5ec]" />
          <Link
            href="/"
            className="flex items-center gap-1.5 text-xs font-mono text-[#5d6b7b] hover:text-[#15202b] transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>Composer</span>
          </Link>
        </div>

        <div className="flex items-center gap-2">
          <Link href={`/scan/${scan.id}/exploit`}>
            <Button
              variant="danger"
              size="sm"
              className="gap-1.5 font-mono text-xs bg-[#d9485f] hover:bg-[#c3384e] text-white shadow-xs"
            >
              <Flame className="h-3.5 w-3.5" />
              <span>Exploit Target</span>
            </Button>
          </Link>

          <Button variant="neutral" size="sm" onClick={handlePrint} className="gap-1.5 font-mono text-xs">
            <Printer className="h-3.5 w-3.5" />
            <span>Export / Print</span>
          </Button>
        </div>
      </header>

      {/* Main Report Body */}
      <main className="flex-1 max-w-5xl mx-auto w-full p-6 sm:p-8 space-y-6">
        {/* Executive Header Banner */}
        <div className="rounded-2xl bg-[#ffffff] border border-[#dfe5ec] p-6 sm:p-8 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="space-y-3 flex-1 text-center md:text-left">
            <div className="flex flex-wrap items-center justify-center md:justify-start gap-2.5">
              <span className="text-xs font-mono text-[#5d6b7b]">Scan #{scan.id}</span>
              <Chip status={scan.status as ChipStatus} dot />
              <GradeBadge grade={scan.grade} size="sm" />
            </div>

            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-[#15202b] break-all">
              {scan.url}
            </h1>

            <div className="flex flex-wrap items-center justify-center md:justify-start gap-4 text-xs font-mono text-[#5d6b7b]">
              <div className="flex items-center gap-1.5">
                <Calendar className="h-3.5 w-3.5" />
                <span>{formatDate(scan.created_at)}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <Globe className="h-3.5 w-3.5" />
                <a
                  href={scan.url}
                  target="_blank"
                  rel="noreferrer"
                  className="hover:text-[#ea7336] inline-flex items-center gap-1"
                >
                  <span>Open Target</span>
                  <ExternalLink className="h-2.5 w-2.5" />
                </a>
              </div>
            </div>
          </div>

          {/* Score Indicator */}
          <div className="shrink-0 flex items-center gap-4 p-4 rounded-xl bg-[#f7f9fc] border border-[#dfe5ec]">
            <ScoreCircle score={scan.score} size={110} strokeWidth={8} />
            <div className="space-y-1">
              <div className="text-xs font-mono text-[#5d6b7b]">ASSESSMENT</div>
              <GradeBadge grade={scan.grade} size="md" />
            </div>
          </div>
        </div>

        {/* Failed Connection Alert Banner */}
        {scan.status === "failed" && (
          <div className="rounded-2xl bg-[#fff5f5] border border-[#fecaca] p-6 sm:p-8 flex items-start gap-4 shadow-sm">
            <div className="h-10 w-10 rounded-xl bg-[#fee2e2] border border-[#fca5a5] flex items-center justify-center shrink-0 text-[#dc2626]">
              <AlertTriangle className="h-5 w-5" />
            </div>
            <div className="space-y-1.5 flex-1 min-w-0">
              <h3 className="text-base font-bold text-[#991b1b]">
                Target Cannot Be Reached • Session Terminated
              </h3>
              <p className="text-xs sm:text-[13px] text-[#b91c1c] leading-relaxed font-mono">
                {String(scan.error || results.error || "The browser could not establish a connection to the target server. No security audit could be completed.")}
              </p>
            </div>
          </div>
        )}

        {/* Executive Summary */}
        {results.summary && scan.status !== "failed" && (
          <div className="rounded-xl bg-[#ffffff] border border-[#dfe5ec] p-5">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-[#5d6b7b] mb-2">
              Executive Assessment Summary
            </h3>
            <p className="text-xs sm:text-sm text-[#15202b] leading-relaxed whitespace-pre-line">
              {results.summary}
            </p>
          </div>
        )}

        {/* Plain-English Executive Security Lapses & Exploit Risks */}
        {scan.status !== "failed" && (
          <ExecutiveLapsesGrid findings={findings} asvsResults={asvsResults} />
        )}

        {/* Technical Matrix Callout Card */}
        {scan.status !== "failed" && (
          <div className="rounded-2xl bg-[#ffffff] border border-[#dfe5ec] p-6 sm:p-7 flex flex-col sm:flex-row items-center justify-between gap-5 shadow-2xs">
            <div className="space-y-1.5 text-center sm:text-left">
              <div className="flex items-center justify-center sm:justify-start gap-2">
                <ShieldCheck className="h-4 w-4 text-[#ea7336]" />
                <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-[#15202b]">
                  OWASP ASVS Verification Matrix
                </h3>
                <span className="px-2 py-0.5 rounded-full bg-[#f3f6f9] border border-[#dfe5ec] text-[10px] font-mono text-[#5d6b7b]">
                  {asvsResults.length} Controls
                </span>
              </div>
              <p className="text-xs text-[#5d6b7b] max-w-xl leading-relaxed">
                Access the complete requirement-by-requirement verification matrix with automated evidence, chapter breakdowns, and targeted remediation guidelines.
              </p>
            </div>

            <Link href={`/scan/${scan.id}/report/technical`} className="shrink-0">
              <Button variant="primary" size="md" className="gap-2 font-semibold shadow-xs">
                <span>Get Detailed Techincal report</span>
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="py-6 text-center text-xs font-mono text-[#5d6b7b] border-t border-[#dfe5ec] bg-[#ffffff] print:hidden">
        Tinyfah Autonomous Security Platform • Generated Report for {scan.url}
      </footer>
    </div>
  );
}
