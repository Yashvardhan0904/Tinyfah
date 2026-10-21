"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getScan } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { ASVSTable } from "@/components/report/asvs-table";
import { GradeBadge } from "@/components/report/grade-badge";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { Button } from "@/components/ui/button";
import { formatDate } from "@/lib/utils";
import {
  ArrowLeft,
  Printer,
  Radio,
  ExternalLink,
  AlertTriangle,
  Calendar,
  Globe,
  Shield,
  FileText,
  CheckCircle2,
  XCircle,
} from "lucide-react";

interface TechnicalReportClientViewProps {
  scanId: number;
}

export function TechnicalReportClientView({ scanId }: TechnicalReportClientViewProps) {
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
        if (!ignore) setError(err instanceof Error ? err.message : "Failed to load technical report");
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
        <span className="text-xs font-mono text-[#748294]">
          Loading OWASP ASVS Technical Matrix for Scan #{scanId}...
        </span>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-[#f7f9fc] text-[#15202b] p-4 text-center">
        <AlertTriangle className="h-8 w-8 text-[#d9485f] mb-2" />
        <h2 className="text-base font-bold text-[#15202b] mb-1">Failed to Load Technical Report</h2>
        <p className="text-xs font-mono text-[#5d6b7b] mb-4">{error || "Scan not found"}</p>
        <Link href={`/scan/${scanId}/report`}>
          <Button variant="neutral" size="sm">
            Return to Executive Report
          </Button>
        </Link>
      </div>
    );
  }

  const results = scan.results || { findings: [], asvs_results: [], agent_trace: [] };
  const asvsResults = results.asvs_results || [];

  const passedCount = asvsResults.filter((i) => i.status === "PASS").length;
  const failedCount = asvsResults.filter((i) => i.status === "FAIL").length;
  const otherCount = asvsResults.length - passedCount - failedCount;

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
            href={`/scan/${scan.id}/report`}
            className="flex items-center gap-1.5 text-xs font-mono font-medium text-[#ea7336] hover:text-[#d96527] transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>Executive Report</span>
          </Link>

          <div className="h-4 w-[1px] bg-[#dfe5ec]" />

          <Link
            href={`/scan/${scan.id}`}
            className="flex items-center gap-1.5 text-xs font-mono text-[#5d6b7b] hover:text-[#15202b] transition-colors"
          >
            <Radio className="h-3.5 w-3.5 text-[#2774c7]" />
            <span>Live Stream</span>
          </Link>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="neutral" size="sm" onClick={handlePrint} className="gap-1.5 font-mono text-xs">
            <Printer className="h-3.5 w-3.5" />
            <span>Export / Print</span>
          </Button>
        </div>
      </header>

      {/* Main Technical Report Body */}
      <main className="flex-1 max-w-5xl mx-auto w-full p-6 sm:p-8 space-y-6">
        {/* Technical Header Card */}
        <div className="rounded-2xl bg-[#ffffff] border border-[#dfe5ec] p-6 sm:p-8 flex flex-col md:flex-row items-center justify-between gap-6 shadow-2xs">
          <div className="space-y-3 flex-1 text-center md:text-left">
            <div className="flex flex-wrap items-center justify-center md:justify-start gap-2.5">
              <span className="text-xs font-mono text-[#5d6b7b]">Scan #{scan.id}</span>
              <Chip status={scan.status as ChipStatus} dot />
              <GradeBadge grade={scan.grade} size="sm" />
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-[#fff0e6] text-[#ea7336] border border-[#fed7c0]">
                <Shield className="h-3 w-3" />
                <span>OWASP ASVS 5.0.0</span>
              </span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-[#15202b] break-all">
              Detailed Technical Report
            </h1>

            <p className="text-xs font-mono text-[#5d6b7b]">
              Target: <span className="text-[#15202b] font-semibold">{scan.url}</span>
            </p>

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

          {/* Verification Statistics Pill */}
          <div className="shrink-0 grid grid-cols-2 gap-3 p-4 rounded-xl bg-[#f7f9fc] border border-[#dfe5ec] text-center">
            <div className="p-2 rounded-lg bg-[#ffffff] border border-[#dfe5ec]">
              <div className="text-[10px] font-mono text-[#5d6b7b] uppercase">Passed</div>
              <div className="text-lg font-mono font-bold text-[#10b981] flex items-center justify-center gap-1">
                <CheckCircle2 className="h-4 w-4" />
                <span>{passedCount}</span>
              </div>
            </div>
            <div className="p-2 rounded-lg bg-[#ffffff] border border-[#dfe5ec]">
              <div className="text-[10px] font-mono text-[#5d6b7b] uppercase">Failed</div>
              <div className="text-lg font-mono font-bold text-[#d9485f] flex items-center justify-center gap-1">
                <XCircle className="h-4 w-4" />
                <span>{failedCount}</span>
              </div>
            </div>
            <div className="col-span-2 p-1.5 rounded-lg bg-[#ffffff] border border-[#dfe5ec] text-[11px] font-mono text-[#5d6b7b]">
              {asvsResults.length} Total Verification Controls Evaluated
            </div>
          </div>
        </div>

        {/* The OWASP ASVS Verification Matrix */}
        <ASVSTable items={asvsResults} />
      </main>

      {/* Footer */}
      <footer className="py-6 text-center text-xs font-mono text-[#5d6b7b] border-t border-[#dfe5ec] bg-[#ffffff] print:hidden">
        Tinyfah Autonomous Security Platform • Technical Compliance Matrix for {scan.url}
      </footer>
    </div>
  );
}
